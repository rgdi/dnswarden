#!/usr/bin/env python3
"""
doh-proxy.py — RFC 8484 DNS-over-HTTPS proxy en Python puro
Escucha en :54321/tcp, reenvía a CoreDNS en 127.0.0.1:53 (UDP)

Compatible con:
  • Chrome/Chromebook (DoH nativo: chrome://settings/security → Custom DNS)
  • curl --doh-url
  • Cualquier cliente DoH RFC 8484

No requiere dependencias externas — stdlib only.
"""
import base64
import selectors
import socket
import struct
import threading
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

# ── Config ──────────────────────────────────────────────────────────────────
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 54321
COREDNS_HOST = "127.0.0.1"
COREDNS_PORT = 53
TIMEOUT = 5.0
MAX_SIZE = 4096

# ── helpers ──────────────────────────────────────────────────────────────────
def parse_dns_wire(data: bytes) -> Optional[bytes]:
    if len(data) < 12:
        return None
    return data

def forward_to_coredns(wire: bytes) -> Optional[bytes]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(wire, (COREDNS_HOST, COREDNS_PORT))
        resp, _ = sock.recvfrom(MAX_SIZE)
        sock.close()
        return resp
    except OSError:
        return None

# ── HTTP/DoH handler ─────────────────────────────────────────────────────────
class DoHHandler(BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # silencia el log de BaseHTTPRequestHandler

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, Accept, Accept-Language, Accept-Encoding")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

    def send_doh_response(self, wire: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Content-Length", len(wire))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(wire)

    def send_dns_error(self, code: int, msg: str):
        self.send_error(code, msg)

    def do_GET(self):
        if self.path.split("?")[0] != "/dns-query":
            self.send_error(404, "Not Found")
            return

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if "dns" not in qs:
            self.send_error(400, "Missing ?dns= parameter")
            return

        wire_b64 = qs["dns"][0]
        try:
            missing = 4 - (len(wire_b64) % 4)
            if missing != 4:
                wire_b64 += "=" * missing
            wire = base64.urlsafe_b64decode(wire_b64)
        except Exception:
            self.send_error(400, "Invalid base64url")
            return

        if not parse_dns_wire(wire):
            self.send_error(400, "Invalid DNS wire format")
            return

        resp_wire = forward_to_coredns(wire)
        if resp_wire is None:
            self.send_error(503, "CoreDNS unreachable")
            return

        self.send_doh_response(resp_wire)

    def do_POST(self):
        if self.path != "/dns-query":
            self.send_error(404, "Not Found")
            return

        ct = self.headers.get("Content-Type", "")
        if ct != "application/dns-message":
            self.send_error(415, f"Unsupported Media Type: {ct}")
            return

        cl = self.headers.get("Content-Length", "")
        if not cl.isdigit() or int(cl) > MAX_SIZE or int(cl) == 0:
            self.send_error(400, "Payload too large or missing Content-Length")
            return

        wire = self.rfile.read(int(cl))
        if not parse_dns_wire(wire):
            self.send_error(400, "Invalid DNS wire format")
            return

        resp_wire = forward_to_coredns(wire)
        if resp_wire is None:
            self.send_error(503, "CoreDNS unreachable")
            return

        self.send_doh_response(resp_wire)


# ── Threaded server para mayor throughput ────────────────────────────────────
class ThreadedHTTPServer(HTTPServer):
    """Un hilo por request — overhead mínimo para un proxy liviano."""

    def process_request(self, request, client_address):
        t = threading.Thread(
            target=self._handle,
            args=(request, client_address),
            daemon=True
        )
        t.start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            try:
                request.close()
            except Exception:
                pass


# ── Health check endpoint ─────────────────────────────────────────────────────
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            dummy = bytes([0] * 12)
            if forward_to_coredns(dummy) is None:
                self.send_response(503)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"SERVFAIL\n")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK\n")
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        pass


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    doh_server = ThreadedHTTPServer((LISTEN_HOST, LISTEN_PORT), DoHHandler)
    health_server = ThreadedHTTPServer((LISTEN_HOST, 5054), HealthHandler)

    t1 = threading.Thread(target=doh_server.serve_forever,
                          daemon=True, name="DoH")
    t2 = threading.Thread(target=health_server.serve_forever,
                          daemon=True, name="Health")
    t1.start()
    t2.start()

    print(f"DoH proxy listening :{LISTEN_PORT} → {COREDNS_HOST}:{COREDNS_PORT}", flush=True)
    print(f"Health endpoint     :5054/health", flush=True)
    print(f"Upstream            Cloudflare Family (1.1.1.3/1.0.0.3) via CoreDNS", flush=True)
    print(f"Blacklist file      ./blacklist.txt", flush=True)

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\nShutting down...")
        doh_server.shutdown()
        health_server.shutdown()


if __name__ == "__main__":
    main()