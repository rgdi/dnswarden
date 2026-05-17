// doh-server: minimal RFC 8484 DNS-over-HTTPS proxy server in Go
// Listens on :54321/tcp, forwards to CoreDNS at 127.0.0.1:1053
package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	upstreamDNS = "127.0.0.1:1053"
	listenPort  = ":54321"
	maxSize     = 4096
)

// RFC 8484 §4.1 — GET ?dns=<base64url>
func parseGET(u *http.Request) ([]byte, error) {
	q := u.URL.Query().Get("dns")
	if q == "" {
		return nil, fmt.Errorf("missing ?dns=")
	}
	// base64url: URL-safe, no padding
	return base64.URLEncoding.DecodeString(q)
}

// RFC 8484 §4.2 — POST application/dns-message
func parsePOST(r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Type") != "application/dns-message" {
		return nil, fmt.Errorf("bad content-type")
	}
	return io.ReadAll(http.MaxBytesReader(nil, r.Body, maxSize))
}

func forward(wire []byte) ([]byte, error) {
	// Raw DNS over UDP to CoreDNS
	conn, err := newUDPConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.WriteTo(wire, udpAddr(upstreamDNS))
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, maxSize)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return buf[:n], nil
}

// ── netjr wrapper para poder mockear en tests ────────────────────────────
func newUDPConn() (interface{ WriteTo([]byte, interface{}) (int, error); ReadFrom([]byte) (int, interface{}, error); SetDeadline(time.Time) error }, error) {
	return &udpConn{}, nil
}

type udpConn struct{}
type UDPAddr struct{ Host string; Port int }

func (*udpConn) WriteTo(b []byte, addr interface{}) (int, error) {
	a := addr.(UDPAddr)
	conn, err := dialUDP(a.Host, a.Port)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return conn.Write(b)
}

func (*udpConn) ReadFrom(b []byte) (int, interface{}, error) {
	conn, err := dialUDP("127.0.0.1", 0)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	n, err := conn.Read(b)
	return n, nil, err
}

func (*udpConn) SetDeadline(t time.Time) error { return nil }

func dialUDP(host string, port int) (interface{ Read([]byte) (int, error); Write([]byte) (int, error); Close() error }, error) {
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
	return c, err
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Path != "/dns-query" {
		http.NotFound(w, r)
		return
	}

	var wire []byte
	var err error

	if r.Method == http.MethodGet {
		wire, err = parseGET(r)
	} else if r.Method == http.MethodPost {
		wire, err = parsePOST(r)
	} else {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	if err != nil {
		log.Printf("parse error: %v", err)
		http.Error(w, "Bad Request", 400)
		return
	}

	resp, err := forward(wire)
	if err != nil {
		log.Printf("upstream error: %v", err)
		http.Error(w, "Service Unavailable", 503)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(resp)
}

func main() {
	mux := &http.ServeMux{}
	mux.HandleFunc("/dns-query", handler)

	srv := &http.Server{
		Addr:         listenPort,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("DoH listening on %s → %s", listenPort, upstreamDNS)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// ── net imports ──────────────────────────────────────────────────────────
import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)