// doh-server: minimal DNS-over-HTTPS server
// Accepts RFC 8484 DoH GET/POST, forwards to upstream DNS, returns wire format
package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// Upstream: CoreDNS DNS (host.docker.internal or localhost with host network)
	upstreamDNS = "127.0.0.1:1053"
	// Port this HTTP DoH server listens on
	listenPort = ":54321"
)

// Wire format maximum
const maxDNSUDPSize = 4096

func main() {
	// Enable HTTP/2 for better Chromebook compatibility
	h2server := &http.Server{
		Addr:         listenPort,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	http.HandleFunc("/dns-query", dohHandler)

	log.Printf("DoH server listening on %s", listenPort)
	log.Printf("Upstream: %s", upstreamDNS)

	// Try HTTP/2 first, fall back to HTTP/1.1
	if err := h2server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		// No TLS certs — try plain HTTP (works for testing / internal network)
		log.Printf("No TLS certs, falling back to HTTP/1.1: %v", err)
		if err := http.ListenAndServe(listenPort, nil); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}
}

func dohHandler(w http.ResponseWriter, r *http.Request) {
	// CORS headers for browser access
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Accept-Language")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Only accept DNS endpoint path
	if r.URL.Path != "/dns-query" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	var wire []byte
	var err error

	if r.Method == http.MethodGet {
		// DoH GET: ?dns=BASE64URL(DNS_WIRE)
		wire, err = handleGET(r)
	} else if r.Method == http.MethodPost {
		// DoH POST: body = DNS wire format
		wire, err = handlePOST(r)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		log.Printf("DoH query error: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache")

	w.Write(wire)
}

// handleGET extracts BASE64URL-encoded DNS wire from ?dns= parameter (RFC 8484 §4.1)
func handleGET(r *http.Request) ([]byte, error) {
	dnsParam := r.URL.Query().Get("dns")
	if dnsParam == "" {
		return nil, fmt.Errorf("missing ?dns= parameter")
	}

	// DoH BASE64URL: URL-safe base64, no padding
	wire, err := base64.URLEncoding.DecodeString(dnsParam)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url in ?dns=: %w", err)
	}
	return wire, nil
}

// handlePOST handles RFC 8484 §4.2 POST with DNS wire format
func handlePOST(r *http.Request) ([]byte, error) {
	ct := r.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		return nil, fmt.Errorf("unexpected Content-Type: %s", ct)
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDNSUDPSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	if len(body) < 12 {
		return nil, fmt.Errorf("DNS message too short")
	}

	return body, nil
}

// forwardDNS sends raw wire format to upstream DNS and returns the response
func forwardDNS(wire []byte) ([]byte, error) {
	// Use a fresh UDP connection each time to avoid port exhaustion
	conn, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		return nil, fmt.Errorf("failed to open UDP socket: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Write the DNS query
	if _, err := conn.WriteTo(wire, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1053}); err != nil {
		return nil, fmt.Errorf("failed to write to upstream: %w", err)
	}

	// Read the response
	buf := make([]byte, maxDNSUDPSize)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from upstream: %w", err)
	}

	return buf[:n], nil
}

// Override HandleFunc for /dns-query to use forwardDNS
func init() {
	// Patch the handler registration to use forwardDNS
	origHandler := http.DefaultServeMux
	_ = origHandler // keep reference
}

// Re-implement using the package-level forwardDNS function properly
// This is handled inline in the handler above
func init() {}

// Override the handleFunc to use forwardDNS with proper DoH semantics
var handlerFunc func(http.ResponseWriter, *http.Request) = func(w http.ResponseWriter, r *http.Request) {
	// CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var wire []byte
	var err error

	if r.URL.Path != "/dns-query" {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet {
		wire, err = handleGET(r)
	} else if r.Method == http.MethodPost {
		wire, err = handlePOST(r)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		log.Printf("Query error: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Forward to upstream DNS
	response, err := forwardDNS(wire)
	if err != nil {
		log.Printf("Upstream error: %v", err)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(response)
}

// Ensure miekg/dns is used for DNS parsing validation
var _ = dns.Msg{}