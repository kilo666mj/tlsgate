package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// truncatedClientHello is a TLS handshake record (type 0x16, handshake
// type 0x01) whose body is too short to be a valid ClientHello, so
// extractTLSMetadata returns an error. It models a fragmented/truncated
// ClientHello an attacker could send to probe the parse path.
var truncatedClientHello = []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00}

func TestSanitizeLog(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "mail.example.com", "mail.example.com"},
		{"newline", "host\ninjected line", "hostinjected line"},
		{"crlf", "a\r\nb", "ab"},
		{"tab", "a\tb", "ab"},
		{"del", "a\x7fb", "ab"},
		{"escape", "\x1b[31mred\x1b[0m", "[31mred[0m"},
		{"empty", "", ""},
		{"unicode kept", "café→x", "café→x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeLog(c.in); got != c.want {
				t.Fatalf("sanitizeLog(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestEnsureDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "db")
	if err := ensureDir(dir); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("ensureDir did not create a directory")
	}
	if perm := info.Mode().Perm(); perm != 0750 {
		t.Fatalf("dir perms = %o, want 750", perm)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// backendRecorder starts a loopback listener standing in for the mail
// backend. It returns the listen address and a channel that receives the
// first bytes of any accepted connection (or nothing if none arrives).
func backendRecorder(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		got <- buf[:n]
	}()
	return ln.Addr().String(), got
}

// captureClientHello drives the standard library TLS client to produce a
// real ClientHello record and returns its raw bytes (record header + body).
func captureClientHello(t *testing.T) []byte {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	go func() {
		c := tls.Client(client, &tls.Config{
			ServerName:         "mail.example.com",
			NextProtos:         []string{"imap"},
			InsecureSkipVerify: true,
		})
		_ = c.Handshake()
		c.Close()
	}()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return append(header, body...)
}

// expectNoBackend asserts the backend was never dialed (connection blocked).
func expectNoBackend(t *testing.T, got <-chan []byte) {
	t.Helper()
	select {
	case b := <-got:
		t.Fatalf("backend received %d bytes; connection should have been blocked", len(b))
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHandleConnBlocksUnparseableWhenBlockUnknown(t *testing.T) {
	backend, got := backendRecorder(t)
	store := newTestStore(t)
	clientConn, testConn := net.Pipe()
	defer testConn.Close()

	done := make(chan struct{})
	go func() {
		handleConn(clientConn, backend, 993, store, true, MethodJA3, nil, nil)
		close(done)
	}()
	go testConn.Write(truncatedClientHello)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not return")
	}
	expectNoBackend(t, got)
}

func TestHandleConnForwardsUnparseableWhenAllowUnknown(t *testing.T) {
	backend, got := backendRecorder(t)
	store := newTestStore(t)
	clientConn, testConn := net.Pipe()
	defer testConn.Close()

	go handleConn(clientConn, backend, 993, store, false, MethodJA3, nil, nil)
	go testConn.Write(truncatedClientHello)

	select {
	case b := <-got:
		if !bytes.Equal(b, truncatedClientHello) {
			t.Fatalf("backend received %x, want %x", b, truncatedClientHello)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive forwarded bytes under allow-unknown")
	}
}

func TestHandleConnBlocksNonTLSWhenBlockUnknown(t *testing.T) {
	backend, got := backendRecorder(t)
	store := newTestStore(t)
	clientConn, testConn := net.Pipe()
	defer testConn.Close()

	go handleConn(clientConn, backend, 993, store, true, MethodJA3, nil, nil)
	go testConn.Write([]byte("HELO plain\r\n"))

	expectNoBackend(t, got)
}

func TestHandleConnRejectsOversizedRecord(t *testing.T) {
	backend, got := backendRecorder(t)
	store := newTestStore(t)
	clientConn, testConn := net.Pipe()
	defer testConn.Close()

	go handleConn(clientConn, backend, 993, store, true, MethodJA3, nil, nil)
	// 0x16 record header declaring a 65535-byte body, far above maxTLSRecordBody.
	go testConn.Write([]byte{0x16, 0x03, 0x01, 0xff, 0xff})

	expectNoBackend(t, got)
}

func TestHandleConnDropsRateLimitedConnection(t *testing.T) {
	backend, got := backendRecorder(t)
	store := newTestStore(t)
	limiter := newRateLimiter(0, 0, time.Minute) // no tokens: every IP denied
	clientConn, testConn := net.Pipe()
	defer testConn.Close()

	done := make(chan struct{})
	go func() {
		handleConn(clientConn, backend, 993, store, true, MethodJA3, nil, limiter)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not return for a rate-limited connection")
	}
	expectNoBackend(t, got)
}

func TestSanitizeAlertFieldStripsBackticks(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "mail.example.com", "mail.example.com"},
		{"backtick breakout", "x`@all`", "x@all"},
		{"control chars", "a\nb\tc", "abc"},
		{"only backticks", "```", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeAlertField(c.in); got != c.want {
				t.Fatalf("sanitizeAlertField(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestBlockedRangeMessageContainsNoBacktickBreakout(t *testing.T) {
	meta := TLSMetadata{SNI: "evil`@channel`", JA3: "771,4865,0,0,0"}
	msg := blockedRangeMessage("home", "198.51.100.1", 993, "fp", meta)
	if strings.Contains(msg, "`@channel`") {
		t.Fatalf("message leaked a backtick breakout: %q", msg)
	}
}

func TestHandleConnProxiesApprovedFingerprintBothWays(t *testing.T) {
	hello := captureClientHello(t)
	fp, meta, err := extractTLSMetadata(hello, MethodJA3)
	if err != nil {
		t.Fatalf("extractTLSMetadata: %v", err)
	}
	store := newTestStore(t)
	if _, err := store.Seen(fp, "127.0.0.1", 993, meta, false); err != nil {
		t.Fatalf("Seen: %v", err)
	}
	if err := store.SetStatus(fp, StatusApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	// Backend sends a banner (server->client) and echoes input back into a
	// channel (client->server), exercising both directions of the pump.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	fromClient := make(chan []byte, 8)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("* OK banner\r\n"))
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				fromClient <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	clientConn, testConn := net.Pipe()
	defer testConn.Close()
	go handleConn(clientConn, ln.Addr().String(), 993, store, true, MethodJA3, nil, nil)

	go func() {
		testConn.Write(hello)
		testConn.Write([]byte("a LOGIN user pass\r\n"))
	}()

	// server -> client: banner reaches the client.
	testConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := testConn.Read(buf)
	if err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("OK banner")) {
		t.Fatalf("banner = %q, want it to contain %q", buf[:n], "OK banner")
	}

	// client -> server: backend receives the forwarded ClientHello followed
	// by the post-handshake payload.
	var fromClientAll []byte
	deadline := time.After(2 * time.Second)
	for !bytes.Contains(fromClientAll, []byte("a LOGIN")) {
		select {
		case b := <-fromClient:
			fromClientAll = append(fromClientAll, b...)
		case <-deadline:
			t.Fatalf("backend never received client payload; got %x", fromClientAll)
		}
	}
	if !bytes.HasPrefix(fromClientAll, hello) {
		t.Fatalf("backend did not receive ClientHello first; got %x", fromClientAll)
	}
}
