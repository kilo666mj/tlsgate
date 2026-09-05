package main

import (
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kilo666mj/gatekit/store"
)

type addressedConn struct {
	net.Conn
	addr net.Addr
}

func (c addressedConn) RemoteAddr() net.Addr { return c.addr }

func exerciseGate(t *testing.T, st *store.Store, hello []byte, method FingerprintMethod, strict, trusted, forward bool) {
	t.Helper()
	backend, got := backendRecorder(t)
	client, peer := net.Pipe()
	defer peer.Close()
	allow := &ipAllowlist{}
	if trusted {
		var err error
		allow, err = newIPAllowlist([]string{"192.0.2.0/24"})
		if err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConn(addressedConn{client, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 54321}}, backend, 993, st, strict, method, nil, nil, allow, false)
	}()
	go func() { _, _ = peer.Write(hello) }()
	if forward {
		select {
		case data := <-got:
			if len(data) == 0 {
				t.Fatal("empty forwarded hello")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("expected forwarding")
		}
	}
	if forward {
		peer.Close()
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("connection did not finish")
	}
	if !forward {
		expectNoBackend(t, got)
	}
}

func TestPendingCannotEscapeEnrollmentOrTrustedSource(t *testing.T) {
	for _, method := range []FingerprintMethod{MethodJA3, MethodJA4} {
		for _, source := range []string{"enrollment", "trusted"} {
			t.Run(string(method)+"/"+source, func(t *testing.T) {
				st := newTestStore(t)
				defer st.Close()
				hello := captureClientHello(t)
				// Create pending through the actual connection path, then remove its bypass.
				exerciseGate(t, st, hello, method, source == "trusted", source == "trusted", true)
				fp, _, err := extractTLSMetadata(hello, method)
				if err != nil {
					t.Fatal(err)
				}
				entry, err := st.Get(fp)
				if err != nil || entry.Status != StatusPending {
					t.Fatalf("pending entry: %+v, %v", entry, err)
				}
				exerciseGate(t, st, hello, method, true, false, false)
				exerciseGate(t, st, hello, method, true, true, true)
				if err := st.SetStatus(fp, StatusApproved); err != nil {
					t.Fatal(err)
				}
				exerciseGate(t, st, hello, method, true, false, true)
				if err := st.SetStatus(fp, StatusBlocked); err != nil {
					t.Fatal(err)
				}
				exerciseGate(t, st, hello, method, true, false, false)
				exerciseGate(t, st, hello, method, true, true, true)
			})
		}
	}
}

func TestSMTPRequiresImplicitTLS(t *testing.T) {
	base := "smtp://audit@example.invalid:465/?from=audit@example.invalid&to=recipient@example.invalid&auth=None"
	for _, suffix := range []string{"", "&encryption=None&starttls=No", "&encryption=ExplicitTLS", "&encryption=Auto", "&encryption=2", "&encryption=ImplicitTLS&encryption=None", "&encryption=ImplicitTLS&Encryption=Auto", "&encryption=ImplicitTLS&disableTLS=yes", "&encryption=ImplicitTLS;encryption=None"} {
		t.Run(suffix, func(t *testing.T) {
			if err := requireSecureNotificationURL(base + suffix); err == nil {
				t.Fatal("accepted insecure or ambiguous SMTP configuration")
			}
			for _, mode := range []NotificationMode{NotificationModeFailover, NotificationModeBroadcast} {
				if _, err := newNotificationSender([]string{base + suffix}, mode); err == nil {
					t.Fatal("sender bypassed transport validation")
				}
			}
		})
	}
	for _, suffix := range []string{"&encryption=ImplicitTLS", "&Encryption=implicittls&starttls=No"} {
		if _, err := newNotificationSender([]string{base + suffix}, NotificationModeFailover); err != nil {
			t.Fatalf("secure URL: %v", err)
		}
	}
}

func TestSMTPDoesNotFallBackToPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		// A server without STARTTLS must not receive SMTP commands or alert content.
		_, _ = fmt.Fprint(c, "220 plaintext SMTP\r\n")
		b := make([]byte, 4096)
		n, _ := c.Read(b)
		received <- b[:n]
	}()
	raw := "smtp://audit@" + ln.Addr().String() + "/?from=audit@example.invalid&to=recipient@example.invalid&auth=None&encryption=ImplicitTLS"
	send, err := newNotificationSender([]string{raw}, NotificationModeFailover)
	if err != nil {
		t.Fatal(err)
	}
	if err := send("secret audit marker"); err == nil {
		t.Fatal("plaintext server accepted")
	}
	select {
	case b := <-received:
		if len(b) == 0 || b[0] != 0x16 || strings.Contains(string(b), "secret audit marker") || strings.Contains(string(b), "EHLO") {
			t.Fatalf("expected only TLS handshake, received %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no handshake")
	}
}

func TestSMTPVerifiesServerCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected HTTP request") }))
	defer server.Close()
	// The server's self-signed certificate is deliberately not trusted.
	raw := "smtp://audit@" + server.Listener.Addr().String() + "/?from=audit@example.invalid&to=recipient@example.invalid&auth=None&encryption=ImplicitTLS"
	send, err := newNotificationSender([]string{raw}, NotificationModeFailover)
	if err != nil {
		t.Fatal(err)
	}
	if err := send("audit marker"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate was not rejected: %v", err)
	}
}

func TestCanonicalFingerprintVectors(t *testing.T) {
	ch := &clientHello{version: 771, cipherSuites: []uint16{0x0a0a, 4865, 4866}, extensions: []uint16{0, 0x1a1a, 10}, ellipticCurves: []uint16{0x2a2a, 29}, ecPointFormats: []uint8{0}}
	_, raw := ja3FromHello(ch)
	if raw != "771,4865-4866,0-10,29,0" {
		t.Fatalf("noncanonical JA3: %q", raw)
	}
	before, _ := ja3FromHello(ch)
	ch.cipherSuites[0] = 0xfafa
	ch.extensions[1] = 0xeaea
	ch.ellipticCurves[0] = 0xdada
	after, _ := ja3FromHello(ch)
	if before != after {
		t.Fatal("GREASE rotation changes JA3")
	}
	for _, tc := range []struct{ alpn, want string }{
		{"", "00"}, {"h2", "h2"}, {"http/1.1", "h1"}, {"a", "aa"},
		{"\xab", "ab"}, {" ", "20"}, {"\xab\xcd", "ad"}, {" a", "21"},
		{"0\xab", "3b"}, {"a ", "60"}, {"01\xab\xcd", "3d"}, {"0\xab\xcd1", "01"},
		{"\n", "0a"}, {"é", "c9"},
	} {
		if got := ja4ALPN([]string{tc.alpn}); got != tc.want {
			t.Errorf("ALPN %q: got %q want %q", tc.alpn, got, tc.want)
		}
	}
}

func TestFingerprintFormatRequiresExplicitReset(t *testing.T) {
	for _, format := range []string{"", "1", "future"} {
		t.Run(format, func(t *testing.T) {
			st := newTestStore(t)
			defer st.Close()
			if err := st.SetMeta(metaFingerprintFormat, format); err != nil {
				t.Fatal(err)
			}
			if err := st.UpsertStatus("legacy", StatusApproved, "keep until reset"); err != nil {
				t.Fatal(err)
			}
			if _, err := reconcileFingerprintFormat(st, false); err == nil {
				t.Fatal("silently accepted old decisions")
			}
			entry, err := st.Get("legacy")
			if err != nil || entry.Label != "keep until reset" || entry.Status != StatusApproved {
				t.Fatalf("modified old decision: %+v %v", entry, err)
			}
			if got, err := st.GetMeta(metaFingerprintFormat); err != nil || got != format {
				t.Fatal("changed format after refused upgrade")
			}
			if err := registerStatus(st, strings.Repeat("a", 32), StatusApproved, "new"); err == nil {
				t.Fatal("registration mixed formats")
			}
			if n, err := reconcileFingerprintFormat(st, true); err != nil || n != 1 {
				t.Fatalf("reset: %d %v", n, err)
			}
			if err := registerStatus(st, strings.Repeat("a", 32), StatusApproved, "new"); err != nil {
				t.Fatal(err)
			}
			if n, err := reconcileFingerprintFormat(st, false); err != nil || n != 0 {
				t.Fatalf("canonical reopen: %d %v", n, err)
			}
		})
	}
	st := newTestStore(t)
	defer st.Close()
	if _, err := reconcileFingerprintFormat(st, false); err != nil {
		t.Fatalf("fresh database: %v", err)
	}
}

func TestAlertHistoryBoundCoversExistingAndConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	// Seed an old Gatekit database before TLSGate installs its retention trigger.
	old, err := store.Open(store.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?)
 INSERT INTO blocked_range_alerts SELECT 'watched', printf('old-%d',x), 'fp', '2026-01-01' FROM n`, maxBlockedRangeAlerts+100); err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	assertBound := func() {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM blocked_range_alerts`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != maxBlockedRangeAlerts {
			t.Fatalf("dedupe rows = %d, want %d", n, maxBlockedRangeAlerts)
		}
	}
	assertBound()
	if seen, err := st.HasBlockedRangeAlert("watched", "old-1"); err != nil || seen {
		t.Fatalf("old alert not evicted: %v %v", seen, err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for worker := range 4 {
		wg.Go(func() {
			for i := range 30 {
				if _, err := old.RecordBlockedRangeAlert("watched", fmt.Sprintf("new-%d-%d", worker, i), "fp"); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	assertBound()
	if seen, err := st.HasBlockedRangeAlert("watched", "new-0-29"); err != nil || !seen {
		t.Fatalf("new alert missing: %v %v", seen, err)
	}
	if inserted, err := st.RecordBlockedRangeAlert("watched", "new-0-29", "other-fp"); err != nil || inserted {
		t.Fatalf("duplicate: %v %v", inserted, err)
	}
	if inserted, err := st.RecordBlockedRangeAlert("watched", "old-1", "fp"); err != nil || !inserted {
		t.Fatalf("evicted pair cannot notify again: %v %v", inserted, err)
	}
	assertBound()
}
