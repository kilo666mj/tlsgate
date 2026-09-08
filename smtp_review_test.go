package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSMTPReviewRealSTARTTLSAndEncryptedMessage(t *testing.T) {
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, "backend listener", backend.Close) })
	backendDone := make(chan error, 1)
	go func() {
		backendDone <- func() (err error) {
			c, err := backend.Accept()
			if err != nil {
				return err
			}
			defer closeWithError(&err, "close test backend connection", c.Close)
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = io.WriteString(c, "220-mx.example\r\n220 ready\r\n"); err != nil {
				return err
			}
			r := bufio.NewReader(c)
			if line, err := r.ReadString('\n'); err != nil || line != "EHLO sender.example\r\n" {
				return fmt.Errorf("EHLO %q: %v", line, err)
			}
			if _, err = io.WriteString(c, "250-mx.example\r\n250-PIPELINING\r\n250 STARTTLS\r\n"); err != nil {
				return err
			}
			if line, err := r.ReadString('\n'); err != nil || line != "STARTTLS\r\n" {
				return fmt.Errorf("STARTTLS %q: %v", line, err)
			}
			if _, err = io.WriteString(c, "220 ready for TLS\r\n"); err != nil {
				return err
			}
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err = tc.Handshake(); err != nil {
				return err
			}
			line, err := bufio.NewReader(tc).ReadString('\n')
			if err != nil || line != "EHLO encrypted.example\r\n" {
				return fmt.Errorf("encrypted payload %q: %v", line, err)
			}
			_, err = io.WriteString(tc, "250 encrypted reply\r\n")
			return err
		}()
	}()
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, "proxy listener", proxy.Close) })
	path := filepath.Join(t.TempDir(), "events.jsonl")
	w, err := newSMTPEventWriter(path, "review-mx")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		c, err := proxy.Accept()
		if err == nil {
			handleSMTPConn(c, backend.Addr().String(), 25, MethodJA4, nil, false, w)
		}
	}()
	c, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, "client connection", c.Close) })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	readReply := func(want string) {
		t.Helper()
		line, err := r.ReadString('\n')
		if err != nil || line != want {
			t.Fatalf("reply %q, want %q: %v", line, want, err)
		}
	}
	readReply("220-mx.example\r\n")
	readReply("220 ready\r\n")
	if _, err = io.WriteString(c, "EHLO sender.example\r\n"); err != nil {
		t.Fatal(err)
	}
	readReply("250-mx.example\r\n")
	readReply("250-PIPELINING\r\n")
	readReply("250 STARTTLS\r\n")
	if _, err = io.WriteString(c, "STARTTLS\r\n"); err != nil {
		t.Fatal(err)
	}
	readReply("220 ready for TLS\r\n")
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "mx.example"})
	if err = tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(tc, "EHLO encrypted.example\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil || line != "250 encrypted reply\r\n" {
		t.Fatalf("encrypted reply %q: %v", line, err)
	}
	_ = tc.Close()
	select {
	case err := <-backendDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not finish")
	}
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not drain")
	}
	w.Close()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, "SMTP event input", f.Close) })
	d := json.NewDecoder(f)
	found := false
	for {
		var e smtpEvent
		if err := d.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if e.Type == "fingerprint" {
			if e.JA3 == "" || e.JA4 == "" || e.Client != c.LocalAddr().String() {
				t.Fatalf("invalid fingerprint event: %+v", e)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("real STARTTLS handshake produced no fingerprint")
	}
}

func closeTestResource(t *testing.T, name string, closeFn func() error) {
	t.Helper()
	if err := closeFn(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close %s: %v", name, err)
	}
}

func TestSMTPReviewPipelinedMessageEndAndSTARTTLS(t *testing.T) {
	o := &smtpObserver{method: MethodJA4}
	o.server([]byte("220 ready\r\n"))
	o.client([]byte("EHLO test\r\nMAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n"))
	o.server([]byte("250-test\r\n250 PIPELINING\r\n250 OK\r\n250 OK\r\n354 send data\r\n"))
	o.client([]byte("Subject: STARTTLS\r\n\r\nSTARTTLS\r\n.\r\nSTARTTLS\r\n"))
	o.server([]byte("250 queued\r\n220 ready for TLS\r\n"))
	o.client(captureClientHello(t))
	if !o.fingerprinted {
		t.Fatal("message acceptance consumed the STARTTLS reply slot")
	}
}

func TestSMTPReviewCommandFloodBoundsObserver(t *testing.T) {
	o := &smtpObserver{method: MethodJA3}
	for i := 0; i < 2048; i++ {
		o.client([]byte("NOOP\r\n"))
	}
	if !o.disabled || len(o.commands) > 1024 {
		t.Fatalf("observer retained unbounded commands: disabled=%v count=%d", o.disabled, len(o.commands))
	}
}

func TestSMTPReviewBDATPayloadNeverBecomesCommand(t *testing.T) {
	o := &smtpObserver{method: MethodJA3}
	o.server([]byte("220 ready\r\n"))
	o.client([]byte("BDAT 10 LAST\r\nSTARTTLS\r\n"))
	o.server([]byte("220 fake payload response\r\n"))
	o.client(captureClientHello(t))
	if o.fingerprinted || !o.disabled {
		t.Fatal("unsupported BDAT flow was interpreted as STARTTLS")
	}
}

func TestSMTPReviewUnsolicitedGreetingDoesNotAcceptSTARTTLS(t *testing.T) {
	o := &smtpObserver{method: MethodJA3}
	o.client([]byte("STARTTLS\r\n"))
	o.server([]byte("220 mx greeting\r\n"))
	o.client([]byte(strings.Repeat("x", 10)))
	if o.tlsArmed {
		t.Fatal("initial greeting was mistaken for STARTTLS acceptance")
	}
}

func TestSMTPReviewDockerEnvelopeAndPayloadIsolation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "postfix.log")
	data := "2026-09-08T12:49:06.465911+02:00 mx 075f16ca663a[3583390]: Sep  8 12:49:06 075f16ca663a postfix/smtpd[40735]: connect from unknown[167.71.57.227]:33700\n" +
		"2026-09-08T12:49:07.465911+02:00 mx 075f16ca663a[3583390]: Sep  8 12:49:07 075f16ca663a postfix/smtpd[40735]: ABC123: client=unknown[167.71.57.227]:33700\n" +
		"2026-09-08T12:49:08.465911+02:00 mx postfix/smtpd[40735]: warning: non-SMTP command: postfix/smtpd[40735]: FAKE123: client=unknown[167.71.57.227]:33700\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	ms, err := readPostfixMessages(path, "mx")
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].QueueID != "ABC123" {
		t.Fatalf("wanted real wrapped message only, got %+v", ms)
	}
}

func TestSMTPReviewDistinctVerdictsRemainAmbiguous(t *testing.T) {
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	vs := []smtpVerdict{
		{Instance: "mx", QueueID: "ABC123", Timestamp: at.Add(time.Second), Classification: "spam", Score: 12},
		{Instance: "mx", QueueID: "ABC123", Timestamp: at.Add(2 * time.Second), Classification: "spam", Score: 25},
	}
	if _, ok := boundedVerdict(vs, at, time.Hour); ok {
		t.Fatal("different verdict events with the same classification were guessed to be the same message")
	}
}

func TestSMTPReviewOldQueueVerdictDoesNotMatchNewMessage(t *testing.T) {
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	vs := []smtpVerdict{{Instance: "mx", QueueID: "ABC123", Timestamp: at.Add(-time.Minute), Classification: "spam", Score: 12}}
	if _, ok := boundedVerdict(vs, at, time.Hour); ok {
		t.Fatal("a verdict preceding the message was matched to a reused queue ID")
	}
}

func TestSMTPReviewQueueWithoutConnectRemainsVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "postfix.log")
	data := "2026-09-08T12:49:07Z mx postfix/smtpd[40735]: ABC123: client=unknown[167.71.57.227]:33700\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	ms, err := readPostfixMessages(path, "mx")
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].QueueID != "ABC123" {
		t.Fatalf("message with missing connect disappeared: %+v", ms)
	}
}

func TestSMTPReviewTransportAndMissingTelemetry(t *testing.T) {
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	c := smtpConnRecord{Start: at, End: at.Add(time.Minute), Accepted: at.Add(10 * time.Second), TLS: at.Add(11 * time.Second), JA3: "j3", JA4: "j4", State: "fingerprinted"}
	for _, test := range []struct {
		offset time.Duration
		want   string
	}{
		{5 * time.Second, "plaintext"}, {10 * time.Second, "unknown"}, {20 * time.Second, "starttls"},
	} {
		if got := messageSMTPTransport(c, at.Add(test.offset), time.Second); got != test.want {
			t.Fatalf("offset %v: got %s want %s", test.offset, got, test.want)
		}
	}
	c.Accepted = time.Time{}
	if c.completeObservation() || messageSMTPTransport(c, at.Add(20*time.Second), time.Second) != "unknown" {
		t.Fatal("lost STARTTLS event was treated as a complete observation")
	}
}

func TestSMTPReviewConflictingEventsInvalidateConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	first := smtpEvent{Version: 1, Type: "start", Instance: "mx", ConnectionID: "c", Timestamp: time.Now().UTC(), Client: "127.0.0.1:1234", Listener: "127.0.0.1:25"}
	second := first
	second.Client = "127.0.0.2:1234"
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if err := os.WriteFile(path, append(append(append(a, '\n'), b...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	cs, bad, err := readSMTPConnectionsStats(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || !cs[0].Invalid || bad != 1 {
		t.Fatalf("conflicting identity: %+v bad=%d", cs, bad)
	}
}

func TestSMTPReviewInputBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxSMTPBatchBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err = newSMTPBatchScanner(path); err == nil {
		t.Fatal("oversized input accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("\n", maxSMTPBatchLines+1)), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := newSMTPBatchScanner(path)
	if err != nil {
		t.Fatal(err)
	}
	for s.Scan() {
	}
	if s.Err() == nil {
		t.Fatal("excess input records accepted")
	}
	if err := os.WriteFile(path, []byte("unfinished record"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = newSMTPBatchScanner(path); err == nil {
		t.Fatal("truncated snapshot accepted")
	}
}

func TestSMTPReviewEventWriterConcurrentClose(t *testing.T) {
	w, err := newSMTPEventWriter(filepath.Join(t.TempDir(), "events.jsonl"), "mx")
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() {
			for j := 0; j < 100; j++ {
				w.emit(smtpEvent{Type: "start", Timestamp: time.Now().UTC()})
			}
		})
	}
	w.Close()
	group.Wait()
	w.emit(smtpEvent{})
	w.Close()
}
