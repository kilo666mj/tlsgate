package main

import (
	"bytes"
	"log"
	"net"
	"strings"
	"testing"
)

func captureSMTPJournal(t *testing.T) *bytes.Buffer {
	t.Helper()
	old := log.Writer()
	var output bytes.Buffer
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(old) })
	return &output
}

func TestSMTPJournalWithoutJSONL(t *testing.T) {
	hello := captureClientHello(t)
	output := captureSMTPJournal(t)
	o := &smtpObserver{method: MethodJA4, base: smtpEvent{ConnectionID: "test-connection", Client: "192.0.2.1:12345", Listener: "192.0.2.2:25"}}
	o.server([]byte("220 ready\r\n"))
	o.client([]byte("EHLO private.example\r\nSTARTTLS\r\n"))
	o.server([]byte("250 ok\r\n220 ready\r\n"))
	o.client(hello)
	lines := output.String()
	for _, want := range []string{"OBSERVED smtp", `event="starttls"`, `state="accepted"`, `event="fingerprint"`, `connection_id="test-connection"`, `ja3="`, `ja4="`} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %s in %s", want, lines)
		}
	}
	if strings.Contains(lines, "private.example") || strings.Contains(lines, "APPROVED") || strings.Contains(lines, "PENDING") {
		t.Fatalf("unexpected SMTP command or policy status in journal: %s", lines)
	}
}

func TestSMTPJournalRefusedSTARTTLS(t *testing.T) {
	output := captureSMTPJournal(t)
	o := &smtpObserver{base: smtpEvent{ConnectionID: "refused"}}
	o.server([]byte("220 ready\r\n"))
	o.client([]byte("STARTTLS\r\n"))
	o.server([]byte("454 private server explanation\r\n"))
	if !strings.Contains(output.String(), `state="refused"`) || strings.Contains(output.String(), "private server explanation") {
		t.Fatalf("unexpected refusal log: %s", output.String())
	}
}

func TestSMTPJournalEndsFailedBackendConnection(t *testing.T) {
	output := captureSMTPJournal(t)
	client, peer := net.Pipe()
	t.Cleanup(func() { closeTestResource(t, "pipe peer", peer.Close) })
	// A missing port fails immediately without a network connection.
	handleSMTPConn(client, "invalid-backend", 25, MethodJA4, nil, false, nil)
	for _, want := range []string{`event="start"`, `event="end"`, `state="observer_incomplete"`, `reason="backend_connect_failed"`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %s in %s", want, output.String())
		}
	}
}

func TestSMTPJournalEscapesFields(t *testing.T) {
	output := captureSMTPJournal(t)
	logSMTPEvent("OBSERVED", smtpEvent{Type: "end", Client: "attacker\nFORGED", ConnectionID: "quote\"", State: "no_observed_upgrade"})
	if strings.Count(output.String(), "\n") != 1 {
		t.Fatalf("multiline journal entry: %q", output.String())
	}
}
