package main

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestExtractTLSMetadata(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		tlsConn := tls.Client(client, &tls.Config{
			ServerName:         "mail.example.com",
			NextProtos:         []string{"imap"},
			InsecureSkipVerify: true,
		})
		_ = tlsConn.Handshake()
		tlsConn.Close()
	}()

	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	bodyLen := int(header[3])<<8 | int(header[4])
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	server.Close()
	<-done

	fp, meta, err := extractTLSMetadata(append(header, body...), MethodJA3)
	if err != nil {
		t.Fatalf("extractTLSMetadata: %v", err)
	}
	if fp == "" || meta.JA3 == "" {
		t.Fatalf("missing JA3 fingerprint: fp=%q ja3=%q", fp, meta.JA3)
	}
	if meta.SNI != "mail.example.com" {
		t.Fatalf("SNI = %q, want mail.example.com", meta.SNI)
	}
	if len(meta.ALPN) != 1 || meta.ALPN[0] != "imap" {
		t.Fatalf("ALPN = %v, want [imap]", meta.ALPN)
	}
	if len(meta.SupportedVersions) == 0 {
		t.Fatal("missing supported TLS versions")
	}
	if len(meta.SignatureAlgorithms) == 0 {
		t.Fatal("missing signature algorithms")
	}
}

func TestComputeJA3(t *testing.T) {
	hello := captureClientHello(t)
	fp, ja3, err := computeJA3(hello)
	if err != nil {
		t.Fatalf("computeJA3: %v", err)
	}
	if ja3 == "" {
		t.Fatal("empty JA3 string")
	}
	if len(fp) != 32 {
		t.Fatalf("fingerprint = %q, want 32-char md5 hex", fp)
	}
}
