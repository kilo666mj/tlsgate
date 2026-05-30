package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// tlsRecord wraps payload in a handshake (0x16) TLS record.
func tlsRecord(payload []byte) []byte {
	return append([]byte{0x16, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func TestReadClientHelloReassemblesMultipleRecords(t *testing.T) {
	hello := captureClientHello(t) // 5-byte record header + handshake message
	body := hello[5:]
	wantFP, _, err := extractTLSMetadata(hello, MethodJA4)
	if err != nil {
		t.Fatalf("baseline extractTLSMetadata: %v", err)
	}

	// Split the single handshake message across two TLS records.
	k := len(body) / 2
	stream := append(tlsRecord(body[:k]), tlsRecord(body[k:])...)

	server, client := net.Pipe()
	defer client.Close()
	go func() {
		server.Write(stream)
		server.Close()
	}()
	client.SetReadDeadline(time.Now().Add(2 * time.Second))

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatalf("read first header: %v", err)
	}
	parseBuf, raw, err := readClientHello(client, hdr)
	if err != nil {
		t.Fatalf("readClientHello: %v", err)
	}
	if !bytes.Equal(raw, stream) {
		t.Fatalf("raw forwarded bytes (%d) do not match the input stream (%d)", len(raw), len(stream))
	}
	// Reassembled buffer must reconstruct the original hello and fingerprint.
	gotFP, meta, err := extractTLSMetadata(parseBuf, MethodJA4)
	if err != nil {
		t.Fatalf("extractTLSMetadata on reassembled: %v", err)
	}
	if gotFP != wantFP {
		t.Fatalf("reassembled fingerprint %q != single-record %q", gotFP, wantFP)
	}
	if meta.SNI != "mail.example.com" {
		t.Fatalf("SNI = %q, want mail.example.com", meta.SNI)
	}
}

func TestParseClientHelloRejectsTruncated(t *testing.T) {
	hello := captureClientHello(t)
	bad := append([]byte{}, hello...)
	// Inflate the declared handshake length by one so the buffer no longer
	// contains the whole message: strict parsing must reject it.
	hsLen := int(bad[6])<<16 | int(bad[7])<<8 | int(bad[8])
	hsLen++
	bad[6], bad[7], bad[8] = byte(hsLen>>16), byte(hsLen>>8), byte(hsLen)

	if _, err := parseClientHello(bad); err == nil {
		t.Fatal("expected error for truncated ClientHello, got nil")
	}
}
