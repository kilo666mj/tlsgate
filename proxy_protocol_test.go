package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyV2HeaderIPv4(t *testing.T) {
	header, err := proxyV2Header(
		&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 54321},
		&net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 443},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != 28 {
		t.Fatalf("header length = %d, want 28", len(header))
	}
	if !bytes.Equal(header[:12], proxyV2Signature[:]) {
		t.Fatal("missing PROXY v2 signature")
	}
	if header[12] != 0x21 || header[13] != 0x11 {
		t.Fatalf("version/command/family = %x %x, want 21 11", header[12], header[13])
	}
	if got := net.IP(header[16:20]).String(); got != "192.0.2.10" {
		t.Fatalf("source IP = %s", got)
	}
	if got := net.IP(header[20:24]).String(); got != "198.51.100.20" {
		t.Fatalf("destination IP = %s", got)
	}
	if got := binary.BigEndian.Uint16(header[24:26]); got != 54321 {
		t.Fatalf("source port = %d", got)
	}
	if got := binary.BigEndian.Uint16(header[26:28]); got != 443 {
		t.Fatalf("destination port = %d", got)
	}
}

func TestProxyV2HeaderIPv6(t *testing.T) {
	header, err := proxyV2Header(
		&net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 1234},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != 52 || header[13] != 0x21 {
		t.Fatalf("IPv6 header length/family = %d/%x, want 52/21", len(header), header[13])
	}
	if got := net.IP(header[16:32]).String(); got != "2001:db8::10" {
		t.Fatalf("source IP = %s", got)
	}
	if got := net.IP(header[32:48]).String(); got != "2001:db8::20" {
		t.Fatalf("destination IP = %s", got)
	}
}

func TestProxyV2HeaderRejectsMixedFamilies(t *testing.T) {
	_, err := proxyV2Header(
		&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::20"), Port: 443},
	)
	if err == nil {
		t.Fatal("mixed address families accepted")
	}
}

func TestHandleConnWritesProxyV2BeforeUntouchedTLS(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	frontend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontend.Close()

	st := newTestStore(t)
	go func() {
		conn, acceptErr := frontend.Accept()
		if acceptErr == nil {
			handleConn(conn, backend.Addr().String(), 443, st, false, MethodJA3, nil, nil, &ipAllowlist{}, true)
		}
	}()

	client, err := net.Dial("tcp4", frontend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write(truncatedClientHello); err != nil {
		t.Fatal(err)
	}

	upstream, err := backend.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	if err := upstream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 28+len(truncatedClientHello))
	if _, err := io.ReadFull(upstream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:12], proxyV2Signature[:]) {
		t.Fatal("backend stream does not begin with PROXY v2")
	}
	if !bytes.Equal(got[28:], truncatedClientHello) {
		t.Fatalf("TLS bytes changed: got %x, want %x", got[28:], truncatedClientHello)
	}
}
