package main

import (
	"testing"
	"time"
)

func TestSMTPObserverSTARTTLSFragmented(t *testing.T) {
	o := &smtpObserver{method: MethodJA3}
	o.server([]byte("220 mx.example\r\n"))
	o.client([]byte("EHLO sender.example\r\nSTART"))
	o.client([]byte("TLS\r\n"))
	o.server([]byte("250-mx.example\r\n250 STARTTLS\r\n220 2.0.0 Ready\r\n"))
	if !o.tlsArmed {
		t.Fatal("STARTTLS was not armed")
	}
	hello := captureClientHello(t)
	for _, b := range hello {
		o.client([]byte{b})
	}
	if !o.fingerprinted {
		t.Fatal("fragmented ClientHello was not fingerprinted")
	}
}

func TestSMTPObserverDoesNotParseDATAAsSTARTTLS(t *testing.T) {
	o := &smtpObserver{method: MethodJA3}
	o.server([]byte("220 mx.example\r\n"))
	o.client([]byte("DATA\r\n"))
	o.server([]byte("354 End data\r\n"))
	o.client([]byte("Subject: test\r\n\r\nSTARTTLS\r\n.\r\n"))
	o.server([]byte("250 queued\r\n"))
	if o.tlsArmed {
		t.Fatal("STARTTLS in DATA body armed observer")
	}
	o.client([]byte("STARTTLS\r\n"))
	o.server([]byte("220 ready\r\n"))
	if !o.tlsArmed {
		t.Fatal("command after DATA was misaligned")
	}
}

func TestSMTPObserverRefusalDoesNotArm(t *testing.T) {
	o := &smtpObserver{method: MethodJA3}
	o.server([]byte("220 mx.example\r\n"))
	o.client([]byte("STARTTLS\r\n"))
	o.server([]byte("454 TLS unavailable\r\n"))
	if o.tlsArmed {
		t.Fatal("refused STARTTLS armed observer")
	}
}

func TestClientHelloFromBytesReassemblesRecords(t *testing.T) {
	hello := captureClientHello(t)
	fragmented := fragmentHandshake(hello, 2)
	for i := range fragmented {
		p, ok, err := clientHelloFromBytes(fragmented[:i+1])
		if err != nil {
			t.Fatal(err)
		}
		if ok && len(p) == 0 {
			t.Fatal("complete result was empty")
		}
	}
	p, ok, err := clientHelloFromBytes(fragmented)
	if err != nil || !ok {
		t.Fatalf("complete=%t err=%v", ok, err)
	}
	if _, _, err := extractTLSMetadata(p, MethodJA4); err != nil {
		t.Fatal(err)
	}
	_ = time.Second
}
