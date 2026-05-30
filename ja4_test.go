package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// sampleHello is a small but realistic ClientHello: TLS 1.3 offered via
// supported_versions, SNI present, ALPN h2, a couple of ciphers and
// extensions, with GREASE values salted in to confirm they are dropped.
func sampleHello() *clientHello {
	return &clientHello{
		version:             0x0303, // legacy record version TLS 1.2
		cipherSuites:        []uint16{0x0a0a /*GREASE*/, 0x1302, 0x1301, 0x1303},
		extensions:          []uint16{0x0a0a /*GREASE*/, 0x002b, 0x0000, 0x0010, 0x000d, 0x000a},
		serverName:          "mail.example.com",
		alpnProtocols:       []string{"h2", "http/1.1"},
		supportedVersions:   []uint16{0x0a0a /*GREASE*/, 0x0304, 0x0303},
		signatureAlgorithms: []uint16{0x0403, 0x0804, 0x0a0a /*GREASE*/},
	}
}

func TestComputeJA4(t *testing.T) {
	got := computeJA4(sampleHello())

	// Section a: t (TCP) + 13 (TLS1.3 from supported_versions) + d (SNI)
	// + 03 ciphers (GREASE dropped) + 05 extensions (GREASE dropped, SNI
	// and ALPN still counted) + h2 (first ALPN).
	wantA := "t13d0305h2"

	// Section b: sorted non-GREASE ciphers.
	wantB := hash12("1301,1302,1303")

	// Section c: sorted non-GREASE extensions with SNI (0000) and ALPN
	// (0010) removed, then "_", then signature algorithms in order.
	wantC := hash12("000a,000d,002b_0403,0804")

	want := wantA + "_" + wantB + "_" + wantC
	if got != want {
		t.Fatalf("computeJA4 = %q, want %q", got, want)
	}
}

// TestComputeJA4OrderStable is the property that motivates JA4 over JA3:
// shuffling the extension order must not change the fingerprint.
func TestComputeJA4OrderStable(t *testing.T) {
	a := sampleHello()
	b := sampleHello()
	b.extensions = []uint16{0x000a, 0x0000, 0x000d, 0x0010, 0x002b, 0x0a0a}
	b.cipherSuites = []uint16{0x1303, 0x0a0a, 0x1301, 0x1302}
	if computeJA4(a) != computeJA4(b) {
		t.Fatalf("JA4 changed under reordering: %q vs %q", computeJA4(a), computeJA4(b))
	}
}

func TestJA4Pieces(t *testing.T) {
	if v := ja4Version(&clientHello{version: 0x0303}); v != "12" {
		t.Errorf("legacy TLS1.2 version = %q, want 12", v)
	}
	if v := ja4Version(&clientHello{version: 0x0303, supportedVersions: []uint16{0x0a0a, 0x0304}}); v != "13" {
		t.Errorf("supported_versions TLS1.3 = %q, want 13", v)
	}
	if c := ja4Count(150); c != "99" {
		t.Errorf("count cap = %q, want 99", c)
	}
	if a := ja4ALPN(nil); a != "00" {
		t.Errorf("no ALPN = %q, want 00", a)
	}
	if a := ja4ALPN([]string{"http/1.1"}); a != "h1" {
		t.Errorf("http/1.1 ALPN = %q, want h1", a)
	}
	if s := ja4HexList([]uint16{0x1302, 0x1301}); s != "1302,1301" {
		t.Errorf("ja4HexList does not sort here = %q (sorting is the caller's job)", s)
	}
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
