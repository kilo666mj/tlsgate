package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// computeJA4 builds the JA4 TLS client fingerprint from a parsed ClientHello.
//
// Format: a_b_c
//
//	a = [proto][tlsver][sni][ciphercount][extcount][alpn]   (human-readable)
//	b = sha256(sorted cipher suites)[:12]
//	c = sha256(sorted extensions "_" signature algorithms)[:12]
//
// Unlike JA3, ciphers and extensions are sorted before hashing, so a client
// that shuffles its extension order (GREASE, deliberate randomization) still
// yields a stable fingerprint. We only ever proxy TCP, so the protocol is
// always "t".
func computeJA4(ch *clientHello) string {
	var (
		ciphers []uint16
		exts    []uint16
		sigAlgs []uint16
	)
	for _, c := range ch.cipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	extCount := 0
	for _, e := range ch.extensions {
		if isGREASE(e) {
			continue
		}
		extCount++
		// SNI (0x0000) and ALPN (0x0010) are counted in section a but
		// excluded from the section c hash, since their values already
		// surface in the readable prefix.
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		exts = append(exts, e)
	}
	for _, s := range ch.signatureAlgorithms {
		if !isGREASE(s) {
			sigAlgs = append(sigAlgs, s)
		}
	}

	sni := "i"
	if ch.serverName != "" {
		sni = "d"
	}
	a := fmt.Sprintf("t%s%s%s%s%s",
		ja4Version(ch),
		sni,
		ja4Count(len(ciphers)),
		ja4Count(extCount),
		ja4ALPN(ch.alpnProtocols),
	)

	// JA4 spec: an empty cipher or extension list hashes to literal zeros
	// rather than sha256(""), so absence is distinguishable and interop with
	// other JA4 tooling holds.
	b := ja4HashSection(ja4HexList(sortU16(ciphers)))

	rawC := ja4HexList(sortU16(exts)) + "_" + ja4HexList(sigAlgs)
	c := ja4HashSection(rawC)

	return a + "_" + b + "_" + c
}

// ja4HashSection hashes a section to 12 hex chars, returning the JA4 sentinel
// of 12 zeros when the section has no values to hash.
func ja4HashSection(s string) string {
	if s == "" {
		return "000000000000"
	}
	return ja4Hash12(s)
}

// ja4Version maps the negotiated TLS version (highest non-GREASE value from
// the supported_versions extension, falling back to the legacy record
// version) to its 2-character JA4 code.
func ja4Version(ch *clientHello) string {
	v := ch.version
	for _, sv := range ch.supportedVersions {
		if isGREASE(sv) {
			continue
		}
		if sv > v {
			v = sv
		}
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

func ja4Count(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// ja4ALPN returns the first and last character of the first ALPN protocol
// (e.g. "h2" -> "h2", "http/1.1" -> "h1"), or "00" when no ALPN is offered.
func ja4ALPN(protocols []string) string {
	if len(protocols) == 0 || protocols[0] == "" {
		return "00"
	}
	p := protocols[0]
	r := []rune(p)
	return string(r[0]) + string(r[len(r)-1])
}

func sortU16(vals []uint16) []uint16 {
	out := append([]uint16(nil), vals...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func ja4HexList(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func ja4Hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
