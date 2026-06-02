package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

type clientHello struct {
	version             uint16
	cipherSuites        []uint16
	extensions          []uint16
	ellipticCurves      []uint16
	ecPointFormats      []uint8
	serverName          string
	alpnProtocols       []string
	supportedVersions   []uint16
	signatureAlgorithms []uint16
}

type TLSMetadata struct {
	JA3                 string   `json:"ja3,omitempty"`
	JA4                 string   `json:"ja4,omitempty"`
	SNI                 string   `json:"sni,omitempty"`
	ALPN                []string `json:"alpn,omitempty"`
	SupportedVersions   []uint16 `json:"supported_versions,omitempty"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`
}

// FingerprintMethod selects which fingerprint is used as the store key that
// allow/block decisions are made against.
type FingerprintMethod string

const (
	MethodJA3 FingerprintMethod = "ja3"
	MethodJA4 FingerprintMethod = "ja4"
)

// ParseFingerprintMethod validates a method name from a flag or config.
func ParseFingerprintMethod(s string) (FingerprintMethod, error) {
	switch FingerprintMethod(s) {
	case MethodJA3:
		return MethodJA3, nil
	case MethodJA4:
		return MethodJA4, nil
	default:
		return "", fmt.Errorf("unknown fingerprint method %q (want ja3 or ja4)", s)
	}
}

// isJA3Fingerprint reports whether s is a full JA3 hash: a 32-character
// lowercase hex MD5 digest as produced by ja3FromHello.
func isJA3Fingerprint(s string) bool {
	if len(s) != 32 {
		return false
	}
	return isLowerHex(s)
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func isGREASE(v uint16) bool {
	return v&0xff == v>>8 && v&0x0f == 0x0a
}

// parseClientHello strictly parses a complete ClientHello. data is a 5-byte
// TLS record header followed by the fully reassembled handshake message (see
// readClientHello). Every field is bounded by the handshake-message length
// declared in the header; any length that runs past it, or a buffer that does
// not contain the whole declared message, is rejected rather than parsed
// partially — so truncated or malformed handshakes do not pollute the store.
func parseClientHello(data []byte) (*clientHello, error) {
	if len(data) < 9 || data[0] != 0x16 || data[5] != 0x01 {
		return nil, fmt.Errorf("not a TLS ClientHello")
	}
	// Handshake message length (24-bit) sets the hard end of the message.
	hsLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	end := 9 + hsLen
	if len(data) < end {
		return nil, fmt.Errorf("truncated ClientHello: have %d handshake bytes, want %d", len(data)-9, hsLen)
	}

	pos := 9 // record header (5) + handshake type (1) + handshake length (3)
	// need reports whether n more bytes fit before the handshake message end.
	need := func(n int) bool { return pos+n <= end }

	if !need(2) {
		return nil, fmt.Errorf("malformed ClientHello: version")
	}
	ch := &clientHello{version: uint16(data[pos])<<8 | uint16(data[pos+1])}
	pos += 2

	if !need(32) {
		return nil, fmt.Errorf("malformed ClientHello: random")
	}
	pos += 32 // random

	if !need(1) {
		return nil, fmt.Errorf("malformed ClientHello: session id length")
	}
	sidLen := int(data[pos])
	pos++
	if !need(sidLen) {
		return nil, fmt.Errorf("malformed ClientHello: session id")
	}
	pos += sidLen

	if !need(2) {
		return nil, fmt.Errorf("malformed ClientHello: cipher suites length")
	}
	cipherLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	if cipherLen%2 != 0 || !need(cipherLen) {
		return nil, fmt.Errorf("malformed ClientHello: cipher suites")
	}
	for i := 0; i < cipherLen; i += 2 {
		ch.cipherSuites = append(ch.cipherSuites, uint16(data[pos])<<8|uint16(data[pos+1]))
		pos += 2
	}

	if !need(1) {
		return nil, fmt.Errorf("malformed ClientHello: compression length")
	}
	compLen := int(data[pos])
	pos++
	if !need(compLen) {
		return nil, fmt.Errorf("malformed ClientHello: compression methods")
	}
	pos += compLen

	// Extensions are optional (absent in older ClientHellos).
	if pos == end {
		return ch, nil
	}
	if !need(2) {
		return nil, fmt.Errorf("malformed ClientHello: extensions length")
	}
	extEnd := pos + 2 + (int(data[pos])<<8 | int(data[pos+1]))
	pos += 2
	if extEnd > end {
		return nil, fmt.Errorf("malformed ClientHello: extensions overrun")
	}

	for pos+4 <= extEnd {
		extType := uint16(data[pos])<<8 | uint16(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if pos+extLen > extEnd {
			return nil, fmt.Errorf("malformed ClientHello: extension 0x%04x body", extType)
		}
		ext := data[pos : pos+extLen]
		ch.extensions = append(ch.extensions, extType)

		switch extType {
		case 0x0000: // server_name
			ch.serverName = parseSNI(ext)
		case 0x000a: // supported_groups
			if len(ext) >= 2 {
				listLen := int(ext[0])<<8 | int(ext[1])
				for i := 2; i+2 <= 2+listLen && i+2 <= len(ext); i += 2 {
					ch.ellipticCurves = append(ch.ellipticCurves, uint16(ext[i])<<8|uint16(ext[i+1]))
				}
			}
		case 0x000b: // ec_point_formats
			if len(ext) >= 1 {
				for i := 1; i <= int(ext[0]) && i < len(ext); i++ {
					ch.ecPointFormats = append(ch.ecPointFormats, ext[i])
				}
			}
		case 0x000d: // signature_algorithms
			ch.signatureAlgorithms = parseU16List(ext)
		case 0x0010: // application_layer_protocol_negotiation
			ch.alpnProtocols = parseALPN(ext)
		case 0x002b: // supported_versions
			ch.supportedVersions = parseSupportedVersions(ext)
		}
		pos += extLen
	}

	return ch, nil
}

func parseSNI(ext []byte) string {
	if len(ext) < 2 {
		return ""
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	pos := 2
	end := min(len(ext), 2+listLen)
	for pos+3 <= end {
		nameType := ext[pos]
		nameLen := int(ext[pos+1])<<8 | int(ext[pos+2])
		pos += 3
		if pos+nameLen > end {
			return ""
		}
		if nameType == 0 {
			return string(ext[pos : pos+nameLen])
		}
		pos += nameLen
	}
	return ""
}

func parseALPN(ext []byte) []string {
	if len(ext) < 2 {
		return nil
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	pos := 2
	end := min(len(ext), 2+listLen)
	var protocols []string
	for pos < end {
		protoLen := int(ext[pos])
		pos++
		if pos+protoLen > end {
			return protocols
		}
		protocols = append(protocols, string(ext[pos:pos+protoLen]))
		pos += protoLen
	}
	return protocols
}

func parseSupportedVersions(ext []byte) []uint16 {
	if len(ext) == 2 {
		return []uint16{uint16(ext[0])<<8 | uint16(ext[1])}
	}
	if len(ext) < 1 {
		return nil
	}
	listLen := int(ext[0])
	var versions []uint16
	for i := 1; i+2 <= 1+listLen && i+2 <= len(ext); i += 2 {
		versions = append(versions, uint16(ext[i])<<8|uint16(ext[i+1]))
	}
	return versions
}

func parseU16List(ext []byte) []uint16 {
	if len(ext) < 2 {
		return nil
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	var values []uint16
	for i := 2; i+2 <= 2+listLen && i+2 <= len(ext); i += 2 {
		values = append(values, uint16(ext[i])<<8|uint16(ext[i+1]))
	}
	return values
}

func u16str(vals []uint16, skipGREASE bool) string {
	var parts []string
	for _, v := range vals {
		if skipGREASE && isGREASE(v) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, "-")
}

func u8str(vals []uint8) string {
	var parts []string
	for _, v := range vals {
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, "-")
}

// ja3FromHello builds the JA3 string and its md5 fingerprint from a parsed
// ClientHello. Per the canonical JA3 spec (Salesforce), GREASE values are NOT
// stripped — they are part of the fingerprinted byte sequence — so these
// hashes match external JA3 databases and threat feeds. (JA4, by contrast,
// deliberately strips GREASE; see computeJA4.)
func ja3FromHello(ch *clientHello) (fp string, ja3str string) {
	ja3str = strings.Join([]string{
		strconv.Itoa(int(ch.version)),
		u16str(ch.cipherSuites, false),
		u16str(ch.extensions, false),
		u16str(ch.ellipticCurves, false),
		u8str(ch.ecPointFormats),
	}, ",")
	sum := md5.Sum([]byte(ja3str))
	return hex.EncodeToString(sum[:]), ja3str
}

func computeJA3(data []byte) (fp string, ja3str string, err error) {
	ch, err := parseClientHello(data)
	if err != nil {
		return "", "", err
	}
	fp, ja3str = ja3FromHello(ch)
	return fp, ja3str, nil
}

// extractTLSMetadata parses a ClientHello and computes both fingerprints. It
// returns the fingerprint selected by method as fp — the key used for
// allow/block decisions — while meta carries both JA3 and JA4 for display.
func extractTLSMetadata(data []byte, method FingerprintMethod) (fp string, meta TLSMetadata, err error) {
	ch, err := parseClientHello(data)
	if err != nil {
		return "", TLSMetadata{}, err
	}
	ja3fp, ja3str := ja3FromHello(ch)
	meta.JA3 = ja3str
	meta.JA4 = computeJA4(ch)
	meta.SNI = ch.serverName
	meta.ALPN = ch.alpnProtocols
	meta.SupportedVersions = ch.supportedVersions
	meta.SignatureAlgorithms = ch.signatureAlgorithms

	if method == MethodJA4 {
		return meta.JA4, meta, nil
	}
	return ja3fp, meta, nil
}
