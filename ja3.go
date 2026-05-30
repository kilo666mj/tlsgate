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

func isGREASE(v uint16) bool {
	return v&0xff == v>>8 && v&0x0f == 0x0a
}

func parseClientHello(data []byte) (*clientHello, error) {
	// data includes the 5-byte TLS record header
	if len(data) < 9 || data[0] != 0x16 || data[5] != 0x01 {
		return nil, fmt.Errorf("not a TLS ClientHello")
	}

	// Skip: record header (5) + handshake type (1) + handshake length (3)
	pos := 9

	if len(data) < pos+2 {
		return nil, fmt.Errorf("too short for version")
	}
	ch := &clientHello{
		version: uint16(data[pos])<<8 | uint16(data[pos+1]),
	}
	pos += 2

	pos += 32 // random

	if len(data) < pos+1 {
		return ch, nil
	}
	pos += 1 + int(data[pos]) // session ID

	if len(data) < pos+2 {
		return ch, nil
	}
	cipherLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	for i := 0; i < cipherLen && pos+2 <= len(data); i += 2 {
		ch.cipherSuites = append(ch.cipherSuites, uint16(data[pos])<<8|uint16(data[pos+1]))
		pos += 2
	}

	if len(data) < pos+1 {
		return ch, nil
	}
	pos += 1 + int(data[pos]) // compression methods

	if len(data) < pos+2 {
		return ch, nil
	}
	extEnd := pos + 2 + (int(data[pos])<<8 | int(data[pos+1]))
	pos += 2

	for pos+4 <= extEnd && pos+4 <= len(data) {
		extType := uint16(data[pos])<<8 | uint16(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if pos+extLen > len(data) {
			break
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

func computeJA3(data []byte) (fp string, ja3str string, err error) {
	ch, err := parseClientHello(data)
	if err != nil {
		return "", "", err
	}
	ja3str = strings.Join([]string{
		strconv.Itoa(int(ch.version)),
		u16str(ch.cipherSuites, true),
		u16str(ch.extensions, true),
		u16str(ch.ellipticCurves, true),
		u8str(ch.ecPointFormats),
	}, ",")
	sum := md5.Sum([]byte(ja3str))
	return hex.EncodeToString(sum[:]), ja3str, nil
}

// extractTLSMetadata parses a ClientHello and computes both fingerprints. It
// returns the fingerprint selected by method as fp — the key used for
// allow/block decisions — while meta carries both JA3 and JA4 for display.
func extractTLSMetadata(data []byte, method FingerprintMethod) (fp string, meta TLSMetadata, err error) {
	ch, err := parseClientHello(data)
	if err != nil {
		return "", TLSMetadata{}, err
	}
	meta.JA3 = strings.Join([]string{
		strconv.Itoa(int(ch.version)),
		u16str(ch.cipherSuites, true),
		u16str(ch.extensions, true),
		u16str(ch.ellipticCurves, true),
		u8str(ch.ecPointFormats),
	}, ",")
	meta.JA4 = computeJA4(ch)
	meta.SNI = ch.serverName
	meta.ALPN = ch.alpnProtocols
	meta.SupportedVersions = ch.supportedVersions
	meta.SignatureAlgorithms = ch.signatureAlgorithms

	if method == MethodJA4 {
		return meta.JA4, meta, nil
	}
	sum := md5.Sum([]byte(meta.JA3))
	return hex.EncodeToString(sum[:]), meta, nil
}
