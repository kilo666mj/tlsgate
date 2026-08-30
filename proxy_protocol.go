package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

var proxyV2Signature = [12]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

// proxyV2Header describes the original client-to-listener TCP connection.
// It is written to the backend immediately before the untouched TLS stream.
func proxyV2Header(source, destination net.Addr) ([]byte, error) {
	src, ok := source.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("source address %T is not TCP", source)
	}
	dst, ok := destination.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("destination address %T is not TCP", destination)
	}

	src4, dst4 := src.IP.To4(), dst.IP.To4()
	if src4 != nil && dst4 != nil {
		header := make([]byte, 28)
		copy(header[:12], proxyV2Signature[:])
		header[12] = 0x21 // version 2, PROXY command
		header[13] = 0x11 // AF_INET, STREAM
		binary.BigEndian.PutUint16(header[14:16], 12)
		copy(header[16:20], src4)
		copy(header[20:24], dst4)
		binary.BigEndian.PutUint16(header[24:26], uint16(src.Port))
		binary.BigEndian.PutUint16(header[26:28], uint16(dst.Port))
		return header, nil
	}

	src6, dst6 := src.IP.To16(), dst.IP.To16()
	if src6 == nil || dst6 == nil || src4 != nil || dst4 != nil {
		return nil, fmt.Errorf("source and destination address families differ")
	}
	header := make([]byte, 52)
	copy(header[:12], proxyV2Signature[:])
	header[12] = 0x21 // version 2, PROXY command
	header[13] = 0x21 // AF_INET6, STREAM
	binary.BigEndian.PutUint16(header[14:16], 36)
	copy(header[16:32], src6)
	copy(header[32:48], dst6)
	binary.BigEndian.PutUint16(header[48:50], uint16(src.Port))
	binary.BigEndian.PutUint16(header[50:52], uint16(dst.Port))
	return header, nil
}
