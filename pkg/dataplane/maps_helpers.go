package dataplane

import (
	"encoding/binary"
	"net"
)

// Shared map-key encoding helpers.
// Same-package split of maps.go (#1686): byte-order + IP conversion helpers
// used by both the map accessors and compiler*.go. They must stay in package
// dataplane (referenced by compiler_nat.go / compiler_filter.go / compiler.go).

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ipToUint32BE converts a net.IP to a uint32 matching the in-memory layout
// that BPF programs use when copying __be32 fields (e.g. iph->daddr).
// The IP address bytes are stored as-is; on little-endian hosts this means
// the uint32 numeric value differs from the big-endian interpretation, but
// the byte pattern in the BPF map key matches what BPF writes.
func ipToUint32BE(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.NativeEndian.Uint32(ip4)
}

// ipTo16Bytes converts a net.IP to a [16]byte array.
func ipTo16Bytes(ip net.IP) [16]byte {
	var b [16]byte
	copy(b[:], ip.To16())
	return b
}
