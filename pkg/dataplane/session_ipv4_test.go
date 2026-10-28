package dataplane

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestSessionIPv4Decode17188 pins the session-field IPv4 decode
// (#17188): the stored u32 is network-order octets held in a
// native-endian word (the Rust publisher's u32::from_ne_bytes), so
// SessionIPv4 must hand back exactly the octets the publisher read —
// on any host endianness. The zero input pins the documented
// pure-decode contract (0.0.0.0, not nil; presence policy stays at
// callers).
func TestSessionIPv4Decode17188(t *testing.T) {
	cases := []struct {
		name string
		in   uint32
		want net.IP
	}{
		{"10.0.0.1", binary.NativeEndian.Uint32([]byte{10, 0, 0, 1}), net.IPv4(10, 0, 0, 1)},
		{"203.0.113.10", binary.NativeEndian.Uint32([]byte{203, 0, 113, 10}), net.IPv4(203, 0, 113, 10)},
		{"192.168.1.254", binary.NativeEndian.Uint32([]byte{192, 168, 1, 254}), net.IPv4(192, 168, 1, 254)},
		{"zero", 0, net.IPv4(0, 0, 0, 0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SessionIPv4(tc.in); !got.Equal(tc.want) {
				t.Errorf("SessionIPv4(%d) = %v, want %v", tc.in, got, tc.want)
			}
			if got := SessionIPv4(tc.in).String(); got != tc.want.String() {
				t.Errorf("SessionIPv4(%d).String() = %q, want %q", tc.in, got, tc.want.String())
			}
		})
	}
}

// TestSessionValueNATAddr17188 pins NATSrcAddr/NATDstAddr as the
// SessionIPv4 decode of the raw NATSrcIP/NATDstIP fields: distinct
// src/dst encodings must not cross, and both must agree with the
// free function on the same fields.
func TestSessionValueNATAddr17188(t *testing.T) {
	v := SessionValue{
		NATSrcIP: binary.NativeEndian.Uint32([]byte{10, 0, 0, 1}),
		NATDstIP: binary.NativeEndian.Uint32([]byte{192, 0, 2, 55}),
	}
	if got := v.NATSrcAddr(); got.String() != "10.0.0.1" {
		t.Errorf("NATSrcAddr() = %v, want 10.0.0.1", got)
	}
	if got := v.NATDstAddr(); got.String() != "192.0.2.55" {
		t.Errorf("NATDstAddr() = %v, want 192.0.2.55", got)
	}
	if !v.NATSrcAddr().Equal(SessionIPv4(v.NATSrcIP)) {
		t.Errorf("NATSrcAddr() = %v, SessionIPv4(NATSrcIP) = %v", v.NATSrcAddr(), SessionIPv4(v.NATSrcIP))
	}
	if !v.NATDstAddr().Equal(SessionIPv4(v.NATDstIP)) {
		t.Errorf("NATDstAddr() = %v, SessionIPv4(NATDstIP) = %v", v.NATDstAddr(), SessionIPv4(v.NATDstIP))
	}
}
