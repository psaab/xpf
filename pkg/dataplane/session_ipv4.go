package dataplane

import (
	"encoding/binary"
	"net"
)

// Session-field IPv4 decode (#17188, R4-Q50-05).
//
// Session-map values hold IPv4 addresses in network order read as a
// NATIVE-endian u32: the Rust helper publishes u32::from_ne_bytes(octets)
// and cilium/ebpf decodes native-endian. SessionValue.NATSrcIP /
// NATDstIP are exactly that encoding, so their decode belongs with the
// type in this package — not copied per front end.
//
// History is the reason: the NativeEndian fix reached the grpcapi copy
// in 8162f9fac7 (2026-02-10) while the pkg/cli and pkg/api copies kept
// the old BigEndian decode until 2026-06-10 (b874c4f33f, 5dee4d9787),
// so for four months the local CLI and REST session views reversed NAT
// IPv4 addresses on little-endian hosts while gRPC was correct. One
// decoder, owned here, cannot diverge that way.
//
// Do NOT use pkg/nat's bigEndianPoolUint32ToIP for these fields:
// that helper decodes deterministic-NAT pool-numeric u32s (Rust
// u32::from(Ipv4Addr), big-endian on every CPU), the opposite
// semantics under a formerly identical name.

// SessionIPv4 decodes a session-field IPv4 u32 (SessionValue.NATSrcIP /
// NATDstIP encoding: network-order octets held in a native-endian u32,
// the from_ne_bytes mirror of the Rust publisher) to net.IP.
//
// Zero decodes to 0.0.0.0, not nil: callers that treat zero as "no NAT
// address" keep that check at the call site (the session-sync request
// builder does), so this function stays a pure decode with no
// presence policy baked in.
func SessionIPv4(u uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, u)
	return ip
}

// NATSrcAddr is the decoded NAT source address of a session value.
func (v SessionValue) NATSrcAddr() net.IP { return SessionIPv4(v.NATSrcIP) }

// NATDstAddr is the decoded NAT destination address of a session value.
func (v SessionValue) NATDstAddr() net.IP { return SessionIPv4(v.NATDstIP) }
