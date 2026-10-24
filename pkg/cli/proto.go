// Protocol name and small numeric helpers shared across presenters
// (session display, RPC translation, byte-order conversions, monotonic
// clock). `capitalizeFirst` lives here for now because it has no other
// consumer; see #1444 plan dead-code carriage note.
package cli

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/dataplane"
	"golang.org/x/sys/unix"
)

// protoNameFromNum maps a numeric IP protocol to a lowercase short name.
func protoNameFromNum(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 4:
		return "ipip"
	case 41:
		return "ipv6"
	case dataplane.ProtoICMPv6:
		return "icmpv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// protoNameToID converts a protocol name (e.g. "TCP") to its numeric string ("6").
func protoNameToID(name string) string {
	switch strings.ToUpper(name) {
	case "TCP":
		return "6"
	case "UDP":
		return "17"
	case "ICMP":
		return "1"
	case "GRE":
		return "47"
	case "ICMPV6":
		return "58"
	default:
		return name
	}
}

// protoNumFromName is the numeric inverse of protoNameFromNum for the
// names the session surfaces emit (#16110 tuple join). An unrecognized
// name yields 0, which simply never matches a local tuple.
func protoNumFromName(name string) uint8 {
	switch strings.ToLower(name) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "gre":
		return 47
	case "esp":
		return 50
	case "ipip":
		return 4
	case "ipv6":
		return 41
	case "icmpv6":
		return 58
	default:
		if n, err := strconv.Atoi(name); err == nil && n >= 0 && n <= 255 {
			return uint8(n)
		}
		return 0
	}
}

// splitAddrPort splits "addr:port" into address and port strings.
// Handles IPv6 bracket notation like "[::1]:443".
func splitAddrPort(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	// IPv6 bracket notation: [addr]:port
	if strings.HasPrefix(s, "[") {
		idx := strings.LastIndex(s, "]:")
		if idx >= 0 {
			return s[1:idx], s[idx+2:]
		}
		return strings.Trim(s, "[]"), ""
	}
	// IPv4: last colon separates addr:port
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, ""
	}
	// Make sure it's not an IPv6 address without brackets
	if strings.Count(s, ":") > 1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// uint32ToIP converts a dataplane IPv4 field to net.IP. Session-map
// values hold IP bytes in network order read as a NATIVE-endian u32
// (the Rust helper publishes u32::from_ne_bytes(octets); cilium/ebpf
// decodes native-endian) — so the bytes are reconstructed with
// NativeEndian, matching grpcapi's uint32ToIP and the userspace
// manager's nativeUint32ToIP. The previous BigEndian decode reversed
// NAT addresses in the local-CLI session display on little-endian.
func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, v)
	return ip
}

// sessionStateName maps a dataplane session-state enum to its Junos label.
func sessionStateName(state uint8) string {
	switch state {
	case dataplane.SessStateNone:
		return "None"
	case dataplane.SessStateNew:
		return "New"
	case dataplane.SessStateSynSent:
		return "SYN_SENT"
	case dataplane.SessStateSynRecv:
		return "SYN_RECV"
	case dataplane.SessStateEstablished:
		return "Established"
	case dataplane.SessStateFINWait:
		return "FIN_WAIT"
	case dataplane.SessStateCloseWait:
		return "CLOSE_WAIT"
	case dataplane.SessStateTimeWait:
		return "TIME_WAIT"
	case dataplane.SessStateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

// ntohs converts a uint16 from network to host byte order.
func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// monotonicSeconds returns CLOCK_MONOTONIC seconds for stamping
// CLI-side intervals. Not used for any wire format.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// capitalizeFirst returns the string with the first letter capitalized.
//
// Note: this helper is unused as of #1444; it is retained here so the
// pure-code-motion scope of the PR is mechanical. Deletion is tracked
// as a follow-up.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
