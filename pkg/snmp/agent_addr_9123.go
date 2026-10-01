package snmp

import (
	"net"
	"time"
)

// #9123: the SNMPv1 Trap-PDU's agent-addr was hardcoded to 0.0.0.0, and the
// comment justifying it cited a section that mandates the opposite.
//
// THE MISCITATION. traps.go said "agent-addr is 0.0.0.0, per the RFC 2576 §3.1
// SNMPv2->SNMPv1 mapping for a standard generic trap." RFC 3584 (which
// obsoletes 2576) puts the SNMPv2->SNMPv1 translation in §3.2 -- §3.1 is the
// OTHER direction -- and its normative text reads:
//
//	If the translation occurs within a notification originator application,
//	and the notification is to be sent over IP, the SNMPv1 agent-addr
//	parameter SHALL be set to the IP address of the SNMP entity in which the
//	notification originator resides. If the notification is to be sent over
//	some other transport, the SNMPv1 agent-addr parameter SHALL be set to
//	0.0.0.0.
//
// xpf is a notification originator sending over IP, so the cited authority
// requires the opposite of what the code did. 0.0.0.0 is the fallback for a
// NON-IP transport (or an indeterminate proxy), not the general case.
//
// THE CONSEQUENCE, kept narrow. Many receivers -- net-snmp's snmptrapd among
// them -- fall back to the UDP source address, so "the trap is dropped as
// malformed" is NOT established and is not claimed. What is established is
// attribution: a receiver that keys its inventory on agent-addr files every
// link-up/down against node 0.0.0.0. Bounded to `version v1` and `version all`
// groups; v2c is the default and carries no agent-addr field at all.
//
// WHY PER TARGET. RFC 3584 says "the IP address of the SNMP entity", which is
// one address rather than one per association -- but a multi-homed firewall has
// no single such address, and the useful answer is the address the receiver
// will actually see this trap arrive from. Deriving it toward each target makes
// agent-addr agree with the UDP source header, which is what a receiver
// cross-checks when it does check. On a single-homed box the two readings are
// identical.
//
// NO CONFIGURED VALUE IS BEING DISCARDED HERE: config.SNMPTrapGroup carries
// only Name, Targets, Version and Categories, and no `trap-options
// source-address` leaf exists in the schema. So this is "never implemented",
// not "operator's value ignored" -- and adding that Junos-parity leaf is a
// separate change with a config-schema blast radius, deliberately not folded in.

// agentAddrDialTimeout bounds the connectionless probe below. A var only so a
// test can shorten it; production never writes it.
var agentAddrDialTimeout9123 = 2 * time.Second

// agentAddrForTarget returns the four bytes to put in the Trap-PDU agent-addr
// field for a trap being sent to target.
//
// It uses a CONNECTED UDP socket, which sends nothing: connect() on a datagram
// socket only fixes the peer and makes the kernel select a source address by
// consulting the routing table. That is the cheapest way to ask "which of my
// addresses would this trap leave from" without duplicating route lookup here,
// and it costs no packet.
//
// Returns 0.0.0.0 whenever no IPv4 source can be determined -- an IPv6-only
// target, an unroutable target, a resolution failure. That is then the
// RFC-sanctioned use of the value rather than the unconditional one it replaced:
// the field genuinely cannot be filled in.
func agentAddrForTarget(target string) [4]byte {
	return agentAddrForTargetOnVRF(target, "")
}

func agentAddrForTargetOnVRF(target, device string) [4]byte {
	var zero [4]byte
	if target == "" {
		return zero
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// A bare address with no port, which is what a trap-group target
		// usually is. sendTrap applies the default port the same way.
		host, port = target, "162"
	}
	dialer := net.Dialer{Timeout: agentAddrDialTimeout9123, Control: snmpVRFSocketControl(device)}
	conn, err := dialer.Dial("udp4", net.JoinHostPort(host, port))
	if err != nil {
		return zero
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP == nil {
		return zero
	}
	b, ok := ipv4Bytes9123(ua.IP)
	if !ok {
		return zero
	}
	return b
}

// ipv4Bytes9123 narrows a net.IP to the four bytes the agent-addr field holds.
//
// SPLIT OUT SO THE NARROWING IS EXERCISABLE. net.IP is a byte slice that may
// hold an IPv4 address in EITHER a 4-byte or a 16-byte v4-mapped form, and
// which one a udp4 socket's LocalAddr() returns is a runtime detail. Indexing
// the first four bytes of the 16-byte form yields 0.0.0.0 -- the leading zeros
// of ::ffff: -- so the trap would carry the very value this change exists to
// stop emitting, on a platform where nothing here changed.
//
// Left inline as `ua.IP.To4()`, that guard was UNTESTABLE from the socket path:
// a mutation removing it survived, because this platform happens to return the
// 4-byte form. As its own function both forms can be driven directly, and the
// mutation dies. Reachability of a guard through the only caller is not the
// same question as whether the guard is correct.
func ipv4Bytes9123(ip net.IP) ([4]byte, bool) {
	var zero [4]byte
	v4 := ip.To4()
	if v4 == nil || len(v4) != 4 {
		return zero, false
	}
	return [4]byte{v4[0], v4[1], v4[2], v4[3]}, true
}
