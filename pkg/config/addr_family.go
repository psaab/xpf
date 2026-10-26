package config

import (
	"net"
	"net/netip"
)

// FRRAddrFamily classifies s — an IP literal or a CIDR prefix — for FRR
// static-route CLI grammar purposes: "v4", "v6", or "" (unparseable).
//
// IPv4-mapped IPv6 literals (::ffff:a.b.c.d) are "v6". This is LITERAL /
// CLI-TOKEN classification only (#9820): the spelling is colon-bearing,
// Rust IpAddr::from_str and parse_route_next_hop_v6
// (userspace-dp/src/afxdp/forwarding_build/fib.rs) classify it V6 while
// the v4 parser rejects it, and FRR's `ipv6 route` grammar accepts it in
// the X:X::X:X gateway slot. It proves nothing about forwarding or gateway
// resolution (zebra converts mapped next-hops to v4-table lookups; Linux
// admits them for RFC4798 addressing) — callers must not derive usability
// from it. Callers that must refuse mapped literals outright
// (backup-router next-hop: product restriction per #9820; OSPF area ID:
// FRR area grammar takes only dotted-quad or integer) check
// FRRAddrIsMapped explicitly.
//
// This is the single family predicate shared by the commit gates, static
// route exclusion and FRR render belts (#9820/#11421): the static next-hop
// gate + exclusion + belt, the backup-router gate + belt + emission, and the
// static `ip`/`ipv6` keying. It supersedes frrOperandIsV6 (which classified
// mapped as v4, disagreeing with both the validator and the emission) and the
// inline strings.Contains(s, ":") spellings on those guarded paths.
// natAddrFamily is untouched — NAT owns it.
func FRRAddrFamily(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		a := p.Addr()
		if a.Is6() {
			return "v6" // includes Is4In6 — the explicit rule
		}
		if a.Is4() {
			return "v4"
		}
		return ""
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Is6() {
			return "v6" // includes Is4In6
		}
		if a.Is4() {
			return "v4"
		}
	}
	return ""
}

// FRRAddrIsMapped reports whether s (an IP literal or valid Go CIDR prefix) is
// an IPv4-mapped IPv6 literal. It recognizes mapped prefixes with padded masks
// even when netip.ParsePrefix rejects that otherwise valid Go spelling.
func FRRAddrIsMapped(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		p, err := netip.ParsePrefix(normalizeCIDRMaskPadding(s))
		return err == nil && p.Addr().Is4In6()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Is4In6()
	}
	return false
}

// FRRNextHopAddressOperand reports whether a next-hop address is renderable
// as a single FRR gateway operand (#6795; exported spelling of the
// pkg/frr render belt's validFRRNextHopAddress so pkg/routing exception
// eligibility and pkg/frr rendering consume the SAME predicate instead of
// maintaining a second parser). Bare address only: FRR's
// `ip route <p> <gw>` takes an address, and a prefix there is a grammar error
// that fails the frr-reload. Zoned literals (`fe80::1%eth0`) parse under
// netip but are rejected too: the commit gate (net.ParseIP) refuses them
// and FRR's gateway slot has no zone syntax, so emitting one would fail the
// reload (#9820 GLM-F2 — belt and gate must agree).
func FRRNextHopAddressOperand(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return a.Zone() == ""
}

// FRRInterfaceOperand reports whether an interface name is renderable as a
// single FRR token (#6795; exported spelling of the pkg/frr render belt's
// validFRRInterfaceOperand).
//
// Kernel interface names cannot contain whitespace or '/', but the value
// reaching the renderer is not always a kernel name: it is assembled from
// config, RETH resolution and a `.vlan` suffix, and on the tolerant load /
// peer-sync path it is whatever the config carried. A name with an embedded
// space would split `ip route <p> <gw> <ifname>` into an extra operand and
// change what FRR installs — or, with a newline, add a statement outright.
//
// Deliberately a token test rather than a name-charset test: over-restricting
// interface names would drop working routes on any naming scheme this tree
// has not seen, and the defect is about token COUNT.
func FRRInterfaceOperand(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}
