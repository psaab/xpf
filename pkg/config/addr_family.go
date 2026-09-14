package config

import "net/netip"

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
// This is the single family predicate shared by the commit gates and the
// FRR render belts (#9820): the static next-hop gate + belt, the
// backup-router gate + belt + emission, and the static `ip`/`ipv6`
// keying. It supersedes frrOperandIsV6 (which classified mapped as v4,
// disagreeing with both the validator and the emission) and the inline
// strings.Contains(s, ":") spellings on those guarded paths.
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

// FRRAddrIsMapped reports whether s (IP literal or CIDR prefix) is an
// IPv4-mapped IPv6 literal (::ffff:a.b.c.d, any spelling netip accepts).
// It recognizes the parsed address class across equivalent spellings —
// compressed, fully expanded, uppercase, dotted or hexadecimal.
func FRRAddrIsMapped(s string) bool {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Is4In6()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Is4In6()
	}
	return false
}
