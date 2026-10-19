package config

import "net/netip"

// NormalizePrefixListEntry returns the canonical CIDR spelling of a
// prefix-list entry, accepting both CIDR prefixes and bare host addresses
// (#15012). A mask-less entry is a host route: /32 for IPv4, /128 for IPv6
// — the same forms the firewall address classifier
// (classifyFilterAddrFamily, #7273) accepts, so the routing (FRR) and
// firewall consumers of one list cannot disagree about whether an entry
// is valid.
//
// Host bits in a CIDR entry are masked off ("10.0.0.1/24" renders as
// "10.0.0.0/24"), matching FRR's own prefix canonicalisation. Zone-scoped
// literals ("fe80::1%eth0") are rejected even though netip accepts them:
// neither FRR prefix-lists nor the userspace matcher has a zone model
// (#10011). ok is false for anything else malformed; callers fail closed
// (omit the entry, and treat an all-malformed list as absent).
func NormalizePrefixListEntry(entry string) (normalized string, ok bool) {
	if entry == "" {
		return "", false
	}
	if pfx, err := netip.ParsePrefix(entry); err == nil {
		if pfx.Addr().Zone() != "" {
			return "", false
		}
		return pfx.Masked().String(), true
	}
	if addr, err := netip.ParseAddr(entry); err == nil {
		if addr.Zone() != "" {
			return "", false
		}
		if addr.Is4() || addr.Is4In6() {
			return addr.String() + "/32", true
		}
		return addr.String() + "/128", true
	}
	return "", false
}
