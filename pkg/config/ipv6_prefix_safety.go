package config

import "net/netip"

var delegatedIPv6BlockedPrefixes = [...]struct {
	prefix netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("::/128"), "unspecified address space"},
	{netip.MustParsePrefix("::1/128"), "loopback address space"},
	{netip.MustParsePrefix("::/96"), "IPv4-compatible address space"},
	{netip.MustParsePrefix("::ffff:0:0/96"), "IPv4-mapped address space"},
	{netip.MustParsePrefix("fe80::/10"), "link-local address space"},
	{netip.MustParsePrefix("fec0::/10"), "site-local address space"},
	{netip.MustParsePrefix("ff00::/8"), "multicast address space"},
}

// DelegatedIPv6PrefixRefusalReasonBlocklist reports whether a delegated prefix
// intersects an address class that must never be advertised as IA_PD. It is a
// blocklist, not a global-unicast allowlist: ULA and documentation prefixes
// remain accepted. The caller owns logging and per-IAPREFIX salvage policy.
func DelegatedIPv6PrefixRefusalReasonBlocklist(prefix netip.Prefix) string {
	if !prefix.IsValid() || !prefix.Addr().Is6() {
		return "not an IPv6 prefix"
	}

	prefix = prefix.Masked()
	for _, blocked := range delegatedIPv6BlockedPrefixes {
		if IPv6PrefixesOverlap(prefix, blocked.prefix) {
			return blocked.reason
		}
	}
	return ""
}

// IPv6PrefixesOverlap reports whether two valid IPv6 prefixes contain any
// common address. Host bits are ignored, so a prefix spanning a blocked range
// is treated the same as one wholly contained by it.
func IPv6PrefixesOverlap(a, b netip.Prefix) bool {
	if !a.IsValid() || !b.IsValid() || !a.Addr().Is6() || !b.Addr().Is6() {
		return false
	}
	a, b = a.Masked(), b.Masked()
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}
