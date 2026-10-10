package config

import "net/netip"

var (
	ipv6GlobalUnicastBlock    = netip.MustParsePrefix("2000::/3")
	ipv6ULAPrefix             = netip.MustParsePrefix("fc00::/7")
	ipv6DocumentationPrefixes = [...]netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"), // RFC 3849
		netip.MustParsePrefix("3fff::/20"),     // RFC 9637
	}
	ipv6SpecialRanges = [...]struct {
		prefix netip.Prefix
		reason string
	}{
		{netip.MustParsePrefix("::/128"), "unspecified address space"},
		{netip.MustParsePrefix("::1/128"), "loopback address space"},
		{netip.MustParsePrefix("fe80::/10"), "link-local address space"},
		{netip.MustParsePrefix("ff00::/8"), "multicast address space"},
	}
)

// DelegatedIPv6PrefixRefusalReason reports why an IA_PD prefix is not a
// globally scoped IPv6 unicast delegation. The caller owns logging and salvage
// policy. ULA is rejected because there is no configured pin/allowlist path.
func DelegatedIPv6PrefixRefusalReason(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return "invalid prefix"
	}
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return "not an IPv6 prefix"
	}

	masked := prefix.Masked()
	for _, special := range ipv6SpecialRanges {
		if IPv6PrefixesOverlap(masked, special.prefix) {
			return special.reason
		}
	}
	for _, documentation := range ipv6DocumentationPrefixes {
		if IPv6PrefixesOverlap(masked, documentation) {
			return "documentation address space"
		}
	}
	if IPv6PrefixesOverlap(masked, ipv6ULAPrefix) {
		return "ULA address space has no configured pin mechanism"
	}

	// Global unicast allocations are within 2000::/3. Require the delegated
	// prefix itself to stay inside that block (not merely its base address):
	// a broader prefix could otherwise include unspecified, loopback, or
	// non-unicast space while its first address looked globally routable.
	if prefix.Bits() < ipv6GlobalUnicastBlock.Bits() ||
		!ipv6GlobalUnicastBlock.Contains(masked.Addr()) ||
		!masked.Addr().IsGlobalUnicast() {
		return "not global-unicast IPv6 address space"
	}
	return ""
}

// IPv6PrefixesOverlap reports whether two valid IPv6 prefixes contain any
// common address. Host bits are ignored, as they are on the wire.
func IPv6PrefixesOverlap(a, b netip.Prefix) bool {
	if !a.IsValid() || !b.IsValid() || !a.Addr().Is6() || !b.Addr().Is6() ||
		a.Addr().Is4In6() || b.Addr().Is4In6() {
		return false
	}
	a, b = a.Masked(), b.Masked()
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}
