package config

import (
	"net/netip"
	"sort"
	"strings"
)

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
	{netip.MustParsePrefix("fc00::/7"), "unique local address space (ULA)"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation address space (RFC 3849)"},
	{netip.MustParsePrefix("3fff::/20"), "documentation address space (RFC 9637)"},
}

// DelegatedIPv6PrefixRefusalReason reports whether a DHCPv6 IA_PD delegated
// prefix may not be accepted and, if not, why. The policy is
// global-unicast-only: the prefix's first address must be a global unicast
// address AND must not intersect any special-purpose range above. ULA
// (fc00::/7) and documentation (2001:db8::/32, 3fff::/20) space is refused
// alongside link-local, multicast, loopback, unspecified, IPv4-compatible,
// IPv4-mapped, and site-local space because a delegated PIO is re-advertised
// on-link + autonomous to the LAN and none of those classes is routable
// delegation space.
//
// ULA delegations and intentional overlaps with configured space ARE legitimate
// in some deployments, but no operator pin/allowlist mechanism exists yet, so
// this refuses them rather than fail open. #12533 tracks the pin design that
// will scope the exceptions. The caller owns logging and per-IAPREFIX salvage
// policy.
func DelegatedIPv6PrefixRefusalReason(prefix netip.Prefix) string {
	if !prefix.IsValid() || !prefix.Addr().Is6() {
		return "not an IPv6 prefix"
	}

	// The table runs first so the refusal names the specific class; the
	// global-unicast floor below is the fallback for non-unicast space
	// outside every enumerated range.
	prefix = prefix.Masked()
	for _, blocked := range delegatedIPv6BlockedPrefixes {
		if IPv6PrefixesOverlap(prefix, blocked.prefix) {
			return blocked.reason
		}
	}
	if !prefix.Addr().IsGlobalUnicast() {
		return "not a global unicast address"
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

// ConfiguredIPv6Prefixes collects every IPv6 prefix the operator configured on
// the box: interface unit addresses, static router-advertisement prefixes,
// per-interface RA NAT64 (PREF64) prefixes, and NAT64 rule-set prefixes. A
// DHCPv6 IA_PD delegation must not overlap any of them (#10856): a delegated
// prefix colliding with real configured space is re-advertised on-link +
// autonomous and collides hosts with the configured segment. Entries that do
// not parse as IPv6 prefixes are skipped (the compiler validates them
// elsewhere); a nil config yields nil.
//
// Only STATIC configuration is collected. Leases, IA_NA addresses, and the
// delegated prefixes themselves are runtime state, not config, so collecting
// them here would make the delegation overlap itself.
func ConfiguredIPv6Prefixes(cfg *Config) []netip.Prefix {
	if cfg == nil {
		return nil
	}
	var out []netip.Prefix
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			// Junos allows a bare address (host prefix implied).
			addr, addrErr := netip.ParseAddr(raw)
			if addrErr != nil || !addr.Is6() || addr.Is4In6() {
				return
			}
			prefix = netip.PrefixFrom(addr, 128)
		}
		if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return
		}
		out = append(out, prefix.Masked())
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			for _, addr := range unit.Addresses {
				add(addr)
			}
		}
	}
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra == nil {
			continue
		}
		for _, pfx := range ra.Prefixes {
			if pfx == nil {
				continue
			}
			add(pfx.Prefix)
		}
		add(ra.NAT64Prefix)
	}
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil {
			continue
		}
		add(rs.Prefix)
	}
	// Deterministic order: iface map iteration above is randomized, and
	// consumers (daemon protected-set stamp, cluster RA digest via JSON
	// marshal) must not observe a different order on every rebuild of
	// the same config (#14153). Dedupe masked prefixes: the same prefix
	// can be collected from an interface address and an RA prefix.
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	deduped := out[:0]
	for i, p := range out {
		if i > 0 && p == out[i-1] {
			continue
		}
		deduped = append(deduped, p)
	}
	out = deduped
	return out
}
