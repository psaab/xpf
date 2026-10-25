package config

import "net/netip"

// BlockedFeedDestinationPrefixes contains IPv6 transition / special-purpose
// address space that is not a public feed destination, plus the IPv4
// special-purpose ranges stdlib classification still calls global unicast.
// netip.Addr.IsGlobalUnicast follows package net: NAT64 (64:ff9b::/96),
// NAT64 local-use (64:ff9b:1::/48), 6to4 (2002::/16), the IETF protocol
// assignments block (2001::/23, which includes Teredo 2001::/32),
// discard-only (100::/64), dummy (100:0:0:1::/64), SRv6 SIDs (5f00::/16)
// and the documentation prefixes below all pass IsGlobalUnicast, so
// without this list a feed hostname resolving to a translator /
// transition address — whose embedded IPv4 can name an internal target —
// would be dialled as if it were a public destination (#14177). The IPv6
// entries mirror specialPurposeV6 in pkg/ddns/checkip.go; keep in sync.
// IsUnspecified/IsLoopback/IsLinkLocal/IsMulticast are still handled by
// the predicates in FeedDestinationBlocked.
//
// This predicate lives in pkg/config (not pkg/feeds) so the strict
// compiler gate can share it without an import cycle: pkg/feeds already
// imports pkg/config (#16656).
var blockedFeedDestinationPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT; Alibaba metadata is within it.
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments.
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking/special-purpose.
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix (RFC 6052).
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use (RFC 8215).
	netip.MustParsePrefix("100::/64"),       // discard-only (RFC 6666).
	netip.MustParsePrefix("100:0:0:1::/64"), // dummy IPv6 prefix (RFC 9780).
	netip.MustParsePrefix("2001::/23"),      // IETF protocol assignments (incl. Teredo 2001::/32).
	netip.MustParsePrefix("2001:db8::/32"),  // documentation (RFC 3849).
	netip.MustParsePrefix("2002::/16"),      // 6to4 (RFC 3056, deprecated).
	netip.MustParsePrefix("3fff::/20"),      // documentation (RFC 9637).
	netip.MustParsePrefix("5f00::/16"),      // SRv6 SIDs (RFC 9602).
	netip.MustParsePrefix("fc00::/7"),       // ULA (RFC 4193; also IsPrivate).
}

// FeedDestinationBlocked reports whether ip is refused as a dynamic-address
// feed destination under the SSRF destination policy (#10177/#14177): only
// a public global-unicast address outside every special-purpose prefix is
// diallable. It is the single shared predicate used by the runtime fetch
// guard (pkg/feeds) and the strict commit gate (#16656), so a destination
// the runtime would refuse for an IP-literal host is rejected at commit.
func FeedDestinationBlocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() ||
		ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() ||
		!ip.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range blockedFeedDestinationPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// FeedDestinationClass names the destination class that makes ip a blocked
// feed destination, for operator-visible diagnostics (#16656). It returns
// "" when ip is not blocked.
func FeedDestinationClass(ip netip.Addr) string {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid():
		return "invalid"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case !ip.IsGlobalUnicast():
		return "non-global-unicast"
	}
	for _, prefix := range blockedFeedDestinationPrefixes {
		if prefix.Contains(ip) {
			return "special-purpose (" + prefix.String() + ")"
		}
	}
	return ""
}

// FeedDestinationAllowed reports whether ip falls inside any allowlist
// prefix. Prefixes are matched masked, mirroring how
// feeds.Manager.SetPrivateFeedAllowlist stores them.
func FeedDestinationAllowed(ip netip.Addr, allowlist []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, prefix := range allowlist {
		if prefix.IsValid() && prefix.Masked().Contains(ip) {
			return true
		}
	}
	return false
}
