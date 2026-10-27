package config

import (
	"net/netip"
	"strconv"
)

// ParseVRRPVIP is the single repo-wide parse of a configured VRRP
// virtual-address string (#17150). A VIP is a CIDR ("10.0.0.1/24",
// "2001:db8::1/64") or, on lenient load paths, a bare host literal
// ("10.0.0.1"); a bare literal parses as the host route of its family
// (/32 or /128, mapped form unmapped). ok=false for anything else —
// in particular a CIDR spelling with an invalid prefix such as
// "10.0.0.1/33" or "10.0.0.1/x" is NOT a VIP: the pre-#17150
// strip-at-"/" parsers in pkg/vrrp counted such entries as real
// addresses while the ParseCIDR-first parsers ignored them, so the
// runtime capacity guard and advert builder disagreed with the
// cross-election claim check and the commit-time count on exactly
// those malformed entries.
//
// IPv4-mapped IPv6 spellings ("::ffff:10.0.0.1", "::ffff:10.0.0.1/120")
// are IPv4 everywhere. The bare path already unmapped them; the CIDR
// path now does too, WITH the /96-offset bit translation: the mapped
// range occupies bits 96..127 of the 128-bit space, so a mapped prefix
// of N>=96 bits is the IPv4 prefix of N-96 bits ("::ffff:10.0.0.1/120"
// is "10.0.0.1/24", "/128" is "/32", "/96" is "/0"). This matches the
// pre-#17150 sites: net.ParseCIDR / net.ParseIP fold a mapped host to
// its 4-byte form (To4() != nil, String() == "10.0.0.1"), so the old
// strip/ParseCIDR helpers classified, claimed, and deduped it as IPv4
// while only the new ParsePrefix-first parse kept it IPv6 — the split
// that reopened the #2516 leak: canonAddr keyed "::ffff:10.0.0.1"
// (never equal to a net.IP lookup key "10.0.0.1") while
// vrrpVIPHostIP-based gates classified the same string as IPv4.
//
// A mapped prefix with Bits() < 96 has NO IPv4 equivalent (it covers
// space outside ::ffff:0:0/96; its N-96 translation is negative). It is
// kept mapped — returned as the 128-bit prefix as authored — rather
// than rejected: the pre-#17150 ParseCIDR sites accepted it as the IPv4
// host "10.0.0.1" regardless of bits, so fail-closed here would newly
// drop a spelling the gates have always classified, and keeping it
// mapped leaves it consistently IPv6 to EVERY consumer of this parse
// (this mirrors proxyARPUnmap4In6, #8631, which likewise leaves
// Bits() < 96 alone). Either choice is safe only because all consumers
// share this one parse; the invariant is agreement, not the family a
// sub-96 mapped prefix lands in.
//
// The mask is returned unmasked: Prefix.Addr is the host address as
// authored and Bits is the authored prefix length, so callers keep
// the host identity and the prefix-preserving identity (#11482)
// distinct. pkg/vrrp imports pkg/config and not the reverse, so the
// shared parse lives here and pkg/vrrp consumes it.
func ParseVRRPVIP(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(normalizeCIDRMaskPadding(s))
	if err == nil {
		return unmapVRRPMappedPrefix(p), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// unmapVRRPMappedPrefix translates an IPv4-mapped CIDR prefix to its
// IPv4 equivalent (address unmapped, bits shifted by the 96-bit mapped
// offset). Prefixes that are not mapped, and mapped prefixes below
// /96 (no IPv4 equivalent — see ParseVRRPVIP), are returned unchanged.
func unmapVRRPMappedPrefix(p netip.Prefix) netip.Prefix {
	if !p.Addr().Is4In6() || p.Bits() < 96 {
		return p
	}
	q := netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	if !q.IsValid() {
		return p
	}
	return q
}

// VRRPVIPIdentity returns the prefix-preserving canonical identity of
// a VIP: "<canonical host>/<prefix bits>". A bare literal and its
// host-route CIDR spelling ("10.0.0.1" vs "10.0.0.1/32") share one
// identity, as do case/expansion spellings of the same IPv6 host
// ("2001:db8::10/64" vs "2001:0DB8:0:0:0:0:0:10/64", #11482). Invalid
// tokens return themselves unchanged so they remain distinct and flow
// through the existing parse-error paths.
func VRRPVIPIdentity(vip string) string {
	p, ok := ParseVRRPVIP(vip)
	if !ok {
		return vip
	}
	return p.Addr().String() + "/" + strconv.Itoa(p.Bits())
}

// DedupeVRRPVIPs preserves input order and the first spelling of each
// canonical VIP identity (VRRPVIPIdentity). Invalid tokens remain
// available for the existing tolerant path. This is the one dedupe
// implementation repo-wide (#17150): pkg/vrrp consumes it instead of
// keeping its own copy.
func DedupeVRRPVIPs(vips []string) []string {
	if len(vips) < 2 {
		return vips
	}
	seen := make(map[string]struct{}, len(vips))
	var unique []string
	for i, vip := range vips {
		id := VRRPVIPIdentity(vip)
		if _, exists := seen[id]; exists {
			if unique == nil {
				unique = append([]string(nil), vips[:i]...)
			}
			continue
		}
		seen[id] = struct{}{}
		if unique != nil {
			unique = append(unique, vip)
		}
	}
	if unique != nil {
		return unique
	}
	return vips
}
