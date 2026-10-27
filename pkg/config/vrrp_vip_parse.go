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
// path now does too, WITH the /96-offset bit translation when one
// exists: the mapped range occupies bits 96..127 of the 128-bit space,
// so a mapped prefix of N>=96 bits is the IPv4 prefix of N-96 bits
// ("::ffff:10.0.0.1/120" is "10.0.0.1/24", "/128" is "/32", "/96" is
// "/0"). This matches the pre-#17150 sites: net.ParseCIDR / net.ParseIP
// fold a mapped host to its 4-byte form (To4() != nil,
// String() == "10.0.0.1"), so the old strip/ParseCIDR helpers
// classified, claimed, and deduped it as IPv4 while only the new
// ParsePrefix-first parse kept it IPv6 — the split that reopened the
// #2516 leak: canonAddr keyed "::ffff:10.0.0.1" (never equal to a
// net.IP lookup key "10.0.0.1") while vrrpVIPHostIP-based gates
// classified the same string as IPv4.
//
// A mapped prefix with Bits() < 96 has NO IPv4 prefix equivalent (it
// covers space outside ::ffff:0:0/96; its N-96 translation is
// negative). It is NOT rejected and NOT kept mapped: every other
// consumer in the repo already treats its host as IPv4 — the
// commit-time gates branch on vrrpVIPHostIP(...).To4(), canonAddr's
// net.IP lookup keys are the 4-byte "10.0.0.1" form, netlink actuation
// re-parses the raw string to a v4 address, and GARP takes its
// To4() != nil branch — and several of those consumers silently SKIP
// an unparseable VIP (continue on nil/false) while still accepting
// the config, so rejecting here would leave the VIP uninstalled and
// uncounted rather than failing the commit closed. Instead the parse
// returns the v4 HOST identity: the unmapped address as a /32 host
// prefix. The authored sub-96 mask has no v4 meaning and is dropped;
// every consumer of this parse (count, gates, advert, claim,
// canonAddr, actuation, GARP) then agrees the VIP is the IPv4 host
// 10.0.0.1, which is exactly how net.ParseCIDR, netlink.ParseAddr,
// and net.ParseCIDR-based GARP have always actuated it (host /32;
// the raw-string netlink mask collapses to /0 only as an artefact
// of re-parsing, never as a distinct identity any consumer keys on).
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
// IPv4 equivalent: for Bits() >= 96 the address is unmapped and the
// bits shifted by the 96-bit mapped offset; for Bits() < 96 there is
// no v4 prefix equivalent, so the v4 host identity (/32) is returned
// (see ParseVRRPVIP). Non-mapped prefixes are returned unchanged.
func unmapVRRPMappedPrefix(p netip.Prefix) netip.Prefix {
	if !p.Addr().Is4In6() {
		return p
	}
	if p.Bits() < 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), 32)
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
