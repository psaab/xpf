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
// The mask is returned unmasked: Prefix.Addr is the host address as
// authored and Bits is the authored prefix length, so callers keep
// the host identity and the prefix-preserving identity (#11482)
// distinct. pkg/vrrp imports pkg/config and not the reverse, so the
// shared parse lives here and pkg/vrrp consumes it.
func ParseVRRPVIP(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(normalizeCIDRMaskPadding(s))
	if err == nil {
		return p, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
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
