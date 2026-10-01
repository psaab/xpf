package config

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// IPsecRouteBasedDefaultTrafficSelector is the dual-stack wildcard emitted
// when a route-based VPN has no explicit selector for one side. The renderer
// and the shared-bind commit gate use this same value.
const IPsecRouteBasedDefaultTrafficSelector = "0.0.0.0/0,::/0"

// validateIPsecBindTrafficSelectorOverlapStrict prevents multiple VPNs from
// sharing one XFRM if_id when their rendered local/remote selector pairs can
// match the same packet. With overlapping selectors, XFRM has no discriminator
// besides if_id and can select the other VPN's SA (#11380).
func validateIPsecBindTrafficSelectorOverlapStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	vpns := cfg.Security.IPsec.VPNs
	vpnNames := make([]string, 0, len(vpns))
	for name := range vpns {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)

	byBind := make(map[string][]string)
	for _, name := range vpnNames {
		vpn := vpns[name]
		if vpn == nil || vpn.BindInterface == "" {
			continue
		}
		if _, ifID := XFRMIfNameAndID(vpn.BindInterface); ifID == 0 {
			continue
		}
		byBind[vpn.BindInterface] = append(byBind[vpn.BindInterface], name)
	}

	binds := make([]string, 0, len(byBind))
	for bind := range byBind {
		binds = append(binds, bind)
	}
	sort.Strings(binds)
	for _, bind := range binds {
		names := byBind[bind]
		if len(names) < 2 {
			continue
		}
		_, ifID := XFRMIfNameAndID(bind)
		selectorSets := make([][]ipsecSelectorPair11380, len(names))
		for i, name := range names {
			selectorSets[i] = renderedIPsecSelectorPairs11380(vpns[name])
		}
		for i := range names {
			for j := i + 1; j < len(names); j++ {
				for _, a := range selectorSets[i] {
					for _, b := range selectorSets[j] {
						if a.overlaps(b) {
							return fmt.Errorf(
								"security ipsec vpns %q and %q share bind-interface %q (if_id %d) with overlapping rendered traffic-selector "+
									"unions; XFRM cannot distinguish their SAs and may encrypt traffic on the wrong VPN; configure "+
									"disjoint local/remote traffic selectors (#11380)",
								names[i], names[j], bind, ifID)
						}
					}
				}
			}
		}
	}
	return nil
}

type ipsecTSAddressRange11380 struct {
	first netip.Addr
	last  netip.Addr
}

type ipsecTSAddressSet11380 struct {
	ranges []ipsecTSAddressRange11380
	known  bool
}

type ipsecSelectorPair11380 struct {
	local  ipsecTSAddressSet11380
	remote ipsecTSAddressSet11380
}

func (a ipsecSelectorPair11380) overlaps(b ipsecSelectorPair11380) bool {
	return ipsecTSAddressSetsOverlap11380(a.local, b.local) &&
		ipsecTSAddressSetsOverlap11380(a.remote, b.remote)
}

// An omitted or unparseable side has dynamic/unknown strongSwan semantics. It
// is not proof of disjointness, so conservatively treat it as overlapping.
func ipsecTSAddressSetsOverlap11380(a, b ipsecTSAddressSet11380) bool {
	if !a.known || !b.known {
		return true
	}
	for _, left := range a.ranges {
		for _, right := range b.ranges {
			if left.first.Is4() != right.first.Is4() {
				continue
			}
			if left.first.Compare(right.last) <= 0 && right.first.Compare(left.last) <= 0 {
				return true
			}
		}
	}
	return false
}

// renderedIPsecSelectorPairs11380 follows effectiveTrafficSelectors in
// pkg/ipsec/policy.go: default route-based selectors, identity fallbacks,
// omitted-side behavior, and explicit children are modeled as they render.
func renderedIPsecSelectorPairs11380(vpn *IPsecVPN) []ipsecSelectorPair11380 {
	if vpn == nil {
		return nil
	}
	if len(vpn.TrafficSelectors) == 0 {
		local, remote := vpn.LocalID, vpn.RemoteID
		if local != "" && !IsTrafficSelectorShape(local) {
			local = ""
		}
		if remote != "" && !IsTrafficSelectorShape(remote) {
			remote = ""
		}
		if _, ifID := XFRMIfNameAndID(vpn.BindInterface); ifID > 0 {
			if local == "" {
				local = IPsecRouteBasedDefaultTrafficSelector
			}
			if remote == "" {
				remote = IPsecRouteBasedDefaultTrafficSelector
			}
		}
		return []ipsecSelectorPair11380{{
			local:  parseIPsecTSAddressSet11380(local),
			remote: parseIPsecTSAddressSet11380(remote),
		}}
	}

	names := make([]string, 0, len(vpn.TrafficSelectors))
	for name := range vpn.TrafficSelectors {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]ipsecSelectorPair11380, 0, len(names))
	for _, name := range names {
		ts := vpn.TrafficSelectors[name]
		if ts == nil {
			// The compiled config does not produce nil selector values, but an
			// unknown child cannot prove this VPN's union disjoint.
			pairs = append(pairs, ipsecSelectorPair11380{})
			continue
		}
		local, remote := vpn.LocalID, vpn.RemoteID
		if ts.LocalIP != "" {
			local = ts.LocalIP
		}
		if ts.RemoteIP != "" {
			remote = ts.RemoteIP
		}
		if (local != "" && !IsTrafficSelectorShape(local)) ||
			(remote != "" && !IsTrafficSelectorShape(remote)) {
			// effectiveTrafficSelectors omits this malformed child.
			continue
		}
		pairs = append(pairs, ipsecSelectorPair11380{
			local:  parseIPsecTSAddressSet11380(local),
			remote: parseIPsecTSAddressSet11380(remote),
		})
	}
	return pairs
}

func parseIPsecTSAddressSet11380(value string) ipsecTSAddressSet11380 {
	if value == "" {
		return ipsecTSAddressSet11380{}
	}
	parts := strings.Split(value, ",")
	set := ipsecTSAddressSet11380{known: true, ranges: make([]ipsecTSAddressRange11380, 0, len(parts))}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return ipsecTSAddressSet11380{}
		}
		var r ipsecTSAddressRange11380
		if dash := strings.IndexByte(part, '-'); dash >= 0 {
			first, firstErr := netip.ParseAddr(part[:dash])
			last, lastErr := netip.ParseAddr(part[dash+1:])
			if firstErr != nil || lastErr != nil || first.Zone() != "" || last.Zone() != "" ||
				first.Is4In6() || last.Is4In6() || first.Is4() != last.Is4() || first.Compare(last) > 0 {
				return ipsecTSAddressSet11380{}
			}
			r = ipsecTSAddressRange11380{first: first, last: last}
		} else if prefix, err := netip.ParsePrefix(part); err == nil {
			if prefix.Addr().Is4In6() {
				return ipsecTSAddressSet11380{}
			}
			prefix = prefix.Masked()
			r = ipsecTSAddressRange11380{first: prefix.Addr(), last: ipsecTSPrefixLast11380(prefix)}
		} else if addr, err := netip.ParseAddr(part); err == nil && addr.Zone() == "" && !addr.Is4In6() {
			r = ipsecTSAddressRange11380{first: addr, last: addr}
		} else {
			return ipsecTSAddressSet11380{}
		}
		set.ranges = append(set.ranges, r)
	}
	return set
}

func ipsecTSPrefixLast11380(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if addr.Is4() {
		bytes := addr.As4()
		for bit := prefix.Bits(); bit < 32; bit++ {
			bytes[bit/8] |= 1 << (7 - uint(bit%8))
		}
		return netip.AddrFrom4(bytes)
	}
	bytes := addr.As16()
	for bit := prefix.Bits(); bit < 128; bit++ {
		bytes[bit/8] |= 1 << (7 - uint(bit%8))
	}
	return netip.AddrFrom16(bytes)
}
