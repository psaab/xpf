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
		selectorSets := make([][]ModeledIPsecSelectorPair11380, len(names))
		for i, name := range names {
			selectorSets[i] = ModeledIPsecSelectorPairs11380(vpns[name])
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

// ModeledIPsecSelectorAddressRange11380 is an inclusive address interval in
// one side of a traffic-selector pair.
type ModeledIPsecSelectorAddressRange11380 struct {
	First netip.Addr
	Last  netip.Addr
}

// ModeledIPsecSelectorAddressSet11380 is one parsed selector side. Known is
// false for an omitted or unparseable selector, whose semantics are dynamic.
type ModeledIPsecSelectorAddressSet11380 struct {
	Ranges []ModeledIPsecSelectorAddressRange11380
	Known  bool
}

// ModeledIPsecSelectorPair11380 is one local/remote pair as modeled by the
// strict shared-bind gate. The IPsec package's parity test compares these
// parsed sets with the renderer's effective selector pairs.
type ModeledIPsecSelectorPair11380 struct {
	Local  ModeledIPsecSelectorAddressSet11380
	Remote ModeledIPsecSelectorAddressSet11380
}

func (a ModeledIPsecSelectorPair11380) overlaps(b ModeledIPsecSelectorPair11380) bool {
	return ipsecTSAddressSetsOverlap11380(a.Local, b.Local) &&
		ipsecTSAddressSetsOverlap11380(a.Remote, b.Remote)
}

// An omitted or unparseable side has dynamic/unknown strongSwan semantics. It
// is not proof of disjointness, so conservatively treat it as overlapping.
func ipsecTSAddressSetsOverlap11380(a, b ModeledIPsecSelectorAddressSet11380) bool {
	if !a.Known || !b.Known {
		return true
	}
	for _, left := range a.Ranges {
		for _, right := range b.Ranges {
			if left.First.Is4() != right.First.Is4() {
				continue
			}
			if left.First.Compare(right.Last) <= 0 && right.First.Compare(left.Last) <= 0 {
				return true
			}
		}
	}
	return false
}

// ModeledIPsecSelectorPairs11380 follows effectiveTrafficSelectors in
// pkg/ipsec/policy.go: default route-based selectors, identity fallbacks,
// omitted-side behavior, and explicit children are modeled as they render.
// The IPsec package's parity test compares these parsed sets directly.
func ModeledIPsecSelectorPairs11380(vpn *IPsecVPN) []ModeledIPsecSelectorPair11380 {
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
		return []ModeledIPsecSelectorPair11380{{
			Local:  parseIPsecTSAddressSet11380(local),
			Remote: parseIPsecTSAddressSet11380(remote),
		}}
	}

	names := make([]string, 0, len(vpn.TrafficSelectors))
	for name := range vpn.TrafficSelectors {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]ModeledIPsecSelectorPair11380, 0, len(names))
	for _, name := range names {
		ts := vpn.TrafficSelectors[name]
		if ts == nil {
			// The compiled config does not produce nil selector values, but an
			// unknown child cannot prove this VPN's union disjoint.
			pairs = append(pairs, ModeledIPsecSelectorPair11380{})
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
		// Keep the shared-bind model aligned with effectiveTrafficSelectors:
		// route-based explicit children default each omitted side to the
		// same dual-stack wildcard that the renderer emits.
		if _, ifID := XFRMIfNameAndID(vpn.BindInterface); ifID > 0 {
			if local == "" {
				local = IPsecRouteBasedDefaultTrafficSelector
			}
			if remote == "" {
				remote = IPsecRouteBasedDefaultTrafficSelector
			}
		}
		pairs = append(pairs, ModeledIPsecSelectorPair11380{
			Local:  parseIPsecTSAddressSet11380(local),
			Remote: parseIPsecTSAddressSet11380(remote),
		})
	}
	return pairs
}

func parseIPsecTSAddressSet11380(value string) ModeledIPsecSelectorAddressSet11380 {
	if value == "" {
		return ModeledIPsecSelectorAddressSet11380{}
	}
	parts := strings.Split(value, ",")
	set := ModeledIPsecSelectorAddressSet11380{
		Known:  true,
		Ranges: make([]ModeledIPsecSelectorAddressRange11380, 0, len(parts)),
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return ModeledIPsecSelectorAddressSet11380{}
		}
		var r ModeledIPsecSelectorAddressRange11380
		if dash := strings.IndexByte(part, '-'); dash >= 0 {
			first, firstErr := netip.ParseAddr(part[:dash])
			last, lastErr := netip.ParseAddr(part[dash+1:])
			if firstErr != nil || lastErr != nil || first.Zone() != "" || last.Zone() != "" ||
				first.Is4In6() || last.Is4In6() || first.Is4() != last.Is4() || first.Compare(last) > 0 {
				return ModeledIPsecSelectorAddressSet11380{}
			}
			r = ModeledIPsecSelectorAddressRange11380{First: first, Last: last}
		} else if prefix, err := netip.ParsePrefix(part); err == nil {
			if prefix.Addr().Is4In6() {
				return ModeledIPsecSelectorAddressSet11380{}
			}
			prefix = prefix.Masked()
			r = ModeledIPsecSelectorAddressRange11380{
				First: prefix.Addr(),
				Last:  ipsecTSPrefixLast11380(prefix),
			}
		} else if addr, err := netip.ParseAddr(part); err == nil && addr.Zone() == "" && !addr.Is4In6() {
			r = ModeledIPsecSelectorAddressRange11380{First: addr, Last: addr}
		} else {
			return ModeledIPsecSelectorAddressSet11380{}
		}
		set.Ranges = append(set.Ranges, r)
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
