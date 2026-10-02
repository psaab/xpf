package ipsec

import (
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestModeledIPsecSelectorPairsMatchRenderer11719(t *testing.T) {
	wildcard := config.IPsecRouteBasedDefaultTrafficSelector
	type selectorPair = [2]string
	cases := []struct {
		name string
		vpn  *config.IPsecVPN
		want []selectorPair
	}{
		{
			name: "wildcard/wildcard",
			vpn:  &config.IPsecVPN{BindInterface: "st0.0"},
			want: []selectorPair{{wildcard, wildcard}},
		},
		{
			name: "explicit disjoint children",
			vpn: &config.IPsecVPN{
				BindInterface: "st0.0",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"branch-b": {LocalIP: "10.20.0.0/24", RemoteIP: "192.0.2.0/24"},
					"branch-a": {LocalIP: "10.10.0.0/24", RemoteIP: "198.51.100.0/24"},
				},
			},
			want: []selectorPair{
				{"10.10.0.0/24", "198.51.100.0/24"},
				{"10.20.0.0/24", "192.0.2.0/24"},
			},
		},
		{
			name: "one-sided explicit child",
			vpn: &config.IPsecVPN{
				BindInterface: "st0.0",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"local-only": {LocalIP: "10.30.0.0/24"},
				},
			},
			want: []selectorPair{{"10.30.0.0/24", wildcard}},
		},
		{
			name: "malformed child omitted while valid sibling remains",
			vpn: &config.IPsecVPN{
				BindInterface: "st0.0",
				LocalID:       "10.40.0.0/24",
				RemoteID:      "10.50.0.0/24",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"bad":  {LocalIP: "bad.example"},
					"good": {RemoteIP: "10.60.0.0/24"},
				},
			},
			want: []selectorPair{{"10.40.0.0/24", "10.60.0.0/24"}},
		},
		{
			name: "selector-shaped identity fallback",
			vpn: &config.IPsecVPN{
				BindInterface: "st0.0",
				LocalID:       "10.70.0.0/24",
				RemoteID:      "2001:db8:70::/48",
			},
			want: []selectorPair{{"10.70.0.0/24", "2001:db8:70::/48"}},
		},
		{
			name: "FQDN identity falls back to route wildcard",
			vpn: &config.IPsecVPN{
				BindInterface: "st0.0",
				LocalID:       "vpn.example",
			},
			want: []selectorPair{{wildcard, wildcard}},
		},
		{
			name: "explicit child inherits selector-shaped identities",
			vpn: &config.IPsecVPN{
				BindInterface: "st0.0",
				LocalID:       "10.80.0.0/24",
				RemoteID:      "10.81.0.0/24",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"inherited": {},
				},
			},
			want: []selectorPair{{"10.80.0.0/24", "10.81.0.0/24"}},
		},
		{
			name: "policy-based omitted side remains unknown",
			vpn:  &config.IPsecVPN{LocalID: "10.90.0.0/24"},
			want: []selectorPair{{"10.90.0.0/24", ""}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modeled := config.ModeledIPsecSelectorPairs11380(tc.vpn)
			rendered := effectiveTrafficSelectors("parity", tc.vpn)
			renderedKeys := make([]string, 0, len(rendered))
			for _, pair := range rendered {
				renderedKeys = append(renderedKeys, selectorPairKey11719(
					rendererSelectorSet11719(pair.LocalTS),
					rendererSelectorSet11719(pair.RemoteTS),
				))
			}
			modeledKeys := make([]string, 0, len(modeled))
			for _, pair := range modeled {
				modeledKeys = append(modeledKeys, selectorPairKey11719(pair.Local, pair.Remote))
			}
			expectedKeys := make([]string, 0, len(tc.want))
			for _, pair := range tc.want {
				expectedKeys = append(expectedKeys, selectorPairKey11719(
					rendererSelectorSet11719(pair[0]),
					rendererSelectorSet11719(pair[1]),
				))
			}
			sort.Strings(renderedKeys)
			sort.Strings(modeledKeys)
			sort.Strings(expectedKeys)
			if !equalSelectorPairKeys11719(renderedKeys, modeledKeys) {
				t.Fatalf("renderer selector sets %q, gate model %q", renderedKeys, modeledKeys)
			}
			if !equalSelectorPairKeys11719(renderedKeys, expectedKeys) {
				t.Fatalf("renderer selector sets %q, expected corpus sets %q", renderedKeys, expectedKeys)
			}
		})
	}
}

func selectorPairKey11719(local, remote config.ModeledIPsecSelectorAddressSet11380) string {
	return selectorSetKey11719(local) + "\x00" + selectorSetKey11719(remote)
}

func selectorSetKey11719(set config.ModeledIPsecSelectorAddressSet11380) string {
	ranges := append([]config.ModeledIPsecSelectorAddressRange11380(nil), set.Ranges...)
	sort.Slice(ranges, func(i, j int) bool {
		if first := ranges[i].First.Compare(ranges[j].First); first != 0 {
			return first < 0
		}
		return ranges[i].Last.Compare(ranges[j].Last) < 0
	})
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		parts = append(parts, r.First.String()+"-"+r.Last.String())
	}
	known := "unknown"
	if set.Known {
		known = "known"
	}
	return known + ":" + strings.Join(parts, ",")
}

func rendererSelectorSet11719(value string) config.ModeledIPsecSelectorAddressSet11380 {
	if value == "" {
		return config.ModeledIPsecSelectorAddressSet11380{}
	}
	set := config.ModeledIPsecSelectorAddressSet11380{Known: true}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return config.ModeledIPsecSelectorAddressSet11380{}
		}
		var r config.ModeledIPsecSelectorAddressRange11380
		if dash := strings.IndexByte(part, '-'); dash >= 0 {
			first, firstErr := netip.ParseAddr(part[:dash])
			last, lastErr := netip.ParseAddr(part[dash+1:])
			if firstErr != nil || lastErr != nil || first.Zone() != "" || last.Zone() != "" ||
				first.Is4In6() || last.Is4In6() || first.Is4() != last.Is4() || first.Compare(last) > 0 {
				return config.ModeledIPsecSelectorAddressSet11380{}
			}
			r = config.ModeledIPsecSelectorAddressRange11380{First: first, Last: last}
		} else if prefix, err := netip.ParsePrefix(part); err == nil {
			if prefix.Addr().Is4In6() {
				return config.ModeledIPsecSelectorAddressSet11380{}
			}
			prefix = prefix.Masked()
			r = config.ModeledIPsecSelectorAddressRange11380{
				First: prefix.Addr(),
				Last:  selectorPrefixLast11719(prefix),
			}
		} else if addr, err := netip.ParseAddr(part); err == nil && addr.Zone() == "" && !addr.Is4In6() {
			r = config.ModeledIPsecSelectorAddressRange11380{First: addr, Last: addr}
		} else {
			return config.ModeledIPsecSelectorAddressSet11380{}
		}
		set.Ranges = append(set.Ranges, r)
	}
	return set
}

func selectorPrefixLast11719(prefix netip.Prefix) netip.Addr {
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

func equalSelectorPairKeys11719(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
