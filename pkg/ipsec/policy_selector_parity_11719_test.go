package ipsec

import (
	"sort"
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
			name: "identity fallback",
			vpn: &config.IPsecVPN{
				BindInterface: "st0.0",
				LocalID:       "10.70.0.0/24",
				RemoteID:      "2001:db8:70::/48",
			},
			want: []selectorPair{{"10.70.0.0/24", "2001:db8:70::/48"}},
		},
	}

	pairKeys := func(pairs []selectorPair) []string {
		keys := make([]string, 0, len(pairs))
		for _, pair := range pairs {
			keys = append(keys, pair[0]+"\x00"+pair[1])
		}
		sort.Strings(keys)
		return keys
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modeled := config.ModeledIPsecSelectorPairs11380(tc.vpn)
			rendered := effectiveTrafficSelectors("parity", tc.vpn)
			renderedPairs := make([]selectorPair, 0, len(rendered))
			for _, pair := range rendered {
				renderedPairs = append(renderedPairs, selectorPair{pair.LocalTS, pair.RemoteTS})
			}
			modeledPairs := make([]selectorPair, 0, len(modeled))
			for _, pair := range modeled {
				modeledPairs = append(modeledPairs, selectorPair{pair.Local, pair.Remote})
			}
			if got, want := pairKeys(renderedPairs), pairKeys(modeledPairs); !equalSelectorPairKeys(got, want) {
				t.Fatalf("renderer selector pairs %q, gate model %q", got, want)
			}
			if got, want := pairKeys(renderedPairs), pairKeys(tc.want); !equalSelectorPairKeys(got, want) {
				t.Fatalf("renderer selector pairs %q, expected corpus pairs %q", got, want)
			}
		})
	}
}

func equalSelectorPairKeys(a, b []string) bool {
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
