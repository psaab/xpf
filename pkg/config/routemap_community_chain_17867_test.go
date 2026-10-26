package config

import "testing"

func TestRouteMapSequenceCountMixedCommunityChain17867(t *testing.T) {
	po := &PolicyOptionsConfig{
		Communities: map[string]*CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		PrefixLists: map[string]*PrefixList{
			"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
	cases := []struct {
		name string
		term *PolicyTerm
	}{
		{"prefix-list", &PolicyTerm{FromCommunity: []string{"SH"}, PrefixList: []string{"PL"}}},
		{"as-path", &PolicyTerm{FromCommunity: []string{"SH"}, FromASPath: []string{"AP"}}},
		{"protocol", &PolicyTerm{FromCommunity: []string{"SH"}, FromProtocols: []string{"bgp"}}},
		{"route-filter", &PolicyTerm{FromCommunity: []string{"SH"}, RouteFilters: []*RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := &PolicyStatement{Terms: []*PolicyTerm{tc.term}}
			if got := RouteMapSequenceCount(po, ps); got != 5 {
				t.Fatalf("mixed chain sequence count = %d, want 5 (four chain slots + one body)", got)
			}
		})
	}
}
