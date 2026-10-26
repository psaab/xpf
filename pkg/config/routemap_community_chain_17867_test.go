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

func TestRouteMapSequenceCountRepeatedChainCommunity17867(t *testing.T) {
	po := &PolicyOptionsConfig{
		Communities: map[string]*CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		PrefixLists: map[string]*PrefixList{
			"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
	for _, tc := range []struct {
		name string
		term *PolicyTerm
	}{
		{name: "orphan", term: &PolicyTerm{FromCommunity: []string{"SH", "SH"}}},
		{name: "mixed", term: &PolicyTerm{FromCommunity: []string{"SH", "SH"}, PrefixList: []string{"PL"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RouteMapSequenceCount(po, &PolicyStatement{Terms: []*PolicyTerm{tc.term}})
			if got != 5 {
				t.Fatalf("repeated-reference chain count = %d, want 5 emitted sequences", got)
			}
		})
	}
}

func TestRepeatedChainCommunityAtExactRouteMapCeiling17867(t *testing.T) {
	prefixNames := makeNames("pl", MaxRouteMapSequences-4)
	prefixLists := make(map[string]*PrefixList, len(prefixNames))
	for _, name := range prefixNames {
		prefixLists[name] = &PrefixList{Name: name, Prefixes: []string{"10.0.0.0/8"}}
	}
	po := PolicyOptionsConfig{
		Communities: map[string]*CommunityDef{
			"SH": {Name: "SH", Members: []string{"65000:.*", ".*:100"}},
		},
		PrefixLists: prefixLists,
	}
	ps := &PolicyStatement{
		Name: "AT-CEILING",
		Terms: []*PolicyTerm{{
			Name:          "mixed",
			FromCommunity: []string{"SH", "SH"},
			PrefixList:    prefixNames,
		}},
	}
	if got := RouteMapSequenceCount(&po, ps); got != MaxRouteMapSequences {
		t.Fatalf("repeated-reference chain count = %d, want exact ceiling %d", got, MaxRouteMapSequences)
	}
	cfg := &Config{}
	cfg.PolicyOptions = po
	cfg.PolicyOptions.PolicyStatements = map[string]*PolicyStatement{"AT-CEILING": ps}
	if err := validatePolicyRouteMapSequenceBoundStrict(cfg); err != nil {
		t.Fatalf("policy with emitted sequence count exactly at ceiling must pass: %v", err)
	}
}
