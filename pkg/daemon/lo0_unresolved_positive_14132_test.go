package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14132: an unresolved POSITIVE prefix-list must refuse the whole lo0
// candidate on both renderers, exactly like the unresolved-except case
// (#11451). Pre-fix only `except` refs refused: the text oracle emitted no
// rule for the constrained-empty deny (so host traffic fell through) and the
// netlink DTO carried no marker, while a partial OR silently narrowed the
// deny to its resolved members. FAIL-ON-REVERT: restoring the except-only
// helper makes every assertion below go RED.
func TestLo0UnresolvedPositiveRefusesCandidate14132(t *testing.T) {
	cases := []struct {
		name string
		term config.FirewallFilterTerm
	}{
		{
			name: "discard",
			term: config.FirewallFilterTerm{
				Name: "discard-unresolved-positive", Action: "discard",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
			},
		},
		{
			name: "reject",
			term: config.FirewallFilterTerm{
				Name: "reject-unresolved-positive", Action: "reject",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
			},
		},
		{
			name: "accept",
			term: config.FirewallFilterTerm{
				Name: "accept-unresolved-positive", Action: "accept",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
			},
		},
		{
			name: "PBR redirect",
			term: config.FirewallFilterTerm{
				Name: "pbr-unresolved-positive", RoutingInstance: "vrf-a",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
			},
		},
		{
			name: "discard partial OR",
			term: config.FirewallFilterTerm{
				Name: "discard-partial-or", Action: "discard",
				SourcePrefixLists: []config.PrefixListRef{{Name: "known"}, {Name: "TYPO"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lo0Cfg9875(&tc.term)
			if tc.name == "discard partial OR" {
				cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
					"known": {Name: "known", Prefixes: []string{"10.0.0.0/8"}},
				}
			}
			textRules := nftRulesFromTerm(&tc.term, "ip", cfg.PolicyOptions.PrefixLists)
			want := []string{nftRefuseUnrepresentableFrom}
			if !reflect.DeepEqual(textRules, want) {
				t.Fatalf("text oracle rules = %v, want refusal %v", textRules, want)
			}
			lowered := lowerLo0Term9875(t, cfg)
			if !lowered.FromUnrepresentable {
				t.Fatal("netlink DTO must carry FromUnrepresentable to refuse the candidate (#14132)")
			}
		})
	}
}

// A defined positive prefix-list must NOT refuse: ordinary lo0 filters keep
// rendering (anti-over-fix control).
func TestLo0DefinedPositiveDoesNotRefuse14132(t *testing.T) {
	term := config.FirewallFilterTerm{
		Name: "discard-defined-positive", Action: "discard",
		SourcePrefixLists: []config.PrefixListRef{{Name: "known"}},
	}
	cfg := lo0Cfg9875(&term)
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"known": {Name: "known", Prefixes: []string{"10.0.0.0/8"}},
	}
	if rules := nftRulesFromTerm(&term, "ip", cfg.PolicyOptions.PrefixLists); reflect.DeepEqual(rules, []string{nftRefuseUnrepresentableFrom}) {
		t.Fatalf("a defined positive prefix-list must not refuse the candidate, got %v", rules)
	}
	if lowered := lowerLo0Term9875(t, cfg); lowered.FromUnrepresentable {
		t.Fatal("a defined positive prefix-list must not set FromUnrepresentable (#14132)")
	}
}
