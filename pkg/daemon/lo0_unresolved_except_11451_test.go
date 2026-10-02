package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11451: an unresolved except must refuse the whole lo0 candidate on both
// renderers. This is action-agnostic: retaining the prior-good filter avoids
// widening an accept/PBR term or installing a new broad discard.
func TestLo0UnresolvedExceptRefusesCandidate11451(t *testing.T) {
	cases := []struct {
		name string
		term config.FirewallFilterTerm
	}{
		{
			name: "accept",
			term: config.FirewallFilterTerm{
				Name: "accept-unresolved-except", Action: "accept",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO", Except: true}},
			},
		},
		{
			name: "discard",
			term: config.FirewallFilterTerm{
				Name: "discard-unresolved-except", Action: "discard",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO", Except: true}},
			},
		},
		{
			name: "PBR redirect",
			term: config.FirewallFilterTerm{
				Name: "pbr-unresolved-except", RoutingInstance: "vrf-a",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO", Except: true}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lo0Cfg9875(&tc.term)
			textRules := nftRulesFromTerm(&tc.term, "ip", cfg.PolicyOptions.PrefixLists)
			want := []string{nftRefuseUnrepresentableFrom}
			if !reflect.DeepEqual(textRules, want) {
				t.Fatalf("text oracle rules = %v, want refusal %v", textRules, want)
			}
			lowered := lowerLo0Term9875(t, cfg)
			if !lowered.FromUnrepresentable {
				t.Fatal("netlink DTO must carry FromUnrepresentable to refuse the candidate")
			}
		})
	}
}
