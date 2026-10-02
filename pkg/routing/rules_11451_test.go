package routing

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11451: an UNRESOLVED `except` prefix-list on the lenient/peer-sync path must
// NOT conflate with defined-empty match-all. The PBR term must drop (0 rules)
// with a degraded error (fail-closed), not steer match-all.
func TestBuildPBRRulesUnresolvedExceptDropsTerm11451(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}
	filter := &config.FirewallFilter{
		Name: "pbr-except-typo",
		Terms: []*config.FirewallFilterTerm{
			{
				Name:              "t",
				DSCPs:             []string{"ef"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO", Except: true}},
				RoutingInstance:   "ATT",
			},
		},
	}
	// TYPO is never defined: unresolved on the lenient path.
	pls := map[string]*config.PrefixList{}
	rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
	if len(rules) != 0 {
		t.Fatalf("unresolved except must drop the term (0 rules), got %d: %+v", len(rules), rules)
	}
	if err == nil {
		t.Fatal("unresolved except must return a degraded error (fail-closed)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unresolved") {
		t.Fatalf("degraded error must name the unresolved except ref, got: %v", err)
	}
}

// #11451 discriminator: a DEFINED-but-EMPTY `except` prefix-list keeps Junos
// match-all (one unconstrained rule, no degraded error).
func TestBuildPBRRulesDefinedEmptyExceptKeepsMatchAll11451(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}
	filter := &config.FirewallFilter{
		Name: "pbr-except-empty",
		Terms: []*config.FirewallFilterTerm{
			{
				Name:              "t",
				DSCPs:             []string{"ef"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "none", Except: true}},
				RoutingInstance:   "ATT",
			},
		},
	}
	pls := map[string]*config.PrefixList{"none": {Name: "none"}}
	rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
	if err != nil {
		t.Fatalf("defined-empty except must not degrade, got err: %v", err)
	}
	if len(rules) != 1 || rules[0].Src != "" {
		t.Fatalf("defined-empty except must yield one unconstrained rule (Src \"\"), got %+v", rules)
	}
}
