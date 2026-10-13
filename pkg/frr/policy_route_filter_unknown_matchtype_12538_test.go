package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func rf12538PolicyOptions(prefix, matchType string) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXPORT": {
				Name: "EXPORT",
				Terms: []*config.PolicyTerm{
					{
						Name:         "t1",
						RouteFilters: []*config.RouteFilter{{Prefix: prefix, MatchType: matchType}},
						Action:       "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}
}

func TestRouteFilterUnknownMatchTypeRendererSkipsEntry_12538(t *testing.T) {
	inlineName := inlinePrefixListName("EXPORT", "EXPORT", "t1", "")
	rendered := New().generatePolicyOptions(rf12538PolicyOptions("10.0.0.0/8", "orlongerr"))
	if strings.Contains(rendered, "prefix-list "+inlineName+" seq") {
		t.Errorf("unknown match-type `orlongerr` must NOT emit prefix-list seq entry, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "permit 10.0.0.0/8") {
		t.Errorf("unknown match-type `orlongerr` must NOT emit prefix-list permit line, got:\n%s", rendered)
	}
}
