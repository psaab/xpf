package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12893: cross-tier coverage must follow runtime tier precedence
// (exact pair before single-wildcard), not lexicographical pair order:
// an exact DENY covering a scoped global PERMIT makes it SHADOWED even
// though a lexicographically-earlier "any" PERMIT also covers it.
func TestCrossTierShadowingFollowsRuntimeTierOrder12893(t *testing.T) {
	zpol := func(name string, action config.PolicyAction) *config.Policy {
		return &config.Policy{Name: name, Action: action, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}}
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{zpol("wide-permit", config.PolicyPermit)}},
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{zpol("exact-deny", config.PolicyDeny)}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "scoped-permit", Action: config.PolicyPermit, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
			FromZones: []string{"trust"}, ToZones: []string{"untrust"}}},
	}
	joined := strings.Join(AnalyzePolicyShadowing(cfg), "\n")
	if !strings.Contains(joined, "scoped-permit") || !strings.Contains(joined, "SHADOWED") {
		t.Fatalf("exact-tier DENY must make the global SHADOWED (not REDUNDANT):\n%s", joined)
	}
	if strings.Contains(joined, "REDUNDANT") {
		t.Fatalf("wildcard coverer must not win over the exact tier:\n%s", joined)
	}
}
