package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPostNATInputRequirement12246(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		NAT: config.NATConfig{Destination: &config.DestinationNATConfig{
			RuleSets: []*config.NATRuleSet{{Name: "dnat"}},
		}},
	}}
	res := Match(cfg, Query{FromZone: "untrust", ToZone: "trust"})
	if res.PostNATInputNote != PostNATInputRequirementNote {
		t.Fatalf("configured inbound destination NAT must carry the post-NAT input requirement; got %q", res.PostNATInputNote)
	}

	for name, usage := range map[string]string{
		"match-policies": MatchPoliciesUsage,
		"test policy":    TestPolicyUsage,
	} {
		if !strings.Contains(usage, "post-DNAT/post-translation") ||
			!strings.Contains(usage, "destination-ip") ||
			!strings.Contains(usage, "destination-port") {
			t.Errorf("%s usage must state the expected post-DNAT destination tuple:\n%s", name, usage)
		}
	}

	withoutNAT := Match(&config.Config{}, Query{FromZone: "untrust", ToZone: "trust"})
	if withoutNAT.PostNATInputNote != "" {
		t.Errorf("a config without inbound destination NAT must not carry the requirement note; got %q", withoutNAT.PostNATInputNote)
	}
}
