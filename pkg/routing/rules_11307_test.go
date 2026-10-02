package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPBRBuildRulesAndStatsCountsUnconstrainedSteer11307(t *testing.T) {
	filter := &config.FirewallFilter{
		Name: "unconstrained-fbf",
		Terms: []*config.FirewallFilterTerm{
			{Name: "steer-all", RoutingInstance: "ATT"},
		},
	}
	cfg := pbrTestConfig("inet", filter, []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}, nil)

	rules, degraded := PBRBuildRulesAndStats(cfg)
	if len(rules) != 0 {
		t.Fatalf("desired rules = %d, want 0: unconstrained steering must stay fail-closed", len(rules))
	}
	if degraded != 1 {
		t.Fatalf("degraded = %d, want 1 dropped unconstrained routing-instance term", degraded)
	}
}

func TestPBRBuildRulesAndStatsCountsUndefinedInstanceSteer11307(t *testing.T) {
	// Lenient loads preserve an undefined routing-instance reference in the
	// filter term. The mirror has no target table and must count that drop.
	filter := &config.FirewallFilter{
		Name: "undefined-instance-fbf",
		Terms: []*config.FirewallFilterTerm{
			{Name: "steer-missing", DSCPs: []string{"ef"}, RoutingInstance: "MISSING"},
		},
	}
	cfg := pbrTestConfig("inet", filter, []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}, nil)

	rules, degraded := PBRBuildRulesAndStats(cfg)
	if len(rules) != 0 {
		t.Fatalf("desired rules = %d, want 0 for undefined routing-instance", len(rules))
	}
	if degraded != 1 {
		t.Fatalf("degraded = %d, want 1 dropped undefined-instance term", degraded)
	}
}
