package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPBRBuildStatsCountsUnconstrainedSteer11307(t *testing.T) {
	filter := &config.FirewallFilter{
		Name: "unconstrained-fbf",
		Terms: []*config.FirewallFilterTerm{
			{Name: "steer-all", RoutingInstance: "ATT"},
		},
	}
	cfg := pbrTestConfig("inet", filter, []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}, nil)

	installed, degraded := PBRBuildStats(cfg)
	if installed != 0 {
		t.Fatalf("installed = %d, want 0: unconstrained steering must stay fail-closed", installed)
	}
	if degraded != 1 {
		t.Fatalf("degraded = %d, want 1 dropped unconstrained routing-instance term", degraded)
	}
}

func TestPBRBuildStatsCountsUndefinedInstanceSteer11307(t *testing.T) {
	// Lenient loads preserve an undefined routing-instance reference in the
	// filter term. The mirror has no target table and must count that drop.
	filter := &config.FirewallFilter{
		Name: "undefined-instance-fbf",
		Terms: []*config.FirewallFilterTerm{
			{Name: "steer-missing", DSCPs: []string{"ef"}, RoutingInstance: "MISSING"},
		},
	}
	cfg := pbrTestConfig("inet", filter, []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}, nil)

	installed, degraded := PBRBuildStats(cfg)
	if installed != 0 {
		t.Fatalf("installed = %d, want 0 for undefined routing-instance", installed)
	}
	if degraded != 1 {
		t.Fatalf("degraded = %d, want 1 dropped undefined-instance term", degraded)
	}
}
