package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16667: an omitted `ip-monitoring global-weight` must demote. These
// tests drive the REAL compiler (hierarchical text -> CompileConfig)
// into the REAL Monitor/Manager, so they bind the omitted-value path
// the operator actually travels rather than a hand-built struct that
// happens to carry 255.
//
// Fail-on-revert: drop the 255 seed in compileRGIPMonitoring and both
// rows stay at weight 255 after their target fails (debt 0).

func compileIPMonCluster16667(t *testing.T, rgBody string) *config.ClusterConfig {
	t.Helper()
	text := `chassis {
    cluster {
        authentication-key test-cluster-psk-16667;
        cluster-id 1;
        no-private-rg-election;
        redundancy-group 1 {
            node 0 priority 200;
` + rgBody + `
        }
    }
}`
	p := config.NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Chassis.Cluster == nil || len(cfg.Chassis.Cluster.RedundancyGroups) != 1 {
		t.Fatalf("compiled cluster = %+v, want one redundancy group", cfg.Chassis.Cluster)
	}
	return cfg.Chassis.Cluster
}

func rgWeight16667(t *testing.T, m *Manager, rgID int) int {
	t.Helper()
	for _, gs := range m.GroupStates() {
		if gs.GroupID == rgID {
			return gs.Weight
		}
	}
	t.Fatalf("redundancy group %d not present in GroupStates()", rgID)
	return 0
}

func runIPMonPoll16667(t *testing.T, cc *config.ClusterConfig, reach map[string]bool) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	m.UpdateConfig(cc)
	drainEvents(m, 1)
	mon := NewMonitor(m, cc.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)
	mon.poll()
	rg := cc.RedundancyGroups[0]
	if w := rgWeight16667(t, m, rg.ID); w != 255 {
		t.Fatalf("all-reachable weight = %d, want 255", w)
	}
	for addr := range reach {
		reach[addr] = false
	}
	mon.poll()
	return m
}

func TestOmittedGlobalWeightAggregateDemotes_16667(t *testing.T) {
	// Aggregate mode: global-threshold 100, one weight-100 target, no
	// global-weight. The target failing crosses the threshold, so the
	// aggregate debt is the (defaulted) global-weight 255 -> weight 0.
	cc := compileIPMonCluster16667(t,
		"            ip-monitoring {\n"+
			"                global-threshold 100;\n"+
			"                family inet {\n"+
			"                    10.0.0.1 weight 100;\n"+
			"                }\n"+
			"            }")
	rg := cc.RedundancyGroups[0]
	if rg.IPMonitoring.GlobalWeight != 255 {
		t.Fatalf("compiled GlobalWeight = %d, want Junos default 255", rg.IPMonitoring.GlobalWeight)
	}
	m := runIPMonPoll16667(t, cc, map[string]bool{"10.0.0.1": true})
	if w := rgWeight16667(t, m, rg.ID); w != 0 {
		t.Fatalf("aggregate omitted-global-weight weight = %d, want 0 (255 - default 255)", w)
	}
}

func TestOmittedGlobalWeightIndependentUnweightedDemotes_16667(t *testing.T) {
	// Independent mode: no global-threshold, one unweighted target, no
	// global-weight. The target inherits the defaulted global-weight
	// 255 -> weight 0.
	cc := compileIPMonCluster16667(t,
		"            ip-monitoring {\n"+
			"                family inet {\n"+
			"                    10.0.0.1;\n"+
			"                }\n"+
			"            }")
	rg := cc.RedundancyGroups[0]
	if rg.IPMonitoring.GlobalWeight != 255 {
		t.Fatalf("compiled GlobalWeight = %d, want Junos default 255", rg.IPMonitoring.GlobalWeight)
	}
	m := runIPMonPoll16667(t, cc, map[string]bool{"10.0.0.1": true})
	if w := rgWeight16667(t, m, rg.ID); w != 0 {
		t.Fatalf("independent omitted-global-weight weight = %d, want 0 (255 - default 255)", w)
	}
}

func TestExplicitZeroGlobalWeightDoesNotDemote_16667(t *testing.T) {
	// Negative control: an explicit `global-weight 0` is a deliberate
	// no-demotion config and must survive the default.
	cc := compileIPMonCluster16667(t,
		"            ip-monitoring {\n"+
			"                global-weight 0;\n"+
			"                global-threshold 100;\n"+
			"                family inet {\n"+
			"                    10.0.0.1 weight 100;\n"+
			"                }\n"+
			"            }")
	rg := cc.RedundancyGroups[0]
	if rg.IPMonitoring.GlobalWeight != 0 {
		t.Fatalf("compiled GlobalWeight = %d, want explicit 0", rg.IPMonitoring.GlobalWeight)
	}
	m := runIPMonPoll16667(t, cc, map[string]bool{"10.0.0.1": true})
	if w := rgWeight16667(t, m, rg.ID); w != 255 {
		t.Fatalf("explicit-zero weight = %d, want 255 (no demotion)", w)
	}
}
