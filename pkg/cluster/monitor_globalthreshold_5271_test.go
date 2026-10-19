package cluster

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// thresholdRG builds an RG that IP-monitors the given addresses (each at the
// given per-target weight) under a cumulative global-threshold + global-weight.
func thresholdRG(id, globalWeight, globalThreshold, perTargetWeight int, addrs ...string) *config.RedundancyGroup {
	targets := make([]*config.IPMonitorTarget, len(addrs))
	for i, a := range addrs {
		targets[i] = &config.IPMonitorTarget{Address: a, Weight: perTargetWeight}
	}
	return &config.RedundancyGroup{
		ID:             id,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight:    globalWeight,
			GlobalThreshold: globalThreshold,
			Targets:         targets,
		},
	}
}

// reachSet is a per-address reachability probe seam shared by these tests.
func reachProbeFn(reach map[string]bool) func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
	return func(_ context.Context, target *config.IPMonitorTarget, _ string, _ string) (bool, bool) {
		return reach[target.Address], true
	}
}

// TestMonitor_GlobalThresholdGatesFailover_5271 is the issue's exact scenario:
// with global-threshold=200 and global-weight=100, one failing weight-50 target
// (cumulative 50 < 200) must NOT deduct any RG election weight, and only once
// enough targets fail to reach 200 does the single global-weight deduction
// apply.
//
// Fail-on-revert: remove the applyRGIPMonitorThreshold gate (or restore the old
// per-target SetMonitorWeight for the threshold case) and the first failing
// weight-50 target immediately drops the RG weight from 255, failing the
// "stays 255 below threshold" assertion.
func TestMonitor_GlobalThresholdGatesFailover_5271(t *testing.T) {
	rg := thresholdRG(0, 100, 200, 50, "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true, "10.0.0.4": true}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	// All reachable → full health.
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("all-reachable weight = %d, want 255", w)
	}

	// One weight-50 target fails: cumulative 50 < threshold 200 → no debt.
	reach["10.0.0.1"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("one failing target (cumulative 50 < 200) weight = %d, want 255 "+
			"(sub-threshold failure must NOT deduct RG weight)", w)
	}

	// Second and third targets fail: cumulative 150 < 200 → still no debt.
	reach["10.0.0.2"] = false
	reach["10.0.0.3"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("three failing targets (cumulative 150 < 200) weight = %d, want 255", w)
	}

	// Fourth target fails: cumulative 200 >= 200 → deduct global-weight 100.
	reach["10.0.0.4"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("cumulative 200 >= threshold weight = %d, want 155 (255 - global-weight 100)", w)
	}

	// One target recovers: cumulative 150 < 200 → clear the debt.
	reach["10.0.0.1"] = true
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("recovery below threshold weight = %d, want 255 (global-weight cleared)", w)
	}
}

// TestMonitor_GlobalThresholdUnsetIsIndependent_5271 pins that with NO
// global-threshold configured, behavior is byte-identical to the historical
// per-target-independent debt: each failing target deducts its own weight.
func TestMonitor_GlobalThresholdUnsetIsIndependent_5271(t *testing.T) {
	// global-threshold 0 (unset), two targets of weight 40 and 30.
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.0.1", Weight: 40},
				{Address: "10.0.0.2", Weight: 30},
			},
		},
	}
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("all-reachable weight = %d, want 255", w)
	}

	// One target fails → its own weight (40) deducted immediately (independent).
	reach["10.0.0.1"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 215 {
		t.Fatalf("independent-mode one failure weight = %d, want 215 (255-40)", w)
	}

	// Both fail → 40+30 deducted.
	reach["10.0.0.2"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 185 {
		t.Fatalf("independent-mode both failing weight = %d, want 185 (255-40-30)", w)
	}
}

// TestMonitor_GlobalThresholdClearedOnDisable_5271 pins Finding 1: disabling
// global-threshold on a KEPT group must release a previously installed
// aggregate global-weight debt. UpdateConfig clears monitorWeights only for
// REMOVED groups and UpdateGroups just swaps the slice, so without the
// clear-on-disable path the deduction is stranded — the RG stays stuck at a
// wrong weight that can wrongly suppress or force a failover.
//
// Fail-on-revert: restore the bare early-return in applyRGIPMonitorThreshold
// and the crossed-then-disabled RG stays at 155 instead of returning to 255.
func TestMonitor_GlobalThresholdClearedOnDisable_5271(t *testing.T) {
	rg := thresholdRG(0, 100, 200, 100, "10.0.0.1", "10.0.0.2")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	// Cross the threshold: both weight-100 targets fail → cumulative 200 >= 200
	// → deduct global-weight 100.
	reach["10.0.0.1"] = false
	reach["10.0.0.2"] = false
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("crossed weight = %d, want 155 (255 - global-weight 100)", w)
	}
	if !mon.ipThresholdState[0] {
		t.Fatalf("ipThresholdState[0] = false, want true after crossing")
	}

	// Live reconfigure: SAME group kept, global-threshold disabled (0), targets
	// now healthy. UpdateConfig keeps the group and does NOT clear the stuck
	// aggregate debt.
	rgDisabled := thresholdRG(0, 100, 0, 100, "10.0.0.1", "10.0.0.2")
	cfg2 := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rgDisabled}}
	m.UpdateConfig(cfg2)
	mon.UpdateGroups(cfg2.RedundancyGroups)
	reach["10.0.0.1"] = true
	reach["10.0.0.2"] = true

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("after disabling global-threshold (group kept) weight = %d, want 255 "+
			"(stranded aggregate global-weight debt must be cleared)", w)
	}
	if mon.ipThresholdState[0] {
		t.Errorf("ipThresholdState[0] = true after disable, want false")
	}
}

// TestMonitor_GlobalThresholdClearedOnIPMonitoringRemoved_5271 is the harder
// Finding 1 variant: ip-monitoring is removed ENTIRELY (rg.IPMonitoring == nil)
// while the group is kept, so global-weight is no longer available to name the
// debt. The clear path must still release it via the fixed aggregate monitor
// name.
func TestMonitor_GlobalThresholdClearedOnIPMonitoringRemoved_5271(t *testing.T) {
	rg := thresholdRG(0, 100, 200, 100, "10.0.0.1", "10.0.0.2")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": false, "10.0.0.2": false}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("crossed weight = %d, want 155", w)
	}

	// Reconfigure: group kept but ip-monitoring dropped entirely.
	rgNoIPM := &config.RedundancyGroup{ID: 0, NodePriorities: map[int]int{0: 200}}
	cfg2 := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rgNoIPM}}
	m.UpdateConfig(cfg2)
	mon.UpdateGroups(cfg2.RedundancyGroups)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("after removing ip-monitoring (group kept) weight = %d, want 255 "+
			"(stranded aggregate debt must be cleared even when IPMonitoring is nil)", w)
	}
	if mon.ipThresholdState[0] {
		t.Errorf("ipThresholdState[0] = true after ip-monitoring removal, want false")
	}
}

// TestMonitor_GlobalThresholdEnabledClearsPerTargetDebts_5271 is the symmetric
// (Direction 2) Finding: enabling global-threshold on a KEPT group while a
// monitored target is already down must drop the stale per-target "ip:<addr>"
// debts installed in independent mode, replacing them with the single aggregate
// global-weight debt. If they coexist the RG is OVER-demoted (55 instead of
// 155 here) — a 100-point over-deduction that can force a spurious failover.
//
// The already-down targets produce no dampening transition after the switch, so
// only a full per-cycle reconcile (not transition-edge cleanup) can clear them.
//
// Fail-on-revert: disable the reconcile's stale-debt removal and the per-target
// debts persist alongside the aggregate debt → weight over-demotes below 155.
func TestMonitor_GlobalThresholdEnabledClearsPerTargetDebts_5271(t *testing.T) {
	// Independent mode (global-threshold 0): two weight-100 targets DOWN →
	// per-target debts → 255 - 100 - 100 = 55.
	rg := thresholdRG(0, 100, 0, 100, "10.0.0.1", "10.0.0.2")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": false, "10.0.0.2": false}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 55 {
		t.Fatalf("independent-mode both-down weight = %d, want 55 (255-100-100)", w)
	}

	// Enable global-threshold 200, SAME group kept, targets STILL down.
	rgAgg := thresholdRG(0, 100, 200, 100, "10.0.0.1", "10.0.0.2")
	cfg2 := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rgAgg}}
	m.UpdateConfig(cfg2)
	mon.UpdateGroups(cfg2.RedundancyGroups)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("after enabling global-threshold (targets still down) weight = %d, want 155 "+
			"(aggregate global-weight ONLY; stale per-target debts must be cleared, not coexist for 55)", w)
	}
	if !mon.ipThresholdState[0] {
		t.Errorf("ipThresholdState[0] = false, want true (aggregate installed)")
	}
}

// TestMonitor_GlobalThresholdEnabledSubThresholdClearsPerTargetDebts_5271 is the
// Direction 2 sub-threshold variant: enabling a global-threshold ABOVE the
// current cumulative failure while targets are down must clear the per-target
// debts and install NO aggregate debt → the RG returns to full health rather
// than staying demoted by the stale per-target debts.
func TestMonitor_GlobalThresholdEnabledSubThresholdClearsPerTargetDebts_5271(t *testing.T) {
	rg := thresholdRG(0, 100, 0, 100, "10.0.0.1", "10.0.0.2") // independent, both down
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": false, "10.0.0.2": false}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 55 {
		t.Fatalf("independent-mode both-down weight = %d, want 55", w)
	}

	// Enable global-threshold 300 — above the cumulative failure (200) — group
	// kept, targets still down. Aggregate NOT installed; per-target debts cleared.
	rgAgg := thresholdRG(0, 100, 300, 100, "10.0.0.1", "10.0.0.2")
	cfg2 := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rgAgg}}
	m.UpdateConfig(cfg2)
	mon.UpdateGroups(cfg2.RedundancyGroups)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("after enabling sub-threshold global-threshold weight = %d, want 255 "+
			"(cumulative 200 < 300 → no aggregate; stale per-target debts must be cleared)", w)
	}
	if mon.ipThresholdState[0] {
		t.Errorf("ipThresholdState[0] = true, want false (below threshold)")
	}
}

// TestMonitor_GlobalWeightChangeReinstallsAggregate_5271 is the third
// mode-switch edge: while an RG stays CROSSED (global-threshold unchanged,
// targets still down), the operator changes global-weight. An edge-triggered
// gate keyed only on the crossed↔cleared transition would skip re-installing
// the debt, leaving the STALE amount deducted until the RG clears and
// re-crosses. The per-cycle reconcile re-installs the aggregate at the CURRENT
// global-weight, so the deduction tracks the config.
//
// It also pins that steady state is quiet: a no-op poll after the change emits
// no new monitor event (the reconcile fires only on an actual change).
//
// Fail-on-revert: make the install loop skip when the debt name is already
// present regardless of weight, and the global-weight change is ignored — the
// RG stays at the stale 155 instead of 205.
func TestMonitor_GlobalThresholdGlobalWeightChangeWhileCrossed_5271(t *testing.T) {
	rg := thresholdRG(0, 100, 200, 100, "10.0.0.1", "10.0.0.2") // gw 100, threshold 200
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reach := map[string]bool{"10.0.0.1": false, "10.0.0.2": false}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	// Both down → cumulative 200 >= 200 → deduct global-weight 100 → 155.
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Fatalf("crossed weight = %d, want 155 (255 - global-weight 100)", w)
	}

	// Change global-weight 100 → 50, threshold unchanged, targets still down
	// (still crossed). The aggregate must re-install at the new weight.
	rg2 := thresholdRG(0, 50, 200, 100, "10.0.0.1", "10.0.0.2")
	cfg2 := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg2}}
	m.UpdateConfig(cfg2)
	mon.UpdateGroups(cfg2.RedundancyGroups)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 205 {
		t.Fatalf("after global-weight 100→50 (still crossed) weight = %d, want 205 (255-50), not stale 155", w)
	}

	// Steady state is quiet: a no-op poll (same config, same down state) must
	// not re-fire SetMonitorWeight / RecordEvent.
	before := len(m.EventHistoryFor(EventMonitor))
	mon.poll()
	if after := len(m.EventHistoryFor(EventMonitor)); after != before {
		t.Errorf("steady-state poll emitted %d new monitor event(s); want 0 (reconcile must be idempotent/quiet)", after-before)
	}
	if w := m.GroupStates()[0].Weight; w != 205 {
		t.Errorf("steady-state weight drifted to %d, want 205", w)
	}
}

// TestMonitor_GlobalThresholdPerRGIndependence_5271 pins that one RG's
// cumulative threshold state does not leak into another RG's decision.
func TestMonitor_GlobalThresholdPerRGIndependence_5271(t *testing.T) {
	// rg0: threshold 100, two weight-60 targets (one failure = 60 < 100).
	// rg1: threshold 100, two weight-60 targets.
	rg0 := thresholdRG(0, 100, 100, 60, "10.0.0.1", "10.0.0.2")
	rg1 := thresholdRG(1, 100, 100, 60, "10.1.0.1", "10.1.0.2")
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg0, rg1}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	reach := map[string]bool{
		"10.0.0.1": true, "10.0.0.2": true,
		"10.1.0.1": true, "10.1.0.2": true,
	}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()

	// rg0 crosses its threshold (both targets fail → 120 >= 100); rg1 stays
	// sub-threshold (one target fails → 60 < 100).
	reach["10.0.0.1"] = false
	reach["10.0.0.2"] = false
	reach["10.1.0.1"] = false
	mon.poll()

	states := m.GroupStates()
	var w0, w1 int
	for _, s := range states {
		switch s.GroupID {
		case 0:
			w0 = s.Weight
		case 1:
			w1 = s.Weight
		}
	}
	if w0 != 155 {
		t.Errorf("rg0 weight = %d, want 155 (crossed 120>=100, -100)", w0)
	}
	if w1 != 255 {
		t.Errorf("rg1 weight = %d, want 255 (sub-threshold 60<100, no debt) — rg0 state leaked", w1)
	}
}
