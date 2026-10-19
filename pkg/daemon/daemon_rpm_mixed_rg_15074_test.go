package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// mixedRG15074Config builds the #15074 shape: one ip-monitoring-referenced
// probe whose tests bind RETHs in two different redundancy groups, plus a
// source-address-bound test, an unbound sibling and an ungated probe.
func mixedRG15074Config() *config.Config {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"MIXED": {Name: "MIXED", Tests: map[string]*config.RPMTest{
			"rg1-iface": {Name: "rg1-iface", Target: "1.1.1.1", DestinationInterface: "reth0.50"},
			"rg2-iface": {Name: "rg2-iface", Target: "2.2.2.2", DestinationInterface: "reth1.50"},
			"rg2-src":   {Name: "rg2-src", Target: "3.3.3.3", SourceAddress: "10.0.1.1"},
			"plain":     {Name: "plain", Target: "4.4.4.4"},
		}},
		"FREE": {Name: "FREE", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: "8.8.8.8"},
		}},
	}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {Name: "wan-failover", MatchRPMProbe: "MIXED"},
	}}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1},
		"reth1": {Name: "reth1", RedundancyGroup: 2, Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, Addresses: []string{"10.0.1.1/24"}},
		}},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:        1,
		ControlInterface: "control0",
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0}, {ID: 1}, {ID: 2}},
	}
	return cfg
}

func daemonPrimaryFor15074(t *testing.T, primary map[int]bool) *Daemon {
	t.Helper()
	m := cluster.NewManager(0, 1)
	var rgs []*config.RedundancyGroup
	for _, id := range []int{1, 2} {
		prio := 100 // secondary (non-preempt, peer default wins)
		if primary[id] {
			prio = 200
		}
		rgs = append(rgs, &config.RedundancyGroup{ID: id, NodePriorities: map[int]int{0: prio}, Preempt: primary[id]})
	}
	m.UpdateConfig(&config.ClusterConfig{RethCount: len(rgs), ControlInterface: "control0", RedundancyGroups: rgs})
	for _, id := range []int{1, 2} {
		m.SetRGReady(id, true, nil)
	}
	for _, id := range []int{1, 2} {
		if got := m.IsLocalPrimary(id); got != primary[id] {
			t.Fatalf("setup: IsLocalPrimary(%d)=%v want %v", id, got, primary[id])
		}
	}
	return &Daemon{cluster: m}
}

func probeTestNames(p *config.RPMProbe) map[string]bool {
	out := map[string]bool{}
	if p == nil {
		return out
	}
	for name := range p.Tests {
		out[name] = true
	}
	return out
}

// TestMixedRGProbeGatesPerTest15074 is the #15074 regression: a node primary
// only for RG1 must run exactly the RG1 test of a probe whose tests span
// RG1+RG2 — not the whole probe, not none of it — and the result must be
// identical over 200 reconciles regardless of Go map iteration order.
// On the pre-fix probe-level last-writer-wins gate this fails: the chosen
// RG flips with map order so the filtered set is all-or-nothing and varies.
func TestMixedRGProbeGatesPerTest15074(t *testing.T) {
	cfg := mixedRG15074Config()

	// Per-test gating map is deterministic and exact.
	want := map[probeTestKey]int{
		{"MIXED", "rg1-iface"}: 1,
		{"MIXED", "rg2-iface"}: 2,
		{"MIXED", "rg2-src"}:   2,
		{"MIXED", "plain"}:     1, // unbound, probe-referenced: lowest data RG
	}
	for i := range 200 {
		got := rpmProbeTestGating(cfg)
		if len(got) != len(want) {
			t.Fatalf("iter %d: gating = %v, want %v", i, got, want)
		}
		for k, rg := range want {
			if got[k] != rg {
				t.Fatalf("iter %d: gating[%v]=%d want %d (full %v)", i, k, got[k], rg, got)
			}
		}
		if _, ok := got[probeTestKey{"FREE", "t"}]; ok {
			t.Fatalf("iter %d: ungated FREE/t must not be gated", i)
		}
	}

	// Node primary only for RG1 runs exactly the RG1 + unbound tests.
	rg1 := daemonPrimaryFor15074(t, map[int]bool{1: true, 2: false})
	for i := range 200 {
		eff := rg1.effectiveRPMConfig(cfg)
		names := probeTestNames(eff.Probes["MIXED"])
		if !names["rg1-iface"] || !names["plain"] || names["rg2-iface"] || names["rg2-src"] || len(names) != 2 {
			t.Fatalf("iter %d: RG1-primary effective MIXED tests = %v, want exactly {rg1-iface, plain}", i, names)
		}
		if eff.Probes["FREE"] == nil || !probeTestNames(eff.Probes["FREE"])["t"] {
			t.Fatalf("iter %d: ungated FREE must run everywhere", i)
		}
		// Authored config must not be mutated by filtering.
		if len(cfg.Services.RPM.Probes["MIXED"].Tests) != 4 {
			t.Fatalf("iter %d: authored MIXED mutated to %d tests", i, len(cfg.Services.RPM.Probes["MIXED"].Tests))
		}
	}

	// Node primary only for RG2 runs exactly the RG2 tests.
	rg2 := daemonPrimaryFor15074(t, map[int]bool{1: false, 2: true})
	eff := rg2.effectiveRPMConfig(cfg)
	names := probeTestNames(eff.Probes["MIXED"])
	if names["rg1-iface"] || names["plain"] || !names["rg2-iface"] || !names["rg2-src"] || len(names) != 2 {
		t.Fatalf("RG2-primary effective MIXED tests = %v, want exactly {rg2-iface, rg2-src}", names)
	}

	// Primary for both runs all; primary for neither drops the gated probe
	// but keeps the ungated one.
	both := daemonPrimaryFor15074(t, map[int]bool{1: true, 2: true})
	if n := len(probeTestNames(both.effectiveRPMConfig(cfg).Probes["MIXED"])); n != 4 {
		t.Fatalf("both-primary MIXED tests = %d, want 4", n)
	}
	none := daemonPrimaryFor15074(t, map[int]bool{1: false, 2: false})
	effNone := none.effectiveRPMConfig(cfg)
	if _, ok := effNone.Probes["MIXED"]; ok {
		t.Fatalf("neither-primary must drop MIXED entirely, got %v", probeTestNames(effNone.Probes["MIXED"]))
	}
	if effNone.Probes["FREE"] == nil {
		t.Fatal("neither-primary must keep ungated FREE")
	}

	// Probe-level representative view is deterministic (lowest test RG).
	if got := rpmProbeGatingRGs(cfg)["MIXED"]; got != 1 {
		t.Fatalf("rpmProbeGatingRGs[MIXED]=%d want 1 (deterministic minimum)", got)
	}

}

// TestProbeLevelGatingControl15074 preserves the neighbouring legitimate
// behaviour: a single-RG probe is all-or-nothing exactly as before.
func TestProbeLevelGatingControl15074(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: "1.1.1.1", DestinationInterface: "reth0.50"},
		}},
	}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"p": {Name: "p", MatchRPMProbe: "WAN"},
	}}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1},
		"reth1": {Name: "reth1", RedundancyGroup: 2},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{{ID: 0}, {ID: 1}, {ID: 2}}}

	sec := daemonPrimaryFor15074(t, map[int]bool{1: false, 2: true})
	if _, ok := sec.effectiveRPMConfig(cfg).Probes["WAN"]; ok {
		t.Fatal("single-RG control: RG1-secondary must drop WAN")
	}
	pri := daemonPrimaryFor15074(t, map[int]bool{1: true, 2: false})
	if _, ok := pri.effectiveRPMConfig(cfg).Probes["WAN"]; !ok {
		t.Fatal("single-RG control: RG1-primary must keep WAN")
	}
}
