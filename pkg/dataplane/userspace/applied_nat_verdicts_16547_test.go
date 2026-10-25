package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16547: the applied snapshot's runtime quarantine must be readable by
// show surfaces. Before this, PoolUnusable/iface_snat_egress_overlap was
// stamped on the snapshot and consumed only by Rust; every NAT show
// surface re-derived its verdict from config and reported the rule armed.

func verdictsManager16547(t *testing.T, snap *ConfigSnapshot) *Manager {
	t.Helper()
	m := New()
	m.proc = selfProc(t)
	snap.Config = &config.Config{}
	m.lastSnapshot = snap
	m.markAppliedSnapshotLocked()
	return m
}

func TestAppliedNATSnapshotVerdicts16547(t *testing.T) {
	snap := &ConfigSnapshot{
		Generation: 3,
		SourceNAT: []SourceNATRuleSnapshot{
			{Name: "pool-snat", PoolName: "P", PoolUnusable: true, PoolUnusableReason: poolUnusableReasonIfaceOverlap},
			{Name: "iface-snat", InterfaceMode: true},
			{Name: "clean-snat", PoolName: "Q"},
		},
		NAT64: []NAT64RuleSnapshot{
			{Name: "n64-overlap", PoolUnusable: true, PoolUnusableReason: poolUnusableReasonIfaceOverlap},
			{Name: "n64-clean"},
		},
	}
	v := verdictsManager16547(t, snap).AppliedNATSnapshotVerdicts()
	if !v.Available {
		t.Fatal("verdicts unavailable after a reconciled apply")
	}
	if got := v.SourceNATRules["pool-snat"]; got != poolUnusableReasonIfaceOverlap {
		t.Errorf("SourceNATRules[pool-snat] = %q, want %q", got, poolUnusableReasonIfaceOverlap)
	}
	if _, ok := v.SourceNATRules["clean-snat"]; ok {
		t.Error("clean rule reported quarantined")
	}
	if _, ok := v.SourceNATRules["iface-snat"]; ok {
		t.Error("interface-mode rule reported quarantined")
	}
	if got := v.SourceNATPools["P"]; got != poolUnusableReasonIfaceOverlap {
		t.Errorf("SourceNATPools[P] = %q, want %q", got, poolUnusableReasonIfaceOverlap)
	}
	if _, ok := v.SourceNATPools["Q"]; ok {
		t.Error("clean pool Q reported quarantined")
	}
	if got := v.NAT64Rules["n64-overlap"]; got != poolUnusableReasonIfaceOverlap {
		t.Errorf("NAT64Rules[n64-overlap] = %q, want %q", got, poolUnusableReasonIfaceOverlap)
	}
	if _, ok := v.NAT64Rules["n64-clean"]; ok {
		t.Error("clean NAT64 rule-set reported quarantined")
	}
}

// A pool referenced by both a quarantined and a usable snapshot row stays
// armed at pool level (the usable row still translates), while the
// quarantined rule itself is still reported.
func TestAppliedNATSnapshotVerdictsPoolSharedWithUsableRow16547(t *testing.T) {
	snap := &ConfigSnapshot{
		Generation: 3,
		SourceNAT: []SourceNATRuleSnapshot{
			{Name: "bad", PoolName: "P", PoolUnusable: true, PoolUnusableReason: poolUnusableReasonIfaceOverlap},
			{Name: "good", PoolName: "P"},
		},
	}
	v := verdictsManager16547(t, snap).AppliedNATSnapshotVerdicts()
	if v.SourceNATRules["bad"] == "" {
		t.Error("quarantined rule not reported")
	}
	if _, ok := v.SourceNATPools["P"]; ok {
		t.Error("pool P reported quarantined though a usable row references it")
	}
}

func TestAppliedNATSnapshotVerdictsUnavailableBeforeApply16547(t *testing.T) {
	m := New()
	if v := m.AppliedNATSnapshotVerdicts(); v.Available {
		t.Fatal("verdicts available before any apply; must be unavailable so surfaces fall back to config")
	}
	// Deferred window: lastSnapshot is newer than the applied generation.
	m2 := New()
	m2.proc = selfProc(t)
	cfg := &config.Config{}
	m2.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 7, SourceNAT: []SourceNATRuleSnapshot{
		{Name: "pool-snat", PoolName: "P", PoolUnusable: true, PoolUnusableReason: poolUnusableReasonIfaceOverlap},
	}}
	m2.markAppliedSnapshotLocked()
	m2.lastSnapshot = &ConfigSnapshot{Config: cfg, Generation: 8, SourceNAT: []SourceNATRuleSnapshot{
		{Name: "pool-snat", PoolName: "P", PoolUnusable: true, PoolUnusableReason: poolUnusableReasonIfaceOverlap},
	}}
	if v := m2.AppliedNATSnapshotVerdicts(); v.Available {
		t.Fatal("verdicts available from an unapplied (deferred) snapshot; must not report a quarantine the helper has not accepted")
	}
}
