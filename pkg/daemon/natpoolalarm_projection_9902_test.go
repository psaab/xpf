package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// The daemon sampler's projection must carry every monitor field —
// including the #9902 F-026 exhaustion identity. Dropping a field here
// silently starves the monitor (a missing AllocatorID reads as legacy-0,
// a missing StatusSequence disables the freshness gate), so each copied
// field gets its own assertion.
func TestProjectNATPoolView9902(t *testing.T) {
	cfg := &config.Config{}
	got := projectNATPoolView(dpuserspace.AppliedNATView{
		Config: cfg,
		Pools: map[string]dpuserspace.AppliedNATPoolStatus{
			"p1": {
				PoolName: "p1", AddressCount: 2,
				PortLow: 10, PortHigh: 20, UsedPorts: 5,
				ExhaustionTotal: 7, AllocatorID: 9,
				LiveFlows: 23, MaxTrackedFlows: 29, PersistentLeases: 31,
			},
		},
		AppliedGeneration: 3,
		HelperCoherent:    true,
		Available:         true,
		StatusSequence:    11,
		ProcGen:           13,
	})

	if got.Config != cfg {
		t.Error("Config not projected")
	}
	if !got.Available || !got.HelperCoherent {
		t.Errorf("Available/HelperCoherent = %v/%v, want true/true", got.Available, got.HelperCoherent)
	}
	if got.StatusSequence != 11 {
		t.Errorf("StatusSequence = %d, want 11", got.StatusSequence)
	}
	if got.ProcGen != 13 {
		t.Errorf("ProcGen = %d, want 13", got.ProcGen)
	}
	p, ok := got.Pools["p1"]
	if !ok {
		t.Fatal("pool p1 missing from projection")
	}
	if p.PoolName != "p1" || p.AddressCount != 2 || p.PortLow != 10 || p.PortHigh != 20 || p.UsedPorts != 5 {
		t.Errorf("utilization sample wrong: %+v", p)
	}
	if p.ExhaustionTotal != 7 {
		t.Errorf("ExhaustionTotal = %d, want 7", p.ExhaustionTotal)
	}
	if p.AllocatorID != 9 {
		t.Errorf("AllocatorID = %d, want 9", p.AllocatorID)
	}
	if p.LiveFlows != 23 {
		t.Errorf("LiveFlows = %d, want 23", p.LiveFlows)
	}
	if p.MaxTrackedFlows != 29 {
		t.Errorf("MaxTrackedFlows = %d, want 29", p.MaxTrackedFlows)
	}
	if p.PersistentLeases != 31 {
		t.Errorf("PersistentLeases = %d, want 31", p.PersistentLeases)
	}
}

// An unavailable applied view projects to an unavailable monitor view.
func TestProjectNATPoolViewUnavailable9902(t *testing.T) {
	got := projectNATPoolView(dpuserspace.AppliedNATView{Available: false})
	if got.Available {
		t.Error("unavailable view must project to unavailable")
	}
}
