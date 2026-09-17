package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func rgWeight9842(t *testing.T, m *Manager, rgID int) RedundancyGroupState {
	t.Helper()
	for _, rg := range m.GroupStates() {
		if rg.GroupID == rgID {
			return rg
		}
	}
	t.Fatalf("RG %d not found", rgID)
	return RedundancyGroupState{}
}

func TestHAConfigStartsRGAtLosingWeight9842(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}, Preempt: true,
		}},
	})

	rg := rgWeight9842(t, m, 0)
	if rg.Weight != 1 {
		t.Fatalf("first HA election weight = %d, want losing floor 1 before XDP proof", rg.Weight)
	}
	if len(rg.MonitorFails) != 1 || rg.MonitorFails[0] != DataplaneArmMonitorIface {
		t.Fatalf("first HA election monitor debt = %v, want [%s]", rg.MonitorFails, DataplaneArmMonitorIface)
	}
}

func TestHAConfigRaisesRGOnFirstReadyReevaluation9842(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0, NodePriorities: map[int]int{0: 200}}},
	})
	if got := rgWeight9842(t, m, 0).Weight; got != 1 {
		t.Fatalf("precondition weight = %d, want 1", got)
	}

	// This is the same transition driven by the daemon's ready-to-serve
	// re-evaluation once armed && AttachedXDPLinkCount > 0 is proven.
	m.SetMonitorWeight(0, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	if got := rgWeight9842(t, m, 0).Weight; got != 255 {
		t.Fatalf("first ready re-evaluation weight = %d, want full 255", got)
	}
}

func TestStandaloneConfigKeepsImmediateFullWeight9842(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0, NodePriorities: map[int]int{0: 200}}},
	})

	rg := rgWeight9842(t, m, 0)
	if rg.Weight != 255 {
		t.Fatalf("standalone first election weight = %d, want unchanged full 255", rg.Weight)
	}
	if len(rg.MonitorFails) != 0 {
		t.Fatalf("standalone first election monitor debt = %v, want none", rg.MonitorFails)
	}
}

func TestHASingleNodeStillElectsAtLosingFloor9842(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0, NodePriorities: map[int]int{0: 200}, Preempt: true}},
	})
	if m.IsLocalPrimary(0) {
		t.Fatal("precondition: HA RG must wait for local readiness before self-election")
	}

	// Once ordinary local readiness is proven, the existing floor semantics
	// still let an isolated node self-elect rather than disappear; the low bid
	// only prevents it from beating a fully attached peer.
	m.SetRGReady(0, true, nil)
	if !m.IsLocalPrimary(0) {
		t.Fatal("single-node HA RG did not self-elect after bounded readiness")
	}
}
