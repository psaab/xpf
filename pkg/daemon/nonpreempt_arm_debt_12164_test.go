package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

func TestUnattachedDataplaneClosesTransitAndKeepsStandalonePrimary12164(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "0")
	fence := withBarrierRecorder(t)
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{{
		ID: 1, NodePriorities: map[int]int{0: 200},
	}}})
	d, rt := armTrackDaemon(t, m, 1)
	d.markDataplaneArmed("test-ready")
	if !m.IsLocalPrimary(1) || rgWeight(t, m, 1) != 255 {
		t.Fatal("precondition: standalone armed node must hold primary at full weight")
	}

	// A fresh kernel census sees the last XDP link disappear. The same closed
	// gate verdict installs arm debt, but the floor of 1 must preserve a solo
	// node's repair path and VIP ownership.
	rt.setCount(0, false)
	d.reassertTransitGate("test-detach")
	waitTransitKnobs9725(t, v4, v6, "0")
	if got := lastBarrierCall(fence); got != "install" {
		t.Fatalf("closed transit gate barrier = %q, want install", got)
	}
	if got := rgWeight(t, m, 1); got != 1 {
		t.Fatalf("standalone arm-debt weight = %d, want floor 1", got)
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("closed-gate standalone node lost primary ownership")
	}
	foundRG, foundArmDebt := false, false
	for _, state := range m.GroupStates() {
		if state.GroupID != 1 {
			continue
		}
		foundRG = true
		for _, iface := range state.MonitorFails {
			foundArmDebt = foundArmDebt || iface == cluster.DataplaneArmMonitorIface
		}
	}
	if !foundRG {
		t.Fatal("redundancy group 1 not found")
	}
	if !foundArmDebt {
		t.Fatal("closed transit gate did not install arm debt")
	}
}
