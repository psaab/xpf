package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func exchangeElection12164(owner, peer *Manager) {
	for range 4 {
		owner.handlePeerHeartbeat(peer.buildHeartbeat())
		peer.handlePeerHeartbeat(owner.buildHeartbeat())
	}
}

func TestNonPreemptDataplaneArmDebtYieldsToReadyPeer12164(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, NodePriorities: map[int]int{0: 200, 1: 100},
		}},
	}
	owner, peer := NewManager(0, 1), NewManager(1, 1)
	owner.UpdateConfig(cfg)
	peer.UpdateConfig(cfg)
	owner.takeoverHoldTime, peer.takeoverHoldTime = 0, 0
	owner.SetRGReady(1, true, nil)
	peer.SetRGReady(1, true, nil)

	// Both nodes first prove their dataplane ready. The higher-priority owner
	// wins before the fault, with non-preempt enabled and the peer secondary.
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	peer.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	exchangeElection12164(owner, peer)
	if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
		t.Fatalf("precondition: owner=%v peer=%v; expected a non-preempt incumbent",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}

	// Losing the owner's XDP link is the production transition: the daemon
	// installs this reserved monitor debt from its closed-gate verdict.
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	if got := rgWeight9842(t, owner, 1).Weight; got != 1 {
		t.Fatalf("arm-debt incumbent weight = %d, want the intentional standalone floor 1", got)
	}
	exchangeElection12164(owner, peer)

	ownerState, peerState := rgWeight9842(t, owner, 1), rgWeight9842(t, peer, 1)
	t.Logf("non-preempt arm-debt election: owner primary=%v weight=%d; ready peer primary=%v weight=%d; preempt=%v",
		owner.IsLocalPrimary(1), ownerState.Weight, peer.IsLocalPrimary(1), peerState.Weight, ownerState.Preempt)
	if ownerState.Preempt {
		t.Fatal("fixture must preserve the canonical non-preempt setting")
	}
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("unready incumbent retained the RG over ready peer: owner=%v/%d peer=%v/%d",
			owner.IsLocalPrimary(1), ownerState.Weight, peer.IsLocalPrimary(1), peerState.Weight)
	}
	if peerState.Weight != maxRedundancyGroupWeight {
		t.Fatalf("ready peer weight = %d, want %d", peerState.Weight, maxRedundancyGroupWeight)
	}

	// Recovering the old owner clears its debt but must not undo a non-preempt
	// transfer; ownership stays with the peer until another explicit transfer.
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	exchangeElection12164(owner, peer)
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("recovery preempted the new incumbent: owner=%v peer=%v",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
}

func TestNonPreemptDataplaneArmDebtKeepsStandalonePrimary12164(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{{
		ID: 1, NodePriorities: map[int]int{0: 200},
	}}})
	if !m.IsLocalPrimary(1) {
		t.Fatal("precondition: standalone node should be primary")
	}
	m.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	if got := rgWeight9842(t, m, 1).Weight; got != 1 {
		t.Fatalf("standalone arm-debt weight = %d, want floor 1", got)
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("standalone node lost primary at the arm-debt floor")
	}
}

func TestNonPreemptOrdinaryMonitorDebtStillKeepsIncumbent12164(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{{
		ID: 1, NodePriorities: map[int]int{0: 200},
	}}})
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{
			GroupID: 1, Priority: 255, Weight: maxRedundancyGroupWeight, State: uint8(StateSecondary),
		}},
	})
	if !m.IsLocalPrimary(1) {
		t.Fatal("precondition: local node should be incumbent")
	}
	m.SetMonitorWeight(1, "ge-0/0/0", true, maxRedundancyGroupWeight-1)
	if got := rgWeight9842(t, m, 1).Weight; got != 1 {
		t.Fatalf("ordinary monitor debt weight = %d, want 1", got)
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("ordinary monitor debt changed the established non-preempt rule")
	}
}
