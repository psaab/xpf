package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16739: under preempt, elect on RAW priority while weight > 0. Junos
// fails an RG over only when its monitor threshold reaches zero, so a
// partial monitor loss must keep the higher-priority node primary.
// Kills the scaled-preempt mutant (EffectivePriority in the preempt
// arm): weight 155 scales 200 -> 121 < 150 and the RG flaps over/back.

func preemptPair16739(t *testing.T) (n0, n1 *Manager) {
	t.Helper()
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 150},
			InterfaceMonitors: []*config.InterfaceMonitor{{Interface: "ge-0/0/2", Weight: 100}},
		}},
	}
	n0, n1 = NewManager(0, 1), NewManager(1, 1)
	n0.UpdateConfig(cfg)
	n1.UpdateConfig(cfg)
	n0.takeoverHoldTime, n1.takeoverHoldTime = 0, 0
	for _, m := range []*Manager{n0, n1} {
		m.SetRGReady(1, true, nil)
		m.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	}
	exchangeElection12164(n0, n1)
	if !n0.IsLocalPrimary(1) || n1.IsLocalPrimary(1) {
		t.Fatalf("precondition: n0 primary=%v n1 primary=%v, want n0 only",
			n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
	}
	t.Cleanup(func() { n0.Stop(); n1.Stop() })
	return n0, n1
}

func TestPreemptPartialMonitorLossKeepsPrimary16739(t *testing.T) {
	n0, n1 := preemptPair16739(t)

	// Partial loss: weight 255 -> 155, threshold still > 0.
	n0.SetMonitorWeight(1, "ge-0/0/2", true, 100)
	if got := n0.GroupState(1).Weight; got != 155 {
		t.Fatalf("weight = %d, want 155", got)
	}
	fc0, fc1 := n0.GroupState(1).FailoverCount, n1.GroupState(1).FailoverCount
	exchangeElection12164(n0, n1)
	if !n0.IsLocalPrimary(1) || n1.IsLocalPrimary(1) {
		t.Fatalf("partial loss moved preempt RG: n0=%v n1=%v, want n0 primary",
			n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
	}
	if got := n0.GroupState(1).FailoverCount - fc0 + n1.GroupState(1).FailoverCount - fc1; got != 0 {
		t.Fatalf("failover count delta = %d, want 0 (no ownership move)", got)
	}

	// Recovery must NOT fail back: ownership never moved.
	n0.SetMonitorWeight(1, "ge-0/0/2", false, 100)
	exchangeElection12164(n0, n1)
	if !n0.IsLocalPrimary(1) || n1.IsLocalPrimary(1) {
		t.Fatalf("recovery moved preempt RG: n0=%v n1=%v", n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
	}
	if got := n0.GroupState(1).FailoverCount - fc0 + n1.GroupState(1).FailoverCount - fc1; got != 0 {
		t.Fatalf("failover count delta after recovery = %d, want 0", got)
	}

	// Full loss: weight -> 0. Only now may the RG fail over.
	n0.SetMonitorWeight(1, "ge-0/0/2", true, 255)
	if got := n0.GroupState(1).Weight; got != 0 {
		t.Fatalf("weight = %d, want 0", got)
	}
	exchangeElection12164(n0, n1)
	if n0.IsLocalPrimary(1) || !n1.IsLocalPrimary(1) {
		t.Fatalf("weight-0 loss did not fail over: n0=%v n1=%v, want n1 primary",
			n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
	}
}

// The peer-side mirror: a secondary with a partial loss must not be
// promoted over a healthy higher-priority primary by scaling either.
func TestPreemptPartialLossOnPeerKeepsPrimary16739(t *testing.T) {
	n0, n1 := preemptPair16739(t)
	n1.SetMonitorWeight(1, "ge-0/0/2", true, 100)
	exchangeElection12164(n0, n1)
	if !n0.IsLocalPrimary(1) || n1.IsLocalPrimary(1) {
		t.Fatalf("peer partial loss moved RG: n0=%v n1=%v", n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
	}
}

// Direct electRG cells: raw-priority tie and win/lose under partial
// weight, plus the weight-0 gate that must still resign.
func TestPreemptRawPriorityCells16739(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		localPrio, peerPrio         int
		localWeight, peerWeight     int
		localState, peerState, want NodeState
		wantPrimary                 bool
	}{
		{"partial-loss-wins", 200, 150, 155, 255, StatePrimary, StateSecondary, StatePrimary, true},
		{"partial-loss-secondary-stays", 150, 200, 255, 155, StateSecondary, StatePrimary, StateSecondary, false},
		{"raw-tie-lower-id-wins", 100, 100, 155, 255, StateSecondary, StateSecondary, StatePrimary, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(0, 1)
			m.peerAlive = true
			m.peerNodeID = 1
			rg := &RedundancyGroupState{GroupID: 1, State: tc.localState, Preempt: true,
				LocalPriority: tc.localPrio, Weight: tc.localWeight}
			peer := &PeerGroupState{GroupID: 1, Priority: tc.peerPrio, Weight: tc.peerWeight, State: tc.peerState}
			result, _ := m.electRG(rg, peer)
			gotPrimary := rg.State == StatePrimary || result == electLocalPrimary
			if tc.wantPrimary && result != electLocalPrimary && rg.State != StatePrimary {
				// electRG returns result only; State is applied by runElection.
				if result == electLocalSecondary {
					t.Fatalf("result = secondary, want primary")
				}
				_ = gotPrimary
			}
			if tc.wantPrimary && result == electLocalSecondary {
				t.Fatalf("electRG yielded under partial weight: prio %d/%d weight %d/%d",
					tc.localPrio, tc.peerPrio, tc.localWeight, tc.peerWeight)
			}
			if !tc.wantPrimary && result == electLocalPrimary {
				t.Fatalf("electRG promoted lower raw priority under partial weight")
			}
		})
	}
}

// #12164 must stay green under preempt: an arm-debt floor node (weight
// 1) must still lose to a healthy peer. This pins that the scaled
// ordering was NOT flattened away — the pin-release / yield ordering
// still uses EffectivePriority. Adapted from the non-preempt handback
// shape with Preempt: true.
func TestPreemptArmDebtFloorStillLoses12164_16739(t *testing.T) {
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100},
		}},
	}
	owner, peer := NewManager(0, 1), NewManager(1, 1)
	owner.UpdateConfig(cfg)
	peer.UpdateConfig(cfg)
	owner.takeoverHoldTime, peer.takeoverHoldTime = 0, 0
	owner.SetRGReady(1, true, nil)
	peer.SetRGReady(1, true, nil)
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	peer.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	exchangeElection12164(owner, peer)
	if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
		t.Fatal("precondition: owner primary / peer secondary")
	}
	t.Cleanup(func() { owner.Stop(); peer.Stop() })

	// Fresh-node arm debt: weight collapses to the floor 1. Even though
	// raw priority 200 > 100, a node whose dataplane is not ready must
	// not hold the RG against a healthy peer (the daemon installs this
	// debt from its closed-gate verdict; SetRGReady is not called here
	// so the peer's readiness gate is not the variable under test).
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	if got := owner.GroupState(1).Weight; got != 1 {
		t.Fatalf("arm-debt weight = %d, want floor 1", got)
	}
	exchangeElection12164(owner, peer)
	// NOTE: if this fails, the raw-priority preempt arm swallowed the
	// arm-debt yield — see the fix note in election.go. The expected
	// behaviour (owner yields) is the #12164 contract.
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("preempt arm-debt floor did not yield: owner=%v peer=%v (weights %d/%d)",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1),
			owner.GroupState(1).Weight, peer.GroupState(1).Weight)
	}
}

// #17781: the first arm-debt yield must be the LAST transition. On the
// defective code the yielded owner is secondary with positive arm debt
// while rg.Ready stays true, so the raw-priority preempt arm re-promotes
// it on the next heartbeat, the yield arm demotes it again, and the pair
// flaps at heartbeat rate with dual-primary windows and growing
// failover counts. The acceptance is exchange-level: after the first
// yield, 6+ further election exchanges produce zero transitions, zero
// dual-primary observations, and zero failover-count growth.
func armDebtYieldPair17781(t *testing.T, preempt bool) (owner, peer *Manager) {
	t.Helper()
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, Preempt: preempt, NodePriorities: map[int]int{0: 200, 1: 100},
		}},
	}
	owner, peer = NewManager(0, 1), NewManager(1, 1)
	owner.UpdateConfig(cfg)
	peer.UpdateConfig(cfg)
	owner.takeoverHoldTime, peer.takeoverHoldTime = 0, 0
	for _, m := range []*Manager{owner, peer} {
		m.SetRGReady(1, true, nil)
		m.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	}
	exchangeElection12164(owner, peer)
	if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
		t.Fatalf("precondition: owner primary=%v peer primary=%v, want owner only",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
	t.Cleanup(func() { owner.Stop(); peer.Stop() })
	return owner, peer
}

func assertArmDebtYieldStable17781(t *testing.T, owner, peer *Manager) {
	t.Helper()

	// Install arm debt on the higher-priority owner while it stays
	// Ready: arm debt and rg.Ready are independent signals, and it is
	// exactly this combination that flapped.
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	if got := owner.GroupState(1).Weight; got != 1 {
		t.Fatalf("arm-debt weight = %d, want floor 1", got)
	}

	// First yield: let the incumbent observe the peer, then relay its
	// demotion so the peer can take over. SetMonitorWeight may itself
	// run election, so only send the incumbent's heartbeat if it still
	// owns the RG.
	if owner.IsLocalPrimary(1) {
		owner.handlePeerHeartbeat(peer.buildHeartbeat())
	}
	if owner.IsLocalPrimary(1) {
		t.Fatal("higher-priority arm-debt owner did not yield")
	}
	peer.handlePeerHeartbeat(owner.buildHeartbeat())
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("first arm-debt yield did not hand over: owner=%v peer=%v",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
	fcOwner := owner.GroupState(1).FailoverCount
	fcPeer := peer.GroupState(1).FailoverCount

	// Eight further exchanges (32 heartbeat rounds), sampling after
	// every single heartbeat so transient dual-primary windows and
	// mid-exchange re-promotions are observed, not just endpoints.
	prevOwner, prevPeer := owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)
	transitions := 0
	observe := func(step string) {
		o, p := owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)
		if o && p {
			t.Fatalf("dual-primary observed at %s (owner and peer both primary)", step)
		}
		if o != prevOwner {
			transitions++
		}
		if p != prevPeer {
			transitions++
		}
		prevOwner, prevPeer = o, p
	}
	for range 8 {
		for range 4 {
			owner.handlePeerHeartbeat(peer.buildHeartbeat())
			observe("owner heartbeat")
			peer.handlePeerHeartbeat(owner.buildHeartbeat())
			observe("peer heartbeat")
		}
	}
	if transitions != 0 {
		t.Fatalf("transitions after first yield = %d, want 0 (owner=%v peer=%v)",
			transitions, owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
	if got := owner.GroupState(1).FailoverCount; got != fcOwner {
		t.Fatalf("owner failover count grew after first yield: %d -> %d", fcOwner, got)
	}
	if got := peer.GroupState(1).FailoverCount; got != fcPeer {
		t.Fatalf("peer failover count grew after first yield: %d -> %d", fcPeer, got)
	}
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("steady state lost: owner=%v peer=%v, want peer only",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
}

func TestPreemptArmDebtYieldDoesNotFlap17781(t *testing.T) {
	owner, peer := armDebtYieldPair17781(t, true)
	assertArmDebtYieldStable17781(t, owner, peer)

	// Clearing the arm debt must restore ordinary preempt ordering:
	// the higher-priority owner takes the RG back. This pins that the
	// anti-flap hold is debt-scoped, not a permanent demotion.
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	exchangeElection12164(owner, peer)
	if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
		t.Fatalf("arm-debt recovery did not fail back under preempt: owner=%v peer=%v",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
}

// Control: the identical fixture with preempt=false (pre-#17538
// semantics) yields once and is stable. Guards against a fix that
// "stabilises" by breaking the non-preempt yield itself.
func TestNonPreemptArmDebtYieldStable17781(t *testing.T) {
	owner, peer := armDebtYieldPair17781(t, false)
	assertArmDebtYieldStable17781(t, owner, peer)
}
