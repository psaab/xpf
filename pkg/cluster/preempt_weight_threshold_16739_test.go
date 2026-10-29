package cluster

import (
	"testing"
	"time"

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

func yieldArmDebtToPeer17781(t *testing.T, owner, peer *Manager) (fcOwner, fcPeer int) {
	t.Helper()

	// Install arm debt on the higher-priority owner while it stays
	// Ready: arm debt and rg.Ready are independent signals.
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
	return owner.GroupState(1).FailoverCount, peer.GroupState(1).FailoverCount
}

func assertArmDebtYieldStable17781(t *testing.T, owner, peer *Manager) {
	t.Helper()
	fcOwner, fcPeer := yieldArmDebtToPeer17781(t, owner, peer)

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

// #17781 fold: crossed-fresh-heartbeat ordering. The peer's SECONDARY
// frame is built BEFORE the owner's yield completes the handoff, so the
// owner consumes it AFTER the peer has taken over from the owner's own
// SECONDARY frame. Sampling both directions on every delivery: the
// owner must not re-promote on the in-flight SECONDARY frame (the hold
// must cover the handoff transient, not only the settled
// peer-primary view), and no step may observe dual-primary.
func TestPreemptArmDebtCrossedHeartbeats17781(t *testing.T) {
	owner, peer := armDebtYieldPair17781(t, true)
	// Capture a fresh peer SECONDARY frame before the owner's arm debt
	// triggers the handoff.
	peerSecondary := peer.buildHeartbeat()
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	owner.mu.RLock()
	yielded := owner.groups[1].armDebtYielded
	owner.mu.RUnlock()
	if !yielded {
		t.Fatal("fixture: applied arm-debt yield did not set sticky hold")
	}

	if owner.IsLocalPrimary(1) {
		owner.handlePeerHeartbeat(peerSecondary)
	}
	if owner.IsLocalPrimary(1) {
		t.Fatal("higher-priority arm-debt owner did not yield")
	}
	// The peer takes over from the owner's demotion.
	peer.handlePeerHeartbeat(owner.buildHeartbeat())
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("handoff incomplete: owner=%v peer=%v", owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
	fcOwner := owner.GroupState(1).FailoverCount
	fcPeer := peer.GroupState(1).FailoverCount

	// The in-flight peer-SECONDARY frame now lands on the owner.
	owner.handlePeerHeartbeat(peerSecondary)
	if owner.IsLocalPrimary(1) && peer.IsLocalPrimary(1) {
		t.Fatal("dual-primary after crossed heartbeats: owner re-promoted over its own arm-debt yield")
	}
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("crossed heartbeat flipped ownership: owner=%v peer=%v", owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
	// Settle with fresh exchanges: still peer-owned, no count growth.
	exchangeElection12164(owner, peer)
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("post-cross settle flipped ownership: owner=%v peer=%v", owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
	if got := owner.GroupState(1).FailoverCount; got != fcOwner {
		t.Fatalf("owner failover count grew: %d -> %d", fcOwner, got)
	}
	if got := peer.GroupState(1).FailoverCount; got != fcPeer {
		t.Fatalf("peer failover count grew: %d -> %d", fcPeer, got)
	}
}

// #17781 fold: owner→peer heartbeat-loss burst. Capture six fresh
// peer-SECONDARY frames (strictly increasing sequences) before the owner
// yields, then deliver them only peer→owner after the peer has taken over.
// The owner→peer heartbeat direction is silent during the burst; these are
// in-flight frames, not replayed packets.
func TestPreemptArmDebtPeerOnlyBurst17781(t *testing.T) {
	owner, peer := armDebtYieldPair17781(t, true)
	peerFrames := make([]*HeartbeatPacket, 0, 6)
	for range 6 {
		peer.handlePeerHeartbeat(owner.buildHeartbeat())
		peerFrames = append(peerFrames, peer.buildHeartbeat())
	}

	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	start := 0
	if owner.IsLocalPrimary(1) {
		owner.handlePeerHeartbeat(peerFrames[0])
		start = 1
	}
	if owner.IsLocalPrimary(1) {
		t.Fatal("higher-priority arm-debt owner did not yield")
	}
	peer.handlePeerHeartbeat(owner.buildHeartbeat())
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatalf("handoff incomplete: owner=%v peer=%v", owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
	fcOwner := owner.GroupState(1).FailoverCount
	fcPeer := peer.GroupState(1).FailoverCount

	for i := start; i < len(peerFrames); i++ {
		owner.handlePeerHeartbeat(peerFrames[i])
		o, p := owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)
		if o && p {
			t.Fatalf("dual-primary during peer-only burst frame %d", i)
		}
		if o || !p {
			t.Fatalf("ownership changed during peer-only burst frame %d: owner=%v peer=%v", i, o, p)
		}
	}
	if got := owner.GroupState(1).FailoverCount; got != fcOwner {
		t.Fatalf("owner failover count grew during burst: %d -> %d", fcOwner, got)
	}
	if got := peer.GroupState(1).FailoverCount; got != fcPeer {
		t.Fatalf("peer failover count grew during burst: %d -> %d", fcPeer, got)
	}
}

// #17781 fold: the yield hold must RELEASE when its conditions end.
// Pins the release/change boundaries that keep the hold from becoming
// a permanent demotion or an availability hole.
func TestPreemptArmDebtHoldRelease17781(t *testing.T) {
	t.Run("peer_death_promotes", func(t *testing.T) {
		owner, peer := armDebtYieldPair17781(t, true)
		yieldArmDebtToPeer17781(t, owner, peer)
		owner.handlePeerTimeout()
		if !owner.IsLocalPrimary(1) {
			t.Fatal("yielded owner did not promote after peer death")
		}
	})
	t.Run("secondary_echo_lease_expired_promotes", func(t *testing.T) {
		owner, peer := armDebtYieldPair17781(t, true)
		yieldArmDebtToPeer17781(t, owner, peer)

		// The peer has relinquished but its last SECONDARY frame no longer
		// proves bidirectional liveness. An expired lease must not pin the
		// yielded owner secondary indefinitely.
		peer.mu.Lock()
		peer.groups[1].State = StateSecondary
		peer.mu.Unlock()
		owner.mu.Lock()
		pg := owner.peerGroups[1]
		pg.State = StateSecondary
		pg.heartbeatEchoLeaseUntil = time.Now().Add(-time.Millisecond)
		owner.peerGroups[1] = pg
		owner.runElection()
		owner.mu.Unlock()
		if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
			t.Fatalf("expired peer echo did not release ownership safely: owner=%v peer=%v",
				owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
		}
	})
	t.Run("peer_restart_secondary_releases", func(t *testing.T) {
		owner, peer := armDebtYieldPair17781(t, true)
		yieldArmDebtToPeer17781(t, owner, peer)

		cfg := &config.ClusterConfig{
			ControlInterface: "em0",
			RedundancyGroups: []*config.RedundancyGroup{{
				ID: 1, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100},
			}},
		}
		restartedPeer := NewManager(1, 1)
		restartedPeer.UpdateConfig(cfg)
		t.Cleanup(restartedPeer.Stop)
		if restartedPeer.LocalProcessToken() == peer.LocalProcessToken() {
			t.Fatal("fixture: restarted peer reused its process session")
		}
		// A fresh peer can be SECONDARY before takeover readiness catches up.
		// Its new-session frame must release the old handoff latch instead
		// of holding both nodes secondary through every heartbeat.
		restartedPeer.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
		restartedPeer.handlePeerHeartbeat(owner.buildHeartbeat())
		if restartedPeer.IsLocalPrimary(1) {
			t.Fatal("fixture: restarted secondary unexpectedly promoted before its readiness gate")
		}
		owner.handlePeerHeartbeat(restartedPeer.buildHeartbeat())
		if !owner.IsLocalPrimary(1) || restartedPeer.IsLocalPrimary(1) {
			t.Fatalf("new peer session failed to release yielded owner: owner=%v restartedPeer=%v",
				owner.IsLocalPrimary(1), restartedPeer.IsLocalPrimary(1))
		}
		owner.mu.RLock()
		held := owner.groups[1].armDebtYielded
		owner.mu.RUnlock()
		if held {
			t.Fatal("old arm-debt hold survived peer-session change")
		}
		restartedPeer.handlePeerHeartbeat(owner.buildHeartbeat())
		if !owner.IsLocalPrimary(1) || restartedPeer.IsLocalPrimary(1) {
			t.Fatalf("restart recovery caused dual-primary: owner=%v restartedPeer=%v",
				owner.IsLocalPrimary(1), restartedPeer.IsLocalPrimary(1))
		}
	})

	t.Run("peer_weight0_promotes", func(t *testing.T) {
		owner, peer := armDebtYieldPair17781(t, true)
		yieldArmDebtToPeer17781(t, owner, peer)
		peer.SetMonitorWeight(1, "ge-0/0/2", true, 255)
		if got := peer.GroupState(1).Weight; got != 0 {
			t.Fatalf("peer weight = %d, want 0", got)
		}
		exchangeElection12164(owner, peer)
		if !owner.IsLocalPrimary(1) {
			t.Fatal("yielded owner did not promote over a weight-0 peer")
		}
	})

	t.Run("peer_partial_demotion_holds", func(t *testing.T) {
		owner, peer := armDebtYieldPair17781(t, true)
		yieldArmDebtToPeer17781(t, owner, peer)
		// Peer partial loss: weight 255 -> 155. Scaled ordering still
		// beats the yielded owner's floor Eff(200,1)=0, so the hold must
		// stay and ownership must not move.
		peer.SetMonitorWeight(1, "ge-0/0/2", true, 100)
		if got := peer.GroupState(1).Weight; got != 155 {
			t.Fatalf("peer weight = %d, want 155", got)
		}
		exchangeElection12164(owner, peer)
		if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
			t.Fatalf("peer partial demotion flipped ownership: owner=%v peer=%v", owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
		}
	})

	t.Run("peer_weight_crossing_holds", func(t *testing.T) {
		owner, peer := armDebtYieldPair17781(t, true)
		yieldArmDebtToPeer17781(t, owner, peer)
		// Peer weight 3 -> 2 (monitor cost 253): Eff(100,3)=1 > 0,
		// Eff(100,2)=0 ties the yielded owner's floor Eff(200,1)=0
		// while raw-weight ordering still favours the peer. A bare
		// predicate-only hold releases into dual-primary here; the
		// sticky yield hold must not.
		peer.SetMonitorWeight(1, "ge-0/0/2", true, 252)
		if got := peer.GroupState(1).Weight; got != 3 {
			t.Fatalf("peer weight = %d, want 3", got)
		}
		exchangeElection12164(owner, peer)
		if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
			t.Fatalf("weight-3 transition flipped ownership: owner=%v peer=%v",
				owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
		}
		peer.SetMonitorWeight(1, "ge-0/0/2", true, 253)
		if got := peer.GroupState(1).Weight; got != 2 {
			t.Fatalf("peer weight = %d, want 2", got)
		}
		for exchange := range 4 {
			owner.handlePeerHeartbeat(peer.buildHeartbeat())
			if owner.IsLocalPrimary(1) && peer.IsLocalPrimary(1) {
				t.Fatalf("dual-primary at crossing exchange %d", exchange)
			}
			peer.handlePeerHeartbeat(owner.buildHeartbeat())
			if owner.IsLocalPrimary(1) && peer.IsLocalPrimary(1) {
				t.Fatalf("dual-primary at crossing exchange %d", exchange)
			}
		}
		if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
			t.Fatalf("weight crossing flipped ownership: owner=%v peer=%v", owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
		}
	})

	t.Run("peer_both_floor_releases", func(t *testing.T) {
		owner, peer := armDebtYieldPair17781(t, true)
		yieldArmDebtToPeer17781(t, owner, peer)
		// Peer falls to the SAME arm floor: neither node is healthier,
		// so the yield's reason is gone. Ordinary arms resume; the
		// peer stays down and the owner reclaims LonePrimary rather
		// than both sitting at the floor.
		peer.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
		if got := peer.GroupState(1).Weight; got != 1 {
			t.Fatalf("peer weight = %d, want floor 1", got)
		}
		exchangeElection12164(owner, peer)
		if !owner.IsLocalPrimary(1) {
			t.Fatal("owner did not reclaim when both nodes sit at the arm floor")
		}
		if peer.IsLocalPrimary(1) {
			t.Fatal("dual-primary when both nodes sit at the arm floor")
		}
	})
}

func TestPreemptArmDebtYieldDoesNotFlap17781(t *testing.T) {
	owner, peer := armDebtYieldPair17781(t, true)
	assertArmDebtYieldStable17781(t, owner, peer)

	// Clearing arm debt permits preemptive recovery, but each step of the
	// handback must remain single-primary while the peer consumes demotion.
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	assertNoDual := func(step string) {
		t.Helper()
		if owner.IsLocalPrimary(1) && peer.IsLocalPrimary(1) {
			t.Fatalf("dual-primary during recovery at %s", step)
		}
	}
	assertNoDual("debt cleared")
	for range 4 {
		owner.handlePeerHeartbeat(peer.buildHeartbeat())
		assertNoDual("owner receives peer heartbeat")
		peer.handlePeerHeartbeat(owner.buildHeartbeat())
		assertNoDual("peer receives owner heartbeat")
	}
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
