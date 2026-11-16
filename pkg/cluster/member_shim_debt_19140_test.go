package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #19140: the RETH member-shim debt sits at the arm floor (weight 1, never 0)
// and joins the #12164 floor-debt yield. These cells pin the election side:
// E1 a charged primary yields to a healthy ready peer; E2 two charged nodes do
// not move; E3 (readiness_section_19140_test.go) a flagged not-ready peer gets
// no yield, an older peer the #12164 behaviour;
// E4 a lone owner keeps it; E5 arm and member-shim debt compose to weight 1, not 0; E6 the yielded
// RG is not re-taken by raw-priority preempt while the debt holds; E7 a healthy
// primary never yields to a charged standby, and a healthy standby still
// preempts normally.

func memberShimPair19140(t *testing.T, preempt bool, ownerPri, peerPri int) (owner, peer *Manager) {
	t.Helper()
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, Preempt: preempt, NodePriorities: map[int]int{0: ownerPri, 1: peerPri},
		}},
	}
	owner, peer = NewManager(0, 1), NewManager(1, 1)
	owner.UpdateConfig(cfg)
	peer.UpdateConfig(cfg)
	owner.takeoverHoldTime, peer.takeoverHoldTime = 0, 0
	owner.SetRGReady(1, true, nil)
	peer.SetRGReady(1, true, nil)
	owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	peer.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	t.Cleanup(func() { owner.Stop(); peer.Stop() })
	return owner, peer
}

func chargeMemberShim19140(m *Manager, on bool) {
	m.SetMonitorWeight(1, RethMemberShimMonitorIface, on, RethMemberShimMonitorCost)
}

// rounds19140 exchanges heartbeats and counts ownership transitions and
// dual-primary rounds.
func rounds19140(owner, peer *Manager, n int) (transitions, dual int) {
	last := [2]bool{owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)}
	for range n {
		owner.handlePeerHeartbeat(peer.buildHeartbeat())
		peer.handlePeerHeartbeat(owner.buildHeartbeat())
		now := [2]bool{owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)}
		if now != last {
			transitions++
		}
		if now[0] && now[1] {
			dual++
		}
		last = now
	}
	return transitions, dual
}

func modes19140() []struct {
	name    string
	preempt bool
} {
	return []struct {
		name    string
		preempt bool
	}{{"preempt", true}, {"non-preempt", false}}
}

// E1.
func TestMemberShimDebtYieldsToHealthyReadyPeer19140(t *testing.T) {
	for _, mode := range modes19140() {
		t.Run(mode.name, func(t *testing.T) {
			owner, peer := memberShimPair19140(t, mode.preempt, 200, 100)
			exchangeElection12164(owner, peer)
			if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
				t.Fatal("precondition: owner primary, peer secondary")
			}
			chargeMemberShim19140(owner, true)
			if got := rgWeight9842(t, owner, 1).Weight; got != 1 {
				t.Fatalf("charged owner weight = %d, want the floor 1", got)
			}
			tr, dual := rounds19140(owner, peer, 10)
			if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) || tr != 1 || dual != 0 {
				t.Fatalf("owner=%v peer=%v transitions=%d dual=%d: a shim-less primary must yield once to a healthy ready peer",
					owner.IsLocalPrimary(1), peer.IsLocalPrimary(1), tr, dual)
			}
		})
	}
}

// E2.
func TestMemberShimDebtOnBothNodesDoesNotMove19140(t *testing.T) {
	for _, mode := range modes19140() {
		t.Run(mode.name, func(t *testing.T) {
			owner, peer := memberShimPair19140(t, mode.preempt, 200, 100)
			exchangeElection12164(owner, peer)
			chargeMemberShim19140(peer, true)
			owner.handlePeerHeartbeat(peer.buildHeartbeat())
			chargeMemberShim19140(owner, true)
			tr, dual := rounds19140(owner, peer, 10)
			if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) || tr != 0 || dual != 0 {
				t.Fatalf("owner=%v peer=%v transitions=%d dual=%d: two equally charged nodes must not move the RG",
					owner.IsLocalPrimary(1), peer.IsLocalPrimary(1), tr, dual)
			}
		})
	}
}

// E3 lives in readiness_section_19140_test.go: the yield toward a not-ready
// peer depends on the peer's heartbeat readiness section.

// E4.
func TestMemberShimDebtLoneOwnerKeepsRG19140(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{{
		ID: 1, NodePriorities: map[int]int{0: 200},
	}}})
	t.Cleanup(m.Stop)
	if !m.IsLocalPrimary(1) {
		t.Fatal("precondition: a standalone node is primary")
	}
	chargeMemberShim19140(m, true)
	if !m.IsLocalPrimary(1) {
		t.Fatal("a lone owner with member-shim debt resigned the RG; it must keep it at the floor")
	}
	if got := rgWeight9842(t, m, 1).Weight; got != 1 {
		t.Fatalf("lone owner weight = %d, want 1", got)
	}
}

// E5.
func TestMemberShimAndArmDebtComposeToTheFloor19140(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{{
		ID: 1, NodePriorities: map[int]int{0: 200},
	}}})
	t.Cleanup(m.Stop)
	m.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	chargeMemberShim19140(m, true)
	if got := rgWeight9842(t, m, 1).Weight; got != 1 {
		t.Fatalf("arm + member-shim weight = %d, want the floor 1 (they share the MAX group, never stack to 0)", got)
	}
	if !m.IsLocalPrimary(1) {
		t.Fatal("arm + member-shim debt resigned a lone owner")
	}
}

// E6: preempt, the charged higher-priority node yields and then must not
// re-take the RG by raw priority while its debt holds. Once the debt clears,
// ordinary preempt moves it back (a planned move).
func TestMemberShimYieldHoldsWhileDebtStays19140(t *testing.T) {
	owner, peer := memberShimPair19140(t, true, 200, 100)
	exchangeElection12164(owner, peer)
	chargeMemberShim19140(owner, true)
	rounds19140(owner, peer, 10)
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatal("precondition: the charged owner yielded")
	}
	tr, dual := rounds19140(owner, peer, 20)
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) || tr != 0 || dual != 0 {
		t.Fatalf("owner=%v peer=%v transitions=%d dual=%d: the yielded RG flapped back while the debt held",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1), tr, dual)
	}
	chargeMemberShim19140(owner, false)
	rounds19140(owner, peer, 20)
	if !owner.IsLocalPrimary(1) || peer.IsLocalPrimary(1) {
		t.Fatalf("owner=%v peer=%v: after the debt cleared, preempt should move the RG back to the higher-priority owner",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1))
	}
}

// E7: a healthy primary at 255 never yields to a charged standby, even one
// with higher priority under preempt. The twin shows that the same standby,
// healthy and ready, still preempts normally, so E7 cannot pass by disabling
// yields altogether.
func TestHealthyPrimaryNeverYieldsToChargedStandby19140(t *testing.T) {
	for _, mode := range modes19140() {
		t.Run(mode.name+"/charged-standby", func(t *testing.T) {
			owner, standby := memberShimPair19140(t, mode.preempt, 100, 200)
			// The standby is charged and not ready before it ever wins.
			chargeMemberShim19140(standby, true)
			standby.SetRGReady(1, false, []string{"userspace data interface ge-7-0-2 has no XDP shim attached (not-attached)"})
			owner.SetGroupStateForTesting(1, StatePrimary)
			standby.SetGroupStateForTesting(1, StateSecondary)
			tr, dual := rounds19140(owner, standby, 10)
			if !owner.IsLocalPrimary(1) || standby.IsLocalPrimary(1) || tr != 0 || dual != 0 {
				t.Fatalf("owner=%v standby=%v transitions=%d dual=%d: a healthy primary yielded to a charged standby",
					owner.IsLocalPrimary(1), standby.IsLocalPrimary(1), tr, dual)
			}
		})
	}
	t.Run("preempt/healthy-standby-twin", func(t *testing.T) {
		owner, standby := memberShimPair19140(t, true, 100, 200)
		owner.SetGroupStateForTesting(1, StatePrimary)
		standby.SetGroupStateForTesting(1, StateSecondary)
		rounds19140(owner, standby, 10)
		if owner.IsLocalPrimary(1) || !standby.IsLocalPrimary(1) {
			t.Fatalf("owner=%v standby=%v: a healthy, ready, higher-priority standby must still preempt",
				owner.IsLocalPrimary(1), standby.IsLocalPrimary(1))
		}
	})
}

// E8: preempt, the charged owner yielded; then the NEW owner is charged too.
// Both are at the floor and equally broken, so the RG stays where it is
// (as in E2), not moved back to the higher-priority node by raw preempt.
func TestMemberShimBothChargedAfterYieldStays19140(t *testing.T) {
	owner, peer := memberShimPair19140(t, true, 200, 100)
	exchangeElection12164(owner, peer)
	chargeMemberShim19140(owner, true)
	rounds19140(owner, peer, 10)
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) {
		t.Fatal("precondition: the charged owner yielded")
	}
	chargeMemberShim19140(peer, true)
	tr, dual := rounds19140(owner, peer, 20)
	if owner.IsLocalPrimary(1) || !peer.IsLocalPrimary(1) || tr != 0 || dual != 0 {
		t.Fatalf("owner=%v peer=%v transitions=%d dual=%d: with both nodes charged the RG must stay, not move back",
			owner.IsLocalPrimary(1), peer.IsLocalPrimary(1), tr, dual)
	}
}

// E9: a committed owner (after an operator transfer, behind the role pin) that
// loses a member's shim hands back to the healthy old owner, as the #12164 arm
// debt does. Kills a pin branch keyed on arm debt only.
func TestCommittedOwnerWithMemberShimDebtHandsBack19140(t *testing.T) {
	oldOwner, newOwner := armDebtPair12164(t)
	newOwner.SetPeerFailoverFunc(func(id int) (uint64, error) {
		_, err := oldOwner.ManualFailover(id)
		return 19140, err
	})
	newOwner.SetPeerFailoverCommitFunc(func(id int, requestID uint64) error {
		return oldOwner.FinalizePeerTransferOut(id)
	})
	if err := newOwner.RequestPeerFailover(1); err != nil {
		t.Fatal(err)
	}
	newOwner.mu.Lock()
	newOwner.peerTransferCommitGraceUntil[1] = time.Now().Add(-time.Second)
	newOwner.mu.Unlock()
	oldOwner.mu.Lock()
	oldOwner.localTransferOutHoldUntil[1] = time.Now().Add(-time.Second)
	oldOwner.mu.Unlock()
	exchangeElection12164(oldOwner, newOwner)
	if oldOwner.IsLocalPrimary(1) || !newOwner.IsLocalPrimary(1) {
		t.Fatal("precondition: the transfer settled on the new owner")
	}
	chargeMemberShim19140(newOwner, true)
	exchangeElection12164(oldOwner, newOwner)
	if newOwner.IsLocalPrimary(1) || !oldOwner.IsLocalPrimary(1) {
		t.Fatalf("the committed owner kept the RG at the member-shim floor over a healthy peer: new=%s/%d old=%s/%d",
			newOwner.GroupState(1).State, newOwner.GroupState(1).Weight,
			oldOwner.GroupState(1).State, oldOwner.GroupState(1).Weight)
	}
}
