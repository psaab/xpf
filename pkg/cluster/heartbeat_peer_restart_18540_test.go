package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18540: a peer daemon restart ends the authority its old incarnation held
// over this node, whether or not peer-loss detection saw the restart.
//
// handlePeerTimeout was the only path that cleared the holding node's
// ManualFailover park. A crashed peer that restarts inside the detection
// window — 1s heartbeat threshold plus the sync-recency deferral, which a
// draining backlog stretches to the 5s cap on master — arrives as a NEW
// heartbeat incarnation while this node still believes the old one alive.
// The new peer comes up secondary in its startup hold at the arm floor, the
// holder stays parked, and no node owns the RG until that hold releases (up
// to 30s). Both orders are covered: the restart lands before detection, and
// after it.

// restartedPeer18540 is a new daemon incarnation of node0: a fresh Manager
// (fresh heartbeat session, #6169) that has just booted — every RG
// secondary, at the arm floor because XDP is not yet proven and the
// startup sync hold is active.
func restartedPeer18540(t *testing.T) *Manager {
	t.Helper()
	var rgs []*config.RedundancyGroup
	for _, id := range restartRGs18540 {
		rgs = append(rgs, makeRG(id, false, map[int]int{0: 200, 1: 100}))
	}
	c := makeConfig(rgs...)
	c.ControlInterface = "em0"
	p := NewManager(0, 1)
	t.Cleanup(p.Stop)
	p.UpdateConfig(c)
	for _, id := range restartRGs18540 {
		p.SetMonitorWeight(id, startupSyncHoldMonitorIface, true, startupSyncHoldMonitorCost)
	}
	p.mu.Lock()
	for _, id := range restartRGs18540 {
		p.groups[id].State = StateSecondary
	}
	p.mu.Unlock()
	if p.LocalProcessToken() == 0 {
		t.Fatal("fixture: restarted peer has no heartbeat session")
	}
	return p
}

func requireHolderOwnsAll18540(t *testing.T, holder *Manager, when string) {
	t.Helper()
	for _, id := range restartRGs18540 {
		if !holder.IsLocalPrimary(id) {
			t.Errorf("%s: RG%d is not primary on the surviving node; the restarted peer is in its "+
				"startup hold, so the RG has no owner (#18540)", when, id)
		}
	}
	for _, rg := range holder.GroupStates() {
		if rg.ManualFailover {
			t.Errorf("%s: RG%d still carries the old incarnation's ManualFailover hold", when, rg.GroupID)
		}
	}
}

// The restart lands BEFORE peer-loss detection: no handlePeerTimeout runs
// between the old incarnation's last frame and the new one's first.
func TestPeerRestartBeforeLossDetectionEndsFailoverHolds18540(t *testing.T) {
	old, holder := restartFixture18540(t)
	if old.LocalProcessToken() == 0 {
		t.Fatal("fixture: old incarnation has no heartbeat session")
	}
	fresh := restartedPeer18540(t)
	if fresh.LocalProcessToken() == old.LocalProcessToken() {
		t.Fatal("fixture: the restarted peer must be a different incarnation")
	}
	exchange18540(fresh, holder)
	requireHolderOwnsAll18540(t, holder, "restart before detection")
	for _, id := range restartRGs18540 {
		if fresh.IsLocalPrimary(id) {
			t.Errorf("RG%d: the restarted peer promoted inside its startup hold", id)
		}
	}
}

// The restart lands AFTER detection: handlePeerTimeout already ended the
// holds and promoted the survivor; the new incarnation's frames must leave
// it the owner (non-preempt) rather than flap it.
func TestPeerRestartAfterLossDetectionKeepsSurvivorOwner18540(t *testing.T) {
	_, holder := restartFixture18540(t)
	holder.handlePeerTimeout()
	requireHolderOwnsAll18540(t, holder, "after peer-loss detection")
	fresh := restartedPeer18540(t)
	exchange18540(fresh, holder)
	requireHolderOwnsAll18540(t, holder, "restart after detection")
}

// Controls: the same incarnation dropping to the arm floor is NOT a restart
// and must not end the operator's hold — that is the arm-debt/dual-resign
// policy's job, unchanged here. And a peer whose frames carry no heartbeat
// session (pre-echo protocol) gives no incarnation signal, so nothing fires.
func TestSameIncarnationOrUnversionedPeerKeepsFailoverHolds18540(t *testing.T) {
	t.Run("same incarnation at the arm floor", func(t *testing.T) {
		old, holder := restartFixture18540(t)
		old.mu.Lock()
		for _, id := range restartRGs18540 {
			old.groups[id].State = StateSecondary
		}
		old.mu.Unlock()
		for _, id := range restartRGs18540 {
			old.SetMonitorWeight(id, startupSyncHoldMonitorIface, true, startupSyncHoldMonitorCost)
		}
		holder.handlePeerHeartbeat(old.buildHeartbeat())
		for _, rg := range holder.GroupStates() {
			if !rg.ManualFailover {
				t.Errorf("RG%d: a frame from the SAME peer incarnation ended the operator's hold", rg.GroupID)
			}
		}
	})
	t.Run("peer frames without a heartbeat session", func(t *testing.T) {
		_, holder := restartFixture18540(t)
		fresh := restartedPeer18540(t)
		pkt := fresh.buildHeartbeat()
		pkt.HeartbeatSession, pkt.HeartbeatSequence = 0, 0
		pkt.PeerHeartbeatSession, pkt.PeerHeartbeatSequence = 0, 0
		holder.handlePeerHeartbeat(pkt)
		for _, rg := range holder.GroupStates() {
			if !rg.ManualFailover {
				t.Errorf("RG%d: a frame with no incarnation identity ended the hold", rg.GroupID)
			}
		}
	})
}
