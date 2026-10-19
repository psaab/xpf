package cluster

import (
	"testing"
	"time"
)

// #14979 (D34-04): ResetFailover left the transfer-commit authority armed.
//
// A transfer completion arms, per RG:
//   - peerTransferOutOverride (+ peerTransferOutPrevious snapshot) —
//     requester side, no expiry, re-forces the peer to SecondaryHold on
//     every heartbeat;
//   - peerTransferCommitGraceUntil — requester side, same rewrite until
//     it expires;
//   - localTransferOutHoldUntil — old-owner side, keeps the demoted RG
//     parked AND suppresses peer-loss detection cluster-wide
//     (suppressPeerTimeoutForTransferCommitLocked scans the whole map).
//
// ResetFailover cleared only ManualFailover / transferCommitRolePinned /
// the remote lease. The leftover state let the requester keep forcing a
// reclaimed peer down (dual-primary on preempt reclaim) and let one RG's
// stale hold silence peer-timeout for every RG. ResetFailover is the
// operator's explicit "this transfer is over, normal election resumes";
// it must clear all of it, per-RG, leaving other RGs' armed state alone.
//
// Revert the three deletes (and the clearPeerTransferOutOverrideLocked
// call) in ResetFailover and these tests go RED: the armed maps survive
// the reset, the stale heartbeat is still rewritten to SecondaryHold,
// and the peer timeout is still suppressed.

func armTransferState14979(m *Manager, rgID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerTransferOutOverride[rgID] = 77
	m.peerTransferOutPrevious[rgID] = peerGroupSnapshot{present: true}
	m.peerTransferCommitGraceUntil[rgID] = time.Now().Add(time.Minute)
	m.localTransferOutHoldUntil[rgID] = time.Now().Add(time.Minute)
}

func transferStateArmed14979(m *Manager, rgID int) (override, previous, grace, hold bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, override = m.peerTransferOutOverride[rgID]
	_, previous = m.peerTransferOutPrevious[rgID]
	_, grace = m.peerTransferCommitGraceUntil[rgID]
	_, hold = m.localTransferOutHoldUntil[rgID]
	return
}

// TestResetFailoverClearsTransferCommitState14979 is the mechanic guard:
// every transfer map entry for the reset RG is gone, and an entry for a
// DIFFERENT RG survives (per-RG clear, not a map wipe).
func TestResetFailoverClearsTransferCommitState14979(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()

	armTransferState14979(m, 0)
	armTransferState14979(m, 1)
	if o, p, g, h := transferStateArmed14979(m, 0); !o || !p || !g || !h {
		t.Fatalf("precondition: RG0 transfer state must be armed (override=%t previous=%t grace=%t hold=%t)", o, p, g, h)
	}

	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover(0) error = %v", err)
	}

	if o, p, g, h := transferStateArmed14979(m, 0); o || p || g || h {
		t.Errorf("ResetFailover must clear RG0 transfer state: override=%t previous=%t grace=%t hold=%t, want all false", o, p, g, h)
	}
	if o, p, g, h := transferStateArmed14979(m, 1); !o || !p || !g || !h {
		t.Errorf("ResetFailover(0) must not clear RG1 transfer state: override=%t previous=%t grace=%t hold=%t, want all true", o, p, g, h)
	}
	// Control: the pre-existing reset behaviour is unchanged.
	if m.GroupStates()[0].ManualFailover {
		t.Error("ManualFailover should be cleared")
	}
}

// TestResetFailoverStopsForcingReclaimedPeerSecondaryHold14979 is the
// dual-primary consequence: after a reset, a peer heartbeat advertising
// primary must be honoured, not rewritten to SecondaryHold by the
// leftover override/grace. On the requester (lower priority here) that
// rewrite is what made electRG take "Peer transfer out" and stay
// primary alongside the reclaimed peer.
func TestResetFailoverStopsForcingReclaimedPeerSecondaryHold14979(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100, 1: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	peerPrimary := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(peerPrimary)
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()
	if err := m.commitRequestedPeerFailover(0, 77); err != nil {
		t.Fatalf("commitRequestedPeerFailover() error = %v", err)
	}
	m.notePeerTransferCommitted(0) // arms grace; override cleared by commit itself
	armTransferState14979(m, 0)    // re-arm override+hold as an in-flight transfer would
	if !m.IsLocalPrimary(0) {
		t.Fatal("precondition: local node primary after commit")
	}

	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover(0) error = %v", err)
	}

	// The peer has reclaimed primary (e.g. preempt after the reset).
	// Its heartbeat must now be taken at face value.
	m.handlePeerHeartbeat(peerPrimary)
	if peer := m.PeerGroupStates()[0]; peer.State != StatePrimary {
		t.Fatalf("peer state = %s, want primary after ResetFailover; leftover transfer override/grace still rewriting the heartbeat", peer.State)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("local node stayed primary alongside a reclaimed peer primary (dual-primary) after ResetFailover")
	}
}

// TestResetFailoverStopsPeerTimeoutSuppression14979 is the cluster-wide
// consequence: localTransferOutHoldUntil is not per-RG in effect —
// suppressPeerTimeoutForTransferCommitLocked scans the whole map, so
// RG0's leftover hold suppresses peer-loss detection for the entire
// cluster. After RG0 is reset the suppression must end, while RG1's
// still-armed hold continues to suppress (control).
func TestResetFailoverStopsPeerTimeoutSuppression14979(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()

	armTransferState14979(m, 0)
	armTransferState14979(m, 1)

	m.mu.Lock()
	suppress, _ := m.suppressPeerTimeoutForTransferCommitLocked(time.Now())
	m.mu.Unlock()
	if !suppress {
		t.Fatal("precondition: armed local hold must suppress peer timeout")
	}

	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover(0) error = %v", err)
	}
	m.mu.Lock()
	suppress, _ = m.suppressPeerTimeoutForTransferCommitLocked(time.Now())
	m.mu.Unlock()
	if !suppress {
		t.Fatal("control: RG1's still-armed hold must keep suppressing peer timeout after RG0 reset")
	}

	if err := m.ResetFailover(1); err != nil {
		t.Fatalf("ResetFailover(1) error = %v", err)
	}
	m.mu.Lock()
	suppress, _ = m.suppressPeerTimeoutForTransferCommitLocked(time.Now())
	m.mu.Unlock()
	if suppress {
		t.Fatal("peer timeout still suppressed after every RG's transfer hold was reset; stale localTransferOutHoldUntil survived ResetFailover")
	}
}
