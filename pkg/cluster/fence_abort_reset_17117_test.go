package cluster

import (
	"errors"
	"testing"
	"time"
)

// #17117 (R4-Q35-01): the #15211 fence-abort restore in handlePeerTimeout
// is a hand copy of the canonical operator-hold restore without its failoverGen
// check, so an operator ResetFailover during the unlocked fence wait is
// undone — ManualFailover and the no-expiry peerTransferOutOverride both
// come back.
//
// FAIL-ON-REVERT: revert the operatorHoldSnapshot generation gate (restore
// without comparing failoverGen) and this cell goes RED with
// ManualFailover=true state=secondary-hold override=true gen=1.

// TestFenceAbortResetDuringFenceWaitIsHonoured17117 reproduces the Q35
// probe against the shipped fixture shape: the fence callback delivers a
// live-peer heartbeat (which must itself acquire m.mu, proving the wait is
// unlocked), invokes the operator reset, then fails the fence.
func TestFenceAbortResetDuringFenceWaitIsHonoured17117(t *testing.T) {
	m := setupFenceAbort15211(t, false)
	// setupFenceAbort15211 installs a fence callback that only heartbeats
	// then fails. Replace it with the reset-bearing form.
	peerPrimary := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		m.handlePeerHeartbeat(peerPrimary)
		if err := m.ResetFailover(0); err != nil {
			t.Errorf("ResetFailover during fence wait: %v", err)
		}
		return FenceAck{}, errors.New("peer not connected")
	})
	m.handlePeerTimeout()

	if !m.PeerAlive() {
		t.Fatal("peerAlive clobbered on fence abort")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if gen := m.failoverGen[0]; gen == 0 {
		t.Fatal("FIXTURE: ResetFailover did not bump failoverGen; the reset never landed in the fence window")
	}
	if m.groups[0].ManualFailover {
		t.Error("ResetFailover during the fence wait was undone: ManualFailover restored by the fence-abort restore (#17117)")
	}
	if _, ok := m.peerTransferOutOverride[0]; ok {
		t.Error("ResetFailover during the fence wait was undone: peerTransferOutOverride restored by the fence-abort restore (#17117)")
	}
	if _, ok := m.abortedPeerTransferReqID[0]; ok {
		t.Error("ResetFailover during the fence wait was undone: abortedPeerTransferReqID restored by the fence-abort restore (#17117)")
	}
	if got := m.groups[0].State; got == StateSecondaryHold {
		t.Errorf("local state = secondary-hold after the operator reset won; the stale hold state was restored (#17117)")
	}
}

// #18148 / #17117-fold (Rev18145Opus blocker): restoreOperatorHoldLocked
// checks generation BEFORE the override/aborted arms, but UpdateConfig's
// removal purge DELETES failoverGen (group_state.go), so a remove+re-add in
// the fence window resets gen to 0 — the snapshot value — and the
// override+aborted arms resurrect onto a FRESH RG incarnation (#8435
// dual-primary class). The hold arm survives only via its rg-pointer check.
//
// FAIL-ON-REVERT: run the override/aborted restores before the
// same-incarnation gate (the pre-fold code) and this cell goes RED with
// override=true aborted=true on the re-added RG while gen reads 0==0 and
// the live RG pointer differs from the snapshot's.
func TestFenceAbortReaddDuringFenceWaitDoesNotRestore17117(t *testing.T) {
	m := setupFenceAbort15211(t, false)

	// Capture the OLD incarnation's pointer for the incarnation assertion.
	m.mu.RLock()
	oldRG := m.groups[0]
	m.mu.RUnlock()
	if oldRG == nil {
		t.Fatal("FIXTURE: RG0 missing before fence")
	}

	peerPrimary := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	var newRG *RedundancyGroupState
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		// Live-peer heartbeat first: proves m.mu is released during
		// the fence wait (handlePeerHeartbeat acquires it) and keeps
		// peerAlive set so awaitPeerFenceLocked aborts the takeover.
		m.handlePeerHeartbeat(peerPrimary)
		// Two config commits land inside the fence window: remove
		// RG0 (purge deletes failoverGen / override / aborted arms
		// and the RG object), then re-add RG0 (fresh incarnation,
		// gen re-seeded at 0, no ManualFailover).
		//
		// PeerFencing must be re-set after each UpdateConfig: the
		// fixture config from makeConfig leaves it empty, and
		// UpdateConfig's heartbeat/fencing tail would otherwise
		// reset m.peerFencing — the fence is already in flight, so
		// the abort decision above is what triggers the restore.
		noRG := makeConfig()
		noRG.PeerFencing = PeerFencingDisableRGConfirmed
		m.UpdateConfig(noRG)
		readded := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
		readded.PeerFencing = PeerFencingDisableRGConfirmed
		m.UpdateConfig(readded)
		m.mu.Lock()
		newRG = m.groups[0]
		m.mu.Unlock()
		if newRG == nil {
			t.Error("FIXTURE: re-add did not recreate RG0")
		}
		// Fence fails (peer not fenced) and a heartbeat arrived, so
		// awaitPeerFenceLocked aborts and the restore runs.
		return FenceAck{}, errors.New("peer not connected")
	})
	m.handlePeerTimeout()

	if !m.PeerAlive() {
		t.Fatal("peerAlive clobbered on fence abort")
	}
	if newRG == nil {
		t.Fatal("fence callback did not run the remove+re-add")
	}
	if newRG == oldRG {
		t.Fatal("re-add must allocate a fresh RedundancyGroupState (incarnation change)")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg := m.groups[0]
	if rg != newRG {
		t.Fatalf("live RG pointer changed across the abort (got %p, want re-added %p)", rg, newRG)
	}
	// Gen really reset: the purge deleted the entry and no ResetFailover
	// ran, so the gen gate alone passes (0==0). Only incarnation rejects.
	if gen := m.failoverGen[0]; gen != 0 {
		t.Fatalf("failoverGen[0] = %d after purge+re-add, want 0 (the gen-0 snapshot gates pass; only incarnation rejects it)", gen)
	}
	if _, ok := m.peerTransferOutOverride[0]; ok {
		t.Error("fence-abort restore resurrected peerTransferOutOverride onto the re-added RG after remove+re-add in the fence window (#18148/#8435)")
	}
	if _, ok := m.peerTransferOutPrevious[0]; ok {
		t.Error("fence-abort restore resurrected peerTransferOutPrevious onto the re-added RG (#18148)")
	}
	if _, ok := m.abortedPeerTransferReqID[0]; ok {
		t.Error("fence-abort restore resurrected abortedPeerTransferReqID onto the re-added RG (#18148)")
	}
	if rg.ManualFailover {
		t.Error("fence-abort restore resurrected ManualFailover onto the re-added RG (#18148)")
	}
	if !rg.ManualFailoverAt.IsZero() {
		t.Errorf("fresh RG ManualFailoverAt=%v after fence abort, want zero (removed incarnation's timestamp must not cross the re-add)", rg.ManualFailoverAt)
	}
	if got := rg.State; got == StateSecondaryHold {
		t.Errorf("fresh RG State=%s after fence abort, want no stale secondary-hold state", got)
	}
}
