package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// #15211 A22-01: handlePeerTimeout clears ManualFailover (+weight), the peer
// transfer-out override+snapshot, and aborted-request markers BEFORE the
// disable-rg-confirmed fence wait. When awaitPeerFenceLocked aborts the
// takeover (#14158: heartbeat during wait + unconfirmed fence), none of that
// operator intent was restored: a later election can pre-empt/move the RG
// contrary to the operator's transfer-out, even though the peer is alive and
// never fenced.
//
// FAIL-ON-REVERT: delete the snapshot/restore in handlePeerTimeout and the
// A22-01 tests below go RED.

// setupFenceAbort15211 builds a confirmed-fence manager with RG0 in a local
// ManualFailover hold, a peer transfer-out override armed, and a fence
// callback that delivers a live peer PRIMARY heartbeat then fails the fence.
func setupFenceAbort15211(t *testing.T, preempt bool) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, preempt, map[int]int{0: 200, 1: 100}))
	cfg.PeerFencing = PeerFencingDisableRGConfirmed
	m.UpdateConfig(cfg)
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	for _, rg := range m.groups {
		rg.State = StateSecondary
	}
	m.mu.Unlock()
	// Drain config events.
	_ = drainEvents9640(m)
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("FIXTURE: manual failover: %v", err)
	}
	_ = drainEvents9640(m)
	// Arm peer transfer-out override (+ snapshot) and aborted marker.
	m.mu.Lock()
	m.peerGroups[0] = PeerGroupState{GroupID: 0, Priority: 111, Weight: 255, State: StateSecondary}
	m.applyPeerTransferOutOverrideLocked(0, 77)
	m.abortedPeerTransferReqID[0] = 77
	m.mu.Unlock()

	peerPrimary := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		m.handlePeerHeartbeat(peerPrimary)
		return FenceAck{}, errors.New("peer not connected")
	})
	return m
}

func TestFenceAbortRestoresOperatorIntent15211(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		name := "nonpreempt"
		if preempt {
			name = "preempt"
		}
		t.Run(name, func(t *testing.T) {
			m := setupFenceAbort15211(t, preempt)
			m.mu.RLock()
			wantAt := m.groups[0].ManualFailoverAt
			wantWeight := m.groups[0].Weight
			m.mu.RUnlock()
			if wantAt.IsZero() {
				t.Fatal("FIXTURE: ManualFailoverAt must be set")
			}

			m.handlePeerTimeout()

			if !m.PeerAlive() {
				t.Fatal("peerAlive clobbered on fence abort")
			}
			m.mu.RLock()
			rg := m.groups[0]
			manual, at, weight := rg.ManualFailover, rg.ManualFailoverAt, rg.Weight
			state := rg.State
			override, overrideArmed := m.transferOverrides[0]
			abortedReqID, abortedArmed := m.abortedPeerTransferReqID[0]
			m.mu.RUnlock()
			if !manual {
				t.Errorf("preempt=%v: ManualFailover cleared and not restored on fence abort (state=%v)", preempt, state)
			}
			if !at.Equal(wantAt) {
				t.Errorf("preempt=%v: ManualFailoverAt=%v, want restored %v", preempt, at, wantAt)
			}
			if weight != wantWeight {
				t.Errorf("preempt=%v: Weight=%d, want restored %d (pre-clear weight)", preempt, weight, wantWeight)
			}
			if state != StateSecondaryHold {
				t.Errorf("preempt=%v: State=%v, want secondary-hold (restored hold state)", preempt, state)
			}
			if !overrideArmed {
				t.Errorf("preempt=%v: transferOverrides cleared and not restored on fence abort", preempt)
			}
			// #17117-fold (F1): the WHOLE transferOverride must come
			// back — reqID plus the pre-override peer snapshot. A
			// restore writing only transferOverride{reqID: ...}
			// (zeroed previous) passes the presence checks above,
			// but a later reqID-matched abort
			// (restorePeerTransferOutOverrideLocked) would then find
			// previous.present=false and DELETE the peer view
			// instead of restoring it. Fixture: setupFenceAbort15211
			// seeds the pre-override peer view ({111, secondary})
			// before arming, so previous is present=true; the
			// fence-window heartbeat then delivered the live peer
			// as PRIMARY — a previous re-derived after the wait
			// would be present=true/PRIMARY(100), not the snapshot.
			if overrideArmed && override.reqID != 77 {
				t.Errorf("preempt=%v: restored transferOverride reqID=%d, want 77", preempt, override.reqID)
			}
			if !abortedArmed {
				t.Errorf("preempt=%v: abortedPeerTransferReqID cleared and not restored on fence abort", preempt)
			}
			if abortedArmed && abortedReqID != 77 {
				t.Errorf("preempt=%v: restored abortedPeerTransferReqID=%d, want 77", preempt, abortedReqID)
			}
			// The restored override must again force our view of the
			// peer to secondary-hold (that is what feeds election and
			// status), not merely exist in the map.
			peerGroups := m.PeerGroupStates()
			if len(peerGroups) != 1 {
				t.Fatalf("peer groups=%d want 1", len(peerGroups))
			}
			if peerGroups[0].State != StateSecondaryHold {
				t.Errorf("preempt=%v: peer view state=%v, want secondary-hold (restored override re-applied)", preempt, peerGroups[0].State)
			}
			// #17117-fold (F1): the reqID-matched abort must restore
			// the snapshotted previous peer view: seeded above as
			// {Priority:111, State:Secondary, present:true} before
			// the override armed. The zeroed-previous mutant
			// (transferOverride{reqID: ...}) makes this abort find
			// present=false and DELETE the peer view instead; a
			// re-derived previous would bring back the PRIMARY
			// view (Priority 100) delivered during the fence wait.
			if overrideArmed {
				if !override.previous.present {
					t.Errorf("preempt=%v: restored transferOverride lost previous.present; the snapshotted previous peer view ({111, secondary}) must survive the fence restore", preempt)
				}
				if override.previous.state.State != StateSecondary || override.previous.state.Priority != 111 {
					t.Errorf("preempt=%v: restored transferOverride previous=(state %v, priority %d), want (secondary, 111)", preempt, override.previous.state.State, override.previous.state.Priority)
				}
			}
			m.mu.Lock()
			aborted := m.restorePeerTransferOutOverrideLocked(0, 77)
			restoredPeer, peerOK := m.peerGroups[0]
			peerPriority := m.groups[0].PeerPriority
			m.mu.Unlock()
			if !aborted {
				t.Errorf("preempt=%v: reqID-matched abort did not match the restored transferOverride (reqID must be 77)", preempt)
			}
			if !peerOK {
				t.Errorf("preempt=%v: reqID-matched abort deleted the peer view; the snapshotted previous (111, secondary) must be restored, not deleted", preempt)
			} else if restoredPeer.State != StateSecondary || restoredPeer.Priority != 111 {
				t.Errorf("preempt=%v: peer view after reqID-matched abort=(state %v, priority %d), want restored snapshot (secondary, 111)", preempt, restoredPeer.State, restoredPeer.Priority)
			}
			if peerPriority != 111 {
				t.Errorf("preempt=%v: PeerPriority=%d after reqID-matched abort, want 111 (restored snapshot priority)", preempt, peerPriority)
			}
		})
	}
}

// Control: confirmed fence (takeover proceeds) must still clear operator intent.
func TestFenceConfirmedStillClearsOperatorIntent15211(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.PeerFencing = PeerFencingDisableRGConfirmed
	m.UpdateConfig(cfg)
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	for _, rg := range m.groups {
		rg.State = StateSecondary
	}
	m.mu.Unlock()
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("manual failover: %v", err)
	}
	m.mu.Lock()
	m.applyPeerTransferOutOverrideLocked(0, 77)
	m.abortedPeerTransferReqID[0] = 77
	m.mu.Unlock()
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		return FenceAck{Status: FenceAckOK, RGsFenced: 1, RGsTotal: 1}, nil
	})
	m.handlePeerTimeout()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.groups[0].ManualFailover {
		t.Error("confirmed takeover must clear ManualFailover")
	}
	if _, ok := m.transferOverrides[0]; ok {
		t.Error("confirmed takeover must clear transferOverrides")
	}
	if _, ok := m.abortedPeerTransferReqID[0]; ok {
		t.Error("confirmed takeover must clear abortedPeerTransferReqID")
	}
	if got := rgState(t, m, 0); got != StatePrimary {
		t.Errorf("confirmed takeover state=%v want primary", got)
	}
}

// Control: failed fence with NO heartbeat (fail-open takeover) must still clear.
func TestFenceFailOpenNoHeartbeatStillClears15211(t *testing.T) {
	m := failOpenManager15211(t)
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		return FenceAck{}, errors.New("peer not connected")
	})
	m.handlePeerTimeout()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.groups[0].ManualFailover {
		t.Error("fail-open takeover must clear ManualFailover")
	}
	if _, ok := m.transferOverrides[0]; ok {
		t.Error("fail-open takeover must clear transferOverrides")
	}
}

func failOpenManager15211(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	cfg.PeerFencing = PeerFencingDisableRGConfirmed
	m.UpdateConfig(cfg)
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	for _, rg := range m.groups {
		rg.State = StateSecondary
	}
	m.mu.Unlock()
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("manual failover: %v", err)
	}
	m.mu.Lock()
	m.applyPeerTransferOutOverrideLocked(0, 77)
	m.mu.Unlock()
	return m
}

// #15211 A22-02: handlePeerNeverSeen takeover must be marked DEGRADED under
// every fencing policy (no fence possible for a never-seen peer).
func TestNeverSeenTakeoverMarkedDegraded15211(t *testing.T) {
	for _, policy := range []string{"", PeerFencingDisableRG, PeerFencingDisableRGConfirmed} {
		t.Run("policy="+policy, func(t *testing.T) {
			m := coldBootManager(t)
			m.mu.Lock()
			m.peerFencing = policy
			m.mu.Unlock()
			m.SetRGReady(0, true, nil)
			m.handlePeerNeverSeen()
			if !peerConfirmedAbsent(m) {
				t.Fatal("peerConfirmedAbsent not set")
			}
			if !m.IsLocalPrimary(0) {
				t.Fatal("ready node did not promote on never-seen takeover")
			}
			for name, render := range map[string]string{
				"status":      m.FormatStatus(),
				"information": m.FormatInformation(),
			} {
				if !strings.Contains(render, "Peer-loss takeover: DEGRADED") {
					t.Errorf("policy %q: %s does not mark never-seen takeover degraded:\n%s", policy, name, render)
				}
				if !strings.Contains(render, "peer never seen; no fence possible") {
					t.Errorf("policy %q: %s missing never-seen reason:\n%s", policy, name, render)
				}
			}
			if !strings.Contains(m.FormatInformation(), "Local node: degraded") {
				t.Errorf("policy %q: information did not mark local degraded:\n%s", policy, m.FormatInformation())
			}
		})
	}
}

// Control: sync-fresh suppression must NOT mark degraded (no takeover happened).
func TestNeverSeenSyncFreshDoesNotMarkDegraded15211(t *testing.T) {
	m := coldBootManager(t)
	m.SetPeerNeverSeenSyncFreshFunc(func() bool { return true })
	m.SetRGReady(0, true, nil)
	m.handlePeerNeverSeen()
	if peerConfirmedAbsent(m) {
		t.Fatal("sync-fresh must suppress confirmation")
	}
	if strings.Contains(m.FormatStatus(), "Peer-loss takeover: DEGRADED") {
		t.Errorf("suppressed never-seen marked degraded:\n%s", m.FormatStatus())
	}
}
