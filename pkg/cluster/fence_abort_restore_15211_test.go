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
			_, overrideArmed := m.peerTransferOutOverride[0]
			_, prevPresent := m.peerTransferOutPrevious[0]
			_, abortedArmed := m.abortedPeerTransferReqID[0]
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
				t.Errorf("preempt=%v: peerTransferOutOverride cleared and not restored on fence abort", preempt)
			}
			if !prevPresent {
				t.Errorf("preempt=%v: peerTransferOutPrevious snapshot lost on fence abort", preempt)
			}
			if !abortedArmed {
				t.Errorf("preempt=%v: abortedPeerTransferReqID cleared and not restored on fence abort", preempt)
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
	if _, ok := m.peerTransferOutOverride[0]; ok {
		t.Error("confirmed takeover must clear peerTransferOutOverride")
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
	if _, ok := m.peerTransferOutOverride[0]; ok {
		t.Error("fail-open takeover must clear peerTransferOutOverride")
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
