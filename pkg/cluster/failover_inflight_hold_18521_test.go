package cluster

import (
	"testing"
	"time"
)

// #18521 (secondary defect): the owner's manual-failover hold for a
// PEER-REQUESTED transfer was released by electRG's 2s dual-resign timer
// ("clearing manual failover (peer also yielded)") while the transfer was
// still in flight. The timer runs from the owner's demotion, but the
// requester is entitled to more than 2s before it commits: its own
// pre-request hold is released only after the owner's applied-ACK (which
// waits for the owner's demotion actuation), and it then spends up to
// localFailoverCommitTimeout (3s) in its local commit-ready settle. While the
// requester still advertises secondary-hold (or weight 0), an owner whose
// actuation or whose requester's commit window exceeded 2s cleared its own
// hold and could be re-promoted by ordinary election — so the commit then
// failed against an owner that was primary again.
//
// The invariant: while the reqID-bound remote transfer-out lease is LIVE, the
// hold belongs to the transfer protocol and is released only by the matching
// commit, the matching abort, the lease expiry, peer loss, or an operator
// reset — never by the 2s timer.

func inflightOwner18521(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(1, 1)
	// The owner OUTRANKS the requester, so a hold cleared mid-transfer is
	// observable: ordinary election hands RG 2 straight back to the owner.
	m.UpdateConfig(makeConfig(makeRG(2, false, map[int]int{0: 100, 1: 200})))
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
		{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
	}})
	m.mu.Lock()
	m.groups[2].Ready = true
	m.groups[2].ReadySince = time.Now().Add(-time.Hour)
	m.groups[2].ReadinessReasons = nil
	m.mu.Unlock()
	m.runElection()
	if !m.IsLocalPrimary(2) {
		t.Fatal("fixture: owner must start primary")
	}
	// The peer's request, exactly as the daemon's OnRemoteFailover wiring does it.
	if _, err := m.ManualFailover(2); err != nil {
		t.Fatal(err)
	}
	m.ArmRemoteTransferOutLease([]int{2}, 18521)
	return m
}

func ageOwnerHold18521(m *Manager, by time.Duration) {
	m.mu.Lock()
	m.groups[2].ManualFailoverAt = m.groups[2].ManualFailoverAt.Add(-by)
	m.mu.Unlock()
}

func ownerHold18521(m *Manager) (held bool, state NodeState) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.groups[2].ManualFailover, m.groups[2].State
}

// RED before the fix: both rows log "clearing manual failover (peer also
// yielded)" and the owner re-promotes itself while the requester is mid-commit.
func TestInFlightRemoteTransferHoldOutlivesDualResignTimer18521(t *testing.T) {
	rows := []struct {
		name   string
		state  NodeState
		weight uint8
	}{
		// The requester's pre-request hold, still advertised until the
		// applied-ACK reaches it.
		{"requester still in its pre-request secondary-hold", StateSecondaryHold, 255},
		// A requester whose weight is momentarily 0 inside the window.
		{"requester advertising weight 0", StateSecondary, 0},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			m := inflightOwner18521(t)
			ageOwnerHold18521(m, 3*time.Second) // past the 2s timer, inside the lease
			m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
				{GroupID: 2, Priority: 100, Weight: row.weight, State: uint8(row.state)},
			}})
			held, state := ownerHold18521(m)
			if !held || state == StatePrimary {
				t.Fatalf("an in-flight peer-requested transfer lost the owner's hold to the 2s "+
					"dual-resign timer (held=%v state=%s): the requester has not committed or "+
					"aborted, and the lease that bounds its commit window is still live (#18521)",
					held, state)
			}
		})
	}
}

// The protocol paths still release the hold, each one promptly.
func TestInFlightRemoteTransferHoldReleasedByProtocol18521(t *testing.T) {
	t.Run("matching commit", func(t *testing.T) {
		m := inflightOwner18521(t)
		ageOwnerHold18521(m, 3*time.Second)
		if err := m.FinalizePeerTransferOut(2); err != nil {
			t.Fatal(err)
		}
		m.ClearRemoteTransferOutLease(2, 18521)
		if held, state := ownerHold18521(m); held || state != StateSecondary {
			t.Fatalf("commit must release the hold and leave the owner secondary: held=%v state=%s", held, state)
		}
	})
	t.Run("matching abort", func(t *testing.T) {
		m := inflightOwner18521(t)
		if err := m.AbortRemoteTransferOut(2, 18521); err != nil {
			t.Fatal(err)
		}
		if held, _ := ownerHold18521(m); held || !m.IsLocalPrimary(2) {
			t.Fatal("abort must release the hold and restore the owner")
		}
	})
	t.Run("lease expiry", func(t *testing.T) {
		m := inflightOwner18521(t)
		m.mu.Lock()
		m.remoteTransferOutLeaseUntil[2] = time.Now().Add(-time.Second)
		m.mu.Unlock()
		m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
			{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
		}})
		if held, _ := ownerHold18521(m); held || !m.IsLocalPrimary(2) {
			t.Fatal("an expired lease must still restore the owner")
		}
	})
}

// Control: an operator hold (no lease — `request chassis cluster failover
// redundancy-group N` on this node) keeps the pre-existing 2s dual-resign
// rescue. The fix is scoped to in-flight peer-requested transfers.
func TestOperatorHoldKeepsDualResignTimer18521(t *testing.T) {
	m := inflightOwner18521(t)
	m.mu.Lock()
	m.clearRemoteTransferOutLeaseLocked(2) // what a local operator hold looks like
	m.mu.Unlock()
	ageOwnerHold18521(m, 3*time.Second)
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
		{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
	}})
	if held, _ := ownerHold18521(m); held {
		t.Fatal("an operator hold against a yielded peer must still clear after 2s (dual-resign rescue)")
	}
}

// End to end through RequestPeerFailover: a requester that starts in its own
// secondary-hold asks a higher-priority owner for RG 2; the owner's demotion
// takes >2s to actuate, and the requester's local commit settle takes >2s.
// The transfer must commit with the owner secondary and the requester primary.
// RED before the fix: the owner clears its hold while the requester still
// advertises hold, re-promotes, and FinalizePeerTransferOut refuses the commit
// ("still primary locally").
func TestSlowTransferCommitsAgainstHigherPriorityOwner18521(t *testing.T) {
	requester, owner := ackWireManagers16592(t, []int{2}, false)
	// The requester carries a hold from an earlier push-away.
	requester.mu.Lock()
	rg := requester.groups[2]
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now().Add(-time.Minute)
	rg.State = StateSecondaryHold
	requester.mu.Unlock()
	owner.handlePeerHeartbeat(requester.buildHeartbeat())
	if !owner.IsLocalPrimary(2) {
		t.Fatal("fixture: owner must be primary")
	}

	const reqID = 18521
	ageOwner := func() {
		owner.mu.Lock()
		owner.groups[2].ManualFailoverAt = owner.groups[2].ManualFailoverAt.Add(-3 * time.Second)
		owner.mu.Unlock()
	}
	requester.SetPeerFailoverFunc(func(id int) (uint64, error) {
		if _, err := owner.ManualFailover(id); err != nil {
			return 0, err
		}
		owner.ArmRemoteTransferOutLease([]int{id}, reqID)
		// Demotion actuation (VRRP resign / rg_active / DHCP server) takes
		// >2s before the applied-ACK; the requester still advertises its
		// pre-request hold the whole time.
		ageOwner()
		owner.handlePeerHeartbeat(requester.buildHeartbeat())
		requester.handlePeerHeartbeat(owner.buildHeartbeat())
		return reqID, nil
	})
	requester.SetLocalTransferCommitReadyHook(func([]int) error {
		// The requester's local commit-ready settle (up to 3s) also passes
		// the 2s mark; heartbeats keep flowing in both directions.
		ageOwner()
		owner.handlePeerHeartbeat(requester.buildHeartbeat())
		requester.handlePeerHeartbeat(owner.buildHeartbeat())
		return nil
	})
	requester.SetPeerFailoverCommitFunc(func(id int, gotReqID uint64) error {
		if err := owner.FinalizePeerTransferOut(id); err != nil {
			return err
		}
		owner.ClearRemoteTransferOutLease(id, gotReqID)
		return nil
	})
	requester.SetPeerFailoverAbortFunc(func(id int, gotReqID uint64) error {
		return owner.AbortRemoteTransferOut(id, gotReqID)
	})

	if err := requester.RequestPeerFailover(2); err != nil {
		t.Fatalf("a slow but healthy transfer failed: %v — the owner's hold was released by "+
			"the 2s timer while the requester was still committing (#18521)", err)
	}
	owner.handlePeerHeartbeat(requester.buildHeartbeat())
	requester.handlePeerHeartbeat(owner.buildHeartbeat())
	if !requester.IsLocalPrimary(2) || owner.IsLocalPrimary(2) {
		t.Fatalf("after commit: requester primary=%v owner primary=%v, want true/false",
			requester.IsLocalPrimary(2), owner.IsLocalPrimary(2))
	}
}
