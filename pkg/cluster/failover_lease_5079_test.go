package cluster

import (
	"testing"
	"time"
)

// TestRemoteTransferOutLeaseRestoresOwnerWhenNoCommitArrives is the #5079
// fail-on-revert guard. A peer failover request demotes this node to
// secondary-hold and arms a reqID-bound auto-restore lease. The requester then
// aborts after the ACK (or crashes / loses the fabric): it sends no commit AND
// no abort frame, and rolls back to a HEALTHY secondary. Before the lease this
// stranded the cluster with both nodes secondary forever — the pre-existing
// dual-resign 2s guard never rescues it because a healthy secondary peer is
// neither resigned (weight 0) nor in secondary-hold. Once the lease expires with
// no commit, electRG restores the owner.
//
// Revert the electRG lease-expiry branch and this test goes RED: the owner stays
// secondary-hold against the healthy-secondary peer.
func TestRemoteTransferOutLeaseRestoresOwnerWhenNoCommitArrives(t *testing.T) {
	m := NewManager(0, 1)
	// Owner outranks the peer so, once the hold clears, normal election promotes
	// the owner back to primary.
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")

	// Peer failover request → demote to secondary-hold, then arm the lease
	// exactly as the daemon's OnRemoteFailover wiring does.
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	recvEvent19161(t, m.Events(), "the next event")
	m.ArmRemoteTransferOutLease([]int{0}, 42)

	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-time.Hour)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	// Requester aborted post-ACK, sent no commit, and is a healthy secondary.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	if m.IsLocalPrimary(0) {
		t.Fatal("owner must stay secondary-hold while the transfer-out lease is live")
	}

	// Prove the pre-existing dual-resign 2s guard does NOT rescue this: age past
	// the 2s window while the lease is still live — still stranded.
	m.mu.Lock()
	m.groups[0].ManualFailoverAt = time.Now().Add(-3 * time.Second)
	m.mu.Unlock()
	m.handlePeerHeartbeat(pkt)
	if m.IsLocalPrimary(0) {
		t.Fatal("dual-resign 2s guard must not restore against a healthy-secondary peer")
	}

	// Expire the lease with no commit; the owner must reclaim primary.
	m.mu.Lock()
	m.remoteTransferOutLeaseUntil[0] = time.Now().Add(-time.Second)
	m.mu.Unlock()
	m.handlePeerHeartbeat(pkt)

	if !m.IsLocalPrimary(0) {
		t.Fatal("owner must reclaim primary once the transfer-out lease expires without a commit")
	}
	m.mu.Lock()
	_, leaseLeft := m.remoteTransferOutLeaseUntil[0]
	manual := m.groups[0].ManualFailover
	m.mu.Unlock()
	if leaseLeft {
		t.Fatal("expired lease must be cleared after restore")
	}
	if manual {
		t.Fatal("ManualFailover must be cleared after lease restore")
	}
}

// TestRemoteTransferOutLeaseClearIsReqIDBound verifies a stale/duplicate commit
// carrying an older request ID cannot clear a newer request's lease, while the
// matching commit does.
func TestRemoteTransferOutLeaseClearIsReqIDBound(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	recvEvent19161(t, m.Events(), "the next event")
	m.ArmRemoteTransferOutLease([]int{0}, 42)

	// Stale commit for a different request must not clear the lease.
	m.ClearRemoteTransferOutLease(0, 41)
	m.mu.Lock()
	_, stillLeased := m.remoteTransferOutLeaseUntil[0]
	m.mu.Unlock()
	if !stillLeased {
		t.Fatal("a stale reqID must not clear a newer lease")
	}

	// The matching commit clears it.
	m.ClearRemoteTransferOutLease(0, 42)
	m.mu.Lock()
	_, leasedAfter := m.remoteTransferOutLeaseUntil[0]
	m.mu.Unlock()
	if leasedAfter {
		t.Fatal("the matching reqID must clear the lease")
	}
}

// TestLocalManualFailoverClearsRemoteTransferOutLease verifies a deliberate
// operator failover supersedes any stale remote transfer-out lease, so an
// operator (or ISSU) hold is never auto-restored underneath them.
func TestLocalManualFailoverClearsRemoteTransferOutLease(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	recvEvent19161(t, m.Events(), "the next event")
	m.ArmRemoteTransferOutLease([]int{0}, 7)

	// A fresh local manual failover supersedes the lease (no re-arm follows).
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("second ManualFailover() error = %v", err)
	}
	m.mu.Lock()
	_, leased := m.remoteTransferOutLeaseUntil[0]
	m.mu.Unlock()
	if leased {
		t.Fatal("a fresh local manual failover must clear any stale remote transfer-out lease")
	}
}

// TestResetFailoverClearsRemoteTransferOutLease is the #6301 fail-on-revert
// guard. A peer failover request demotes this node and arms a reqID-bound
// auto-restore lease. An operator then runs `request ... reset`
// (ResetFailover), which clears ManualFailover — but before #6301 it left the
// remoteTransferOutLease{Until,ReqID} entry dormant in the maps. Repeated
// resets accumulate dead entries. ResetFailover must clear the lease too,
// mirroring the ManualFailover / ForceSecondary(ISSU) / ManualFailoverBatch
// reset paths, so the lease maps stay in lockstep with ManualFailover.
//
// Revert the clearRemoteTransferOutLeaseLocked call added to ResetFailover and
// this test goes RED: the lease entry survives the reset.
func TestResetFailoverClearsRemoteTransferOutLease(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	recvEvent19161(t, m.Events(), "the next event")
	m.ArmRemoteTransferOutLease([]int{0}, 13)

	// Sanity: the lease is armed before the reset.
	m.mu.Lock()
	_, untilBefore := m.remoteTransferOutLeaseUntil[0]
	_, reqIDBefore := m.remoteTransferOutLeaseReqID[0]
	m.mu.Unlock()
	if !untilBefore || !reqIDBefore {
		t.Fatal("precondition: remote transfer-out lease must be armed before ResetFailover")
	}

	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover() error = %v", err)
	}

	m.mu.Lock()
	_, untilAfter := m.remoteTransferOutLeaseUntil[0]
	_, reqIDAfter := m.remoteTransferOutLeaseReqID[0]
	m.mu.Unlock()
	if untilAfter {
		t.Fatal("ResetFailover must clear the remote transfer-out lease Until entry")
	}
	if reqIDAfter {
		t.Fatal("ResetFailover must clear the remote transfer-out lease ReqID entry")
	}
}

// TestRemoteTransferOutLeaseRestoresBatchOwners exercises the multi-RG path: a
// batch transfer-out arms a lease per RG, and expiry restores every member.
func TestRemoteTransferOutLeaseRestoresBatchOwners(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(1, false, map[int]int{0: 200}),
		makeRG(2, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")
	recvEvent19161(t, m.Events(), "the next event")

	if _, err := m.ManualFailoverBatch([]int{1, 2}); err != nil {
		t.Fatalf("ManualFailoverBatch() error = %v", err)
	}
	recvEvent19161(t, m.Events(), "the next event")
	recvEvent19161(t, m.Events(), "the next event")
	m.ArmRemoteTransferOutLease([]int{1, 2}, 99)

	m.mu.Lock()
	for _, id := range []int{1, 2} {
		m.groups[id].Ready = true
		m.groups[id].ReadySince = time.Now().Add(-time.Hour)
		m.groups[id].ReadinessReasons = nil
		m.remoteTransferOutLeaseUntil[id] = time.Now().Add(-time.Second)
	}
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	for _, id := range []int{1, 2} {
		if !m.IsLocalPrimary(id) {
			t.Fatalf("rg %d must reclaim primary after batch transfer-out lease expiry", id)
		}
	}
}
