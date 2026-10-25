package cluster

import (
	"errors"
	"net"
	"testing"
	"time"
)

// #16592 (R3-B22-01): the #5640/#6371 applied-ack did not gate the
// requester's promotion. On a node-targeted failover the owner demotes to
// secondary-hold BEFORE the ack verdict is known, and the requester's
// heartbeat election promoted via "Peer transfer out" on that hold —
// mid-request (before any ack) and after a FAILED or timed-out ack, even
// though RequestPeerFailover reported the failover as failed and, on the
// fence-failure arm, the owner's demotion was known not to have landed.
// The request-ACK error exit also never recorded the #15164 abort marker
// and (on timeout) had no reqID to bind an abort to.
//
// FAIL-ON-REVERT: drop the electRG failoverInProgress gate and the
// mid-request heartbeats below promote; drop the fn-error abort and the
// post-error heartbeats promote / no abort frame is sent; drop the
// SendFailover timeout reqID and the timeout rows cannot bind the abort;
// drop the owner-side restore in handleRemoteFailover and the owner
// stays in secondary-hold in the fence-verdict rows.

func ackGateFixture16592(t *testing.T, preempt bool) (requester, owner *Manager) {
	t.Helper()
	requester = NewManager(0, 1)
	owner = NewManager(1, 1)
	reqCfg := makeConfig(makeRG(0, preempt, map[int]int{0: 100, 1: 200}))
	ownCfg := makeConfig(makeRG(0, preempt, map[int]int{0: 100, 1: 200}))
	requester.UpdateConfig(reqCfg)
	owner.UpdateConfig(ownCfg)
	<-requester.Events()
	<-owner.Events()
	owner.mu.Lock()
	owner.groups[0].State = StatePrimary
	owner.groups[0].Ready = true
	owner.groups[0].ReadySince = time.Now().Add(-time.Hour)
	owner.mu.Unlock()
	requester.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	requester.mu.Lock()
	requester.groups[0].Ready = true
	requester.groups[0].ReadySince = time.Now().Add(-time.Hour)
	requester.groups[0].ReadinessReasons = nil
	requester.mu.Unlock()
	if requester.IsLocalPrimary(0) {
		t.Fatal("fixture: requester must start secondary")
	}
	return requester, owner
}

func holdHeartbeat16592(m *Manager) {
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StateSecondaryHold)},
		},
	})
}

func ownerRestored16592(t *testing.T, owner *Manager) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if owner.IsLocalPrimary(0) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	owner.mu.RLock()
	st, hold := owner.groups[0].State, owner.groups[0].ManualFailover
	owner.mu.RUnlock()
	t.Fatalf("owner not restored to primary: state=%v manualHold=%v", st, hold)
}

// Single path: ack-failed (owner fence verdict failed) and ack-timeout,
// each with the owner's secondary-hold heartbeat arriving DURING the
// request and again AFTER the error. The requester must never promote;
// the owner must be restored to primary; the reqID-bound abort must fire.
func TestAckGateRequestAckFailureDoesNotPromote16592(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		for _, mode := range []string{"ack-failed", "ack-timeout"} {
			name := "non-preempt"
			if preempt {
				name = "preempt"
			}
			t.Run(name+"/"+mode, func(t *testing.T) {
				requester, owner := ackGateFixture16592(t, preempt)
				const reqID = uint64(16592)
				demoted := make(chan struct{})
				release := make(chan struct{})
				var abortReq uint64
				abortCalls := 0
				requester.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
					if _, err := owner.ManualFailover(rgID); err != nil {
						return 0, err
					}
					owner.ArmRemoteTransferOutLease([]int{rgID}, reqID)
					close(demoted)
					<-release // hold the request open: ack verdict pending
					if mode == "ack-timeout" {
						return reqID, errors.New("timed out waiting for peer failover ack for redundancy group 0")
					}
					return reqID, errors.New("peer failed failover request for redundancy group 0: timed out waiting for local fence actuation")
				})
				requester.SetPeerFailoverAbortFunc(func(rgID int, id uint64) error {
					abortCalls++
					abortReq = id
					return owner.AbortRemoteTransferOut(rgID, id)
				})
				requester.SetPeerFailoverCommitFunc(func(int, uint64) error {
					t.Error("commit must not be sent after a failed/timed-out ack")
					return nil
				})
				done := make(chan error, 1)
				go func() { done <- requester.RequestPeerFailover(0) }()
				<-demoted
				// Heartbeat DURING the request (owner already in hold,
				// fence outcome unknown): must not promote.
				holdHeartbeat16592(requester)
				if requester.IsLocalPrimary(0) {
					t.Fatalf("%s: requester promoted mid-request on secondary-hold heartbeat", mode)
				}
				close(release)
				if err := <-done; err == nil {
					t.Fatalf("%s: RequestPeerFailover must report the ack failure", mode)
				}
				if abortCalls != 1 || abortReq != reqID {
					t.Fatalf("%s: abort = calls %d req %d, want 1/%d", mode, abortCalls, abortReq, reqID)
				}
				ownerRestored16592(t, owner)
				// Heartbeat AFTER the error: must not promote.
				holdHeartbeat16592(requester)
				if requester.IsLocalPrimary(0) {
					t.Fatalf("%s: requester promoted after ack failure on secondary-hold heartbeat", mode)
				}
				// Marker lifetime control (mirrors #15164): once the peer
				// stops advertising the aborted hold, a later legitimate
				// transfer-out promotes normally again.
				requester.handlePeerHeartbeat(&HeartbeatPacket{
					NodeID:    1,
					ClusterID: 1,
					Groups: []HeartbeatGroup{
						{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
					},
				})
				holdHeartbeat16592(requester)
				if !requester.IsLocalPrimary(0) {
					t.Fatalf("%s: legitimate transfer-out after aborted hold ended must promote", mode)
				}
			})
		}
	}
}

// Batch path: same ack-failed / ack-timeout coverage for RG1+RG2.
func TestAckGateBatchRequestAckFailureDoesNotPromote16592(t *testing.T) {
	for _, mode := range []string{"ack-failed", "ack-timeout"} {
		t.Run(mode, func(t *testing.T) {
			requester := NewManager(0, 1)
			owner := NewManager(1, 1)
			reqCfg := makeConfig(
				makeRG(1, true, map[int]int{0: 100, 1: 200}),
				makeRG(2, true, map[int]int{0: 100, 1: 200}),
			)
			ownCfg := makeConfig(
				makeRG(1, true, map[int]int{0: 100, 1: 200}),
				makeRG(2, true, map[int]int{0: 100, 1: 200}),
			)
			requester.UpdateConfig(reqCfg)
			owner.UpdateConfig(ownCfg)
			<-requester.Events()
			<-requester.Events()
			<-owner.Events()
			<-owner.Events()
			owner.mu.Lock()
			for _, id := range []int{1, 2} {
				owner.groups[id].State = StatePrimary
			}
			owner.mu.Unlock()
			requester.handlePeerHeartbeat(&HeartbeatPacket{
				NodeID:    1,
				ClusterID: 1,
				Groups: []HeartbeatGroup{
					{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
					{GroupID: 2, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
				},
			})
			requester.mu.Lock()
			for _, id := range []int{1, 2} {
				requester.groups[id].Ready = true
				requester.groups[id].ReadySince = time.Now().Add(-time.Hour)
				requester.groups[id].ReadinessReasons = nil
			}
			requester.mu.Unlock()

			const reqID = uint64(16593)
			demoted := make(chan struct{})
			release := make(chan struct{})
			var abortRGs []int
			var abortReq uint64
			requester.SetPeerFailoverBatchFunc(func(rgIDs []int) (uint64, error) {
				if _, err := owner.ManualFailoverBatch(rgIDs); err != nil {
					return 0, err
				}
				owner.ArmRemoteTransferOutLease(rgIDs, reqID)
				close(demoted)
				<-release
				if mode == "ack-timeout" {
					return reqID, errors.New("timed out waiting for peer failover ack for redundancy groups [1 2]")
				}
				return reqID, errors.New("peer failed failover request for redundancy groups [1 2]: fence not actuated")
			})
			requester.SetPeerFailoverAbortBatchFunc(func(rgIDs []int, id uint64) error {
				abortRGs = append([]int(nil), rgIDs...)
				abortReq = id
				return owner.AbortRemoteTransferOutBatch(rgIDs, id)
			})
			requester.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error {
				t.Error("batch commit must not be sent after a failed/timed-out ack")
				return nil
			})
			holdHB := func() {
				requester.handlePeerHeartbeat(&HeartbeatPacket{
					NodeID:    1,
					ClusterID: 1,
					Groups: []HeartbeatGroup{
						{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StateSecondaryHold)},
						{GroupID: 2, Priority: 200, Weight: 255, State: uint8(StateSecondaryHold)},
					},
				})
			}
			done := make(chan error, 1)
			go func() { done <- requester.RequestPeerFailoverBatch([]int{1, 2}) }()
			<-demoted
			holdHB()
			for _, id := range []int{1, 2} {
				if requester.IsLocalPrimary(id) {
					t.Fatalf("%s: requester promoted rg %d mid-request", mode, id)
				}
			}
			close(release)
			if err := <-done; err == nil {
				t.Fatalf("%s: batch must report the ack failure", mode)
			}
			if len(abortRGs) != 2 || abortReq != reqID {
				t.Fatalf("%s: batch abort = rgs %v req %d, want [1 2]/%d", mode, abortRGs, abortReq, reqID)
			}
			holdHB()
			for _, id := range []int{1, 2} {
				if requester.IsLocalPrimary(id) {
					t.Fatalf("%s: requester promoted rg %d after batch ack failure", mode, id)
				}
				deadline := time.Now().Add(2 * time.Second)
				for !owner.IsLocalPrimary(id) && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
				if !owner.IsLocalPrimary(id) {
					t.Fatalf("%s: owner rg %d not restored to primary", mode, id)
				}
			}
		})
	}
}

// Owner side: a failed fence verdict must restore the owner (reqID-bound)
// before the failed ack is sent — single and batch.
func TestFailedFenceRestoresOwnerBeforeFailedAck16592(t *testing.T) {
	mkSync := func(t *testing.T) (*SessionSync, net.Conn, net.Conn) {
		ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
		local, peer := net.Pipe()
		t.Cleanup(func() { local.Close(); peer.Close() })
		ss.mu.Lock()
		ss.conn0 = local
		ss.mu.Unlock()
		ss.stats.Connected.Store(true)
		return ss, local, peer
	}
	t.Run("single", func(t *testing.T) {
		ss, local, peer := mkSync(t)
		restored := make(chan uint64, 1)
		ss.OnRemoteFailover = func(int, uint64) error { return nil }
		ss.WaitFailoverApplied = func(int, uint64) error {
			return errors.New("redundancy group 7 rg_active=false not applied on demotion")
		}
		ss.OnRemoteFailoverAbort = func(rgID int, reqID uint64) error {
			if rgID != 7 {
				t.Errorf("restore rg = %d, want 7", rgID)
			}
			restored <- reqID
			return nil
		}
		frames := make(chan syncFrame, 4)
		readFramesInto(peer, frames)
		go ss.handleRemoteFailover(local, 7, 42)
		select {
		case reqID := <-restored:
			if reqID != 42 {
				t.Fatalf("restore reqID = %d, want 42", reqID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("owner restore not invoked on failed fence verdict")
		}
		select {
		case f := <-frames:
			if f.typ != syncMsgFailoverAck || len(f.payload) < 2 || f.payload[1] != failoverAckFailed {
				t.Fatalf("ack = type %d payload %v, want failed ack", f.typ, f.payload)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no failover ack delivered for a failed fence verdict")
		}
	})
	t.Run("batch", func(t *testing.T) {
		ss, _, peer := mkSync(t)
		restored := make(chan uint64, 1)
		ss.OnRemoteFailoverBatch = func([]int, uint64) error { return nil }
		ss.WaitFailoverAppliedBatch = func([]int, uint64) error {
			return errors.New("redundancy group 7 rg_active=false not applied on demotion")
		}
		ss.OnRemoteFailoverAbortBatch = func(rgIDs []int, reqID uint64) error {
			if len(rgIDs) != 2 {
				t.Errorf("batch restore rgs = %v, want 2", rgIDs)
			}
			restored <- reqID
			return nil
		}
		frames := make(chan syncFrame, 4)
		readFramesInto(peer, frames)
		go ss.handleRemoteFailoverBatch(nil, []int{7, 8}, 43)
		select {
		case reqID := <-restored:
			if reqID != 43 {
				t.Fatalf("batch restore reqID = %d, want 43", reqID)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("batch owner restore not invoked on failed fence verdict")
		}
		select {
		case f := <-frames:
			if f.typ != syncMsgFailoverBatchAck {
				t.Fatalf("frame type = %d, want batch ack %d", f.typ, syncMsgFailoverBatchAck)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no batch failover ack delivered for a failed fence verdict")
		}
	})
}
