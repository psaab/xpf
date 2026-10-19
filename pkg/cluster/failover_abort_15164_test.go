package cluster

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// #15164 (B22-01): after RequestPeerFailover aborts locally, the requester
// reports an error and demotes, but the owner keeps advertising
// StateSecondaryHold under its #5079 lease and electRG's "Peer transfer out"
// rule promotes the requester again on the next heartbeat. Under preempt the
// owner then takes the RG back when the lease expires — an unrequested second
// move. The fix sends a reqID-bound abort frame that restores the owner
// promptly, while the requester records the aborted reqID and refuses
// "Peer transfer out" while the peer's hold still belongs to that request.
//
// FAIL-ON-REVERT: drop the abort send from abortRequestedPeerFailover (or the
// electRG aborted-hold guard) and the requester re-promotes on the heartbeat
// below.

func abortFixture15164(t *testing.T, preempt bool) (requester, owner *Manager) {
	t.Helper()
	requester = NewManager(0, 1)
	owner = NewManager(1, 1)
	// Owner (node 1) outranks the requester, so under preempt it reclaims the
	// RG once its lease expires.
	reqCfg := makeConfig(makeRG(0, preempt, map[int]int{0: 100, 1: 200}))
	ownCfg := makeConfig(makeRG(0, preempt, map[int]int{0: 100, 1: 200}))
	requester.UpdateConfig(reqCfg)
	owner.UpdateConfig(ownCfg)
	<-requester.Events()
	<-owner.Events()

	// Owner is primary; requester sees it via heartbeat.
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

func TestAbortedPeerFailoverDoesNotRepromoteRequester15164(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		name := "non-preempt"
		if preempt {
			name = "preempt"
		}
		t.Run(name, func(t *testing.T) {
			requester, owner := abortFixture15164(t, preempt)
			const reqID = uint64(777)

			var abortRG int
			var abortReq uint64
			abortCalls := 0
			requester.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
				// Owner side: demote + arm lease, exactly as the daemon's
				// OnRemoteFailover wiring does.
				if _, err := owner.ManualFailover(rgID); err != nil {
					return 0, err
				}
				owner.ArmRemoteTransferOutLease([]int{rgID}, reqID)
				return reqID, nil
			})
			requester.SetPeerFailoverAbortFunc(func(rgID int, id uint64) error {
				abortCalls++
				abortRG, abortReq = rgID, id
				return owner.AbortRemoteTransferOut(rgID, id)
			})
			requester.SetPeerFailoverCommitFunc(func(rgID int, id uint64) error {
				t.Error("commit must not be sent after local commit-ready fails")
				return nil
			})
			requester.SetLocalTransferCommitReadyHook(func(rgIDs []int) error {
				return errors.New("local commit not ready")
			})

			if err := requester.RequestPeerFailover(0); err == nil {
				t.Fatal("RequestPeerFailover must report the local abort")
			}
			if abortCalls != 1 || abortRG != 0 || abortReq != reqID {
				t.Fatalf("abort frame = calls %d rg %d req %d, want 1/0/%d", abortCalls, abortRG, abortReq, reqID)
			}
			if requester.IsLocalPrimary(0) {
				t.Fatal("requester must stay non-primary after abort")
			}
			// Owner restored promptly by the abort frame, not by lease expiry.
			if owner.IsLocalPrimary(0) {
				// Owner may still need an election tick; check flags directly.
			}
			owner.mu.Lock()
			ownerHold := owner.groups[0].ManualFailover
			_, ownerLeased := owner.remoteTransferOutLeaseUntil[0]
			owner.mu.Unlock()
			if ownerHold {
				t.Fatal("owner ManualFailover must be cleared by the reqID-bound abort")
			}
			if ownerLeased {
				t.Fatal("owner lease must be cleared by the reqID-bound abort")
			}

			// Next heartbeat: even if the owner still advertises
			// secondary-hold under the aborted request (abort frame lost /
			// reordered), the requester must not take "Peer transfer out".
			requester.handlePeerHeartbeat(&HeartbeatPacket{
				NodeID:    1,
				ClusterID: 1,
				Groups: []HeartbeatGroup{
					{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StateSecondaryHold)},
				},
			})
			if requester.IsLocalPrimary(0) {
				t.Fatal("requester re-promoted via Peer transfer out after aborting the request")
			}

			// Control: once the peer stops advertising the aborted hold,
			// the marker expires and a later legitimate transfer-out (a
			// fresh hold not belonging to the aborted request) promotes
			// normally again.
			requester.handlePeerHeartbeat(&HeartbeatPacket{
				NodeID:    1,
				ClusterID: 1,
				Groups: []HeartbeatGroup{
					{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
				},
			})
			if requester.IsLocalPrimary(0) {
				t.Fatal("requester must stay secondary while peer is primary")
			}
			requester.handlePeerHeartbeat(&HeartbeatPacket{
				NodeID:    1,
				ClusterID: 1,
				Groups: []HeartbeatGroup{
					{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StateSecondaryHold)},
				},
			})
			if !requester.IsLocalPrimary(0) {
				t.Fatal("legitimate peer transfer out after the aborted hold ended must promote")
			}
		})
	}
}

func TestAbortedPeerFailoverBatchDoesNotRepromoteRequester15164(t *testing.T) {
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

	const reqID = uint64(888)
	var abortRGs []int
	var abortReq uint64
	requester.SetPeerFailoverBatchFunc(func(rgIDs []int) (uint64, error) {
		if _, err := owner.ManualFailoverBatch(rgIDs); err != nil {
			return 0, err
		}
		owner.ArmRemoteTransferOutLease(rgIDs, reqID)
		return reqID, nil
	})
	requester.SetPeerFailoverAbortBatchFunc(func(rgIDs []int, id uint64) error {
		abortRGs = append([]int(nil), rgIDs...)
		abortReq = id
		return owner.AbortRemoteTransferOutBatch(rgIDs, id)
	})
	requester.SetPeerFailoverCommitBatchFunc(func(rgIDs []int, id uint64) error {
		t.Error("batch commit must not be sent after local commit-ready fails")
		return nil
	})
	requester.SetLocalTransferCommitReadyHook(func(rgIDs []int) error {
		return errors.New("local commit not ready")
	})

	if err := requester.RequestPeerFailoverBatch([]int{1, 2}); err == nil {
		t.Fatal("RequestPeerFailoverBatch must report the local abort")
	}
	if len(abortRGs) != 2 || abortReq != reqID {
		t.Fatalf("batch abort = rgs %v req %d, want [1 2]/%d", abortRGs, abortReq, reqID)
	}
	owner.mu.Lock()
	for _, id := range []int{1, 2} {
		if owner.groups[id].ManualFailover {
			t.Fatalf("owner rg %d ManualFailover must be cleared by batch abort", id)
		}
	}
	owner.mu.Unlock()
	requester.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StateSecondaryHold)},
			{GroupID: 2, Priority: 200, Weight: 255, State: uint8(StateSecondaryHold)},
		},
	})
	for _, id := range []int{1, 2} {
		if requester.IsLocalPrimary(id) {
			t.Fatalf("requester re-promoted rg %d via Peer transfer out after batch abort", id)
		}
	}
}

// A stale abort for an older reqID must not restore an owner demoted by a
// newer request, and a legitimate later transfer-out must still promote.
func TestStaleAbortDoesNotRestoreNewerHold15164(t *testing.T) {
	owner := NewManager(1, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100, 1: 200}))
	owner.UpdateConfig(cfg)
	<-owner.Events()
	owner.mu.Lock()
	owner.groups[0].State = StatePrimary
	owner.mu.Unlock()
	if _, err := owner.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover: %v", err)
	}
	owner.ArmRemoteTransferOutLease([]int{0}, 200)
	if err := owner.AbortRemoteTransferOut(0, 100); err != nil {
		t.Fatalf("stale AbortRemoteTransferOut: %v", err)
	}
	owner.mu.Lock()
	hold := owner.groups[0].ManualFailover
	leasedReq := owner.remoteTransferOutLeaseReqID[0]
	owner.mu.Unlock()
	if !hold || leasedReq != 200 {
		t.Fatalf("stale abort disturbed newer hold: hold=%v leaseReq=%d, want true/200", hold, leasedReq)
	}
	if err := owner.AbortRemoteTransferOut(0, 200); err != nil {
		t.Fatalf("matching AbortRemoteTransferOut: %v", err)
	}
	owner.mu.Lock()
	hold = owner.groups[0].ManualFailover
	owner.mu.Unlock()
	if hold {
		t.Fatal("matching abort must clear the owner hold")
	}
}

func TestSendFailoverAbortWire15164(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ss.mu.Lock()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- ss.SendFailoverAbort(7, 41) }()
	var hdr [syncHeaderSize]byte
	if _, err := io.ReadFull(peer, hdr[:]); err != nil {
		t.Fatalf("read abort header: %v", err)
	}
	if hdr[4] != syncMsgFailoverAbort {
		t.Fatalf("msg type = %d, want %d (failover abort)", hdr[4], syncMsgFailoverAbort)
	}
	payload := make([]byte, binary.LittleEndian.Uint32(hdr[8:12]))
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read abort payload: %v", err)
	}
	if len(payload) != 9 || payload[0] != 7 || binary.LittleEndian.Uint64(payload[1:9]) != 41 {
		t.Fatalf("abort payload = %v, want rg=7 req=41", payload)
	}
	if err := <-done; err != nil {
		t.Fatalf("SendFailoverAbort() error = %v", err)
	}
}

func TestHandleRemoteFailoverAbortInvokesCallback15164(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	got := make(chan uint64, 1)
	ss.OnRemoteFailoverAbort = func(rgID int, reqID uint64) error {
		if rgID != 5 {
			t.Errorf("abort rg = %d, want 5", rgID)
		}
		got <- reqID
		return nil
	}
	payload := make([]byte, 9)
	payload[0] = 5
	binary.LittleEndian.PutUint64(payload[1:9], 99)
	ss.handleMessage(nil, syncMsgFailoverAbort, payload)
	select {
	case reqID := <-got:
		if reqID != 99 {
			t.Fatalf("abort reqID = %d, want 99", reqID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("remote failover abort callback did not run")
	}

	batchGot := make(chan uint64, 1)
	ss.OnRemoteFailoverAbortBatch = func(rgIDs []int, reqID uint64) error {
		if len(rgIDs) != 2 || rgIDs[0] != 1 || rgIDs[1] != 2 {
			t.Errorf("batch abort rgs = %v, want [1 2]", rgIDs)
		}
		batchGot <- reqID
		return nil
	}
	ss.handleMessage(nil, syncMsgFailoverBatchAbort, encodeFailoverBatchRequestPayload([]int{2, 1}, 100))
	select {
	case reqID := <-batchGot:
		if reqID != 100 {
			t.Fatalf("batch abort reqID = %d, want 100", reqID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("remote batch failover abort callback did not run")
	}
}
