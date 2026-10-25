package cluster

import (
	"encoding/binary"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Exercise the real request and abort senders through a pipe. Timeout rows
// withhold the ACK for the actual failoverAckTimeout; completing a waiter with
// a synthetic error would not exercise the timer's reqID return.
func TestFailoverWireAckOutcome16592(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name, ids := "single", []int{1}
		if batch {
			name, ids = "batch", []int{1, 2}
		}
		t.Run(name, func(t *testing.T) {
			for _, outcome := range []string{"failed", "timeout", "rejected", "applied"} {
				t.Run(outcome, func(t *testing.T) {
					requester, owner := ackWireManagers16592(t, ids, false)
					ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
					local, peer := net.Pipe()
					defer local.Close()
					defer peer.Close()
					ss.conn0 = local
					ss.stats.Connected.Store(true)
					frames := make(chan syncFrame, 4)
					readFramesInto(peer, frames)
					requester.SetPeerFailoverFunc(ss.SendFailover)
					requester.SetPeerFailoverBatchFunc(ss.SendFailoverBatch)
					requester.SetPeerFailoverAbortFunc(ss.SendFailoverAbort)
					requester.SetPeerFailoverAbortBatchFunc(ss.SendFailoverAbortBatch)
					commits := 0
					commit := func(rgs []int, reqID uint64) error {
						commits++
						if err := owner.FinalizePeerTransferOutBatch(rgs); err != nil {
							return err
						}
						for _, id := range rgs {
							owner.ClearRemoteTransferOutLease(id, reqID)
						}
						return nil
					}
					requester.SetPeerFailoverCommitFunc(func(id int, reqID uint64) error {
						return commit([]int{id}, reqID)
					})
					requester.SetPeerFailoverCommitBatchFunc(commit)
					done := make(chan error, 1)
					go func() { done <- requester.RequestPeerFailoverBatch(ids) }()
					var request syncFrame
					select {
					case request = <-frames:
					case <-time.After(2 * time.Second):
						t.Fatal("no request frame")
					}
					wantType := uint8(syncMsgFailover)
					if batch {
						wantType = syncMsgFailoverBatch
					}
					if request.typ != wantType {
						t.Fatalf("request type = %d, want %d", request.typ, wantType)
					}
					var reqID uint64
					if batch {
						rgs, id, err := decodeFailoverBatchRequestPayload(request.payload)
						if err != nil || !slices.Equal(rgs, ids) {
							t.Fatalf("request = %v, %v; want %v", rgs, err, ids)
						}
						reqID = id
					} else {
						if len(request.payload) != 9 || request.payload[0] != byte(ids[0]) {
							t.Fatalf("request payload = %v", request.payload)
						}
						reqID = binary.LittleEndian.Uint64(request.payload[1:])
					}
					if reqID == 0 {
						t.Fatal("request ID must be nonzero")
					}
					if outcome != "rejected" {
						if _, err := owner.ManualFailoverBatch(ids); err != nil {
							t.Fatal(err)
						}
						owner.ArmRemoteTransferOutLease(ids, reqID)
					}
					hold := owner.buildHeartbeat()
					requester.handlePeerHeartbeat(hold)
					for _, id := range ids {
						if requester.IsLocalPrimary(id) {
							t.Errorf("rg %d promoted before the applied ACK", id)
						}
					}
					if outcome != "timeout" {
						status := uint8(failoverAckFailed)
						if outcome == "applied" {
							status = failoverAckApplied
						} else if outcome == "rejected" {
							status = failoverAckRejected
						}
						if batch {
							ss.handleMessage(local, syncMsgFailoverBatchAck,
								encodeFailoverBatchAckPayload(ids, status, reqID, outcome))
						} else {
							payload := make([]byte, 10+len(outcome))
							payload[0], payload[1] = byte(ids[0]), status
							binary.LittleEndian.PutUint64(payload[2:10], reqID)
							copy(payload[10:], outcome)
							ss.handleMessage(local, syncMsgFailoverAck, payload)
						}
					}
					var err error
					select {
					case err = <-done:
					case <-time.After(failoverAckTimeout + 5*time.Second):
						t.Fatal("request did not complete within ACK timeout")
					}
					if outcome == "applied" {
						if err != nil || commits != 1 {
							t.Fatalf("applied request: err=%v commits=%d", err, commits)
						}
						for _, id := range ids {
							if !requester.IsLocalPrimary(id) {
								t.Errorf("rg %d not primary after applied ACK", id)
							}
						}
						return
					}
					if err == nil || commits != 0 {
						t.Fatalf("failed request: err=%v commits=%d", err, commits)
					}
					if outcome == "timeout" && !strings.Contains(err.Error(), "timed out waiting for peer failover ack") {
						t.Fatalf("did not reach request timer branch: %v", err)
					}
					// The abort must carry the transmitted reqID, not zero.
					select {
					case abort := <-frames:
						if batch {
							rgs, abortID, decodeErr := decodeFailoverBatchRequestPayload(abort.payload)
							if abort.typ != syncMsgFailoverBatchAbort || decodeErr != nil ||
								!slices.Equal(rgs, ids) || abortID != reqID {
								t.Fatalf("abort frame = %+v, want rgs=%v reqID=%d", abort, ids, reqID)
							}
						} else if abort.typ != syncMsgFailoverAbort || len(abort.payload) != 9 ||
							abort.payload[0] != byte(ids[0]) || binary.LittleEndian.Uint64(abort.payload[1:]) != reqID {
							t.Fatalf("abort frame = %+v, want rg=%d reqID=%d", abort, ids[0], reqID)
						}
					case <-time.After(time.Second):
						t.Fatal("no reqID-bound abort frame after request error")
					}
					// Delay delivery of the abort: the stale hold must not
					// authorize promotion after the request returned an error.
					requester.handlePeerHeartbeat(hold)
					for _, id := range ids {
						if requester.IsLocalPrimary(id) {
							t.Errorf("requester promoted rg %d after abort", id)
						}
					}
					if err := owner.AbortRemoteTransferOutBatch(ids, reqID); err != nil {
						t.Fatal(err)
					}
					for _, id := range ids {
						if !owner.IsLocalPrimary(id) {
							t.Errorf("owner rg %d not restored by bound abort", id)
						}
					}
					requester.handlePeerHeartbeat(owner.buildHeartbeat())
					for _, id := range ids {
						if requester.IsLocalPrimary(id) {
							t.Errorf("requester preempted restored incumbent rg %d", id)
						}
					}
				})
			}
		})
	}
}

func ackWireManagers16592(t *testing.T, ids []int, requesterHigher bool) (*Manager, *Manager) {
	t.Helper()
	groups := make([]*config.RedundancyGroup, 0, len(ids))
	priorities := map[int]int{0: 100, 1: 200}
	if requesterHigher {
		priorities = map[int]int{0: 200, 1: 100}
	}
	for _, id := range ids {
		groups = append(groups, makeRG(id, false, priorities))
	}
	owner := NewManager(1, 1)
	owner.UpdateConfig(makeConfig(groups...))
	requester := NewManager(0, 1)
	requester.handlePeerHeartbeat(owner.buildHeartbeat())
	requester.UpdateConfig(makeConfig(groups...))
	requester.mu.Lock()
	for _, id := range ids {
		requester.groups[id].Ready = true
		requester.groups[id].ReadySince = time.Now().Add(-time.Hour)
	}
	requester.mu.Unlock()
	owner.handlePeerHeartbeat(requester.buildHeartbeat())
	for _, id := range ids {
		if requester.IsLocalPrimary(id) || !owner.IsLocalPrimary(id) {
			t.Fatalf("fixture rg %d: requester must be secondary, owner primary", id)
		}
	}
	return requester, owner
}

// The old abort guard skipped only "Peer transfer out", then priority election
// promoted a higher-priority non-preempt requester. Keep both requester paths
// secondary while the abort is undelivered, even if peer weight also reaches 0.
func TestHigherPriorityRequesterHoldsAfterAbort16592(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name, ids := "single", []int{1}
		if batch {
			name, ids = "batch", []int{1, 2}
		}
		t.Run(name, func(t *testing.T) {
			requester, owner := ackWireManagers16592(t, ids, true)
			const reqID = 16592
			request := func(rgs []int) (uint64, error) {
				if _, err := owner.ManualFailoverBatch(rgs); err != nil {
					return 0, err
				}
				owner.ArmRemoteTransferOutLease(rgs, reqID)
				requester.handlePeerHeartbeat(owner.buildHeartbeat())
				for _, id := range ids {
					if requester.IsLocalPrimary(id) {
						t.Errorf("rg %d promoted while ACK still pending", id)
					}
				}
				return reqID, failoverAckError(rgs, failoverAck{status: failoverAckFailed})
			}
			requester.SetPeerFailoverFunc(func(id int) (uint64, error) {
				return request([]int{id})
			})
			requester.SetPeerFailoverBatchFunc(request)
			requester.SetPeerFailoverCommitFunc(func(int, uint64) error {
				t.Error("commit sent after failed ACK")
				return nil
			})
			requester.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error {
				t.Error("batch commit sent after failed ACK")
				return nil
			})
			// No abort transport: the marker must protect the requester even
			// while the owner keeps advertising its uncommitted hold.
			if err := requester.RequestPeerFailoverBatch(ids); err == nil {
				t.Fatal("request did not return the failed ACK")
			}
			for _, weight := range []uint8{255, 0} {
				hold := owner.buildHeartbeat()
				for i := range hold.Groups {
					hold.Groups[i].Weight = weight
				}
				requester.handlePeerHeartbeat(hold)
				for _, id := range ids {
					if requester.IsLocalPrimary(id) {
						t.Errorf("higher-priority requester promoted rg %d after abort (peer weight %d)", id, weight)
					}
				}
			}
		})
	}
}
