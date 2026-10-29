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

// A failed fence must keep the requester blocked after the owner restores to
// ordinary secondary: a higher-priority requester would otherwise win the
// neither-primary election after the hold-only abort marker is cleared.
func TestFailedFenceRestorationKeepsHigherPriorityRequesterFenced17713(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name, ids := "single", []int{1}
		if batch {
			name, ids = "batch", []int{1, 2}
		}
		t.Run(name, func(t *testing.T) {
			requester, owner := ackWireManagers16592(t, ids, true)
			const reqID = uint64(17713)
			staleOwnerPrimary := owner.buildHeartbeat()
			failRequest := func(rgs []int) (uint64, error) {
				if batch {
					if _, err := owner.ManualFailoverBatch(rgs); err != nil {
						return 0, err
					}
				} else if _, err := owner.ManualFailover(rgs[0]); err != nil {
					return 0, err
				}
				owner.ArmRemoteTransferOutLease(rgs, reqID)
				requester.handlePeerHeartbeat(owner.buildHeartbeat())
				return reqID, failoverAckError(rgs, failoverAck{status: failoverAckFailed})
			}
			requester.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
				return failRequest([]int{rgID})
			})
			requester.SetPeerFailoverBatchFunc(failRequest)
			requester.SetPeerFailoverAbortFunc(func(rgID int, id uint64) error {
				return owner.AbortRemoteTransferOut(rgID, id)
			})
			requester.SetPeerFailoverAbortBatchFunc(func(rgs []int, id uint64) error {
				return owner.AbortRemoteTransferOutBatch(rgs, id)
			})
			requester.SetPeerFailoverCommitFunc(func(int, uint64) error {
				t.Fatal("commit must not be sent after a failed fence ACK")
				return nil
			})
			requester.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error {
				t.Fatal("batch commit must not be sent after a failed fence ACK")
				return nil
			})
			var err error
			if batch {
				err = requester.RequestPeerFailoverBatch(ids)
			} else {
				err = requester.RequestPeerFailover(ids[0])
			}
			if err == nil {
				t.Fatal("failed fence ACK must fail the requester operation")
			}
			// A delayed primary frame from before the failed transfer is not
			// proof that the owner reclaimed the RG after its hold.
			requester.handlePeerHeartbeat(staleOwnerPrimary)
			for _, id := range ids {
				if requester.IsLocalPrimary(id) {
					t.Fatalf("stale pre-transfer primary heartbeat promoted rg %d", id)
				}
				requester.mu.RLock()
				_, marker := requester.abortedPeerTransferReqID[id]
				requester.mu.RUnlock()
				if !marker {
					t.Fatalf("stale pre-transfer primary heartbeat cleared rg %d fence", id)
				}
			}
			for _, id := range ids {
				if owner.IsLocalPrimary(id) {
					t.Fatalf("fixture rg %d: lower-priority owner must restore to ordinary secondary", id)
				}
			}
			for range 3 {
				restored := owner.buildHeartbeat()
				peerStates := make(map[int]NodeState, len(restored.Groups))
				for _, group := range restored.Groups {
					peerStates[int(group.GroupID)] = NodeState(group.State)
				}
				for _, id := range ids {
					if peerStates[id] != StateSecondary {
						t.Fatalf("restoration heartbeat reports rg %d=%s, want ordinary secondary", id, peerStates[id])
					}
				}
				requester.handlePeerHeartbeat(restored)
				for _, id := range ids {
					if requester.IsLocalPrimary(id) {
						t.Fatalf("higher-priority requester promoted on owner restoration heartbeat for rg %d", id)
					}
					requester.mu.RLock()
					gotReqID, marker := requester.abortedPeerTransferReqID[id]
					fence, fenced := requester.abortedPeerTransferFence[id]
					requester.mu.RUnlock()
					if !marker || gotReqID != reqID || !fenced || !fence.sawHold {
						t.Fatalf("restoration heartbeat cleared rg %d failed-transfer fence: reqID=%d marker=%v fenced=%v saw_hold=%v", id, gotReqID, marker, fenced, fence.sawHold)
					}
				}
			}

			// An owner-primary heartbeat resolves the failed transfer epoch. A
			// later explicit transfer-out is then allowed to promote normally.
			owner.mu.Lock()
			for _, id := range ids {
				owner.groups[id].State = StatePrimary
			}
			owner.mu.Unlock()
			requester.handlePeerHeartbeat(owner.buildHeartbeat())
			for _, id := range ids {
				requester.mu.RLock()
				_, marker := requester.abortedPeerTransferReqID[id]
				requester.mu.RUnlock()
				if marker {
					t.Fatalf("fresh owner-primary heartbeat must resolve rg %d failed transfer epoch", id)
				}
			}
			if batch {
				if _, err := owner.ManualFailoverBatch(ids); err != nil {
					t.Fatal(err)
				}
			} else if _, err := owner.ManualFailover(ids[0]); err != nil {
				t.Fatal(err)
			}
			requester.handlePeerHeartbeat(owner.buildHeartbeat())
			for _, id := range ids {
				if !requester.IsLocalPrimary(id) {
					t.Fatalf("requester must promote rg %d after the failed epoch resolves and a new transfer-out is advertised", id)
				}
			}
		})
	}
}

// Peer loss is an epoch boundary that must discard a failed-transfer fence.
func TestFailedFencePeerLossClearsFence17713(t *testing.T) {
	requester, owner := ackWireManagers16592(t, []int{1}, true)
	const reqID = uint64(17713)
	requester.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		if _, err := owner.ManualFailover(rgID); err != nil {
			return 0, err
		}
		owner.ArmRemoteTransferOutLease([]int{rgID}, reqID)
		requester.handlePeerHeartbeat(owner.buildHeartbeat())
		return reqID, failoverAckError([]int{rgID}, failoverAck{status: failoverAckFailed})
	})
	requester.SetPeerFailoverAbortFunc(func(rgID int, id uint64) error {
		return owner.AbortRemoteTransferOut(rgID, id)
	})
	requester.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Fatal("commit must not be sent after a failed fence ACK")
		return nil
	})
	if err := requester.RequestPeerFailover(1); err == nil {
		t.Fatal("failed fence ACK must fail the requester operation")
	}
	requester.mu.RLock()
	_, marker := requester.abortedPeerTransferReqID[1]
	_, fenced := requester.abortedPeerTransferFence[1]
	requester.mu.RUnlock()
	if !marker || !fenced {
		t.Fatalf("failed transfer did not leave a fence before peer loss: marker=%v fenced=%v", marker, fenced)
	}

	requester.mu.Lock()
	requester.peerHeartbeatFreshFn = func() bool { return false }
	requester.mu.Unlock()
	requester.handlePeerTimeout()

	requester.mu.RLock()
	_, marker = requester.abortedPeerTransferReqID[1]
	_, fenced = requester.abortedPeerTransferFence[1]
	peerAlive := requester.peerAlive
	requester.mu.RUnlock()
	if peerAlive {
		t.Fatal("peer-loss control did not mark peer lost")
	}
	if marker || fenced {
		t.Fatalf("peer loss retained failed-transfer fence: marker=%v fenced=%v", marker, fenced)
	}
}
