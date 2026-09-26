package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestRequestedPreemptTransferPinsCommittedRoleUntilReset10776 reproduces the
// requested transfer of an RG from a higher-priority preempt node to a lower-
// priority one. The old owner must not preempt back, and the new owner must keep
// its committed primary role after the heartbeat grace expires. Resetting the
// old owner is the explicit action that returns ordinary preempt election.
func TestRequestedPreemptTransferPinsCommittedRoleUntilReset10776(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "single"
		ids := []int{0}
		if batch {
			name = "batch"
			ids = []int{1, 2}
		}
		t.Run(name, func(t *testing.T) {
			priorities := map[int]int{0: 200, 1: 100}
			groups := make([]*config.RedundancyGroup, 0, len(ids))
			for _, id := range ids {
				groups = append(groups, makeRG(id, true, priorities))
			}
			cfg := makeConfig(groups...)

			owner := NewManager(0, 1)
			owner.UpdateConfig(cfg)
			requester := NewManager(1, 1)
			requester.handlePeerHeartbeat(owner.buildHeartbeat())
			requester.UpdateConfig(cfg)
			owner.handlePeerHeartbeat(requester.buildHeartbeat())

			for _, id := range ids {
				if !owner.IsLocalPrimary(id) || requester.IsLocalPrimary(id) {
					t.Fatalf("fixture rg %d: owner primary=%t, requester primary=%t; want true,false",
						id, owner.IsLocalPrimary(id), requester.IsLocalPrimary(id))
				}
			}

			requester.mu.Lock()
			for _, id := range ids {
				rg := requester.groups[id]
				rg.Ready = true
				rg.ReadySince = time.Now().Add(-requester.takeoverHoldTime - time.Second)
			}
			requester.mu.Unlock()

			if batch {
				requester.SetPeerFailoverBatchFunc(func(requested []int) (uint64, error) {
					if _, err := owner.ManualFailoverBatch(requested); err != nil {
						return 0, err
					}
					return 10776, nil
				})
				requester.SetPeerFailoverCommitBatchFunc(func(requested []int, reqID uint64) error {
					if reqID != 10776 {
						t.Fatalf("batch commit reqID = %d, want 10776", reqID)
					}
					return owner.FinalizePeerTransferOutBatch(requested)
				})
				if err := requester.RequestPeerFailoverBatch(ids); err != nil {
					t.Fatalf("RequestPeerFailoverBatch() error = %v", err)
				}
			} else {
				requester.SetPeerFailoverFunc(func(int) (uint64, error) {
					if _, err := owner.ManualFailover(ids[0]); err != nil {
						return 0, err
					}
					return 10776, nil
				})
				requester.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error {
					if reqID != 10776 {
						t.Fatalf("commit reqID = %d, want 10776", reqID)
					}
					return owner.FinalizePeerTransferOut(rgID)
				})
				if err := requester.RequestPeerFailover(ids[0]); err != nil {
					t.Fatalf("RequestPeerFailover() error = %v", err)
				}
			}

			owner.handlePeerHeartbeat(requester.buildHeartbeat())
			for _, id := range ids {
				if owner.IsLocalPrimary(id) {
					t.Fatalf("rg %d: old owner preempted back while the committed requester was primary", id)
				}
			}

			// The requester initially masks the peer heartbeat during commit
			// grace. Once that bounded window expires, the higher-priority old
			// owner still advertises secondary and ordinary preempt would make
			// both nodes secondary unless the committed role remains pinned.
			requester.mu.Lock()
			for _, id := range ids {
				requester.peerTransferCommitGraceUntil[id] = time.Now().Add(-time.Second)
			}
			requester.mu.Unlock()
			requester.handlePeerHeartbeat(owner.buildHeartbeat())
			for _, id := range ids {
				if !requester.IsLocalPrimary(id) {
					t.Fatalf("rg %d: requester yielded committed primary role after grace expired", id)
				}
			}

			// A reset is the explicit end of the pin: the higher-priority
			// owner resumes preempt election and the requester yields to it.
			for _, id := range ids {
				if err := owner.ResetFailover(id); err != nil {
					t.Fatalf("ResetFailover(%d) error = %v", id, err)
				}
			}
			requester.handlePeerHeartbeat(owner.buildHeartbeat())
			for _, id := range ids {
				if !owner.IsLocalPrimary(id) || requester.IsLocalPrimary(id) {
					t.Fatalf("rg %d after reset: owner primary=%t, requester primary=%t; want true,false",
						id, owner.IsLocalPrimary(id), requester.IsLocalPrimary(id))
				}
			}
		})
	}
}
