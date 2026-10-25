package cluster

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// #16818 (R3-F08-01): a post-ACK abort of a node-targeted peer failover
// left the requester primary whenever the requester outranked the owner
// (or the owner's hold heartbeat had already been seen before the local
// commit). commitRequestedPeerFailover had already promoted the
// requester, but abortRequestedPeerFailover only re-ran the election
// when it restored a peer snapshot whose pre-request state was not the
// hold, and the restored snapshot then decided the outcome through the
// ordinary dual-active arms — so a higher-priority requester (or a
// hold-shaped snapshot) kept the RG while RequestPeerFailover reported
// failure. The abort must demote the requester it promoted, in every
// ordering, for both post-ACK abort causes, whether or not the abort
// frame reaches the owner, and whether the owner's hold heartbeat was
// observed before or after the local commit.
//
// FAIL-ON-REVERT: drop the unconditional election (demotion) from
func abortFixture16818(t *testing.T, reqPrio, ownPrio int) (requester, owner *Manager) {
	t.Helper()
	prios := map[int]int{0: reqPrio, 1: ownPrio}
	requester = NewManager(0, 1)
	owner = NewManager(1, 1)
	requester.UpdateConfig(makeConfig(makeRG(0, false, prios)))
	owner.UpdateConfig(makeConfig(makeRG(0, false, prios)))
	<-requester.Events()
	<-owner.Events()
	// The owner starts primary and the requester secondary regardless of
	// the priority ordering under test: pin both states with peerAlive
	// false so UpdateConfig's initial election cannot promote the
	// higher-priority requester before the first heartbeat.
	owner.mu.Lock()
	owner.groups[0].State = StatePrimary
	owner.groups[0].Ready = true
	owner.groups[0].ReadySince = time.Now().Add(-time.Hour)
	owner.mu.Unlock()
	requester.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: uint16(ownPrio), Weight: 255, State: uint8(StatePrimary)},
		},
	})
	requester.mu.Lock()
	requester.groups[0].State = StateSecondary
	requester.groups[0].Ready = true
	requester.groups[0].ReadySince = time.Now().Add(-time.Hour)
	requester.groups[0].ReadinessReasons = nil
	requester.mu.Unlock()
	if requester.IsLocalPrimary(0) {
		t.Fatal("fixture: requester must start secondary")
	}
	if !owner.IsLocalPrimary(0) {
		t.Fatal("fixture: owner must start primary")
	}
	return requester, owner
}

func managerState16818(m *Manager, rgID int) NodeState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.groups[rgID].State
}

// exchange16818 delivers each manager's current RG state to the other,
// as the next heartbeat round would.
func exchange16818(requester, owner *Manager, reqPrio, ownPrio int) {
	requester.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: uint16(ownPrio), Weight: 255, State: uint8(managerState16818(owner, 0))},
		},
	})
	owner.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: uint16(reqPrio), Weight: 255, State: uint8(managerState16818(requester, 0))},
		},
	})
}

func TestAbortedPeerFailoverDemotesRequester16818(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reqPrio    int
		ownPrio    int
		cause      string // "commit-ready" | "commit-send"
		frameLost  bool
		holdBefore bool // owner's hold heartbeat seen before the local commit
	}{
		{"control/commit-ready/delivered/hold-after", 100, 200, "commit-ready", false, false},
		{"control/commit-ready/delivered/hold-before", 100, 200, "commit-ready", false, true},
		{"control/commit-ready/lost/hold-after", 100, 200, "commit-ready", true, false},
		{"control/commit-ready/lost/hold-before", 100, 200, "commit-ready", true, true},
		{"control/commit-send/delivered/hold-after", 100, 200, "commit-send", false, false},
		{"control/commit-send/delivered/hold-before", 100, 200, "commit-send", false, true},
		{"control/commit-send/lost/hold-after", 100, 200, "commit-send", true, false},
		{"control/commit-send/lost/hold-before", 100, 200, "commit-send", true, true},
		{"outranks/commit-ready/delivered/hold-after", 200, 100, "commit-ready", false, false},
		{"outranks/commit-ready/delivered/hold-before", 200, 100, "commit-ready", false, true},
		{"outranks/commit-ready/lost/hold-after", 200, 100, "commit-ready", true, false},
		{"outranks/commit-ready/lost/hold-before", 200, 100, "commit-ready", true, true},
		{"outranks/commit-send/delivered/hold-after", 200, 100, "commit-send", false, false},
		{"outranks/commit-send/delivered/hold-before", 200, 100, "commit-send", false, true},
		{"outranks/commit-send/lost/hold-after", 200, 100, "commit-send", true, false},
		{"outranks/commit-send/lost/hold-before", 200, 100, "commit-send", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requester, owner := abortFixture16818(t, tc.reqPrio, tc.ownPrio)
			const reqID = uint64(16818)
			holdHB := func() {
				requester.handlePeerHeartbeat(&HeartbeatPacket{
					NodeID:    1,
					ClusterID: 1,
					Groups: []HeartbeatGroup{
						{GroupID: 0, Priority: uint16(tc.ownPrio), Weight: 255, State: uint8(StateSecondaryHold)},
					},
				})
			}
			requester.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
				if _, err := owner.ManualFailover(rgID); err != nil {
					return 0, err
				}
				owner.ArmRemoteTransferOutLease([]int{rgID}, reqID)
				if tc.holdBefore {
					holdHB()
				}
				return reqID, nil
			})
			requester.SetPeerFailoverAbortFunc(func(rgID int, id uint64) error {
				if tc.frameLost {
					return errors.New("abort frame lost")
				}
				return owner.AbortRemoteTransferOut(rgID, id)
			})
			requester.SetLocalTransferCommitReadyHook(func(rgIDs []int) error {
				if tc.cause != "commit-ready" {
					return nil
				}
				if !tc.holdBefore {
					holdHB()
				}
				return errors.New("local commit not ready")
			})
			requester.SetPeerFailoverCommitFunc(func(rgID int, id uint64) error {
				if tc.cause != "commit-send" {
					t.Error("commit must not be sent after local commit-ready fails")
					return nil
				}
				if !tc.holdBefore {
					holdHB()
				}
				return errors.New("commit send failed")
			})

			if err := requester.RequestPeerFailover(0); err == nil {
				t.Fatal("RequestPeerFailover must report the post-ACK abort")
			}
			if requester.IsLocalPrimary(0) {
				t.Fatalf("requester still primary immediately after abort (reqPrio=%d ownPrio=%d cause=%s frameLost=%v holdBefore=%v)",
					tc.reqPrio, tc.ownPrio, tc.cause, tc.frameLost, tc.holdBefore)
			}
			exchange16818(requester, owner, tc.reqPrio, tc.ownPrio)
			exchange16818(requester, owner, tc.reqPrio, tc.ownPrio)
			if requester.IsLocalPrimary(0) {
				t.Fatal("requester primary after heartbeat exchange following abort")
			}
			if !tc.frameLost && !owner.IsLocalPrimary(0) {
				t.Fatal("owner must be restored to primary when the abort frame is delivered")
			}
		})
	}
}

// Batch form: the same post-ACK abort must demote every RG the batch
// commit promoted, in the requester-outranks ordering with the owner's
// hold heartbeat seen before the commit.
func TestAbortedPeerFailoverBatchDemotesRequester16818(t *testing.T) {
	for _, frameLost := range []bool{false, true} {
		t.Run(fmt.Sprintf("frameLost=%v", frameLost), func(t *testing.T) {
			prios := map[int]int{0: 200, 1: 100}
			requester := NewManager(0, 1)
			owner := NewManager(1, 1)
			requester.UpdateConfig(makeConfig(makeRG(1, false, prios), makeRG(2, false, prios)))
			owner.UpdateConfig(makeConfig(makeRG(1, false, prios), makeRG(2, false, prios)))
			<-requester.Events()
			<-requester.Events()
			<-owner.Events()
			<-owner.Events()
			owner.mu.Lock()
			for _, id := range []int{1, 2} {
				owner.groups[id].State = StatePrimary
				owner.groups[id].Ready = true
				owner.groups[id].ReadySince = time.Now().Add(-time.Hour)
			}
			owner.mu.Unlock()
			requester.handlePeerHeartbeat(&HeartbeatPacket{
				NodeID:    1,
				ClusterID: 1,
				Groups: []HeartbeatGroup{
					{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
					{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
				},
			})
			requester.mu.Lock()
			for _, id := range []int{1, 2} {
				requester.groups[id].State = StateSecondary
				requester.groups[id].Ready = true
				requester.groups[id].ReadySince = time.Now().Add(-time.Hour)
				requester.groups[id].ReadinessReasons = nil
			}
			requester.mu.Unlock()

			const reqID = uint64(16819)
			holdHB := func() {
				requester.handlePeerHeartbeat(&HeartbeatPacket{
					NodeID:    1,
					ClusterID: 1,
					Groups: []HeartbeatGroup{
						{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
						{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
					},
				})
			}
			requester.SetPeerFailoverBatchFunc(func(rgIDs []int) (uint64, error) {
				if _, err := owner.ManualFailoverBatch(rgIDs); err != nil {
					return 0, err
				}
				owner.ArmRemoteTransferOutLease(rgIDs, reqID)
				holdHB() // hold heartbeat seen before the local commit
				return reqID, nil
			})
			requester.SetPeerFailoverAbortBatchFunc(func(rgIDs []int, id uint64) error {
				if frameLost {
					return errors.New("abort frame lost")
				}
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
				t.Fatal("RequestPeerFailoverBatch must report the post-ACK abort")
			}
			for _, id := range []int{1, 2} {
				if requester.IsLocalPrimary(id) {
					t.Fatalf("requester still primary for rg %d immediately after batch abort", id)
				}
			}
			holdHB()
			for _, id := range []int{1, 2} {
				if requester.IsLocalPrimary(id) {
					t.Fatalf("requester re-promoted rg %d on hold heartbeat after batch abort", id)
				}
			}
			if !frameLost {
				for _, id := range []int{1, 2} {
					if !owner.IsLocalPrimary(id) {
						t.Fatalf("owner must be restored to primary for rg %d when the abort frame is delivered", id)
					}
				}
			}
		})
	}
}
