package cluster

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func makeConfig(groups ...*config.RedundancyGroup) *config.ClusterConfig {
	return &config.ClusterConfig{
		RethCount:        len(groups),
		RedundancyGroups: groups,
	}
}

func makeRG(id int, preempt bool, priorities map[int]int, monitors ...*config.InterfaceMonitor) *config.RedundancyGroup {
	return &config.RedundancyGroup{
		ID:                id,
		NodePriorities:    priorities,
		Preempt:           preempt,
		InterfaceMonitors: monitors,
	}
}

func TestNewManager(t *testing.T) {
	m := NewManager(0, 1)
	if m.NodeID() != 0 {
		t.Fatalf("NodeID = %d, want 0", m.NodeID())
	}
	if m.ClusterID() != 1 {
		t.Fatalf("ClusterID = %d, want 1", m.ClusterID())
	}
	if states := m.GroupStates(); len(states) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(states))
	}
}

func TestUpdateConfig_CreatesRGs(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
		makeRG(1, true, map[int]int{0: 150, 1: 250}),
	)
	m.UpdateConfig(cfg)

	states := m.GroupStates()
	if len(states) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(states))
	}

	// RG 0: node0 priority=200
	if states[0].GroupID != 0 {
		t.Errorf("group 0 ID = %d", states[0].GroupID)
	}
	if states[0].LocalPriority != 200 {
		t.Errorf("group 0 priority = %d, want 200", states[0].LocalPriority)
	}
	if states[0].Preempt {
		t.Error("group 0 preempt should be false")
	}

	// RG 1: node0 priority=150
	if states[1].GroupID != 1 {
		t.Errorf("group 1 ID = %d", states[1].GroupID)
	}
	if states[1].LocalPriority != 150 {
		t.Errorf("group 1 priority = %d, want 150", states[1].LocalPriority)
	}
	if !states[1].Preempt {
		t.Error("group 1 preempt should be true")
	}
}

func TestUpdateConfig_SingleNodeElection(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)

	if !m.IsLocalPrimary(0) {
		t.Error("node should be primary after single-node election")
	}

	// Check event was emitted.
	select {
	case ev := <-m.Events():
		if ev.OldState != StateSecondary || ev.NewState != StatePrimary {
			t.Errorf("event = %v->%v, want secondary->primary", ev.OldState, ev.NewState)
		}
	default:
		t.Error("expected election event")
	}
}

func TestUpdateConfig_PreservesState(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)

	// Drain events from initial election.
	for i := 0; i < 2; i++ {
		<-m.Events()
	}

	// Manually failover RG 0.
	_, _ = m.ManualFailover(0)

	// Re-apply config with updated priority but same groups.
	cfg2 := makeConfig(
		makeRG(0, true, map[int]int{0: 250}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg2)

	states := m.GroupStates()
	// RG 0: priority updated, but manual failover should be preserved.
	if states[0].LocalPriority != 250 {
		t.Errorf("RG 0 priority = %d, want 250", states[0].LocalPriority)
	}
	if !states[0].ManualFailover {
		t.Error("RG 0 manual failover should be preserved")
	}
	if states[0].State != StateSecondaryHold {
		t.Errorf("RG 0 state = %s, want secondary-hold (manual failover)", states[0].State)
	}
	if !states[0].Preempt {
		t.Error("RG 0 preempt should be updated to true")
	}
}

func TestUpdateConfig_RemovesDeletedGroups(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)

	// Remove RG 1 from config.
	cfg2 := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg2)

	states := m.GroupStates()
	if len(states) != 1 {
		t.Fatalf("expected 1 group after removal, got %d", len(states))
	}
	if states[0].GroupID != 0 {
		t.Errorf("remaining group ID = %d, want 0", states[0].GroupID)
	}
}

func TestUpdateConfig_NilConfig(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(nil) // should not panic
	if len(m.GroupStates()) != 0 {
		t.Error("nil config should not create groups")
	}
}

func TestSetMonitorWeight_Down(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)

	// Drain election event.
	<-m.Events()

	// Mark an interface down with weight 100.
	m.SetMonitorWeight(0, "trust0", true, 100)

	states := m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight = %d, want 155 (255-100)", states[0].Weight)
	}
	if len(states[0].MonitorFails) != 1 || states[0].MonitorFails[0] != "trust0" {
		t.Errorf("monitor fails = %v, want [trust0]", states[0].MonitorFails)
	}
	// Still primary since weight > 0.
	if !m.IsLocalPrimary(0) {
		t.Error("should still be primary with weight 155")
	}
}

func TestSetMonitorWeight_AllDown(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	<-m.Events() // drain initial election

	// Bring down two interfaces totaling 255+.
	m.SetMonitorWeight(0, "trust0", true, 200)
	m.SetMonitorWeight(0, "untrust0", true, 100)

	states := m.GroupStates()
	if states[0].Weight != 0 {
		t.Errorf("weight = %d, want 0 (clamped)", states[0].Weight)
	}
	if m.IsLocalPrimary(0) {
		t.Error("should not be primary with weight 0")
	}
}

func TestSetMonitorWeight_Recovery(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()

	m.SetMonitorWeight(0, "trust0", true, 255)
	// Weight = 0, secondary.

	// Recover.
	m.SetMonitorWeight(0, "trust0", false, 0)
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 after recovery", states[0].Weight)
	}
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary after recovery")
	}
	if len(states[0].MonitorFails) != 0 {
		t.Errorf("monitor fails = %v, want empty", states[0].MonitorFails)
	}
}

func TestSetMonitorWeight_UnknownRG(t *testing.T) {
	m := NewManager(0, 1)
	// Should not panic on unknown RG.
	m.SetMonitorWeight(99, "trust0", true, 100)
}

func TestSetMonitorWeight_DuplicateDown(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Same interface reported down twice — should not double-count.
	m.SetMonitorWeight(0, "trust0", true, 100)
	m.SetMonitorWeight(0, "trust0", true, 100)

	states := m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight = %d, want 155 (no double-count)", states[0].Weight)
	}
	if len(states[0].MonitorFails) != 1 {
		t.Errorf("monitor fails count = %d, want 1", len(states[0].MonitorFails))
	}
}

func TestManualFailover(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events() // election event

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatal(err)
	}

	states := m.GroupStates()
	if states[0].State != StateSecondaryHold {
		t.Errorf("state = %s, want secondary-hold after failover", states[0].State)
	}
	if !states[0].ManualFailover {
		t.Error("ManualFailover should be true")
	}
	if states[0].FailoverCount != 1 {
		t.Errorf("failover count = %d, want 1", states[0].FailoverCount)
	}
	// Weight stays monitor-derived (255 = full weight, no monitors down).
	// The peer now sees an explicit transfer-out state instead of
	// relying on weight=0 to signal demotion.
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 after manual failover (preserved, not zeroed)", states[0].Weight)
	}

	// Failover event should be emitted.
	select {
	case ev := <-m.Events():
		if ev.OldState != StatePrimary || ev.NewState != StateSecondaryHold {
			t.Errorf("event = %v->%v, want primary->secondary-hold", ev.OldState, ev.NewState)
		}
	default:
		t.Error("expected failover event")
	}
}

func TestManualFailover_PreHookRunsBeforeResign(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	called := false
	m.SetPreManualFailoverHook(func(rgID int) error {
		called = true
		if rgID != 0 {
			t.Fatalf("hook rg=%d, want 0", rgID)
		}
		if !m.IsLocalPrimary(0) {
			t.Fatal("manual failover hook ran after local node resigned")
		}
		return nil
	})

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected pre-manual-failover hook to run")
	}
}

func TestManualFailover_PreHookErrorPreventsResign(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.SetPreManualFailoverHook(func(rgID int) error {
		return fmt.Errorf("boom")
	})

	if _, err := m.ManualFailover(0); err == nil {
		t.Fatal("expected pre-manual-failover hook error")
	}

	states := m.GroupStates()
	if states[0].State != StatePrimary {
		t.Fatalf("state = %s, want primary after failed pre-hook", states[0].State)
	}
	if states[0].ManualFailover {
		t.Fatal("manual failover should remain cleared on pre-hook failure")
	}
}

func TestManualFailover_RetryablePreHookRetriesThenSucceeds(t *testing.T) {
	m := NewManager(0, 1)
	m.preManualFailoverRetryTimeout = 100 * time.Millisecond
	m.preManualFailoverRetryInterval = 5 * time.Millisecond
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	attempts := 0
	m.SetPreManualFailoverHook(func(rgID int) error {
		attempts++
		if attempts < 3 {
			return &RetryablePreFailoverError{Err: fmt.Errorf("not yet")}
		}
		return nil
	})

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	states := m.GroupStates()
	if states[0].State != StateSecondaryHold {
		t.Fatalf("state = %s, want secondary-hold after manual failover", states[0].State)
	}
	if !states[0].ManualFailover {
		t.Fatal("manual failover should be set after successful retry")
	}
}

func TestManualFailover_RetryablePreHookTimeoutKeepsPrimary(t *testing.T) {
	m := NewManager(0, 1)
	m.preManualFailoverRetryTimeout = 30 * time.Millisecond
	m.preManualFailoverRetryInterval = 5 * time.Millisecond
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	attempts := 0
	m.SetPreManualFailoverHook(func(rgID int) error {
		attempts++
		return &RetryablePreFailoverError{Err: fmt.Errorf("still busy")}
	})

	if _, err := m.ManualFailover(0); err == nil {
		t.Fatal("expected retryable pre-hook timeout error")
	}
	if attempts < 2 {
		t.Fatalf("expected multiple retry attempts, got %d", attempts)
	}
	states := m.GroupStates()
	if states[0].State != StatePrimary {
		t.Fatalf("state = %s, want primary after failed retry window", states[0].State)
	}
	if states[0].ManualFailover {
		t.Fatal("manual failover should remain cleared after retry timeout")
	}
}

func TestManualFailover_UnknownRG(t *testing.T) {
	m := NewManager(0, 1)
	if _, err := m.ManualFailover(99); err == nil {
		t.Error("expected error for unknown RG")
	}
}

func TestManualFailover_RejectsBackToBack(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Pre-hook blocks until released, simulating a long barrier wait.
	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	m.SetPreManualFailoverHook(func(rgID int) error {
		close(hookStarted)
		<-hookRelease
		return nil
	})

	errCh := make(chan error, 1)
	go func() {
		_, err := m.ManualFailover(0)
		errCh <- err
	}()

	// Wait for the first failover to enter the pre-hook.
	<-hookStarted

	// Second failover for the same RG should be rejected immediately.
	_, err := m.ManualFailover(0)
	if err == nil {
		t.Fatal("expected error for back-to-back failover on same RG")
	}
	if !strings.Contains(err.Error(), "failover already in progress") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Release the first failover and verify it completes.
	close(hookRelease)
	if err := <-errCh; err != nil {
		t.Fatalf("first failover should succeed: %v", err)
	}

	states := m.GroupStates()
	if states[0].State != StateSecondaryHold {
		t.Fatalf("state = %s, want secondary-hold", states[0].State)
	}
}

func TestManualFailover_DifferentRGsAllowed(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	// Drain both RG events.
	<-m.Events()
	<-m.Events()

	// Pre-hook blocks for RG 0 but not RG 1.
	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	m.SetPreManualFailoverHook(func(rgID int) error {
		if rgID == 0 {
			close(hookStarted)
			<-hookRelease
		}
		return nil
	})

	errCh := make(chan error, 1)
	go func() {
		_, err := m.ManualFailover(0)
		errCh <- err
	}()

	<-hookStarted

	// RG 1 failover should succeed even though RG 0 is in progress.
	if _, err := m.ManualFailover(1); err != nil {
		t.Fatalf("failover for different RG should succeed: %v", err)
	}

	close(hookRelease)
	if err := <-errCh; err != nil {
		t.Fatalf("RG 0 failover should succeed: %v", err)
	}
}

func TestManualFailover_InProgressClearedOnPreHookError(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.SetPreManualFailoverHook(func(rgID int) error {
		return fmt.Errorf("fatal hook error")
	})

	// First attempt fails.
	if _, err := m.ManualFailover(0); err == nil {
		t.Fatal("expected pre-hook error")
	}

	// Second attempt should NOT be rejected as "in progress" — the flag
	// must have been cleared by the failed first attempt.
	m.SetPreManualFailoverHook(func(rgID int) error {
		return nil
	})
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("retry after failed failover should succeed: %v", err)
	}
}

func TestRequestPeerFailoverCommitsLocalPrimaryWithoutHeartbeatObservation(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	if m.IsLocalPrimary(0) {
		t.Fatal("test setup error: should be secondary before peer failover")
	}

	var committedRG int
	var committedReqID uint64
	m.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		return 77, nil
	})
	m.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error {
		committedRG = rgID
		committedReqID = reqID
		return nil
	})

	if err := m.RequestPeerFailover(0); err != nil {
		t.Fatalf("RequestPeerFailover() error = %v", err)
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("should be primary after explicit transfer commit")
	}
	if committedRG != 0 || committedReqID != 77 {
		t.Fatalf("commit = rg %d req %d, want rg 0 req 77", committedRG, committedReqID)
	}
	if peer := m.PeerGroupStates()[0]; peer.State != StateSecondaryHold {
		t.Fatalf("peer state = %s, want secondary-hold during post-commit grace", peer.State)
	}
}

func TestRequestPeerFailoverAllowsTransferWithSyncWhenHeartbeatLost(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.mu.Lock()
	m.peerEverSeen = true
	m.peerAlive = false
	m.peerGroups[0] = PeerGroupState{
		GroupID:  0,
		Priority: 200,
		Weight:   255,
		State:    StatePrimary,
	}
	m.groups[0].State = StateSecondary
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	var committedRG int
	var committedReqID uint64
	m.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		return 91, nil
	})
	m.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error {
		committedRG = rgID
		committedReqID = reqID
		return nil
	})

	if err := m.RequestPeerFailover(0); err != nil {
		t.Fatalf("RequestPeerFailover() error = %v", err)
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("should be primary after explicit transfer commit with sync-connected peer")
	}
	if committedRG != 0 || committedReqID != 91 {
		t.Fatalf("commit = rg %d req %d, want rg 0 req 91", committedRG, committedReqID)
	}
	if peer := m.PeerGroupStates()[0]; peer.State != StateSecondaryHold {
		t.Fatalf("peer state = %s, want secondary-hold during post-commit grace", peer.State)
	}
}

func TestRequestPeerFailoverBatchCommitsLocalPrimaryTogether(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(1, true, map[int]int{0: 100}),
		makeRG(2, true, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 2, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	for _, rgID := range []int{1, 2} {
		m.groups[rgID].Ready = true
		m.groups[rgID].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
		m.groups[rgID].ReadinessReasons = nil
	}
	m.mu.Unlock()

	var committedRGs []int
	var committedReqID uint64
	m.SetPeerFailoverBatchFunc(func(rgIDs []int) (uint64, error) {
		committedRGs = append([]int(nil), rgIDs...)
		return 88, nil
	})
	m.SetPeerFailoverCommitBatchFunc(func(rgIDs []int, reqID uint64) error {
		committedRGs = append([]int(nil), rgIDs...)
		committedReqID = reqID
		return nil
	})

	if err := m.RequestPeerFailoverBatch([]int{2, 1}); err != nil {
		t.Fatalf("RequestPeerFailoverBatch() error = %v", err)
	}
	if !m.IsLocalPrimary(1) || !m.IsLocalPrimary(2) {
		t.Fatal("both redundancy groups should be primary after explicit batch transfer commit")
	}
	if committedReqID != 88 {
		t.Fatalf("commit reqID = %d, want 88", committedReqID)
	}
	if len(committedRGs) != 2 || committedRGs[0] != 1 || committedRGs[1] != 2 {
		t.Fatalf("committed rgs = %v, want [1 2]", committedRGs)
	}
	for _, rgID := range []int{1, 2} {
		if peer := m.PeerGroupStates()[rgID]; peer.State != StateSecondaryHold {
			t.Fatalf("peer state for rg %d = %s, want secondary-hold during post-commit grace", rgID, peer.State)
		}
	}
}

func TestRequestPeerFailoverBatchAllowsTransferWithSyncWhenHeartbeatLost(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(1, true, map[int]int{0: 100}),
		makeRG(2, true, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()
	<-m.Events()

	m.mu.Lock()
	m.peerEverSeen = true
	m.peerAlive = false
	for _, rgID := range []int{1, 2} {
		m.peerGroups[rgID] = PeerGroupState{
			GroupID:  rgID,
			Priority: 200,
			Weight:   255,
			State:    StatePrimary,
		}
		m.groups[rgID].State = StateSecondary
		m.groups[rgID].Ready = true
		m.groups[rgID].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
		m.groups[rgID].ReadinessReasons = nil
	}
	m.mu.Unlock()

	var committedRGs []int
	var committedReqID uint64
	m.SetPeerFailoverBatchFunc(func(rgIDs []int) (uint64, error) {
		committedRGs = append([]int(nil), rgIDs...)
		return 92, nil
	})
	m.SetPeerFailoverCommitBatchFunc(func(rgIDs []int, reqID uint64) error {
		committedReqID = reqID
		return nil
	})

	if err := m.RequestPeerFailoverBatch([]int{2, 1}); err != nil {
		t.Fatalf("RequestPeerFailoverBatch() error = %v", err)
	}
	if committedReqID != 92 {
		t.Fatalf("commit req id = %d, want 92", committedReqID)
	}
	if !reflect.DeepEqual(committedRGs, []int{1, 2}) {
		t.Fatalf("requested rg IDs = %v, want [1 2]", committedRGs)
	}
	for _, rgID := range []int{1, 2} {
		if !m.IsLocalPrimary(rgID) {
			t.Fatalf("rg %d should be primary after explicit batch transfer commit", rgID)
		}
		if peer := m.PeerGroupStates()[rgID]; peer.State != StateSecondaryHold {
			t.Fatalf("peer state for rg %d = %s, want secondary-hold during post-commit grace", rgID, peer.State)
		}
	}
}

func TestRequestPeerFailoverWaitsForLocalCommitReadyHookBeforePeerCommit(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	var order []string
	m.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		return 77, nil
	})
	m.SetLocalTransferCommitReadyHook(func(rgIDs []int) error {
		order = append(order, "ready")
		if len(rgIDs) != 1 || rgIDs[0] != 0 {
			t.Fatalf("local commit ready rgIDs = %v, want [0]", rgIDs)
		}
		if !m.IsLocalPrimary(0) {
			t.Fatal("local node should already be primary before local commit ready hook runs")
		}
		return nil
	})
	m.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error {
		order = append(order, "commit")
		return nil
	})

	if err := m.RequestPeerFailover(0); err != nil {
		t.Fatalf("RequestPeerFailover() error = %v", err)
	}
	if len(order) != 2 || order[0] != "ready" || order[1] != "commit" {
		t.Fatalf("call order = %v, want [ready commit]", order)
	}
}

func TestRequestPeerFailoverAbortsToPriorPeerStateWhenLocalCommitReadyHookFails(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	m.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		return 77, nil
	})
	m.SetLocalTransferCommitReadyHook(func(rgIDs []int) error {
		return fmt.Errorf("local activation not settled")
	})
	m.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error {
		t.Fatal("peer failover commit should not run when local commit ready hook fails")
		return nil
	})

	err := m.RequestPeerFailover(0)
	if err == nil {
		t.Fatal("expected local commit ready error")
	}
	if !strings.Contains(err.Error(), "local activation not settled") {
		t.Fatalf("RequestPeerFailover() error = %v", err)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("local node should not remain primary after abort")
	}
	if peer := m.PeerGroupStates()[0]; peer.State != StatePrimary {
		t.Fatalf("peer state = %s, want primary after abort", peer.State)
	}
}

func TestRequestPeerFailoverBatchAbortsWhenLocalCommitReadyHookFails(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(1, true, map[int]int{0: 100}),
		makeRG(2, true, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 2, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	for _, rgID := range []int{1, 2} {
		m.groups[rgID].Ready = true
		m.groups[rgID].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
		m.groups[rgID].ReadinessReasons = nil
	}
	m.mu.Unlock()

	m.SetPeerFailoverBatchFunc(func(rgIDs []int) (uint64, error) {
		return 88, nil
	})
	m.SetLocalTransferCommitReadyHook(func(rgIDs []int) error {
		return fmt.Errorf("local activation not settled")
	})
	m.SetPeerFailoverCommitBatchFunc(func(rgIDs []int, reqID uint64) error {
		t.Fatal("peer failover batch commit should not run when local commit ready hook fails")
		return nil
	})

	err := m.RequestPeerFailoverBatch([]int{1, 2})
	if err == nil {
		t.Fatal("expected local commit ready error")
	}
	if !strings.Contains(err.Error(), "local activation not settled") {
		t.Fatalf("RequestPeerFailoverBatch() error = %v", err)
	}
	for _, rgID := range []int{1, 2} {
		if m.IsLocalPrimary(rgID) {
			t.Fatalf("local node should not remain primary for rg %d after abort", rgID)
		}
		if peer := m.PeerGroupStates()[rgID]; peer.State != StatePrimary {
			t.Fatalf("peer state for rg %d = %s, want primary after local commit ready abort", rgID, peer.State)
		}
	}
}

func TestRequestPeerFailoverRequiresLocalReadiness(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()
	m.mu.Lock()
	rg := m.groups[0]
	rg.Ready = false
	rg.ReadySince = time.Time{}
	rg.ReadinessReasons = []string{"userspace not ready"}
	m.mu.Unlock()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})

	called := false
	m.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		called = true
		return 0, nil
	})
	m.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error { return nil })

	err := m.RequestPeerFailover(0)
	if err == nil {
		t.Fatal("expected local readiness error")
	}
	if !strings.Contains(err.Error(), "not ready for explicit failover") {
		t.Fatalf("RequestPeerFailover() error = %v", err)
	}
	if called {
		t.Fatal("peer failover request should not be sent while local node is not ready")
	}
}

func TestRequestPeerFailoverRequiresLocalTransferReadiness(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	called := false
	m.SetTransferReadinessFunc(func(rgID int) (bool, []string) {
		return false, []string{"local bulk receive still in progress epoch=7 sessions=128"}
	})
	m.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		called = true
		return 0, nil
	})
	m.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error { return nil })

	err := m.RequestPeerFailover(0)
	if err == nil {
		t.Fatal("expected local transfer readiness error")
	}
	if !strings.Contains(err.Error(), "not transfer-ready for explicit failover") {
		t.Fatalf("RequestPeerFailover() error = %v", err)
	}
	if !strings.Contains(err.Error(), "local bulk receive still in progress epoch=7 sessions=128") {
		t.Fatalf("RequestPeerFailover() error = %v", err)
	}
	if called {
		t.Fatal("peer failover request should not be sent while transfer readiness is false")
	}
}

func TestRequestPeerFailoverTransferReadinessFailurePreservesManualFailover(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	state := m.GroupState(0)
	m.SetTransferReadinessFunc(func(rgID int) (bool, []string) {
		return false, []string{"session sync disconnected"}
	})
	m.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		t.Fatal("peer failover request should not be sent while transfer readiness is false")
		return 0, nil
	})
	m.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error {
		t.Fatal("peer failover commit should not run while transfer readiness is false")
		return nil
	})

	err := m.RequestPeerFailover(0)
	if err == nil {
		t.Fatal("expected local transfer readiness error")
	}
	state = m.GroupState(0)
	if !state.ManualFailover {
		t.Fatal("manual failover should remain set after transfer readiness rejection")
	}
	if state.State != StateSecondaryHold {
		t.Fatalf("state = %s, want secondary-hold", state.State)
	}
}

func TestRequestPeerFailoverPeerSendFailurePreservesManualFailover(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	state := m.GroupState(0)
	m.SetTransferReadinessFunc(func(rgID int) (bool, []string) {
		return true, nil
	})
	m.SetPeerFailoverFunc(func(rgID int) (uint64, error) {
		return 0, errors.New("peer sync write failed")
	})
	m.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error {
		t.Fatal("peer failover commit should not run when the request send fails")
		return nil
	})

	err := m.RequestPeerFailover(0)
	if err == nil {
		t.Fatal("expected peer failover send error")
	}
	state = m.GroupState(0)
	if !state.ManualFailover {
		t.Fatal("manual failover should remain set after peer request send failure")
	}
	if state.State != StateSecondaryHold {
		t.Fatalf("state = %s, want secondary-hold", state.State)
	}
}

func TestFinalizePeerTransferOutClearsSecondaryHold(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	<-m.Events()

	if err := m.FinalizePeerTransferOut(0); err != nil {
		t.Fatalf("FinalizePeerTransferOut() error = %v", err)
	}
	state := m.GroupState(0)
	if state.State != StateSecondary {
		t.Fatalf("state = %s, want secondary", state.State)
	}
	if state.ManualFailover {
		t.Fatal("ManualFailover should be cleared after peer commit")
	}
}

func TestFinalizePeerTransferOutBatchClearsSecondaryHold(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(1, true, map[int]int{0: 100}),
		makeRG(2, true, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()
	<-m.Events()

	if _, err := m.ManualFailoverBatch([]int{1, 2}); err != nil {
		t.Fatalf("ManualFailoverBatch() error = %v", err)
	}
	<-m.Events()
	<-m.Events()

	if err := m.FinalizePeerTransferOutBatch([]int{2, 1}); err != nil {
		t.Fatalf("FinalizePeerTransferOutBatch() error = %v", err)
	}
	for _, rgID := range []int{1, 2} {
		state := m.GroupState(rgID)
		if state.State != StateSecondary {
			t.Fatalf("rg %d state = %s, want secondary", rgID, state.State)
		}
		if state.ManualFailover {
			t.Fatalf("rg %d ManualFailover should be cleared after peer batch commit", rgID)
		}
	}
}

func TestPeerTransferOutOverrideSurvivesHeartbeatRefreshUntilCommit(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	if err := m.commitRequestedPeerFailover(0, 77); err != nil {
		t.Fatalf("commitRequestedPeerFailover() error = %v", err)
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("should be primary after local transfer commit")
	}

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})

	if !m.IsLocalPrimary(0) {
		t.Fatal("heartbeat refresh should not clobber in-flight transfer-out override")
	}
	if peer := m.PeerGroupStates()[0]; peer.State != StateSecondaryHold {
		t.Fatalf("peer state = %s, want secondary-hold while transfer commit in flight", peer.State)
	}
}

func TestNotePeerTransferCommittedPreservesPeerTransferOutDuringGrace(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	if err := m.commitRequestedPeerFailover(0, 77); err != nil {
		t.Fatalf("commitRequestedPeerFailover() error = %v", err)
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("should be primary after local transfer commit")
	}

	m.notePeerTransferCommitted(0)
	if peer := m.PeerGroupStates()[0]; peer.State != StateSecondaryHold {
		t.Fatalf("peer state = %s, want secondary-hold during post-commit grace", peer.State)
	}

	m.handlePeerHeartbeat(pkt)
	if !m.IsLocalPrimary(0) {
		t.Fatal("stale peer-primary heartbeat should not clobber committed ownership during grace")
	}
	if peer := m.PeerGroupStates()[0]; peer.State != StateSecondaryHold {
		t.Fatalf("peer state = %s, want secondary-hold during post-commit grace", peer.State)
	}

	m.mu.Lock()
	m.peerTransferCommitGraceUntil[0] = time.Now().Add(-time.Second)
	m.mu.Unlock()

	m.handlePeerHeartbeat(pkt)
	if m.IsLocalPrimary(0) {
		t.Fatal("should yield after post-commit grace expires and peer still advertises primary")
	}
}

func TestHandlePeerHeartbeatSkipsTransferOverridesForAbsentRG(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.mu.Lock()
	m.transferOverrides[0] = transferOverride{reqID: 77}
	m.peerTransferCommitGraceUntil[0] = time.Now().Add(time.Second)
	m.mu.Unlock()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups:    nil,
	})

	if got := len(m.PeerGroupStates()); got != 0 {
		t.Fatalf("peer groups = %d, want 0 when heartbeat omits overridden RG", got)
	}
}

func TestHandlePeerTimeoutSuppressedDuringRecentTransferCommitGrace(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = 1
	m.peerGroups = map[int]PeerGroupState{
		0: {GroupID: 0, Priority: 100, Weight: 255, State: StateSecondaryHold},
	}
	m.mu.Unlock()
	if err := m.FinalizePeerTransferOut(0); err != nil {
		t.Fatalf("FinalizePeerTransferOut() error = %v", err)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("should remain secondary immediately after peer transfer commit")
	}

	m.handlePeerTimeout()
	if !m.PeerAlive() {
		t.Fatal("peer should remain alive while recent transfer-commit grace is active")
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("old primary should stay secondary while transfer-commit grace is active")
	}

	m.mu.Lock()
	m.localTransferOutHoldUntil[0] = time.Now().Add(-time.Second)
	m.mu.Unlock()

	m.handlePeerTimeout()
	if m.PeerAlive() {
		t.Fatal("peer should be marked lost after transfer-commit grace expires")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("old primary should reclaim ownership after grace expires and peer times out")
	}
}

func TestFinalizePeerTransferOutClearsStaleInboundTransferGrace(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	if err := m.commitRequestedPeerFailover(0, 77); err != nil {
		t.Fatalf("commitRequestedPeerFailover() error = %v", err)
	}
	m.notePeerTransferCommitted(0)
	if !m.IsLocalPrimary(0) {
		t.Fatal("should be primary after local transfer commit")
	}

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	if err := m.FinalizePeerTransferOut(0); err != nil {
		t.Fatalf("FinalizePeerTransferOut() error = %v", err)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("should be secondary after peer transfer commit")
	}

	m.handlePeerHeartbeat(pkt)
	if m.IsLocalPrimary(0) {
		t.Fatal("stale inbound transfer grace should not re-promote the old primary after direction change")
	}
	if peer := m.PeerGroupStates()[0]; peer.State != StatePrimary {
		t.Fatalf("peer state = %s, want primary after direction change heartbeat", peer.State)
	}
}

func TestFinalizePeerTransferOutBatchClearsStaleInboundTransferGrace(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(1, true, map[int]int{0: 100}),
		makeRG(2, true, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()
	<-m.Events()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
			{GroupID: 2, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	m.mu.Lock()
	for _, rgID := range []int{1, 2} {
		m.groups[rgID].Ready = true
		m.groups[rgID].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
		m.groups[rgID].ReadinessReasons = nil
	}
	m.mu.Unlock()

	if err := m.commitRequestedPeerFailoverBatch([]int{1, 2}, 88); err != nil {
		t.Fatalf("commitRequestedPeerFailoverBatch() error = %v", err)
	}
	m.notePeerTransferCommittedBatch([]int{1, 2})
	if !m.IsLocalPrimary(1) || !m.IsLocalPrimary(2) {
		t.Fatal("both redundancy groups should be primary after local batch transfer commit")
	}

	if _, err := m.ManualFailoverBatch([]int{1, 2}); err != nil {
		t.Fatalf("ManualFailoverBatch() error = %v", err)
	}
	if err := m.FinalizePeerTransferOutBatch([]int{1, 2}); err != nil {
		t.Fatalf("FinalizePeerTransferOutBatch() error = %v", err)
	}
	if m.IsLocalPrimary(1) || m.IsLocalPrimary(2) {
		t.Fatal("both redundancy groups should be secondary after peer batch transfer commit")
	}

	m.handlePeerHeartbeat(pkt)
	if m.IsLocalPrimary(1) || m.IsLocalPrimary(2) {
		t.Fatal("stale inbound batch transfer grace should not re-promote the old primary after direction change")
	}
	for _, rgID := range []int{1, 2} {
		if peer := m.PeerGroupStates()[rgID]; peer.State != StatePrimary {
			t.Fatalf("peer state for rg %d = %s, want primary after direction change heartbeat", rgID, peer.State)
		}
	}
}

func TestFormatStatusShowsSeparateTransferReadiness(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()
	m.SetTransferReadinessFunc(func(rgID int) (bool, []string) {
		return false, []string{"peer still receiving outbound bulk epoch=7 age=25.7s"}
	})

	out := m.FormatStatus()
	if !strings.Contains(out, "Takeover ready: yes") {
		t.Fatalf("status missing takeover readiness: %s", out)
	}
	if !strings.Contains(out, "Transfer ready: no (peer still receiving outbound bulk epoch=7 age=25.7s)") {
		t.Fatalf("status missing transfer readiness: %s", out)
	}
}

func TestFormatStatusShowsSoftwareVersions(t *testing.T) {
	m := NewManager(0, 1)
	m.SetSoftwareVersion("local-build")
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:          1,
		ClusterID:       1,
		SoftwareVersion: "peer-build",
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})

	out := m.FormatStatus()
	if !strings.Contains(out, "Software version: local-build") {
		t.Fatalf("status missing local software version: %s", out)
	}
	if !strings.Contains(out, "HA protocol version: 1") {
		t.Fatalf("status missing local ha protocol version: %s", out)
	}
	if !strings.Contains(out, "Peer software version: peer-build") {
		t.Fatalf("status missing peer software version: %s", out)
	}
	if !strings.Contains(out, "Peer HA protocol version: 1") {
		t.Fatalf("status missing peer ha protocol version: %s", out)
	}
}

func TestFormatInformationShowsUnknownPeerSoftwareVersion(t *testing.T) {
	m := NewManager(0, 1)
	m.SetSoftwareVersion("local-build")
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})

	out := m.FormatInformation()
	if !strings.Contains(out, "Peer software version: unknown") {
		t.Fatalf("information missing unknown peer software version: %s", out)
	}
	if !strings.Contains(out, "HA protocol version: 1") {
		t.Fatalf("information missing local ha protocol version: %s", out)
	}
	if !strings.Contains(out, "Peer HA protocol version: 1") {
		t.Fatalf("information missing peer ha protocol version: %s", out)
	}
}

func TestHAProtocolVersionMismatchIgnoresUnknownPeerAfterTimeout(t *testing.T) {
	m := NewManager(0, 1)
	m.SetHAProtocolVersion(2)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100, 1: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:            1,
		ClusterID:         1,
		HAProtocolVersion: 2,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	})
	m.handlePeerTimeout()

	mismatch, local, peer := m.HAProtocolVersionMismatch()
	if mismatch {
		t.Fatalf("unexpected mismatch after peer timeout: local=%d peer=%d", local, peer)
	}
	if local != 2 || peer != 0 {
		t.Fatalf("unexpected versions after peer timeout: local=%d peer=%d", local, peer)
	}
}

func TestResetFailover(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	_, _ = m.ManualFailover(0)
	<-m.Events() // drain failover event

	if err := m.ResetFailover(0); err != nil {
		t.Fatal(err)
	}

	states := m.GroupStates()
	if states[0].ManualFailover {
		t.Error("ManualFailover should be cleared")
	}
	if states[0].State != StatePrimary {
		t.Errorf("state = %s, want primary after reset", states[0].State)
	}
	// Failover count should be preserved.
	if states[0].FailoverCount != 1 {
		t.Errorf("failover count = %d, want 1 (preserved)", states[0].FailoverCount)
	}
	// Weight must be restored to 255 (no monitor failures).
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 after reset", states[0].Weight)
	}
}

func TestResetFailover_UnknownRG(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.ResetFailover(99); err == nil {
		t.Error("expected error for unknown RG")
	}
}

func TestIsLocalPrimary(t *testing.T) {
	m := NewManager(0, 1)
	// Non-existent RG should return false.
	if m.IsLocalPrimary(0) {
		t.Error("should return false for non-existent RG")
	}

	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary after election")
	}
}

func TestGroupStates_Sorted(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(2, false, map[int]int{0: 100}),
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)

	states := m.GroupStates()
	if len(states) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(states))
	}
	for i, expected := range []int{0, 1, 2} {
		if states[i].GroupID != expected {
			t.Errorf("states[%d].GroupID = %d, want %d", i, states[i].GroupID, expected)
		}
	}
}

func TestGroupStates_Snapshot(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	states := m.GroupStates()
	// Modify returned state — should not affect internal state.
	states[0].LocalPriority = 999
	states2 := m.GroupStates()
	if states2[0].LocalPriority != 200 {
		t.Error("GroupStates should return snapshot, not reference")
	}
}

func TestGroupState_Single(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	rg := m.GroupState(0)
	if rg == nil {
		t.Fatal("GroupState(0) returned nil")
	}
	if rg.LocalPriority != 200 {
		t.Errorf("priority = %d, want 200", rg.LocalPriority)
	}

	if m.GroupState(99) != nil {
		t.Error("GroupState(99) should return nil")
	}
}

func TestNodeStateString(t *testing.T) {
	tests := []struct {
		state NodeState
		want  string
	}{
		{StateSecondary, "secondary"},
		{StatePrimary, "primary"},
		{StateSecondaryHold, "secondary-hold"},
		{StateLost, "lost"},
		{StateDisabled, "disabled"},
		{NodeState(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", int(tt.state), got, tt.want)
		}
	}
}

func TestFormatStatus(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)

	out := m.FormatStatus()
	if !strings.Contains(out, "Cluster ID: 1") {
		t.Error("missing cluster ID")
	}
	if !strings.Contains(out, "Node name: node0") {
		t.Error("missing node name")
	}
	if !strings.Contains(out, "Redundancy group: 0") {
		t.Error("missing RG 0")
	}
	if !strings.Contains(out, "Redundancy group: 1") {
		t.Error("missing RG 1")
	}
	if !strings.Contains(out, "primary") {
		t.Error("missing primary status")
	}
	if !strings.Contains(out, "200") {
		t.Error("missing priority 200")
	}
	if !strings.Contains(out, "yes") {
		t.Error("missing preempt yes")
	}
}

func TestFormatStatus_WithMonitorFails(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	m.SetMonitorWeight(0, "trust0", true, 50)
	m.SetMonitorWeight(0, "untrust0", true, 50)

	out := m.FormatStatus()
	if !strings.Contains(out, "trust0") {
		t.Error("missing failed monitor trust0")
	}
	if !strings.Contains(out, "untrust0") {
		t.Error("missing failed monitor untrust0")
	}
}

func TestMultipleMonitorWeights(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Three interfaces down with different weights.
	m.SetMonitorWeight(0, "trust0", true, 50)
	m.SetMonitorWeight(0, "untrust0", true, 75)
	m.SetMonitorWeight(0, "dmz0", true, 30)

	states := m.GroupStates()
	expectedWeight := 255 - 50 - 75 - 30 // = 100
	if states[0].Weight != expectedWeight {
		t.Errorf("weight = %d, want %d", states[0].Weight, expectedWeight)
	}

	// Recover one.
	m.SetMonitorWeight(0, "untrust0", false, 0)
	states = m.GroupStates()
	expectedWeight = 255 - 50 - 30 // = 175
	if states[0].Weight != expectedWeight {
		t.Errorf("weight after recovery = %d, want %d", states[0].Weight, expectedWeight)
	}
}

func TestMonitorFailsSorted(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	m.SetMonitorWeight(0, "untrust0", true, 50)
	m.SetMonitorWeight(0, "dmz0", true, 50)
	m.SetMonitorWeight(0, "trust0", true, 50)

	states := m.GroupStates()
	want := []string{"dmz0", "trust0", "untrust0"}
	if len(states[0].MonitorFails) != 3 {
		t.Fatalf("monitor fails count = %d, want 3", len(states[0].MonitorFails))
	}
	for i, name := range want {
		if states[0].MonitorFails[i] != name {
			t.Errorf("monitor fails[%d] = %s, want %s", i, states[0].MonitorFails[i], name)
		}
	}
}

func TestElectionSkipsDisabled(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Force state to disabled directly (simulating admin action).
	m.mu.Lock()
	m.groups[0].State = StateDisabled
	m.mu.Unlock()

	// Re-apply config — disabled state should be preserved by electSingleNode.
	m.UpdateConfig(cfg)
	states := m.GroupStates()
	if states[0].State != StateDisabled {
		t.Errorf("state = %s, want disabled (should be preserved)", states[0].State)
	}
}

func TestActiveActive_DifferentPrimariesPerRG(t *testing.T) {
	// Active/Active: RG 0 primary on node0, RG 1 primary on node1.
	// This validates that different RGs can have different primaries,
	// which is the core requirement for active/active mode.
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200, 1: 100}), // node0 higher for RG0
		makeRG(1, true, map[int]int{0: 100, 1: 200}), // node1 higher for RG1
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Peer heartbeat: node1 has RG0=secondary, RG1=primary.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Verify active/active: RG 0 primary here, RG 1 secondary here.
	if !m.IsLocalPrimary(0) {
		t.Error("RG 0: should be primary on node0 (active/active)")
	}
	if m.IsLocalPrimary(1) {
		t.Error("RG 1: should be secondary on node0 (active/active)")
	}

	// Verify peer states reflect the complementary configuration.
	peerStates := m.PeerGroupStates()
	if pg, ok := peerStates[0]; !ok || pg.State != StateSecondary {
		t.Errorf("peer RG 0: expected secondary, got %v", peerStates[0])
	}
	if pg, ok := peerStates[1]; !ok || pg.State != StatePrimary {
		t.Errorf("peer RG 1: expected primary, got %v", peerStates[1])
	}
}

func TestForceSecondary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Simulate peer alive.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Both RGs should be primary.
	if !m.IsLocalPrimary(0) || !m.IsLocalPrimary(1) {
		t.Fatal("both RGs should be primary before ForceSecondary")
	}

	// ForceSecondary.
	if err := m.ForceSecondary(); err != nil {
		t.Fatal(err)
	}

	// Both should now be secondary.
	states := m.GroupStates()
	for _, rg := range states {
		if rg.State != StateSecondary {
			t.Errorf("RG %d: state = %s, want secondary after ForceSecondary", rg.GroupID, rg.State)
		}
		if rg.Weight != 0 {
			t.Errorf("RG %d: weight = %d, want 0 after ForceSecondary", rg.GroupID, rg.Weight)
		}
		if !rg.ManualFailover {
			t.Errorf("RG %d: ManualFailover should be true after ForceSecondary", rg.GroupID)
		}
	}

	// Drain the failover events.
	drainEvents(m, 2)
}

func TestForceSecondary_NoPeer(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	// No peer — should fail.
	if err := m.ForceSecondary(); err == nil {
		t.Error("ForceSecondary should fail without active peer")
	}
}

func TestForceSecondary_SkipsDisabled(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Simulate peer alive.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Disable RG 1.
	m.mu.Lock()
	m.groups[1].State = StateDisabled
	m.mu.Unlock()

	if err := m.ForceSecondary(); err != nil {
		t.Fatal(err)
	}

	states := m.GroupStates()
	// RG 0: should be secondary.
	if states[0].State != StateSecondary {
		t.Errorf("RG 0: state = %s, want secondary", states[0].State)
	}
	// RG 1: should remain disabled.
	if states[1].State != StateDisabled {
		t.Errorf("RG 1: state = %s, want disabled (should be preserved)", states[1].State)
	}
}

func TestLocalPriorities_Empty(t *testing.T) {
	m := NewManager(0, 1)
	prios := m.LocalPriorities()
	if len(prios) != 0 {
		t.Fatalf("expected empty map, got %v", prios)
	}
}

func TestLocalPriorities_PrimaryGets200(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Both primary in single-node mode.
	prios := m.LocalPriorities()
	if len(prios) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(prios))
	}
	if prios[0] != 200 {
		t.Errorf("RG 0 priority = %d, want 200 (primary)", prios[0])
	}
	if prios[1] != 200 {
		t.Errorf("RG 1 priority = %d, want 200 (primary)", prios[1])
	}
}

func TestLocalPriorities_SecondaryGets100(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Manually failover RG 1 → secondary.
	_, _ = m.ManualFailover(1)
	drainEvents(m, 1)

	prios := m.LocalPriorities()
	if prios[0] != 200 {
		t.Errorf("RG 0 priority = %d, want 200 (still primary)", prios[0])
	}
	if prios[1] != 100 {
		t.Errorf("RG 1 priority = %d, want 100 (secondary after failover)", prios[1])
	}
}

func TestLocalPriorities_ActiveActive(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200, 1: 100}),
		makeRG(1, true, map[int]int{0: 100, 1: 200}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Peer heartbeat: node1 primary for RG1, secondary for RG0.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	prios := m.LocalPriorities()
	if prios[0] != 200 {
		t.Errorf("RG 0 priority = %d, want 200 (primary on node0)", prios[0])
	}
	if prios[1] != 100 {
		t.Errorf("RG 1 priority = %d, want 100 (secondary on node0)", prios[1])
	}
}

func TestEventsChannel(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)

	// Should have 2 events (both RGs elected to primary).
	for i := 0; i < 2; i++ {
		select {
		case ev := <-m.Events():
			if ev.NewState != StatePrimary {
				t.Errorf("event %d: new state = %s, want primary", i, ev.NewState)
			}
		default:
			t.Errorf("expected event %d", i)
		}
	}

	// No more events.
	select {
	case ev := <-m.Events():
		t.Errorf("unexpected extra event: %+v", ev)
	default:
	}
}

func TestIsLocalPrimaryAny(t *testing.T) {
	m := NewManager(0, 1)

	// No groups configured yet — should return false.
	if m.IsLocalPrimaryAny() {
		t.Fatal("should not be primary with no groups")
	}

	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
		makeRG(1, false, map[int]int{0: 100, 1: 200}),
	)
	m.UpdateConfig(cfg)

	// After UpdateConfig with single-node election, all groups become primary.
	if !m.IsLocalPrimaryAny() {
		t.Fatal("should be primary for at least one RG after single-node election")
	}

	// Manually set both to secondary
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.groups[1].State = StateSecondary
	m.mu.Unlock()

	if m.IsLocalPrimaryAny() {
		t.Fatal("should not be primary when all RGs are secondary")
	}

	// Make only RG 0 primary
	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	if !m.IsLocalPrimaryAny() {
		t.Fatal("should be primary for at least one RG")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("should be primary for RG 0")
	}
	if m.IsLocalPrimary(1) {
		t.Fatal("should not be primary for RG 1")
	}
}

func TestActiveActiveElection(t *testing.T) {
	// Simulate active/active: node 0 has higher priority for RG 0,
	// node 1 has higher priority for RG 1.
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200, 1: 100}),
		makeRG(1, true, map[int]int{0: 100, 1: 200}),
	)
	m.UpdateConfig(cfg)

	// Manually set states to simulate election result.
	m.mu.Lock()
	m.groups[0].State = StatePrimary   // node 0 wins RG 0
	m.groups[1].State = StateSecondary // node 1 wins RG 1
	m.mu.Unlock()

	if !m.IsLocalPrimary(0) {
		t.Fatal("node 0 should be primary for RG 0")
	}
	if m.IsLocalPrimary(1) {
		t.Fatal("node 0 should be secondary for RG 1")
	}
	if !m.IsLocalPrimaryAny() {
		t.Fatal("node 0 is primary for RG 0 — IsLocalPrimaryAny should be true")
	}
}

func TestHandlePeerTimeout_FencingDisableRG(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	cfg.PeerFencing = "disable-rg"
	m.UpdateConfig(cfg)

	// Simulate peer alive.
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.mu.Unlock()

	// Track fence calls.
	fenceCalled := false
	m.SetPeerFenceFunc(func() error {
		fenceCalled = true
		return nil
	})

	m.handlePeerTimeout()

	if !fenceCalled {
		t.Error("expected fence function to be called on peer timeout with disable-rg")
	}

	// Verify fence event was recorded.
	events := m.EventHistoryFor(EventFence)
	if len(events) == 0 {
		t.Error("expected fence event in history")
	} else if !strings.Contains(events[0].Message, "sent to peer") {
		t.Errorf("fence event message = %q, want 'sent to peer'", events[0].Message)
	}

	// Drain election event.
	select {
	case <-m.Events():
	default:
	}
}

func TestHandlePeerTimeout_FencingDisabled(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	// No PeerFencing configured (default empty).
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.mu.Unlock()

	fenceCalled := false
	m.SetPeerFenceFunc(func() error {
		fenceCalled = true
		return nil
	})

	m.handlePeerTimeout()

	if fenceCalled {
		t.Error("fence function should NOT be called when fencing is not configured")
	}

	// No fence events.
	events := m.EventHistoryFor(EventFence)
	if len(events) != 0 {
		t.Errorf("expected 0 fence events, got %d", len(events))
	}

	select {
	case <-m.Events():
	default:
	}
}

func TestHandlePeerTimeout_SuppressedByGuard(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = 1
	m.peerGroups = map[int]PeerGroupState{
		0: {GroupID: 0, Priority: 100, Weight: 255, State: StatePrimary},
	}
	m.mu.Unlock()

	called := false
	m.SetPeerTimeoutGuard(func() (bool, string) {
		called = true
		return true, "recent control-link sync activity"
	})

	m.handlePeerTimeout()

	if !called {
		t.Fatal("peer timeout guard was not called")
	}
	if !m.PeerAlive() {
		t.Fatal("peer should remain alive when timeout is suppressed")
	}
	if got := len(m.PeerGroupStates()); got != 1 {
		t.Fatalf("peer groups = %d, want 1 after suppressed timeout", got)
	}
}

func TestHandlePeerTimeout_FencingNoSyncFunc(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	cfg.PeerFencing = "disable-rg"
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.mu.Unlock()

	// No fence function set (simulates sync not available).
	m.handlePeerTimeout()

	// Verify fence event records that sync was not available.
	events := m.EventHistoryFor(EventFence)
	if len(events) == 0 {
		t.Error("expected fence event in history")
	} else if !strings.Contains(events[0].Message, "sync not available") {
		t.Errorf("fence event message = %q, want 'sync not available'", events[0].Message)
	}

	select {
	case <-m.Events():
	default:
	}
}

func TestHandlePeerTimeout_FencingSendError(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	cfg.PeerFencing = "disable-rg"
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.mu.Unlock()

	m.SetPeerFenceFunc(func() error {
		return fmt.Errorf("connection refused")
	})

	m.handlePeerTimeout()

	events := m.EventHistoryFor(EventFence)
	if len(events) == 0 {
		t.Error("expected fence event in history")
	} else if !strings.Contains(events[0].Message, "Fence failed") {
		t.Errorf("fence event message = %q, want 'Fence failed'", events[0].Message)
	}

	select {
	case <-m.Events():
	default:
	}
}

func TestFenceStatus(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	cfg.PeerFencing = "disable-rg"
	m.UpdateConfig(cfg)

	action, events := m.FenceStatus()
	if action != "disable-rg" {
		t.Errorf("FenceStatus action = %q, want %q", action, "disable-rg")
	}
	if len(events) != 0 {
		t.Errorf("expected 0 fence events initially, got %d", len(events))
	}

	// Simulate a fence event.
	m.history.Record(EventFence, -1, "test fence event")
	_, events = m.FenceStatus()
	if len(events) != 1 {
		t.Errorf("expected 1 fence event, got %d", len(events))
	}
}
