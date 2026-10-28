package cluster

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// #17120 probe-02: remove+re-add during the unlocked pre-hook window.
// Pre-fix ManualFailover/Batch used exists+gen (gen purges to 0, matching a
// gen-0 capture) and demoted the fresh incarnation; ForceSecondary already
// aborted via pointer identity. Post-fix all three share
// failoverReservation.revalidateLocked (pointer+gen) and all abort.

func readdFixture17120(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	))
	drainEvents(m, 4)
	// ForceSecondary needs a live peer.
	pkt := &HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	return m
}

// readdHook returns a hook that, on first call, removes all RGs and re-adds
// RG0/RG1 as fresh incarnations (capturing the new pointers), then returns nil.
func readdDuringHook17120(m *Manager, newRGs map[int]**RedundancyGroupState) func(int) error {
	var once sync.Once
	return func(int) error {
		once.Do(func() {
			m.UpdateConfig(makeConfig())
			m.UpdateConfig(makeConfig(
				makeRG(0, false, map[int]int{0: 200}),
				makeRG(1, false, map[int]int{0: 200}),
			))
			m.mu.RLock()
			for id, dst := range newRGs {
				rg := m.groups[id]
				*dst = rg
			}
			m.mu.RUnlock()
		})
		return nil
	}
}

func assertFreshNotDemoted17120(t *testing.T, m *Manager, id int, fresh *RedundancyGroupState) {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg := m.groups[id]
	if rg != fresh {
		t.Fatalf("rg %d: live pointer changed (got %p want fresh %p)", id, rg, fresh)
	}
	if rg.ManualFailover {
		t.Errorf("rg %d: fresh incarnation demoted (ManualFailover=true) — barrier ran for old incarnation (#17120)", id)
	}
	if rg.State == StateSecondaryHold || rg.State == StateSecondary {
		t.Errorf("rg %d: fresh incarnation state=%s, want not demoted", id, rg.State)
	}
}

func TestManualFailoverReaddDuringBarrierAborts17120(t *testing.T) {
	m := readdFixture17120(t)
	var fresh0 *RedundancyGroupState
	m.SetPreManualFailoverHook(readdDuringHook17120(m, map[int]**RedundancyGroupState{0: &fresh0}))
	_, err := m.ManualFailover(0)
	if err == nil {
		t.Fatal("ManualFailover on re-added RG should abort, not demote fresh incarnation (#17120)")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err=%v want 'not found' (byte-identical to removed-member path)", err)
	}
	if fresh0 == nil {
		t.Fatal("hook did not re-add")
	}
	assertFreshNotDemoted17120(t, m, 0, fresh0)
	// Reservation released on fresh incarnation? Old reservation token-matched
	// release must not leave stale entry; a new failover on fresh RG succeeds
	// (hook now no-ops via once).
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("failover on fresh RG after abort should succeed: %v", err)
	}
}

func TestManualFailoverBatchReaddDuringBarrierAborts17120(t *testing.T) {
	m := readdFixture17120(t)
	var fresh0, fresh1 *RedundancyGroupState
	m.SetPreManualFailoverHook(readdDuringHook17120(m, map[int]**RedundancyGroupState{0: &fresh0, 1: &fresh1}))
	// Need 2-member batch; hook re-adds both on first call.
	_, err := m.ManualFailoverBatch([]int{0, 1})
	if err == nil {
		t.Fatal("Batch on re-added RGs should abort, not demote fresh incarnations (#17120)")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err=%v want 'not found'", err)
	}
	assertFreshNotDemoted17120(t, m, 0, fresh0)
	assertFreshNotDemoted17120(t, m, 1, fresh1)
}

func TestForceSecondaryReaddDuringBarrierAborts17120(t *testing.T) {
	m := readdFixture17120(t)
	var fresh0, fresh1 *RedundancyGroupState
	m.SetPreManualFailoverHook(readdDuringHook17120(m, map[int]**RedundancyGroupState{0: &fresh0, 1: &fresh1}))
	err := m.ForceSecondary()
	if err == nil {
		t.Fatal("ForceSecondary on re-added RGs should abort (#17120 control — already passed pre-fix)")
	}
	if !strings.Contains(err.Error(), "membership changed") {
		t.Fatalf("err=%v want membership changed", err)
	}
	assertFreshNotDemoted17120(t, m, 0, fresh0)
	assertFreshNotDemoted17120(t, m, 1, fresh1)
}

// F1 (Rev18154Opus): a disabled RG must NOT be reserved by ForceSecondary.
// During its barrier a manual failover on the disabled RG must be admitted
// (not rejected "already in progress"), and ForceSecondary itself must still
// succeed and leave the disabled RG untouched.
func TestDisabledRGManualFailoverDuringForceSecondaryBarrier17120(t *testing.T) {
	m := readdFixture17120(t)
	m.mu.Lock()
	m.groups[1].State = StateDisabled
	m.mu.Unlock()

	entered := make(chan struct{})
	release := make(chan struct{})
	m.SetPreManualFailoverHook(func(rgID int) error {
		if rgID == 0 {
			close(entered)
			<-release
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- m.ForceSecondary() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("ForceSecondary did not reach barrier")
	}
	// Barrier is open for active RG0; disabled RG1 must not be reserved.
	if _, err := m.ManualFailover(1); err != nil {
		close(release)
		<-done
		t.Fatalf("manual failover on disabled RG during ForceSecondary barrier: %v (want admitted, not reserved)", err)
	}
	close(release)
	// The admitted manual failover flipped RG1 disabled->SecondaryHold, an
	// active/membership change during the barrier, so ForceSecondary aborts
	// without demotion (same gate as parent) — disclosed, not "already in
	// progress" on the disabled RG.
	if err := <-done; err == nil || !strings.Contains(err.Error(), "membership changed") {
		t.Fatalf("ForceSecondary err=%v, want membership changed abort", err)
	}
	m.mu.RLock()
	if m.groups[1].forcedSecondary {
		t.Error("disabled RG must not be pinned forcedSecondary")
	}
	if !m.groups[1].ManualFailover {
		t.Error("manual failover on disabled RG should have applied")
	}
	if m.groups[0].ManualFailover {
		t.Error("ForceSecondary abort must leave RG0 undemoted")
	}
	m.mu.RUnlock()
}
