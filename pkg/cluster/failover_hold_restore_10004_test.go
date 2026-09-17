package cluster

import (
	"fmt"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #10004: RequestPeerFailover(RequestPeerFailoverBatch) clears the local
// manual-failover hold BEFORE the transfer commit, and the abort arms never
// re-armed it. A failed transfer therefore silently consumed the operator's
// intent: the node no longer held, with no record the hold died by failure
// rather than success.
//
// The property under test is the AGREEMENT between every failure arm — the
// three targeted arms (local commit, local-commit-ready, peer commit) and the
// three batch arms — plus the two promises that must NOT change: success
// still consumes the hold exactly once, and preflight/send failures (which
// return before the clear) still preserve it.
//
// FAIL-ON-REVERT: drop the restore from any abort arm and its cell reds with
// ManualFailover=false after a failed transfer.

// holdFixture10004 builds a secondary manager with the peer primary and every
// listed RG takeover-ready, following the TestRequestPeerFailover recipe.
func holdFixture10004(t *testing.T, rgIDs ...int) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	groups := make([]HeartbeatGroup, 0, len(rgIDs))
	configGroups := make([]*config.RedundancyGroup, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		groups = append(groups, HeartbeatGroup{
			GroupID: uint8(rgID), Priority: 200, Weight: 255, State: uint8(StatePrimary),
		})
		configGroups = append(configGroups, makeRG(rgID, true, map[int]int{0: 100}))
	}
	m.UpdateConfig(makeConfig(configGroups...))
	drainHoldEvents10004(m)
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 1, ClusterID: 1, Groups: groups})
	m.mu.Lock()
	for _, rgID := range rgIDs {
		m.groups[rgID].Ready = true
		m.groups[rgID].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
		m.groups[rgID].ReadinessReasons = nil
	}
	m.mu.Unlock()
	drainHoldEvents10004(m)
	for _, rgID := range rgIDs {
		if m.IsLocalPrimary(rgID) {
			t.Fatalf("fixture: rg %d should be secondary before failover", rgID)
		}
	}
	return m
}

func armHold10004(t *testing.T, m *Manager, rgID int) time.Time {
	t.Helper()
	if _, err := m.ManualFailover(rgID); err != nil {
		t.Fatalf("fixture: ManualFailover(%d): %v", rgID, err)
	}
	drainHoldEvents10004(m)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.groups[rgID].ManualFailover {
		t.Fatalf("fixture: rg %d hold not armed", rgID)
	}
	return m.groups[rgID].ManualFailoverAt
}

func assertHoldRestored10004(t *testing.T, m *Manager, rgID int, wantAt time.Time) {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg := m.groups[rgID]
	if !rg.ManualFailover {
		t.Errorf("rg %d: ManualFailover=false after failed transfer — the failure silently consumed the operator's hold (#10004)", rgID)
	}
	if !rg.ManualFailoverAt.Equal(wantAt) {
		t.Errorf("rg %d: ManualFailoverAt=%v after failed transfer, want %v (the preexisting hold timestamp must survive)", rgID, rg.ManualFailoverAt, wantAt)
	}
	if rg.State != StateSecondaryHold {
		t.Errorf("rg %d: State=%s after failed transfer, want secondary-hold (the held state must be restored with the flag)", rgID, rg.State)
	}
}

func assertHoldConsumed10004(t *testing.T, m *Manager, rgID int) {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg := m.groups[rgID]
	if rg.ManualFailover {
		t.Errorf("rg %d: ManualFailover still set after successful transfer — success must consume the hold exactly once", rgID)
	}
	if !rg.ManualFailoverAt.IsZero() {
		t.Errorf("rg %d: ManualFailoverAt=%v after successful transfer, want zero", rgID, rg.ManualFailoverAt)
	}
}

func drainHoldEvents10004(m *Manager) {
	for {
		select {
		case <-m.Events():
		default:
			return
		}
	}
}

// --- targeted arms ---

func TestRequestPeerFailoverCommitFailureRestoresHold10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	wantAt := armHold10004(t, m, 0)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		t.Error("local transfer-commit-ready hook must not run after the commit lost readiness")
		return nil
	})
	m.SetPeerFailoverFunc(func(int) (uint64, error) {
		// Takeover readiness lapses while the request is on the wire — the
		// commit re-check fails before any override is armed.
		m.mu.Lock()
		m.groups[0].Ready = false
		m.mu.Unlock()
		return 1001, nil
	})
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not be sent after the local commit failed")
		return nil
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected the transfer commit to fail on lapsed readiness")
	}
	assertHoldRestored10004(t, m, 0, wantAt)
}

func TestRequestPeerFailoverLocalCommitReadyFailureRestoresHold10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	wantAt := armHold10004(t, m, 0)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 1002, nil })
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not be sent after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected local-commit-ready failure")
	}
	assertHoldRestored10004(t, m, 0, wantAt)
	if m.IsLocalPrimary(0) {
		t.Error("local node must roll back out of primary after local-commit-ready failed")
	}
	if got := m.PeerGroupStates()[0].State; got != StatePrimary {
		t.Errorf("peer state = %s after rollback, want primary", got)
	}
}

func TestRequestPeerFailoverPeerCommitFailureRestoresHold10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	wantAt := armHold10004(t, m, 0)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 1003, nil })
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		return fmt.Errorf("commit frame lost")
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected peer-commit failure")
	}
	assertHoldRestored10004(t, m, 0, wantAt)
	if m.IsLocalPrimary(0) {
		t.Error("local node must roll back out of primary after peer-commit failed")
	}
}

func TestRequestPeerFailoverForceSecondaryHoldRestoresWeight10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	if err := m.ForceSecondary(); err != nil {
		t.Fatalf("fixture: ForceSecondary(): %v", err)
	}
	m.mu.RLock()
	wantAt := m.groups[0].ManualFailoverAt
	m.mu.RUnlock()

	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 1008, nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not run after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected local-commit-ready failure")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg := m.groups[0]
	if !rg.ManualFailover || !rg.ManualFailoverAt.Equal(wantAt) {
		t.Fatalf("ForceSecondary hold after abort = held=%t at=%v, want held at=%v",
			rg.ManualFailover, rg.ManualFailoverAt, wantAt)
	}
	if rg.State != StateSecondary || rg.Weight != 0 {
		t.Fatalf("ForceSecondary hold after abort = state %s weight %d, want secondary/0",
			rg.State, rg.Weight)
	}
}

func TestRequestPeerFailoverManualHoldKeepsInFlightMonitorWeight10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	wantAt := armHold10004(t, m, 0)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 1009, nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		// This monitor debt lands after the request clears the hold. The abort
		// must restore only the hold fields, not the newer debt-derived weight.
		m.SetMonitorWeight(0, "ge-0/0/9", true, 100)
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not run after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected local-commit-ready failure")
	}
	assertHoldRestored10004(t, m, 0, wantAt)
	m.mu.RLock()
	gotWeight := m.groups[0].Weight
	m.mu.RUnlock()
	if gotWeight != 155 {
		t.Fatalf("weight after failed transfer = %d, want 155 after monitor debt", gotWeight)
	}
}

// --- batch arms ---

func TestRequestPeerFailoverBatchCommitFailureRestoresHold10004(t *testing.T) {
	m := holdFixture10004(t, 1, 2)
	// Partial hold: only RG1 held. RG2 must be left untouched.
	wantAt := armHold10004(t, m, 1)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		t.Error("local transfer-commit-ready hook must not run after the batch commit failed")
		return nil
	})
	m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) {
		m.mu.Lock()
		m.groups[1].Ready = false
		m.mu.Unlock()
		return 2001, nil
	})
	m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error {
		t.Error("peer batch transfer-commit must not be sent after the local batch commit failed")
		return nil
	})

	if err := m.RequestPeerFailoverBatch([]int{1, 2}); err == nil {
		t.Fatal("expected the batch transfer commit to fail on lapsed readiness")
	}
	assertHoldRestored10004(t, m, 1, wantAt)
	m.mu.RLock()
	held2 := m.groups[2].ManualFailover
	m.mu.RUnlock()
	if held2 {
		t.Error("rg 2 was never held — the abort must not arm a hold this request did not clear")
	}
}

func TestRequestPeerFailoverBatchLocalCommitReadyFailureRestoresHold10004(t *testing.T) {
	m := holdFixture10004(t, 1, 2)
	wantAt1 := armHold10004(t, m, 1)
	wantAt2 := armHold10004(t, m, 2)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) { return 2002, nil })
	m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error {
		t.Error("peer batch transfer-commit must not be sent after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailoverBatch([]int{2, 1}); err == nil {
		t.Fatal("expected batch local-commit-ready failure")
	}
	assertHoldRestored10004(t, m, 1, wantAt1)
	assertHoldRestored10004(t, m, 2, wantAt2)
}

func TestRequestPeerFailoverBatchPeerCommitFailureRestoresHold10004(t *testing.T) {
	m := holdFixture10004(t, 1, 2)
	wantAt1 := armHold10004(t, m, 1)
	wantAt2 := armHold10004(t, m, 2)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) { return 2003, nil })
	m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error {
		return fmt.Errorf("commit frame lost")
	})

	if err := m.RequestPeerFailoverBatch([]int{1, 2}); err == nil {
		t.Fatal("expected batch peer-commit failure")
	}
	assertHoldRestored10004(t, m, 1, wantAt1)
	assertHoldRestored10004(t, m, 2, wantAt2)
}

// --- unchanged promises: success consumes, preflight/send preserve ---

func TestRequestPeerFailoverSuccessConsumesHold10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	armHold10004(t, m, 0)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 1004, nil })
	m.SetPeerFailoverCommitFunc(func(int, uint64) error { return nil })

	if err := m.RequestPeerFailover(0); err != nil {
		t.Fatalf("RequestPeerFailover() error = %v", err)
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("should be primary after explicit transfer commit")
	}
	assertHoldConsumed10004(t, m, 0)
}

func TestRequestPeerFailoverBatchSuccessConsumesHold10004(t *testing.T) {
	m := holdFixture10004(t, 1, 2)
	armHold10004(t, m, 1)
	armHold10004(t, m, 2)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) { return 2004, nil })
	m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error { return nil })

	if err := m.RequestPeerFailoverBatch([]int{1, 2}); err != nil {
		t.Fatalf("RequestPeerFailoverBatch() error = %v", err)
	}
	if !m.IsLocalPrimary(1) || !m.IsLocalPrimary(2) {
		t.Fatal("both RGs should be primary after explicit batch transfer commit")
	}
	assertHoldConsumed10004(t, m, 1)
	assertHoldConsumed10004(t, m, 2)
}

func TestRequestPeerFailoverPreflightAndSendPreserveHold10004(t *testing.T) {
	t.Run("preflight", func(t *testing.T) {
		m := holdFixture10004(t, 0)
		wantAt := armHold10004(t, m, 0)
		m.SetTransferReadinessFunc(func(int) (bool, []string) { return false, []string{"not-ready"} })
		m.SetPeerFailoverFunc(func(int) (uint64, error) {
			t.Error("request must not be sent after preflight rejection")
			return 0, nil
		})
		m.SetPeerFailoverCommitFunc(func(int, uint64) error { return nil })

		if err := m.RequestPeerFailover(0); err == nil {
			t.Fatal("expected preflight rejection")
		}
		assertHoldRestored10004(t, m, 0, wantAt)
	})
	t.Run("send", func(t *testing.T) {
		m := holdFixture10004(t, 0)
		wantAt := armHold10004(t, m, 0)
		m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
		m.SetPeerFailoverFunc(func(int) (uint64, error) { return 0, fmt.Errorf("fabric down") })
		m.SetPeerFailoverCommitFunc(func(int, uint64) error { return nil })

		if err := m.RequestPeerFailover(0); err == nil {
			t.Fatal("expected request-send failure")
		}
		assertHoldRestored10004(t, m, 0, wantAt)
	})
}

func TestRequestPeerFailoverBatchPreflightAndSendPreserveHold10004(t *testing.T) {
	t.Run("preflight", func(t *testing.T) {
		m := holdFixture10004(t, 1, 2)
		wantAt := armHold10004(t, m, 1)
		m.SetTransferReadinessFunc(func(int) (bool, []string) { return false, []string{"not-ready"} })
		m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) {
			t.Error("batch request must not be sent after preflight rejection")
			return 0, nil
		})
		m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error { return nil })

		if err := m.RequestPeerFailoverBatch([]int{1, 2}); err == nil {
			t.Fatal("expected batch preflight rejection")
		}
		assertHoldRestored10004(t, m, 1, wantAt)
	})
	t.Run("send", func(t *testing.T) {
		m := holdFixture10004(t, 1, 2)
		wantAt := armHold10004(t, m, 2)
		m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
		m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) { return 0, fmt.Errorf("fabric down") })
		m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error { return nil })

		if err := m.RequestPeerFailoverBatch([]int{1, 2}); err == nil {
			t.Fatal("expected batch request-send failure")
		}
		assertHoldRestored10004(t, m, 2, wantAt)
	})
}

// Peer-transfer requests share the per-RG failover ownership guard. A later
// request or manual hold cannot race an earlier request's abort and resurrect
// a stale timestamp after the later operation has completed.
func TestRequestPeerFailoverSerializesHoldOwner10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	wantAt := armHold10004(t, m, 0)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })

	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	m.SetPeerFailoverFunc(func(int) (uint64, error) {
		close(requestStarted)
		<-releaseRequest
		return 1006, nil
	})
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not run after local-commit-ready failed")
		return nil
	})
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		return fmt.Errorf("dataplane not settled")
	})

	firstErr := make(chan error, 1)
	go func() { firstErr <- m.RequestPeerFailover(0) }()
	<-requestStarted

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("overlapping peer failover request must be rejected while the first owns the RG")
	}
	if _, err := m.ManualFailover(0); err == nil {
		t.Fatal("manual failover must be rejected while the peer failover owns the RG")
	}

	close(releaseRequest)
	if err := <-firstErr; err == nil {
		t.Fatal("expected the first peer failover to fail its local-commit-ready check")
	}
	assertHoldRestored10004(t, m, 0, wantAt)
}

// ForceSecondary is a separate operator path that can install a newer hold
// while a peer transfer is in its post-commit hook. The abort must leave that
// newer hold untouched instead of restoring the stale request snapshot.
func TestRequestPeerFailoverForceSecondaryDuringTransferWins10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	wantAt := armHold10004(t, m, 0)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })

	var forcedAt time.Time
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		if err := m.ForceSecondary(); err != nil {
			t.Fatalf("ForceSecondary during transfer: %v", err)
		}
		m.mu.RLock()
		forcedAt = m.groups[0].ManualFailoverAt
		m.mu.RUnlock()
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 1007, nil })
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not run after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected local-commit-ready failure")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg := m.groups[0]
	if !rg.ManualFailover {
		t.Fatal("ForceSecondary hold was cleared by the failed transfer abort")
	}
	if !rg.ManualFailoverAt.Equal(forcedAt) || rg.ManualFailoverAt.Equal(wantAt) {
		t.Fatalf("ManualFailoverAt=%v after abort, want newer ForceSecondary timestamp %v (not stale %v)",
			rg.ManualFailoverAt, forcedAt, wantAt)
	}
	if rg.State != StateSecondary || rg.Weight != 0 {
		t.Fatalf("ForceSecondary state after abort = state %s weight %d, want secondary/0", rg.State, rg.Weight)
	}
}

// A ResetFailover that lands after this request cleared the hold is newer
// operator intent: the abort must NOT resurrect the stale hold over it (#5246
// reset-wins, applied to the request path).
func TestRequestPeerFailoverResetDuringTransferWins10004(t *testing.T) {
	m := holdFixture10004(t, 0)
	armHold10004(t, m, 0)
	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		// Operator resets while the transfer is committed locally but not
		// yet sent to the peer; the hook then fails and the abort runs.
		if err := m.ResetFailover(0); err != nil {
			t.Fatalf("ResetFailover during transfer: %v", err)
		}
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 1005, nil })
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not be sent after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected local-commit-ready failure")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.groups[0].ManualFailover {
		t.Error("a ResetFailover that won during the transfer must not be clobbered by abort-time hold restore (#5246)")
	}
}
