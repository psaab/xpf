package cluster

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// #10244: failover-hold restore is not bound to the RG incarnation, and
// reservation cleanup is not bound to the requesting request.
//
// UpdateConfig holds m.mu but never reads failoverInProgress, so a
// remove+re-add (two commits) can land while a RequestPeerFailover(Batch)
// sits unlocked in its hooks. The purge deletes failoverGen /
// failoverInProgress / the RG object, and the re-add allocates a FRESH
// RedundancyGroupState (ManualFailover=false, gen 0). An in-flight gen-0
// snapshot then passes every restore gate (0==0, groups[rgID] exists, flag
// false) and the abort installs the OLD incarnation's hold/At/state/weight
// on the NEW RG. Independently, the old request's deferred unconditional
// delete(failoverInProgress, rgID) can wipe a NEW request's reservation
// taken after the re-add.
//
// Two independent fail-on-revert regressions (one per mechanism — a combined
// test that fails first on stale state would not prove the identity-bound
// cleanup):
//
//   - stale hold restore (targeted + batch): remove+re-add inside the
//     local-commit-ready hook, fail the hook, assert the fresh RG has no
//     hold and the old timestamp is absent.
//   - reservation wipe (targeted): remove+re-add inside the hook, reserve a
//     new request after the re-add and block it in send, let the old request
//     return and run its defer, assert the new reservation remains and an
//     overlapping request is still rejected.
//
// FAIL-ON-REVERT (stale restore): drop the incarnation guard from
// restoreManualFailoverHoldLocked and the fresh RG comes back held at the
// old timestamp in SecondaryHold.
// FAIL-ON-REVERT (reservation): drop the delete-only-if-match guard and the
// old defer wipes the new token, so the overlapping probe is admitted.

func TestRequestPeerFailoverReaddSkipsStaleHoldRestore10244(t *testing.T) {
	m := holdFixture10004(t, 0)
	wantAt := armHold10004(t, m, 0)

	m.mu.RLock()
	oldRG := m.groups[0]
	m.mu.RUnlock()

	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 3001, nil })
	var newRG *RedundancyGroupState
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		// Two config commits land while the request sits unlocked here:
		// the purge drops the RG object + generation, the re-add allocates
		// a fresh incarnation the in-flight snapshot must not touch.
		m.UpdateConfig(makeConfig())
		m.UpdateConfig(makeConfig(makeRG(0, true, map[int]int{0: 100})))
		m.mu.Lock()
		newRG = m.groups[0]
		newRG.State = StateSecondary
		m.mu.Unlock()
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not run after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected local-commit-ready failure")
	}
	if newRG == nil {
		t.Fatal("hook did not run the remove+re-add")
	}
	if newRG == oldRG {
		t.Fatal("re-add must allocate a fresh RedundancyGroupState (incarnation change)")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg := m.groups[0]
	if rg != newRG {
		t.Fatalf("live RG pointer changed across the abort (got %p, want re-added %p)", rg, newRG)
	}
	if gen := m.failoverGen[0]; gen != 0 {
		t.Fatalf("failoverGen[0] = %d after purge+re-add, want 0 (the gen-0 snapshot gates pass; only incarnation rejects it)", gen)
	}
	if rg.ManualFailover {
		t.Error("fresh RG has ManualFailover=true after abort — the removed incarnation's hold was restored onto it (#10244)")
	}
	if !rg.ManualFailoverAt.IsZero() {
		t.Errorf("fresh RG ManualFailoverAt=%v after abort, want zero (old timestamp %v must not cross the re-add)", rg.ManualFailoverAt, wantAt)
	}
	if rg.State == StateSecondaryHold {
		t.Errorf("fresh RG State=%s after abort, want no stale secondary-hold state", rg.State)
	}
	if rg.Weight != maxRedundancyGroupWeight {
		t.Errorf("fresh RG Weight=%d after abort, want %d", rg.Weight, maxRedundancyGroupWeight)
	}
}

func TestRequestPeerFailoverBatchReaddSkipsStaleHoldRestore10244(t *testing.T) {
	m := holdFixture10004(t, 1, 2)
	wantAt1 := armHold10004(t, m, 1)
	wantAt2 := armHold10004(t, m, 2)

	m.mu.RLock()
	old1, old2 := m.groups[1], m.groups[2]
	m.mu.RUnlock()

	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) { return 3002, nil })
	var new1, new2 *RedundancyGroupState
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		m.UpdateConfig(makeConfig())
		m.UpdateConfig(makeConfig(
			makeRG(1, true, map[int]int{0: 100}),
			makeRG(2, true, map[int]int{0: 100}),
		))
		m.mu.Lock()
		new1, new2 = m.groups[1], m.groups[2]
		new1.State = StateSecondary
		new2.State = StateSecondary
		m.mu.Unlock()
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error {
		t.Error("peer batch transfer-commit must not run after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailoverBatch([]int{1, 2}); err == nil {
		t.Fatal("expected batch local-commit-ready failure")
	}
	if new1 == nil || new2 == nil {
		t.Fatal("hook did not run the remove+re-add")
	}
	if new1 == old1 || new2 == old2 {
		t.Fatal("re-add must allocate fresh RedundancyGroupState objects (incarnation change)")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, tc := range []struct {
		rgID   int
		want   *RedundancyGroupState
		wantAt time.Time
	}{
		{1, new1, wantAt1},
		{2, new2, wantAt2},
	} {
		rg := m.groups[tc.rgID]
		if rg != tc.want {
			t.Fatalf("rg %d: live pointer changed across the abort (got %p, want re-added %p)", tc.rgID, rg, tc.want)
		}
		if gen := m.failoverGen[tc.rgID]; gen != 0 {
			t.Fatalf("rg %d: failoverGen = %d after purge+re-add, want 0", tc.rgID, gen)
		}
		if rg.ManualFailover {
			t.Errorf("rg %d: fresh RG held after abort — stale hold restored across the re-add (#10244)", tc.rgID)
		}
		if !rg.ManualFailoverAt.IsZero() {
			t.Errorf("rg %d: fresh ManualFailoverAt=%v, want zero (old %v must not cross the re-add)", tc.rgID, rg.ManualFailoverAt, tc.wantAt)
		}
		if rg.State == StateSecondaryHold {
			t.Errorf("rg %d: fresh State=%s, want no stale secondary-hold state", tc.rgID, rg.State)
		}
	}
}

func TestRequestPeerFailoverReaddPreservesNewReservation10244(t *testing.T) {
	m := holdFixture10004(t, 0)
	armHold10004(t, m, 0)

	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })

	// Call 1 is the old request (returns immediately); call 2 is the new
	// request taken after the re-add (blocks in send while the old request
	// returns and runs its defer); call 3+ is an overlapping probe that
	// must never reach send while the new reservation is held.
	newEntered := make(chan struct{})
	releaseNew := make(chan struct{})
	var sendMu sync.Mutex
	sendCalls := 0
	m.SetPeerFailoverFunc(func(int) (uint64, error) {
		sendMu.Lock()
		sendCalls++
		call := sendCalls
		sendMu.Unlock()
		switch call {
		case 1:
			return 3101, nil
		case 2:
			close(newEntered)
			<-releaseNew
			return 3102, nil
		default:
			return 0, fmt.Errorf("overlapping probe reached peer-failover send (call %d) — reservation was wiped (#10244)", call)
		}
	})
	// The new request must be able to commit once released.
	m.SetPeerFailoverCommitFunc(func(int, uint64) error { return nil })

	var hookMu sync.Mutex
	hookCalls := 0
	var newDone chan error
	var newEarlyErr error
	newEarly := false
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		hookMu.Lock()
		hookCalls++
		call := hookCalls
		hookMu.Unlock()
		if call != 1 {
			return nil
		}
		// Old request: purge + fresh incarnation, make it eligible, then
		// reserve the new request before failing.
		m.UpdateConfig(makeConfig())
		m.UpdateConfig(makeConfig(makeRG(0, true, map[int]int{0: 100})))
		m.mu.Lock()
		if rg := m.groups[0]; rg != nil {
			rg.State = StateSecondary
			rg.Ready = true
			rg.ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
			rg.ReadinessReasons = nil
		}
		m.mu.Unlock()
		newDone = make(chan error, 1)
		go func() { newDone <- m.RequestPeerFailover(0) }()
		select {
		case <-newEntered:
		case err := <-newDone:
			newEarly = true
			newEarlyErr = err
			t.Errorf("new request returned %v before reserving (want it blocked in send)", err)
		case <-time.After(5 * time.Second):
			t.Error("timed out waiting for the new request to reserve after the re-add")
		}
		return fmt.Errorf("dataplane not settled")
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected the old request to fail its local-commit-ready check")
	}
	if newDone == nil {
		t.Fatal("old hook never started the new request")
	}
	if newEarly {
		t.Fatalf("new request ended early with %v; no reservation to defend", newEarlyErr)
	}
	select {
	case err := <-newDone:
		t.Fatalf("new request returned %v while still expected blocked in send", err)
	default:
	}

	// The old defer has run. White-box: the new token must still be held.
	m.mu.RLock()
	_, reserved := m.failoverInProgress[0]
	m.mu.RUnlock()
	if !reserved {
		t.Error("new reservation missing after the old request returned — the old defer wiped it (#10244)")
	}
	// Black-box: overlapping requests must still be rejected.
	if err := m.RequestPeerFailover(0); err == nil {
		t.Error("overlapping peer request admitted while the new request holds the reservation")
	} else if !strings.Contains(err.Error(), "already in progress") {
		t.Errorf("overlapping peer request error = %v, want 'already in progress' rejection", err)
	}
	if _, err := m.ManualFailover(0); err == nil {
		t.Error("manual failover admitted while the new request holds the reservation")
	} else if !strings.Contains(err.Error(), "already in progress") {
		t.Errorf("manual failover error = %v, want 'already in progress' rejection", err)
	}

	close(releaseNew)
	if err := <-newDone; err != nil {
		t.Fatalf("new request after re-add failed: %v", err)
	}
	if !m.IsLocalPrimary(0) {
		t.Error("new request should have promoted the local node to primary")
	}
}
