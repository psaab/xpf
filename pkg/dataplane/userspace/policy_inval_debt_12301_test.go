package userspace

// policy_inval_debt_12301_test.go — #12301: the full-snapshot completion
// callback (SetPolicySnapshotCommitter) must fire when the status loop settles
// a content-equivalent newer generation without a control-socket RPC, and
// every settled tick must repeat it so daemon-side retained failed-delete debt
// retries on the existing status loop (no new timer).

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestInvalidationDebtContentEquivalentSettle12301 (#12301 MAJOR-b): a retained
// content-equivalent newer generation settling through the hash-dedup branch
// (zero apply_snapshot RPCs) is a successful convergence boundary for the
// policy snapshot, so the completion callback must fire with the new target
// generation. Callback-only: the NAT applied-generation must NOT advance to a
// generation the helper never echoed (see markAppliedSnapshotLocked's
// contract — the dedup path is not an applied snapshot).
func TestInvalidationDebtContentEquivalentSettle12301(t *testing.T) {
	f := newDeferredPublishFixture9337(t, nil)
	// Force the content-hash dedup: seed the published hash from the exact
	// copy syncSnapshotLocked hashes (single-use metadata stripped).
	retained := *f.snap
	stripSingleUseCommitMetadata(&retained)
	h, ok := snapshotContentHash(&retained)
	if !ok {
		t.Fatal("snapshotContentHash failed")
	}
	f.m.lastSnapshotHash = h
	f.m.appliedSnapshot = appliedSnapshot{Config: f.snap.Config, Generation: f.m.publishedSnapshot}

	var committed []uint64
	f.m.SetPolicySnapshotCommitter(func(generation uint64) {
		committed = append(committed, generation)
	})
	requests := 0
	f.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		requests++
		return nil
	}

	if err := f.runSync(t); err != nil {
		t.Fatalf("syncSnapshotLocked: %v", err)
	}
	if requests != 0 {
		t.Fatalf("control RPCs = %d, want 0 (a content-equivalent settle must dedup, not publish)", requests)
	}
	if f.m.publishedSnapshot != f.snap.Generation {
		t.Fatalf("publishedSnapshot = %d, want %d", f.m.publishedSnapshot, f.snap.Generation)
	}
	if f.m.appliedSnapshot.Generation != 1 {
		t.Fatalf("appliedSnapshot.Generation = %d, want 1 (dedup must not claim the helper echoed the newer generation)",
			f.m.appliedSnapshot.Generation)
	}
	if len(committed) != 1 || committed[0] != f.snap.Generation {
		t.Fatalf("policy snapshot commit notifications = %v, want [%d] (content-equivalent settle is a completion boundary)",
			committed, f.snap.Generation)
	}
}

// TestInvalidationDebtSettledTickRetriesCompletion12301: once the retained full
// config is settled (published == retained), every status-loop tick repeats the
// completion notification with that generation and sends no snapshot RPC, so a
// daemon-side retained failed-delete debt gets another attempt on the existing
// tick. No new timer, no debt lifecycle redesign.
func TestInvalidationDebtSettledTickRetriesCompletion12301(t *testing.T) {
	m := New()
	m.proc = selfProc(t)
	snap := mustBuildSnapshot(t, &config.Config{}, config.UserspaceConfig{}, 7, 0)
	m.lastSnapshot = snap
	m.publishedSnapshot = 7
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	} else {
		t.Fatal("snapshotContentHash failed")
	}
	m.lastStatus = ProcessStatus{
		ConfigSnapshotProtocolVersion: ProtocolVersion,
		LastSnapshotGeneration:        7,
	}
	m.helperStatusObserved = true

	var committed []uint64
	m.SetPolicySnapshotCommitter(func(generation uint64) {
		committed = append(committed, generation)
	})
	sends := 0
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			sends++
		}
		return nil
	}

	// Two consecutive status-loop ticks over settled state.
	for i := 0; i < 2; i++ {
		m.mu.Lock()
		err := m.syncSnapshotLocked()
		m.mu.Unlock()
		if err != nil {
			t.Fatalf("settled tick %d: %v", i+1, err)
		}
	}
	if sends != 0 {
		t.Fatalf("apply_snapshot sends = %d, want 0 (settled ticks must not republish)", sends)
	}
	if len(committed) != 2 || committed[0] != 7 || committed[1] != 7 {
		t.Fatalf("policy snapshot commit notifications = %v, want [7 7] (each settled tick retries completion)", committed)
	}
}

// TestInvalidationDebtSettledTickDefersWhileWorkersDeferred12301 pins the
// reconciled gate: while workers are deferred the helper has accepted but not
// reconciled the snapshot, so settled ticks must NOT notify (same invariant as
// TestPolicySnapshotCommitterWaitsForReconciledSnapshot).
func TestInvalidationDebtSettledTickDefersWhileWorkersDeferred12301(t *testing.T) {
	m := New()
	m.proc = selfProc(t)
	snap := mustBuildSnapshot(t, &config.Config{}, config.UserspaceConfig{}, 7, 0)
	m.lastSnapshot = snap
	m.publishedSnapshot = 7
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	} else {
		t.Fatal("snapshotContentHash failed")
	}
	m.deferWorkers = true

	var committed []uint64
	m.SetPolicySnapshotCommitter(func(generation uint64) {
		committed = append(committed, generation)
	})

	m.mu.Lock()
	err := m.syncSnapshotLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("settled tick: %v", err)
	}
	if len(committed) != 0 {
		t.Fatalf("deferred (not-reconciled) settled tick notified %v, want no notification", committed)
	}
}
