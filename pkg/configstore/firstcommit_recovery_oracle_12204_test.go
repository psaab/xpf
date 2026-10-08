package configstore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #12204: the expired-first-commit boot-recovery branch
// (recoverPendingConfirmLocked, rec.FirstCommit) is the ONLY writer of the
// never-committed marker on the Load path — yet the test that executes it
// (TestActiveSnapshotRecoveryFirstCommitNil9905) asserts only the published
// nil snapshot. The EverCommitted/committed=0 assertions live on the
// PromoteRollback and timer paths (#7291, #6538), which run different code.
// A regression here that stops clearing everCommitted/marker passes the whole
// suite: the production branch is pinned by nothing.
//
// This oracle drives the exact uncovered shape — a GENUINE first commit
// confirmed whose window expires while the daemon is DOWN — through Load
// (restart), asserting immediately, after reopen, and after a
// failed-write/heal cycle:
//   - ActiveConfig()==nil AND EverCommitted()==false (in-memory boot inputs);
//   - disk marker committed=false via ReadActiveMeta, on a FRESH store;
//   - a failed first marker write that later heals via the retry loop still
//     lands committed=false (persistMarkerCommitted seed);
//   - the (nil active, never-committed) pair classifies BOOTSTRAP per the
//     daemon's computeBootClass truth table — never operator-committed-empty.
//
// Each subtest kills exactly one of the three retained-marker mutants:
//   M1  s.everCommitted = false -> true        (killed by Immediate)
//   M2  s.persistMarkerCommitted = false->true (killed by FailedWriteHealsUncommitted)
//   M3  writeActiveMarker(prevTree, false->true) (killed by ReopenReadsUncommitted)

// armExpiredFirstCommitLocked is the shared fixture: a genuine first commit
// confirmed (FirstCommit=true) whose window expired during downtime. The
// arming store is closed for restart semantics: its timer is cancelled so no
// in-process rollback can race the fresh Load below (#9615).
func armExpiredFirstCommitLocked(t *testing.T, path string) {
	t.Helper()
	s0 := newTestStoreAt(t, path)
	if err := s0.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s0.SetFromInput("system host-name First"); err != nil {
		t.Fatal(err)
	}
	if _, err := s0.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if rec, err := s0.db.ReadConfirm(); err != nil || rec == nil || !rec.FirstCommit {
		t.Fatalf("premise broken: want persisted FirstCommit record, rec=%v err=%v", rec, err)
	}
	s0.CancelConfirmTimerForTesting()
	forceConfirmDeadlinePast(t, path)
}

func TestFirstCommitRecoveryOracle12204(t *testing.T) {
	t.Run("Immediate", func(t *testing.T) {
		// Right after the expired-window Load: the rollback target is the
		// empty bootstrap tree, so recovery publishes nil — AND the store
		// must already read never-committed in memory. M1 (everCommitted
		// stays true) survives the nil-snapshot assert but dies here.
		path := filepath.Join(t.TempDir(), "config")
		armExpiredFirstCommitLocked(t, path)
		s := newTestStoreAt(t, path)
		if err := s.Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if s.ActiveConfig() != nil {
			t.Fatal("ActiveConfig non-nil after first-commit recovery rollback")
		}
		if s.EverCommitted() {
			t.Fatal("EverCommitted=true after an expired first-commit window " +
				"recovered on boot; the in-memory boot predicate now reads " +
				"operator-committed-empty (M1 survives the nil-snapshot assert)")
		}
	})

	t.Run("ReopenReadsUncommitted", func(t *testing.T) {
		// The durable half: a FRESH store reopened over the recovered DB
		// must read committed=false from disk. M3 (marker written true)
		// leaves EverCommitted false in memory (M1's line still clears it)
		// but poisons the disk — the reopen is what observes it, and the
		// NEXT restart would then classify NORMAL.
		path := filepath.Join(t.TempDir(), "config")
		armExpiredFirstCommitLocked(t, path)
		s := newTestStoreAt(t, path)
		if err := s.Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
		reopened := newTestStoreAt(t, path)
		_, committed, err := reopened.db.ReadActiveMeta()
		if err != nil {
			t.Fatalf("ReadActiveMeta: %v", err)
		}
		if committed {
			t.Fatal("disk marker committed=true after first-commit boot recovery; " +
				"want committed=false (M3: the recovery wrote the committed bit)")
		}
		if err := reopened.Load(); err != nil {
			t.Fatalf("reopen Load: %v", err)
		}
		if reopened.EverCommitted() {
			t.Fatal("reopened EverCommitted=true; the recovered DB must stay " +
				"never-committed across restarts")
		}
	})

	t.Run("FailedWriteHealsUncommitted", func(t *testing.T) {
		// The degraded half: the recovery rollback write FAILS (disk full),
		// then the retry loop heals it. The heal must re-write committed=0 —
		// the seed for that is persistMarkerCommitted=false, set on the same
		// branch. M2 flips the seed to true: the immediate write still lands
		// committed=0, so only the heal leg observes the poison.
		path := filepath.Join(t.TempDir(), "config")
		armExpiredFirstCommitLocked(t, path)
		s := newTestStoreAt(t, path)
		s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)
		s.SetWriteActiveMarkerForTesting(func(_ *config.ConfigTree, _ bool) error {
			return errDiskFull
		})
		if err := s.Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !s.ConfigPersistDegraded() {
			t.Fatal("premise broken: failed recovery write must set degraded")
		}
		// Disk heals; restore the real write so the retry lands durably.
		s.SetWriteActiveMarkerForTesting(nil)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && s.ConfigPersistDegraded() {
			time.Sleep(5 * time.Millisecond)
		}
		if s.ConfigPersistDegraded() {
			t.Fatal("recovery rollback retry did not converge")
		}
		prober := newTestStoreAt(t, path)
		_, committed, err := prober.db.ReadActiveMeta()
		if err != nil {
			t.Fatalf("ReadActiveMeta: %v", err)
		}
		if committed {
			t.Fatal("healed marker committed=true; the degraded retry must " +
				"re-write committed=false for a first-commit rollback (M2: the " +
				"retry seed was flipped to committed)")
		}
	})

	t.Run("BootClassStaysBootstrap", func(t *testing.T) {
		// The classification half: the recovered (nil active, never-committed)
		// pair must resolve BOOTSTRAP — not operator-committed-empty NORMAL
		// with positional claim-all naming on an empty config (#1922 Item 2
		// case-5). configstore cannot import pkg/daemon (import cycle: daemon
		// imports configstore), so this pins the daemon's published truth
		// table inputs instead: shouldBootstrapFromFile(!hasActive ||
		// !everCommitted) and the computeBootClass never-committed row both
		// key off exactly these two values.
		path := filepath.Join(t.TempDir(), "config")
		armExpiredFirstCommitLocked(t, path)
		s := newTestStoreAt(t, path)
		if err := s.Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
		hasActive := s.ActiveConfig() != nil
		everCommitted := s.EverCommitted()
		// shouldBootstrapFromFile(hasActive, everCommitted, failClosed=false).
		if hasActive {
			t.Fatalf("boot inputs (hasActive=%v, everCommitted=%v): first-commit recovery must retain the nil active-config bootstrap shape", hasActive, everCommitted)
		}
		if everCommitted {
			t.Fatalf("boot inputs (hasActive=%v, everCommitted=%v): the committed half misclassifies the empty rollback target as operator-committed (NORMAL), not never-committed (BOOTSTRAP)", hasActive, everCommitted)
		}
	})
}
