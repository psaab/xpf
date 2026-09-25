package configstore

// #9887: a plain commit does not clear the #8566 confirm-read-failure flag,
// so /health stays 503 after the window it describes has been superseded.
//
// Mechanism on base: recoverPendingConfirmLocked sets confirmRecoveryReadFailed
// and Load succeeds with NO timer armed. clearPendingConfirmLocked early-returns
// when no timer is armed (store_commit.go:946-950), so a plain Commit that
// promotes a new tree never reaches resolveConfirmRemovalLocked — the only
// leg that would remove the unreadable record and clear the flag. SyncApply
// has the same hole: it keys its removal on cancelPendingConfirmTimerLocked,
// which also reports nothing to cancel here.
//
// A health degradation must clear when the condition that raised it is
// superseded: the flag says "an unconfirmed config stands with no timer",
// and a later plain commit / sync makes that false.
import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// errInjectedConfirmTransientRead models a TRANSIENT confirm.json read failure:
// the bytes on disk are a valid live record, but the read fails. Distinct from
// a corrupt file (invalid bytes); the armed-timer gate exists for exactly this
// case, where "unreadable" must not be read as "not a fresh arm".
var errInjectedConfirmTransientRead = errors.New("injected transient confirm.json read failure")

// bootWithLostWindow replays the #8566 premise via the shared helper and
// returns a store that has Loaded it: Load ok, no timer, flag set, degraded.
func bootWithLostWindow9887(t *testing.T) (*Store, string) {
	t.Helper()
	path, _ := armThenCorruptConfirm(t)
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("#9887 PREMISE: boot Load must succeed: %v", err)
	}
	if s2.IsConfirmPending() {
		t.Fatal("#9887 PREMISE: no timer can be armed from an unreadable record")
	}
	if !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#9887 PREMISE: the lost-window flag must be set after boot")
	}
	if !s2.ConfigPersistDegraded() {
		t.Fatal("#9887 PREMISE: the boot must report degraded health")
	}
	return s2, path
}

func assertLostWindowCleared9887(t *testing.T, s *Store, via string) {
	t.Helper()
	if s.ConfirmRecoveryReadFailed() {
		t.Fatalf("#9887: %s supersedes the lost window, so the flag must clear", via)
	}
	if s.ConfigPersistDegraded() {
		t.Fatalf("#9887: /health must recover once %s supersedes the lost window", via)
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("#9887: the unreadable record must be durably gone after %s: rec=%v err=%v", via, rec, err)
	}
}

// TestPlainCommitClearsLostWindowFlag_9887 pins the core defect: a plain
// commit after a corrupt-confirm boot clears the flag and restores health.
func TestPlainCommitClearsLostWindowFlag_9887(t *testing.T) {
	s2, path := bootWithLostWindow9887(t)

	if err := s2.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	committed := commitPlainChange(t, s2, "eth3", "dmz")
	if got := s2.ShowActiveSet(); got != committed {
		t.Fatalf("#9887 PREMISE: the plain commit must stand.\nwant %s\ngot  %s", committed, got)
	}
	assertLostWindowCleared9887(t, s2, "a plain commit")

	// The next boot must not re-raise the flag: the record is gone, not masked.
	s3 := newTestStoreAt(t, path)
	if err := s3.Load(); err != nil {
		t.Fatalf("reboot Load: %v", err)
	}
	if s3.ConfirmRecoveryReadFailed() || s3.ConfigPersistDegraded() {
		t.Fatal("#9887: a reboot after the superseding commit must come up clean")
	}
}

// TestSyncApplyClearsLostWindowFlag_9887 pins the same supersede rule on the
// HA config-sync path: an authoritative sync replaces the unconfirmed config
// standing with no timer, so the flag must clear once the sync is durable.
func TestSyncApplyClearsLostWindowFlag_9887(t *testing.T) {
	s2, _ := bootWithLostWindow9887(t)

	if _, err := s2.SyncApply("system {\n    host-name synced9887;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	assertLostWindowCleared9887(t, s2, "an authoritative sync")
}

// TestLostWindowRemovalFailureRetainsDebt_9887 pins the failure leg: when the
// unreadable record cannot be removed, the commit still lands (degrade-not-fail)
// but the flag stays with removal debt + degraded health — and the background
// retry converges to a clear flag once the removal lands.
func TestLostWindowRemovalFailureRetainsDebt_9887(t *testing.T) {
	path, _ := armThenCorruptConfirm(t)
	var failUnlink atomic.Bool
	installConfirmDeleteSeams(t, &failUnlink, nil)

	s2 := newTestStoreAt(t, path)
	s2.SetPersistRetryBackoffForTesting(time.Millisecond, 4*time.Millisecond) // fast heal
	if err := s2.Load(); err != nil {
		t.Fatalf("#9887 PREMISE: boot Load must succeed: %v", err)
	}
	if !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#9887 PREMISE: the lost-window flag must be set after boot")
	}

	failUnlink.Store(true)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	commitPlainChange(t, s2, "eth3", "dmz")

	if !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#9887: a removal that did not land must NOT clear the flag — the " +
			"unreadable record is still on disk")
	}
	if !s2.ConfirmRemovalDegraded() {
		t.Fatal("#9887: the failed removal must retain retry debt (ConfirmRemovalDegraded)")
	}
	if !s2.ConfigPersistDegraded() {
		t.Fatal("#9887: health must stay degraded while the removal is owed")
	}

	failUnlink.Store(false)
	waitForCondition(t, "#9887: removal debt to heal", func() bool {
		return !s2.ConfirmRemovalDegraded()
	})
	waitForCondition(t, "#9887: lost-window flag to clear once the record is durably gone", func() bool {
		return !s2.ConfirmRecoveryReadFailed()
	})
	if s2.ConfigPersistDegraded() {
		t.Fatal("#9887: /health must recover once the retry durably removes the record")
	}
	if rec, err := s2.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("#9887: confirm.json must be gone once the retry converges: rec=%v err=%v", rec, err)
	}
}

// TestSyncWriteFailureDefersLostWindowRemoval_9887 pins the #5473 ordering on
// the lost-window leg: when the superseding sync's own write fails, the
// unreadable record is KEPT (not removed up front) and its removal is deferred
// until the replacement config is durable.
func TestSyncWriteFailureDefersLostWindowRemoval_9887(t *testing.T) {
	s2, _ := bootWithLostWindow9887(t)
	s2.SetPersistRetryBackoffForTesting(time.Millisecond, 4*time.Millisecond) // fast heal

	s2.SetWriteActiveForTesting(failingWriteActive)
	if _, err := s2.SyncApply("system {\n    host-name synced9887;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply must not fail on persist failure (Option B): %v", err)
	}

	// In memory the sync stands, but nothing is durable yet: the flag stays
	// and the record stays — removing it now would lose the ordering #5473
	// requires of every superseding removal.
	if !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#9887: the flag must stay while the superseding sync is not durable")
	}
	if !s2.ConfigPersistDegraded() {
		t.Fatal("#9887 PREMISE: the failed sync write must report degraded")
	}

	s2.SetWriteActiveForTesting(nil) // the replacement write can land now
	waitForCondition(t, "#9887: lost-window flag to clear once the sync is durable", func() bool {
		return !s2.ConfirmRecoveryReadFailed()
	})
	if s2.ConfigPersistDegraded() {
		t.Fatal("#9887: /health must recover once the deferred removal lands")
	}
	if rec, err := s2.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("#9887: confirm.json must be gone once the sync is durable: rec=%v err=%v", rec, err)
	}
}

// TestExplicitConfirmDoesNotClearLostWindow_9887 pins the boundary: an
// explicit confirm with no timer armed ERRORS ("no pending confirmed commit")
// and supersedes nothing, so it must neither succeed nor clear the flag.
// This is the control that fails on the over-broad fix (clearing inside
// clearPendingConfirmLocked itself, which would make this call succeed and
// flip ConfirmPendingOnDemotion to true with no window pending).
func TestExplicitConfirmDoesNotClearLostWindow_9887(t *testing.T) {
	s2, _ := bootWithLostWindow9887(t)

	if err := s2.ConfirmCommit(); err == nil {
		t.Fatal("#9887: an explicit confirm with no pending window must keep erroring — " +
			"there is nothing to confirm and the call supersedes nothing")
	}
	if s2.ConfirmPendingOnDemotion() {
		t.Fatal("#9887: demotion must not report a cleared window when none was pending")
	}
	if !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#9887: erroring callers supersede nothing, so the flag must stay")
	}
}

// TestRemovalRetryNeverDeletesLiveRecordOnTransientReadError_9887 pins the GPT
// blocking finding on the parent review: removal debt that survives a
// successful re-arm (the re-arm clears read-failure/arm flags but leaves the
// debt) must NOT be re-driven while the newer window's timer is armed when
// reads fail transiently. The supersede check reports "not superseded" on ANY
// read error, so without the armed-timer gate the loop deletes the live
// window's crash-recovery file while its timer REMAINS ARMED (#4577).
// Unreadable is not proof of not-a-fresh-arm.
//
// RED without the gate: the first fast tick re-drives DeleteConfirm and the
// remove-attempt counter trips (and the live record is gone).
func TestRemovalRetryNeverDeletesLiveRecordOnTransientReadError_9887(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	var failUnlink, failRead atomic.Bool
	var removeAttempts atomic.Int64
	restoreRollbackSeams(t)
	rbRemove = func(p string) error {
		if filepath.Base(p) == "confirm.json" {
			removeAttempts.Add(1)
		}
		if failUnlink.Load() && filepath.Base(p) == "confirm.json" {
			return errInjectedConfirmUnlink
		}
		return os.Remove(p)
	}
	rbReadBoundedFile = func(p string, max int64) ([]byte, error) {
		if failRead.Load() && filepath.Base(p) == "confirm.json" {
			return nil, errInjectedConfirmTransientRead
		}
		return ReadBoundedFile(p, max)
	}

	s := newTestStoreAt(t, path)
	s.SetPersistRetryBackoffForTesting(time.Millisecond, 4*time.Millisecond) // fast ticks
	commitBaseline(t, s)                                                     // A
	stagePendingConfirmed(t, s, "eth1", "untrust")                           // W1 (B): R1 on disk, armed
	// Take removal debt for R1: confirm W1 with the unlink failing.
	failUnlink.Store(true)
	commitPlainChange(t, s, "eth3", "dmz") // C confirms W1
	if !s.ConfirmRemovalDegraded() {
		t.Fatal("PREMISE: the failed resolution must retain removal debt")
	}
	if s.IsConfirmPending() {
		t.Fatal("PREMISE: W1 was confirmed, so no timer is armed")
	}

	// Fail reads BEFORE the re-arm: otherwise the fast loop supersede-clears
	// the debt within ~1ms of the re-arm landing and the setup below races.
	// With reads failing, no tick can clear (supersede reports false) or
	// delete (the gate skips once armed; the unlink fault blocks it before).
	failRead.Store(true)

	// Re-arm: a newer live window whose record replaces R1. The re-arm leaves
	// the older removal debt outstanding — the GPT setup. Inlined (not
	// stagePendingConfirmed) because that helper asserts readability, which
	// is exactly what is faulted here; the arm path itself performs no reads.
	if err := s.SetFromInput("interfaces eth2 unit 0 family inet address 10.9.0.1/24"); err != nil {
		t.Fatalf("SetFromInput iface: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone guest interfaces eth2.0"); err != nil {
		t.Fatalf("SetFromInput zone: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed W2: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("PREMISE: W2 must be armed")
	}
	if !s.ConfirmRemovalDegraded() {
		t.Fatal("PREMISE: the successful re-arm must leave the older removal debt " +
			"outstanding (writeConfirmState clears arm/read-failure flags, not removal debt)")
	}
	// Capture the live record's identity from the raw bytes (reads are faulted,
	// so ReadConfirm is unusable). Strip the outer format marker before decrypt,
	// matching ReadConfirm's decode order.
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(path), ".configdb", "confirm.json"))
	if err != nil {
		t.Fatalf("PREMISE: the live record file must exist: %v", err)
	}
	raw, err = stripConfirmEnvelope(raw)
	if err != nil {
		t.Fatalf("PREMISE: strip live record envelope: %v", err)
	}
	raw, _, err = s.db.maybeDecryptTreeJSON(raw, nil)
	if err != nil {
		t.Fatalf("PREMISE: decrypt live record: %v", err)
	}
	var live confirmRecord
	if err := json.Unmarshal(raw, &live); err != nil || live.Deadline.IsZero() || live.PrevTree == nil {
		t.Fatalf("PREMISE: the live record must decode valid: err=%v", err)
	}
	liveID := confirmRecordIdentity(&live)

	// Race transient read errors against the armed timer: every supersede
	// check now reports "not superseded". The unlink fault lifts now that
	// reads fail, so without the gate the racing tick would REALLY delete R2.
	removeAttempts.Store(0)
	failUnlink.Store(false)
	time.Sleep(100 * time.Millisecond) // dozens of fast ticks race here
	if n := removeAttempts.Load(); n != 0 {
		t.Fatalf("#9887/GPT: the retry must never re-drive the delete while a window is armed "+
			"and reads fail transiently: %d remove attempts", n)
	}
	// The live record must still be there — via the raw bytes, since reads are
	// still injected to fail.
	st, err := os.Stat(filepath.Join(filepath.Dir(path), ".configdb", "confirm.json"))
	if err != nil || st.Size() == 0 {
		t.Fatalf("#9887/GPT: the live window's record must survive the race: stat=%v err=%v", st, err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("PREMISE: W2's timer must still be armed")
	}

	// Reads heal: the next tick supersede-clears the debt WITHOUT deleting.
	failRead.Store(false)
	waitForCondition(t, "#9887/GPT: removal debt to supersede-clear", func() bool {
		return !s.ConfirmRemovalDegraded()
	})
	if n := removeAttempts.Load(); n != 0 {
		t.Fatalf("#9887/GPT: supersession must clear the debt without deleting: %d remove attempts", n)
	}
	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("#9887/GPT: the live record must still be on disk after supersede-clear: rec=%v err=%v", rec, err)
	}
	if id := confirmRecordIdentity(rec); id != liveID {
		t.Fatalf("#9887/GPT: the live record must be untouched: want %s got %s", liveID, id)
	}
	s.CancelConfirmTimerForTesting() // tidy: do not leak W2's 1-minute timer
}

// TestSupersedeAndDeferSingleDrain_9887 pins SPARK-F2: when a durable sync or
// plain commit both resolves the lost window directly AND has a deferred
// removal pending for the same single file, exactly ONE removal is attempted —
// not a direct resolve plus a deferred finalize (two I/Os, two
// confirm_remove_error journals) for one record.
func TestSupersedeAndDeferSingleDrain_9887(t *testing.T) {
	s2, _ := bootWithLostWindow9887(t)
	s2.SetPersistRetryBackoffForTesting(time.Hour, time.Hour) // dormant loop
	var failUnlink atomic.Bool
	var removeAttempts atomic.Int64
	restoreRollbackSeams(t)
	rbRemove = func(p string) error {
		if filepath.Base(p) == "confirm.json" {
			removeAttempts.Add(1)
		}
		if failUnlink.Load() && filepath.Base(p) == "confirm.json" {
			return errInjectedConfirmUnlink
		}
		return os.Remove(p)
	}

	// Defer a lost-window removal via a failing sync write.
	s2.SetWriteActiveForTesting(failingWriteActive)
	if _, err := s2.SyncApply("system {\n    host-name synced9887;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply must not fail on persist failure (Option B): %v", err)
	}
	if !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("PREMISE: the flag must stay while the superseding sync is not durable")
	}

	// Phase 1 — durable sync with the removal failing: one drain, not two.
	s2.SetWriteActiveForTesting(nil)
	failUnlink.Store(true)
	removeAttempts.Store(0)
	if _, err := s2.SyncApply("system {\n    host-name synced9887b;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if n := removeAttempts.Load(); n != 1 {
		t.Fatalf("#9887/SPARK-F2: one drain per sync, want 1 remove attempt, got %d", n)
	}
	if !s2.ConfirmRemovalDegraded() || !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#9887/SPARK-F2: the failed drain must retain debt and keep the flag")
	}

	// Phase 2 — durable plain commit with a deferral pending and the removal
	// failing: the deferred finalize drains; the direct supersede stands down.
	s2.SetWriteActiveForTesting(failingWriteActive)
	if _, err := s2.SyncApply("system {\n    host-name synced9887c;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply must not fail on persist failure (Option B): %v", err)
	}
	s2.SetWriteActiveForTesting(nil)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	removeAttempts.Store(0)
	commitPlainChange(t, s2, "eth3", "dmz")
	if n := removeAttempts.Load(); n != 1 {
		t.Fatalf("#9887/SPARK-F2: one drain per commit, want 1 remove attempt, got %d", n)
	}
	if !s2.ConfirmRemovalDegraded() || !s2.ConfirmRecoveryReadFailed() {
		t.Fatal("#9887/SPARK-F2: the failed drain must retain debt and keep the flag")
	}
}
