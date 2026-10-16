package configstore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// uncompilableTree returns a tree that a previously-committed config could
// plausibly hold and that the LENIENT compile still rejects AFTER the
// #14168 pending-confirm normalization (normalizePendingConfirmTree applies
// rewriteRetiredDataplaneType + SanitizeTreeControlChars to PrevTree before
// compile/promotion — #14301).
//
// `apply-groups` naming a group that is not defined under `groups` is
// genuinely uncompilable on every compile path: group expansion returns
// "apply-groups references undefined group", and neither tolerant repair
// touches it — the dataplane-type rewrite rewrites only a retired
// `system dataplane-type` leaf, and the control-char scrub scrubs only
// control characters in free-text values. It is the same trigger
// brokenActiveTree9884 and TestLoadCommittedConfigCompileFailureFailsClosed
// use for a present-but-uncompilable committed config: the text is
// unchanged, but a group definition the target relied on is no longer
// present (removed, or supplied only for another cluster node), so a
// target that compiled when committed fails even the lenient compile at
// boot.
//
// The retired `system dataplane-type ebpf` leaf this fixture used before
// #14301 is NO LONGER uncompilable as a rollback target: since #14286
// (#14168) normalizePendingConfirmTree repairs exactly that leaf in
// PrevTree before compiling it, so it silently compiled and the #6538
// sentinels below lost their premise (expired cell failed on its premise
// check; the in-window cells passed without ever exercising a nil
// confirmPrevCfg from a failed compile).
func uncompilableTree(t *testing.T) *config.ConfigTree {
	t.Helper()
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "probe"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("apply-groups xpf6538-undefined-group"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := s.SetFromInput("system host-name Prev"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	tree := s.candidate.Clone()
	s.ExitConfigure()
	if _, err := s.compileTreeLenient(tree); err == nil {
		t.Fatal("premise broken: the probe tree compiles leniently; it cannot " +
			"stand in for an uncompilable rollback target")
	}
	// #14301: the fixture must remain uncompilable after the exact repairs
	// recoverPendingConfirmLocked applies to PrevTree, not merely before
	// them — that gap is what superseded the retired-leaf fixture.
	normalized := tree.Clone()
	normalizePendingConfirmTree(normalized)
	if _, err := s.compileTreeLenient(normalized); err == nil {
		t.Fatal("premise broken: the probe tree compiles leniently after " +
			"normalizePendingConfirmTree (#14168 repairs); it cannot stand in " +
			"for an uncompilable rollback target (#14301)")
	}
	return tree
}

// rearmWithUncompilableTarget takes a store armed by armedConfirmStore and
// rewrites its persisted confirm record so the ROLLBACK TARGET no longer
// compiles, leaving everything else (GuardedHash, FirstCommit=false) intact.
// deadline selects the expired vs still-in-window recovery branch.
func rearmWithUncompilableTarget(t *testing.T, path string, deadline time.Time) {
	t.Helper()
	s0 := newTestStoreAt(t, path)
	rec, err := s0.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
	}
	if rec.FirstCommit {
		t.Fatal("premise broken: the armed record claims FirstCommit; this test " +
			"is about a REAL previously-committed rollback target")
	}
	rec.PrevTree = uncompilableTree(t)
	rec.Deadline = deadline
	if err := s0.db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}
}

// TestConfirmRecoveryExpiredUncompilableTargetFailsClosed is part 1 of #6538.
//
// The expired-during-downtime branch of recoverPendingConfirmLocked compiles
// the rollback target leniently, warns if that fails, and then assigns the
// result — nil — into s.compiled while setting everCommitted/persistMarker
// true. recoverPendingConfirmLocked returns void and runs inside Load, so
// Load's success return is already fixed by then.
//
// The daemon reads that as a NORMAL boot with no compiled policy: #1960 exists
// precisely so a present-but-uncompilable committed config yields
// ErrConfigCompile and the #1922 bootstrap/lifeline safe state instead of
// positional claim-all with an empty policy. This branch bypassed it.
func TestConfirmRecoveryExpiredUncompilableTargetFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10)
	rearmWithUncompilableTarget(t, path, time.Now().Add(-2*time.Minute))

	s := newTestStoreAt(t, path)
	err := s.Load()

	if s.ActiveConfig() != nil {
		t.Fatalf("premise broken: the rollback target compiled after all (%v)", s.ActiveConfig())
	}
	if err == nil {
		t.Fatalf("Load reported SUCCESS while writing a nil compiled config: "+
			"ActiveConfig()=nil, EverCommitted()=%v. The daemon resolves that to a "+
			"NORMAL boot with no policy (#6538 part 1)", s.EverCommitted())
	}
	if !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Load error = %v, want one tagged ErrConfigCompile so "+
			"classifyLoadError routes it to the #1922 bootstrap/lifeline safe "+
			"state rather than the generic warn-and-continue path", err)
	}
	// The reverted tree must still be reachable so the operator can fix it
	// from the CLI — the same recovery shape the #1960 Load path leaves.
	if s.ActiveTree() == nil {
		t.Fatal("active tree is nil after the fail-closed recovery; the operator " +
			"has nothing to `show | compare` or roll back from")
	}
}

// TestConfirmRecoveryInWindowRollbackDoesNotPersistNeverCommitted is part 2 of
// #6538 — the durable half.
//
// The still-in-window branch re-arms the timer and sets confirmPrevCfg from the
// lenient compile of the rollback target: nil when that compile fails. Two
// consumers then DERIVE "this was the first commit on a fresh store" from that
// nil — PromoteRollback's firstCommitRollback, and the firstCommit bit
// writeConfirmState persists. "Nil because it genuinely was the first commit"
// and "nil because the rollback target failed to compile" are different facts,
// and the action taken on the first is destructive for the second: committed=0
// persisted over a real config, so a later restart re-classifies the box into
// bootstrap (day-0 / claim-all).
func TestConfirmRecoveryInWindowRollbackDoesNotPersistNeverCommitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10)
	rearmWithUncompilableTarget(t, path, time.Now().Add(30*time.Minute))

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load (still in window): %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("premise broken: the still-in-window record did not re-arm")
	}
	if !s.EverCommitted() {
		t.Fatal("premise broken: the store must be everCommitted before the rollback")
	}

	type markerWrite struct{ committed bool }
	var markerWrites []markerWrite
	var plainWrites int
	s.SetWriteActiveMarkerForTesting(func(_ *config.ConfigTree, committed bool) error {
		markerWrites = append(markerWrites, markerWrite{committed: committed})
		return nil
	})
	s.SetWriteActiveForTesting(func(*config.ConfigTree) error {
		plainWrites++
		return nil
	})

	s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())

	for _, w := range markerWrites {
		if !w.committed {
			t.Fatalf("the auto-rollback persisted the NEVER-COMMITTED marker " +
				"(committed=0) over a real previously-committed config: it derived " +
				"\"first commit on a fresh store\" from confirmPrevCfg==nil, which " +
				"here means \"the rollback target failed to compile\". The next " +
				"restart re-classifies this box into bootstrap (#6538 part 2)")
		}
	}
	if plainWrites == 0 {
		t.Fatalf("the rollback wrote no ordinary active config (marker writes=%v); "+
			"a real rollback target must be persisted as committed", markerWrites)
	}
	if !s.EverCommitted() {
		t.Fatal("everCommitted was cleared by a rollback to a REAL committed config; " +
			"the in-memory boot predicate now reads never-committed (#6538 part 2)")
	}
}

// TestConfirmRecoveryInWindowNestedArmKeepsFirstCommitFalse is the second
// consumer of the same overloaded nil: the firstCommit bit persisted into
// confirm.json by a NESTED commit-confirmed. A nested arm preserves the
// recovered rollback target, so it re-persists the record with
// `s.confirmPrevCfg == nil` as its firstCommit value — durably mislabelling a
// real config as the empty bootstrap tree. The NEXT boot past the deadline then
// takes the rec.FirstCommit branch and writes committed=0.
func TestConfirmRecoveryInWindowNestedArmKeepsFirstCommitFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10)
	rearmWithUncompilableTarget(t, path, time.Now().Add(30*time.Minute))

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load (still in window): %v", err)
	}

	// A nested commit-confirmed while the recovered window is still pending.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name Nested"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("nested CommitConfirmed: %v", err)
	}

	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm after nested arm: rec=%v err=%v", rec, err)
	}
	if rec.FirstCommit {
		t.Fatal("the nested arm persisted FirstCommit=true for a rollback target " +
			"that is a REAL previously-committed config — it derived the bit from " +
			"confirmPrevCfg==nil, which here means the target failed to compile. " +
			"The next boot past the deadline writes committed=0 over that config " +
			"and the restart after it classifies bootstrap (#6538 part 2)")
	}
}

// TestConfirmRecoveryInWindowGenuineFirstCommitStillWritesNeverCommitted is the
// OTHER side of the #6538 discriminator, on the same recovery path.
//
// The fix must not become a blanket "never write the never-committed marker".
// A genuine first commit confirmed on a fresh store still has to persist
// committed=0 and clear everCommitted on rollback (#1922 Item 1b) — otherwise
// the restart after it classifies committed-empty => NORMAL and takes over
// interfaces on an empty config. Recovering that record across a restart must
// preserve the bit, since confirmPrevCfg is legitimately nil here too. This row
// and the one above differ ONLY in the persisted FirstCommit bit, so a fix that
// hard-coded either answer reds one of them.
func TestConfirmRecoveryInWindowGenuineFirstCommitStillWritesNeverCommitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")

	// A FIRST commit confirmed on a fresh store — no prior Commit.
	s0 := newTestStoreAt(t, path)
	if err := s0.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s0.SetFromInput("system host-name FirstEver"); err != nil {
		t.Fatal(err)
	}
	if _, err := s0.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	rec, err := s0.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
	}
	if !rec.FirstCommit {
		t.Fatal("premise broken: a first commit confirmed on a fresh store must " +
			"persist FirstCommit=true")
	}

	// Restart inside the window, then let the re-armed timer fire.
	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("premise broken: the record did not re-arm")
	}

	var sawNeverCommitted bool
	s.SetWriteActiveMarkerForTesting(func(_ *config.ConfigTree, committed bool) error {
		if !committed {
			sawNeverCommitted = true
		}
		return nil
	})

	s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())

	if !sawNeverCommitted {
		t.Fatal("a GENUINE first-commit rollback did not persist the never-committed " +
			"marker (committed=0). The next restart reads committed-empty => NORMAL " +
			"and takes over interfaces on an empty config (#1922 Item 1b)")
	}
	if s.EverCommitted() {
		t.Fatal("everCommitted still true after a genuine first-commit rollback; the " +
			"in-memory boot predicate reads operator-committed (#1922 Item 1b)")
	}
}
