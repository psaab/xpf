package configstore

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFirstCommitTeardownDebtDiscardedByInProcessCommit14993 is the D38-05
// store leg: after an expired FIRST window leaves teardown debt, a plain
// in-process commit (no restart) must discard the superseded debt. On
// pre-fix code discardSupersededFirstCommitTeardownLocked only ran from
// Load, so the debt stayed owed for the life of the process and the
// daemon teardown gate could tear down the replacement's takeover.
func TestFirstCommitTeardownDebtDiscardedByInProcessCommit14993(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	armFirstCommitWindow12155(t, path)

	store := newTestStoreAt(t, path)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("expired FIRST fixture did not acquire teardown debt")
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name Corrected"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()

	if store.FirstCommitTeardownOwed() {
		t.Fatal("in-process plain commit left superseded FIRST teardown debt owed")
	}
	markerPath := firstCommitTeardownMarkerPath(filepath.Join(filepath.Dir(path), ".configdb"))
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("superseded teardown marker remains after in-process commit: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if restarted.FirstCommitTeardownOwed() {
		t.Fatal("superseded teardown debt was resurrected on restart")
	}
	if got := restarted.ActiveConfig(); got == nil || got.System.HostName != "Corrected" {
		t.Fatalf("replacement config = %+v", got)
	}
}

// TestFirstCommitTeardownDebtDiscardedByInProcessConfirmedCommit14993 is
// the confirmed-commit sibling: CommitConfirmed + ConfirmCommit in one
// process must also discard the superseded debt.
func TestFirstCommitTeardownDebtDiscardedByInProcessConfirmedCommit14993(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	armFirstCommitWindow12155(t, path)

	store := newTestStoreAt(t, path)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("expired FIRST fixture did not acquire teardown debt")
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name Corrected"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()

	if store.FirstCommitTeardownOwed() {
		t.Fatal("in-process confirmed commit left superseded FIRST teardown debt owed")
	}
}
