package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9947 item (5): after a FAILED `commit confirmed` (e.g. an FRR frrErr),
// the confirm window is still pending with a clean candidate — the store
// arms at promote time and a daemon apply failure does not disarm it. A
// bare `commit` in that state takes the #4000 confirm-only intercept:
// it cancels the rollback WITHOUT re-running the apply. These cells pin
// which retry actually reapplies, so the runbook cannot drift back to
// "just re-commit".

func TestBareCommitAfterFailedConfirmedDoesNotReapply9947(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("set system host-name Base"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("set system host-name Confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(5); err != nil {
		t.Fatal(err)
	}
	if !store.IsConfirmPending() || store.IsDirty() {
		t.Fatal("CONTROL FAILED: want pending window with clean candidate")
	}
	calls := 0
	c := &CLI{store: store, commitFn: func(context.Context, string) (*config.Config, error) {
		calls++
		return store.ActiveConfig(), nil
	}}
	if err := c.handleCommit(nil); err != nil {
		t.Fatalf("bare commit: %v", err)
	}
	if calls != 0 {
		t.Fatalf("bare commit after commit-confirmed drove %d applies, want 0 — "+
			"it is confirm-only and must not be documented as a retry", calls)
	}
	if store.IsConfirmPending() {
		t.Fatal("bare commit must clear the pending window (pure confirmation)")
	}
}

func TestDirtyCommitAfterFailedConfirmedReapplies9947(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("set system host-name Base"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("set system host-name Confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(5); err != nil {
		t.Fatal(err)
	}
	// The retry: stage any edit so the candidate is dirty.
	if _, err := store.LoadSet("set system host-name Confirmed2"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	// The spy models the daemon's atomic commit+apply (#846): it counts
	// the apply-driving commit and delegates to the real store Commit so
	// the #3861 window-clearing also runs.
	c := &CLI{store: store, commitFn: func(context.Context, string) (*config.Config, error) {
		calls++
		return store.Commit()
	}}
	if err := c.handleCommit(nil); err != nil {
		t.Fatalf("dirty commit: %v", err)
	}
	if calls != 1 {
		t.Fatalf("dirty commit after commit-confirmed drove %d applies, want 1 — "+
			"this is the retry that actually reapplies", calls)
	}
	if store.IsConfirmPending() {
		t.Fatal("dirty commit must clear the pending window (#3861)")
	}
}
