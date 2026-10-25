package daemon

// #16665: the #9615 refused-target bootstrap safe state had no commit
// exit. Bootstrap refused plain `commit`, and the #6707 gate refused
// `commit confirmed` on the very (refused) active target that caused
// the bootstrap. The only way out was a reboot.
//
// Fix: the #9615 refused branch records bootstrapFromRefusedRollback.
// In that provenance a plain commit is allowed (the refused target is
// already the persisted committed config, so the #1922 first-takeover
// risk does not apply) and the #6707 rollback-target gate is skipped
// (a timeout returns to the same safe state). Generic bootstrap is
// unchanged.
//
// RED on master: after the refused fire, the plain commit below is
// refused with the bootstrap message and the confirmed commit is
// refused by errRollbackTargetUnappliable.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

const corrected16665 = `system { host-name corrected; }
security { zones { security-zone trust; security-zone untrust; }
  policies { from-zone trust to-zone untrust { policy p1 { match { source-address any; destination-address any; application any; } then { permit; } } } } }
`

// stageCorrected16665 loads the corrected candidate into the store's
// candidate tree (the operator's "fix the configuration" step).
func stageCorrected16665(t *testing.T, s *configstore.Store) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride(corrected16665); err != nil {
		t.Fatalf("LoadOverride(corrected): %v", err)
	}
}

// TestRefusedTargetBootstrapPlainCommitExit16665 is the defect cell:
// after the #9615 refused fire, a corrected candidate commits by the
// plain route, is applied, and the store holds it.
func TestRefusedTargetBootstrapPlainCommitExit16665(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, refusedTarget9615)
	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())
	if !h.d.inBootstrap() {
		t.Fatal("premise: refused fire must enter bootstrap")
	}
	if got := hostName9615(h.s); got != "refused-target" {
		t.Fatalf("premise: active must be the refused target, got %q", got)
	}

	stageCorrected16665(t, h.s)
	compiled, err := h.d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever)
	if err != nil {
		t.Fatalf("plain commit of a corrected candidate in refused-target bootstrap must succeed (#16665); got %v", err)
	}
	if compiled == nil || compiled.System.HostName != "corrected" {
		t.Fatalf("plain commit must promote the corrected candidate, got %+v", compiled)
	}
	if got := hostName9615(h.s); got != "corrected" {
		t.Fatalf("store must hold the corrected config, got %q", got)
	}
	found := false
	for _, a := range h.applied {
		if a == "corrected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("corrected candidate must be applied, applied=%v", h.applied)
	}
	h.s.ExitConfigure()
}

// TestRefusedTargetBootstrapConfirmedCommitExit16665 pins the second
// route: `commit confirmed` in the refused-target bootstrap must not
// be refused by the #6707 gate on the refused active target.
func TestRefusedTargetBootstrapConfirmedCommitExit16665(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, refusedTarget9615)
	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())
	if !h.d.inBootstrap() {
		t.Fatal("premise: refused fire must enter bootstrap")
	}

	stageCorrected16665(t, h.s)
	compiled, err := h.d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever)
	if err != nil {
		if errors.Is(err, errRollbackTargetUnappliable) {
			t.Fatalf("commit confirmed in refused-target bootstrap must not hit the #6707 gate (#16665); got %v", err)
		}
		t.Fatalf("commit confirmed of a corrected candidate in refused-target bootstrap must succeed (#16665); got %v", err)
	}
	if compiled == nil || compiled.System.HostName != "corrected" {
		t.Fatalf("commit confirmed must promote the corrected candidate, got %+v", compiled)
	}
	if !h.s.IsConfirmPending() {
		t.Fatal("commit confirmed must arm its confirm window")
	}
	// Confirm it so no timer outlives the test, then the window is gone.
	if err := h.s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	h.s.ExitConfigure()
}

// TestGenericBootstrapStillRefusesPlainCommit16665 is the healthy
// control: bootstrap NOT entered from the #9615 refused branch keeps
// the #1922 plain-commit refusal, and commit-confirmed remains its
// escape hatch (the #15055 contract, unchanged).
func TestGenericBootstrapStillRefusesPlainCommit16665(t *testing.T) {
	h := newDaemon9615(t)
	// Generic bootstrap: flag only, no refused provenance, no window.
	h.d.bootstrapMode.Store(true)

	stageCorrected16665(t, h.s)
	if _, err := h.d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("plain commit in generic bootstrap must still be refused; got %v", err)
	}
	if got := hostName9615(h.s); got == "corrected" {
		t.Fatal("a refused plain commit must not promote the candidate")
	}
	// commit-confirmed is the generic-bootstrap escape hatch and its
	// rollback target here is nil/empty, so the #6707 gate passes.
	if _, err := h.d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("commit confirmed in generic bootstrap must still succeed: %v", err)
	}
	if err := h.s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	h.s.ExitConfigure()
}

// TestHealthyWindowUnchanged16665 is the adjacent control from the
// issue acceptance: a healthy recovered target keeps its existing
// behaviour — plain and confirmed commits on a non-bootstrap daemon
// are unchanged, and no refused provenance is latched.
func TestHealthyWindowUnchanged16665(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, healthyTarget9615)
	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())
	if h.d.inBootstrap() {
		t.Fatal("a healthy target must not enter bootstrap")
	}
	if h.d.bootstrapFromRefusedRollback.Load() {
		t.Fatal("a healthy rollback must not latch the refused provenance")
	}
	if len(h.applied) != 1 || h.applied[0] != "healthy-target" {
		t.Fatalf("a healthy target must be applied once, got %v", h.applied)
	}
}
