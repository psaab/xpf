package configstore

import (
	"errors"
	"path/filepath"
	"testing"
)

// #16070: CommitCheckAs must deny a non-holder, admit the holder, admit the
// internal ("") caller, and fail fast with ErrCommitCheckBusy when the
// single compile slot is already held. These are store-level pins; the
// gRPC and REST handler wiring is pinned in their own packages.
//
// FAIL-ON-REVERT: drop the ensureHolderLocked call from CommitCheckAs and
// the non-holder case compiles the holder's candidate instead of returning
// ErrConfigLockedByOther. Drop the semaphore acquire and the busy case
// compiles instead of returning ErrCommitCheckBusy.

func commitCheckHolderStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnterConfigureSession("owner"); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	if err := store.SetFromInputAs("owner", "system host-name staged-by-owner"); err != nil {
		t.Fatalf("SetFromInputAs: %v", err)
	}
	return store
}

func TestCommitCheckAsHolderGate_16070(t *testing.T) {
	store := commitCheckHolderStore(t)

	// Non-holder: denied with the shared holder sentinel, before any
	// compile diagnostics about the owner's candidate can leak.
	if _, err := store.CommitCheckAs("intruder"); !errors.Is(err, ErrConfigLockedByOther) {
		t.Fatalf("CommitCheckAs(non-holder) = %v, want ErrConfigLockedByOther", err)
	}

	// Holder: compiles its own candidate.
	compiled, err := store.CommitCheckAs("owner")
	if err != nil {
		t.Fatalf("CommitCheckAs(holder) = %v, want nil", err)
	}
	if compiled == nil || compiled.System.HostName != "staged-by-owner" {
		t.Fatalf("CommitCheckAs(holder) compiled = %+v, want host-name staged-by-owner", compiled)
	}

	// Internal/system caller ("") bypasses ownership, matching
	// ensureHolderLocked's documented bypass (in-process CLI, event
	// engine). It is still admission-bounded (busy case below).
	if _, err := store.CommitCheckAs(""); err != nil {
		t.Fatalf("CommitCheckAs(internal) = %v, want nil", err)
	}
	// The legacy CommitCheck() form is the internal form.
	if _, err := store.CommitCheck(); err != nil {
		t.Fatalf("CommitCheck() = %v, want nil", err)
	}
}

func TestCommitCheckAsBusy_16070(t *testing.T) {
	store := commitCheckHolderStore(t)

	// Hold the single compile slot directly, simulating an in-flight
	// full compile. A concurrent check — even from the holder — must
	// fail fast rather than queue a second full compile.
	store.commitCheckSem <- struct{}{}
	if _, err := store.CommitCheckAs("owner"); !errors.Is(err, ErrCommitCheckBusy) {
		t.Fatalf("CommitCheckAs(holder, slot held) = %v, want ErrCommitCheckBusy", err)
	}
	if _, err := store.CommitCheckAs(""); !errors.Is(err, ErrCommitCheckBusy) {
		t.Fatalf("CommitCheckAs(internal, slot held) = %v, want ErrCommitCheckBusy", err)
	}
	<-store.commitCheckSem

	// Slot released: the holder's check succeeds again, proving the busy
	// refusal is admission, not a wedge.
	if _, err := store.CommitCheckAs("owner"); err != nil {
		t.Fatalf("CommitCheckAs(holder, slot released) = %v, want nil", err)
	}
}
