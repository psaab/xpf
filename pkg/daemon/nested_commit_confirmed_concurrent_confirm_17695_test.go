package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #17695: a concurrent same-holder ConfirmCommit takes only the store
// lock (gRPC server_config.go ConfirmCommit has no applySem), clearing
// the pending window between the nested arm's target selection and
// its promotion. Without a confirmation-generation binding the arm
// still succeeds, now saving the unconfirmed active C2 — which the
// daemon never pre-flighted as the arm's target — as the rollback
// target, even though only the retained C1 was validated.
//
// These tests drive production commitConfirmedAndApply while a
// deterministic seam (d.beforeCommitConfirmedPromotionForTest) performs the
// confirm through the exact production confirmation path
// (ConfirmCommitPrincipalAs, as gRPC invokes it) at the exact defect
// point: after the arm's target capture/pre-flight, before its
// promotion. The store rejects the stale window generation; no retry is
// attempted with a target that has not passed the gates.
//
// FAIL-ON-REVERT: remove the confirmation-generation binding
// (RollbackTargetForArm snapshot generation + the under-lock
// comparison in CommitConfirmedGenAndConfirmAs + the daemon passing it)
// and TestNestedCommitConfirmedConcurrentConfirmDeterministic17695 reds:
// the nested arm succeeds while its saved rollback target is the
// un-preflighted feed-bound C2.
func TestNestedCommitConfirmedConcurrentConfirmDeterministic17695(t *testing.T) {
	d, s := newDaemon16668(t)
	if err := s.EnterConfigureSession("ops-session"); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()

	stage16668(t, s, healthyLines16668("c1-healthy")...)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit C1: %v", err)
	}
	if err := s.DeleteFromInput("security policies from-zone trust to-zone untrust policy p1 then permit"); err != nil {
		t.Fatalf("delete C1 permit: %v", err)
	}
	stage16668(t, s, feedLines16668("c2-feed")...)
	authority, err := s.AuthorizeCommit("ops-session")
	if err != nil {
		t.Fatalf("authorize C2: %v", err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), authority, 5, peerSyncNever); err != nil {
		t.Fatalf("first commit confirmed (C2 over healthy C1) must succeed: %v", err)
	}
	// Premise: pending window retains healthy C1; unconfirmed C2 is
	// the config the mirror refuses naming dyn1 (validated in the
	// #16668 cells against the same fixture).
	if !s.IsConfirmPending() {
		t.Fatal("window must be pending after first arm")
	}
	target, pending, first, _ := s.RollbackTargetForArm()
	if !pending || first || target == nil || target.System.HostName != "c1-healthy" {
		t.Fatalf("premise: retained target must be healthy C1, got target=%v pending=%v first=%v", target, pending, first)
	}

	// Deterministic concurrent confirm at the exact defect point:
	// after this arm's target capture/pre-flight, before promotion,
	// the same holder confirms C2 through the production path.
	var confirmErr error
	var confirmCalled bool
	var once sync.Once
	d.beforeCommitConfirmedPromotionForTest = func() {
		once.Do(func() {
			confirmCalled = true
			confirmErr = s.ConfirmCommitPrincipalAs("ops-session", "source=grpc;user=ops;class=super-user")
		})
	}
	defer func() { d.beforeCommitConfirmedPromotionForTest = nil }()

	authority, err = s.AuthorizeCommit("ops-session")
	if err != nil {
		t.Fatalf("authorize C3: %v", err)
	}
	_, armErr := d.commitConfirmedAndApply(context.Background(), authority, 5, peerSyncNever)

	if !confirmCalled {
		t.Fatal("deterministic confirm seam was not reached after rollback-target pre-flight")
	}
	if confirmErr != nil {
		t.Fatalf("concurrent confirm through production path must succeed (window was pending): %v", confirmErr)
	}
	if !errors.Is(armErr, configstore.ErrRollbackTargetChanged) {
		t.Fatalf("nested arm error = %v, want ErrRollbackTargetChanged after target generation changed", armErr)
	}
	// The arm was refused; nothing was promoted and no window may be
	// armed against C2.
	if got := s.ActiveConfig().System.HostName; got != "c2-feed" {
		t.Fatalf("refused nested arm promoted %q, want active unchanged at c2-feed (arm error: %v)", got, armErr)
	}
	target, pending, _, _ = s.RollbackTargetForArm()
	targetHost := ""
	if target != nil {
		targetHost = target.System.HostName
	}
	if pending && targetHost == "c2-feed" {
		t.Fatalf("refused nested arm still left a window saving un-preflighted C2 (arm error: %v)", armErr)
	}
	t.Logf("nested arm refused under deterministic concurrent confirm (safe outcome): %v", armErr)
}

// TestNestedCommitConfirmedConcurrentConfirmRace17695 is the
// supplementary unordered race shape of the same defect: the confirm
// runs in a free goroutine (exactly as gRPC drives it, without
// applySem) racing the full nested arm. Every interleaving outcome is
// asserted safe; no assertion depends on which side wins. Var
// duration makes one deterministic path dominate, so this is a
// supporting witness — the deterministic cell above is the RED gate.
func TestNestedCommitConfirmedConcurrentConfirmRace17695(t *testing.T) {
	d, s := newDaemon16668(t)
	if err := s.EnterConfigureSession("ops-session"); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()

	stage16668(t, s, healthyLines16668("c1-healthy")...)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit C1: %v", err)
	}
	if err := s.DeleteFromInput("security policies from-zone trust to-zone untrust policy p1 then permit"); err != nil {
		t.Fatalf("delete C1 permit: %v", err)
	}
	stage16668(t, s, feedLines16668("c2-feed")...)
	authority, err := s.AuthorizeCommit("ops-session")
	if err != nil {
		t.Fatalf("authorize C2: %v", err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), authority, 5, peerSyncNever); err != nil {
		t.Fatalf("first commit confirmed (C2 over healthy C1) must succeed: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("window must be pending after first arm")
	}

	stage16668(t, s, "system host-name c3-extend")
	authority, err = s.AuthorizeCommit("ops-session")
	if err != nil {
		t.Fatalf("authorize C3: %v", err)
	}
	confirmDone := make(chan error, 1)
	go func() {
		confirmDone <- s.ConfirmCommitPrincipalAs("ops-session", "source=grpc;user=ops;class=super-user")
	}()
	_, armErr := d.commitConfirmedAndApply(context.Background(), authority, 5, peerSyncNever)

	if cerr := <-confirmDone; cerr != nil {
		t.Logf("concurrent ConfirmCommitPrincipalAs: %v (no pending window by the time it ran is acceptable)", cerr)
	}

	target, pending, _, _ := s.RollbackTargetForArm()
	targetHost := ""
	if target != nil {
		targetHost = target.System.HostName
	}
	if armErr == nil {
		// A successful arm must be backed by a pending window whose
		// rollback target was actually pre-flighted: healthy C1,
		// never the un-preflighted feed-bound C2.
		if !pending {
			t.Fatalf("nested arm succeeded but no window is pending; confirm-cleared state was silently re-armed against %q", targetHost)
		}
		if targetHost == "c2-feed" {
			t.Fatal("nested arm saved un-preflighted C2 (feed-bound, refused naming dyn1) as its rollback target; " +
				"the daemon pre-flighted only the retained C1 that a concurrent confirm discarded (#17695)")
		}
		if targetHost != "c1-healthy" {
			t.Fatalf("nested arm succeeded with rollback target %q, want retained healthy c1-healthy", targetHost)
		}
		return
	}
	// A refused arm is the other safe outcome, provided nothing was
	// promoted and no window was armed against C2.
	if got := s.ActiveConfig().System.HostName; got != "c2-feed" {
		t.Fatalf("refused nested arm promoted %q, want active unchanged at c2-feed (arm error: %v)", got, armErr)
	}
	if pending && targetHost == "c2-feed" {
		t.Fatalf("refused nested arm still left a window saving un-preflighted C2 (arm error: %v)", armErr)
	}
	t.Logf("nested arm refused under concurrent confirm (safe outcome): %v", armErr)
}

// TestNestedCommitConfirmedFirstCommitNilTarget17695 pins the fresh-store
// first-commit target: it is nil, and the timer returns to bootstrap. The
// discarded pending/first flags made the safety contract implicit. The arm
// must succeed through the explicit bootstrap-target branch, preserve the nil
// target, and still run the candidate's device-map preflight.
func TestNestedCommitConfirmedFirstCommitNilTarget17695(t *testing.T) {
	d, s := newDaemon16668(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()

	// First-ever commit, armed: its window retains the nil
	// first-commit target by design.
	stage16668(t, s, healthyLines16668("first-only")...)
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("first commit confirmed must succeed: %v", err)
	}
	target, pending, first, _ := s.RollbackTargetForArm()
	if !pending || !first || target != nil {
		t.Fatalf("premise: first-commit window must retain nil first target, got target=%v pending=%v first=%v", target, pending, first)
	}

	// Nested arm extends the window; the nil first-commit target is
	// explicit (bootstrap rollback), never a silently-skipped gate.
	stage16668(t, s, "system host-name second")
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("nested first-commit arm must succeed (explicit nil bootstrap target): %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "second" {
		t.Fatalf("active = %q, want second", got)
	}
	target, pending, first, _ = s.RollbackTargetForArm()
	if !pending || !first || target != nil {
		t.Fatalf("after nested first-commit arm target=%v pending=%v first=%v, want nil first-commit target retained", target, pending, first)
	}
}

// TestNestedCommitConfirmedFirstCommitAfterRestart17695 covers the other
// first-commit target shape: after a first-commit rollback and restart, Load
// compiles the empty never-committed tree to a non-nil config while
// EverCommitted remains false (#7291). A confirmed commit still treats that
// target as bootstrap and must not reject it as a malformed non-first target
// or send the empty snapshot through rollback-specific gates.
func TestNestedCommitConfirmedFirstCommitAfterRestart17695(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	beforeRestart := newConfigStore(t, path)
	if err := beforeRestart.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := beforeRestart.LoadOverride("system { host-name before-restart; }"); err != nil {
		t.Fatalf("stage first config: %v", err)
	}
	if _, err := beforeRestart.CommitConfirmed(1); err != nil {
		t.Fatalf("first commit confirmed: %v", err)
	}
	beforeRestart.ExitConfigure()
	if _, ok := beforeRestart.PromoteRollback(beforeRestart.ConfirmGenForTesting()); !ok {
		t.Fatal("first-commit rollback did not promote")
	}

	afterRestart := newConfigStore(t, path)
	if err := afterRestart.Load(); err != nil {
		t.Fatalf("load after first-commit rollback: %v", err)
	}
	if afterRestart.EverCommitted() {
		t.Fatal("restart fixture must remain never-committed")
	}
	if afterRestart.ActiveConfig() == nil {
		t.Fatal("restart fixture must have a compiled empty config (#7291)")
	}

	d := &Daemon{applySem: semaphore.NewWeighted(1), store: afterRestart}
	d.applyBodyForTest = func(*config.Config) {}
	if err := afterRestart.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer afterRestart.ExitConfigure()
	t.Cleanup(func() { _ = afterRestart.ConfirmCommit() })
	if err := afterRestart.LoadOverride("system { host-name after-restart; }"); err != nil {
		t.Fatalf("stage post-restart config: %v", err)
	}
	target, pending, first, _ := afterRestart.RollbackTargetForArm()
	if pending || !first || target == nil {
		t.Fatalf("first target after restart = (%v, pending=%v, first=%v), want compiled first target", target, pending, first)
	}

	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("commit confirmed after never-committed restart must use bootstrap target: %v", err)
	}
	if got := afterRestart.ActiveConfig().System.HostName; got != "after-restart" {
		t.Fatalf("active host-name = %q, want after-restart", got)
	}
	target, pending, first, _ = afterRestart.RollbackTargetForArm()
	if !pending || !first || target == nil {
		t.Fatalf("armed rollback target after restart = (%v, pending=%v, first=%v), want non-nil first target retained", target, pending, first)
	}
}
