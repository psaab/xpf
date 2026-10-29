package configstore

import (
	"errors"
	"testing"
)

// #17695: a same-holder ConfirmCommit can clear the rollback window without
// taking the daemon apply semaphore. A commit-confirmed promotion that already
// pre-flighted the retained target must reject the captured stale window token
// rather than re-arm against the now-active, unexamined config.
//
// FAIL-ON-REVERT: remove the expected confirmGen comparison from
// CommitConfirmedGenAndConfirmAs and this test promotes C3 and arms a new
// rollback window after its preflighted C1 target was discarded.
func TestCommitConfirmedGenRejectsChangedRollbackWindow17695(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigureSession("ops-session"); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()
	t.Cleanup(func() { _ = s.ConfirmCommit() })

	if err := s.SetFromInput("system host-name c1"); err != nil {
		t.Fatalf("stage C1: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit C1: %v", err)
	}
	if err := s.SetFromInput("system host-name c2"); err != nil {
		t.Fatalf("stage C2: %v", err)
	}
	_, c2Gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("compile C2: %v", err)
	}
	c2Authority, err := s.AuthorizeCommit("ops-session")
	if err != nil {
		t.Fatalf("authorize C2: %v", err)
	}
	if _, err := s.CommitConfirmedGenAs(c2Authority, 5, c2Gen); err != nil {
		t.Fatalf("arm C2 over C1: %v", err)
	}
	if err := s.SetFromInput("system host-name c3"); err != nil {
		t.Fatalf("stage C3: %v", err)
	}
	_, candidateGen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("compile C3: %v", err)
	}
	target, pending, first, confirmGen := s.RollbackTargetForArm()
	if !pending || first || target == nil || target.System.HostName != "c1" {
		t.Fatalf("precondition: target=%v pending=%v first=%v, want retained C1", target, pending, first)
	}

	authority, err := s.AuthorizeCommit("ops-session")
	if err != nil {
		t.Fatalf("authorize C3: %v", err)
	}
	if err := s.ConfirmCommitPrincipalAs("ops-session", "source=grpc;user=ops;class=super-user"); err != nil {
		t.Fatalf("confirm C2 through production path: %v", err)
	}
	if _, err := s.CommitConfirmedGenAndConfirmAs(authority, 5, candidateGen, confirmGen); !errors.Is(err, ErrRollbackTargetChanged) {
		t.Fatalf("commit-confirmed after target confirmation = %v, want ErrRollbackTargetChanged", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "c2" {
		t.Fatalf("stale-target refusal promoted %q, want active C2 unchanged", got)
	}
	if s.IsConfirmPending() {
		t.Fatal("stale-target refusal armed a new rollback window")
	}
}
