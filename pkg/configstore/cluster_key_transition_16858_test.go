package configstore

import (
	"strings"
	"testing"
)

// #16858 (R3-B04-02): the candidate-vs-active signing-key interlock at
// the Store boundary. Commit / CommitCheck (and therefore rollback and
// load override, which only stage the candidate) must refuse a signing
// key the active config does not already accept, and must admit every
// step of the #6630 five-step rotation. The tolerant ingresses
// (SyncApply / Load) must still boot a mismatched config (#1960).

const (
	transitionKeyA16858 = "alpha-key-0123456789abcdef"
	transitionKeyB16858 = "bravo-key-0123456789abcdef"
)

func commitCluster16858(t *testing.T, s *Store, primary, additional string) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{"chassis cluster cluster-id 1"}
	if primary != "" {
		lines = append(lines, "chassis cluster authentication-key "+primary)
	}
	if additional != "" {
		lines = append(lines, "chassis cluster additional-authentication-key "+additional)
	}
	// A fresh candidate starts empty; a re-commit after a previous
	// commit starts from the active clone, so delete the key leaves
	// first to make the staged shape exact.
	_ = s.DeleteFromInput("chassis cluster additional-authentication-key")
	for _, line := range lines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput %q: %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(signs %q, additional %q): %v", primary, additional, err)
	}
	s.ExitConfigure()
}

func stageCluster16858(t *testing.T, s *Store, primary, additional string) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_ = s.DeleteFromInput("chassis cluster authentication-key")
	_ = s.DeleteFromInput("chassis cluster additional-authentication-key")
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key " + primary,
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput %q: %v", line, err)
		}
	}
	if additional != "" {
		if err := s.SetFromInput("chassis cluster additional-authentication-key " + additional); err != nil {
			t.Fatalf("SetFromInput additional: %v", err)
		}
	}
}

// TestStoreOneShotKeyChangeRefused16858 is the Store-level RED cell:
// from active {A}, a one-shot `set authentication-key B; commit` (and
// commit check) must fail, leaving the active config untouched.
func TestStoreOneShotKeyChangeRefused16858(t *testing.T) {
	s := newTestStore(t)
	commitCluster16858(t, s, transitionKeyA16858, "")

	stageCluster16858(t, s, transitionKeyB16858, "")
	if _, err := s.CommitCheck(); err == nil {
		t.Fatal("CommitCheck accepted one-shot A->B; peer active {A} does not accept B (#16858)")
	} else if strings.Contains(err.Error(), transitionKeyA16858) || strings.Contains(err.Error(), transitionKeyB16858) {
		t.Fatalf("CommitCheck rejection leaked key material: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("Commit accepted one-shot A->B (#16858)")
	}
	s.ExitConfigure()
	// Active still signs A: a routine re-commit of A succeeds.
	commitCluster16858(t, s, transitionKeyA16858, "")
}

// TestStoreRollbackPastFinalizeRefused16858: walk the full rotation to
// the finalized {B} state, then `rollback 1` (pre-rotation {A} shape in
// history) staged + committed must be refused. Also covers rollback
// while the overlap is still open, which must be admitted.
func TestStoreRollbackPastFinalizeRefused16858(t *testing.T) {
	s := newTestStore(t)
	commitCluster16858(t, s, transitionKeyA16858, "")                  // {A}
	commitCluster16858(t, s, transitionKeyA16858, transitionKeyB16858) // signs A, accepts A+B
	commitCluster16858(t, s, transitionKeyB16858, transitionKeyA16858) // signs B, accepts B+A

	// Rollback while overlap open: history slot 1 is {signs A, A+B}.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.Rollback(1); err != nil {
		t.Fatalf("Rollback(1) while overlap open: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("rollback while overlap open must commit (control arm): %v", err)
	}
	s.ExitConfigure()

	// Re-finalize to {B}, then rollback to a pre-rotation {A} slot.
	commitCluster16858(t, s, transitionKeyB16858, transitionKeyA16858)
	commitCluster16858(t, s, transitionKeyB16858, "") // finalized {B}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Find a history slot whose tree signs A with no additional key:
	// walk slots via repeated rollback staging is destructive, so use
	// Rollback(2): slot1={signs B,A+B} (admitted), slot2={signs B only
	// pre-finalize?} — instead stage the exact pre-rotation shape by
	// rollback 3+ if present; fall back to asserting slot semantics
	// through CommitCheck on the staged candidate.
	rolled := false
	for n := 1; n <= 6; n++ {
		if err := s.Rollback(n); err != nil {
			continue
		}
		_, err := s.CommitCheck()
		if err != nil && strings.Contains(err.Error(), "does not already accept") {
			rolled = true
			break
		}
		// This slot is still accepted by {B} (signs B); keep looking
		// deeper for a pre-rotation {A} slot.
		_ = s.Rollback(0)
	}
	if !rolled {
		t.Fatal("no rollback slot from finalized {B} was refused; expected a pre-rotation {A} slot to hit the #16858 interlock")
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("Commit accepted rollback from finalized {B} to pre-rotation {A} (#16858)")
	}
	s.ExitConfigure()
}

// TestStoreLoadOverrideOneShotRefused16858: `load override` staging a
// {B} candidate over active {A} commits nothing until commit, and that
// commit must be refused.
func TestStoreLoadOverrideOneShotRefused16858(t *testing.T) {
	s := newTestStore(t)
	commitCluster16858(t, s, transitionKeyA16858, "")

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	text := "chassis {\n cluster {\n  cluster-id 1;\n  authentication-key " + transitionKeyB16858 + ";\n }\n}\n"
	if err := s.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride staging: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("Commit accepted load-override one-shot A->B (#16858)")
	}
	s.ExitConfigure()
}

// TestStoreRotationProcedureCommits16858 is the positive control at the
// Store boundary: every step of the documented rotation commits.
func TestStoreRotationProcedureCommits16858(t *testing.T) {
	s := newTestStore(t)
	s.SetNodeID(0) // clustered: also exercises the #9619 peer pipeline
	commitCluster16858(t, s, transitionKeyA16858, "")
	commitCluster16858(t, s, transitionKeyA16858, transitionKeyB16858)
	commitCluster16858(t, s, transitionKeyB16858, transitionKeyA16858)
	commitCluster16858(t, s, transitionKeyB16858, "")
}

// TestStoreSyncApplyMismatchedKeyBoots16858 pins #1960 on the sync
// ingress: a peer-pushed config signing B over a local active {A} still
// installs (the peer's commit is the strict boundary; refusing here
// would brick the standby).
func TestStoreSyncApplyMismatchedKeyBoots16858(t *testing.T) {
	s := newTestStore(t)
	commitCluster16858(t, s, transitionKeyA16858, "")
	text := "chassis {\n cluster {\n  cluster-id 1;\n  authentication-key " + transitionKeyB16858 + ";\n }\n}\n"
	cfg, err := s.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply refused a peer-pushed key change (no-brick violated): %v", err)
	}
	if cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal() != transitionKeyB16858 {
		t.Fatal("SyncApply did not install the peer signing key")
	}
}
