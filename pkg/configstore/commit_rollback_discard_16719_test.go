package configstore

import (
	"errors"
	"path/filepath"
	"testing"
)

// #16719 (R3-A19-02): a NON-first commit-confirmed timeout that wins
// applySem over a parked commit with staged edits lets the commit
// promote the rolled-back config and report success with the
// pre-rollback change summary. The #15055 epoch bump was scoped to
// the first-commit branch, so an ordinary (non-first) rollback reset
// the candidate to the rollback target, cleared dirty, and left the
// holder epoch unchanged — a commit authorized before the timeout
// (AuthorizeCommit, then parked on the daemon apply semaphore)
// therefore verified, bound the RESET generation in
// commitWithGenBinding, promoted the rollback target as a no-op, and
// the handler returned "commit complete: N statement(s) changed"
// for edits that were discarded.
//
// The fix records the discard in PromoteRollback whenever the
// rollback actually discarded a dirty candidate (rollbackDiscardGen
// = the holderEpoch at discard time) and:
//   - verifyCommitAuthorityLocked refuses a store-minted authority
//     minted before the discard with ErrCommitConfirmedRolledBack
//     (never a generation conflict, so the daemon retry cannot adopt
//     the reset candidate, and never a holder turnover, because the
//     holder did not change — the edits are gone);
//   - a clean (non-dirty) rollback discards nothing and must NOT
//     invalidate the holder (the #15055 neighbouring control);
//   - a fresh authority minted AFTER the discard over the reset
//     candidate still promotes — only pre-discard mints are stale.
//
// RED-on-revert: dropping the discardedDirty capture in
// PromoteRollback leaves rollbackDiscardGen at 0, so the race cells
// below promote the rollback target and report success instead of
// ErrCommitConfirmedRolledBack.

// nonFirstDirtyWindow16719 builds the #16719 premise: active=A, a
// commit-confirmed window armed over C (confirmPrev=A), and a dirty
// candidate C' staged inside the window. The store is left in
// configure mode held by "op" with C' staged.
func nonFirstDirtyWindow16719(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigureSession("op"); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	if err := s.LoadOverride("system { host-name A; }"); err != nil {
		t.Fatalf("LoadOverride A: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if err := s.LoadOverride("system { host-name C; }"); err != nil {
		t.Fatalf("LoadOverride C: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed C: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("premise: confirm window must be pending after CommitConfirmed")
	}
	// Stage C' inside the window — the edits the parked commit will
	// try to promote after the timeout discards them.
	if err := s.LoadOverride("system { host-name staged; }"); err != nil {
		t.Fatalf("LoadOverride staged: %v", err)
	}
	if !s.IsDirty() {
		t.Fatal("premise: candidate must be dirty after staging C'")
	}
	return s
}

func TestNonFirstRollbackDiscardingDirtyCandidateInvalidatesPreRollbackAuthority16719(t *testing.T) {
	s := nonFirstDirtyWindow16719(t)

	// Mint the commit authority exactly as a transport does
	// immediately before invoking the daemon commit — before the
	// timeout fires, while C' is staged.
	authority, err := s.AuthorizeCommit("op")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	if authority.IsInternal() {
		t.Fatal("premise: holder authority must be bound, not internal")
	}
	epochBefore := s.HolderEpoch()

	// The timeout wins: PromoteRollback resets the candidate to A.
	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: non-first PromoteRollback must succeed")
	}
	if got := s.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("active after rollback = %q, want A (the rollback target)", got)
	}
	if s.IsDirty() {
		t.Fatal("premise: rollback must clear dirty (candidate reset to A)")
	}
	if s.IsConfirmPending() {
		t.Fatal("premise: rollback must consume the confirm window")
	}
	// The holder did NOT turn over, so holderEpoch itself must not
	// have advanced (that is what distinguishes this from a holder
	// turnover and from the first-commit #15055 bump); the discard is
	// recorded on the dedicated rollbackDiscardGen counter instead.
	if got := s.HolderEpoch(); got != epochBefore {
		t.Fatalf("non-first dirty rollback must not bump holderEpoch (before=%d after=%d); "+
			"the holder did not change — only its staged edits were discarded", epochBefore, got)
	}
	if s.RollbackDiscardGen() == 0 {
		t.Fatal("dirty-discarding rollback must advance rollbackDiscardGen")
	}

	// The parked commit now binds the RESET generation (as
	// commitWithGenBinding does after acquiring applySem) and tries
	// to promote. It must be refused with the rolled-back sentinel,
	// never a generation conflict (the daemon would retry and adopt
	// the reset candidate) and never a holder turnover.
	_, curGen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	_, err = s.CommitWithDescriptionGenAs(authority, "", curGen)
	if !errors.Is(err, ErrCommitConfirmedRolledBack) {
		t.Fatalf("pre-rollback authority after dirty rollback = %v, want ErrCommitConfirmedRolledBack (#16719)", err)
	}
	if errors.Is(err, ErrCandidateGenerationConflict) {
		t.Fatal("rolled-back refusal must not be a generation conflict; the daemon retry would adopt the reset candidate")
	}
	if errors.Is(err, ErrConfigHolderTurnover) {
		t.Fatal("rolled-back refusal must not be a holder turnover; the holder never changed")
	}
	// CommitConfirmed half: the same authority must not re-arm a
	// window over the reset candidate either.
	if _, err := s.CommitConfirmedGenAs(authority, 5, curGen); !errors.Is(err, ErrCommitConfirmedRolledBack) {
		t.Fatalf("CommitConfirmed with pre-rollback authority = %v, want ErrCommitConfirmedRolledBack", err)
	}
	if s.IsConfirmPending() {
		t.Fatal("a refused commit-confirmed must not arm a rollback timer")
	}
	// Nothing was promoted beyond the rollback itself.
	if got := s.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("active after refused commit = %q, want A (no success for discarded edits)", got)
	}
	s.ExitConfigureSession("op")
}

// TestNonFirstCleanRollbackKeepsHolderAuthority16719 is the
// neighbouring-behaviour control (the #15055 scoping, preserved): a
// non-first rollback over a CLEAN candidate discards nothing, so the
// holder's pre-rollback authority stays valid and a fresh commit over
// the reset candidate still promotes.
func TestNonFirstCleanRollbackKeepsHolderAuthority16719(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigureSession("op"); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name A; }"); err != nil {
		t.Fatalf("LoadOverride A: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if err := s.LoadOverride("system { host-name C; }"); err != nil {
		t.Fatalf("LoadOverride C: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed C: %v", err)
	}
	if s.IsDirty() {
		t.Fatal("premise: candidate must be clean inside the window before edits")
	}
	authority, err := s.AuthorizeCommit("op")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	epochBefore := s.HolderEpoch()
	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: clean non-first PromoteRollback must succeed")
	}
	if got := s.HolderEpoch(); got != epochBefore {
		t.Fatalf("clean rollback must not bump holderEpoch (before=%d after=%d)", epochBefore, got)
	}
	if s.RollbackDiscardGen() != 0 {
		t.Fatalf("clean rollback must not record a discard; got rollbackDiscardGen=%d", s.RollbackDiscardGen())
	}
	// The pre-rollback authority still promotes the reset candidate:
	// stage a fresh edit and commit it under the SAME authority.
	if err := s.LoadOverride("system { host-name after; }"); err != nil {
		t.Fatalf("LoadOverride after: %v", err)
	}
	_, curGen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s.CommitWithDescriptionGenAs(authority, "", curGen); err != nil {
		t.Fatalf("pre-rollback authority after a CLEAN rollback must still commit: %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "after" {
		t.Fatalf("active after clean-rollback commit = %q, want after", got)
	}
	s.ExitConfigureSession("op")
}

// TestFreshAuthorityAfterDirtyRollbackStillCommits16719 pins that
// only PRE-discard mints are stale: an authority minted after the
// rollback, over the reset candidate, promotes normally — the fix
// must not wedge the holder out of its own (reset) candidate.
func TestFreshAuthorityAfterDirtyRollbackStillCommits16719(t *testing.T) {
	s := nonFirstDirtyWindow16719(t)
	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: PromoteRollback must succeed")
	}
	// Re-stage and mint fresh, as an operator who re-issues the
	// commit after seeing the rolled-back error would.
	if err := s.LoadOverride("system { host-name restaged; }"); err != nil {
		t.Fatalf("LoadOverride restaged: %v", err)
	}
	fresh, err := s.AuthorizeCommit("op")
	if err != nil {
		t.Fatalf("AuthorizeCommit fresh: %v", err)
	}
	_, curGen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s.CommitWithDescriptionGenAs(fresh, "", curGen); err != nil {
		t.Fatalf("fresh authority after dirty rollback must commit: %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "restaged" {
		t.Fatalf("active after fresh commit = %q, want restaged", got)
	}
	s.ExitConfigureSession("op")
}

// TestPromotionStaleTracksDirtyDiscard16719 pins the daemon fence
// token directly: PromotionStale is false before any discard, true
// for a pre-discard sample after a dirty rollback, and false again
// for a sample taken after the discard (a commit that started after
// the rollback examines the reset candidate legitimately).
func TestPromotionStaleTracksDirtyDiscard16719(t *testing.T) {
	s := nonFirstDirtyWindow16719(t)
	before := s.RollbackDiscardGen()
	if s.PromotionStale(before) {
		t.Fatal("PromotionStale must be false before any rollback")
	}
	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: PromoteRollback must succeed")
	}
	if !s.PromotionStale(before) {
		t.Fatal("PromotionStale must be true for a pre-discard sample after a dirty rollback")
	}
	after := s.RollbackDiscardGen()
	if after == 0 {
		t.Fatal("dirty rollback must record a non-zero discard epoch")
	}
	if s.PromotionStale(after) {
		t.Fatal("PromotionStale must be false for a sample taken after the discard")
	}
	s.ExitConfigureSession("op")
}
