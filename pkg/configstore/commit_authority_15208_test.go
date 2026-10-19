package configstore

import (
	"errors"
	"path/filepath"
	"testing"
)

// #15208 (A19-02): an authority minted while NOBODY holds the config lock
// (a commit RPC from a session not in configure mode, or against an
// unowned internal candidate) must not promote a candidate that a holder
// stages afterwards. The #14990 mint gate already refuses a NAMED
// unheld session, and refuses a `!configDir` mint outright; the surviving
// arm is the EXPLICIT internal mint (`sessionID == ""` /
// InternalCommitterAs): verifyCommitAuthorityLocked accepted
// authorityInternal unconditionally, so any already-minted internal
// authority — however old, and under whatever journal principal —
// promoted whatever candidate existed at promotion time. That is the
// exact A19-02 trace one level down: X's authority is minted unheld,
// Y enters and stages a partial candidate, X's late promotion applies
// Y's work journalled to X's principal.
//
// These cells pin the fail-closed behaviour: an authority minted while
// the lock is unheld binds to the holder epoch at mint time, and any
// acquisition-or-later turnover before promotion refuses the commit
// with ErrConfigHolderTurnover (never a generation conflict, so the
// daemon's commitWithGenBinding retry cannot automate the
// substitution). Controls pin the neighbouring legitimate behaviour.

func TestA19InternalAuthorityMintedUnheldCannotPromoteLaterHolder15208(t *testing.T) {
	// Cell 1: minted BEFORE anyone enters configure mode (the A19-02
	// "Commit RPC from a session not in configure mode" arm).
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	// X is the explicit internal caller (sessionID == "") — the only
	// mint the #14990 gate still allows while unheld.
	auth, err := s.AuthorizeCommitAs("", "user:x")
	if err != nil {
		t.Fatalf("AuthorizeCommitAs(internal, unheld) = %v, want a mint (the internal path must still work)", err)
	}
	if !auth.IsInternal() {
		t.Fatal("internal mint must be internal")
	}
	// --- the turnover, in the window between mint and promotion ---
	// Y enters configure and stages a PARTIAL candidate.
	if err := s.EnterConfigureSession("sessionY"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAs("sessionY", []string{"system", "host-name", "y-partial"}); err != nil {
		t.Fatal(err)
	}
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatal(err)
	}
	// X's stale authority must not promote Y's candidate.
	if _, err := s.CommitWithDescriptionGenAs(auth, "", gen); !errors.Is(err, ErrConfigHolderTurnover) {
		t.Fatalf("stale unheld-minted authority promoted later holder = %v, want ErrConfigHolderTurnover (A19-02)", err)
	}
	if got := hostName(t, s); got == "y-partial" {
		t.Fatalf("Y's partial candidate was promoted under X's stale authority (host-name=%q)", got)
	}
	if got := hostName(t, s); got != "" {
		t.Fatalf("host-name = %q, want empty: a refused commit must not promote anything", got)
	}
	// A turnover must NEVER be reported as a generation conflict:
	// commitWithGenBinding retries that sentinel, which would
	// re-snapshot and promote the new holder's candidate automatically.
	if _, err := s.CommitWithDescriptionGenAs(auth, "", gen); errors.Is(err, ErrCandidateGenerationConflict) {
		t.Fatal("turnover reported as generation conflict; the daemon retry would automate the substitution")
	}
	// CommitConfirmed half: a separate entry point with the same check.
	if _, err := s.CommitConfirmedGenAs(auth, 5, gen); !errors.Is(err, ErrConfigHolderTurnover) {
		t.Fatalf("CommitConfirmed with stale authority = %v, want ErrConfigHolderTurnover", err)
	}
	if s.IsConfirmPending() {
		t.Fatal("a refused commit-confirmed armed the auto-rollback timer")
	}
	// Control: Y, the live holder, mints fresh and promotes its own work.
	authY, err := s.AuthorizeCommit("sessionY")
	if err != nil {
		t.Fatalf("AuthorizeCommit(holder Y) = %v, want nil (control)", err)
	}
	_, genY, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescriptionGenAs(authY, "", genY); err != nil {
		t.Fatalf("holder Y control commit = %v, want nil", err)
	}
	if got := hostName(t, s); got != "y-partial" {
		t.Fatalf("host-name after holder control = %q, want y-partial", got)
	}
}

func TestA19InternalAuthorityMintedUnownedCannotPromoteLaterHolder15208(t *testing.T) {
	// Cell 2: minted against an UNOWNED internal candidate
	// (EnterConfigure with ""). Same substitution shape: the mint saw
	// no holder, so a holder who takes over afterwards must invalidate it.
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil { // internal/unowned
		t.Fatal(err)
	}
	if err := s.SetAs("", []string{"system", "host-name", "internal-host"}); err != nil {
		t.Fatal(err)
	}
	auth, err := s.AuthorizeCommitAs("", "user:x")
	if err != nil {
		t.Fatalf("AuthorizeCommitAs(internal, unowned) = %v", err)
	}
	// Turnover: the internal candidate is discarded and Y takes the lock.
	s.ExitConfigure()
	if err := s.EnterConfigureSession("sessionY"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAs("sessionY", []string{"system", "host-name", "y-partial"}); err != nil {
		t.Fatal(err)
	}
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescriptionGenAs(auth, "", gen); !errors.Is(err, ErrConfigHolderTurnover) {
		t.Fatalf("unowned-minted authority promoted later holder = %v, want ErrConfigHolderTurnover (A19-02)", err)
	}
	if got := hostName(t, s); got == "y-partial" {
		t.Fatalf("Y's candidate promoted under stale unowned-minted authority")
	}
}

func TestA19EpochBoundInternalAuthorityControls15208(t *testing.T) {
	// Control 1: an internal authority minted while unheld and promoted
	// with NO intervening turnover still commits. System/daemon
	// commits (HA sync, event engine, bootstrap, tests) mint and
	// promote inside one apply-semaphore transaction with no lock
	// turnover in between; binding them to the mint epoch must not
	// refuse them.
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAs("", []string{"system", "host-name", "internal-host"}); err != nil {
		t.Fatal(err)
	}
	auth, err := s.AuthorizeCommitAs("", "system:test")
	if err != nil {
		t.Fatal(err)
	}
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitWithDescriptionGenAs(auth, "", gen); err != nil {
		t.Fatalf("no-turnover internal control commit = %v, want nil", err)
	}
	if got := hostName(t, s); got != "internal-host" {
		t.Fatalf("host-name = %q, want internal-host (control must reach promotion)", got)
	}

	// Control 2: the direct InternalCommitter()/InternalCommitterAs
	// constructors (no store round-trip at mint time) carry no epoch
	// binding and stay unconditional — they are how the HA-sync /
	// event-engine / bootstrap paths construct authority in-process,
	// and there is no mint-time lock state to bind.
	s2, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.EnterConfigureSession("sessionY"); err != nil {
		t.Fatal(err)
	}
	if err := s2.SetAs("sessionY", []string{"system", "host-name", "y-host"}); err != nil {
		t.Fatal(err)
	}
	_, gen2, err := s2.CompileCandidateGen()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.CommitWithDescriptionGenAs(InternalCommitter(), "", gen2); err != nil {
		t.Fatalf("direct InternalCommitter control = %v, want nil", err)
	}
	if got := hostName(t, s2); got != "y-host" {
		t.Fatalf("host-name = %q, want y-host", got)
	}

	// Control 3: a holder-bound authority is unaffected — unchanged
	// holder still commits (also pinned by #6808, kept here so this
	// file's controls are self-contained).
	s3 := authTestStore(t, "sessionA")
	authA, err := s3.AuthorizeCommit("sessionA")
	if err != nil {
		t.Fatal(err)
	}
	_, gen3, err := s3.CompileCandidateGen()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3.CommitWithDescriptionGenAs(authA, "", gen3); err != nil {
		t.Fatalf("holder control commit = %v, want nil", err)
	}
	if got := hostName(t, s3); got != "sessionA-host" {
		t.Fatalf("host-name = %q, want sessionA-host", got)
	}
}
