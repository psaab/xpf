package configstore

import (
	"errors"
	"path/filepath"
	"testing"
)

// #14990 (D38-02): AuthorizeCommitAs minted authorityInternal for a named
// session that held nothing (`!configDir` or effectiveHolder==""), and
// ForceExitConfigure did not mark the evicted holder reclaimed. A named
// session could therefore obtain an unexpiring internal authority and
// promote another operator's candidate after turnover. These cells pin
// the fail-closed behaviour; controls pin the neighbouring legitimate
// behaviour (#5059/#9632/#6808).

func TestAuthorizeCommitUnheldNamedSessionIsNotInternal14990(t *testing.T) {
	// Cell 1: not in config mode at all.
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := s.AuthorizeCommit("named-a")
	if err == nil {
		t.Fatalf("AuthorizeCommit(named, not in config mode) = nil (IsInternal=%v), want refusal", auth.IsInternal())
	}
	if !errors.Is(err, ErrConfigLockedByOther) {
		t.Fatalf("AuthorizeCommit(named, not in config mode) = %v, want ErrConfigLockedByOther", err)
	}
	if auth.IsInternal() {
		t.Fatal("unheld named session minted internal authority")
	}

	// Cell 2: internal/unowned candidate (EnterConfigure with "").
	s2, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s2.SetAs("", []string{"system", "host-name", "internal-host"}); err != nil {
		t.Fatal(err)
	}
	auth2, err := s2.AuthorizeCommit("named-b")
	if err == nil {
		t.Fatalf("AuthorizeCommit(named, unowned candidate) = nil (IsInternal=%v), want refusal", auth2.IsInternal())
	}
	if !errors.Is(err, ErrConfigLockedByOther) {
		t.Fatalf("AuthorizeCommit(named, unowned candidate) = %v, want ErrConfigLockedByOther", err)
	}
	// The internal candidate must not be promotable by that named session.
	_, gen, err := s2.CompileCandidateGen()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.CommitWithDescriptionGenAs(auth2, "", gen); err == nil {
		t.Fatal("named session promoted internal candidate with minted authority")
	}
	// Control: explicit internal still promotes the internal candidate.
	if _, err := s2.CommitWithDescriptionGenAs(InternalCommitter(), "", gen); err != nil {
		t.Fatalf("internal control commit: %v", err)
	}
	if got := hostName(t, s2); got != "internal-host" {
		t.Fatalf("hostName=%q want internal-host", got)
	}
}

func TestForceExitEvictedHolderCannotMintInternal14990(t *testing.T) {
	s := authTestStore(t, "sessionA")
	// Operator force-clears the lock (clear system config-lock).
	s.ForceExitConfigure()
	// Evicted holder must not be able to mint authority now.
	if _, err := s.AuthorizeCommit("sessionA"); !errors.Is(err, ErrConfigLockedByOther) {
		t.Fatalf("AuthorizeCommit(evicted after ForceExit) = %v, want ErrConfigLockedByOther", err)
	}
	// Another operator enters and stages work.
	if err := s.EnterConfigureSession("sessionB"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAs("sessionB", []string{"system", "host-name", "b-host"}); err != nil {
		t.Fatal(err)
	}
	// Evicted A still cannot mint (now also non-holder), and certainly not internal.
	authA, err := s.AuthorizeCommit("sessionA")
	if err == nil || authA.IsInternal() {
		t.Fatalf("AuthorizeCommit(evicted A while B holds) = (%v, internal=%v), want refusal non-internal", err, authA.IsInternal())
	}
	// Internal reclaims / takes over (unowned candidate).
	s.ExitConfigureSession("sessionB")
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAs("", []string{"system", "host-name", "internal2"}); err != nil {
		t.Fatal(err)
	}
	// A was force-evicted: reclaimed marking must refuse it on the unowned candidate (like #9632 lease reclaim).
	if _, err := s.AuthorizeCommit("sessionA"); !errors.Is(err, ErrConfigLockedByOther) {
		t.Fatalf("AuthorizeCommit(force-evicted A on internal candidate) = %v, want ErrConfigLockedByOther (reclaimed)", err)
	}
	if err := s.SetAs("sessionA", []string{"system", "host-name", "a-stale"}); !errors.Is(err, ErrConfigLockedByOther) {
		t.Fatalf("SetAs(force-evicted A on internal candidate) = %v, want ErrConfigLockedByOther", err)
	}
	// Controls: never-evicted named session may still edit internal candidate (#5059),
	// holder path still bound, internal still works.
	if err := s.SetAs("sessionC", []string{"system", "host-name", "c-host"}); err != nil {
		t.Fatalf("SetAs(never-evicted on internal) = %v, want nil (#5059 control)", err)
	}
	s.ExitConfigure()
	if err := s.EnterConfigureSession("sessionB"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAs("sessionB", []string{"system", "host-name", "b2"}); err != nil {
		t.Fatal(err)
	}
	authB, err := s.AuthorizeCommit("sessionB")
	if err != nil || authB.IsInternal() {
		t.Fatalf("AuthorizeCommit(holder B) = (%v, internal=%v), want bound holder", err, authB.IsInternal())
	}
	// Re-entering clears force-evicted mark for A.
	s.ExitConfigureSession("sessionB")
	if err := s.EnterConfigureSession("sessionA"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeCommit("sessionA"); err != nil {
		t.Fatalf("AuthorizeCommit(A after re-enter) = %v, want nil", err)
	}
}
