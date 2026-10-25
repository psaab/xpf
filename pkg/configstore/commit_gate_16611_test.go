package configstore

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16611: the #14981 commit-time expanded deny-configuration gate prices
// the candidate at interceptor time, but promotion re-snapshots whatever
// candidate exists after the daemon's applySem wait (and adopts it on
// generation conflict). A same-holder copy/rename landing in between
// was committed unadjudicated. These cells bind the priced generation
// into CommitAuthority and assert promotion refuses the changed tree.
//
// FAIL-ON-REVERT: drop verifyGateBindingLocked (or return nil from it)
// and the copy-between cells RED — the denied leaf is promoted.
//
// The denied leaf is `system host-name` (not a credential leaf) so the
// changed candidate COMPILES cleanly: only the gate, never the
// compiler, can refuse it. That keeps the cell honest — a compile
// failure would mask a missing gate check.

func gateCfg16611() *config.Config {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{Classes: []*config.LoginClass{{
		Name: "limited", Permissions: []string{"all"},
		DenyConfiguration: "system domain-name", DenyLeavesPresent: []string{"deny-configuration"},
	}}}
	return cfg
}

// gateStore16611 returns a store held by "limited-session" whose ACTIVE
// config carries an admin-authored group G carrying the denied leaf,
// plus the allowed active host-name it would override. The candidate
// starts as a clean clone of active (group defined, not applied).
func gateStore16611(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"groups G system domain-name evil16611",
		"system host-name base16611",
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("seed active %q: %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	s.ExitConfigure()
	if err := s.EnterConfigureSession("limited-session"); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	return s
}

func pricedAuthority16611(t *testing.T, s *Store) CommitAuthority {
	t.Helper()
	auth, err := s.AuthorizeCommit("limited-session")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	return auth.WithCommitGate(gateCfg16611(), "limited", s.CandidateGeneration(), s.ActiveTree())
}

func TestGateBoundCommitRefusesCopyBetweenGateAndPromotion16611(t *testing.T) {
	s := gateStore16611(t)
	auth := pricedAuthority16611(t, s)
	if !auth.GateBound() {
		t.Fatal("priced authority must be gate-bound")
	}
	// Same-holder mutation between gate and promotion: apply the
	// admin-authored denied group. This is the candidate state a
	// same-connection copy/apply-groups landing while the commit
	// waits on applySem produces.
	if err := s.SetAs("limited-session", []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("interleaved apply-groups: %v", err)
	}
	// Daemon mirror: re-snapshot the (changed) generation, exactly as
	// commitWithGenBinding does on its adopt-on-conflict retry.
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s.CommitWithDescriptionGenAs(auth, "", gen); err == nil {
		t.Fatal("gate-bound commit promoted a candidate changed after pricing (#16611)")
	} else if !errors.Is(err, ErrCommitCandidateChanged) && !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("changed-candidate refusal = %v, want the gate's permission denied or ErrCommitCandidateChanged, never a silent promotion", err)
	}
	if got := hostName(t, s); got != "base16611" {
		t.Fatalf("active host-name = %q, want unchanged base16611 (denied commit must not promote)", got)
	}

	// CommitConfirmed half: separate entry point, same binding.
	s2 := gateStore16611(t)
	auth2 := pricedAuthority16611(t, s2)
	if err := s2.SetAs("limited-session", []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("interleaved apply-groups (confirmed): %v", err)
	}
	_, gen2, err := s2.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen (confirmed): %v", err)
	}
	if _, err := s2.CommitConfirmedGenAs(auth2, 5, gen2); err == nil {
		t.Fatal("gate-bound commit-confirmed promoted a candidate changed after pricing (#16611)")
	} else if !errors.Is(err, ErrCommitCandidateChanged) && !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("changed-candidate commit-confirmed refusal = %v, want the gate's permission denied or ErrCommitCandidateChanged", err)
	}
	if s2.IsConfirmPending() {
		t.Fatal("refused commit-confirmed must not arm the confirm timer")
	}
	if got := hostName(t, s2); got != "base16611" {
		t.Fatalf("active host-name after refused commit-confirmed = %q, want base16611", got)
	}
}

// An allowed candidate change after pricing is still refused as
// *changed* — the operator re-issues and the new candidate is priced —
// but the same candidate unchanged commits. Both halves matter: never
// promote unpriced, never refuse priced.
func TestGateBoundCommitAllowedChangeRefusedAsChanged16611(t *testing.T) {
	s := gateStore16611(t)
	auth := pricedAuthority16611(t, s)
	if err := s.SetAs("limited-session", []string{"system", "services", "ssh"}); err != nil {
		t.Fatalf("allowed interleaved edit: %v", err)
	}
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s.CommitWithDescriptionGenAs(auth, "", gen); !errors.Is(err, ErrCommitCandidateChanged) {
		t.Fatalf("allowed-but-changed candidate = %v, want ErrCommitCandidateChanged", err)
	}
	// Re-priced at the new generation, the same work commits.
	auth2 := pricedAuthority16611(t, s)
	_, gen2, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen (re-priced): %v", err)
	}
	if _, err := s.CommitWithDescriptionGenAs(auth2, "", gen2); err != nil {
		t.Fatalf("re-priced allowed commit refused: %v", err)
	}
}

func TestGateBoundCommitUnchangedCandidateCommits16611(t *testing.T) {
	s := gateStore16611(t)
	if err := s.SetAs("limited-session", []string{"system", "services", "ssh"}); err != nil {
		t.Fatalf("allowed edit: %v", err)
	}
	auth := pricedAuthority16611(t, s)
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s.CommitWithDescriptionGenAs(auth, "", gen); err != nil {
		t.Fatalf("unchanged gate-bound commit refused: %v", err)
	}
	if got := hostName(t, s); got != "base16611" {
		t.Fatalf("active host-name = %q, want base16611", got)
	}
}

func TestGateBoundCommitBeforeCommitCopyStillRefused16611(t *testing.T) {
	// Control: the denied candidate priced AT the gate is refused by
	// the interceptor's own AuthorizeExpandedCandidate — the binding
	// must not weaken that (it only adds the promotion-time check).
	s := gateStore16611(t)
	if err := s.SetAs("limited-session", []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("apply-groups: %v", err)
	}
	if err := config.AuthorizeExpandedCandidate(gateCfg16611(), "limited", s.CandidateTree(), s.ActiveTree()); err == nil {
		t.Fatal("before-commit denied candidate ALLOWED by priced gate (control broken)")
	}
}

func TestUnrestrictedAuthorityUnaffected16611(t *testing.T) {
	s := gateStore16611(t)
	if err := s.SetAs("limited-session", []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("apply-groups: %v", err)
	}
	_, gen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	// Internal (unrestricted/system) authority carries no gate binding
	// and promotes the same candidate — the binding must not become a
	// global generation lock.
	if _, err := s.CommitWithDescriptionGenAs(InternalCommitter(), "", gen); err != nil {
		t.Fatalf("internal commit of changed candidate refused: %v", err)
	}
	if got := s.ShowActiveSet(); !strings.Contains(got, "domain-name evil16611") {
		t.Fatalf("internal commit active = %q, want domain-name evil16611 (control: promotion itself works)", got)
	}
	// A holder authority minted WITHOUT WithCommitGate (unrestricted
	// classes, whose handlers never bind) is likewise unbound.
	s2 := gateStore16611(t)
	auth2, err := s2.AuthorizeCommit("limited-session")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	if auth2.GateBound() {
		t.Fatal("unpriced authority must not be gate-bound")
	}
	if err := s2.SetAs("limited-session", []string{"system", "services", "ssh"}); err != nil {
		t.Fatalf("allowed edit: %v", err)
	}
	_, gen2, err := s2.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s2.CommitWithDescriptionGenAs(auth2, "", gen2); err != nil {
		t.Fatalf("unbound holder commit refused: %v", err)
	}
}
