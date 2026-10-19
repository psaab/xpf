package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #15055 (A32-02): the plain-commit bootstrap gate in commitAndApply was
// tested BEFORE applySem.Acquire and never re-tested. A plain commit that
// checked the gate while a first commit-confirmed rollback was mid-flight
// (executor holding applySem, bootstrapMode not yet stored) parked on
// applySem; PromoteRollback then reset the candidate to the empty rollback
// tree, bumped its generation and cleared everCommitted, and
// enterBootstrapMode set bootstrapMode. When the parked commit finally
// acquired applySem it bound the RESET generation inside
// commitWithGenBinding and promoted the empty candidate — reporting
// success, persisting committed=1-empty, so the next boot classified
// NORMAL instead of bootstrap. The operator's staged edits were replaced
// by an empty config while success was reported — the exact state
// #1922 Item 1b / #7291 exist to prevent.
//
// Fix: re-test inBootstrap() after applySem.Acquire (before any store
// promotion), and bump holderEpoch on the first-commit PromoteRollback so
// a commit authority minted before the rollback cannot promote under it
// afterwards (holder-session leg; InternalCommitter is deliberately
// unconditional and is stopped by the daemon gate instead).
//
// RED-on-revert: removing the post-Acquire recheck makes the parked commit
// promote the reset empty candidate (err==nil, EverCommitted()==true,
// reloaded everCommitted==true) and the first test reds; removing the
// holderEpoch bump reds the second test.

// TestPlainCommitParkedBehindFirstCommitRollbackIsRefused15055 drives the
// exact race. The test holds applySem as the rollback executor's stand-in
// (executeConfirmedRollback acquires it for the whole PromoteRollback +
// enterBootstrapMode transaction), parks the plain commit behind it — the
// commit passes the pre-Acquire gate while bootstrap is still false —
// then runs the rollback's real store and daemon halves
// (PromoteRollback + enterBootstrapModeWithLifeline) and releases the
// semaphore. The parked commit must then be refused by the post-Acquire
// recheck instead of promoting the reset empty candidate.
func TestPlainCommitParkedBehindFirstCommitRollbackIsRefused15055(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "xpf.conf")
	s, err := configstore.New(path)
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.bootstrapTeardownForTest = func() []bootstrapTeardownStep { return nil }
	var applyCalls int
	d.applyBodyForTest = func(_ *config.Config) { applyCalls++ }
	s.SetRollbackExecutor(d.executeConfirmedRollback)

	// First commit-confirmed on a fresh store — the takeover that will
	// time out. The daemon is NOT in bootstrap, so a plain commit's
	// pre-Acquire gate passes at this point.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	s.ExitConfigure()
	if d.inBootstrap() {
		t.Fatal("premise: daemon must not be in bootstrap before the timeout")
	}

	// Stage the operator's plain-commit candidate edit.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name staged; }"); err != nil {
		t.Fatalf("LoadOverride staged: %v", err)
	}

	// Hold applySem (the rollback executor's position), park the plain
	// commit behind it, then run the rollback halves and release.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("setup acquire: %v", err)
	}
	type result struct {
		cfg *config.Config
		err error
	}
	resCh := make(chan result, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cfg, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever)
		resCh <- result{cfg, err}
	}()
	// Let the commit pass the pre-Acquire gate and park on applySem.
	time.Sleep(100 * time.Millisecond)

	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: first-commit PromoteRollback must succeed")
	}
	if err := d.enterBootstrapModeWithLifeline(true); err != nil {
		t.Fatalf("enterBootstrapModeWithLifeline: %v", err)
	}
	d.applySem.Release(1)
	wg.Wait()
	res := <-resCh

	if !d.inBootstrap() {
		t.Fatal("after first-commit rollback timeout, daemon must be in BOOTSTRAP mode")
	}
	if res.err == nil || !strings.Contains(res.err.Error(), "bootstrap") {
		t.Fatalf("plain commit racing the first-commit-confirmed timeout must return the bootstrap error; got cfg=%v err=%v", res.cfg, res.err)
	}
	if res.cfg != nil {
		t.Fatalf("refused plain commit must return no config; got %+v", res.cfg)
	}
	if applyCalls != 0 {
		t.Fatalf("refused plain commit must not apply a config to the dataplane; got %d apply calls", applyCalls)
	}
	if s.EverCommitted() {
		t.Fatal("in-memory store has everCommitted=true after the refused commit")
	}
	if got := s.ActiveConfig(); got != nil && got.System.HostName == "staged" {
		t.Fatal("parked plain commit promoted the staged candidate despite the bootstrap rollback")
	}
	// The reloaded store has everCommitted=false: the rollback's
	// committed=0 empty state must NOT be overwritten by a committed=1
	// empty promotion from the parked commit.
	s2, err := configstore.New(path)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	if err := s2.Load(); err != nil {
		t.Fatalf("reload Load: %v", err)
	}
	if s2.EverCommitted() {
		t.Fatal("reloaded store has everCommitted=true; the parked plain commit persisted committed=1-empty (next boot would classify NORMAL)")
	}
	s.ExitConfigure()
}

// TestFirstCommitPromoteRollbackBumpsHolderEpoch15055 pins the second fix
// leg: PromoteRollback on a first-commit window advances holderEpoch, so a
// commit authority minted for a holder session BEFORE the rollback fails
// verification at promotion (holder-turnover) instead of promoting the
// reset candidate under the pre-rollback holder's authority.
func TestFirstCommitPromoteRollbackBumpsHolderEpoch15055(t *testing.T) {
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigureSession("op"); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	// Mint a holder-bound authority for the still-holding session, as a
	// transport does immediately before invoking the daemon commit.
	authority, err := s.AuthorizeCommit("op")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	if authority.IsInternal() {
		t.Fatal("premise: holder authority must be bound, not internal")
	}
	epochBefore := s.HolderEpoch()

	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: first-commit PromoteRollback must succeed")
	}
	if got := s.HolderEpoch(); got == epochBefore {
		t.Fatalf("first-commit PromoteRollback must bump holderEpoch (before=%d after=%d); a pre-rollback holder authority would still verify", epochBefore, got)
	}
	if s.EverCommitted() {
		t.Fatal("premise: first-commit rollback must clear everCommitted")
	}
	// The pre-rollback authority must now fail at promotion on the
	// generation the daemon would bind (the reset candidate's current
	// generation, re-staged here as a post-rollback commit attempt would).
	if err := s.LoadOverride("system { host-name staged; }"); err != nil {
		t.Fatalf("LoadOverride staged: %v", err)
	}
	_, curGen, err := s.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if _, err := s.CommitWithDescriptionGenAs(authority, "", curGen); err == nil {
		t.Fatal("commit under a pre-rollback holder authority must be refused after the first-commit rollback")
	} else if !strings.Contains(err.Error(), "changed hands") {
		t.Fatalf("pre-rollback authority refusal must be the holder-turnover error; got %v", err)
	}
	s.ExitConfigureSession("op")
}

// TestNonFirstPromoteRollbackDoesNotBumpHolderEpoch15055 is the
// neighbouring-behaviour control for the epoch leg: an ordinary
// (non-first) rollback keeps the holder's authority valid — the epoch
// advance is scoped to the first-commit candidate reset.
func TestNonFirstPromoteRollbackDoesNotBumpHolderEpoch15055(t *testing.T) {
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
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
	if err := s.LoadOverride("system { host-name B; }"); err != nil {
		t.Fatalf("LoadOverride B: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed B: %v", err)
	}
	epochBefore := s.HolderEpoch()
	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: non-first PromoteRollback must succeed")
	}
	if got := s.HolderEpoch(); got != epochBefore {
		t.Fatalf("non-first PromoteRollback must not bump holderEpoch (before=%d after=%d)", epochBefore, got)
	}
	if !s.EverCommitted() {
		t.Fatal("non-first rollback must keep everCommitted=true")
	}
	s.ExitConfigureSession("op")
}

// TestPlainCommitAfterBootstrapEnteredIsRefused15055 is the named control:
// once bootstrap has been entered (no race), a plain commit is refused by
// the gate and commit-confirmed remains the escape hatch. This must stay
// green before and after the fix.
func TestPlainCommitAfterBootstrapEnteredIsRefused15055(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.bootstrapTeardownForTest = func() []bootstrapTeardownStep { return nil }
	d.applyBodyForTest = func(_ *config.Config) {}
	d.bootstrapMode.Store(true)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("plain commit in bootstrap = %v, want bootstrap-mode refusal", err)
	}
	if s.EverCommitted() {
		t.Fatal("refused plain commit must not mark the store everCommitted")
	}
	// commit-confirmed is the legitimate escape hatch and must succeed.
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("commit-confirmed in bootstrap must succeed: %v", err)
	}
	if !s.EverCommitted() {
		t.Fatal("successful commit-confirmed must mark the store everCommitted")
	}
	s.ExitConfigure()
}

// TestPlainCommitNotInBootstrapStillSucceeds15055 is the legitimate-traffic
// control: with bootstrap never entered, a plain commit through the same
// code path still promotes and applies the staged candidate.
func TestPlainCommitNotInBootstrapStillSucceeds15055(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}

	compiled, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever)
	if err != nil {
		t.Fatalf("plain commit outside bootstrap must succeed; got %v", err)
	}
	if compiled == nil || compiled.System.HostName != "NEW" {
		t.Fatalf("plain commit must return the committed NEW config; got %+v", compiled)
	}
	if got := s.ActiveConfig().System.HostName; got != "NEW" {
		t.Fatalf("active host-name = %q, want NEW", got)
	}
	if !s.EverCommitted() {
		t.Fatal("successful plain commit must leave everCommitted=true")
	}
}
