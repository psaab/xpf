package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #16719 (R3-A19-02): the daemon-level race the store fix must close.
// A non-first `commit confirmed` (A -> C) is pending; the operator
// stages C' and issues a bare `commit`. The handler authorizes and
// computes the C->C' summary, then the commit parks on applySem. The
// confirm timer fires first: executeConfirmedRollback acquires
// applySem, PromoteRollback resets active/candidate to A and clears
// dirty — but (pre-fix) left the holder epoch unchanged, so when the
// parked commit acquired applySem it bound the RESET generation,
// promoted A as a no-op, applied it, and the handler returned
// success with the pre-rollback C->C' summary. The operator left
// believing C' was live and the window confirmed, while A ran and
// no timer remained.
//
// These cells drive the exact interleaving with the #15055 harness
// shape: the test holds applySem as the rollback executor's stand-in,
// parks the commit behind it, runs PromoteRollback, then releases.
// The parked commit must return ErrCommitConfirmedRolledBack with
// active=A and no apply — never success.
//
// RED-on-revert: dropping the discardedDirty capture in
// PromoteRollback (rollbackDiscardGen never advances) makes the internal
// cell promote A and return nil (compiled=A), and dropping the
// PromotionStale fence in commitWithGenBinding does the same even
// with the store token recorded; dropping the store-side
// verifyRollbackDiscardLocked makes the holder-authority cell
// promote A under the pre-rollback authority.

// nonFirstWindowStore16719 builds A committed, a commit-confirmed
// window over C, and C' staged dirty inside the window.
func nonFirstWindowStore16719(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
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
	s.ExitConfigure()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name staged; }"); err != nil {
		t.Fatalf("LoadOverride staged: %v", err)
	}
	if !s.IsDirty() {
		t.Fatal("premise: candidate must be dirty after staging C'")
	}
	return s
}

// parkCommit16719 holds applySem (the rollback executor's position),
// launches commitFn behind it, and waits until the commit is parked.
// The caller then runs the rollback half and calls release.
type commitResult16719 struct {
	cfg *config.Config
	err error
}

// parkCommit16719 holds applySem (the rollback executor's position),
// launches commitFn behind it, and waits until the commit is parked.
// The caller then runs the rollback half and calls release.
func parkCommit16719(t *testing.T, d *Daemon, commitFn func() (*config.Config, error)) (chan commitResult16719, func()) {
	t.Helper()
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("setup acquire: %v", err)
	}
	ch := make(chan commitResult16719, 1)
	go func() {
		cfg, err := commitFn()
		ch <- commitResult16719{cfg, err}
	}()
	// Let the commit pass its pre-Acquire checks and park on applySem.
	time.Sleep(100 * time.Millisecond)
	return ch, func() { d.applySem.Release(1) }
}

func TestNonFirstRollbackParkedInternalCommitIsRefused16719(t *testing.T) {
	s := nonFirstWindowStore16719(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	var applyCalls int
	d.applyBodyForTest = func(_ *config.Config) { applyCalls++ }
	s.SetRollbackExecutor(d.executeConfirmedRollback)

	resCh, release := parkCommit16719(t, d, func() (*config.Config, error) {
		return d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever)
	})

	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: non-first PromoteRollback must succeed")
	}
	release()
	res := <-resCh

	if !errors.Is(res.err, configstore.ErrCommitConfirmedRolledBack) {
		t.Fatalf("parked commit racing a dirty-discarding rollback = (cfg=%v, err=%v), want ErrCommitConfirmedRolledBack (#16719)", res.cfg, res.err)
	}
	if res.cfg != nil {
		t.Fatalf("refused commit must return no config; got %+v", res.cfg)
	}
	if applyCalls != 0 {
		t.Fatalf("refused commit must not apply a config to the dataplane; got %d apply calls", applyCalls)
	}
	if got := s.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("active after refused parked commit = %q, want A (the rollback target ran, not C')", got)
	}
	if s.IsConfirmPending() {
		t.Fatal("rollback must have consumed the confirm window; no timer may remain")
	}
	if !s.EverCommitted() {
		t.Fatal("non-first rollback must keep everCommitted=true")
	}
	s.ExitConfigure()
}

func TestNonFirstRollbackParkedHolderCommitIsRefused16719(t *testing.T) {
	// Holder-authority arm: the gRPC/REST shape. The transport mints
	// the authority BEFORE commitFn (AuthorizeCommitAs in the
	// handler), so the mint predates the rollback even though the
	// daemon fence is also present. Either fence refusing suffices;
	// this cell pins that the refusal is the rolled-back error and
	// active stays at A.
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
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
	if err := s.LoadOverride("system { host-name C; }"); err != nil {
		t.Fatalf("LoadOverride C: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed C: %v", err)
	}
	if err := s.LoadOverride("system { host-name staged; }"); err != nil {
		t.Fatalf("LoadOverride staged: %v", err)
	}
	authority, err := s.AuthorizeCommit("op")
	if err != nil {
		t.Fatalf("AuthorizeCommit: %v", err)
	}
	if authority.IsInternal() {
		t.Fatal("premise: holder authority must be bound, not internal")
	}

	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	var applyCalls int
	d.applyBodyForTest = func(_ *config.Config) { applyCalls++ }

	resCh, release := parkCommit16719(t, d, func() (*config.Config, error) {
		return d.commitAndApply(context.Background(), authority, "", peerSyncNever)
	})
	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: non-first PromoteRollback must succeed")
	}
	release()
	res := <-resCh

	if !errors.Is(res.err, configstore.ErrCommitConfirmedRolledBack) {
		t.Fatalf("parked holder commit racing a dirty rollback = (cfg=%v, err=%v), want ErrCommitConfirmedRolledBack", res.cfg, res.err)
	}
	if errors.Is(res.err, configstore.ErrCandidateGenerationConflict) {
		t.Fatal("refusal must not be a generation conflict; the daemon retry would adopt the reset candidate")
	}
	if res.cfg != nil {
		t.Fatalf("refused holder commit must return no config; got %+v", res.cfg)
	}
	if applyCalls != 0 {
		t.Fatalf("refused holder commit must not apply; got %d apply calls", applyCalls)
	}
	if got := s.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("active = %q, want A", got)
	}
	s.ExitConfigureSession("op")
}

// TestNonFirstCommitNoTimeoutControl16719 is the twin control from
// the probe: the SAME parked-commit shape WITHOUT the timeout still
// promotes and applies C'. The fence must not refuse legitimate
// traffic that merely waited on applySem.
func TestNonFirstCommitNoTimeoutControl16719(t *testing.T) {
	s := nonFirstWindowStore16719(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	var lastApplied string
	d.applyBodyForTest = func(cfg *config.Config) {
		if cfg != nil {
			lastApplied = cfg.System.HostName
		}
	}

	resCh, release := parkCommit16719(t, d, func() (*config.Config, error) {
		return d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever)
	})
	// No PromoteRollback: release straight away.
	release()
	res := <-resCh

	if res.err != nil {
		t.Fatalf("no-timeout control commit must succeed; got %v", res.err)
	}
	if res.cfg == nil || res.cfg.System.HostName != "staged" {
		t.Fatalf("control must return the staged config; got %+v", res.cfg)
	}
	if got := s.ActiveConfig().System.HostName; got != "staged" {
		t.Fatalf("active after control = %q, want staged", got)
	}
	if lastApplied != "staged" {
		t.Fatalf("control must apply staged; last applied = %q", lastApplied)
	}
	if s.IsConfirmPending() {
		t.Fatal("plain commit inside the window must confirm it (#3861)")
	}
	s.ExitConfigure()
}

// TestNonFirstRollbackParkedCommitConfirmedIsRefused16719 pins the
// commit-confirmed analogue: a parked `commit confirmed` must not
// re-arm a window over the rollback-reset candidate after its staged
// candidate was discarded.
func TestNonFirstRollbackParkedCommitConfirmedIsRefused16719(t *testing.T) {
	s := nonFirstWindowStore16719(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}

	resCh, release := parkCommit16719(t, d, func() (*config.Config, error) {
		return d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever)
	})
	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("premise: PromoteRollback must succeed")
	}
	release()
	res := <-resCh

	if !errors.Is(res.err, configstore.ErrCommitConfirmedRolledBack) {
		t.Fatalf("parked commit-confirmed racing a dirty rollback = (cfg=%v, err=%v), want ErrCommitConfirmedRolledBack", res.cfg, res.err)
	}
	if s.IsConfirmPending() {
		t.Fatal("refused commit-confirmed must not arm a new rollback window over the reset candidate")
	}
	if got := s.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("active = %q, want A", got)
	}
	s.ExitConfigure()
}
