package daemon

import (
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// TestFirstCommitRollbackEntersBootstrap proves #1922 Item 1b at the daemon
// level: a FIRST commit confirmed on a fresh store, timed out in SERVICE mode
// (no interactive shell), drives executeConfirmedRollback down the
// prevCfg==nil branch, which calls enterBootstrapMode — re-arming bootstrap
// suppression — WITHOUT applying an empty config to the dataplane.
func TestFirstCommitRollbackEntersBootstrap(t *testing.T) {
	isolateFirstCommitRollbackHostAuth12169(t)
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}

	// Body seam: the dataplane apply must NEVER be called on the first-commit
	// rollback (prevCfg==nil) — enterBootstrapMode handles teardown, not a
	// normal apply.
	var applyCalls int
	d.applyBodyForTest = func(_ *config.Config) { applyCalls++ }

	s.SetRollbackExecutor(d.executeConfirmedRollback)

	// First commit confirmed on a fresh store.
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
		t.Fatal("daemon should not be in bootstrap before the timeout")
	}

	// Fire the rollback timer's executor branch deterministically.
	gen := s.ConfirmGenForTesting()
	s.InvokeRollbackTimerForTesting(gen)

	if !d.inBootstrap() {
		t.Fatal("after first-commit rollback timeout, daemon must be in BOOTSTRAP mode")
	}
	if applyCalls != 0 {
		t.Fatalf("first-commit rollback must NOT apply a config to the dataplane; got %d apply calls", applyCalls)
	}
	if s.EverCommitted() {
		t.Fatal("after first-commit rollback, store must read never-committed")
	}
}

// TestNonFirstCommitRollbackDoesNotEnterBootstrap proves the regression
// boundary: a rollback that reverts to a REAL prior config (prevCfg != nil)
// re-applies that config and does NOT enter bootstrap mode.
func TestNonFirstCommitRollbackDoesNotEnterBootstrap(t *testing.T) {
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}

	var lastApplied string
	d.applyBodyForTest = func(cfg *config.Config) {
		if cfg != nil {
			lastApplied = cfg.System.HostName
		}
	}
	s.SetRollbackExecutor(d.executeConfirmedRollback)

	// First a real (plain) commit so there is a confirmed prior config "A".
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name A; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	s.ExitConfigure()

	// Now a commit confirmed to "B"; on timeout it must roll back to "A".
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name B; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	s.ExitConfigure()

	gen := s.ConfirmGenForTesting()
	s.InvokeRollbackTimerForTesting(gen)

	if d.inBootstrap() {
		t.Fatal("a non-first-commit rollback must NOT enter bootstrap mode")
	}
	if lastApplied != "A" {
		t.Fatalf("rollback must re-apply prior config A; last applied = %q", lastApplied)
	}
	if !s.EverCommitted() {
		t.Fatal("after a non-first-commit rollback, store must still read committed")
	}
}

var _ = config.Config{}
