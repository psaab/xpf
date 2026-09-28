package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// resetHelperStateDP simulates the userspace helper's shutdown behavior: its
// final state write lands on Close/Teardown, after the wipe already erased
// the file. The interface is nil-embedded like shutdownModeDP; only the
// lifecycle arms run here.
type resetHelperStateDP struct {
	dataplane.RuntimeDataPlane

	stateFile string
}

func (d *resetHelperStateDP) Start(context.Context) error { return nil }
func (d *resetHelperStateDP) Close() error                { return d.writeFinal() }
func (d *resetHelperStateDP) Teardown() error             { return d.writeFinal() }

func (d *resetHelperStateDP) writeFinal() error {
	if err := os.MkdirAll(filepath.Dir(d.stateFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(d.stateFile, []byte("helper final snapshot"), 0o600)
}

// TestRunShutdownSequenceRemovesHelperStateAfterReset pins the S-RUN fix:
// the helper's final state write lands after the wipe erased it, so a
// reset shutdown must sweep the configured state file once the helper is
// gone. Without the sweep the shutdown recreates tenant state behind a
// reported-success reset. The non-reset control keeps the file.
func TestRunShutdownSequenceRemovesHelperStateAfterReset(t *testing.T) {
	isolateHandoffFlag(t)
	for _, resetting := range []bool{true, false} {
		name := "reset sweeps helper state"
		if !resetting {
			name = "plain shutdown keeps helper state"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			stateFile := filepath.Join(root, "run", "xpf", "userspace-dp.json")
			store, err := configstore.New(filepath.Join(root, "xpf.conf"))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			set := "set system dataplane-type userspace\n" +
				"set system dataplane control-socket " + filepath.Join(root, "run", "xpf", "control.sock") + "\n" +
				"set system dataplane state-file " + stateFile + "\n"
			if _, err := store.LoadSet(set); err != nil {
				t.Fatalf("LoadSet: %v", err)
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
			d.setDataplane(&resetHelperStateDP{stateFile: stateFile})
			if resetting {
				d.enterResetGeneration()
			}
			var wg sync.WaitGroup
			sentinel := context.Canceled
			done := make(chan error, 1)
			go func() { done <- d.runShutdownSequence(&wg, func() {}, sentinel) }()
			select {
			case got := <-done:
				if got != sentinel {
					t.Fatalf("runShutdownSequence returned %v, want passthrough", got)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("runShutdownSequence did not return within 30s")
			}
			_, statErr := os.Lstat(stateFile)
			if resetting && !os.IsNotExist(statErr) {
				t.Fatalf("helper state %s survived a reset shutdown: %v", stateFile, statErr)
			}
			if !resetting && statErr != nil {
				t.Fatalf("plain shutdown must not sweep helper state: %v", statErr)
			}
		})
	}
}

// TestRunShutdownSequenceMarksPathlessOnHelperFailure10769 pins the
// shutdown-race wiring through the REAL runShutdownSequence isResetting
// branch (not the sweep method alone): a reset shutdown whose helper
// sweep fails with no flag present persists a pathless dirty mark via
// MarkResetHandoffDirty. The held-semaphore leg additionally drives the
// real 5s apply-drain timeout: the shutdown must proceed past it and
// still take the sweep branch. No wipes run here; the pending-write /
// post-verify / flip completion ordering is pinned through factoryReset
// in TestShutdownRacePathlessFlagStaysGated10769.
func TestRunShutdownSequenceMarksPathlessOnHelperFailure10769(t *testing.T) {
	setup := func(t *testing.T) (*Daemon, string, string) {
		t.Helper()
		isolateHandoffFlag(t)
		root := t.TempDir()
		target := filepath.Join(root, "run", "xpf", "real-state.json")
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("helper final snapshot"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "run", "xpf", "state-link.json")
		store, err := configstore.New(filepath.Join(root, "xpf.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		set := "set system dataplane-type userspace\n" +
			"set system dataplane state-file " + link + "\n"
		if _, err := store.LoadSet(set); err != nil {
			t.Fatalf("LoadSet: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
		// Production Run always arms the apply cancel pair; without it
		// the shutdown drain is skipped and the drain-timeout branch
		// below would never run.
		d.applyCancelContext, d.applyCancel = context.WithCancel(context.Background())
		t.Cleanup(d.applyCancel)
		d.setDataplane(&resetHelperStateDP{stateFile: filepath.Join(root, "dp.json")})
		d.enterResetGeneration()
		return d, link, target
	}
	runShutdown := func(t *testing.T, d *Daemon) {
		t.Helper()
		var wg sync.WaitGroup
		sentinel := context.Canceled
		done := make(chan error, 1)
		go func() { done <- d.runShutdownSequence(&wg, func() {}, sentinel) }()
		select {
		case got := <-done:
			if got != sentinel {
				t.Fatalf("runShutdownSequence returned %v, want passthrough", got)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("runShutdownSequence did not return within 30s")
		}
	}
	assertPathlessMarked := func(t *testing.T, link, target string) {
		t.Helper()
		_, dirty, gotPath, present, err := configstore.ReadResetHandoff()
		if err != nil || !present || dirty == "" || gotPath != "" {
			t.Fatalf("shutdown-branch mark with no flag must persist pathless dirty: dirty=%q path=%q present=%v err=%v", dirty, gotPath, present, err)
		}
		if !strings.Contains(dirty, "helper state sweep failed") {
			t.Fatalf("pathless reason must name the sweep failure, got %q", dirty)
		}
		for _, path := range []string{link, target} {
			if _, serr := os.Lstat(path); serr != nil {
				t.Fatalf("symlink refusal must remove nothing, %s stat err=%v", path, serr)
			}
		}
		if err := configstore.CheckResetHandoff(); !errors.Is(err, configstore.ErrResetHandoffDirty) {
			t.Fatalf("gate = %v, want incomplete", err)
		}
	}
	t.Run("failure marks pathless dirty", func(t *testing.T) {
		d, link, target := setup(t)
		runShutdown(t, d)
		assertPathlessMarked(t, link, target)
	})
	t.Run("held semaphore still marks after drain timeout", func(t *testing.T) {
		d, link, target := setup(t)
		// Hold the semaphore the way an in-flight wipe does. The
		// shutdown must time out its drain, proceed anyway, and take
		// the sweep branch. It then parks at the (post-sweep,
		// fail-closed-actions-complete) tunables restore, which takes
		// applySem unboundedly — so watch for the mark, then release
		// to let the shutdown converge. The poll is orchestration
		// only (generous cap); the >=drain assertion below proves
		// the timeout branch ran rather than the fast path.
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatalf("setup acquire: %v", err)
		}
		var wg sync.WaitGroup
		sentinel := context.Canceled
		done := make(chan error, 1)
		go func() { done <- d.runShutdownSequence(&wg, func() {}, sentinel) }()
		start := time.Now()
		deadline := start.Add(20 * time.Second)
		for {
			if _, serr := os.Lstat(configstore.ResetHandoffPath); serr == nil {
				break
			} else if !os.IsNotExist(serr) {
				t.Fatalf("stat reset handoff flag: %v", serr)
			}
			if time.Now().After(deadline) {
				t.Fatal("shutdown with a held apply semaphore never reached the sweep branch")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if elapsed := time.Since(start); elapsed < applyCloseoutDrainTimeout {
			t.Fatalf("shutdown with a held apply semaphore must take the drain timeout (%v), took %v", applyCloseoutDrainTimeout, elapsed)
		}
		d.applySem.Release(1)
		select {
		case got := <-done:
			if got != sentinel {
				t.Fatalf("runShutdownSequence returned %v, want passthrough", got)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("runShutdownSequence did not return within 30s")
		}
		assertPathlessMarked(t, link, target)
	})
}
