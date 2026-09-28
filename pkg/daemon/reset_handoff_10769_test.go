package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func isolateHandoffFlag(t *testing.T) {
	t.Helper()
	orig := configstore.ResetHandoffPath
	configstore.ResetHandoffPath = filepath.Join(t.TempDir(), ".reset-handoff")
	t.Cleanup(func() { configstore.ResetHandoffPath = orig })
}

func handoffTestStore(t *testing.T) *configstore.Store {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestCommitRefusedWhileHandoffDirty10769(t *testing.T) {
	isolateHandoffFlag(t)
	store := handoffTestStore(t)
	if err := configstore.WriteResetHandoff("other-boot", "helper sweep failed"); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("commit with dirty handoff = %v, want incomplete", err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 1, peerSyncNever); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("commit-confirmed with dirty handoff = %v, want incomplete", err)
	}
	if _, err := d.syncAndApply(context.Background(), "system { host-name peer; }", nil); !errors.Is(err, configstore.ErrResetHandoffDirty) {
		t.Fatalf("sync with dirty handoff = %v, want incomplete", err)
	}
	if cfg := store.ActiveConfig(); cfg != nil {
		t.Fatalf("refused provisioning must persist nothing, active = %+v", cfg.System.HostName)
	}
}

func TestCommitRefusedPreReboot10769(t *testing.T) {
	isolateHandoffFlag(t)
	store := handoffTestStore(t)
	boot, err := configstore.CurrentBootID()
	if err != nil {
		t.Fatal(err)
	}
	if err := configstore.WriteResetHandoff(boot, ""); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	if _, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever); !errors.Is(err, configstore.ErrResetHandoffRebootRequired) {
		t.Fatalf("pre-reboot commit = %v, want reboot-required", err)
	}
}

func TestCommitOpensPostReboot10769(t *testing.T) {
	isolateHandoffFlag(t)
	store := handoffTestStore(t)
	if err := configstore.WriteResetHandoff("other-boot", ""); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	_, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "", peerSyncNever)
	if errors.Is(err, configstore.ErrResetHandoffDirty) || errors.Is(err, configstore.ErrResetHandoffRebootRequired) {
		t.Fatalf("post-reboot commit must pass the handoff gate, got %v", err)
	}
	if _, serr := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(serr) {
		t.Fatalf("converged flag must be cleared, stat err = %v", serr)
	}
}

func commitUserspaceStateFile(t *testing.T, store *configstore.Store, stateFile string) {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	set := "set system dataplane-type userspace\n" +
		"set system dataplane state-file " + stateFile + "\n"
	if _, err := store.LoadSet(set); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func TestReconcileHandoffAtBoot10769(t *testing.T) {
	t.Run("absent flag is a no-op", func(t *testing.T) {
		isolateHandoffFlag(t)
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
	})
	t.Run("clean post-reboot clears", func(t *testing.T) {
		isolateHandoffFlag(t)
		if err := configstore.WriteResetHandoff("other-boot", ""); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
			t.Fatalf("converged flag must be cleared: %v", err)
		}
	})
	t.Run("clean same-boot is kept", func(t *testing.T) {
		isolateHandoffFlag(t)
		boot, err := configstore.CurrentBootID()
		if err != nil {
			t.Fatal(err)
		}
		if err := configstore.WriteResetHandoff(boot, ""); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: handoffTestStore(t)}
		d.reconcileResetHandoffAtBoot()
		if _, err := os.Lstat(configstore.ResetHandoffPath); err != nil {
			t.Fatalf("same-boot flag must be kept: %v", err)
		}
	})
	t.Run("dirty post-reboot repairs and clears", func(t *testing.T) {
		isolateHandoffFlag(t)
		stateFile := filepath.Join(t.TempDir(), "run", "xpf", "userspace-dp.json")
		if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stateFile, []byte("stale snapshot"), 0o600); err != nil {
			t.Fatal(err)
		}
		store := handoffTestStore(t)
		commitUserspaceStateFile(t, store, stateFile)
		if err := configstore.WriteResetHandoff("other-boot", "helper sweep failed"); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: store}
		d.reconcileResetHandoffAtBoot()
		if _, err := os.Lstat(stateFile); !os.IsNotExist(err) {
			t.Fatalf("dirty residue must be repaired at boot: %v", err)
		}
		if _, err := os.Lstat(configstore.ResetHandoffPath); !os.IsNotExist(err) {
			t.Fatalf("repaired flag must be cleared: %v", err)
		}
	})
	t.Run("dirty repair failure keeps the flag", func(t *testing.T) {
		isolateHandoffFlag(t)
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("not a dir"), 0o600); err != nil {
			t.Fatal(err)
		}
		store := handoffTestStore(t)
		commitUserspaceStateFile(t, store, filepath.Join(blocker, "userspace-dp.json"))
		if err := configstore.WriteResetHandoff("other-boot", "helper sweep failed"); err != nil {
			t.Fatal(err)
		}
		d := &Daemon{store: store}
		d.reconcileResetHandoffAtBoot()
		if _, err := os.Lstat(configstore.ResetHandoffPath); err != nil {
			t.Fatalf("unrepaired dirty flag must be kept: %v", err)
		}
	})
}

// resetHelperDP simulates a userspace dataplane whose helper writes its
// final state (plus an orphan temp sibling, exact writer shape) when
// stopped — the write the post-wipe sweep must catch and verify.
type resetHelperDP struct {
	dataplane.RuntimeDataPlane

	stateFile string
	stops     int
}

func (d *resetHelperDP) Start(context.Context) error { return nil }
func (d *resetHelperDP) Close() error                { return nil }
func (d *resetHelperDP) Teardown() error             { return nil }
func (d *resetHelperDP) StopHelperForReset() {
	d.stops++
	if d.stateFile == "" {
		return
	}
	// Best-effort final write: sweep-failure cells point stateFile at an
	// unwritable path on purpose, and the helper's own write error is not
	// what they assert.
	_ = os.MkdirAll(filepath.Dir(d.stateFile), 0o700)
	_ = os.WriteFile(d.stateFile, []byte("final snapshot"), 0o600)
	base := filepath.Base(d.stateFile)
	_ = os.WriteFile(filepath.Join(filepath.Dir(d.stateFile), base+".1_1.1.tmp"), []byte("orphan temp"), 0o600)
}

// The reset stop must keep matching the concrete userspace manager: a
// signature drift that silently disables the optional-interface assertion
// fails the build here instead of skipping the helper stop.
var _ helperResetStopper = (*dpuserspace.Manager)(nil)

func TestFactoryResetStopsSweepsAndDisarmsHelper10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, true)
	fence := withBarrierRecorder(t)
	root := t.TempDir()
	stateFile := filepath.Join(root, "run", "xpf", "userspace-dp.json")
	store := handoffTestStore(t)
	commitUserspaceStateFile(t, store, stateFile)
	stub := &resetHelperDP{stateFile: stateFile}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	d.setDataplane(stub)
	d.dataplaneArmed.Store(true)
	if err := d.factoryReset(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("factoryReset: %v", err)
	}
	if stub.stops != 1 {
		t.Fatalf("helper stops = %d, want exactly one pre-success stop", stub.stops)
	}
	if _, err := os.Lstat(stateFile); !os.IsNotExist(err) {
		t.Fatalf("helper state survived post-stop sweep: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(stateFile)); len(entries) != 0 {
		t.Fatalf("helper temp siblings survived: %v", entries)
	}
	if d.dataplaneArmed.Load() {
		t.Fatal("dataplane must be disarmed after a successful wipe")
	}
	if got := lastBarrierCall(fence); got != "install" {
		t.Fatalf("barrier call = %q, want install", got)
	}
	assertTransitForwarding(t, v4, v6, "0", "after a successful wipe")
	if _, _, present, _ := configstore.ReadResetHandoff(); present {
		t.Fatal("clean reset must not mark the handoff dirty")
	}
}

func TestFactoryResetSkipsHelperStopOnWipeFailure10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, true)
	fence := withBarrierRecorder(t)
	stub := &resetHelperDP{}
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.setDataplane(stub)
	d.dataplaneArmed.Store(true)
	wipeErr := errors.New("wipe failed")
	if err := d.factoryReset(context.Background(), func() error { return wipeErr }); !errors.Is(err, wipeErr) {
		t.Fatalf("factoryReset error = %v, want %v", err, wipeErr)
	}
	if stub.stops != 0 {
		t.Fatal("failed wipe must not stop the helper (box stays serving)")
	}
	if !d.dataplaneArmed.Load() {
		t.Fatal("failed wipe must not disarm transit")
	}
	if got := lastBarrierCall(fence); got != "" {
		t.Fatalf("barrier call = %q, want none on wipe failure", got)
	}
	assertTransitForwarding(t, v4, v6, "1", "after a failed wipe")
}

func TestFactoryResetMarksHandoffDirtyOnSweepFailure10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	isolateHandoffFlag(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := handoffTestStore(t)
	commitUserspaceStateFile(t, store, filepath.Join(blocker, "userspace-dp.json"))
	stub := &resetHelperDP{}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	d.setDataplane(stub)
	if err := d.factoryReset(context.Background(), func() error { return nil }); err == nil {
		t.Fatal("sweep failure must fail the reset")
	}
	if _, dirty, present, _ := configstore.ReadResetHandoff(); !present || dirty == "" {
		t.Fatalf("sweep failure must mark the handoff dirty: present=%v dirty=%q", present, dirty)
	}
	if stub.stops != 1 {
		t.Fatal("helper stop precedes the sweep and must still have run")
	}
}
