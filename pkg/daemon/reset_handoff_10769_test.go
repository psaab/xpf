package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
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
