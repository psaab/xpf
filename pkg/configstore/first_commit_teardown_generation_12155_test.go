package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

func TestFirstCommitTeardownMarkerGapRecovery12155(t *testing.T) {
	for _, crash := range []bool{false, true} {
		name := "marker-write-error"
		if crash {
			name = "crash-before-marker"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "xpf.conf")
			armFirstCommitWindow12155(t, path)
			oldWrite := rbWriteFileDurable
			injected := errors.New("injected marker boundary")
			rbWriteFileDurable = func(p string, b []byte, mode os.FileMode, opts ...fsatomic.Option) error {
				if filepath.Base(p) == firstCommitTeardownMarkerBase {
					if crash {
						panic(injected)
					}
					return injected
				}
				return oldWrite(p, b, mode, opts...)
			}
			t.Cleanup(func() { rbWriteFileDurable = oldWrite })

			interrupted := newTestStoreAt(t, path)
			interrupted.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
			func() {
				defer func() {
					if r := recover(); r != nil && r != injected {
						panic(r)
					}
				}()
				if err := interrupted.Load(); err != nil {
					t.Fatalf("first Load: %v", err)
				}
			}()
			if _, committed, err := interrupted.db.ReadActiveMeta(); err != nil || committed {
				t.Fatalf("rollback active marker: committed=%v err=%v", committed, err)
			}
			if rec, err := interrupted.db.ReadConfirm(); err != nil || rec == nil || rec.Resolved {
				t.Fatalf("confirm recovery record was not retained: rec=%+v err=%v", rec, err)
			}

			rbWriteFileDurable = oldWrite
			restarted := newTestStoreAt(t, path)
			if err := restarted.Load(); err != nil {
				t.Fatalf("restart Load: %v", err)
			}
			if !restarted.FirstCommitTeardownOwed() {
				t.Fatal("durable FIRST rollback lost teardown debt across marker publication gap")
			}
		})
	}
}

func TestFirstCommitTeardownDebtSupersededByConfirmedGeneration12155(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	armFirstCommitWindow12155(t, path)
	store := newTestStoreAt(t, path)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("expired FIRST fixture did not acquire teardown debt")
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name Corrected"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if got := restarted.ActiveConfig(); got == nil || got.System.HostName != "Corrected" {
		t.Fatalf("confirmed replacement config = %+v", got)
	}
	if restarted.FirstCommitTeardownOwed() {
		t.Fatal("old FIRST-generation debt survived restart and can tear down the confirmed replacement")
	}
}

func TestLegacyFirstCommitDebtDoesNotOverrideCommittedSameContent12155(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	armFirstCommitWindow12155(t, path)
	store := newTestStoreAt(t, path)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("expired FIRST fixture did not acquire teardown debt")
	}

	markerPath := firstCommitTeardownMarkerPath(filepath.Join(filepath.Dir(path), ".configdb"))
	if err := os.WriteFile(markerPath, []byte(firstCommitTeardownMarkerText), 0o600); err != nil {
		t.Fatal(err)
	}
	activeText := store.ShowActive()
	if _, err := store.SyncApply(activeText, nil); err != nil {
		t.Fatalf("sync identical active config: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if restarted.FirstCommitTeardownOwed() {
		t.Fatal("legacy debt marker overrode a committed, byte-identical replacement")
	}
}
