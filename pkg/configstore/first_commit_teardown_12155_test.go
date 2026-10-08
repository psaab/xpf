package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

func armFirstCommitWindow12155(t *testing.T, path string) {
	t.Helper()
	store := newTestStoreAt(t, path)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name FirstWindow"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	store.ExitConfigure()

	persisted := newTestStoreAt(t, path)
	rec, err := persisted.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
	}
	if !rec.FirstCommit {
		t.Fatal("fixture must represent a genuinely first commit-confirmed window")
	}
	rec.Deadline = time.Now().Add(-2 * time.Minute)
	if err := persisted.db.WriteConfirm(rec); err != nil {
		t.Fatalf("backdate confirm deadline: %v", err)
	}
}

func TestExpiredFirstCommitRecoveryPersistsTeardownDebt12155(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	armFirstCommitWindow12155(t, path)

	recovered := newTestStoreAt(t, path)
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load expired FIRST window: %v", err)
	}
	if !recovered.FirstCommitTeardownOwed() {
		t.Fatal("expired FIRST rollback did not expose teardown debt")
	}
	if _, committed, err := recovered.db.ReadActiveMeta(); err != nil || committed {
		t.Fatalf("rollback active marker = committed %v, err %v; want committed=false", committed, err)
	}
	confirmPath := filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")
	if _, err := os.Stat(confirmPath); !os.IsNotExist(err) {
		t.Fatalf("confirm.json remains after durable teardown marker publication: %v", err)
	}
	markerPath := firstCommitTeardownMarkerPath(filepath.Join(filepath.Dir(path), ".configdb"))
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("durable teardown marker missing: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load with teardown marker: %v", err)
	}
	if !restarted.FirstCommitTeardownOwed() {
		t.Fatal("teardown debt was not re-armed from disk on restart")
	}
	if err := restarted.ClearFirstCommitTeardown(); err != nil {
		t.Fatalf("clear converged teardown debt: %v", err)
	}
	if restarted.FirstCommitTeardownOwed() {
		t.Fatal("cleared teardown debt remains in memory")
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("teardown marker remains after clear: %v", err)
	}

	finalBoot := newTestStoreAt(t, path)
	if err := finalBoot.Load(); err != nil {
		t.Fatalf("Load after teardown debt clear: %v", err)
	}
	if finalBoot.FirstCommitTeardownOwed() {
		t.Fatal("cleared teardown debt was resurrected on the next boot")
	}
}

func TestExpiredFirstCommitPersistFailureCannotClearTeardownDebt12155(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	armFirstCommitWindow12155(t, path)

	recovered := newTestStoreAt(t, path)
	recovered.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	recovered.SetWriteActiveForTesting(failingWriteActive)
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load with rollback write failure: %v", err)
	}
	if !recovered.FirstCommitTeardownOwed() {
		t.Fatal("failed FIRST rollback write did not keep the current boot fail-closed")
	}
	if err := recovered.ClearFirstCommitTeardown(); err == nil {
		t.Fatal("cleared teardown debt before the rollback active write was durable")
	}
	markerPath := firstCommitTeardownMarkerPath(filepath.Join(filepath.Dir(path), ".configdb"))
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("marker must not be published before rollback active durability: %v", err)
	}
	if rec, err := recovered.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("confirm.json must remain the rollback retry source: rec=%v err=%v", rec, err)
	}
}

func TestAbsentActiveWithFirstCommitTeardownMarkerFailsClosed12155(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newTestStoreAt(t, path)
	markerPath := firstCommitTeardownMarkerPath(filepath.Join(filepath.Dir(path), ".configdb"))
	if err := os.WriteFile(markerPath, []byte(firstCommitTeardownMarkerText), 0o600); err != nil {
		t.Fatalf("write teardown marker: %v", err)
	}
	if err := store.Load(); !errors.Is(err, ErrConfigAbsentWithHistory) {
		t.Fatalf("Load without active.json but with teardown marker = %v; want ErrConfigAbsentWithHistory", err)
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("teardown marker was not re-armed while rejecting absent active config")
	}
}

func TestExpiredFirstCommitMarkerWriteFailureRetainsConfirm12155(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	armFirstCommitWindow12155(t, path)

	previousWrite := rbWriteFileDurable
	markerWriteErr := errors.New("injected teardown marker write failure")
	rbWriteFileDurable = func(filePath string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Base(filePath) == firstCommitTeardownMarkerBase {
			return markerWriteErr
		}
		return previousWrite(filePath, data, perm, opts...)
	}
	t.Cleanup(func() { rbWriteFileDurable = previousWrite })

	recovered := newTestStoreAt(t, path)
	recovered.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load with marker write failure: %v", err)
	}
	if !recovered.FirstCommitTeardownOwed() {
		t.Fatal("marker write failure dropped in-memory teardown debt")
	}
	confirmPath := filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")
	if _, err := os.Stat(confirmPath); err != nil {
		t.Fatalf("confirm.json removed despite teardown marker failure: %v", err)
	}
	if rec, err := recovered.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("confirm.json must remain until teardown debt is durable: rec=%v err=%v", rec, err)
	}
	markerPath := firstCommitTeardownMarkerPath(filepath.Join(filepath.Dir(path), ".configdb"))
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("failed marker write unexpectedly left marker: %v", err)
	}
}
