package configstore

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

func TestConfirmRecordFinalizationRetryOutlivesASecondFailure9625(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	restoreRollbackSeams(t)
	var fail atomic.Bool
	var attempts atomic.Int32
	inner := rbWriteFileDurable
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Base(path) == "confirm.json" {
			if attempts.Add(1) >= 2 && fail.Load() {
				return errInjectedConfirmArm
			}
		}
		return inner(path, data, perm, opts...)
	}
	if err := s.SetFromInput("system host-name finalize-retry"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)
	fail.Store(true)
	base := attempts.Load()
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.IsConfirmPending() || !s.ConfigPersistDegraded() {
		t.Fatal("finalization fault must leave a protected live window and degraded retry debt")
	}

	// The provisional write succeeds; the final binding write and at least
	// three retries fail. The loop must keep running after the second failure.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && attempts.Load()-base < 5 {
		time.Sleep(5 * time.Millisecond)
	}
	if n := attempts.Load() - base; n < 5 {
		t.Fatalf("only %d confirm.json writes occurred while the finalization fault persisted; want initial, final, and three retries", n)
	}
	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("the provisional record must remain readable during retries: rec=%v err=%v", rec, err)
	}
	if rec.GuardedHash != guardedConfigHash(s.active) {
		t.Fatal("the provisional record does not guard the active candidate")
	}

	fail.Store(false)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.ConfigPersistDegraded() {
		time.Sleep(5 * time.Millisecond)
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("finalization debt did not heal after the write fault cleared")
	}
	rec, err = s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("healed finalization lost confirm.json: rec=%v err=%v", rec, err)
	}
	if rec.PreviousHash != "" {
		t.Fatalf("healed finalization retained temporary previous hash %q", rec.PreviousHash)
	}
	if rec.GuardedHash != guardedConfigHash(s.active) {
		t.Fatal("healed record no longer guards the active candidate")
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		active := s.persistRetryActive
		s.mu.Unlock()
		if !active {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("persist retry loop did not stop after finalization debt healed")
}
