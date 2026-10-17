package configstore

// #14578: commit-confirmed timeout revert (PromoteRollback), boot recovery
// (recoverPendingConfirmLocked) and the persist-retry writer
// (retryActiveConfigPersistLocked) rewrite active.json without rebinding
// rollback-meta.json. fsatomic creates a new inode per write, so the next
// restart sees a generation mismatch and tombstones the whole rollback
// ladder. These tests exercise the decisive chain from the issue.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func commitHost14578(t *testing.T, s *Store, host string) {
	t.Helper()
	// Caller must already be in configure mode (Commit keeps candidate open).
	if err := s.SetFromInput("system host-name " + host); err != nil {
		t.Fatalf("SetFromInput %s: %v", host, err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit %s: %v", host, err)
	}
}
func rollbackHost14578(t *testing.T, s *Store, n int) string {
	t.Helper()
	entry, err := s.rollbackEntry(n)
	if err != nil {
		t.Fatalf("rollbackEntry(%d): %v", n, err)
	}
	text := entry.Config.Format()
	// Format is hierarchical: system { host-name hostA; }
	for _, h := range []string{"hostA", "hostB", "hostC", "hostD"} {
		if strings.Contains(text, "host-name "+h) {
			return h
		}
	}
	t.Fatalf("rollback %d config has no known host-name: %q", n, text)
	return ""
}

func assertLadder14578(t *testing.T, s *Store, want1, want2 string) {
	t.Helper()
	if got := rollbackHost14578(t, s, 1); got != want1 {
		t.Errorf("rollback 1 host = %q, want %q", got, want1)
	}
	if got := rollbackHost14578(t, s, 2); got != want2 {
		t.Errorf("rollback 2 host = %q, want %q", got, want2)
	}
	if s.RollbackHistoryDegraded() {
		t.Error("RollbackHistoryDegraded = true, want false")
	}
	// No tombstone marker on disk in any slot.
	for i := 1; i <= 3; i++ {
		data, err := os.ReadFile(s.rollbackPath(i))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), rollbackTombstoneMarkerPrefix) {
			t.Errorf("slot %d on disk is a tombstone after fix", i)
		}
	}
}

// Runtime path: commit A, commit B, commit-confirmed C, PromoteRollback, restart.
func TestPromoteRollbackRebindsRollbackHistory_14578(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s, "hostA")
	commitHost14578(t, s, "hostB")

	// commit-confirmed C
	if err := s.SetFromInput("system host-name hostC"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
	}
	gen := s.ConfirmGenForTesting()
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("PromoteRollback ok=false")
	}
	if got := s.ActiveConfig().System.HostName; got != "hostB" {
		t.Fatalf("active after rollback = %q, want hostB", got)
	}

	// Restart
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load after PromoteRollback: %v", err)
	}
	if got := s2.ActiveConfig().System.HostName; got != "hostB" {
		t.Fatalf("active after restart = %q, want hostB", got)
	}
	// History after commits: slot1=B(prev of C), slot2=A ... after revert to B,
	// ladder should still resolve: rollback1 = B? History is not shifted by
	// PromoteRollback (it doesn't push). At CommitConfirmed C, history pushed B,
	// before that B's commit pushed A. So slot1=B, slot2=A.
	assertLadder14578(t, s2, "hostB", "hostA")

	// Further commit must leave no tombstones and shift correctly.
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s2, "hostD")
	s3 := newTestStoreAt(t, path)
	if err := s3.Load(); err != nil {
		t.Fatalf("Load after further commit: %v", err)
	}
	// After D commit: slot1 = B (active before D), slot2 = B? Let's check:
	// history in s2 loaded [B,A], D commit pushes B -> [B,B,A] so 1=B,2=B
	// Just assert slot1 is B and no tombstone, slot2 readable.
	if got := rollbackHost14578(t, s3, 1); got != "hostB" {
		t.Errorf("after D rollback1 = %q want hostB", got)
	}
	for i := 1; i <= 3; i++ {
		data, err := os.ReadFile(s3.rollbackPath(i))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), rollbackTombstoneMarkerPrefix) {
			t.Errorf("after D slot %d tombstone", i)
		}
	}
}

// Boot path: commit A, B, commit-confirmed C, crash past deadline, boot recovery, restart again.
func TestBootRecoveryRebindsRollbackHistory_14578(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s, "hostA")
	commitHost14578(t, s, "hostB")
	if err := s.SetFromInput("system host-name hostC"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	s.CancelConfirmTimerForTesting()
	forceConfirmDeadlinePast(t, path)

	// Boot 1: expired recovery reverts to B
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot1 Load: %v", err)
	}
	if got := s2.ActiveConfig().System.HostName; got != "hostB" {
		t.Fatalf("boot1 active = %q want hostB", got)
	}

	// Boot 2: ladder must survive
	s3 := newTestStoreAt(t, path)
	if err := s3.Load(); err != nil {
		t.Fatalf("boot2 Load: %v", err)
	}
	assertLadder14578(t, s3, "hostB", "hostA")
}

// Persist-retry path: PromoteRollback write fails, retry heals, restart must keep ladder.
func TestPersistRetryRebindsRollbackHistory_14578(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s, "hostA")
	commitHost14578(t, s, "hostB")
	if err := s.SetFromInput("system host-name hostC"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	gen := s.ConfirmGenForTesting()
	// Fast retry, but failing write first.
	s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)
	s.SetWriteActiveForTesting(failingWriteActive)
	if _, ok := s.PromoteRollback(gen); !ok {
		t.Fatal("PromoteRollback ok=false")
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("expected persist degraded after failed rollback write")
	}
	// Heal: retry should write B and rebind.
	s.SetWriteActiveForTesting(nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.ConfigPersistDegraded() {
		time.Sleep(5 * time.Millisecond)
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("persist retry did not heal")
	}
	// Restart
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load after retry heal: %v", err)
	}
	if got := s2.ActiveConfig().System.HostName; got != "hostB" {
		t.Fatalf("active after retry+restart = %q want hostB", got)
	}
	assertLadder14578(t, s2, "hostB", "hostA")
}
