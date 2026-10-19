package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #15190 (D08-01): SyncApply's degrade-not-fail branch writes
// rollback-meta.json bound to the unwritten synced tree. History is
// shifted (push old active) and saveRollbackFiles runs unconditionally
// after a failed writeActive, so the sidecar names the NEW tree's hash
// while active.json on disk still holds the OLD tree. A restart before
// the persist retry heals then sees a generation mismatch in
// loadRollbackHistory and refuses every slot, and the next successful
// save tombstones the in-memory ladder — silently losing the HA
// standby's entire rollback history with rollbackPersistDegraded=false.
//
// Acceptance (issue): the degraded-restart cell yields a readable
// ladder, and the heal path keeps [C,B,A] — i.e. after the retry lands
// the synced config, a restart sees slot1 = the config that was active
// before the sync (the entry pushed by the sync), slot2 = its
// predecessor, etc.
//
// Ladder construction: local commits A -> B -> C leave active=C and
// history (most-recent-first) [B, A]. A peer sync to D (writeActive
// fails) pushes C, so in-memory history becomes [C, B, A] while disk
// active stays C. Pre-fix, saveRollbackFiles writes slots [C,B,A] plus
// a sidecar bound to D's hash/inode-of-old-file: restart refuses all.
// Post-fix the degraded save must not bind to the unwritten tree, so
// the restart still yields a readable ladder; after heal, active=D is
// durable and the ladder is [C,B,A].

func syncHost15190(t *testing.T, s *Store, host string) {
	t.Helper()
	if _, err := s.SyncApply("system {\n    host-name "+host+";\n}\n", nil); err != nil {
		t.Fatalf("SyncApply %s: %v", host, err)
	}
}

func assertLadderHosts15190(t *testing.T, s *Store, want ...string) {
	t.Helper()
	for i, w := range want {
		got := rollbackHost14578(t, s, i+1)
		if got != w {
			t.Errorf("rollback %d host = %q, want %q", i+1, got, w)
		}
	}
	if s.RollbackHistoryDegraded() {
		t.Error("RollbackHistoryDegraded = true, want false (readable ladder must not be silently degraded)")
	}
}

// Degraded-restart cell: commit A,B,C; sync D with writeActive failing
// (long retry backoff so the retry cannot heal before the restart);
// restart before heal. The ladder must remain readable and must not be
// reported as cleanly degraded-away — pre-fix every slot is refused
// (rollbackEntry errors / tombstones).
func TestSyncApplyPersistFailureRestartKeepsLadder_15190(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s, "hostA")
	commitHost14578(t, s, "hostB")
	commitHost14578(t, s, "hostC")
	s.ExitConfigure()
	if got := s.ActiveConfig().System.HostName; got != "hostC" {
		t.Fatalf("premise: active = %q, want hostC", got)
	}
	// Premise ladder on a clean restart: [B, A].
	pre := newTestStoreAt(t, path)
	if err := pre.Load(); err != nil {
		t.Fatalf("premise Load: %v", err)
	}
	assertLadderHosts15190(t, pre, "hostB", "hostA")

	// Sync D with a failing active write; keep the retry from healing
	// before the simulated restart (hour backoff, same pattern as the
	// singleton test).
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	var failing atomic.Bool
	failing.Store(true)
	s.SetWriteActiveForTesting(func(tree *config.ConfigTree) error {
		if failing.Load() {
			return errDiskFull
		}
		return s.db.WriteActive(tree)
	})
	syncHost15190(t, s, "hostD")
	if got := s.ActiveConfig().System.HostName; got != "hostD" {
		t.Fatalf("in-memory active after degraded sync = %q, want hostD (Option B)", got)
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("premise: failed sync write must set ConfigPersistDegraded")
	}
	// In-memory ladder after the sync push: slot1=C, then B, A (a
	// trailing empty-tree entry from the first commit may follow).
	s.mu.RLock()
	memEntries := s.history.List()
	s.mu.RUnlock()
	if len(memEntries) < 3 {
		t.Fatalf("premise: in-memory history len = %d, want at least 3", len(memEntries))
	}
	if memEntries[0].Config == nil || !strings.Contains(memEntries[0].Config.Format(), "hostC") {
		t.Fatalf("premise: in-memory slot1 is not hostC")
	}

	// Restart before the retry heals: a fresh store over the same dir.
	// Disk active is still C (the D write failed).
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	if got := s2.ActiveConfig().System.HostName; got != "hostC" {
		t.Fatalf("restart active = %q, want hostC (synced D never persisted)", got)
	}
	// The decisive assertion: the rollback ladder must be readable.
	// Pre-fix the sidecar binds D, so generationMismatch refuses every
	// slot and rollbackEntry(1) errors (tombstone). Post-fix the on-disk
	// ladder is the pre-sync one ([B,A] for active C, which never moved
	// on disk); the shifted [C,B,A] is owed until the retry heals.
	assertLadderHosts15190(t, s2, "hostB", "hostA")
}

// Heal cell: same degraded sync, but the disk heals and the persist
// retry lands D; a restart then keeps [C,B,A] with active D.
func TestSyncApplyPersistRetryHealKeepsLadder_15190(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s, "hostA")
	commitHost14578(t, s, "hostB")
	commitHost14578(t, s, "hostC")
	s.ExitConfigure()

	s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)
	var failing atomic.Bool
	failing.Store(true)
	s.SetWriteActiveForTesting(func(tree *config.ConfigTree) error {
		if failing.Load() {
			return errDiskFull
		}
		return s.db.WriteActive(tree)
	})
	syncHost15190(t, s, "hostD")
	if !s.ConfigPersistDegraded() {
		t.Fatal("premise: failed sync write must set ConfigPersistDegraded")
	}
	// Heal.
	failing.Store(false)
	s.SetWriteActiveForTesting(nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.ConfigPersistDegraded() {
		time.Sleep(5 * time.Millisecond)
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("persist retry did not heal")
	}
	// In-memory ladder must be [C,B,A] after heal.
	assertLadderHosts15190(t, s, "hostC", "hostB", "hostA")

	// Restart: active D durable, ladder [C,B,A].
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	if got := s2.ActiveConfig().System.HostName; got != "hostD" {
		t.Fatalf("restart active = %q, want hostD", got)
	}
	assertLadderHosts15190(t, s2, "hostC", "hostB", "hostA")

	// And the next save must not tombstone the ladder: a further local
	// commit E shifts to [D,C,B,A]; restart keeps it readable.
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s2, "hostE")
	s3 := newTestStoreAt(t, path)
	if err := s3.Load(); err != nil {
		t.Fatalf("Load after E: %v", err)
	}
	if got := s3.ActiveConfig().System.HostName; got != "hostE" {
		t.Fatalf("active after E restart = %q, want hostE", got)
	}
	assertLadderHosts15190(t, s3, "hostD", "hostC", "hostB")
	for i := 1; i <= 3; i++ {
		data, err := s3.rollbackPath(i), error(nil)
		_ = data
		_ = err
		raw, rerr := readFileString15190(s3.rollbackPath(i))
		if rerr == nil && strings.Contains(raw, rollbackTombstoneMarkerPrefix) {
			t.Errorf("slot %d tombstoned after heal+commit", i)
		}
	}
}

// Post-rename control: the write lands (new tree visible) but reports a
// typed post-rename failure. The shifted save binds correctly to the
// visible tree, so a pre-heal restart loads D with ladder [C,B,A] —
// this is NOT the deferred case and must not be deferred.
func TestSyncApplyPostRenameFailureKeepsShiftedLadder_15190(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s, "hostA")
	commitHost14578(t, s, "hostB")
	commitHost14578(t, s, "hostC")
	s.ExitConfigure()
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	s.SetWriteActiveForTesting(postRenameFailingWriteActive(s))
	syncHost15190(t, s, "hostD")
	if !s.ConfigPersistDegraded() {
		t.Fatal("premise: post-rename failure must set ConfigPersistDegraded")
	}
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	if got := s2.ActiveConfig().System.HostName; got != "hostD" {
		t.Fatalf("restart active = %q, want hostD (post-rename write is visible)", got)
	}
	assertLadderHosts15190(t, s2, "hostC", "hostB", "hostA")
}

// Control: a successful sync (no write fault) behaves exactly as
// before — ladder shifts to [C,B,A] and survives restart.
func TestSyncApplySuccessKeepsLadderControl_15190(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commitHost14578(t, s, "hostA")
	commitHost14578(t, s, "hostB")
	commitHost14578(t, s, "hostC")
	s.ExitConfigure()
	syncHost15190(t, s, "hostD")
	if s.ConfigPersistDegraded() {
		t.Fatal("successful sync must not be degraded")
	}
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	if got := s2.ActiveConfig().System.HostName; got != "hostD" {
		t.Fatalf("restart active = %q, want hostD", got)
	}
	assertLadderHosts15190(t, s2, "hostC", "hostB", "hostA")
}

func readFileString15190(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
