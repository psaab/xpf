package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #10296: a zero-length text rollback slot loads as a healthy empty config;
// rollback then commit wipes the active config. Slots 2..N use the atomic
// (non-fsync) writer, so a power cut can leave a torn zero-length slot that
// the loader must fail closed on, never offer as a healthy wipe-target.
//
// Empty bytes parse with ZERO errors into an EMPTY tree (measured: "", "  ",
// and "# comment" all yield 0 errs, 0 children), and the empty tree's
// Format() is "" — so without a guard the slot is indistinguishable from a
// healthy config at the parse layer. The guard tombstones in place,
// preserving the #4810 positional invariant (later slots keep their
// `rollback N` indices).

// setupThreeSlotStore10296 commits four configs. The active config is hostD,
// and the three rollback slots hold hostC, hostB, and hostA (most-recent
// first). Returns the store path.
func setupThreeSlotStore10296(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hostA", "hostB", "hostC", "hostD"} {
		s.SetFromInput("system host-name " + name)
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}
	return path
}

// loadEntries10296 reloads rollback history from path and returns the
// entries most-recent-first.
func loadEntries10296(t *testing.T, path string) []*HistoryEntry {
	t.Helper()
	s := newTestStoreAt(t, path)
	s.loadRollbackHistory()
	return s.history.List()
}

// TestLoadRollbackHistory_ZeroLengthSlotTombstones_10296 pins the core cell:
// a zero-length slot file tombstones IN PLACE (nil Config) instead of
// loading as a healthy empty config, and later slots keep their positions.
//
// RED on revert: without the empty guard the zero-length slot parses clean
// into an empty tree, so entries[1].Config is non-nil (healthy) and the
// first assertion fires.
func TestLoadRollbackHistory_ZeroLengthSlotTombstones_10296(t *testing.T) {
	path := setupThreeSlotStore10296(t)
	s := newTestStoreAt(t, path)
	if err := os.WriteFile(s.rollbackPath(2), []byte{}, 0o600); err != nil {
		t.Fatalf("truncate slot 2 to zero length: %v", err)
	}

	entries := loadEntries10296(t, path)
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 history entries after reload, got %d", len(entries))
	}
	if entries[1].Config != nil {
		t.Fatalf("zero-length slot 2 loaded HEALTHY (empty tree, %d children) — "+
			"`rollback 2` + commit would WIPE the active config; want a tombstone (nil Config)",
			len(entries[1].Config.Children))
	}
	// Positional integrity (#4810): slot 3 stays in position 2.
	if entries[2].Config == nil || !strings.Contains(entries[2].Config.Format(), "host-name hostA") {
		t.Errorf("slot 3 (position 2) shifted or lost after slot 2 tombstoned: %+v", entries[2])
	}
	if entries[0].Config == nil || !strings.Contains(entries[0].Config.Format(), "host-name hostC") {
		t.Errorf("slot 1 (position 0) shifted or lost: %+v", entries[0])
	}
}

// TestLoadRollbackHistory_WhitespaceOnlySlotTombstones_10296 pins the
// whitespace-only sibling: spaces/tabs/newlines with no statements also
// parse clean into an empty tree and must tombstone, not load healthy.
//
// RED on revert: same as the zero-length cell — parses clean, loads healthy.
func TestLoadRollbackHistory_WhitespaceOnlySlotTombstones_10296(t *testing.T) {
	path := setupThreeSlotStore10296(t)
	s := newTestStoreAt(t, path)
	if err := os.WriteFile(s.rollbackPath(2), []byte("  \n\t  \n   "), 0o600); err != nil {
		t.Fatalf("write whitespace-only slot 2: %v", err)
	}

	entries := loadEntries10296(t, path)
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 history entries after reload, got %d", len(entries))
	}
	if entries[1].Config != nil {
		t.Fatalf("whitespace-only slot 2 loaded HEALTHY (empty tree, %d children) — "+
			"want a tombstone (nil Config)", len(entries[1].Config.Children))
	}
	if entries[2].Config == nil || !strings.Contains(entries[2].Config.Format(), "host-name hostA") {
		t.Errorf("slot 3 (position 2) shifted or lost: %+v", entries[2])
	}
}

// TestLoadRollbackHistory_CommentOnlySlotTombstones_10296 pins the
// comment-only empty-shape: "# ..." parses with zero errors into an empty
// tree (the #7176 precedent), so it must also tombstone rather than offer
// a wipe-target. This is the post-parse empty-tree catch-all.
//
// RED on revert: comment-only parses clean, loads healthy.
func TestLoadRollbackHistory_CommentOnlySlotTombstones_10296(t *testing.T) {
	path := setupThreeSlotStore10296(t)
	s := newTestStoreAt(t, path)
	if err := os.WriteFile(s.rollbackPath(2), []byte("# operator note, no statements\n# another line\n"), 0o600); err != nil {
		t.Fatalf("write comment-only slot 2: %v", err)
	}

	entries := loadEntries10296(t, path)
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 history entries after reload, got %d", len(entries))
	}
	if entries[1].Config != nil {
		t.Fatalf("comment-only slot 2 loaded HEALTHY (empty tree, %d children) — "+
			"want a tombstone (nil Config)", len(entries[1].Config.Children))
	}
	if entries[2].Config == nil || !strings.Contains(entries[2].Config.Format(), "host-name hostA") {
		t.Errorf("slot 3 (position 2) shifted or lost: %+v", entries[2])
	}
}

// TestRollbackToEmptySlotFailsClosed_10296 is the issue's
// "rollback-to-empty confirm" cell: after a zero-length slot tombstones,
// `rollback N` to that slot ERRORS (never silently restores an empty
// candidate that a commit would promote over active), while rollback to
// healthy slots on either side still resolves correctly.
//
// RED on revert: Rollback(2) succeeds with an empty candidate (the wipe
// shape), so the first assertion fires.
func TestRollbackToEmptySlotFailsClosed_10296(t *testing.T) {
	path := setupThreeSlotStore10296(t)
	probe := newTestStoreAt(t, path)
	if err := os.WriteFile(probe.rollbackPath(2), []byte{}, 0o600); err != nil {
		t.Fatalf("truncate slot 2: %v", err)
	}

	s := newTestStoreAt(t, path)
	s.loadRollbackHistory()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	if err := s.Rollback(2); err == nil {
		t.Fatal("Rollback(2) to a zero-length slot SUCCEEDED — the candidate is now an " +
			"empty tree and a commit would WIPE the active config; want an error")
	}
	// Healthy neighbours still resolve to their own generations (#4810).
	if err := s.Rollback(1); err != nil {
		t.Fatalf("Rollback(1) to healthy slot 1 failed: %v", err)
	}
	if got := s.ShowCandidateSet(); !strings.Contains(got, "host-name hostC") {
		t.Errorf("Rollback(1) resolved to the wrong generation: %q (want hostC)", got)
	}
	if err := s.Rollback(3); err != nil {
		t.Fatalf("Rollback(3) to healthy slot 3 failed: %v", err)
	}
	if got := s.ShowCandidateSet(); !strings.Contains(got, "host-name hostA") {
		t.Errorf("Rollback(3) resolved to the wrong generation: %q (want hostA)", got)
	}
}

// TestLoadRollbackHistory_CrashTornSlot3FailsClosed_10296 proves
// crash-consistency for the slots 2..N range: a power-cut-torn slot 3
// (simulated by truncating to zero length after the commits) tombstones
// without dropping or shifting any other slot. The atomic writer + trailing
// dir sync keeps the SEQUENCE contiguous (never missing); this guard keeps
// a torn member from loading as a healthy wipe-target.
//
// RED on revert: slot 3 loads healthy-empty.
func TestLoadRollbackHistory_CrashTornSlot3FailsClosed_10296(t *testing.T) {
	path := setupThreeSlotStore10296(t)
	s := newTestStoreAt(t, path)
	if err := os.WriteFile(s.rollbackPath(3), []byte{}, 0o600); err != nil {
		t.Fatalf("truncate slot 3 (2..N range): %v", err)
	}

	entries := loadEntries10296(t, path)
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 history entries after reload, got %d", len(entries))
	}
	if entries[2].Config != nil {
		t.Fatalf("torn slot 3 loaded HEALTHY (empty tree) — want a tombstone (nil Config)")
	}
	if entries[0].Config == nil || !strings.Contains(entries[0].Config.Format(), "host-name hostC") {
		t.Errorf("slot 1 lost after slot 3 tore: %+v", entries[0])
	}
	if entries[1].Config == nil || !strings.Contains(entries[1].Config.Format(), "host-name hostB") {
		t.Errorf("slot 2 lost after slot 3 tore: %+v", entries[1])
	}
}

// TestLoadRollbackHistory_NormalHistoryUnaffected_10296 is the no-regression
// control: an ordinary 4-commit history reloads with every slot healthy and
// every `rollback N` resolving to its own generation. Green before and
// after the fix.
func TestLoadRollbackHistory_NormalHistoryUnaffected_10296(t *testing.T) {
	path := setupThreeSlotStore10296(t)
	entries := loadEntries10296(t, path)
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 history entries after reload, got %d", len(entries))
	}
	want := map[int]string{0: "host-name hostC", 1: "host-name hostB", 2: "host-name hostA"}
	for pos, substr := range want {
		if entries[pos].Config == nil {
			t.Errorf("position %d (slot %d) tombstoned on a NORMAL history, want healthy %q",
				pos, pos+1, substr)
			continue
		}
		if !strings.Contains(entries[pos].Config.Format(), substr) {
			t.Errorf("position %d (slot %d) = %q, want %q",
				pos, pos+1, entries[pos].Config.Format(), substr)
		}
	}
}
// TestSaveRollbackFiles_AllSlotsDurable_10296 pins the second half of the
// issue: every canonical text rollback slot (not only slot 1) is routed
// through WriteFileDurable, so a power cut cannot publish an unsynced or
// zero-length slot. The one trailing directory sync remains the batch
// namespace barrier.
//
// RED on revert: the pre-fix split routes slots 2 and 3 through
// WriteFileAtomic, so the durable recorder does not contain those paths and
// the atomic recorder does.
func TestSaveRollbackFiles_AllSlotsDurable_10296(t *testing.T) {
	restoreRollbackSeams(t)
	var durableWrites, atomicWrites []string
	var syncedDirs []string
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		durableWrites = append(durableWrites, path)
		return fsatomic.WriteFileDurable(path, data, perm, opts...)
	}
	rbWriteFileAtomic = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		atomicWrites = append(atomicWrites, path)
		return fsatomic.WriteFileAtomic(path, data, perm, opts...)
	}
	rbSyncDir = func(dir string) error {
		syncedDirs = append(syncedDirs, dir)
		return fsatomic.SyncDir(dir)
	}

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"durable-a", "durable-b", "durable-c", "durable-d"} {
		s.SetFromInput("system host-name " + name)
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}

	for slot := 1; slot <= 3; slot++ {
		path := s.rollbackPath(slot)
		if !containsPath(durableWrites, path) {
			t.Errorf("slot %d %q was not written durably; durable=%v", slot, path, durableWrites)
		}
		if containsPath(atomicWrites, path) {
			t.Errorf("slot %d %q was written via the atomic (non-fsync) writer; atomic=%v",
				slot, path, atomicWrites)
		}
	}
	if len(syncedDirs) == 0 {
		t.Error("rollback directory was never fsync'd (SyncDir not called)")
	}
}
