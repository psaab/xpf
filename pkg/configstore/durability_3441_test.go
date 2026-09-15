package configstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// restoreRollbackSeams restores the package-level rollback/archive
// persistence seams (#3441) after a test overrides them. Tests in this
// package run serially, so a single deferred restore is sufficient.
func restoreRollbackSeams(t *testing.T) {
	t.Helper()
	dur, atom, sync, rm, rd := rbWriteFileDurable, rbWriteFileAtomic, rbSyncDir, rbRemove, rbReadBoundedFile
	t.Cleanup(func() {
		rbWriteFileDurable, rbWriteFileAtomic, rbSyncDir, rbRemove, rbReadBoundedFile = dur, atom, sync, rm, rd
	})
}

// TestAutoArchiveCapturesCommittedTreeNoOverwrite pins #3441 H4: each commit
// must archive ITS OWN just-committed text, and two rapid commits must not
// overwrite each other's archive.
//
// RED on revert: the pre-#3441 code passed nothing to the async goroutine and
// let it read s.active.Format() whenever it ran (so both goroutines could
// archive the second commit's tree) AND named the file at second resolution
// (so two same-second commits resolved to one path, overwriting). Either
// failure mode trips the assertions below.
func TestAutoArchiveCapturesCommittedTreeNoOverwrite(t *testing.T) {
	s := newTestStore(t)
	archiveDir := filepath.Join(t.TempDir(), "archive")
	s.SetArchiveConfig(archiveDir, 10)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"archive-aaa", "archive-bbb"} {
		s.SetFromInput("system host-name " + name)
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}

	// Let the async archive goroutines finish.
	deadline := time.Now().Add(2 * time.Second)
	var ents []os.DirEntry
	for time.Now().Before(deadline) {
		e, err := os.ReadDir(archiveDir)
		if err == nil && len(e) >= 2 {
			ents = e
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(ents) != 2 {
		t.Fatalf("expected 2 distinct archive files (no overwrite), got %d", len(ents))
	}

	contents := map[string]bool{}
	for _, e := range ents {
		data, err := os.ReadFile(filepath.Join(archiveDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents[string(data)] = true
	}

	for _, name := range []string{"archive-aaa", "archive-bbb"} {
		found := false
		for c := range contents {
			if strings.Contains(c, "host-name "+name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no archive captured commit %q — async writer archived the wrong (later) tree", name)
		}
	}
}

// TestWriteArchiveSameTimestampNoOverwrite pins the #3441 H4 Codex MAJOR
// fix: two archives sharing the SAME wall-clock timestamp (the coarse-clock
// / NTP-step-back collision the nanosecond format alone could not rule out)
// must still produce TWO distinct files, because the monotonic seq is part
// of the filename.
//
// RED on revert: with a ts-only filename both writes resolve to the same
// path, so the second overwrites the first — len == 1 and the first config
// is lost.
func TestWriteArchiveSameTimestampNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 6, 28, 12, 0, 0, 123456789, time.UTC)

	if err := writeArchive(dir, 10, "config-A\n", ts, 1); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(dir, 10, "config-B\n", ts, 2); err != nil {
		t.Fatal(err)
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("same-timestamp archives must not overwrite: got %d files, want 2", len(ents))
	}
	contents := map[string]bool{}
	for _, e := range ents {
		d, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents[string(d)] = true
	}
	if !contents["config-A\n"] || !contents["config-B\n"] {
		t.Errorf("an archive was overwritten despite the seq: contents=%v", contents)
	}
}

// TestWriteArchivePrunesOldestByTimestampSeq verifies retention still prunes
// the OLDEST archives with the new config-<ts>.<seq>.conf filename: the
// lexical sort rotateArchives uses stays chronological because the timestamp
// dominates and the zero-padded seq only breaks same-ts ties in commit order.
func TestWriteArchivePrunesOldestByTimestampSeq(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		if err := writeArchive(dir, 3, fmt.Sprintf("cfg-%d\n", i), ts, uint64(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("want 3 archives after prune (max=3), got %d", len(ents))
	}
	remain := map[string]bool{}
	for _, e := range ents {
		d, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		remain[strings.TrimSpace(string(d))] = true
	}
	for _, w := range []string{"cfg-2", "cfg-3", "cfg-4"} {
		if !remain[w] {
			t.Errorf("newest archive %q should be retained; remain=%v", w, remain)
		}
	}
	for _, w := range []string{"cfg-0", "cfg-1"} {
		if remain[w] {
			t.Errorf("oldest archive %q should have been pruned; remain=%v", w, remain)
		}
	}
}

// TestRollbackSlotOneDurableAndDirSync pins the rollback-file durability
// contract via the seam recorders: slot 1 (the immediate `rollback 1` target)
// must be written with WriteFileDurable, and the directory must be fsync'd.
// The recorders prove the call ROUTING (durable-vs-atomic + dir-sync); the
// actual fsync syscalls are covered by pkg/fsatomic's own tests
// (TestDurableFsyncsFileAndDir, TestSyncDir), so this need not re-assert them.
//
// RED on revert: downgrading slot 1 to WriteFileAtomic drops it from the
// durable-write recorder; removing the trailing SyncDir clears syncedDir.
func TestRollbackSlotOneDurableAndDirSync(t *testing.T) {
	restoreRollbackSeams(t)

	var durableWrites, atomicWrites []string
	var syncedDir bool
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		durableWrites = append(durableWrites, path)
		return fsatomic.WriteFileDurable(path, data, perm, opts...)
	}
	rbWriteFileAtomic = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		atomicWrites = append(atomicWrites, path)
		return fsatomic.WriteFileAtomic(path, data, perm, opts...)
	}
	rbSyncDir = func(dir string) error {
		syncedDir = true
		return fsatomic.SyncDir(dir)
	}

	s := newTestStore(t)
	// Two commits => slot1 (durable) + slot2 (atomic).
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"durable-a", "durable-b"} {
		s.SetFromInput("system host-name " + name)
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}

	slot1 := s.rollbackPath(1)
	if !containsPath(durableWrites, slot1) {
		t.Errorf("slot 1 %q was not written durably (WriteFileDurable); durable=%v", slot1, durableWrites)
	}
	if containsPath(atomicWrites, slot1) {
		t.Errorf("slot 1 %q was written via the atomic (non-fsync) writer", slot1)
	}
	if !syncedDir {
		t.Error("rollback directory was never fsync'd (SyncDir not called)")
	}
}

// TestRollbackHistoryDegradedOnWriteFailure pins #3441 L1: a rollback-slot
// write failure must flip the degraded bit and emit a journal entry instead
// of being warning-only.
//
// RED on revert: removing the degraded tracking leaves
// RollbackHistoryDegraded()==false and no journal entry after an injected
// slot-write failure.
func TestRollbackHistoryDegradedOnWriteFailure(t *testing.T) {
	restoreRollbackSeams(t)
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		return errors.New("injected slot write failure")
	}

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("system host-name degraded-host")
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit should still succeed despite rollback-file failure: %v", err)
	}

	if !s.RollbackHistoryDegraded() {
		t.Error("RollbackHistoryDegraded() = false after a slot-write failure, want true")
	}

	entries, err := s.journal.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "rollback_persist_error" {
			found = true
			break
		}
	}
	if !found {
		t.Error("no rollback_persist_error journal entry after a slot-write failure")
	}
}

// TestLoadRollbackHistoryContinuesPastReadError pins #3441 L2:
// loadRollbackHistory must break only on a genuinely-missing slot, not on a
// transient/permission read error — otherwise a bad intermediate slot drops
// every later readable slot. It also pins #4810: the unreadable slot must
// tombstone IN PLACE (nil Config, same position) rather than being bare-
// skipped, which used to collapse every later slot's position down by one.
//
// RED on revert (#3441 L2): breaking on any read error loads only slot 1,
// dropping the readable slot 3 below.
// RED on revert (#4810): bare-skipping (continuing without appending a
// tombstone) leaves slot 3's config (hostA) sitting at POSITION 1 instead of
// position 2 — see TestRollbackAfterUnreadableSlotResolvesCorrectSlot below
// for the end-to-end Rollback(n) assertion that actually catches the shift;
// this test pins the tombstone's position directly.
func TestLoadRollbackHistoryContinuesPastReadError(t *testing.T) {
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
	// Slots after the 4 commits (most-recent-first): .1=hostC, .2=hostB,
	// .3=hostA, .4=<empty initial>. Make slot 2 unreadable as a regular file
	// by replacing it with a directory — os.ReadFile then returns an error
	// that is NOT os.IsNotExist, independent of euid (works as root too).
	slot2 := s.rollbackPath(2)
	if err := os.Remove(slot2); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(slot2, 0755); err != nil {
		t.Fatal(err)
	}

	// Fresh store over the same files; New() already loads rollback history,
	// so this second explicit load re-populates the (large-enough, no-evict)
	// ring on top — List() below reads back the freshest load's slots at
	// positions 0..3 regardless, so the assertions are robust to that.
	s2 := newTestStoreAt(t, path)
	s2.loadRollbackHistory()

	entries := s2.history.List() // most-recent-first: position i == slot i+1
	if len(entries) < 4 {
		t.Fatalf("loaded %d rollback entries, want >=4 (slots after the corrupt slot 2 must still load, in place)", len(entries))
	}

	// Slot 2 (position 1) must be a tombstone: unreadable at load, so there
	// is no config to show — NOT silently replaced by slot 3's config.
	if entries[1].Config != nil {
		t.Errorf("slot 2 (position 1) = %+v, want a tombstone (nil Config) after its read error", entries[1])
	}

	// Slot 3 (position 2) must be hostA, in ITS OWN position — not shifted
	// up into position 1 where the tombstone belongs.
	if entries[2].Config == nil || !strings.Contains(entries[2].Config.Format(), "host-name hostA") {
		t.Errorf("slot 3 (position 2) does not contain hostA: %+v", entries[2])
	}

	gotA := false
	for i, e := range entries {
		if i == 1 {
			continue // tombstone: nothing to inspect
		}
		if e.Config != nil && strings.Contains(e.Config.Format(), "host-name hostA") {
			gotA = true
			break
		}
	}
	if !gotA {
		t.Error("slot 3 (hostA) was dropped — loader broke on the slot-2 read error instead of continuing")
	}
}

// TestRollbackAfterUnreadableSlotResolvesCorrectSlot is the #4810
// RED-on-revert guard for the end-to-end symptom: an operator running
// `rollback N` after an intermediate slot failed to load at boot must get
// slot N's config (or a clear "unreadable" error for the tombstoned slot
// itself), never a DIFFERENT slot's config silently substituted in.
//
// RED on revert: bare-`continue`-skipping the unreadable slot 2 collapses
// slot 3 (hostA) into history POSITION 1, so Rollback(2) (History.Get(1))
// would silently return hostA's config instead of erroring, and Rollback(3)
// would run off the end of the (now one-shorter) history.
func TestRollbackAfterUnreadableSlotResolvesCorrectSlot(t *testing.T) {
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
	// Slots (most-recent-first): .1=hostC, .2=hostB, .3=hostA, .4=<empty>.
	// Corrupt slot 2 the same way as the sibling test above.
	slot2 := s.rollbackPath(2)
	if err := os.Remove(slot2); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(slot2, 0755); err != nil {
		t.Fatal(err)
	}

	s2 := newTestStoreAt(t, path)
	s2.loadRollbackHistory()
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// rollback 2 targets the tombstoned slot: must error, never silently
	// resolve to hostA (slot 3's config) or any other slot.
	if err := s2.Rollback(2); err == nil {
		t.Error("Rollback(2) on the unreadable slot succeeded, want an error")
	}

	// rollback 3 must still resolve to slot 3's own config (hostA). Under
	// the pre-#4810 bug, the bare-skip at slot 2 collapsed slot 3 into
	// history position 1 and slot 4 (the empty initial config) into
	// position 2, so Rollback(3) -> History.Get(2) silently returned the
	// EMPTY initial config instead of erroring or returning hostA.
	if err := s2.Rollback(3); err != nil {
		t.Fatalf("Rollback(3): %v", err)
	}
	got := s2.candidate.Format()
	if !strings.Contains(got, "host-name hostA") {
		t.Errorf("Rollback(3) candidate = %q, want it to contain host-name hostA (slot 3's own config, not shifted)", got)
	}
}

// TestSaveRollbackFilesSkipsTombstoneWithoutPanic pins the write-side half of
// the #4810 fix: once a tombstone (nil Config) occupies a history position —
// because its on-disk slot failed to load at boot — the NEXT commit's
// saveRollbackFiles must not dereference that nil Config while rewriting all
// numbered slot files. A naive "just fix the read side" patch would leave
// this call site calling entry.Config.Format() on nil, panicking the daemon
// on the very next commit after a degraded boot — a regression worse than
// the original #4810 bug (which never panicked).
func TestSaveRollbackFilesSkipsTombstoneWithoutPanic(t *testing.T) {
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
	slot2 := s.rollbackPath(2)
	if err := os.Remove(slot2); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(slot2, 0755); err != nil {
		t.Fatal(err)
	}

	s2 := newTestStoreAt(t, path)
	s2.loadRollbackHistory() // slot 2 tombstones into history position 1 (0-based)

	// slot 3 (hostA) is a real, readable file at this point — capture it so
	// we can prove it is left BYTE-IDENTICAL after the commit below. The
	// upcoming commit pushes a new entry to history position 0, shifting
	// the tombstone from position 1 to position 2 — i.e. onto SLOT 3, not
	// slot 2 — so slot 3 (not slot 2) is where saveRollbackFiles' tombstone
	// skip is actually exercised on this commit.
	slot3 := s.rollbackPath(3)
	before, err := os.ReadFile(slot3)
	if err != nil {
		t.Fatalf("read slot 3 before commit: %v", err)
	}

	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s2.SetFromInput("system host-name hostE")
	if _, err := s2.Commit(); err != nil {
		t.Fatalf("commit hostE (with a tombstoned history entry present): %v", err)
	}

	// The subject of this test is that saveRollbackFiles does not dereference a
	// tombstone's nil Config (which would panic). The commit above completing is
	// that property, and it is unchanged.
	//
	// #7176 (C179-056) changed what the slot must CONTAIN. This used to assert
	// slot 3 was BYTE-IDENTICAL, reasoning that saveRollbackFiles "must not
	// overwrite a perfectly good slot with garbage". That rationale does not
	// survive measurement: the slot is only perfectly good for a position it NO
	// LONGER OCCUPIES. History is most-recent-first and shifted on this commit,
	// so those bytes belong to the previous generation's slot 3 — and persisting
	// them is exactly what resurrects the tombstone as a HEALTHY entry on the
	// next boot (see TestRollbackTombstoneSurvivesReload_7176, which is the
	// across-restart cell this suite did not have).
	after, err := os.ReadFile(slot3)
	if err != nil {
		t.Fatalf("read slot 3 after commit: %v", err)
	}
	if string(after) != rollbackTombstoneMarker {
		t.Errorf("slot 3 must hold the tombstone marker after the commit, not another "+
			"generation's config:\nbefore=%q\nafter=%q\nwant=%q",
			before, after, rollbackTombstoneMarker)
	}
}

// TestCleanupRollbackFilesContinuesPastRemoveError pins #3441 L3:
// cleanupRollbackFiles must break only on a genuinely-absent slot, not on an
// arbitrary remove error — otherwise stale higher slots survive and violate
// the loader's contiguous-sequence invariant.
//
// RED on revert: breaking on any remove error leaves config.4 / config.5
// behind once config.3's remove is injected to fail.
func TestCleanupRollbackFilesContinuesPastRemoveError(t *testing.T) {
	restoreRollbackSeams(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	s := newTestStoreAt(t, path)

	// Create stale slots 3, 4, 5 directly on disk.
	for _, n := range []int{3, 4, 5} {
		if err := os.WriteFile(s.rollbackPath(n), []byte("stale"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	slot3 := s.rollbackPath(3)
	rbRemove = func(p string) error {
		if p == slot3 {
			return errors.New("injected remove failure") // not os.IsNotExist
		}
		return os.Remove(p)
	}

	s.cleanupRollbackFiles(3)

	if _, err := os.Stat(slot3); err != nil {
		t.Errorf("slot 3 should remain (its remove was injected to fail): %v", err)
	}
	for _, n := range []int{4, 5} {
		if _, err := os.Stat(s.rollbackPath(n)); !os.IsNotExist(err) {
			t.Errorf("slot %d should have been removed despite the slot-3 failure (stat err=%v)", n, err)
		}
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
