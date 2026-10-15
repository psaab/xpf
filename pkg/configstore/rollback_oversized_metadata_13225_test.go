package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #13225 (D4-07a): an oversized rollback slot must keep its recorded
// Timestamp/Comment. ReadBoundedFile rejects it before the old (unreachable)
// len(data) > MaxConfigSize check, so the error path must recover the slot
// metadata instead of stamping time.Now()/"".
func TestLoadRollbackHistoryOversizedSlotPreservesMetadata13225(t *testing.T) {
	dir := t.TempDir()
	s := newTestStoreAt(t, filepath.Join(dir, "xpf.conf"))

	slot1Path := s.rollbackPath(1)
	oversized := []byte(strings.Repeat("#", MaxConfigSize+128))
	if err := os.WriteFile(slot1Path, oversized, 0600); err != nil {
		t.Fatal(err)
	}
	ident, ok := rollbackSlotIdentityForPath(slot1Path)
	if !ok {
		t.Fatal("failed to stat slot 1")
	}
	metaTime := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	if err := s.writeRollbackMetadataGeneration(0, []rollbackSlotMetadataEntry{{
		Hash:      rollbackSlotHash(oversized),
		Device:    ident.Device,
		Inode:     ident.Inode,
		ModTime:   ident.ModTime,
		Timestamp: metaTime,
		Comment:   "operator-audit-comment",
	}}); err != nil {
		t.Fatal(err)
	}

	s.loadRollbackHistory()
	entries := s.history.List()
	if len(entries) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(entries))
	}
	got := entries[0]
	if got.Config != nil {
		t.Fatalf("oversized slot must be a tombstone (Config=nil), got non-nil config")
	}
	if got.Comment != "operator-audit-comment" || !got.Timestamp.Equal(metaTime) {
		t.Fatalf("oversized slot lost metadata: Comment=%q Timestamp=%v, want %q %v",
			got.Comment, got.Timestamp, "operator-audit-comment", metaTime)
	}
}

// #13225 (D4-07b): a non-ENOENT unlink failure in cleanupRollbackFiles must
// surface as RollbackHistoryDegraded, otherwise the stale slot silently
// reappears on next boot with health green (#3441 L1).
func TestSaveRollbackFilesCleanupFailureDegrades13225(t *testing.T) {
	restoreRollbackSeams(t)

	dir := t.TempDir()
	s := newTestStoreAt(t, filepath.Join(dir, "xpf.conf"))
	metaTime := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	s.history.Push(&HistoryEntry{Config: &config.ConfigTree{}, Comment: "keep-1", Timestamp: metaTime})

	staleSlot := s.rollbackPath(2)
	if err := os.WriteFile(staleSlot, []byte("stale\n"), 0600); err != nil {
		t.Fatal(err)
	}
	origRemove := rbRemove
	rbRemove = func(path string) error {
		if path == staleSlot {
			return errors.New("injected EIO on stale rollback unlink")
		}
		return origRemove(path)
	}

	s.saveRollbackFiles()
	if !s.RollbackHistoryDegraded() {
		t.Fatalf("RollbackHistoryDegraded()=false after cleanup failed to remove %s", staleSlot)
	}
}

// #13225 (D4-07c): when history is empty but cleanup removed a stale slot,
// the unlinks must still be fsynced via rbSyncDir.
func TestSaveRollbackFilesSyncsDirAfterEmptyCleanup13225(t *testing.T) {
	restoreRollbackSeams(t)

	dir := t.TempDir()
	s := newTestStoreAt(t, filepath.Join(dir, "xpf.conf"))
	staleSlot := s.rollbackPath(1)
	if err := os.WriteFile(staleSlot, []byte("stale\n"), 0600); err != nil {
		t.Fatal(err)
	}
	syncs := 0
	rbSyncDir = func(string) error { syncs++; return nil }

	s.saveRollbackFiles()
	if _, err := os.Stat(staleSlot); !os.IsNotExist(err) {
		t.Fatalf("stale slot should have been removed, stat err=%v", err)
	}
	if syncs == 0 {
		t.Fatalf("rbSyncDir not called after cleanup removed stale slot with empty history")
	}
}
