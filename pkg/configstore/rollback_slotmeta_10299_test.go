package configstore

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// saveRollbackFiles rewrites every slot on each commit and loadRollbackHistory
// stamps info.ModTime(), so all slots share the last commit's mtime;
// HistoryEntry.Comment exists but is never persisted.
//
// Cell 1 pins per-slot timestamps: distinct commit times must survive a
// rewrite+reload instead of collapsing onto one mtime.
//
// RED on revert: save ignores entry timestamps and load stamps mtime, so the
// reloaded timestamps cluster around now instead of the injected hours-apart
// values.
func TestRollbackSlotTimestampsSurviveRestart_10299(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hostA", "hostB", "hostC", "hostD"} {
		if err := s.SetFromInput("system host-name " + name); err != nil {
			t.Fatalf("SetFromInput(%s): %v", name, err)
		}
		if _, err := s.CommitWithDescription("comment-" + name); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}

	// Deterministic distinct timestamps (most-recent-first): slot 1 (hostC)
	// at base, slot 2 (hostB) at base+1h, slot 3 (hostA) at base+2h. A
	// fourth entry (the initial empty tree) exists at position 3 but its
	// slot reloads as a tombstone (see #10296), so only the first three
	// positions carry round-trip assertions.
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	entries := s.ListHistory()
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 history entries before reload, got %d", len(entries))
	}
	for i := range entries {
		entries[i].Timestamp = base.Add(time.Duration(i) * time.Hour)
	}
	s.saveRollbackFiles()

	s2 := newTestStoreAt(t, path)
	s2.loadRollbackHistory()
	after := s2.history.List()
	if len(after) < 3 {
		t.Fatalf("expected at least 3 history entries after reload, got %d", len(after))
	}
	wantHost := map[int]string{0: "host-name hostC", 1: "host-name hostB", 2: "host-name hostA"}
	for i := 0; i < 3; i++ {
		if after[i].Config == nil {
			t.Errorf("slot %d tombstoned on a NORMAL history, want healthy %q", i+1, wantHost[i])
			continue
		}
		if !strings.Contains(after[i].Config.Format(), wantHost[i]) {
			t.Errorf("slot %d holds the wrong generation: want %q", i+1, wantHost[i])
		}
		wantTs := base.Add(time.Duration(i) * time.Hour)
		if !after[i].Timestamp.Equal(wantTs) {
			t.Errorf("slot %d timestamp = %s, want %s (per-slot timestamps must survive restart, not collapse onto one mtime)",
				i+1, after[i].Timestamp.Format(time.RFC3339), wantTs.Format(time.RFC3339))
		}
	}
	if after[0].Timestamp.Equal(after[1].Timestamp) || after[1].Timestamp.Equal(after[2].Timestamp) {
		t.Errorf("reloaded slot timestamps are not distinct: %v %v %v",
			after[0].Timestamp, after[1].Timestamp, after[2].Timestamp)
	}
}

// Cell 2 pins comment persistence: the operator's commit description attached
// to each history entry must round-trip through save+reload.
//
// RED on revert: nothing persists Comment, so every reloaded entry has "".
func TestRollbackSlotCommentSurvivesRestart_10299(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// Include pipe/quote/unicode/newline-adjacent shapes so a naive
	// line-oriented sidecar encoding fails and only a safe encoding passes.
	comments := []string{
		"op deploy #42 | reason: \"hotfix\" \u2713",
		"second change; semicolons, commas, and \ttab",
		"third: unicode \u2014 dash and \u00e9",
		"fourth comment",
	}
	names := []string{"hostA", "hostB", "hostC", "hostD"}
	for i, name := range names {
		if err := s.SetFromInput("system host-name " + name); err != nil {
			t.Fatalf("SetFromInput(%s): %v", name, err)
		}
		if _, err := s.CommitWithDescription(comments[i]); err != nil {
			t.Fatalf("commit %s: %v", name, err)
		}
	}

	before := s.ListHistory()
	if len(before) < 3 {
		t.Fatalf("expected at least 3 history entries before reload, got %d", len(before))
	}
	for i := 0; i < 3; i++ {
		if before[i].Comment == "" {
			t.Fatalf("setup: in-memory slot %d has an empty comment — the test cannot pin persistence", i+1)
		}
	}

	s2 := newTestStoreAt(t, path)
	s2.loadRollbackHistory()
	after := s2.history.List()
	if len(after) < 3 {
		t.Fatalf("expected at least 3 history entries after reload, got %d", len(after))
	}
	for i := 0; i < 3; i++ {
		if after[i].Comment != before[i].Comment {
			t.Errorf("slot %d comment = %q, want %q (comments must survive restart)",
				i+1, after[i].Comment, before[i].Comment)
		}
	}
}
// A hash alone is insufficient to reject stale metadata when a no-op commit
// rewrites the same config bytes with a new comment. The sidecar also binds
// each record to the rewritten file's device/inode/mtime.
//
// RED on revert: restoring the pre-rewrite sidecar makes the loader accept
// the old comment because the slot hash is identical.
func TestRollbackSlotMetadataRejectsStaleManifestForDuplicateBytes_10299(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		comment string
	}{
		{"duplicate-a", "first"},
		{"duplicate-b", "second"},
	} {
		if err := s.SetFromInput("system host-name " + tc.name); err != nil {
			t.Fatalf("SetFromInput(%s): %v", tc.name, err)
		}
		if _, err := s.CommitWithDescription(tc.comment); err != nil {
			t.Fatalf("commit %s: %v", tc.name, err)
		}
	}
	if _, err := s.CommitWithDescription("same-bytes-old"); err != nil {
		t.Fatalf("first no-op commit: %v", err)
	}
	stale := append([]rollbackSlotMetadataEntry(nil), s.readRollbackMetadata()...)
	if len(stale) == 0 || stale[0].Comment != "same-bytes-old" {
		t.Fatalf("setup: stale sidecar lacks the duplicate-byte comment: %#v", stale)
	}
	if _, err := s.CommitWithDescription("same-bytes-new"); err != nil {
		t.Fatalf("second no-op commit: %v", err)
	}
	fresh := s.readRollbackMetadata()
	if len(fresh) == 0 || fresh[0].Hash != stale[0].Hash {
		t.Fatalf("setup: no-op commits did not retain identical slot bytes: stale=%#v fresh=%#v", stale, fresh)
	}
	if stale[0].Inode == fresh[0].Inode && stale[0].ModTime.Equal(fresh[0].ModTime) {
		t.Fatalf("setup: rollback slot rewrite did not change its file identity: stale=%#v fresh=%#v", stale[0], fresh[0])
	}

	// Model a crash after the slot rewrite but before the metadata-sidecar
	// rename: the old manifest is visible alongside the new slot inode.
	if err := s.writeRollbackMetadata(stale); err != nil {
		t.Fatalf("restore stale metadata: %v", err)
	}
	s2 := newTestStoreAt(t, path)
	s2.loadRollbackHistory()
	after := s2.history.List()
	if len(after) == 0 {
		t.Fatal("reload lost all rollback history")
	}
	if after[0].Comment == "same-bytes-old" {
		t.Fatalf("stale metadata was accepted for a rewritten duplicate-byte slot: got %q", after[0].Comment)
	}
}
