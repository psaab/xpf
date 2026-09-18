package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedCommittedHistory10297 creates the shape at issue #10297: active.json is
// the DB canonical config, while the day-0 text file is deliberately stale
// and the numbered text slots carry the real committed history.
func seedCommittedHistory10297(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	for _, host := range []string{"history-a", "history-b"} {
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.LoadOverride("system { host-name " + host + "; }"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatal(err)
		}
		s.ExitConfigure()
	}
	if err := os.WriteFile(path, []byte("system { host-name day-0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadAbsentActiveWithHistoryFailsClosed_10297 is the fail-on-revert cell:
// deleting only active.json must not turn a previously committed store into a
// fresh import. The loader must retain the surviving rollback history and set
// the committed state proved by that history.
func TestLoadAbsentActiveWithHistoryFailsClosed_10297(t *testing.T) {
	path := seedCommittedHistory10297(t)
	dbDir := filepath.Join(filepath.Dir(path), ".configdb")
	if err := os.Remove(filepath.Join(dbDir, "active.json")); err != nil {
		t.Fatal(err)
	}

	s := newTestStoreAt(t, path)
	err := s.Load()
	if !errors.Is(err, ErrConfigAbsentWithHistory) {
		t.Fatalf("Load error = %v; want ErrConfigAbsentWithHistory", err)
	}
	if !s.EverCommitted() {
		t.Fatal("absent active with surviving history: EverCommitted=false; want true")
	}
	entries := s.history.List()
	if len(entries) < 2 {
		t.Fatalf("surviving rollback history entries = %d; want at least 2", len(entries))
	}
	found := false
	for _, entry := range entries {
		if entry.Config != nil && strings.Contains(entry.Config.Format(), "history-a") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("surviving rollback history lost history-a after active.json disappeared")
	}

	// An operator-directed re-import is allowed to recover the store, but it
	// must append the stale day-0 candidate to history rather than erase the
	// surviving entries that caused the fail-closed decision.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name day-0; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	s.ExitConfigure()
	found = false
	for _, entry := range s.history.List() {
		if entry.Config != nil && strings.Contains(entry.Config.Format(), "history-a") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("explicit re-import clobbered surviving rollback history")
	}

	reloadedAfterImport := newTestStoreAt(t, path)
	if err := reloadedAfterImport.Load(); err != nil {
		t.Fatalf("Load after explicit re-import: %v", err)
	}
	if !reloadedAfterImport.EverCommitted() {
		t.Fatal("Load after explicit re-import: EverCommitted=false; want true")
	}
	found = false
	for _, entry := range reloadedAfterImport.history.List() {
		if entry.Config != nil && strings.Contains(entry.Config.Format(), "history-a") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("reloaded rollback history lost history-a after explicit re-import")
	}
}

// TestLoadAbsentActiveWithoutHistoryStartsFresh_10297 is the genuine first-boot
// cell: no active DB and no rollback markers remains the existing bootstrap
// path, including the never-committed state.
func TestLoadAbsentActiveWithoutHistoryStartsFresh_10297(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("fresh absent DB Load error = %v; want nil", err)
	}
	if s.EverCommitted() {
		t.Fatal("fresh absent DB: EverCommitted=true; want false")
	}
	if s.ActiveConfig() != nil {
		t.Fatal("fresh absent DB: ActiveConfig()!=nil; want nil")
	}
}

// TestLoadAbsentActiveWithKeyOnlyStartsFresh_10297 pins the encrypted
// first-boot boundary: a failed first active write can leave master.key, but
// that key alone is not proof of a prior commit and must not block bootstrap.
func TestLoadAbsentActiveWithKeyOnlyStartsFresh_10297(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	newTestStoreAt(t, path)
	key := filepath.Join(filepath.Dir(path), ".configdb", "master.key")
	if err := os.WriteFile(key, []byte("failed-first-write-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("key-only absent DB Load error = %v; want nil", err)
	}
	if s.EverCommitted() {
		t.Fatal("key-only absent DB: EverCommitted=true; want false")
	}
}

// TestLoadAbsentActiveWithConfirmMarkerFailsClosed_10297 keeps a pending
// commit-confirmed record as prior-state evidence even when active.json is
// missing; it must not be mistaken for a fresh store.
func TestLoadAbsentActiveWithConfirmMarkerFailsClosed_10297(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	newTestStoreAt(t, path)
	marker := filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")
	if err := os.WriteFile(marker, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded := newTestStoreAt(t, path)
	if err := reloaded.Load(); !errors.Is(err, ErrConfigAbsentWithHistory) {
		t.Fatalf("Load with surviving confirm marker = %v; want ErrConfigAbsentWithHistory", err)
	}
	if !reloaded.EverCommitted() {
		t.Fatal("surviving confirm marker: EverCommitted=false; want true")
	}
}

// TestLoadAbsentActiveWithDBRollbackMarkerFailsClosed_10297 covers the
// .configdb marker arm independently of the canonical text-slot arm.
func TestLoadAbsentActiveWithDBRollbackMarkerFailsClosed_10297(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	newTestStoreAt(t, path)
	marker := filepath.Join(filepath.Dir(path), ".configdb", "rollback.1.json")
	if err := os.WriteFile(marker, []byte(`{"Children":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded := newTestStoreAt(t, path)
	if err := reloaded.Load(); !errors.Is(err, ErrConfigAbsentWithHistory) {
		t.Fatalf("Load with surviving DB rollback marker = %v; want ErrConfigAbsentWithHistory", err)
	}
	if !reloaded.EverCommitted() {
		t.Fatal("surviving DB rollback marker: EverCommitted=false; want true")
	}
}
