package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #15143 store-level: Store.Load is the #10826 migration driver. Its
// journal arm must scrub pre-#1896 v1 lines (full compiled config in
// before/after, incl. cleartext api-auth credentials) even though Load
// never reads history — otherwise a migrated box keeps the journal
// copy until first history view/commit. History must still render.

func TestLoadScrubsLegacyJournal15143(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	s := newTestStoreAt(t, configPath)
	if err := s.db.WriteActive(parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)); err != nil {
		t.Fatalf("write legacy active: %v", err)
	}
	journalPath := filepath.Join(dir, ".config.journal")
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339Nano)
	legacy := `{"timestamp":"` + ts + `","action":"commit","detail":"legacy commit","before":null,"after":{"System":{"Services":{"WebManagement":{"APIAuth":{"Users":[{"Username":"api-admin","Password":"correct-horse-battery"}],"APIKeys":["machine-generated-key-alpha"]}}}}}}` + "\n"
	if err := os.WriteFile(journalPath, []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(journalPath, 0644); err != nil {
		t.Fatal(err)
	}

	// Fresh Store over the same dir, as at daemon restart.
	s2 := newTestStoreAt(t, configPath)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"correct-horse-battery", "machine-generated-key-alpha", `"before"`, `"after"`} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("journal still contains %q after Load migration:\n%s", secret, raw)
		}
	}
	if fi, err := os.Stat(journalPath); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("scrubbed journal mode = %v, err=%v; want 0600", fi, err)
	}

	entries, err := s2.ListCommitHistory(10)
	if err != nil {
		t.Fatalf("ListCommitHistory: %v", err)
	}
	if len(entries) != 1 || entries[0].Detail != "legacy commit" {
		t.Fatalf("history after Load scrub = %+v, want the legacy commit metadata", entries)
	}
	if s2.JournalLegacyScrubDegraded() {
		t.Fatal("JournalLegacyScrubDegraded set after clean Load scrub")
	}
}
