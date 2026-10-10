package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// TestPersistentConfigSyncNACKPreservesDistinctHistory12163 drives the real
// handleConfigSync -> syncAndApply path with a persistent apply failure and a
// legacy cleartext API-auth payload. Each failed attempt promotes the peer
// config but leaves ActiveApplied false, so the next identical delivery must
// retry apply without evicting distinct rollback targets.
func TestPersistentConfigSyncNACKPreservesDistinctHistory12163(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.db")
	store := newConfigStore(t, configPath)
	for _, host := range []string{"history-a-12163", "history-b-12163"} {
		text := renderSyncedConfigText(t, "system host-name "+host)
		if _, err := store.SyncApply(text, nil); err != nil {
			t.Fatalf("SyncApply seed %s: %v", host, err)
		}
	}

	var applyCalls int
	nack := errors.New("persistent config-sync apply NACK")
	d := &Daemon{
		store:    store,
		applySem: semaphore.NewWeighted(1),
		// Exercise SyncApply + the real retry path while injecting a persistent
		// NACK at the apply boundary without touching a live dataplane.
		applyBodyForTest: func(*config.Config) { applyCalls++ },
		applyErrForTest:  nack,
	}
	peerText := `system {
 host-name history-c-12163;
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    user admin { password correct-horse-battery; }
   }
  }
 }
}`

	const retries = 60
	for i := range retries {
		err := d.handleConfigSync(peerText)
		if !errors.Is(err, nack) {
			t.Fatalf("config-sync attempt %d error = %v, want injected persistent NACK", i+1, err)
		}
		if store.ActiveApplied() {
			t.Fatalf("config-sync attempt %d: failed apply must remain unapplied", i+1)
		}
	}
	if applyCalls != retries {
		t.Fatalf("apply attempts = %d, want %d (each unapplied re-push must retry)", applyCalls, retries)
	}

	entries := store.ListHistory()
	if len(entries) != 3 {
		t.Fatalf("history length after %d persistent NACKs = %d, want 3 (initial empty + two distinct configs)", retries, len(entries))
	}
	for _, marker := range []string{"history-a-12163", "history-b-12163"} {
		found := false
		for _, entry := range entries {
			if entry != nil && entry.Config != nil && strings.Contains(entry.Config.Format(), marker) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("distinct rollback target %q was evicted by persistent identical NACK retries", marker)
		}
	}
	if activeText := store.ShowActive(); strings.Contains(activeText, "correct-horse-battery") {
		t.Fatalf("legacy cleartext credential was persisted in active config:\n%s", activeText)
	}

	activeDB, err := os.ReadFile(filepath.Join(filepath.Dir(configPath), ".configdb", "active.json"))
	if err != nil {
		t.Fatalf("read persisted active config: %v", err)
	}
	if strings.Contains(string(activeDB), "correct-horse-battery") ||
		!strings.Contains(string(activeDB), "$xpf-bcrypt$") {
		t.Fatalf("persisted active config must contain only the tagged verifier:\n%s", activeDB)
	}

	// The history ring and hashed active tree survive store restart.
	reopened := newConfigStore(t, configPath)
	if err := reopened.Load(); err != nil {
		t.Fatalf("reopen persistent-NACK store: %v", err)
	}
	for _, marker := range []string{"history-a-12163", "history-b-12163"} {
		found := false
		for _, entry := range reopened.ListHistory() {
			if entry != nil && entry.Config != nil && strings.Contains(entry.Config.Format(), marker) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("restart lost rollback target %q", marker)
		}
	}
	if activeText := reopened.ShowActive(); strings.Contains(activeText, "correct-horse-battery") {
		t.Fatalf("legacy cleartext credential survived in persisted active config:\n%s", activeText)
	}

	// A genuinely different credential still pushes the former active tree.
	d.applyErrForTest = nil
	changedSecretText := strings.ReplaceAll(peerText, "correct-horse-battery", "changed-horse-battery-12163")
	if err := d.handleConfigSync(changedSecretText); err != nil {
		t.Fatalf("changed-secret config sync: %v", err)
	}
	entries = store.ListHistory()
	if len(entries) != 4 {
		t.Fatalf("changed credential history length = %d, want 4", len(entries))
	}
	if entries[0] == nil || entries[0].Config == nil ||
		!strings.Contains(entries[0].Config.Format(), "history-c-12163") {
		t.Fatal("changed credential did not push the previous active config")
	}

	// A non-credential change also pushes, even with the same credential intent.
	otherText := strings.ReplaceAll(changedSecretText, "history-c-12163", "history-d-12163")
	if err := d.handleConfigSync(otherText); err != nil {
		t.Fatalf("distinct non-credential config sync: %v", err)
	}
	entries = store.ListHistory()
	if len(entries) != 5 {
		t.Fatalf("distinct non-credential history length = %d, want 5", len(entries))
	}
	if entries[0] == nil || entries[0].Config == nil ||
		!strings.Contains(entries[0].Config.Format(), "history-c-12163") {
		t.Fatal("distinct non-credential change did not retain the previous active config at the history head")
	}
}
