package daemon

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// TestPersistentConfigSyncNACKPreservesDistinctHistory12163 drives the real
// handleConfigSync -> syncAndApply path with a persistent apply failure. Each
// failed attempt promotes the peer config but leaves ActiveApplied false, so
// the next identical delivery falls through the #4957 shortcut and retries the
// apply. Those retries must not evict distinct rollback targets.
func TestPersistentConfigSyncNACKPreservesDistinctHistory12163(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
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
	peerText := renderSyncedConfigText(t, "system host-name history-c-12163")

	const retries = 60
	for i := 0; i < retries; i++ {
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

	// A genuinely different config still pushes the former active tree.
	d.applyErrForTest = nil
	otherText := renderSyncedConfigText(t, "system host-name history-d-12163")
	if err := d.handleConfigSync(otherText); err != nil {
		t.Fatalf("distinct config sync: %v", err)
	}
	entries = store.ListHistory()
	if len(entries) != 4 {
		t.Fatalf("distinct config history length = %d, want 4", len(entries))
	}
	if entries[0] == nil || entries[0].Config == nil ||
		!strings.Contains(entries[0].Config.Format(), "history-c-12163") {
		t.Fatal("distinct config push did not retain the previous active config at the history head")
	}
}
