package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/networkd"
)

// TestSyncApplyConfirmClearsSnapshot12154 pins MINOR-1/M2: an HA SyncApply
// that supersedes a pending first-commit window must clear the day-0
// snapshot via the store notify (dropping the store.go:1121 notify leaves
// the snapshot behind and this test fails).
func TestSyncApplyConfirmClearsSnapshot12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	lifeline := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.99/24\n")
	if err := os.WriteFile(path, lifeline, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := configstore.New(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("fresh Load: %v", err)
	}
	d := lifelineDaemon12154(t, store, dir,
		[]networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"192.0.2.99/24"}}})
	d.bootstrapMode.Store(true)
	commitConfirmedText12154(t, store,
		"interfaces { fxp0 { unit 0 { family inet { address 192.0.2.99/24; } } } }\n")
	if err := d.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	d.bootstrapLifelineMu.Lock()
	snapLen := len(d.bootstrapLifelineNetwork)
	d.bootstrapLifelineMu.Unlock()
	if snapLen == 0 {
		t.Fatal("premise: snapshot not captured")
	}
	if _, err := store.SyncApply("system { host-name synced; }\n", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	if store.IsConfirmPending() {
		t.Fatal("premise: SyncApply did not resolve the window")
	}
	d.bootstrapLifelineMu.Lock()
	after := len(d.bootstrapLifelineNetwork)
	captured := d.bootstrapLifelineCaptured
	d.bootstrapLifelineMu.Unlock()
	if after != 0 || captured {
		t.Fatalf("SyncApply confirmation retained the day-0 snapshot: len=%d captured=%v", after, captured)
	}
}
