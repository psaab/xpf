package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestLoadAndBootstrapRescueFallback11802(t *testing.T) {
	isolateRescueBootState11802(t)
	path := filepath.Join(t.TempDir(), "xpf.conf")
	day0 := "system { host-name day0-must-not-load; }\n"
	rescue := "system { host-name rescued-during-boot; }\n"
	if err := os.WriteFile(path, []byte(day0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), configstore.RescueConfigBase), []byte(rescue), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newConfigStore(t, path)
	d := &Daemon{store: store, opts: Options{ConfigFile: path}}
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil {
		t.Fatalf("loadAndBootstrapConfig: %v", err)
	}
	if !failClosed || !d.inBootstrap() {
		t.Fatalf("rescue fallback boot state: failClosed=%v bootstrap=%v; want true/true", failClosed, d.inBootstrap())
	}
	if store.ActiveConfig() != nil || !store.EverCommitted() {
		t.Fatalf("rescue fallback installed unsafe compiled state: active=%v everCommitted=%v", store.ActiveConfig(), store.EverCommitted())
	}
	activeTree := store.ShowActiveSet()
	if !strings.Contains(activeTree, "rescued-during-boot") || strings.Contains(activeTree, "day0-must-not-load") {
		t.Fatalf("rescue selection/day-0 suppression failed: %s", activeTree)
	}
	activePath := filepath.Join(filepath.Dir(path), ".configdb", "active.json")
	if _, err := os.Stat(activePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("boot fallback wrote active.json: %v", err)
	}
	day0After, err := os.ReadFile(path)
	if err != nil || string(day0After) != day0 {
		t.Fatalf("day-0 config changed despite rescue fallback: data=%q err=%v", day0After, err)
	}
	if got := d.BootstrapImportSnapshot(); got.Status != bootstrapImportRescueFallback || got.Failed {
		t.Fatalf("bootstrap import status = %+v, want non-failed rescue-fallback", got)
	}
}

func isolateRescueBootState11802(t *testing.T) {
	t.Helper()
	previousFactoryResetPath := configstore.FactoryResetPendingPath
	previousResetHandoffPath := configstore.ResetHandoffPath
	root := t.TempDir()
	configstore.FactoryResetPendingPath = filepath.Join(root, configstore.FactoryResetPendingBase)
	configstore.ResetHandoffPath = filepath.Join(root, ".reset-handoff")
	t.Cleanup(func() {
		configstore.FactoryResetPendingPath = previousFactoryResetPath
		configstore.ResetHandoffPath = previousResetHandoffPath
	})
}

func TestFlatRescueFallbackRemainsBootstrapOnHANodeAndCanCommitConfirmed11802(t *testing.T) {
	isolateRescueBootState11802(t)
	previousNodeIDCheck := hasNodeIDFileFn
	hasNodeIDFileFn = func() bool { return true }
	t.Cleanup(func() { hasNodeIDFileFn = previousNodeIDCheck })

	path := filepath.Join(t.TempDir(), "xpf.conf")
	day0 := "system { host-name day0-must-not-load; }\n"
	rescue := "set system host-name flat-rescued-during-boot\n"
	if err := os.WriteFile(path, []byte(day0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), configstore.RescueConfigBase), []byte(rescue), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newConfigStore(t, path)
	d := &Daemon{store: store, opts: Options{ConfigFile: path}}
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil || !failClosed || !d.inBootstrap() {
		t.Fatalf("HA rescue boot state: failClosed=%v bootstrap=%v err=%v; want true/true/nil",
			failClosed, d.inBootstrap(), err)
	}
	if store.ActiveConfig() != nil || !store.EverCommitted() {
		t.Fatalf("flat rescue fallback installed compiled active state: active=%v everCommitted=%v",
			store.ActiveConfig(), store.EverCommitted())
	}
	activeTree := store.ShowActiveSet()
	if !strings.Contains(activeTree, "host-name flat-rescued-during-boot") ||
		strings.Contains(activeTree, "day0-must-not-load") {
		t.Fatalf("flat rescue selection/day-0 suppression failed: %s", activeTree)
	}
	if got := d.BootstrapImportSnapshot(); got.Status != bootstrapImportRescueFallback || got.Failed {
		t.Fatalf("bootstrap import status = %+v, want non-failed rescue-fallback", got)
	}

	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.CommitCheck(); err != nil {
		t.Fatalf("strict commit-check rejected flat rescue fallback: %v", err)
	}
	if _, err := store.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	t.Cleanup(func() {
		if store.IsConfirmPending() {
			_ = store.ConfirmCommit()
		}
	})
	if !store.IsConfirmPending() || store.ActiveConfig() == nil {
		t.Fatal("commit-confirmed did not promote the validated flat rescue candidate")
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	if store.IsConfirmPending() {
		t.Fatal("confirmed rescue commit retained its rollback window")
	}
}

func TestMalformedRescueRetainsFreshDay0Import11802(t *testing.T) {
	isolateRescueBootState11802(t)
	previousNodeIDCheck := hasNodeIDFileFn
	hasNodeIDFileFn = func() bool { return false }
	t.Cleanup(func() { hasNodeIDFileFn = previousNodeIDCheck })

	path := filepath.Join(t.TempDir(), "xpf.conf")
	day0 := "system { host-name day0-after-bad-rescue; }\n"
	if err := os.WriteFile(path, []byte(day0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), configstore.RescueConfigBase),
		[]byte("system { host-name malformed-rescue\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newConfigStore(t, path)
	d := &Daemon{store: store, opts: Options{ConfigFile: path}}
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil || failClosed || d.inBootstrap() {
		t.Fatalf("malformed rescue boot state: failClosed=%v bootstrap=%v err=%v; want false/false/nil",
			failClosed, d.inBootstrap(), err)
	}
	if store.ActiveConfig() == nil || !strings.Contains(store.ShowActiveSet(), "day0-after-bad-rescue") ||
		strings.Contains(store.ShowActiveSet(), "malformed-rescue") {
		t.Fatalf("fresh day-0 config was not imported after malformed rescue: %s", store.ShowActiveSet())
	}
	if got := d.BootstrapImportSnapshot(); got.Status != bootstrapImportPending || got.Failed {
		t.Fatalf("bootstrap import status = %+v, want non-failed pending", got)
	}
	activePath := filepath.Join(filepath.Dir(path), ".configdb", "active.json")
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("fresh day-0 import did not persist active.json: %v", err)
	}
}
