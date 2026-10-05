package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestLoadAndBootstrapRescueFallback11802(t *testing.T) {
	withApplianceMarker10733(t, true)
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
	if store.ActiveConfig() != nil || store.EverCommitted() {
		t.Fatalf("rescue selection changed active provenance: active=%v everCommitted=%v",
			store.ActiveConfig(), store.EverCommitted())
	}
	if got := store.ShowActiveSet(); got != "" {
		t.Fatalf("rescue selection installed a tree as active: %q", got)
	}
	if !d.applianceFactoryBoot() {
		t.Fatal("valid rescue selection erased never-committed provenance for the appliance factory lifeline")
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

func TestRescueFallbackDoesNotClaimForeignHostTransitGate11802(t *testing.T) {
	isolateRescueBootState11802(t)
	withApplianceMarker10733(t, false)
	path := filepath.Join(t.TempDir(), "xpf.conf")
	writeRescue11802Daemon(t, filepath.Join(filepath.Dir(path), configstore.RescueConfigBase),
		"system { host-name foreign-rescue-11802; }\n")

	store := newConfigStore(t, path)
	d := &Daemon{store: store, opts: Options{ConfigFile: path}}
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil || !failClosed || !d.inBootstrap() {
		t.Fatalf("foreign rescue fallback: failClosed=%v bootstrap=%v err=%v",
			failClosed, d.inBootstrap(), err)
	}
	if store.EverCommitted() {
		t.Fatal("rescue selection must remain never-committed on a foreign host")
	}
	if d.shouldManageTransitGate() {
		t.Fatal("rescue selection claimed the foreign host's transit forwarding gate")
	}
}

func writeRescue11802Daemon(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write rescue config: %v", err)
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

func TestFlatRescueFallbackCanCommitAfterExplicitLoad11802(t *testing.T) {
	isolateRescueBootState11802(t)
	previousNodeIDCheck := hasNodeIDFileFn
	hasNodeIDFileFn = func() bool { return false }
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
		t.Fatalf("flat rescue fallback boot state: failClosed=%v bootstrap=%v err=%v; want true/true/nil",
			failClosed, d.inBootstrap(), err)
	}
	if store.ActiveConfig() != nil || store.EverCommitted() {
		t.Fatalf("rescue fallback changed committed active state: active=%v everCommitted=%v",
			store.ActiveConfig(), store.EverCommitted())
	}
	if got := store.ShowActiveSet(); got != "" {
		t.Fatalf("rescue fallback installed rescue as active: %q", got)
	}
	if got := d.BootstrapImportSnapshot(); got.Status != bootstrapImportRescueFallback || got.Failed {
		t.Fatalf("bootstrap import status = %+v, want non-failed rescue-fallback", got)
	}

	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadRescueAsPlantClass("", ""); err != nil {
		t.Fatalf("LoadRescueAsPlantClass: %v", err)
	}
	if got := store.ShowCandidateSet(); !strings.Contains(got, "host-name flat-rescued-during-boot") {
		t.Fatalf("explicit load rescue did not seed the candidate: %s", got)
	}
	if _, err := store.CommitCheck(); err != nil {
		t.Fatalf("strict commit-check rejected explicitly loaded flat rescue: %v", err)
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

func TestClusteredRescueFallbackRequiresOfflinePromotion11802(t *testing.T) {
	isolateRescueBootState11802(t)
	previousNodeIDCheck := hasNodeIDFileFn
	hasNodeIDFileFn = func() bool { return true }
	t.Cleanup(func() { hasNodeIDFileFn = previousNodeIDCheck })

	path := filepath.Join(t.TempDir(), "xpf.conf")
	rescuePath := filepath.Join(filepath.Dir(path), configstore.RescueConfigBase)
	clusterRescue := clusterBootstrapConf(0, "test-cluster-psk-11802")
	writeRescue11802Daemon(t, rescuePath, clusterRescue)

	store := newConfigStore(t, path)
	store.SetNodeID(0)
	d := &Daemon{
		store:    store,
		opts:     Options{ConfigFile: path},
		applySem: semaphore.NewWeighted(1),
	}
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil || !failClosed || !d.inBootstrap() {
		t.Fatalf("cluster rescue fallback: failClosed=%v bootstrap=%v err=%v",
			failClosed, d.inBootstrap(), err)
	}
	if d.cluster != nil || store.EverCommitted() || store.ActiveConfig() != nil {
		t.Fatalf("cluster rescue fallback claimed runtime/state: runtime=%v committed=%v active=%v",
			d.cluster, store.EverCommitted(), store.ActiveConfig())
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadRescueAsPlantClass("", ""); err != nil {
		t.Fatalf("LoadRescueAsPlantClass: %v", err)
	}
	if _, err := store.CommitCheck(); err != nil {
		t.Fatalf("strict cluster rescue candidate rejected: %v", err)
	}
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 1, peerSyncNever); !errors.Is(err, errClusterTopologyRequiresRestart) {
		t.Fatalf("live commit-confirmed rescue promotion = %v, want restart-required topology rejection", err)
	}
	if store.ActiveConfig() != nil || store.EverCommitted() || store.IsConfirmPending() {
		t.Fatalf("rejected live promotion changed active state: active=%v committed=%v pending=%v",
			store.ActiveConfig(), store.EverCommitted(), store.IsConfirmPending())
	}

	// Promotion of the validated HA file is an offline restart procedure: the
	// rescue source must no longer take precedence on the next load.
	if err := os.WriteFile(path, []byte(clusterRescue), 0o600); err != nil {
		t.Fatalf("stage offline cluster config: %v", err)
	}
	if err := os.Remove(rescuePath); err != nil {
		t.Fatalf("remove rescue source after offline promotion: %v", err)
	}
	rebootStore := newConfigStore(t, path)
	rebootStore.SetNodeID(0)
	reboot := &Daemon{store: rebootStore, opts: Options{ConfigFile: path}}
	failClosed, err = reboot.loadAndBootstrapConfig()
	if err != nil || failClosed {
		t.Fatalf("offline cluster restart: failClosed=%v err=%v", failClosed, err)
	}
	active := rebootStore.ActiveConfig()
	if active == nil || active.Chassis.Cluster == nil {
		t.Fatalf("offline restart did not import the clustered config required by startup cluster-manager construction: active=%v",
			active)
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
