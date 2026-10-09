package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

func TestFirstCommitRollbackRestoresLifelineNetwork12154(t *testing.T) {
	const (
		lifelineAddress  = "192.0.2.1/24"
		candidateAddress = "192.0.2.99/24"
	)
	lifeline := []byte("# Managed by xpfd — #1922 bootstrap lifeline (static snapshot)\n" +
		"[Match]\nName=fxp0\n\n[Network]\nAddress=" + lifelineAddress + "\n")

	tests := []struct {
		name        string
		config      string
		managed     networkd.InterfaceConfig
		wantApplied string
		omitFxp0    bool
	}{
		{
			name:        "static fxp0",
			config:      "interfaces { fxp0 { unit 0 { family inet { address " + candidateAddress + "; } } } }",
			managed:     networkd.InterfaceConfig{Name: "fxp0", Addresses: []string{candidateAddress}},
			wantApplied: candidateAddress,
		},
		{
			name:     "DHCP fxp0",
			config:   "interfaces { fxp0 { unit 0 { family inet { dhcp; } } } }",
			managed:  networkd.InterfaceConfig{Name: "fxp0", DHCPv4: true},
			omitFxp0: false,
		},
		{
			name:        "candidate omits fxp0",
			config:      "interfaces { ge-0/0/0 { unit 0 { family inet { address 198.51.100.2/24; } } } }",
			managed:     networkd.InterfaceConfig{Name: "ge-0-0-0", Addresses: []string{"198.51.100.2/24"}},
			wantApplied: "198.51.100.2/24",
			omitFxp0:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			networkDir := t.TempDir()
			oldLinkDir := linkDir
			linkDir = networkDir
			t.Cleanup(func() { linkDir = oldLinkDir })
			installFakeNetworkctl(t)

			var reloads int
			oldRun := runCommandTimeout
			runCommandTimeout = func(name string, args ...string) ([]byte, error) {
				if name == "networkctl" && len(args) > 0 && args[0] == "reload" {
					reloads++
				}
				return nil, nil
			}
			t.Cleanup(func() { runCommandTimeout = oldRun })

			lifelinePath := filepath.Join(networkDir, linkPrefix+"fxp0.network")
			if err := os.WriteFile(lifelinePath, lifeline, 0o644); err != nil {
				t.Fatal(err)
			}

			store, err := configstore.New(filepath.Join(t.TempDir(), "config.db"))
			if err != nil {
				t.Fatal(err)
			}
			d := &Daemon{
				applySem: semaphore.NewWeighted(1),
				store:    store,
				networkd: networkd.NewInDir(networkDir),
				vrrpMgr:  vrrp.NewManager(),
				opts:     Options{NoDataplane: true},
			}
			d.networkd.SetProtectedResolver(func() map[string]bool {
				return map[string]bool{"fxp0": true}
			})
			store.SetRollbackExecutor(d.executeConfirmedRollback)
			d.bootstrapMode.Store(true)
			d.setDataplane(&runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{
				ManagedInterfaces: []networkd.InterfaceConfig{tt.managed},
			}})

			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := store.LoadOverride(tt.config); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.CommitConfirmed(1); err != nil {
				t.Fatalf("CommitConfirmed: %v", err)
			}
			store.ExitConfigure()

			if err := d.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
				t.Fatalf("first commit apply: %v", err)
			}
			applied, err := os.ReadFile(lifelinePath)
			if err != nil {
				t.Fatalf("read applied fxp0 network: %v", err)
			}
			if tt.omitFxp0 {
				if string(applied) != string(lifeline) {
					t.Fatalf("candidate omitting fxp0 changed the lifeline: got %q, want %q", applied, lifeline)
				}
			} else {
				if string(applied) == string(lifeline) || isBootstrapLifelineNetwork(applied) {
					t.Fatalf("networkd did not replace the lifeline with config content: %q", applied)
				}
				if tt.wantApplied != "" && !strings.Contains(string(applied), tt.wantApplied) {
					t.Fatalf("networkd winner %q omits candidate content %q", applied, tt.wantApplied)
				}
				if strings.Contains(string(applied), lifelineAddress) {
					t.Fatalf("networkd winner still contains the old lifeline address: %q", applied)
				}
			}
			if tt.omitFxp0 {
				if _, err := os.Stat(filepath.Join(networkDir, linkPrefix+"ge-0-0-0.network")); err != nil {
					t.Fatalf("candidate .network missing before rollback: %v", err)
				}
			}

			reloadsBeforeRollback := reloads
			gen := store.ConfirmGenForTesting()
			store.InvokeRollbackTimerForTesting(gen)
			if !d.inBootstrap() {
				t.Fatal("first-commit rollback did not return the daemon to bootstrap mode")
			}

			got, err := os.ReadFile(lifelinePath)
			if err != nil {
				t.Fatalf("rollback removed the bootstrap lifeline: %v", err)
			}
			if string(got) != string(lifeline) {
				t.Fatalf("rollback left the abandoned networkd winner instead of restoring the lifeline: got %q, want %q", got, lifeline)
			}
			if tt.omitFxp0 {
				if _, err := os.Stat(filepath.Join(networkDir, linkPrefix+"ge-0-0-0.network")); !os.IsNotExist(err) {
					t.Fatalf("rollback left config-driven networkd file; stat err=%v", err)
				}
			}
			if reloads != reloadsBeforeRollback+1 {
				t.Fatalf("rollback networkctl reloads = %d, want exactly one after file removal/restoration", reloads-reloadsBeforeRollback)
			}
		})
	}
}

func lifelineNetworkDir12154(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldLinkDir := linkDir
	linkDir = dir
	t.Cleanup(func() { linkDir = oldLinkDir })
	installFakeNetworkctl(t)
	return dir
}

func lifelineDaemon12154(t *testing.T, store *configstore.Store, dir string, managed []networkd.InterfaceConfig) *Daemon {
	t.Helper()
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    store,
		networkd: networkd.NewInDir(dir),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.networkd.SetProtectedResolver(func() map[string]bool { return map[string]bool{"fxp0": true} })
	store.SetRollbackExecutor(d.executeConfirmedRollback)
	store.SetFirstCommitConfirmedHook(d.clearBootstrapLifelineNetwork)
	d.setDataplane(&runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{ManagedInterfaces: managed}})
	return d
}

func commitConfirmedText12154(t *testing.T, store *configstore.Store, text string) {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	store.ExitConfigure()
}

func TestConfirmedFirstCommitThen9615KeepsCommittedLifeline12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	factory := []byte(bootstrapLifelineNetworkMarker +
		" (DHCP)\n[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n")
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	if err := os.WriteFile(path, factory, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := configstore.New(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	managed := []networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"10.1.1.5/24"}}}
	d := lifelineDaemon12154(t, store, dir, managed)
	d.bootstrapMode.Store(true)

	fxp0 := "interfaces { fxp0 { unit 0 { family inet { address 10.1.1.5/24; } } } }\n"
	commitConfirmedText12154(t, store, fxp0)
	if err := d.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatalf("confirm first commit: %v", err)
	}
	if len(d.bootstrapLifelineNetwork) != 0 {
		t.Fatal("confirmed first-commit window retained its day-0 lifeline snapshot")
	}
	before, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(before), "10.1.1.5/24") {
		t.Fatalf("precondition: committed fxp0 network = %q, err=%v", before, err)
	}

	if _, err := store.SyncApply(refusedTarget9615+fxp0, nil); err != nil {
		t.Fatalf("SyncApply refused target: %v", err)
	}
	commitConfirmedText12154(t, store, "system { host-name abandoned; }\n"+fxp0)
	if err := d.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
		t.Fatalf("abandoned apply: %v", err)
	}
	buf, restore := captureSlog(t)
	store.InvokeRollbackTimerForTesting(store.ConfirmGenForTesting())
	restore()

	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("#9615 safe-state entry rewrote committed fxp0: got %q, want unchanged %q (err=%v)",
			after, before, err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "bootstrap rollback complete") ||
		strings.Contains(logs, "restored management lifeline network") ||
		strings.Contains(logs, "DEGRADED") {
		t.Fatalf("#9615 must complete without restoring the day-0 lifeline or reporting DEGRADED:\n%s", logs)
	}
}

func TestRestartInsideFirstCommitWindowWithoutSnapshotReportsDegraded12154(t *testing.T) {
	for _, tc := range []struct {
		name       string
		removeFile bool
	}{
		{name: "candidate network remains"},
		{name: "fxp0 file missing", removeFile: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := lifelineNetworkDir12154(t)
			lifeline := []byte(bootstrapLifelineNetworkMarker +
				" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.1/24\n")
			path := filepath.Join(dir, linkPrefix+"fxp0.network")
			if err := os.WriteFile(path, lifeline, 0o644); err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(t.TempDir(), "config.db")
			storeA, err := configstore.New(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			managed := []networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"192.0.2.99/24"}}}
			dA := lifelineDaemon12154(t, storeA, dir, managed)
			dA.bootstrapMode.Store(true)
			commitConfirmedText12154(t, storeA,
				"interfaces { fxp0 { unit 0 { family inet { address 192.0.2.99/24; } } } }")
			if err := dA.applyConfigLocked(context.Background(), storeA.ActiveConfig()); err != nil {
				t.Fatalf("first-process apply: %v", err)
			}
			storeA.CancelConfirmTimerForTesting()
			if tc.removeFile {
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove fxp0 network: %v", err)
				}
			}

			storeB, err := configstore.New(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := storeB.Load(); err != nil {
				t.Fatalf("restart Load: %v", err)
			}
			t.Cleanup(func() {
				if storeB.IsConfirmPending() {
					_ = storeB.ConfirmCommit()
				}
			})
			dB := lifelineDaemon12154(t, storeB, dir, managed)
			if len(dB.bootstrapLifelineNetwork) != 0 {
				t.Fatal("new daemon unexpectedly inherited an in-memory lifeline snapshot")
			}
			buf, restore := captureSlog(t)
			storeB.InvokeRollbackTimerForTesting(storeB.ConfirmGenForTesting())
			restore()
			logs := buf.String()
			if !strings.Contains(logs, "restore management lifeline network") ||
				!strings.Contains(logs, "DEGRADED") ||
				strings.Contains(logs, "bootstrap rollback complete") {
				t.Fatalf("restart rollback without the in-memory snapshot must report lifeline restoration as DEGRADED:\n%s", logs)
			}
		})
	}
}

func TestFirstCommitRollbackStopsAbandonedDHCPClient12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	lifeline := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.1/24\n")
	if err := os.WriteFile(filepath.Join(dir, linkPrefix+"fxp0.network"), lifeline, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := configstore.New(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	managed := []networkd.InterfaceConfig{{Name: "fxp0", DHCPv4: true}}
	d := lifelineDaemon12154(t, store, dir, managed)
	manager := dhcp.NewManagerForTesting(func(ctx context.Context, _ string, _ dhcp.AddressFamily) {
		<-ctx.Done()
	})
	defer manager.StopAll()
	d.dhcp = manager
	d.bootstrapMode.Store(true)
	commitConfirmedText12154(t, store,
		"interfaces { fxp0 { unit 0 { family inet { dhcp; } } } }")
	if err := d.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	d.opts.NoDataplane = false
	d.reconcileDHCPClients(store.ActiveConfig())
	d.opts.NoDataplane = true
	if _, ok := manager.RunningClientHandlesForTesting()["fxp0/4"]; !ok {
		t.Fatal("premise: first-commit DHCP fxp0 client did not start")
	}

	store.InvokeRollbackTimerForTesting(store.ConfirmGenForTesting())
	if got := manager.RunningClientHandlesForTesting(); len(got) != 0 {
		t.Fatalf("first-commit rollback left abandoned DHCP clients running: %v", got)
	}
}

func TestRestoreLifelineRejectsDifferentMarkedFile12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	snapshot := []byte(bootstrapLifelineNetworkMarker +
		" (DHCP)\n[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n")
	current := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.99/24\n")
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	if err := os.WriteFile(path, current, 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{bootstrapLifelineNetwork: snapshot}
	changed, err := d.restoreBootstrapLifelineNetwork()
	if err != nil || !changed {
		t.Fatalf("different marked file restore = (changed=%v, err=%v), want changed=true", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(snapshot) {
		t.Fatalf("restore content = %q, err=%v; want captured snapshot %q", got, err, snapshot)
	}
}

func TestCaptureBootstrapLifelineIsOnce12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	first := []byte(bootstrapLifelineNetworkMarker +
		" (DHCP)\n[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n")
	second := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.99/24\n")
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	if err := os.WriteFile(path, first, 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{}
	d.captureBootstrapLifelineNetwork()
	if err := os.WriteFile(path, second, 0o644); err != nil {
		t.Fatal(err)
	}
	d.captureBootstrapLifelineNetwork()
	if string(d.bootstrapLifelineNetwork) != string(first) {
		t.Fatalf("second capture replaced the original day-0 snapshot: got %q, want %q",
			d.bootstrapLifelineNetwork, first)
	}
}

func TestFirstCommitRollbackSurfacesLifelineWriteError12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	snapshot := []byte(bootstrapLifelineNetworkMarker +
		" (DHCP)\n[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n")
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{bootstrapLifelineNetwork: snapshot}
	steps := d.runBootstrapTeardownSteps(true)
	err, degraded := summarizeBootstrapTeardown(steps)
	if err == nil || !degraded || !strings.Contains(err.Error(), "restore management lifeline network") {
		t.Fatalf("lifeline write failure must be surfaced as DEGRADED, got err=%v degraded=%v steps=%+v",
			err, degraded, steps)
	}
}
