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
