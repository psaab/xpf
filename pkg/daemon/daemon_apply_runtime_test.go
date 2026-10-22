package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/networkd"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestApplyConfigLockedSurfacesHostInboundFailure is the #3333 commit-level
// wiring proof: it drives the REAL applyConfigLocked body (not the
// applyHostInboundFilter helper directly) with an injected host-inbound nft
// failure via the nftApplyPayload seam, and asserts the returned commit error
// includes that failure. This pins the production wiring — the
// errors.Join(networkdErr, dhcpServerErr, hostInboundErr) at the tail of
// applyConfigLocked — which the helper-level seam tests do NOT cover.
//
// RED-on-revert: remove hostInboundErr from that join and this test goes RED
// (the apply completes and returns nil despite the host-inbound deny failing to
// install — the silent fail-open the issue describes).
func TestApplyConfigLockedSurfacesHostInboundFailure(t *testing.T) {
	installFakeNetworkctl(t)

	injected := errors.New("nftables: host-inbound rule load failed")
	// #6387 PR-3: inject the failure through the netlink install seam. The failure
	// rides SOLELY on the host-inbound real install (InstallHostInbound); the
	// cold-boot fence and every table delete succeed (nil hooks), so the lo0
	// no-filter teardown and the host-inbound gap/fence paths do NOT also surface
	// `injected` — isolating this test to the hostInboundErr join term (dropping it
	// from the join must be the ONLY thing that makes the commit go green → RED).
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return injected },
	}
	defer func() { nftInstaller = orig }()

	networkDir := t.TempDir()
	d := &Daemon{
		networkd: networkd.NewInDir(networkDir),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell

	// Enforceable host-inbound config: a non-lifeline zone with a static
	// address and a host-inbound stanza, so applyConfigLocked reaches the APPLY
	// path and the injected nft failure is the deny-not-installed failure.
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.7.7.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}

	err := d.applyConfigLocked(context.Background(), cfg)
	if err == nil {
		t.Fatal("applyConfigLocked must surface the host-inbound nft failure " +
			"(fail-closed); got nil (the silent fail-open #3333 describes)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the host-inbound failure "+
			"via errors.Join wiring, got %v", err)
	}
}

// TestApplyConfigLockedSurfacesLo0Failure is the #3392 commit-level wiring
// proof: it drives the REAL applyConfigLocked body (not the applyLo0Filter
// helper directly) with an injected lo0-filter nft failure via the
// nftApplyPayload seam, and asserts the returned commit error includes that
// failure. This pins the production wiring — the errors.Join(networkdErr,
// dhcpServerErr, hostInboundErr, lo0Err) at the tail of applyConfigLocked —
// which the helper-level seam tests do NOT cover.
//
// RED-on-revert: remove lo0Err from that join and this test goes RED (the apply
// completes and returns nil despite the lo0 input filter failing to install —
// the silent fail-open the issue describes). The config binds an lo0 filter but
// declares NO host-inbound stanza, so the only nftApplyPayload caller that can
// fail is applyLo0Filter — isolating this from the #3333 host-inbound wiring.
func TestApplyConfigLockedSurfacesLo0Failure(t *testing.T) {
	installFakeNetworkctl(t)

	injected := errors.New("nftables: lo0 rule load failed")
	// #6387 PR-3: inject the failure through the netlink lo0 install seam. The
	// host-inbound no-enforceable-view TEARDOWN (this config takes it) and every
	// other table delete succeed (nil del hook), so removing lo0Err from the join
	// must be the ONLY thing that surfaces `injected` → RED-on-revert.
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error { return injected },
	}
	defer func() { nftInstaller = orig }()

	networkDir := t.TempDir()
	d := &Daemon{
		networkd: networkd.NewInDir(networkDir),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell

	// An lo0 input filter is bound (so applyLo0Filter reaches the APPLY path and
	// the injected nft failure is the filter-not-installed failure). The single
	// zone's interface has NO firewall-local address, so even though #3405 makes
	// every zone host-inbound-enforcing (default-deny), the zone yields no
	// enforceable host-inbound view (no address to scope a drop): applyHostInbound
	// Filter takes the no-enforceable-view teardown branch, which is stubbed to
	// succeed above — keeping the injected error scoped to the lo0 apply wiring.
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "mgmt-lockdown"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"mgmt-lockdown": {
			Name: "mgmt-lockdown",
			Terms: []*config.FirewallFilterTerm{
				{Name: "deny-all", Action: config.FilterActionDiscard},
			},
		},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}

	err := d.applyConfigLocked(context.Background(), cfg)
	if err == nil {
		t.Fatal("applyConfigLocked must surface the lo0 nft failure " +
			"(fail-closed); got nil (the silent fail-open #3392 describes)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the lo0 failure "+
			"via errors.Join wiring, got %v", err)
	}
}

func TestApplyConfigRuntimeResultDrivesDownstreamConsumers(t *testing.T) {
	networkDir := t.TempDir()
	installFakeNetworkctl(t)

	dp := &runtimeOnlyApplyTestDP{
		applyResult: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint16{"trust": 7},
			ManagedInterfaces: []networkd.InterfaceConfig{{
				Name:      "ge-0-0-0",
				Addresses: []string{"192.0.2.1/24"},
			}},
		},
	}
	ss := cluster.NewSessionSync(":0", "127.0.0.1:4785", nil)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 2 }
	d := &Daemon{
		networkd:    networkd.NewInDir(networkDir),
		sessionSync: ss,
		store:       newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:     vrrp.NewManager(),
		opts:        Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 2,
				},
			},
		},
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust": {
					Name:       "trust",
					Interfaces: []string{"reth0.0"},
				},
			},
		},
	}

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("ApplyConfig calls = %d, want 1", dp.applyCalls)
	}
	if !ss.ShouldSyncZone(7) {
		t.Fatal("session sync did not use runtime ApplyResult ZoneIDs")
	}
	if ss.ShouldSyncZone(8) {
		t.Fatal("session sync unexpectedly owns unmapped zone 8")
	}

	networkPath := filepath.Join(networkDir, "10-xpf-ge-0-0-0.network")
	data, err := os.ReadFile(networkPath)
	if err != nil {
		t.Fatalf("read generated networkd file: %v", err)
	}
	if !strings.Contains(string(data), "Address=192.0.2.1/24") {
		t.Fatalf("networkd file missing runtime managed address:\n%s", string(data))
	}
}

func installFakeNetworkctl(t *testing.T) {
	t.Helper()
	binDir := t.TempDir()
	networkctl := filepath.Join(binDir, "networkctl")
	if err := os.WriteFile(networkctl, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake networkctl: %v", err)
	}
	// #3333: applyConfigLocked now surfaces a host-inbound `nft` apply/teardown
	// failure as a commit error (fail-closed). The CI/test host has no `nft`
	// binary, so without a benign stub these full-apply tests would fail on an
	// nft-not-found error unrelated to what they assert. Install a no-op nft
	// alongside networkctl (the host-inbound failure semantics themselves are
	// covered by the seam-injection tests in host_inbound_nft_test.go).
	nft := filepath.Join(binDir, "nft")
	if err := os.WriteFile(nft, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake nft: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
}
