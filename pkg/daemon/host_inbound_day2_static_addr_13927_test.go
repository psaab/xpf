package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/vrrp"
)

func TestDay2StaticAddressFencePreservesDHCPBackstop13927(t *testing.T) {
	installFakeNetworkctl(t)
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	makeConfig := func(addresses []string, dhcp bool) *config.Config {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: addresses},
			}},
			"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, DHCP: dhcp},
			}},
		}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"wan": {Name: "wan", Interfaces: []string{"reth0.0", "reth1.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		}
		return cfg
	}

	injected := errors.New("host-inbound render failed")
	var gapSpecs []xnft.GapFenceSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return injected },
		gapFence: func(spec xnft.GapFenceSpec) error {
			gapSpecs = append(gapSpecs, spec)
			return nil
		},
	}

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	d.hostInboundEnforced.Store(true)
	d.hostInboundCoveredAddrs = map[string]struct{}{
		hostInboundDropAddrKey('4', "10.139.27.1"): {},
	}

	// First commit: a failed host-inbound render leaves an active gap whose
	// DHCP backstop protects a pending lease interface.
	if err := d.applyHostInboundFilter(makeConfig([]string{"10.139.27.1/24"}, true)); !errors.Is(err, injected) {
		t.Fatalf("initial failed render error = %v, want %v", err, injected)
	}
	if len(gapSpecs) != 1 || len(gapSpecs[0].UnleasedV4) == 0 {
		t.Fatalf("failed render did not leave an active DHCP backstop gap: %+v", gapSpecs)
	}

	// Next commit removes DHCP intent and adds a static address. Its temporary
	// address drop must use a distinct table so replacing it cannot erase the
	// still-active DHCP gap before networkd has applied the new configuration.
	d.afterNetworkdApplyForTest = func() {
		if len(gapSpecs) < 2 {
			t.Fatalf("networkd activated the new address without installing its preactivation fence: %+v", gapSpecs)
		}
		pre := gapSpecs[1]
		if !pre.PreActivation {
			t.Errorf("pre-networkd fence would replace the active DHCP gap table: %+v", pre)
		}
		if !sliceContains(pre.UncoveredV4, "10.139.27.2") {
			t.Errorf("pre-networkd fence omits new static address: %+v", pre)
		}
		if len(pre.UnleasedV4) != 0 || len(gapSpecs[0].UnleasedV4) == 0 {
			t.Errorf("preactivation replacement must leave the previous DHCP backstop intact in its own table: %+v", gapSpecs)
		}
	}
	cfg := makeConfig([]string{"10.139.27.1/24", "10.139.27.2/24"}, false)
	if err := d.applyConfigLocked(context.Background(), cfg); !errors.Is(err, injected) {
		t.Fatalf("day-2 apply error = %v, want host-inbound render failure %v", err, injected)
	}
	if len(gapSpecs) < 3 || gapSpecs[2].PreActivation || len(gapSpecs[2].UnleasedV4) == 0 {
		t.Errorf("failed tail render replaced the previous DHCP guard with incoming-config-only intent: %+v", gapSpecs)
	}
}

func TestDay2StaticAddressFencedBeforeNetworkd13927(t *testing.T) {
	installFakeNetworkctl(t)
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.139.27.2/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"reth0.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}

	var gapSpecs []xnft.GapFenceSpec
	nftInstaller = &fakeNftInstaller{
		gapFence: func(spec xnft.GapFenceSpec) error {
			gapSpecs = append(gapSpecs, spec)
			return nil
		},
	}

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	// Model an already-enforced day-1 generation which does not cover the new
	// day-2 address. The fence must be live before networkd activates it.
	d.hostInboundEnforced.Store(true)
	d.hostInboundCoveredAddrs = map[string]struct{}{
		hostInboundDropAddrKey('4', "10.139.27.1"): {},
	}
	d.afterNetworkdApplyForTest = func() {
		if len(gapSpecs) == 0 {
			t.Error("new static address reached networkd activation before a host-inbound preactivation fence was installed")
			return
		}
		if !gapSpecs[0].PreActivation {
			t.Errorf("new static address fence was not installed in its dedicated preactivation table: %+v", gapSpecs[0])
		}
		if !sliceContains(gapSpecs[0].UncoveredV4, "10.139.27.2") {
			t.Errorf("pre-networkd fence does not drop new static address: %+v", gapSpecs[0])
		}
		if len(gapSpecs[0].Views) != 0 || len(gapSpecs[0].WGZonePorts) != 0 {
			t.Errorf("pre-activation fence must deny host services uniformly before the new policy is installed: %+v", gapSpecs[0])
		}
	}

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("day-2 apply: %v", err)
	}
}
