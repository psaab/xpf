package daemon

import (
	"errors"
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

func TestHostInboundDesiredAndUncoveredIncludeIngressDeny13174(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{{
		Zone: "deny", V4Addrs: []string{"10.0.0.1"}, V6Addrs: []string{"2001:db8::1"},
		IngressDenyV4: []string{"192.0.2.50"}, IngressDenyV6: []string{"2001:db8::50"},
	}}
	desired := hostInboundDesiredDropAddrs(views, nil, nil)
	for fam, addr := range map[byte]string{'4': "192.0.2.50", '6': "2001:db8::50"} {
		if _, ok := desired[hostInboundDropAddrKey(fam, addr)]; !ok {
			t.Errorf("desiredDrop missing IngressDeny %s", addr)
		}
	}
	v4, v6 := hostInboundUncoveredDropAddrs(views, nil, nil, nil)
	if !slices.Contains(v4, "192.0.2.50") || !slices.Contains(v6, "2001:db8::50") {
		t.Errorf("uncovered = %v %v, want ingress-deny addrs", v4, v6)
	}
	covered := map[string]struct{}{hostInboundDropAddrKey('4', "192.0.2.50"): {}}
	v4, _ = hostInboundUncoveredDropAddrs(views, nil, nil, covered)
	if slices.Contains(v4, "192.0.2.50") {
		t.Error("covered ingress-deny addr must not be uncovered")
	}
}

func TestHostInboundGapFenceForUnleasedOnlyNewcomer13174(t *testing.T) {
	origInstaller := nftInstaller
	t.Cleanup(func() { nftInstaller = origInstaller })
	origSample := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = origSample })

	makeConfig := func(withDHCP bool) *config.Config {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}
		members := []string{"ge-0/0/0.0"}
		if withDHCP {
			cfg.Interfaces.Interfaces["ge-0/0/9"] = &config.InterfaceConfig{Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}}}
			members = append(members, "ge-0/0/9.0")
		}
		cfg.Security.Zones = map[string]*config.ZoneConfig{"trust": {
			Name: "trust", Interfaces: members,
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		}}
		return cfg
	}
	uni := int(netlink.SCOPE_UNIVERSE)
	sampleHostInboundSnapshots = func(_ *config.Config) []dpuserspace.InterfaceSnapshot {
		return []dpuserspace.InterfaceSnapshot{
			scriptedSnap10751("ge-0/0/0.0", "trust", scriptedAddr10751("inet", "192.0.2.1/24", uni)),
			scriptedSnap10751("ge-0/0/9.0", "trust"),
		}
	}
	nftInstaller = &fakeNftInstaller{}
	d := &Daemon{}
	if err := d.applyHostInboundFilter(makeConfig(false)); err != nil {
		t.Fatalf("initial host-inbound install: %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("initial host-inbound install did not establish enforcement")
	}
	installErr := errors.New("injected real host-inbound failure")
	var gapCalls int
	var gapSpec xnft.GapFenceSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return installErr },
		gapFence: func(spec xnft.GapFenceSpec) error {
			gapCalls++
			gapSpec = spec
			return nil
		},
	}
	err := d.applyHostInboundFilter(makeConfig(true))
	if !errors.Is(err, installErr) {
		t.Fatalf("failed real install error = %v, want injected error", err)
	}
	if gapCalls != 1 {
		t.Fatalf("unleased DHCP-only newcomer must install a gap fence, got %d calls", gapCalls)
	}
	if !slices.Contains(gapSpec.UnleasedV4, "ge-0-0-9") {
		t.Errorf("gap spec omitted new DHCP backstop: %+v", gapSpec)
	}
}

func TestHostInboundNoScopeTeardownClearsGapDebt13174(t *testing.T) {
	origInstaller := nftInstaller
	t.Cleanup(func() { nftInstaller = origInstaller })
	origSample := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = origSample })
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return nil }
	nftInstaller = &fakeNftInstaller{}
	d := &Daemon{}
	d.noteHostInboundGapApplyResult(errors.New("old gap failure"))
	if owed, _, _ := d.HostInboundGapDebt(); !owed {
		t.Fatal("precondition: gap debt must be owed")
	}
	if err := d.applyHostInboundFilter(&config.Config{}); err != nil {
		t.Fatalf("no-scope teardown: %v", err)
	}
	if owed, _, lastErr := d.HostInboundGapDebt(); owed || lastErr != "" {
		t.Fatalf("successful no-scope teardown left gap debt: owed=%v err=%q", owed, lastErr)
	}
}
