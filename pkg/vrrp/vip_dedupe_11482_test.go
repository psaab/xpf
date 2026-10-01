package vrrp

import (
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestVIPDedupeAcrossUpdateAdvertAndGARP(t *testing.T) {
	const (
		canonical = "2001:db8::10/64"
		alias     = "2001:0DB8:0:0:0:0:0:10/64"
	)
	if canonicalVIPIdentity(canonical) != canonicalVIPIdentity(alias) {
		t.Fatal("test spellings do not have the same canonical VIP identity")
	}
	want := []string{canonical, alias}

	vi := newInstance(Instance{
		Interface: "vrrp11482", GroupID: 1, VirtualAddresses: want,
	}, nil, make(chan VRRPEvent, 1), nil)
	vi.addrsFn = func() ([]net.Addr, error) { return nil, nil }
	var emitted []string
	previousSendPacket := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, isIPv6 bool) error {
		if !isIPv6 {
			t.Error("IPv4 advert emitted for an IPv6-only VIP set")
		}
		for _, ip := range pkt.IPAddresses {
			emitted = append(emitted, ip.String())
		}
		return nil
	}
	defer func() { sendPacketFn = previousSendPacket }()
	vi.sendAdvert(100)
	if len(emitted) != 1 || emitted[0] != "2001:db8::10" {
		t.Fatalf("advert VIPs = %v, want one canonical IPv6 address", emitted)
	}

	if err := vi.updateVIPs(want); err != nil {
		t.Fatalf("updateVIPs() error = %v", err)
	}
	if got := vi.vipsSnapshot(); len(got) != 1 || canonicalVIPIdentity(got[0]) != canonicalVIPIdentity(canonical) {
		t.Fatalf("stored VIPs = %v, want one VIP with identity %q", got, canonicalVIPIdentity(canonical))
	}

	capacityVIPs := make([]string, 0, MaxConfiguredVIPs(true)+1)
	for i := 1; i <= MaxConfiguredVIPs(true); i++ {
		capacityVIPs = append(capacityVIPs, capacityBoundaryVIP(true, i))
	}
	capacityVIPs = append(capacityVIPs, capacityVIPs[0])
	if err := checkAdvertCapacity(capacityVIPs); err != nil {
		t.Fatalf("capacity-sized set plus a canonical duplicate must fit: %v", err)
	}

	vi.vipMu.Lock()
	vi.pendingGARPVIPs = map[string]struct{}{canonicalVIPIdentity(canonical): {}}
	announcements := vi.pendingGARPForSetLocked(want, nil, false)
	vi.vipMu.Unlock()
	if len(announcements) != 1 || canonicalVIPIdentity(announcements[0]) != canonicalVIPIdentity(canonical) {
		t.Fatalf("pending GARP VIPs = %v, want one canonical VIP", announcements)
	}
}

func TestUpdateVIPsReevaluatesCapacityAfterCanonicalDedupe(t *testing.T) {
	const (
		canonical = "2001:db8::10/64"
		alias     = "2001:0DB8:0:0:0:0:0:10/64"
	)
	vi := newInstance(Instance{
		Interface: "vrrp11482", GroupID: 1,
		VirtualAddresses: []string{canonical},
	}, nil, make(chan VRRPEvent, 1), nil)
	vi.addrsFn = func() ([]net.Addr, error) { return nil, nil }

	// Model an instance whose prior entry-based capacity result predates
	// canonicalization; the update's equivalent set must refresh that result.
	vi.mu.Lock()
	vi.cfg.VirtualAddresses = []string{canonical, alias}
	vi.advertCapacityErr = errors.New("stale entry-based capacity error")
	vi.mu.Unlock()

	if err := vi.updateVIPs([]string{canonical, alias}); err != nil {
		t.Fatalf("canonical-equivalent update failed: %v", err)
	}
	if err := vi.getAdvertCapacityErr(); err != nil {
		t.Fatalf("capacity error was not reevaluated after dedupe: %v", err)
	}
	if got := vi.vipsSnapshot(); len(got) != 1 {
		t.Fatalf("stored VIPs = %v, want one canonical identity", got)
	}
}

func TestCollectorsAndManagerDeduplicateCanonicalVIPs(t *testing.T) {
	const (
		canonical = "2001:db8::10/64"
		alias     = "2001:0DB8:0:0:0:0:0:10/64"
	)

	genericCfg := vrrpTestCfg("ge-0/0/0", false, map[int]*config.InterfaceUnit{
		0: {VRRPGroups: map[string]*config.VRRPGroup{
			"2001:db8::2/64_grp1": {
				ID:               1,
				VirtualAddresses: []string{canonical, alias},
			},
		}},
	})
	generic := CollectInstances(genericCfg)
	if len(generic) != 1 || len(generic[0].VirtualAddresses) != 1 {
		t.Fatalf("generic collector VIPs = %v, want one canonical VIP", generic)
	}

	rethCfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0": {
				Name:            "reth0",
				RedundancyGroup: 1,
				Units: map[int]*config.InterfaceUnit{
					0: {Addresses: []string{canonical}},
					1: {Addresses: []string{alias}},
				},
			},
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		}},
	}
	reth := CollectRethInstances(rethCfg, nil)
	if len(reth) != 1 || len(reth[0].VirtualAddresses) != 1 {
		t.Fatalf("untagged RETH VIPs = %v, want one canonical VIP across units", reth)
	}

	manager, _ := newTestManagerNoNetwork()
	defer stopManagerForTest(manager)
	if err := manager.UpdateInstances([]*Instance{{
		Interface: "vrrp11482", Family: "inet6", GroupID: 1,
		VirtualAddresses: []string{canonical, alias},
	}}); err != nil {
		t.Fatalf("UpdateInstances() error = %v", err)
	}
	vi := manager.instances[instanceKey{iface: "vrrp11482", groupID: 1, family: "inet6"}]
	if vi == nil {
		t.Fatal("manager did not build the desired VRRP instance")
	}
	if got := vi.vipsSnapshot(); len(got) != 1 || canonicalVIPIdentity(got[0]) != canonicalVIPIdentity(canonical) {
		t.Fatalf("manager stored VIPs = %v, want one canonical VIP", got)
	}
}
