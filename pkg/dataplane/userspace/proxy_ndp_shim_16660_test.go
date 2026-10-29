package userspace

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
)

// #16660: a unicast NS (NUD PROBE) to an IPv6 static-NAT/DNAT external
// that is NOT an interface address was LocalDelivered by the worker into
// the xpf-usp0 TUN, where the kernel's per-device proxy-NDP lookup
// misses the pneigh entry installed on the WAN netdev, so no NA was
// ever sent. The fix publishes the v6 proxy-NDP target set (per routing
// domain) to a shim map and passes hop-255 unicast NDP to such a
// destination on its ingress netdev via cpumap_or_pass, mirroring the
// #15117 interface-NAT arm.
//
// These cells pin (a) the Go desired-set builder, (b) the map sync, and
// (c) the retained XDP program itself via BPF_PROG_TEST_RUN: an NS to a
// non-interface proxy external must XDP_PASS with the
// session_miss_proxy_ndp branch counter, while the #15117 controls
// (off-link NS, echo, non-proxy destination) keep the worker path.

func proxyNDPSnapshot16660() *ConfigSnapshot {
	cfg := &config.Config{}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "ge-0/0/1.0", Addresses: []string{
			"2001:db8:0:1::10/128", // the static-NAT external (not an iface addr)
			"198.51.100.10/32",     // v4: never a proxy-NDP target
			"bogus/128",            // skipped, exactly as the installer skips it
		}},
		{Interface: "ge-0/0/2.0", Addresses: []string{"2001:db8:0:9::10/128"}},
	}
	return &ConfigSnapshot{
		Config: cfg,
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/1.0", RoutingDomain: 0, Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "2001:db8:0:1::1/64"},
			}},
			{Name: "ge-0/0/2.0", RoutingDomain: 100042},
		},
	}
}

func TestBuildDesiredProxyNDPAddressSets16660(t *testing.T) {
	got := buildDesiredProxyNDPAddressSets(proxyNDPSnapshot16660(), nil)
	ext := netip.MustParseAddr("2001:db8:0:1::10")
	vr := netip.MustParseAddr("2001:db8:0:9::10")
	want := map[userspaceLocalV6Key]struct{}{
		{Domain: 0, Addr: ext.As16()}:     {},
		{Domain: 100042, Addr: vr.As16()}: {},
	}
	if len(got) != len(want) {
		t.Fatalf("proxy-NDP desired set = %v, want exactly %v (v4, malformed and unscoped entries excluded)", got, want)
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("proxy-NDP desired set missing %+v; got %v", k, got)
		}
	}
	// The external must key under the domain of ITS interface only: the
	// same address arriving in the foreign domain must not pass.
	if _, ok := got[userspaceLocalV6Key{Domain: 100042, Addr: ext.As16()}]; ok {
		t.Fatalf("external keyed under foreign domain 100042: %+v", got)
	}
	// Nil / config-less snapshots yield an empty (prune-all) set, never a panic.
	if s := buildDesiredProxyNDPAddressSets(nil, nil); len(s) != 0 {
		t.Fatalf("nil snapshot desired = %v, want empty", s)
	}
	if s := buildDesiredProxyNDPAddressSets(&ConfigSnapshot{}, nil); len(s) != 0 {
		t.Fatalf("config-less snapshot desired = %v, want empty", s)
	}
}

func TestBuildDesiredProxyNDPAddressSetsResolvesInterfaceAliases17743(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {Name: "ge-0/0/1"},
			"ge-0/0/2": {Name: "ge-0/0/2"},
		}},
	}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{{
		Interface: "ge-0-0-1",
		Addresses: []string{"2001:db8:1774::1/128"},
	}}
	snapshot := &ConfigSnapshot{
		Config: cfg,
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", RoutingDomain: 17},
			{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", RoutingDomain: 18},
		},
	}

	addr := netip.MustParseAddr("2001:db8:1774::1").As16()
	got := buildDesiredProxyNDPAddressSets(snapshot, nil)
	want := userspaceLocalV6Key{Domain: 17, Addr: addr}
	if len(got) != 1 {
		t.Fatalf("proxy-NDP desired set = %v, want only the resolved interface's target %+v", got, want)
	}
	if _, ok := got[want]; !ok {
		t.Fatalf("proxy-NDP desired set missing cross-spelled target %+v; got %v", want, got)
	}
	if _, ok := got[userspaceLocalV6Key{Domain: 18, Addr: addr}]; ok {
		t.Fatalf("proxy-NDP target was published for genuinely different interface ge-0/0/2: %v", got)
	}
}

func TestSyncProxyNDPAddressMaps16660(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	proxyMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 20, ValueSize: 1, MaxEntries: 16,
	})
	if err != nil {
		t.Skipf("new userspace_proxy_ndp_v6_domain map: %v", err)
	}
	t.Cleanup(func() { proxyMap.Close() })
	injectShimMap(t, m.bpfShim, mapNameUserspaceProxyNDPv6, proxyMap)

	stale := userspaceLocalV6Key{Domain: 0, Addr: netip.MustParseAddr("2001:db8::dead").As16()}
	if err := proxyMap.Update(stale, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed stale proxy entry: %v", err)
	}
	if err := m.syncProxyNDPAddressMapsWithSetsLocked(buildDesiredProxyNDPAddressSets(proxyNDPSnapshot16660(), nil)); err != nil {
		t.Fatalf("syncProxyNDPAddressMapsWithSetsLocked: %v", err)
	}
	ext := userspaceLocalV6Key{Domain: 0, Addr: netip.MustParseAddr("2001:db8:0:1::10").As16()}
	var got uint8
	if err := proxyMap.Lookup(ext, &got); err != nil {
		t.Fatalf("proxy external missing after sync: %v", err)
	}
	if err := proxyMap.Lookup(stale, &got); !errIsNotExist(err) {
		t.Fatalf("stale proxy entry lookup err = %v, want ErrKeyNotExist", err)
	}
	// A follow-up sync against an empty desired set prunes everything.
	if err := m.syncProxyNDPAddressMapsWithSetsLocked(map[userspaceLocalV6Key]struct{}{}); err != nil {
		t.Fatalf("syncProxyNDPAddressMapsWithSetsLocked (empty): %v", err)
	}
	if err := proxyMap.Lookup(ext, &got); !errIsNotExist(err) {
		t.Fatalf("proxy entry after empty sync lookup err = %v, want ErrKeyNotExist", err)
	}
}

func errIsNotExist(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}

// BPF cell: the retained shim object itself. Pre-fix there is no proxy
// map and no session_miss_proxy_ndp arm, so the NS to the external
// takes the worker redirect (redirect_err drop on the empty XSK map);
// post-fix it passes to the kernel on the ingress netdev.
func TestUserspaceXDPProxyNDP16660(t *testing.T) {
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x99}
	ext := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x10}
	other := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x77}

	hop64 := icmpv6TestPacket(src, ext, 135)
	hop64[14+7] = 64 // IPv6 hop limit byte

	cases := []struct {
		name       string
		packet     []byte
		wantAction uint32
		wantArm    string
		absentArms []string
	}{
		{
			name:       "unicast NS hop 255 to non-interface proxy external passes to kernel",
			packet:     icmpv6TestPacket(src, ext, 135),
			wantAction: xdpActionPass,
			wantArm:    "session_miss_proxy_ndp",
			absentArms: []string{"session_miss_redirect", "redirect_err", "session_miss_nat_ndp"},
		},
		{
			name:       "NA hop 255 to proxy external passes to kernel",
			packet:     icmpv6TestPacket(src, ext, 136),
			wantAction: xdpActionPass,
			wantArm:    "session_miss_proxy_ndp",
			absentArms: []string{"redirect_err"},
		},
		{
			name:       "off-link NS hop 64 to proxy external stays on worker path",
			packet:     hop64,
			wantAction: xdpActionDrop,
			wantArm:    "redirect_err",
			absentArms: []string{"session_miss_proxy_ndp"},
		},
		{
			name:       "echo request to proxy external stays on worker path",
			packet:     icmpv6TestPacket(src, ext, 128),
			wantAction: xdpActionDrop,
			wantArm:    "redirect_err",
			absentArms: []string{"session_miss_proxy_ndp"},
		},
		{
			name:       "NS to a non-proxy global destination stays on worker path",
			packet:     icmpv6TestPacket(src, other, 135),
			wantAction: xdpActionDrop,
			wantArm:    "redirect_err",
			absentArms: []string{"session_miss_proxy_ndp"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			seedHealthy16241(t, coll, 0)
			updateUserspaceXDPTestMap(t, coll, mapNameUserspaceProxyNDPv6,
				userspaceLocalV6Key{Domain: 0, Addr: ext}, uint8(1))
			got := runUserspaceXDPTestPacket(t, coll, tc.packet)
			if got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
			assertXDPBranchStat(t, coll, tc.wantArm)
			for _, absent := range tc.absentArms {
				assertXDPBranchStatAbsent(t, coll, absent)
			}
		})
	}
}

// TestBuildDesiredProxyNDPAddressSetsSuppressesNotOwnedRG17742 exercises the
// same per-RG primary source wired by the daemon. A proxy-NDP target on a
// peer-owned RETH must never reach the shim's domain/address set.
func TestBuildDesiredProxyNDPAddressSetsSuppressesNotOwnedRG17742(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1}, {ID: 2}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1": {Name: "reth1", RedundancyGroup: 1},
		"reth2": {Name: "reth2", RedundancyGroup: 2},
	}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "reth1", Addresses: []string{"2001:db8:1::10/128"}},
		{Interface: "reth2", Addresses: []string{"2001:db8:2::10/128"}},
	}
	snapshot := &ConfigSnapshot{
		Config: cfg,
		Interfaces: []InterfaceSnapshot{
			// These deliberately disagree with the config's resolved RGs:
			// target ownership must come from the config reference resolver,
			// not an authored or stale snapshot label.
			{Name: "reth1", RoutingDomain: 101, RedundancyGroup: 2},
			{Name: "reth2", RoutingDomain: 202, RedundancyGroup: 1},
		},
	}
	var queriedRGs []int
	primary := RGPrimaryProvider(func(rgID int) (bool, bool) {
		queriedRGs = append(queriedRGs, rgID)
		return rgID == 1, true
	})
	got := buildDesiredProxyNDPAddressSets(snapshot, primary)
	owned := userspaceLocalV6Key{
		Domain: 101,
		Addr:   netip.MustParseAddr("2001:db8:1::10").As16(),
	}
	peerOwned := userspaceLocalV6Key{
		Domain: 202,
		Addr:   netip.MustParseAddr("2001:db8:2::10").As16(),
	}
	if _, ok := got[owned]; !ok {
		t.Fatalf("locally-owned RG target missing from desired set: %+v (got %v)", owned, got)
	}
	if _, ok := got[peerOwned]; ok {
		t.Fatalf("peer-owned RG target published to desired set: %+v", peerOwned)
	}

	if len(queriedRGs) != 2 || queriedRGs[0] != 1 || queriedRGs[1] != 2 {
		t.Fatalf("primary provider queried for RGs %v, want config-resolved [1 2]", queriedRGs)
	}
	unknown := buildDesiredProxyNDPAddressSets(snapshot, func(int) (bool, bool) {
		return false, false
	})
	if _, ok := unknown[owned]; !ok {
		t.Fatalf("unknown-owner RG target missing from desired set: %+v (got %v)", owned, unknown)
	}
	if _, ok := unknown[peerOwned]; !ok {
		t.Fatalf("unknown-owner RG target suppressed from desired set: %+v", peerOwned)
	}
}
