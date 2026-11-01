package daemon

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18617, live on loss: during test-failover's manual RG1 failback slice, RG1
// (WAN, reth0) is on node0 while RG2 (LAN, reth1) stays on node1. node0 denied
// one packet a second, every one of them
//
//	[2001:559:8585:50::8]:<eph> -> [2001:559:8585:ef00:...:d017]:1 UDP  wan->wan default deny
//
// That is warmNeighborCache's probe to the LAN host, sent by node0 through its
// WAN default route because node0 holds no LAN address, returned by the
// upstream router to the cluster's own WAN address, and denied as transit.
// Probes to the source-NAT pool / proxy-ARP address 172.16.80.7 looped the
// same way through whichever node answers ARP for it.

// splitWarmConfig18617 is the loss shape, reduced: reth0 (RG1, WAN) with VLAN
// units 50 and 80, reth1 (RG2, LAN), a pool + proxy-ARP address, and a
// non-RETH management unit. Member names follow node0.
func splitWarmConfig18617() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
			50: {VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:559:8585:50::8/64"}},
			80: {VlanID: 80, Addresses: []string{"172.16.80.8/24", "2001:559:8585:80::8/64"}},
		}},
		"reth1": {Name: "reth1", RedundancyGroup: 2, Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"10.0.61.1/24", "2001:559:8585:ef00::1/64"}},
		}},
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"192.168.99.10/24"}},
		}},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-snat-pool": {Name: "pool-snat-pool", Addresses: []string{"172.16.80.7/32"}},
	}
	cfg.Security.NAT.ProxyARP = []*config.ProxyARPEntry{
		{Interface: "reth0.80", Addresses: []string{"172.16.80.7/32"}},
	}
	return cfg
}

// splitWarmInputs18617 models node0 in the split: primary for RG1 only. The
// kernel holds exactly the addresses of the units this node owns, which is
// what bondless RETH does (a standby holds no VIP on its member).
func splitWarmInputs18617(primary map[int]bool) neighborWarmPlanInputs {
	held := map[string][]string{
		"fxp0": {"192.168.99.10/24"},
	}
	if primary[1] {
		held["ge-0-0-2.50"] = []string{"172.16.50.8/24", "2001:559:8585:50::8/64"}
		held["ge-0-0-2.80"] = []string{"172.16.80.8/24", "2001:559:8585:80::8/64"}
	}
	if primary[2] {
		held["ge-0-0-1"] = []string{"10.0.61.1/24", "2001:559:8585:ef00::1/64"}
	}
	return neighborWarmPlanInputs{
		rgPrimary: func(rg int) bool { return primary[rg] },
		localAddrs: func(ifname string) []netip.Prefix {
			var out []netip.Prefix
			for _, s := range held[ifname] {
				out = append(out, netip.MustParsePrefix(s))
			}
			return out
		},
	}
}

// warmEndpointStore18617 yields one forward session per endpoint pair.
type warmEndpointStore18617 struct {
	dataplane.SessionStore
	v4 [][2]netip.Addr
	v6 [][2]netip.Addr
}

func (s *warmEndpointStore18617) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, p := range s.v4 {
		if !fn(dataplane.SessionKey{SrcIP: p[0].As4(), DstIP: p[1].As4()}, dataplane.SessionValue{}) {
			return nil
		}
	}
	return nil
}

func (s *warmEndpointStore18617) ForEachV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, p := range s.v6 {
		if !fn(dataplane.SessionKeyV6{SrcIP: p[0].As16(), DstIP: p[1].As16()}, dataplane.SessionValueV6{}) {
			return nil
		}
	}
	return nil
}

var (
	lanHost4      = netip.MustParseAddr("10.0.61.102")
	lanHost6      = netip.MustParseAddr("2001:559:8585:ef00:1266:6aff:fe0b:d017")
	wanTarget4    = netip.MustParseAddr("172.16.80.200")
	wanTarget6    = netip.MustParseAddr("2001:559:8585:80::200")
	poolAddr      = netip.MustParseAddr("172.16.80.7")
	wanVIP4       = netip.MustParseAddr("172.16.50.8")
	internetHost4 = netip.MustParseAddr("8.8.8.8")
	internetHost6 = netip.MustParseAddr("2606:4700:4700::1111")
	mgmtHost4     = netip.MustParseAddr("192.168.99.20")
)

func runSplitWarm18617(t *testing.T, primary map[int]bool) (*countingWarmDialer, *neighborWarmCounts) {
	t.Helper()
	dialer := newCountingWarmDialer()
	d := &Daemon{neighborWarmDialer: dialer, neighborWarmPlanInputs: splitWarmInputs18617(primary)}
	d.setDataplane(&warmNeighborTestDP{store: &warmEndpointStore18617{
		v4: [][2]netip.Addr{
			{lanHost4, wanTarget4},    // the iperf flow
			{poolAddr, wanTarget4},    // a pool-SNAT forward entry carries the pool address
			{lanHost4, internetHost4}, // an internet flow
			{wanVIP4, internetHost4},  // a host flow from the WAN VIP
			{mgmtHost4, mgmtHost4},    // an SSH client on the non-RETH management unit
		},
		v6: [][2]netip.Addr{
			{lanHost6, wanTarget6},
			{lanHost6, internetHost6},
		},
	}})
	d.warmNeighborCacheFor(splitWarmConfig18617())
	counts := d.lastNeighborWarmCounts.Load()
	if counts == nil {
		t.Fatal("warmNeighborCacheFor recorded no counts")
	}
	return dialer, counts
}

func probedSet18617(dialer *countingWarmDialer) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	for a := range dialer.probedV4 {
		out[a] = dialer.boundTo[a]
	}
	for a := range dialer.probedV6 {
		out[a] = dialer.boundTo[a]
	}
	return out
}

// The defect shape: node0 holds RG1 (WAN) but not RG2 (LAN). RED on revert:
// before #18617 every global endpoint was probed through an unbound socket,
// the LAN host and the pool address included.
func TestWarmProbesOnlyHeldOnLinkEndpoints18617(t *testing.T) {
	dialer, counts := runSplitWarm18617(t, map[int]bool{1: true})
	got := probedSet18617(dialer)
	want := map[netip.Addr]string{
		wanTarget4: "ge-0-0-2.80", // on-link on an owned RETH prefix, bound to its unit
		wanTarget6: "ge-0-0-2.80",
		mgmtHost4:  "fxp0", // on-link on a non-RETH unit
	}
	for a, ifname := range want {
		if got[a] != ifname {
			t.Errorf("%v: probed on %q, want %q", a, got[a], ifname)
		}
	}
	for a, ifname := range got {
		if _, ok := want[a]; !ok {
			t.Errorf("%v probed on %q; want no probe (routed, owned, or on a RETH prefix this node does not hold)", a, ifname)
		}
	}
	if counts.skippedOwned != 2 { // pool 172.16.80.7, WAN VIP 172.16.50.8
		t.Errorf("skippedOwned=%d, want 2", counts.skippedOwned)
	}
	if counts.skippedNotHeld != 2 { // LAN host v4 and v6 on reth1 (RG2 not here)
		t.Errorf("skippedNotHeld=%d, want 2", counts.skippedNotHeld)
	}
	if counts.skippedRouted != 2 { // 8.8.8.8, 2606:4700:4700::1111
		t.Errorf("skippedRouted=%d, want 2", counts.skippedRouted)
	}
}

// Twin: the same node once it also owns the LAN. The LAN host is now on-link
// on a held prefix and is probed on the LAN member, so the predicate is keyed
// on ownership, not on the endpoint's zone.
func TestWarmProbesLANHostOnceLANIsHeld18617(t *testing.T) {
	dialer, counts := runSplitWarm18617(t, map[int]bool{1: true, 2: true})
	got := probedSet18617(dialer)
	for _, a := range []netip.Addr{lanHost4, lanHost6} {
		if got[a] != "ge-0-0-1" {
			t.Errorf("%v: probed on %q, want ge-0-0-1 (reth1's local member)", a, got[a])
		}
	}
	if _, ok := got[poolAddr]; ok {
		t.Error("the pool / proxy-ARP address must never be probed, even on its own prefix")
	}
	if counts.skippedNotHeld != 0 {
		t.Errorf("skippedNotHeld=%d, want 0 with every RG held", counts.skippedNotHeld)
	}
}

// A standby holds no RETH prefix, so only the non-RETH unit is probed. The
// RG-ownership conjunct matters on its own: even a kernel that still showed
// the address must not make a standby source probes from a VIP.
func TestWarmProbesNothingOnRETHPrefixesOfAStandby18617(t *testing.T) {
	in := splitWarmInputs18617(map[int]bool{1: true, 2: true}) // kernel holds everything
	in.rgPrimary = func(int) bool { return false }             // but this node owns no RG
	dialer := newCountingWarmDialer()
	d := &Daemon{neighborWarmDialer: dialer, neighborWarmPlanInputs: in}
	d.setDataplane(&warmNeighborTestDP{store: &warmEndpointStore18617{
		v4: [][2]netip.Addr{{lanHost4, wanTarget4}, {mgmtHost4, mgmtHost4}},
	}})
	d.warmNeighborCacheFor(splitWarmConfig18617())
	got := probedSet18617(dialer)
	if len(got) != 1 || got[mgmtHost4] != "fxp0" {
		t.Errorf("standby probed %v; want only %v on fxp0", got, mgmtHost4)
	}
}

// The longest configured prefix decides. A /26 carved out of a held /24 on a
// different, unheld unit must not be probed on the /24's interface: the kernel
// would route it out the /26's interface.
func TestWarmLongestConfiguredPrefixDecides18617(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*config.InterfaceUnit{0: {Addresses: []string{"10.9.0.1/24"}}}},
		"ge-0/0/4": {Name: "ge-0/0/4", Units: map[int]*config.InterfaceUnit{0: {Addresses: []string{"10.9.0.65/26"}}}},
	}
	plan := buildNeighborWarmPlan(cfg, neighborWarmPlanInputs{
		localAddrs: func(ifname string) []netip.Prefix {
			if ifname == "ge-0-0-3" {
				return []netip.Prefix{netip.MustParsePrefix("10.9.0.1/24")}
			}
			return nil // ge-0-0-4 holds nothing
		},
	})
	if ifname, v := plan.classify(netip.MustParseAddr("10.9.0.70")); v != neighborWarmNotHeld {
		t.Errorf("10.9.0.70 classified %v on %q; want not-held (its /26 is unheld)", v, ifname)
	}
	if ifname, v := plan.classify(netip.MustParseAddr("10.9.0.10")); v != neighborWarmProbe || ifname != "ge-0-0-3" {
		t.Errorf("10.9.0.10 classified %v on %q; want probe on ge-0-0-3", v, ifname)
	}
}

// A DHCP unit has no configured prefix; it is on-link for the lease the
// kernel holds, and the lease address itself is owned.
func TestWarmDHCPUnitUsesTheHeldLease18617(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {DHCP: true}}},
	}
	plan := buildNeighborWarmPlan(cfg, neighborWarmPlanInputs{
		localAddrs: func(ifname string) []netip.Prefix {
			if ifname == "fxp0" {
				return []netip.Prefix{netip.MustParsePrefix("10.136.126.45/24")}
			}
			return nil
		},
	})
	if ifname, v := plan.classify(netip.MustParseAddr("10.136.126.1")); v != neighborWarmProbe || ifname != "fxp0" {
		t.Errorf("DHCP gateway classified %v on %q; want probe on fxp0", v, ifname)
	}
	if _, v := plan.classify(netip.MustParseAddr("10.136.126.45")); v != neighborWarmOwned {
		t.Errorf("the DHCP lease address classified %v; want owned", v)
	}
}

// forceProbeNeighbors re-validates kernel neighbour entries. The kernel can
// hold one for the pool / proxy-ARP address; it must not be force-probed.
// RED if collectMonitoredNeighbors stops consulting the owned set.
type forceProbeDP18617 struct {
	dataplane.RuntimeDataPlane
	neighbors []net.IP
}

func (f *forceProbeDP18617) RegenerateNeighborSnapshot() {}
func (f *forceProbeDP18617) LookupSnapshotNeighbor(int, net.IP) *userspace.NeighborSnapshot {
	return nil
}
func (f *forceProbeDP18617) SnapshotHasIfindex(int) bool { return true }
func (f *forceProbeDP18617) IsMonitoredIfindex(int) bool { return true }
func (f *forceProbeDP18617) ForEachSnapshotNeighbor(fn func(int, net.IP)) {
	for _, ip := range f.neighbors {
		fn(1, ip)
	}
}

func TestForceProbeSkipsClusterOwnedNeighbours18617(t *testing.T) {
	d := &Daemon{neighborWarmPlanInputs: splitWarmInputs18617(map[int]bool{1: true})}
	d.setDataplane(&forceProbeDP18617{neighbors: []net.IP{
		net.ParseIP("172.16.80.7"),   // pool / proxy-ARP
		net.ParseIP("172.16.80.200"), // a real neighbour
	}})
	targets := d.collectMonitoredNeighbors(splitWarmConfig18617())
	got := map[string]bool{}
	for _, tg := range targets {
		got[tg.ip.String()] = true
	}
	if got["172.16.80.7"] {
		t.Errorf("force-probe targets %v include the pool / proxy-ARP address", got)
	}
	if !got["172.16.80.200"] {
		t.Errorf("force-probe targets %v lost the real neighbour", got)
	}
}

// The two per-second lines must not log at Info (CLAUDE.md logging rule).
func TestWarmLinesLogAtDebug18617(t *testing.T) {
	logs, restore := captureSlog(t)
	defer restore()
	dialer := newCountingWarmDialer()
	d := &Daemon{neighborWarmDialer: dialer, neighborWarmPlanInputs: splitWarmInputs18617(map[int]bool{1: true})}
	d.setDataplane(&warmNeighborTestDP{store: &warmEndpointStore18617{
		v4: [][2]netip.Addr{{lanHost4, wanTarget4}},
	}})
	d.warmNeighborCacheFor(splitWarmConfig18617())
	out := logs.String()
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "neighbor cache warmup complete") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no warmup-complete line logged: %q", out)
	}
	if !strings.Contains(line, "level=DEBUG") {
		t.Errorf("warmup-complete logged at a level above Debug: %q", line)
	}
	if !strings.Contains(line, "skipped_not_held=") {
		t.Errorf("warmup-complete line does not carry the skipped counts: %q", line)
	}
}

// Each owned-address source on its own, so dropping any one of them is RED:
// a RETH VIP this node does not hold now, a VRRP virtual address, a pool
// address with no proxy-ARP entry, a pool prefix, and a proxy-ARP address
// with no pool. All of them sit inside a held on-link prefix, so only the
// owned set keeps them from being probed.
func TestWarmOwnedSetCoversEverySource18617(t *testing.T) {
	cfg := splitWarmConfig18617()
	cfg.Interfaces.Interfaces["ge-0/0/5"] = &config.InterfaceConfig{Name: "ge-0/0/5", Units: map[int]*config.InterfaceUnit{
		0: {Addresses: []string{"10.20.0.1/24"}, VRRPGroups: map[string]*config.VRRPGroup{
			"10.20.0.1/24": {VirtualAddresses: []string{"10.20.0.254"}},
		}},
	}}
	cfg.Security.NAT.SourcePools["only-pool"] = &config.NATPool{Name: "only-pool", Addresses: []string{"10.20.0.9"}}
	cfg.Security.NAT.SourcePools["prefix-pool"] = &config.NATPool{Name: "prefix-pool", Addresses: []string{"10.20.0.32/30"}}
	cfg.Security.NAT.ProxyARP = append(cfg.Security.NAT.ProxyARP,
		&config.ProxyARPEntry{Interface: "ge-0/0/5.0", Addresses: []string{"10.20.0.77/32"}})
	in := splitWarmInputs18617(map[int]bool{1: true})
	base := in.localAddrs
	in.localAddrs = func(ifname string) []netip.Prefix {
		if ifname == "ge-0-0-5" {
			return []netip.Prefix{netip.MustParsePrefix("10.20.0.1/24")}
		}
		return base(ifname)
	}
	plan := buildNeighborWarmPlan(cfg, in)
	for _, tc := range []struct {
		name string
		ip   string
	}{
		{"RETH VIP of an RG this node does not own", "10.0.61.1"},
		{"VRRP virtual address", "10.20.0.254"},
		{"pool address without proxy-ARP", "10.20.0.9"},
		{"address inside a pool prefix", "10.20.0.34"},
		{"proxy-ARP address without a pool", "10.20.0.77"},
	} {
		if _, v := plan.classify(netip.MustParseAddr(tc.ip)); v != neighborWarmOwned {
			t.Errorf("%s (%s) classified %v; want owned", tc.name, tc.ip, v)
		}
	}
	if ifname, v := plan.classify(netip.MustParseAddr("10.20.0.50")); v != neighborWarmProbe || ifname != "ge-0-0-5" {
		t.Errorf("control 10.20.0.50 classified %v on %q; want probe on ge-0-0-5", v, ifname)
	}
}
