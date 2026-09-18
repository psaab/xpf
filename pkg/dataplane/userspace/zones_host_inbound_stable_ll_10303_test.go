package userspace

import (
	"net"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// wantStableLL10303 mirrors cluster.StableRethLinkLocal byte-for-byte
// (pkg/cluster/reth.go: fe80::bf72:<cluster>:<rg>, no nodeID component). This
// package cannot import pkg/cluster (cluster imports pkg/dataplane), so the
// expectation pins the 16 bytes here; the production helper cites the same
// source.
func wantStableLL10303(t *testing.T, clusterID, rgID int) string {
	t.Helper()
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0, 0, 0xbf, 0x72, 0, byte(clusterID), 0, byte(rgID)}.String()
}

func stableLLHAConfig10303() *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:        7,
		NodeID:           0,
		NodeIDSet:        true,
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0, Addresses: []string{"10.0.61.1/24", "2001:db8:61::1/64"}},
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth0.0"}, HostInboundTraffic: &config.HostInboundTraffic{}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.50"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	return cfg
}

func viewsByZone10303(views []ZoneHostInboundView) map[string]ZoneHostInboundView {
	out := make(map[string]ZoneHostInboundView, len(views))
	for _, v := range views {
		out[v.Zone] = v
	}
	return out
}

func containsStr10303(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func countStr10303(hay []string, needle string) int {
	n := 0
	for _, h := range hay {
		if h == needle {
			n++
		}
	}
	return n
}

func keys10303(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestStableRethLLInViewsOnBackupRender10303 is the #10303 failover RED cell:
// a BACKUP render (no live stable LL anywhere — the address exists only on
// the MASTER) must still scope the deterministic fe80::bf72:<cluster>:<rg> in
// every zone whose RETH units carry it, exactly like VRRP VIPs (#3172).
// Without the union, host-bound traffic to the RA router address misses every
// deny after a failover and falls to `policy accept` (fail-open host
// exposure).
func TestStableRethLLInViewsOnBackupRender10303(t *testing.T) {
	cfg := stableLLHAConfig10303()
	want := wantStableLL10303(t, 7, 1)
	views := BuildZoneHostInboundViews(cfg)
	byZone := viewsByZone10303(views)
	for _, zone := range []string{"lan", "wan"} {
		v, ok := byZone[zone]
		if !ok {
			t.Fatalf("zone %s view missing (views=%+v)", zone, views)
		}
		if !containsStr10303(v.V6Addrs, want) {
			t.Errorf("BACKUP render: zone %s V6Addrs = %v, want containing stable LL %s (union deterministically like VIPs, #10303)", zone, v.V6Addrs, want)
		}
	}
}

// TestStableRethLLBackupEqualsMasterRender10303 pins mastership-independence:
// the BACKUP render (no live LL) must equal the MASTER render (live LL on
// every reth netdev), with exactly one copy per view. Pre-#10303 the LL was
// scoped only when live at the last apply, so the two renders disagreed.
func TestStableRethLLBackupEqualsMasterRender10303(t *testing.T) {
	cfg := stableLLHAConfig10303()
	want := wantStableLL10303(t, 7, 1)
	backup := BuildZoneHostInboundViews(cfg)

	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "" {
			return 0, 0, "", nil
		}
		return 42, 1500, "02:bf:72:07:01:00", []InterfaceAddressSnapshot{
			{Family: "inet6", Address: want + "/128"},
		}
	}
	master := BuildZoneHostInboundViews(cfg)

	sets := func(views []ZoneHostInboundView) map[string][]string {
		out := map[string][]string{}
		for _, v := range views {
			addrs := append(append([]string{}, v.V4Addrs...), v.V6Addrs...)
			sort.Strings(addrs)
			out[v.Zone] = addrs
		}
		return out
	}
	b, m := sets(backup), sets(master)
	if len(b) != len(m) {
		t.Fatalf("BACKUP zones = %v, MASTER zones = %v: renders must agree (#10303)", keys10303(b), keys10303(m))
	}
	for zone, bAddrs := range b {
		mAddrs, ok := m[zone]
		if !ok {
			t.Fatalf("zone %s missing from MASTER render", zone)
		}
		if !eqStr(bAddrs, mAddrs) {
			t.Errorf("zone %s: BACKUP addrs = %v, MASTER addrs = %v: stable LL must be unioned from config, not the live snapshot (#10303)", zone, bAddrs, mAddrs)
		}
	}
	renders := []struct {
		name  string
		views []ZoneHostInboundView
	}{{"BACKUP", backup}, {"MASTER", master}}
	for _, r := range renders {
		for _, v := range r.views {
			if n := countStr10303(v.V6Addrs, want); n != 1 {
				t.Errorf("%s render: zone %s carries %d copies of %s, want exactly 1 (dedup against the live snapshot, #10303)", r.name, v.Zone, n, want)
			}
		}
	}
}

// TestStableRethLLInFenceScope10303 is the #10303 cold-boot RED cell (zoned
// router): until the first commit the fence stands in for the real table, so
// its drop scope must include the stable LL.
func TestStableRethLLInFenceScope10303(t *testing.T) {
	cfg := stableLLHAConfig10303()
	want := wantStableLL10303(t, 7, 1)
	views := BuildZoneHostInboundViews(cfg)
	sets := BuildFenceAddrSets(cfg, views)
	byZone := viewsByZone10303(sets.Views)
	for _, zone := range []string{"lan", "wan"} {
		v, ok := byZone[zone]
		if !ok {
			t.Fatalf("fence: zone %s view missing", zone)
		}
		if !containsStr10303(v.V6Addrs, want) {
			t.Errorf("fence: zone %s V6Addrs = %v, want containing stable LL %s (#10303 cold-boot)", zone, v.V6Addrs, want)
		}
	}
}

// TestStableRethLLInFenceScopeZoneless10303 covers the zone-less router
// (Finding B, #6492): with no zones the fence derives its scope from
// firewall-local addresses, which must include the stable LL.
func TestStableRethLLInFenceScopeZoneless10303(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:        7,
		NodeID:           0,
		NodeIDSet:        true,
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"2001:db8:61::1/64"}},
		}},
	}
	want := wantStableLL10303(t, 7, 1)
	sets := BuildFenceAddrSets(cfg, nil)
	if !containsStr10303(sets.UnzonedV6, want) {
		t.Errorf("zone-less fence: UnzonedV6 = %v, want containing stable LL %s (#10303)", sets.UnzonedV6, want)
	}
}

// TestStableRethLLInUnzonedAddrs10303: a stable LL whose RG has NO zoned unit
// (unzoned RETH on a zoned router, #4420 HI-2) must land in the unzoned
// catch-all set; one already zoned must not duplicate there.
func TestStableRethLLInUnzonedAddrs10303(t *testing.T) {
	cfg := stableLLHAConfig10303()
	cfg.Chassis.Cluster.RedundancyGroups = []*config.RedundancyGroup{{ID: 1}, {ID: 2}}
	cfg.Interfaces.Interfaces["reth1"] = &config.InterfaceConfig{Name: "reth1", RedundancyGroup: 2, Units: map[int]*config.InterfaceUnit{
		0: {Number: 0, Addresses: []string{"2001:db8:62::1/64"}},
	}}
	// reth1 is bound to no zone; wan/lan bind reth0 units only.
	_, v6 := BuildUnzonedHostInboundAddrs(cfg)
	if !containsStr10303(v6, wantStableLL10303(t, 7, 2)) {
		t.Errorf("unzoned v6 = %v, want containing unzoned RG's stable LL %s (#10303)", v6, wantStableLL10303(t, 7, 2))
	}
	if containsStr10303(v6, wantStableLL10303(t, 7, 1)) {
		t.Errorf("unzoned v6 = %v: zoned RG's stable LL must be subtracted (already in zone views), not duplicated (#10303)", v6)
	}
}

// TestStableRethLLExplicitLinkLocalSuppresses10303 pins daemon parity: when
// unit 0 carries an explicit link-local, addStableRethLinkLocal installs
// nothing on that interface, so the views must not scope a phantom LL.
func TestStableRethLLExplicitLinkLocalSuppresses10303(t *testing.T) {
	cfg := stableLLHAConfig10303()
	cfg.Interfaces.Interfaces["reth0"].Units[0].Addresses = []string{"10.0.61.1/24", "2001:db8:61::1/64", "fe80::9/64"}
	want := wantStableLL10303(t, 7, 1)
	for _, v := range BuildZoneHostInboundViews(cfg) {
		if containsStr10303(v.V6Addrs, want) {
			t.Errorf("zone %s scopes phantom stable LL %s despite explicit unit-0 LL (daemon installs nothing there, #10303)", v.Zone, want)
		}
	}
}

// TestStableRethLLOnlyOnIPv6Units10303 pins per-unit placement: the daemon
// installs the LL on the base plus IPv6 VLAN units only. A v4-only VLAN
// unit's zone must not scope it — its drop would precede and shadow the base
// zone's accept under daddr-only matching.
func TestStableRethLLOnlyOnIPv6Units10303(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:        7,
		NodeID:           0,
		NodeIDSet:        true,
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0, Addresses: []string{"10.0.61.1/24", "2001:db8:61::1/64"}},
			60: {Number: 60, VlanID: 60, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth0.0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"dmz": {Name: "dmz", Interfaces: []string{"reth0.60"}, HostInboundTraffic: &config.HostInboundTraffic{}},
	}
	want := wantStableLL10303(t, 7, 1)
	byZone := viewsByZone10303(BuildZoneHostInboundViews(cfg))
	if v := byZone["lan"]; !containsStr10303(v.V6Addrs, want) {
		t.Errorf("lan V6Addrs = %v, want containing stable LL %s (base unit carries it, #10303)", v.V6Addrs, want)
	}
	if v := byZone["dmz"]; containsStr10303(v.V6Addrs, want) {
		t.Errorf("dmz V6Addrs = %v: v4-only unit's zone must not scope the LL the daemon never installs there (#10303)", v.V6Addrs)
	}
}
