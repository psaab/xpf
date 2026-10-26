package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #12190 — a suppressed learned route's MTU must survive on the surviving
// config static.
//
// A non-FRR kernel route with RTAX_MTU (RTPROT_STATIC, BOOT or DHCP —
// protocols the importer deliberately admits) for a config-static prefix is
// suppressed by the gap-fill comparison when the static is at least as
// preferred. The suppression `continue` drops the learned row together with
// its MTU, and config statics carry no MTU, so the surviving row emits MTU 0
// (unconstrained) and the Rust FIB forwards oversized DF packets it should
// PTB against the kernel-selected constraint.
//
// RED on STEP-0 base: the surviving preference-5 static emits MTU 0.
func TestSuppressedLearnedRouteMTUMergesOntoSurvivingStatic12190(t *testing.T) {
	cfg := cfgWithStaticDefault("192.0.2.1")
	cfg.RoutingOptions.StaticRoutes[0].Preference = 5
	learned := learnedV4("0.0.0.0/0", "192.0.2.1")
	learned.Protocol = "static"
	learned.MTU = 1400
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", out)
	if len(hits) != 1 {
		t.Fatalf("preference-5 config default must be the sole route, got %d: %+v", len(hits), hits)
	}
	if hits[0].Preference != 5 || !reflect.DeepEqual(hits[0].NextHops, []string{"192.0.2.1"}) {
		t.Fatalf("better-preference config route lost: %+v", hits[0])
	}
	if hits[0].MTU != 1400 {
		t.Fatalf("surviving static MTU = %d, want learned constraint 1400: %+v", hits[0].MTU, hits[0])
	}
}

// A competing route's MTU is not a constraint on a different configured
// next-hop; only an identical selected path inherits the kernel MTU.
func TestSuppressedLearnedRouteMTUDoesNotConstrainDifferentStaticNextHop12190(t *testing.T) {
	cfg := cfgWithStaticDefault("192.0.2.1")
	cfg.RoutingOptions.StaticRoutes[0].Preference = 5
	learned := learnedV4("0.0.0.0/0", "198.51.100.254")
	learned.Protocol = "static"
	learned.MTU = 1400
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", out)
	if len(hits) != 1 || hits[0].Preference != 5 ||
		!reflect.DeepEqual(hits[0].NextHops, []string{"192.0.2.1"}) ||
		hits[0].MTU != 0 {
		t.Fatalf("competing route must not constrain the static next-hop: %+v", hits)
	}
}
func requireSuppressedMTU(t *testing.T, out []RouteSnapshot, table, family, destination string, want int) RouteSnapshot {
	t.Helper()
	hits := snapshotFor(t, table, family, destination, out)
	if len(hits) != 1 {
		t.Fatalf("%s %s %s: got %d snapshots, want one: %+v", table, family, destination, len(hits), hits)
	}
	if hits[0].MTU != want {
		t.Fatalf("%s %s %s: MTU = %d, want %d: %+v", table, family, destination, hits[0].MTU, want, hits[0])
	}
	return hits[0]
}

func suppressedMTULearnedV4(destination string, mtu int, nextHops ...string) routing.LearnedRoute {
	return routing.LearnedRoute{
		TableID: 254, Family: netlink.FAMILY_V4, Destination: destination,
		NextHops: nextHops, Protocol: "static", MTU: mtu,
	}
}

func suppressedMTULearnedV6(destination string, mtu int, nextHops ...string) routing.LearnedRoute {
	return routing.LearnedRoute{
		TableID: 254, Family: netlink.FAMILY_V6, Destination: destination,
		NextHops: nextHops, Protocol: "static", MTU: mtu,
	}
}

// Host bits in a configured prefix must not defeat the canonical prefix
// identity used to suppress the learned row and carry its MTU.
func TestSuppressedLearnedRouteMTUMatchesHostBitsPrefix12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "10.20.30.1/24", Preference: 5,
		NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}},
	}}
	learned := suppressedMTULearnedV4("10.20.30.0/24", 1400, "192.0.2.1")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet.0", "inet", "10.20.30.1/24", 1400)
}

// Uppercase/non-canonical IPv6 text and its canonical kernel prefix have the
// same suppression identity.
func TestSuppressedLearnedRouteMTUMatchesNonCanonicalV6Prefix12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{{
		Destination: "2001:DB8:1::/48", Preference: 5,
		NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}},
	}}
	learned := suppressedMTULearnedV6("2001:db8:1::/48", 1400, "2001:db8::1")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet6.0", "inet6", "2001:DB8:1::/48", 1400)
}

func TestSuppressedLearnedRouteMTUMatchesJunosLinuxLinkLocal12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{{
		Destination: "::/0", Preference: 5,
		NextHops: []config.NextHopEntry{{
			Address: "fe80::1", Interface: "ge-0/0/0.0",
		}},
	}}
	learned := suppressedMTULearnedV6("::/0", 1400, "fe80::1@ge-0-0-0")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet6.0", "inet6", "::/0", 1400)
}

func TestSuppressedLearnedRouteMTUMatchesQualifiedV4ToBare12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0", Preference: 5,
		NextHops: []config.NextHopEntry{{
			Address: "192.0.2.1", Interface: "ge-0/0/0.0",
		}},
	}}
	learned := suppressedMTULearnedV4("0.0.0.0/0", 1400, "192.0.2.1")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet.0", "inet", "0.0.0.0/0", 1400)
}

func TestSuppressedLearnedRouteMTUMatchesReorderedECMP12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0", Preference: 5,
		NextHops: []config.NextHopEntry{
			{Address: "192.0.2.1"},
			{Address: "192.0.2.2"},
		},
	}}
	learned := suppressedMTULearnedV4(
		"0.0.0.0/0", 1400, "192.0.2.2", "192.0.2.1",
	)
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hit := requireSuppressedMTU(t, out, "inet.0", "inet", "0.0.0.0/0", 1400)
	if !reflect.DeepEqual(hit.NextHops, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("configured ECMP order changed: %v", hit.NextHops)
	}
}

func TestSuppressedLearnedRouteMTUMatchesLargeReorderedECMP12190(t *testing.T) {
	addresses := []string{
		"192.0.2.1", "192.0.2.2", "192.0.2.3",
		"192.0.2.4", "192.0.2.5", "192.0.2.6",
		"192.0.2.7", "192.0.2.8", "192.0.2.9",
	}
	static := &config.StaticRoute{Destination: "0.0.0.0/0", Preference: 5}
	learnedHops := make([]string, 0, len(addresses))
	for i, address := range addresses {
		static.NextHops = append(static.NextHops, config.NextHopEntry{Address: address})
		learnedHops = append(learnedHops, addresses[len(addresses)-1-i])
	}
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{static}
	learned := suppressedMTULearnedV4("0.0.0.0/0", 1400, learnedHops...)
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet.0", "inet", "0.0.0.0/0", 1400)
}

func TestSuppressedLearnedRouteMTUDoesNotCrossDifferentQualifiedInterface12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{{
		Destination: "2001:db8:1::/64", Preference: 5,
		NextHops: []config.NextHopEntry{{
			Address: "fe80::1", Interface: "ge-0/0/0.0",
		}},
	}}
	learned := suppressedMTULearnedV6("2001:db8:1::/64", 1400, "fe80::1@ge-0-0-1")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet6.0", "inet6", "2001:db8:1::/64", 0)
}

func TestSuppressedLearnedRouteMTUDoesNotConflateECMPMembers12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0", Preference: 5,
		NextHops: []config.NextHopEntry{
			{Address: "192.0.2.1"},
			{Address: "192.0.2.2"},
		},
	}}
	learned := suppressedMTULearnedV4(
		"0.0.0.0/0", 1400, "192.0.2.1", "192.0.2.3",
	)
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet.0", "inet", "0.0.0.0/0", 0)
}

func TestSuppressedLearnedRouteMTUMatchesNonCanonicalV6Gateway12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{{
		Destination: "::/0", Preference: 5,
		NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}},
	}}
	learned := suppressedMTULearnedV6("::/0", 1400, "2001:0db8::1")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet6.0", "inet6", "::/0", 1400)
}

// Route MTU is not per-member: a weighted learned ECMP route still constrains
// an otherwise identical configured ECMP group.
func TestSuppressedLearnedRouteMTUIsIndependentOfECMPWeights12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0", Preference: 5,
		NextHops: []config.NextHopEntry{
			{Address: "192.0.2.1"},
			{Address: "192.0.2.2"},
		},
	}}
	learned := suppressedMTULearnedV4(
		"0.0.0.0/0", 1400, "192.0.2.1", "192.0.2.2",
	)
	learned.NextHopWeights = []uint32{1, 4}
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet.0", "inet", "0.0.0.0/0", 1400)
}

func TestSuppressedLearnedRouteMTUIsScopedToItsTable12190(t *testing.T) {
	const destination = "10.20.30.0/24"
	route := func() *config.StaticRoute {
		return &config.StaticRoute{
			Destination: destination, Preference: 5,
			NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}},
		}
	}
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{route()}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", TableID: 100, StaticRoutes: []*config.StaticRoute{route()},
	}}
	learned := suppressedMTULearnedV4(destination, 1400, "192.0.2.1")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet.0", "inet", destination, 1400)
	requireSuppressedMTU(t, out, "blue.inet.0", "inet", destination, 0)
}

func TestSuppressedLearnedRouteMTUIsScopedToItsPrefix12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{
			Destination: "10.20.30.0/24", Preference: 5,
			NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}},
		},
		{
			Destination: "10.20.31.0/24", Preference: 5,
			NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}},
		},
	}
	learned := suppressedMTULearnedV4("10.20.30.0/24", 1400, "192.0.2.1")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	requireSuppressedMTU(t, out, "inet.0", "inet", "10.20.30.0/24", 1400)
	requireSuppressedMTU(t, out, "inet.0", "inet", "10.20.31.0/24", 0)
}

func TestSuppressedLearnedRouteMTUIsScopedToItsFamily12190(t *testing.T) {
	existing := []RouteSnapshot{
		{
			Table: "inet.0", Family: "inet", Destination: "10.20.30.0/24",
			NextHops: []string{"192.0.2.1"}, Preference: 5,
		},
		{
			Table: "inet.0", Family: "inet6", Destination: "10.20.30.0/24",
			NextHops: []string{"192.0.2.1"}, Preference: 5,
		},
	}
	withLearnedRoutes(t, fixedLearned(suppressedMTULearnedV4("10.20.30.0/24", 1400, "192.0.2.1")))

	_, carried, err := addLearnedRouteSnapshots(&config.Config{}, existing, func(RouteSnapshot) {})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if carried[0] != 1400 {
		t.Fatalf("matching inet route MTU = %d, want 1400: %v", carried[0], carried)
	}
	if _, ok := carried[1]; ok {
		t.Fatalf("MTU crossed into a different family: %v", carried)
	}
}

func TestSuppressedLearnedRouteMTUStaysOnBestPreferenceTier12190(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0", Preference: 5,
		NextHops: []config.NextHopEntry{
			{Address: "192.0.2.1", Preference: 5, HasPreference: true},
			{Address: "192.0.2.1", Preference: 10, HasPreference: true},
		},
	}}
	learned := suppressedMTULearnedV4("0.0.0.0/0", 1400, "192.0.2.1")
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", out)
	if len(hits) != 2 {
		t.Fatalf("want primary and backup preference tiers, got %+v", hits)
	}
	var primary, backup *RouteSnapshot
	for i := range hits {
		switch hits[i].Preference {
		case 5:
			primary = &hits[i]
		case 10:
			backup = &hits[i]
		}
	}
	if primary == nil || primary.MTU != 1400 {
		t.Fatalf("best tier did not inherit MTU 1400: %+v", hits)
	}
	if backup == nil || backup.MTU != 0 {
		t.Fatalf("non-best tier inherited the selected route MTU: %+v", hits)
	}
}

func TestSuppressedBlackholeMTUDoesNotConstrainConnectedRoute12190(t *testing.T) {
	iface := InterfaceSnapshot{
		Name: "eth0", Ifindex: 1,
		Addresses: []InterfaceAddressSnapshot{{
			Family: "inet", Address: "198.51.100.1/24",
		}},
	}
	learned := routing.LearnedRoute{
		TableID: 254, Family: netlink.FAMILY_V4,
		Destination: "198.51.100.0/24", Discard: true,
		Protocol: "static", MTU: 1300,
	}
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(&config.Config{}, []InterfaceSnapshot{iface}, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "198.51.100.0/24", out)
	var connected *RouteSnapshot
	for i := range hits {
		if hits[i].Preference != 0 || hits[i].Discard || hits[i].Reject {
			continue
		}
		if connected != nil {
			t.Fatalf("multiple connected snapshots for the prefix: %+v", hits)
		}
		connected = &hits[i]
	}
	if connected == nil {
		t.Fatalf("no connected snapshot for the prefix: %+v", hits)
	}
	if connected.MTU != 0 {
		t.Fatalf("suppressed blackhole MTU constrained the connected route: %+v", *connected)
	}
}

func TestSuppressedLearnedMTUDoesNotStampDiscardSnapshot12190(t *testing.T) {
	const destination = "198.51.100.0/24"
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: destination, Preference: 5, Discard: true,
	}}
	learned := suppressedMTULearnedV4(destination, 1400)
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hit := requireSuppressedMTU(t, out, "inet.0", "inet", destination, 0)
	if !hit.Discard {
		t.Fatalf("expected the configured discard route, got %+v", hit)
	}
}

func TestSuppressedLearnedMTUDoesNotStampNextTableSnapshot12190(t *testing.T) {
	const destination = "10.20.30.0/24"
	existing := []RouteSnapshot{
		{
			Table: "inet.0", Family: "inet", Destination: destination,
			Preference: 5,
		},
		{
			Table: "inet.0", Family: "inet", Destination: destination,
			Preference: 5, NextTable: "blue.inet.0",
		},
	}
	withLearnedRoutes(t, fixedLearned(suppressedMTULearnedV4(destination, 1400)))

	_, carried, err := addLearnedRouteSnapshots(&config.Config{}, existing, func(RouteSnapshot) {})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if carried[0] != 1400 {
		t.Fatalf("ordinary route MTU = %d, want 1400: %v", carried[0], carried)
	}
	if _, ok := carried[1]; ok {
		t.Fatalf("MTU was carried to a next-table rule: %v", carried)
	}
}

func TestSuppressedLearnedZeroMTUIsNotCarried12190(t *testing.T) {
	const destination = "10.20.30.0/24"
	existing := []RouteSnapshot{{
		Table: "inet.0", Family: "inet", Destination: destination,
		NextHops: []string{"192.0.2.1"}, Preference: 5, MTU: 1500,
	}}
	withLearnedRoutes(t, fixedLearned(suppressedMTULearnedV4(destination, 0, "192.0.2.1")))

	_, carried, err := addLearnedRouteSnapshots(&config.Config{}, existing, func(RouteSnapshot) {})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, ok := carried[0]; ok {
		t.Fatalf("unknown/zero MTU was carried as a constraint: %v", carried)
	}
}

// The minimum survives regardless of which order the learned rows sort in:
// larger-first pins the merge against first-wins, smaller-first against
// last-wins.
func TestSuppressedLearnedRouteMTUMergeKeepsMinimum12190(t *testing.T) {
	for _, tc := range []struct {
		name          string
		firstMTU, sec int
	}{
		{"larger_sorts_first", 1400, 1300},
		{"smaller_sorts_first", 1300, 1400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
				Destination: "0.0.0.0/0", Preference: 5,
				NextHops: []config.NextHopEntry{
					{Address: "192.0.2.1"},
					{Address: "192.0.2.2"},
				},
			}}
			first := suppressedMTULearnedV4(
				"0.0.0.0/0", tc.firstMTU, "192.0.2.1", "192.0.2.2",
			)
			second := suppressedMTULearnedV4(
				"0.0.0.0/0", tc.sec, "192.0.2.2", "192.0.2.1",
			)
			withLearnedRoutes(t, fixedLearned(second, first))

			out, _, err := buildRouteSnapshots(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			requireSuppressedMTU(t, out, "inet.0", "inet", "0.0.0.0/0", 1300)
		})
	}
}

func TestSuppressedLearnedRouteMTUResolvesDeclaredConfigInterfaces12190(t *testing.T) {
	unit := func(number, vlanID int) *config.InterfaceUnit {
		return &config.InterfaceUnit{Number: number, VlanID: vlanID}
	}
	iface := func(name, redundantParent string, u *config.InterfaceUnit) *config.InterfaceConfig {
		ifc := &config.InterfaceConfig{Name: name, RedundantParent: redundantParent}
		if u != nil {
			ifc.Units = map[int]*config.InterfaceUnit{u.Number: u}
		}
		return ifc
	}
	tests := []struct {
		name         string
		configIface  string
		learnedIface string
		interfaces   map[string]*config.InterfaceConfig
		wantMTU      int
	}{
		{
			name:        "reth_unit0_to_member",
			configIface: "reth0.0", learnedIface: "ge-0-0-0",
			interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": iface("ge-0/0/0", "reth0", nil),
				"reth0":    iface("reth0", "", unit(0, 0)),
			},
			wantMTU: 1400,
		},
		{
			name:        "vlan_id_differs_from_unit",
			configIface: "ge-0/0/1.10", learnedIface: "ge-0-0-1.100",
			interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/1": iface("ge-0/0/1", "", unit(10, 100)),
			},
			wantMTU: 1400,
		},
		{
			name:        "tagged_unit0_same_link",
			configIface: "ge-0/0/2.0", learnedIface: "ge-0-0-2.100",
			interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/2": iface("ge-0/0/2", "", unit(0, 100)),
			},
			wantMTU: 1400,
		},
		{
			name:        "tagged_unit0_not_parent",
			configIface: "ge-0/0/2.0", learnedIface: "ge-0-0-2",
			interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/2": iface("ge-0/0/2", "", unit(0, 100)),
			},
			wantMTU: 0,
		},
		{
			name:        "reth_vlan_unit50",
			configIface: "reth1.50", learnedIface: "ge-0-0-3.50",
			interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": iface("ge-0/0/3", "reth1", nil),
				"reth1":    iface("reth1", "", unit(50, 50)),
			},
			wantMTU: 1400,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = tc.interfaces
			cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{{
				Destination: "::/0", Preference: 5,
				NextHops: []config.NextHopEntry{{
					Address: "fe80::1", Interface: tc.configIface,
				}},
			}}
			learned := suppressedMTULearnedV6(
				"::/0", 1400, "fe80::1@"+tc.learnedIface,
			)
			withLearnedRoutes(t, fixedLearned(learned))

			out, _, err := buildRouteSnapshots(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			requireSuppressedMTU(t, out, "inet6.0", "inet6", "::/0", tc.wantMTU)
		})
	}
}
