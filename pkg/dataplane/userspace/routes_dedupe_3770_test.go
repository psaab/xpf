package userspace

import (
	"net"
	"reflect"
	"slices"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestRouteSnapshotDedupeKeepsDiscardAndConnected verifies #3770 H8: a
// discard (blackhole) static route and a connected route to the SAME
// prefix are DISTINCT forwarding decisions and must both survive the
// dedupe. Before the fix the dedupe key omitted Discard, so the two
// collided on Table|Family|Destination|NextHops|NextTable and the
// second-inserted one was silently dropped, hiding a real route.
func TestRouteSnapshotDedupeKeepsDiscardAndConnected(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.0.1.0/24", Discard: true},
	}
	ifaces := []InterfaceSnapshot{
		{
			Name: "ge-0-0-1",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.1.5/24", Scope: int(netlink.SCOPE_UNIVERSE)},
			},
		},
	}

	routes, _, err := buildRouteSnapshots(cfg, ifaces, nil)
	if err != nil {
		t.Fatal(err)
	}

	var haveDiscard, haveConnected bool
	count := 0
	for _, r := range routes {
		if r.Table == "inet.0" && r.Family == "inet" && r.Destination == "10.0.1.0/24" {
			count++
			if r.Discard {
				haveDiscard = true
			} else {
				haveConnected = true
			}
		}
	}
	if count != 2 || !haveDiscard || !haveConnected {
		t.Fatalf("routes for 10.0.1.0/24: count=%d haveDiscard=%v haveConnected=%v, want both a discard and a connected entry (%+v)",
			count, haveDiscard, haveConnected, routes)
	}
}

// TestRouteSnapshotDedupeKeepsDistinctPreference verifies #3770 H8 for
// preference: two routes to the same prefix and next-table differing
// ONLY in preference are distinct and both survive so the Rust FIB can
// apply its preference tie-break.
func TestRouteSnapshotDedupeKeepsDistinctPreference(t *testing.T) {
	// Hermetic: stub the kernel ip-rule dump so a live host rule cannot enter the
	// snapshot (the defined table IDs below would otherwise map a stray dump rule
	// into a NextTable leak). Only the config-static dedupe path is under test.
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	// #9810: one unclaimed unit (N=1) so the leaks publish.
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	// The target instance must be DEFINED and named by its bare instance name:
	// the compiler stores route.NextTable as the bare name (parseNextTableInstance
	// strips the ".inet[6].0" suffix), and the #6467 eligibility gate now skips a
	// next-table route whose target is not a defined instance — mirroring the
	// applier, which likewise skips it (no ip rule).
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.5.0.0/16", NextTable: "blue", Preference: 5},
		{Destination: "10.5.0.0/16", NextTable: "blue", Preference: 0},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "10.5.0.0/16" && r.NextTable == "blue" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("distinct-preference routes for 10.5.0.0/16 = %d, want 2 (%+v)", count, routes)
	}
}

// TestRouteSnapshotSortIsDeterministic verifies #3770 M10 plus #9955:
// emitted order is a deterministic function of route content, not of kernel
// rule-dump order. For leak rows, RulePriority is the stage-1 ordering key.
// This uses identical live rule content in opposite dump orders; unlike
// config-static order, reversing a netlink dump must not change the actual
// priorities assigned by the kernel.
func TestRouteSnapshotSortIsDeterministic(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })

	_, dst, err := net.ParseCIDR("10.5.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	reverseDump := false
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family != syscall.AF_INET {
			return nil, nil
		}
		rules := []netlink.Rule{
			{Dst: dst, Table: 100, Priority: 101},
			{Dst: dst, Table: 101, Priority: 100},
		}
		if reverseDump {
			slices.Reverse(rules)
		}
		return rules, nil
	}
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "aaa", TableID: 100},
			{Name: "bbb", TableID: 101},
		},
	}

	got1, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reverseDump = true
	got2, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got1, got2) {
		t.Fatalf("route order depends on ip-rule dump order:\n first=%+v\n reverse=%+v", got1, got2)
	}

	var priorities []uint32
	var targets []string
	for _, r := range got1 {
		if r.Table == "inet.0" && r.Destination == "10.5.0.0/16" && r.NextTable != "" {
			priorities = append(priorities, r.RulePriority)
			targets = append(targets, r.NextTable)
		}
	}
	if !reflect.DeepEqual(priorities, []uint32{100, 101}) ||
		!reflect.DeepEqual(targets, []string{"bbb.inet.0", "aaa.inet.0"}) {
		t.Fatalf("priority order = %v targets=%v, want priorities [100 101] and targets [bbb.inet.0 aaa.inet.0]",
			priorities, targets)
	}
}

// TestRouteOverlayCarriesStaticPreference verifies #3770 M7: the
// ip-monitoring overlay route is injected at the documented Static/1
// preference (route preference 1), matching the FRR managed-section
// distance-1 static, not the default 0.
func TestRouteOverlayCarriesStaticPreference(t *testing.T) {
	cfg := &config.Config{}
	overlay := []config.RouteOverlayEntry{
		{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, overlay)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" {
			found = true
			if r.Preference != 1 {
				t.Fatalf("overlay route preference = %d, want 1 (Static/1)", r.Preference)
			}
		}
	}
	if !found {
		t.Fatalf("overlay default route not found in %+v", routes)
	}
}
