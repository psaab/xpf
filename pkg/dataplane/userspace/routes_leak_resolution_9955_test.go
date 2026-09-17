package userspace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

const (
	leakProbeV4_9955 = "10.1.2.5"
	leakProbeV6_9955 = "2001:db8:1::5"
)

func mustCIDR9955(t *testing.T, text string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(text)
	if err != nil || network == nil {
		t.Fatalf("ParseCIDR(%q): %v", text, err)
	}
	return network
}

func baseLeakConfig9955() *config.Config {
	return &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "red", TableID: 501},
			{Name: "blue", TableID: 502},
		},
	}
}

func defaultIngressConfig9955(units int) *config.Config {
	cfg := baseLeakConfig9955()
	cfg.Interfaces.Interfaces = make(map[string]*config.InterfaceConfig, units)
	for i := range units {
		name := fmt.Sprintf("ge-0/0/%d", i)
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{
			Name:  name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		}
	}
	return cfg
}

func targetRoute9955(destination, nextHop string) *config.StaticRoute {
	return &config.StaticRoute{
		Destination: destination,
		NextHops:    []config.NextHopEntry{{Address: nextHop}},
	}
}

func targetRouteForFamily9955(instance *config.RoutingInstanceConfig, family, destination, nextHop string) {
	route := targetRoute9955(destination, nextHop)
	if family == "inet6" {
		instance.Inet6StaticRoutes = append(instance.Inet6StaticRoutes, route)
		return
	}
	instance.StaticRoutes = append(instance.StaticRoutes, route)
}

func findRouteSnapshot9955(routes []RouteSnapshot, destination string, nextTable string) (RouteSnapshot, bool) {
	for _, route := range routes {
		if route.Destination == destination && (nextTable == "" || route.NextTable == nextTable) {
			return route, true
		}
	}
	return RouteSnapshot{}, false
}

// TestBuildRouteSnapshotsCarriesRulePriority9955 verifies that every live
// per-prefix ip-rule mirror carries the kernel's exact priority and that rows
// differing only in priority survive deduplication. A priority of zero here
// would be the old producer's information loss, not a valid live rule.
func TestBuildRouteSnapshotsCarriesRulePriority9955(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	v4 := mustCIDR9955(t, "10.1.2.0/24")
	v6 := mustCIDR9955(t, "2001:db8:1::/48")
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		switch family {
		case syscall.AF_INET:
			return []netlink.Rule{
				{Dst: v4, Table: 501, Priority: 201},
				{Dst: v4, Table: 501, Priority: 200},
			}, nil
		case syscall.AF_INET6:
			return []netlink.Rule{{Dst: v6, Table: 502, Priority: 30_500}}, nil
		default:
			return nil, nil
		}
	}

	routes, _, err := buildRouteSnapshots(baseLeakConfig9955(), nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var v4Priorities []uint32
	for _, route := range routes {
		if route.Destination != "10.1.2.0/24" || route.NextTable == "" {
			continue
		}
		if route.RulePriority == 0 {
			t.Fatalf("live leak lost its rule priority: %+v", route)
		}
		v4Priorities = append(v4Priorities, route.RulePriority)
	}
	if !reflect.DeepEqual(v4Priorities, []uint32{200, 201}) {
		t.Fatalf("same-prefix live leaks = %v, want both kernel priorities [200 201]", v4Priorities)
	}
	v6Leak, ok := findRouteSnapshot9955(routes, "2001:db8:1::/48", "blue.inet6.0")
	if !ok || v6Leak.RulePriority != 30_500 {
		t.Fatalf("IPv6 live leak = %+v, want rule priority 30500", v6Leak)
	}
}
func TestRouteSnapshotRulePriorityWireKey9955(t *testing.T) {
	leak := RouteSnapshot{
		Table:        "inet.0",
		Family:       "inet",
		Destination:  "10.1.2.0/24",
		NextTable:    "red.inet.0",
		RulePriority: 150,
	}
	raw, err := json.Marshal(leak)
	if err != nil {
		t.Fatalf("marshal leak snapshot: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode leak snapshot object: %v", err)
	}
	var got uint32
	if err := json.Unmarshal(fields["rule_priority"], &got); err != nil {
		t.Fatalf("decode rule_priority: %v", err)
	}
	if got != leak.RulePriority {
		t.Fatalf("rule_priority = %d, want %d", got, leak.RulePriority)
	}
	var back RouteSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal leak snapshot: %v", err)
	}
	if back.RulePriority != leak.RulePriority {
		t.Fatalf("round-trip RulePriority = %d, want %d", back.RulePriority, leak.RulePriority)
	}

	ordinaryRaw, err := json.Marshal(RouteSnapshot{
		Table:       "inet.0",
		Family:      "inet",
		Destination: "10.1.2.0/24",
	})
	if err != nil {
		t.Fatalf("marshal ordinary snapshot: %v", err)
	}
	fields = nil
	if err := json.Unmarshal(ordinaryRaw, &fields); err != nil {
		t.Fatalf("decode ordinary snapshot object: %v", err)
	}
	if _, ok := fields["rule_priority"]; ok {
		t.Fatalf("ordinary zero RulePriority was not omitted: %s", ordinaryRaw)
	}
}

// TestLiveRuleReplacesConfigLeakMirror9955 verifies live-wins precedence when
// the two producers intentionally disagree. The config mirror's computed
// priority (100) must not survive beside a live rule at 150, because Rust
// canonicalizes the bare and qualified targets to one leak identity. Distinct
// live priorities remain separate stage-1 candidates.
func TestLiveRuleReplacesConfigLeakMirror9955(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	dst := mustCIDR9955(t, "10.1.2.0/24")
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family == syscall.AF_INET {
			return []netlink.Rule{
				{Dst: dst, Table: 501, Priority: 151},
				{Dst: dst, Table: 501, Priority: 150},
			}, nil
		}
		return nil, nil
	}
	cfg := defaultIngressConfig9955(1)
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "10.1.2.0/24",
		NextTable:   "red",
	}}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var priorities []uint32
	for _, route := range routes {
		if route.Destination == "10.1.2.0/24" && route.NextTable != "" {
			priorities = append(priorities, route.RulePriority)
			if route.NextTable != "red.inet.0" {
				t.Fatalf("live row retained noncanonical target %q", route.NextTable)
			}
		}
	}
	if !reflect.DeepEqual(priorities, []uint32{150, 151}) {
		t.Fatalf("live leak priorities = %v, want [150 151] with config mirror suppressed", priorities)
	}
}

// TestBuildRouteSnapshotsConfigRulePriorityMatchesKernelWindow9955 pins the
// config-global mirror to nextTableManager.Apply: one shared priority cursor,
// parsed-CIDR IPv4-first order, and a slot stride equal to the number of
// default-instance ingress interfaces. A v6 CIDR deliberately appears in the
// v4 config list so list position cannot accidentally define the priority.
func TestBuildRouteSnapshotsConfigRulePriorityMatchesKernelWindow9955(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	cfg := defaultIngressConfig9955(2)
	v6First := &config.StaticRoute{Destination: "2001:db8:10::/48", NextTable: "blue"}
	v4 := &config.StaticRoute{Destination: "10.1.2.0/24", NextTable: "red"}
	v6Second := &config.StaticRoute{Destination: "2001:db8:11::/48", NextTable: "red"}
	ordinary := &config.StaticRoute{
		Destination: "10.1.0.0/16",
		NextHops:    []config.NextHopEntry{{Address: "172.16.52.1"}},
	}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{v6First, v4, ordinary}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{v6Second}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	want := map[string]uint32{
		"10.1.2.0/24":      100,
		"2001:db8:10::/48": 102,
		"2001:db8:11::/48": 104,
	}
	for destination, priority := range want {
		route, ok := findRouteSnapshot9955(routes, destination, "")
		if !ok || route.NextTable == "" || route.RulePriority != priority {
			t.Fatalf("config leak %s = %+v, want nonempty NextTable and priority %d", destination, route, priority)
		}
	}
	ordinaryRoute, ok := findRouteSnapshot9955(routes, "10.1.0.0/16", "")
	if !ok || ordinaryRoute.NextTable != "" || ordinaryRoute.RulePriority != 0 {
		t.Fatalf("ordinary route = %+v, want no leak target and priority 0", ordinaryRoute)
	}
}

// TestBuildRouteSnapshotsConfigRulePriorityPreservesStrideAndCap9955 extends
// the existing count-only window coverage with the actual wire priorities.
func TestBuildRouteSnapshotsConfigRulePriorityPreservesStrideAndCap9955(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	const ingress = 4
	cfg := defaultIngressConfig9955(ingress)
	for i := range config.NextTableRuleWindow/ingress + 1 {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes, &config.StaticRoute{
			Destination: fmt.Sprintf("10.10.%d.0/24", i),
			NextTable:   "red",
		})
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	published := make(map[string]uint32)
	for _, route := range routes {
		if route.NextTable == "red" {
			published[route.Destination] = route.RulePriority
		}
	}
	wantCount := config.NextTableRuleWindow / ingress
	if len(published) != wantCount {
		t.Fatalf("published %d config leaks, want cap %d", len(published), wantCount)
	}
	for i := range wantCount {
		destination := fmt.Sprintf("10.10.%d.0/24", i)
		if got := published[destination]; got != uint32(config.NextTableRulePriorityBase+i*ingress) {
			t.Fatalf("priority for route %d = %d, want %d", i, got,
				config.NextTableRulePriorityBase+i*ingress)
		}
	}
	last := fmt.Sprintf("10.10.%d.0/24", wantCount)
	if _, exists := published[last]; exists {
		t.Fatalf("route past the %d-slot cap was published: %s", config.NextTableRuleWindow, last)
	}
}

// TestRouteOverlayKeepsLeakAndReplacesOrdinary9955 verifies that an
// ip-monitoring ordinary-route replacement cannot erase a stage-1 leak for the
// same table/family/prefix. The ordinary overlay row itself still replaces the
// ordinary route entry as before.
func TestRouteOverlayKeepsLeakAndReplacesOrdinary9955(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	cfg := defaultIngressConfig9955(1)
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.1.2.0/24", NextTable: "red"},
		{Destination: "10.1.2.0/24", NextHops: []config.NextHopEntry{{Address: "172.16.51.1"}}},
	}
	overlay := []config.RouteOverlayEntry{{Destination: "10.1.2.0/24", NextHop: "172.16.52.1"}}
	routes, _, err := buildRouteSnapshots(cfg, nil, overlay)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var leak, ordinary *RouteSnapshot
	for i := range routes {
		route := &routes[i]
		if route.Destination != "10.1.2.0/24" {
			continue
		}
		if route.NextTable != "" {
			leak = route
		} else {
			ordinary = route
		}
	}
	if leak == nil || leak.NextTable != "red" || leak.RulePriority != 100 {
		t.Fatalf("leak after overlay = %+v, want preserved priority-100 leak", leak)
	}
	if ordinary == nil || !reflect.DeepEqual(ordinary.NextHops, []string{"172.16.52.1"}) {
		t.Fatalf("ordinary overlay route = %+v, want the overlay next-hop", ordinary)
	}
}

// TestLearnedRouteGapIgnoresLeak9955 verifies that an existing NextTable rule
// does not count as ordinary table coverage. A learned main-table row for the
// same prefix must survive so a target-table miss can fall through to it.
func TestLearnedRouteGapIgnoresLeak9955(t *testing.T) {
	origRules := ruleListFn
	origImport := learnedRouteImportFn
	t.Cleanup(func() {
		ruleListFn = origRules
		learnedRouteImportFn = origImport
	})
	leakDestination := mustCIDR9955(t, "10.1.2.0/24")
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family == syscall.AF_INET {
			return []netlink.Rule{{Dst: leakDestination, Table: 501, Priority: 150}}, nil
		}
		return nil, nil
	}
	learnedRouteImportFn = func(_ []int) ([]routing.LearnedRoute, error) {
		return []routing.LearnedRoute{{
			TableID:     learnedRouteMainTableID,
			Family:      netlink.FAMILY_V4,
			Destination: "10.1.2.0/24",
			NextHops:    []string{"172.16.52.1@ge-0/0/14.50"},
			Protocol:    "bgp",
		}}, nil
	}

	routes, _, err := buildRouteSnapshots(baseLeakConfig9955(), nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var sawLeak, sawOrdinary bool
	for _, route := range routes {
		if route.Destination != "10.1.2.0/24" {
			continue
		}
		if route.NextTable != "" {
			sawLeak = true
		} else if route.Table == "inet.0" {
			sawOrdinary = true
		}
	}
	if !sawLeak || !sawOrdinary {
		t.Fatalf("same-prefix leak/fallback rows = %+v, want both rows", routes)
	}
}

type leakCorpusRow9955 struct {
	Name        string          `json:"name"`
	Routes      []RouteSnapshot `json:"routes"`
	Destination string          `json:"destination"`
	WantIfindex int             `json:"want_ifindex"`
}

type leakCorpusShape9955 struct {
	name        string
	destination string
	cfg         *config.Config
	rulesV4     []netlink.Rule
	rulesV6     []netlink.Rule
}

func prefixContaining9955(family string, prefixLen int) string {
	text := leakProbeV4_9955
	bits := 32
	if family == "inet6" {
		text = leakProbeV6_9955
		bits = 128
	}
	ip := net.ParseIP(text)
	if bits == 32 {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}
	return fmt.Sprintf("%s/%d", ip.Mask(net.CIDRMask(prefixLen, bits)), prefixLen)
}

func liveOverlapShape9955(t *testing.T, family string, shortLen, longLen int, shortPriority, longPriority uint32, label string) leakCorpusShape9955 {
	t.Helper()
	cfg := baseLeakConfig9955()
	if family == "inet6" {
		targetRouteForFamily9955(cfg.RoutingInstances[0], family, "2001:db8::/32", "2001:db8:50::1@ge-0/0/12.50")
		targetRouteForFamily9955(cfg.RoutingInstances[1], family, "2001:db8::/32", "2001:db8:51::1@ge-0/0/13.50")
	} else {
		targetRouteForFamily9955(cfg.RoutingInstances[0], family, "10.0.0.0/8", "172.16.50.1@ge-0/0/12.50")
		targetRouteForFamily9955(cfg.RoutingInstances[1], family, "10.0.0.0/8", "172.16.51.1@ge-0/0/13.50")
	}
	shortDestination := prefixContaining9955(family, shortLen)
	longDestination := prefixContaining9955(family, longLen)
	shortTable, longTable := 501, 502
	if family == "inet6" {
		return leakCorpusShape9955{
			name:        label,
			destination: leakProbeV6_9955,
			cfg:         cfg,
			rulesV6: []netlink.Rule{
				{Dst: mustCIDR9955(t, shortDestination), Table: shortTable, Priority: int(shortPriority)},
				{Dst: mustCIDR9955(t, longDestination), Table: longTable, Priority: int(longPriority)},
			},
		}
	}
	return leakCorpusShape9955{
		name:        label,
		destination: leakProbeV4_9955,
		cfg:         cfg,
		rulesV4: []netlink.Rule{
			{Dst: mustCIDR9955(t, shortDestination), Table: shortTable, Priority: int(shortPriority)},
			{Dst: mustCIDR9955(t, longDestination), Table: longTable, Priority: int(longPriority)},
		},
	}
}

func canonicalLeakTable9955(table, family string) string {
	suffix := ".inet.0"
	if family == "inet6" {
		suffix = ".inet6.0"
	}
	if table == "inet.0" || table == "inet6.0" {
		return suffix
	}
	if strings.HasSuffix(table, ".inet.0") || strings.HasSuffix(table, ".inet6.0") {
		return table[:strings.LastIndex(table, ".inet")] + suffix
	}
	return table + suffix
}

var oracleIfindexes9955 = map[string]int{
	"ge-0/0/12.50": 12,
	"ge-0/0/13.50": 13,
	"ge-0/0/14.50": 14,
}

// kernelStageOracle9955 is an expectation-only kernel model for corpus rows.
// It is intentionally separate from buildRouteSnapshots and from the Rust
// resolver under test: stage 1 scans matching NextTable rules by ascending
// RulePriority and retries after a target-table miss; stage 2 performs ordinary
// longest-prefix-match in main. This oracle supplies expected egress only.
func kernelStageOracle9955(routes []RouteSnapshot, destination string) int {
	ip := net.ParseIP(destination)
	if ip == nil {
		return 0
	}
	family := "inet"
	if strings.Contains(destination, ":") {
		family = "inet6"
	}
	leaks := make([]RouteSnapshot, 0)
	for _, route := range routes {
		if route.NextTable == "" || route.Family != family {
			continue
		}
		_, network, err := net.ParseCIDR(route.Destination)
		if err == nil && network != nil && network.Contains(ip) {
			leaks = append(leaks, route)
		}
	}
	sort.SliceStable(leaks, func(i, j int) bool {
		if leaks[i].RulePriority != leaks[j].RulePriority {
			return leaks[i].RulePriority < leaks[j].RulePriority
		}
		return leaks[i].NextTable < leaks[j].NextTable
	})
	for _, leak := range leaks {
		table := canonicalLeakTable9955(leak.NextTable, family)
		if ifindex, hit := kernelTableChoice9955(routes, table, family, ip); hit {
			return ifindex
		}
	}
	if ifindex, hit := kernelTableChoice9955(routes, map[string]string{"inet": "inet.0", "inet6": "inet6.0"}[family], family, ip); hit {
		return ifindex
	}
	return 0
}

func kernelTableChoice9955(routes []RouteSnapshot, table, family string, ip net.IP) (int, bool) {
	best := -1
	bestPrefix := -1
	bestPreference := 0
	for i, route := range routes {
		if route.NextTable != "" || route.Table != table || route.Family != family {
			continue
		}
		_, network, err := net.ParseCIDR(route.Destination)
		if err != nil || network == nil || !network.Contains(ip) {
			continue
		}
		prefix, _ := network.Mask.Size()
		if best < 0 || prefix > bestPrefix || (prefix == bestPrefix && route.Preference < bestPreference) {
			best = i
			bestPrefix = prefix
			bestPreference = route.Preference
		}
	}
	if best < 0 {
		return 0, false
	}
	if routes[best].Discard || len(routes[best].NextHops) == 0 {
		return 0, true
	}
	for _, nextHop := range routes[best].NextHops {
		at := strings.LastIndexByte(nextHop, '@')
		if at >= 0 {
			if ifindex, ok := oracleIfindexes9955[nextHop[at+1:]]; ok {
				return ifindex, true
			}
		}
	}
	return 0, true
}

func addTargetRoutesForShape9955(cfg *config.Config, family string, red, blue bool) {
	if family == "inet6" {
		if red {
			targetRouteForFamily9955(cfg.RoutingInstances[0], family, "2001:db8::/32", "2001:db8:50::1@ge-0/0/12.50")
		}
		if blue {
			targetRouteForFamily9955(cfg.RoutingInstances[1], family, "2001:db8::/32", "2001:db8:51::1@ge-0/0/13.50")
		}
		return
	}
	if red {
		targetRouteForFamily9955(cfg.RoutingInstances[0], family, "10.0.0.0/8", "172.16.50.1@ge-0/0/12.50")
	}
	if blue {
		targetRouteForFamily9955(cfg.RoutingInstances[1], family, "10.0.0.0/8", "172.16.51.1@ge-0/0/13.50")
	}
}

func corpusControlShapes9955(t *testing.T) []leakCorpusShape9955 {
	t.Helper()
	shapes := make([]leakCorpusShape9955, 0, 32)
	for _, family := range []string{"inet", "inet6"} {
		pairs := [][2]int{{8, 24}, {8, 16}, {16, 24}, {12, 28}, {8, 32}}
		if family == "inet6" {
			pairs = [][2]int{{32, 64}, {32, 48}, {48, 64}, {40, 80}, {32, 96}}
		}
		for _, pair := range pairs {
			for _, arrangement := range []struct {
				short, long uint32
				label       string
			}{
				{150, 30_500, "next-table-first"},
				{30_500, 150, "rib-group-first"},
			} {
				name := fmt.Sprintf("overlap_%s_%d_%d_%s_9955", family, pair[0], pair[1], arrangement.label)
				shapes = append(shapes, liveOverlapShape9955(t, family, pair[0], pair[1], arrangement.short, arrangement.long, name))
			}
		}

		// Single-leak control: the two-stage ordering question is absent, so
		// this must always resolve through the red target.
		cfg := baseLeakConfig9955()
		addTargetRoutesForShape9955(cfg, family, true, false)
		if family == "inet6" {
			shapes = append(shapes, leakCorpusShape9955{
				name: "single_leak_inet6_9955", destination: leakProbeV6_9955, cfg: cfg,
				rulesV6: []netlink.Rule{{Dst: mustCIDR9955(t, prefixContaining9955(family, 48)), Table: 501, Priority: 150}},
			})
		} else {
			shapes = append(shapes, leakCorpusShape9955{
				name: "single_leak_inet_9955", destination: leakProbeV4_9955, cfg: cfg,
				rulesV4: []netlink.Rule{{Dst: mustCIDR9955(t, prefixContaining9955(family, 24)), Table: 501, Priority: 150}},
			})
		}

		// A leak rule precedes the ordinary route in the kernel even when its
		// prefix is broader, so stage 1 must choose red.
		cfg = baseLeakConfig9955()
		addTargetRoutesForShape9955(cfg, family, true, false)
		if family == "inet6" {
			cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{targetRoute9955("2001:db8:1::/64", "2001:db8:52::1@ge-0/0/14.50")}
			shapes = append(shapes, leakCorpusShape9955{
				name: "leak_versus_ordinary_inet6_9955", destination: leakProbeV6_9955, cfg: cfg,
				rulesV6: []netlink.Rule{{Dst: mustCIDR9955(t, "2001:db8::/32"), Table: 501, Priority: 150}},
			})
		} else {
			cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{targetRoute9955("10.1.2.0/24", "172.16.52.1@ge-0/0/14.50")}
			shapes = append(shapes, leakCorpusShape9955{
				name: "leak_versus_ordinary_inet_9955", destination: leakProbeV4_9955, cfg: cfg,
				rulesV4: []netlink.Rule{{Dst: mustCIDR9955(t, "10.0.0.0/8"), Table: 501, Priority: 150}},
			})
		}

		// An empty target table is a miss, not a terminal answer: the main
		// ordinary fallback must remain available after the leak rule.
		cfg = baseLeakConfig9955()
		if family == "inet6" {
			cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{targetRoute9955("2001:db8::/32", "2001:db8:52::1@ge-0/0/14.50")}
			shapes = append(shapes, leakCorpusShape9955{
				name: "empty_target_fallback_inet6_9955", destination: leakProbeV6_9955, cfg: cfg,
				rulesV6: []netlink.Rule{{Dst: mustCIDR9955(t, "2001:db8:1::/48"), Table: 501, Priority: 150}},
			})
		} else {
			cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{targetRoute9955("10.0.0.0/8", "172.16.52.1@ge-0/0/14.50")}
			shapes = append(shapes, leakCorpusShape9955{
				name: "empty_target_fallback_inet_9955", destination: leakProbeV4_9955, cfg: cfg,
				rulesV4: []netlink.Rule{{Dst: mustCIDR9955(t, "10.1.2.0/24"), Table: 501, Priority: 150}},
			})
		}

		// The first rule misses and the next priority-ordered rule resolves in
		// blue. This is the explicit next-rule fall-through control.
		cfg = baseLeakConfig9955()
		addTargetRoutesForShape9955(cfg, family, false, true)
		if family == "inet6" {
			shapes = append(shapes, leakCorpusShape9955{
				name: "next_rule_fallback_inet6_9955", destination: leakProbeV6_9955, cfg: cfg,
				rulesV6: []netlink.Rule{
					{Dst: mustCIDR9955(t, "2001:db8:1::/48"), Table: 501, Priority: 150},
					{Dst: mustCIDR9955(t, "2001:db8::/32"), Table: 502, Priority: 200},
				},
			})
		} else {
			shapes = append(shapes, leakCorpusShape9955{
				name: "next_rule_fallback_inet_9955", destination: leakProbeV4_9955, cfg: cfg,
				rulesV4: []netlink.Rule{
					{Dst: mustCIDR9955(t, "10.1.2.0/24"), Table: 501, Priority: 150},
					{Dst: mustCIDR9955(t, "10.0.0.0/8"), Table: 502, Priority: 200},
				},
			})
		}

		// Config-global static next-table order is the actual producer path,
		// including its bare target names and nonzero computed priorities.
		cfg = defaultIngressConfig9955(1)
		if family == "inet6" {
			addTargetRoutesForShape9955(cfg, family, true, true)
			cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
				{Destination: "2001:db8:1::/48", NextTable: "blue"},
				{Destination: "2001:db8:1::/48", NextTable: "red"},
			}
			shapes = append(shapes, leakCorpusShape9955{
				name: "config_order_inet6_blue_then_red_9955", destination: leakProbeV6_9955, cfg: cfg,
			})
		} else {
			addTargetRoutesForShape9955(cfg, family, true, true)
			cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
				{Destination: "10.1.2.0/24", NextTable: "red"},
				{Destination: "10.1.2.0/24", NextTable: "blue"},
			}
			shapes = append(shapes, leakCorpusShape9955{
				name: "config_order_inet_red_then_blue_9955", destination: leakProbeV4_9955, cfg: cfg,
			})
		}
	}
	return shapes
}

func buildLeakCorpusRows9955(t *testing.T) []leakCorpusRow9955 {
	t.Helper()
	origRules := ruleListFn
	origImport := learnedRouteImportFn
	t.Cleanup(func() {
		ruleListFn = origRules
		learnedRouteImportFn = origImport
	})
	learnedRouteImportFn = nil

	rows := make([]leakCorpusRow9955, 0)
	for _, shape := range corpusControlShapes9955(t) {
		shape := shape
		ruleListFn = func(family int) ([]netlink.Rule, error) {
			if family == syscall.AF_INET {
				return shape.rulesV4, nil
			}
			if family == syscall.AF_INET6 {
				return shape.rulesV6, nil
			}
			return nil, nil
		}
		routes, _, err := buildRouteSnapshots(shape.cfg, nil, nil)
		if err != nil {
			t.Fatalf("buildRouteSnapshots(%s): %v", shape.name, err)
		}
		rows = append(rows, leakCorpusRow9955{
			Name:        shape.name,
			Routes:      routes,
			Destination: shape.destination,
			WantIfindex: kernelStageOracle9955(routes, shape.destination),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// TestLeakResolution9955Corpus checks the deterministic Go producer output
// against the cross-language fixture consumed by the Rust forwarding tests.
// Generate the committed fixture only with UPDATE_LEAK_CORPUS_9955=1; normal
// runs fail on any producer drift rather than laundering it into a new golden.
func TestLeakResolution9955Corpus(t *testing.T) {
	rows := buildLeakCorpusRows9955(t)
	raw, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatalf("marshal leak corpus: %v", err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("testdata", "leak_resolution_9955.json")
	if os.Getenv("UPDATE_LEAK_CORPUS_9955") == "1" {
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatalf("write leak corpus: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (generate with UPDATE_LEAK_CORPUS_9955=1 go test ./pkg/dataplane/userspace -run TestLeakResolution9955Corpus -count=1)", path, err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("%s drifted from buildRouteSnapshots output; regenerate intentionally with UPDATE_LEAK_CORPUS_9955=1", path)
	}
}
