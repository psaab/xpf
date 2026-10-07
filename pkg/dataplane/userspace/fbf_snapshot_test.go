package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1827 PR-2 — FBF (filter-based forwarding) compiled-snapshot shape.
//
// The dataplane side of FBF: buildRouteSnapshots files every routing
// instance's statics under `<ri>.inet.0` regardless of instance-type.
// #11312 excludes forwarding-instance members from connected-route and
// routing-domain maps, matching the daemon's no-VRF binding behavior for
// interfaces. The Rust PBR path looks up `<ri>.inet.0` for `then
// routing-instance` filter hits. PR-2 fixed the KERNEL side (FRR `table <id>`)
// to agree with the static-route path. These tests pin the dataplane half of
// that contract so a future routes.go refactor cannot silently re-open the
// divergence.

func fbfTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:         "ISP-B",
			InstanceType: "forwarding",
			TableID:      100,
			StaticRoutes: []*config.StaticRoute{
				{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.80.1"}}},
			},
			Inet6StaticRoutes: []*config.StaticRoute{
				{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8:80::1"}}},
			},
		},
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"fbf-steer": {
			Name: "fbf-steer",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:            "to-isp-b",
					SourceAddresses: []string{"10.0.61.0/24"},
					Count:           "fbf-isp-b",
					RoutingInstance: "ISP-B",
				},
				{Name: "default", Action: "accept"},
			},
		},
	}
	return cfg
}

func fbfTestInterfaces() []InterfaceSnapshot {
	return []InterfaceSnapshot{
		{
			Name:    "reth0.50",
			Ifindex: 50,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "172.16.50.8/24"},
			},
		},
		{
			Name:    "reth0.80",
			Ifindex: 80,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "172.16.80.8/24"},
				{Family: "inet6", Address: "2001:db8:80::8/64"},
			},
		},
	}
}

// TestFBFSnapshotCarriesForwardingTableAuthorization11420 pins the producer
// side of the narrow cross-table interface exception consumed by Rust.
func TestFBFSnapshotCarriesForwardingTableAuthorization11420(t *testing.T) {
	snap, err := buildSnapshot(fbfTestConfig(), config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if got := strings.Join(snap.ForwardingTables, ","); got != "ISP-B.inet.0,ISP-B.inet6.0" {
		t.Fatalf("forwarding tables = %q, want sorted family-qualified FBF tables", got)
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if got := string(fields["forwarding_tables"]); got != `["ISP-B.inet.0","ISP-B.inet6.0"]` {
		t.Fatalf("forwarding_tables wire value = %s, want canonical FI tables", got)
	}
}

func TestForwardingTablesWireKeyMatchesRust11420(t *testing.T) {
	goKey := jsonKeyOf(t, reflect.TypeOf(ConfigSnapshot{}), "ForwardingTables")
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "snapshot.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	rustKey := rustSerdeRenameOf(t, rustStructBody(t, string(src), "ConfigSnapshot"), "forwarding_tables")
	if goKey != rustKey {
		t.Fatalf("forwarding-tables wire key skew: Go emits %q, Rust reads %q", goKey, rustKey)
	}
}

// TestFBFForwardingInstanceRouteSnapshots: forwarding-instance statics
// land in `<ri>.inet.0` / `<ri>.inet6.0` — the table the Rust PBR
// lookup targets — and never in the master tables.
func TestFBFForwardingInstanceRouteSnapshots(t *testing.T) {
	routes, _, err := buildRouteSnapshots(fbfTestConfig(), fbfTestInterfaces(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var v4, v6 *RouteSnapshot
	for i := range routes {
		r := &routes[i]
		if r.Table == "ISP-B.inet.0" && r.Destination == "0.0.0.0/0" {
			v4 = r
		}
		if r.Table == "ISP-B.inet6.0" && r.Destination == "::/0" {
			v6 = r
		}
		if (r.Table == "inet.0" || r.Table == "inet6.0") &&
			len(r.NextHops) == 1 &&
			(strings.HasPrefix(r.NextHops[0], "172.16.80.1") ||
				strings.HasPrefix(r.NextHops[0], "2001:db8:80::1")) {
			t.Fatalf("forwarding-instance static leaked into master table: %+v", r)
		}
	}
	if v4 == nil || len(v4.NextHops) != 1 || v4.NextHops[0] != "172.16.80.1@reth0.80" {
		t.Fatalf("ISP-B.inet.0 default = %+v, want 172.16.80.1@reth0.80", v4)
	}
	if v6 == nil || len(v6.NextHops) != 1 || v6.NextHops[0] != "2001:db8:80::1@reth0.80" {
		t.Fatalf("ISP-B.inet6.0 default = %+v, want 2001:db8:80::1@reth0.80", v6)
	}
}

// TestFBFInterfaceOnlyNextHopSnapshot12036 exercises both user-authored
// interface-only spellings through the config parser and route snapshot
// producer. The Rust forwarding-build regression consumes the same @st0.0
// member format for either spelling.
func TestFBFInterfaceOnlyNextHopSnapshot12036(t *testing.T) {
	src := `routing-instances {
		VPN {
			instance-type forwarding;
			routing-options {
				static {
					route 0.0.0.0/0 {
						next-hop {
							interface st0.0;
						}
					}
					route 198.51.100.0/24 {
						next-hop st0.0;
					}
				}
			}
		}
	}`
	tree, parseErrors := config.NewParser(src).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse static routes: %v", parseErrors)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile static routes: %v", err)
	}
	routes, _, err := buildRouteSnapshots(cfg, []InterfaceSnapshot{{Name: "st0.0"}}, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	snapshot := &ConfigSnapshot{
		ForwardingTables: []string{"VPN.inet.0", "VPN.inet6.0"},
		Routes:           routes,
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	wantByDestination := map[string]bool{
		"0.0.0.0/0":       false,
		"198.51.100.0/24": false,
	}
	for _, route := range got.Routes {
		if route.Table != "VPN.inet.0" {
			continue
		}
		if _, expected := wantByDestination[route.Destination]; !expected {
			continue
		}
		if len(route.NextHops) != 1 || route.NextHops[0] != "@st0.0" {
			t.Errorf("interface-only route %s snapshot = %+v, want @st0.0",
				route.Destination, route)
			continue
		}
		wantByDestination[route.Destination] = true
	}
	for destination, found := range wantByDestination {
		if !found {
			t.Errorf("interface-only route %s missing from VPN.inet.0 snapshot", destination)
		}
	}
}

// TestFBFQualificationLeavesVirtualRouterBare guards the #4446 boundary:
// only forwarding-instance snapshots get an explicit external interface.
// A virtual-router route must retain table-scoped bare-gateway inference so
// an overlapping default-instance prefix can never select its egress.
func TestFBFQualificationLeavesVirtualRouterBare(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "VRF-A",
			InstanceType: "virtual-router",
			Interfaces:   []string{"reth0.80"},
			StaticRoutes: []*config.StaticRoute{{
				Destination: "0.0.0.0/0",
				NextHops:    []config.NextHopEntry{{Address: "172.16.80.1"}},
			}},
		}},
	}
	routes, _, err := buildRouteSnapshots(cfg, fbfTestInterfaces(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Table == "VRF-A.inet.0" && route.Destination == "0.0.0.0/0" {
			if len(route.NextHops) != 1 || route.NextHops[0] != "172.16.80.1" {
				t.Fatalf("virtual-router default = %+v, want bare gateway", route)
			}
			return
		}
	}
	t.Fatal("VRF-A default route missing")
}

// TestFBFQualifiesUniqueDefaultLinkLocalGateway11420: a forwarding-instance
// bare link-local gateway is reachable through the one IPv6-capable default
// interface, even though no connected prefix can match a link-local address.
func TestFBFQualifiesUniqueDefaultLinkLocalGateway11420(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "ISP-B",
			InstanceType: "forwarding",
			Inet6StaticRoutes: []*config.StaticRoute{{
				Destination: "::/0",
				NextHops:    []config.NextHopEntry{{Address: "fe80::254"}},
			}},
		}},
	}
	interfaces := []InterfaceSnapshot{{
		Name: "reth0.80",
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet6", Address: "fe80::8/64"},
		},
	}}
	routes, _, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Table == "ISP-B.inet6.0" && route.Destination == "::/0" {
			if len(route.NextHops) != 1 || route.NextHops[0] != "fe80::254@reth0.80" {
				t.Fatalf("ISP-B default = %+v, want fe80::254@reth0.80", route)
			}
			return
		}
	}
	t.Fatal("ISP-B default with a uniquely reachable default-instance link-local gateway was omitted")
}

func TestFBFLinkLocalGatewayKeepsSameInstanceScope11420(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "ISP-B",
			InstanceType: "forwarding",
			Inet6StaticRoutes: []*config.StaticRoute{{
				Destination: "::/0",
				NextHops:    []config.NextHopEntry{{Address: "fe80::254"}},
			}},
		}},
	}
	interfaces := []InterfaceSnapshot{
		{
			Name: "reth0.80",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "fe80::8/64"},
			},
		},
		{
			Name:            "ge-0-0-4.0",
			RoutingInstance: "ISP-B",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "fe80::4/64"},
			},
		},
	}
	routes, _, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Table == "ISP-B.inet6.0" && route.Destination == "::/0" {
			if len(route.NextHops) != 1 || route.NextHops[0] != "fe80::254@ge-0-0-4.0" {
				t.Fatalf("ISP-B default = %+v, want same-instance fe80::254@ge-0-0-4.0", route)
			}
			return
		}
	}
	t.Fatal("ISP-B default route missing")
}

// TestFBFLinkLocalGatewayRequiresUniqueDefaultInterface11420: ambiguity is
// not resolved by snapshot order or lexical interface name.
func TestFBFLinkLocalGatewayRequiresUniqueDefaultInterface11420(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "ISP-B",
			InstanceType: "forwarding",
			Inet6StaticRoutes: []*config.StaticRoute{{
				Destination: "::/0",
				NextHops:    []config.NextHopEntry{{Address: "fe80::254"}},
			}},
		}},
	}
	interfaces := []InterfaceSnapshot{
		{
			Name: "reth0.80",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "fe80::8/64"},
			},
		},
		{
			Name: "reth0.81",
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "fe80::9/64"},
			},
		},
	}
	routes, _, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Table == "ISP-B.inet6.0" && route.Destination == "::/0" {
			t.Fatalf("ambiguous forwarding-instance link-local route must remain unresolved, got %+v", route)
		}
	}
}

func TestFBFLinkLocalGatewayRejectsQuarantinedDefaultInterface11420(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "ISP-B",
			InstanceType: "forwarding",
			Inet6StaticRoutes: []*config.StaticRoute{{
				Destination: "::/0",
				NextHops:    []config.NextHopEntry{{Address: "fe80::254"}},
			}},
		}},
	}
	interfaces := []InterfaceSnapshot{{
		Name:          "reth0.80",
		RoutingDomain: 2, // Go's quarantine-only interface row has no instance name.
		Addresses: []InterfaceAddressSnapshot{
			{Family: "inet6", Address: "fe80::8/64"},
		},
	}}
	routes, _, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Table == "ISP-B.inet6.0" && route.Destination == "::/0" {
			t.Fatalf("quarantined default interface must not qualify the FI gateway, got %+v", route)
		}
	}
}

// TestFBFFilterTermSnapshotCarriesSteeringAndCounter: the FBF steering
// term reaches the dataplane with BOTH the routing-instance action and
// its per-policy counter name — the counter is how operators verify
// per-uplink steering (`xpf_filter_hits_total{filter,term}`).
func TestFBFFilterTermSnapshotCarriesSteeringAndCounter(t *testing.T) {
	snaps := buildFirewallFilterSnapshots(fbfTestConfig())
	if len(snaps) != 1 {
		t.Fatalf("filter snapshots = %+v, want 1", snaps)
	}
	if snaps[0].Name != "fbf-steer" || snaps[0].Family != "inet" {
		t.Fatalf("filter snapshot header = %+v", snaps[0])
	}
	if len(snaps[0].Terms) != 2 {
		t.Fatalf("terms = %+v, want 2", snaps[0].Terms)
	}
	steer := snaps[0].Terms[0]
	if steer.RoutingInstance != "ISP-B" {
		t.Fatalf("steer term RoutingInstance = %q, want ISP-B", steer.RoutingInstance)
	}
	if steer.Count != "fbf-isp-b" {
		t.Fatalf("steer term Count = %q, want fbf-isp-b", steer.Count)
	}
	if len(steer.SourceAddresses) != 1 || steer.SourceAddresses[0] != "10.0.61.0/24" {
		t.Fatalf("steer term sources = %+v", steer.SourceAddresses)
	}
}

// TestFBFOverlayIntoForwardingInstance: an ip-monitoring overlay entry
// targeting a forwarding instance replaces that instance's
// (table, family, prefix) entry — same whole-entry-replacement rule as
// virtual-router instances (PR-2 lifts the PR-1b rejection; the
// snapshot path needs no instance-type branch).
func TestFBFOverlayIntoForwardingInstance(t *testing.T) {
	overlay := []config.RouteOverlayEntry{
		{RoutingInstance: "ISP-B", Destination: "0.0.0.0/0", NextHop: "172.16.80.254", Policy: "wan-failover"},
	}
	routes, _, err := buildRouteSnapshots(fbfTestConfig(), fbfTestInterfaces(), overlay)
	if err != nil {
		t.Fatal(err)
	}

	var defaults []RouteSnapshot
	for _, r := range routes {
		if r.Table == "ISP-B.inet.0" && r.Destination == "0.0.0.0/0" {
			defaults = append(defaults, r)
		}
	}
	if len(defaults) != 1 {
		t.Fatalf("ISP-B.inet.0 defaults = %+v, want exactly one", defaults)
	}
	if len(defaults[0].NextHops) != 1 || defaults[0].NextHops[0] != "172.16.80.254@reth0.80" {
		t.Fatalf("ISP-B.inet.0 default = %+v, want overlay next-hop 172.16.80.254@reth0.80", defaults[0])
	}
	// Master table untouched.
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" {
			if len(r.NextHops) != 1 || r.NextHops[0] != "172.16.50.1" {
				t.Fatalf("master default disturbed: %+v", r)
			}
		}
	}
}

// An ip-monitoring overlay is applied after the #11317 config-static
// unresolved-gateway gate. Keep the bare link-local replacement in the helper
// snapshot so Rust can perform scope-aware inference against live interface
// rows instead of silently losing the monitored route.
func TestLinkLocalRouteOverlayBypassesRecursiveStaticGate_11650(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{{
		Destination: "2001:db8:beef::/48",
		NextHops:    []config.NextHopEntry{{Address: "fe80::254"}},
	}}
	interfaces := []InterfaceSnapshot{{
		Name:      "ge-0/0/1.0",
		LinuxName: "ge-0-0-1",
		Ifindex:   101,
		Addresses: []InterfaceAddressSnapshot{{
			Family: "inet6", Address: "fe80::1/64", Scope: 253,
		}},
	}}
	overlay := []config.RouteOverlayEntry{{
		Destination: "2001:db8:beef::/48",
		NextHop:     "fe80::254",
		Policy:      "wan-failover",
	}}
	routes, _, err := buildRouteSnapshots(cfg, interfaces, overlay)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var found []RouteSnapshot
	for _, route := range routes {
		if route.Table == "inet6.0" && route.Destination == "2001:db8:beef::/48" {
			found = append(found, route)
		}
	}
	if len(found) != 1 || len(found[0].NextHops) != 1 || found[0].NextHops[0] != "fe80::254" {
		t.Fatalf("link-local monitoring overlay snapshots = %+v, want one bare-fe80 replacement", found)
	}
}
