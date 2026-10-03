package userspace

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const fibImportGoldenPath11419 = "../../../testdata/fib_import_11419.json"

func fibImportGoldenConfig11419() (*config.Config, []InterfaceSnapshot) {
	cfg := &config.Config{
		RoutingOptions: config.RoutingOptionsConfig{
			StaticRoutes: []*config.StaticRoute{{
				Destination: "198.51.100.0/24",
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.1"}},
			}},
		},
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "blue",
			InstanceType: "virtual-router",
			TableID:      100,
			Interfaces:   []string{"blue-a.0", "blue-b.0"},
			StaticRoutes: []*config.StaticRoute{{
				Destination: "198.51.100.0/24",
				NextHops: []config.NextHopEntry{
					{Address: "198.18.0.1"},
					{Address: "198.19.0.1"},
				},
			}},
		}},
	}
	interfaces := []InterfaceSnapshot{
		{
			Name: "main.0", Zone: "trust", EgressZone: "trust", LinuxName: "main0", Ifindex: 12,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "192.0.2.2/24"}},
		},
		{
			Name: "blue-a.0", Zone: "wan", EgressZone: "wan", RoutingInstance: "blue", LinuxName: "bluea", Ifindex: 13,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "198.18.0.2/24"}},
		},
		{
			Name: "blue-b.0", Zone: "wan", EgressZone: "wan", RoutingInstance: "blue", LinuxName: "blueb", Ifindex: 14,
			Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "198.19.0.2/24"}},
		},
	}
	return cfg, interfaces
}

func fibImportCIDR11419(text string) *net.IPNet {
	_, network, err := net.ParseCIDR(text)
	if err != nil {
		panic(err)
	}
	return network
}

// TestFIBImportGoldenSnapshotFresh11419 pins the Go builder's exact snapshot
// JSON for a fixed static config and kernel route dump. The route dump is fed
// through routing.ImportLearnedRoutes itself, not a LearnedRoute stub: the
// fixture is the shared Go→JSON→Rust FIB contract for builder table selection,
// learned ECMP preservation, and Rust egress resolution.
func TestFIBImportGoldenSnapshotFresh11419(t *testing.T) {
	previousImport := learnedRouteImportFn
	t.Cleanup(func() { learnedRouteImportFn = previousImport })
	learnedRouteImportFn = routing.ImportLearnedRoutes

	previousRules := ruleListFn
	t.Cleanup(func() { ruleListFn = previousRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	learned := netlink.Route{
		Table:    100,
		Dst:      fibImportCIDR11419("203.0.113.0/24"),
		Type:     unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_BGP),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("198.18.0.1"), Hops: 0},
			{Gw: net.ParseIP("198.19.0.1"), Hops: 0},
		},
	}
	restoreRoutes := routing.SetLearnedRouteListFnForTest(func(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 && filter != nil && filter.Table == 100 {
			return []netlink.Route{learned}, nil
		}
		return nil, nil
	})
	t.Cleanup(restoreRoutes)

	cfg, interfaces := fibImportGoldenConfig11419()
	routes, capped, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatalf("build route snapshots from config and kernel dump: %v", err)
	}
	if capped {
		t.Fatal("fixed single-route kernel dump unexpectedly hit the learned-route cap")
	}
	snapshot := ConfigSnapshot{
		Version:     ProtocolVersion,
		Generation:  1,
		GeneratedAt: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		Zones: []ZoneSnapshot{
			{Name: "trust", ID: 1},
			{Name: "wan", ID: 2},
		},
		Interfaces: interfaces,
		Neighbors: []NeighborSnapshot{
			{Interface: "main0", Ifindex: 12, Family: "inet", IP: "192.0.2.1", MAC: "00:11:22:33:44:12", State: "reachable", Router: true},
			{Interface: "bluea", Ifindex: 13, Family: "inet", IP: "198.18.0.1", MAC: "00:11:22:33:44:13", State: "reachable", Router: true},
			{Interface: "blueb", Ifindex: 14, Family: "inet", IP: "198.19.0.1", MAC: "00:11:22:33:44:14", State: "reachable", Router: true},
		},
		Routes: routes,
	}
	got, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		t.Fatalf("marshal Go-built snapshot: %v", err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_FIB_GOLDEN_11419") == "1" {
		if err := os.WriteFile(fibImportGoldenPath11419, got, 0o644); err != nil {
			t.Fatalf("write golden snapshot: %v", err)
		}
		return
	}
	want, err := os.ReadFile(filepath.Clean(fibImportGoldenPath11419))
	if err != nil {
		t.Fatalf("read shared Go→Rust FIB golden: %v (regenerate with UPDATE_FIB_GOLDEN_11419=1)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Go-built FIB snapshot drifted from %s; regenerate with UPDATE_FIB_GOLDEN_11419=1 and run the Rust consumer too\ngot:\n%s", fibImportGoldenPath11419, got)
	}
}
