package userspace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// pmechTunnelScaleRoutes returns count /24s inside the tunnel selector, all via
// the tunnel: the worst case, where every route is tunnel-relevant.
func pmechTunnelScaleRoutes(tb testing.TB, count int) []netlink.Route {
	tb.Helper()
	routes := make([]netlink.Route, 0, count+1)
	routes = append(routes, netlink.Route{
		Table: int(pmechMainTable), Family: unix.AF_INET, Type: unix.RTN_UNICAST,
		Protocol: unix.RTPROT_STATIC, LinkIndex: 10,
	})
	for i := range count {
		destination := fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
		_, prefix, err := net.ParseCIDR(destination)
		if err != nil {
			tb.Fatalf("parse scale route %q: %v", destination, err)
		}
		routes = append(routes, netlink.Route{
			Table: int(pmechMainTable), Family: unix.AF_INET, Dst: prefix,
			Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_STATIC, LinkIndex: 10,
		})
	}
	return routes
}

// pmechForeignScaleRoutes returns the tunnel route, a WAN default route, and
// count foreign /24s via the WAN: a full-table edge whose tunnel owns little.
func pmechForeignScaleRoutes(count int) []netlink.Route {
	gateway := net.ParseIP("192.0.2.1")
	routes := make([]netlink.Route, 0, count+2)
	routes = append(routes,
		netlink.Route{
			Table: int(pmechMainTable), Family: unix.AF_INET, Type: unix.RTN_UNICAST,
			Protocol: unix.RTPROT_STATIC, LinkIndex: 10,
			Dst: &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
		},
		netlink.Route{
			Table: int(pmechMainTable), Family: unix.AF_INET, Type: unix.RTN_UNICAST,
			Protocol: unix.RTPROT_STATIC, LinkIndex: 20, Gw: gateway,
		},
	)
	for i := range count {
		routes = append(routes, netlink.Route{
			Table: int(pmechMainTable), Family: unix.AF_INET, Type: unix.RTN_UNICAST,
			Protocol: unix.RTPROT_BGP, LinkIndex: 20, Gw: gateway,
			Dst: &net.IPNet{IP: net.IPv4(byte(11+i>>16), byte(i>>8), byte(i), 0).To4(), Mask: net.CIDRMask(24, 32)},
		})
	}
	return routes
}

func pmechScaleSnapshot() *ConfigSnapshot {
	return &ConfigSnapshot{
		Generation: 11, FIBGeneration: 7,
		Config: &config.Config{Security: config.SecurityConfig{IPsec: config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
			"vpn": {BindInterface: "st0", LocalID: "198.51.100.0/24", RemoteID: "10.0.0.0/8"},
		}}}},
		IpsecTunnelRows: []IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}},
	}
}

// pmechStampBudget100k bounds one 100k-route stamp. The pre-filter inventory
// spent 2.30s and 14.3 MB of JSON here; the filtered stamp is ~20x faster, so
// the bound catches a return to full-table processing without timing flakes.
const pmechStampBudget100k = time.Second

// TestPMechInventoryScalesWithTunnelRelevantRoutes9506 is the full-table cell
// for the inventory every FIB bump carries: the retained rows and the bump
// JSON must not grow with foreign routes, and a 100k-route stamp stays inside
// pmechStampBudget100k.
func TestPMechInventoryScalesWithTunnelRelevantRoutes9506(t *testing.T) {
	var baseline []byte
	for _, count := range []int{1_000, 100_000} {
		routes := pmechForeignScaleRoutes(count)
		snapshot := pmechScaleSnapshot()
		start := time.Now()
		stampPMechInventoryFromRoutes(snapshot, routes, nil)
		elapsed := time.Since(start)
		inventory := snapshot.PMechInventory
		body, err := json.Marshal(inventory)
		if err != nil {
			t.Fatal(err)
		}
		row := inventory.TunnelRows[0]
		if !inventory.Complete || !row.InventoryValid ||
			!reflect.DeepEqual(row.EffectivePrefixes, []string{"10.0.0.0/8"}) {
			t.Fatalf("N=%d: inventory complete=%v row=%+v, want valid 10.0.0.0/8", count, inventory.Complete, row)
		}
		if len(inventory.MainRoutes) != 2 {
			t.Fatalf("N=%d: retained %d main routes, want the tunnel route and the default route",
				count, len(inventory.MainRoutes))
		}
		if baseline == nil {
			baseline = body
		} else if !bytes.Equal(body, baseline) {
			t.Fatalf("N=%d: inventory JSON changed with foreign routes (%d bytes, baseline %d)",
				count, len(body), len(baseline))
		}
		if count == 100_000 && elapsed > pmechStampBudget100k {
			t.Fatalf("N=%d: stamp took %s, budget %s", count, elapsed, pmechStampBudget100k)
		}
		t.Logf("N=%d stamp=%s json=%d bytes main_routes=%d", count, elapsed, len(body), len(inventory.MainRoutes))
	}
}

// Dropping routes that neither leave through a tunnel nor overlap a remote
// selector must not change any row's projection: the filtered stamp equals a
// stamp that keeps every route.
func TestPMechRelevanceFilterPreservesProjection9506(t *testing.T) {
	routes := []netlink.Route{
		v96MainRoute(t, "10.0.0.0/8", unix.RTN_UNICAST, 10),
		v96MainRoute(t, "10.1.0.0/16", unix.RTN_UNICAST, 20),   // blocker inside the selector
		v96MainRoute(t, "10.200.0.0/16", unix.RTN_UNICAST, 20), // blocker outside the selector
		v96MainRoute(t, "10.201.0.0/16", unix.RTN_BLACKHOLE, 0),
		v96MainRoute(t, "11.0.0.0/8", unix.RTN_UNICAST, 20),
	}
	snapshot := func() *ConfigSnapshot {
		return &ConfigSnapshot{
			Generation: 11, FIBGeneration: 7,
			Config: &config.Config{Security: config.SecurityConfig{IPsec: config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
				"vpn": {BindInterface: "st0", LocalID: "198.51.100.0/24", RemoteID: "10.0.0.0/9"},
			}}}},
			IpsecTunnelRows: []IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}},
		}
	}
	filtered := snapshot()
	stampPMechInventoryFromRoutes(filtered, routes, nil)

	unfiltered := snapshot()
	selectorsBySTN, selectorErrors := pmechSelectorsBySTN(unfiltered.Config)
	keepAll := newPMechRouteCollector(unfiltered.IpsecTunnelRows, selectorsBySTN)
	keepAll.remotePrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	for _, route := range routes {
		keepAll.add(route)
	}
	keepAll.stamp(unfiltered, selectorsBySTN, selectorErrors, nil, false)

	if len(filtered.PMechInventory.MainRoutes) != 2 || len(unfiltered.PMechInventory.MainRoutes) != len(routes) {
		t.Fatalf("retained rows filtered=%d unfiltered=%d, want 2 and %d",
			len(filtered.PMechInventory.MainRoutes), len(unfiltered.PMechInventory.MainRoutes), len(routes))
	}
	got, want := filtered.PMechInventory.TunnelRows[0], unfiltered.PMechInventory.TunnelRows[0]
	if !got.InventoryValid || !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered row=%+v, want the full-table row %+v", got, want)
	}
}

// The FIB bump streams the main table before taking m.mu, so a slow dump
// never holds up status polls, neighbor updates, or publishes.
func TestBumpFIBGenerationDumpsRoutesOffManagerLock9506(t *testing.T) {
	m, _, requests := pmechDedupManager9506(t)
	routes := []netlink.Route{v96MainRoute(t, "10.99.0.0/24", unix.RTN_UNICAST, 3)}
	dumps, underLock := 0, 0
	previous := pmechMainRouteIterFn
	t.Cleanup(func() { pmechMainRouteIterFn = previous })
	pmechMainRouteIterFn = func(visit func(netlink.Route) bool) error {
		dumps++
		if m.mu.TryLock() {
			m.mu.Unlock()
		} else {
			underLock++
		}
		for _, route := range routes {
			visit(route)
		}
		return nil
	}
	newGen, err := m.BumpFIBGeneration()
	if err != nil && !errors.Is(err, dataplane.ErrDataplaneNotArmed) {
		t.Fatalf("BumpFIBGeneration: %v", err)
	}
	if dumps != 1 || underLock != 0 {
		t.Fatalf("bump route dumps=%d under m.mu=%d, want one dump off the lock", dumps, underLock)
	}
	m.mu.Lock()
	inventory := m.lastSnapshot.PMechInventory
	fibGeneration := m.lastSnapshot.FIBGeneration
	m.mu.Unlock()
	if requests["bump_fib_generation"] != 1 || inventory == nil ||
		inventory.FIBGeneration != newGen || fibGeneration != newGen || len(inventory.MainRoutes) != 1 {
		t.Fatalf("bump requests=%v inventory=%+v fib=%d, want one bump carrying the prefetched inventory at %d",
			requests, inventory, fibGeneration, newGen)
	}
}

// Two tunnel rows that would claim the same effective prefixes both lose
// authority; disjoint selectors on the same leg keep both.
func TestPMechOverlappingTunnelPrefixesPoisonBothRows9506(t *testing.T) {
	stamp := func(remoteA, remoteB string) []IpsecPMechTunnelRowSnapshot {
		snapshot := &ConfigSnapshot{
			Generation: 11, FIBGeneration: 7,
			Config: &config.Config{Security: config.SecurityConfig{IPsec: config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
				"vpn-a": {BindInterface: "st0", LocalID: "198.51.100.0/24", RemoteID: remoteA},
				"vpn-b": {BindInterface: "st1", LocalID: "198.51.100.0/24", RemoteID: remoteB},
			}}}},
			IpsecTunnelRows: []IpsecTunnelRowSnapshot{
				{STN: "st0", IfID: 9, LogicalIfindex: 10},
				{STN: "st1", IfID: 10, LogicalIfindex: 10},
			},
		}
		stampPMechInventoryFromRoutes(snapshot, []netlink.Route{
			v96MainRoute(t, "10.0.0.0/24", unix.RTN_UNICAST, 10),
		}, nil)
		return snapshot.PMechInventory.TunnelRows
	}
	for _, row := range stamp("10.0.0.0/24", "10.0.0.0/25") {
		if row.InventoryValid || row.InventoryReason != "DOMAIN_OVERLAP" {
			t.Fatalf("overlapping row %s valid=%v reason=%q, want DOMAIN_OVERLAP", row.STN, row.InventoryValid, row.InventoryReason)
		}
	}
	for _, row := range stamp("10.0.0.0/25", "10.0.0.128/25") {
		if !row.InventoryValid || row.InventoryReason != "" {
			t.Fatalf("disjoint row %s valid=%v reason=%q, want valid", row.STN, row.InventoryValid, row.InventoryReason)
		}
	}
}

func BenchmarkPMechRouteInventoryScale9506(b *testing.B) {
	for _, count := range []int{1_000, 4_000, 16_000} {
		routes := pmechTunnelScaleRoutes(b, count)
		b.Run(fmt.Sprintf("N=%d/no-tunnels", count), func(b *testing.B) {
			calls := setPMechRouteDump9506(b, routes, nil)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				snapshot := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
				stampPMechInventory(snapshot)
				if snapshot.PMechInventory == nil || snapshot.PMechInventory.Complete ||
					len(snapshot.PMechInventory.MainRoutes) != 0 {
					b.Fatal("empty tunnel inventory did not take the authority-free fast path")
				}
			}
			if *calls != 0 {
				b.Fatalf("empty tunnel benchmark performed %d route dumps", *calls)
			}
		})
		b.Run(fmt.Sprintf("N=%d/one-tunnel", count), func(b *testing.B) {
			snapshot := pmechScaleSnapshot()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				snapshot.PMechInventory = nil
				stampPMechInventoryFromRoutes(snapshot, routes, nil)
				if !snapshot.PMechInventory.Complete || !snapshot.PMechInventory.TunnelRows[0].InventoryValid {
					b.Fatal("scale inventory lost valid tunnel authority")
				}
			}
		})
	}
}
