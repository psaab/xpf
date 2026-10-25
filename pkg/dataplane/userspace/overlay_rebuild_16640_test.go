package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestRebuildAfterRevalidatePreservesCompileOverlay16640 pins #16640
// (R3-A29-02). A fresh Compile snapshot is built with the active
// ip-monitoring overlay, but its Config is not yet the retained
// applied config, so the old routeOverlayForSnapshot identity check
// returned nil and the apply-time derived-section rebuild discarded
// the overlay whenever revalidation moved or dropped a row (on HA
// nodes, on every Compile, because the peer-fabric row is dropped).
// The rebuild must re-derive Routes from the overlay the snapshot
// was actually built with, recorded on the snapshot by the builder.
//
// FAIL-ON-REVERT: reverting routeOverlayForSnapshot to the identity
// check (or dropping the builder's builtRouteOverlay record) makes
// the defect cell lose the overlay default route; the retained-config
// control and the build-time-overlay-wins cell pin the boundaries.
func TestRebuildAfterRevalidatePreservesCompileOverlay16640(t *testing.T) {
	origBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = origBuild })
	origLookup := linkByNameFn
	t.Cleanup(func() { linkByNameFn = origLookup })
	origXfrm := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = origXfrm })
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })

	// ge-0-0-1 vanished at apply time; ge-0-0-0 is unchanged. The
	// dropped row forces prepareSnapshotForApply into the rebuild.
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		switch linuxName {
		case "ge-0-0-0":
			return 17, 1500, "", nil
		default:
			return 0, 0, "", nil
		}
	}
	linkByNameFn = func(string) (netlink.Link, error) { return nil, errors.New("test link lookup") }
	liveXfrmNetdevs = func() (map[string]bool, error) { return nil, nil }
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	overlay := []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "10.0.0.253", Policy: "wan-failover"}}

	newCfg := func() *config.Config {
		cfg := &config.Config{}
		cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.0.1"}}},
		}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.0.2/24"}},
			}},
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.1.2/24"}},
			}},
		}
		return cfg
	}

	defaultRoute := func(snap *ConfigSnapshot) *RouteSnapshot {
		for i := range snap.Routes {
			if snap.Routes[i].Table == "inet.0" && snap.Routes[i].Destination == "0.0.0.0/0" {
				return &snap.Routes[i]
			}
		}
		return nil
	}

	// Defect cell: fresh Compile snapshot (Config != retained Config)
	// built WITH the overlay; m.routeOverlay has since moved to a
	// different next hop. The rebuild must keep the build-time overlay.
	t.Run("fresh-compile-keeps-build-overlay", func(t *testing.T) {
		prevCfg := newCfg()
		newCfgObj := newCfg()
		snap, err := buildSnapshotWithSchedulerState(newCfgObj, config.UserspaceConfig{}, 7, 0, nil, overlay, nil)
		if err != nil {
			t.Fatalf("build snapshot: %v", err)
		}
		if r := defaultRoute(snap); r == nil || len(r.NextHops) != 1 || r.NextHops[0] != "10.0.0.253" {
			t.Fatalf("premise: built default route = %+v, want overlay 10.0.0.253", r)
		}
		m := New()
		m.lastSnapshot = &ConfigSnapshot{Config: prevCfg}
		// The manager overlay moved after the build; the fresh snapshot
		// must not pick it up (its routes were built with `overlay`).
		m.routeOverlay = []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "10.0.0.99", Policy: "wan-failover"}}
		m.mu.Lock()
		m.prepareSnapshotForApply(snap)
		m.mu.Unlock()
		if !m.revalidateChangedIfindex {
			t.Fatal("premise: revalidation did not move/drop a row, rebuild never ran")
		}
		r := defaultRoute(snap)
		if r == nil || len(r.NextHops) != 1 || r.NextHops[0] != "10.0.0.253" {
			t.Fatalf("rebuilt default route = %+v, want build-time overlay 10.0.0.253 preserved (#16640)", r)
		}
	})

	// Retained-config control: a snapshot whose Config IS the retained
	// config and which carries no recorded build overlay keeps the
	// manager's current overlay, exactly as before.
	t.Run("retained-config-control", func(t *testing.T) {
		cfg := newCfg()
		snap := &ConfigSnapshot{
			Config: cfg,
			Interfaces: []InterfaceSnapshot{
				{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0", Ifindex: 17, Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.0.2/24"}}},
				{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1", Ifindex: 18, Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.1.2/24"}}},
			},
			Routes: []RouteSnapshot{
				{Table: "inet.0", Family: "inet", Destination: "0.0.0.0/0", NextHops: []string{"10.0.0.1"}},
			},
		}
		m := New()
		m.lastSnapshot = &ConfigSnapshot{Config: cfg}
		m.routeOverlay = cloneRouteOverlay(overlay)
		m.mu.Lock()
		m.prepareSnapshotForApply(snap)
		m.mu.Unlock()
		if !m.revalidateChangedIfindex {
			t.Fatal("premise: revalidation did not move/drop a row, rebuild never ran")
		}
		r := defaultRoute(snap)
		if r == nil || len(r.NextHops) != 1 || r.NextHops[0] != "10.0.0.253" {
			t.Fatalf("retained rebuild default route = %+v, want current overlay 10.0.0.253", r)
		}
	})

	// Hand-built fresh snapshot with no recorded overlay and a foreign
	// Config must NOT re-apply the manager's current overlay: its
	// routes are its author's own.
	t.Run("foreign-handbuilt-no-reapply", func(t *testing.T) {
		cfg := newCfg()
		snap := &ConfigSnapshot{
			Config: cfg,
			Interfaces: []InterfaceSnapshot{
				{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0", Ifindex: 17, Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.0.2/24"}}},
				{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1", Ifindex: 18, Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.1.2/24"}}},
			},
			Routes: []RouteSnapshot{
				{Table: "inet.0", Family: "inet", Destination: "0.0.0.0/0", NextHops: []string{"10.0.0.1"}},
			},
		}
		m := New()
		m.lastSnapshot = &ConfigSnapshot{Config: newCfg()}
		m.routeOverlay = cloneRouteOverlay(overlay)
		m.mu.Lock()
		m.prepareSnapshotForApply(snap)
		m.mu.Unlock()
		r := defaultRoute(snap)
		if r == nil || len(r.NextHops) != 1 || r.NextHops[0] != "10.0.0.1" {
			t.Fatalf("foreign rebuild default route = %+v, want authored 10.0.0.1 (no re-apply)", r)
		}
	})
}
