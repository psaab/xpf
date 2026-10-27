package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17971: the route listener's coalesced actuation must reconcile the
// next-table main-table exception band from the active config before it
// republishes the helper FIB, so a learned main route that appears between
// commits converges the kernel RPDB and the snapshot together. The refresh
// inputs must be the same derivation the commit path feeds Apply.

func TestNextTableApplyInputsMatchCommitDerivation17971(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"fxp0":     {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	v4 := &config.StaticRoute{Destination: "10.0.0.0/8", NextTable: "red"}
	v6 := &config.StaticRoute{Destination: "2001:db8::/32", NextTable: "red"}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{v4}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{v6}

	routes, ifaces := nextTableApplyInputs(cfg)
	if len(routes) != 2 || routes[0] != v4 || routes[1] != v6 {
		t.Fatalf("nextTableApplyInputs routes = %v, want [v4 v6] in commit order", routes)
	}
	// Fresh slice: mutating the result must not write into the config's
	// own backing arrays (#1781 hazard the helper exists to preserve).
	routes[0] = nil
	if cfg.RoutingOptions.StaticRoutes[0] != v4 {
		t.Fatal("nextTableApplyInputs aliased the config static-route slice")
	}
	if len(ifaces) != 1 || ifaces[0] != "ge-0-0-1" {
		t.Fatalf("nextTableApplyInputs ifaces = %v, want only the default-instance ingress ge-0-0-1", ifaces)
	}

	// A nil routing manager (helperless/test daemon) refreshes as a no-op.
	d := &Daemon{}
	if err := d.refreshNextTableCarveouts(cfg); err != nil {
		t.Fatalf("refreshNextTableCarveouts without routing manager: %v", err)
	}
	if err := d.refreshNextTableCarveouts(nil); err != nil {
		t.Fatalf("refreshNextTableCarveouts with nil config: %v", err)
	}
}

func TestRouteListenerActuationRefreshesCarveouts17971(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := routeListenerBumpDaemon11565(t, dp)
	// d.routing is nil in this fixture, so the carve-out refresh is the
	// no-op arm; the actuation must still converge end to end. The
	// error arm (refresh failure keeps the coalescer dirty) is pinned at
	// the routing layer by TestNextTableDynamicCarveoutDumpFailureKeepsBand17971.
	if !d.actuateLearnedRouteRefresh(context.Background()) {
		t.Fatal("actuation with nil routing manager did not converge")
	}
	requireRouteListenerCalls11565(t, dp.calls, "publish", "bump")
}
