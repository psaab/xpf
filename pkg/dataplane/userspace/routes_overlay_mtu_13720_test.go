package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13720 — applyRouteOverlay runs after addLearnedRouteSnapshots and
// whole-entry replaces the winning row with a fresh(RouteSnapshot{MTU:0}).
// When the replaced row is the learned/surviving row carrying kernel
// RTAX_MTU, or when the overlay nexthop matches that row by meaning, the
// constraint must survive on the published overlay row. A different path
// is not constrained by the replaced route's MTU.
//
// RED on master: the overlay row emits MTU 0.

func TestRouteOverlayPreservesLearnedMTUOnSameNextHop13720(t *testing.T) {
	cfg := cfgWithStaticDefault("192.0.2.1")
	cfg.RoutingOptions.StaticRoutes[0].Preference = 5
	learned := learnedV4("0.0.0.0/0", "192.0.2.1")
	learned.Protocol = "static"
	learned.MTU = 1400
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, []config.RouteOverlayEntry{{
		Destination: "0.0.0.0/0", NextHop: "192.0.2.1", Policy: "wan-failover",
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", out)
	if len(hits) != 1 {
		t.Fatalf("want sole overlay route, got %d: %+v", len(hits), hits)
	}
	if hits[0].Preference != 1 || !reflect.DeepEqual(hits[0].NextHops, []string{"192.0.2.1"}) {
		t.Fatalf("overlay row lost: %+v", hits[0])
	}
	if hits[0].MTU != 1400 {
		t.Fatalf("overlay row MTU = %d, want learned constraint 1400: %+v", hits[0].MTU, hits[0])
	}
}

func TestRouteOverlayPreservesImportedLearnedMTU13720(t *testing.T) {
	learned := learnedV4("10.20.30.0/24", "192.0.2.1")
	learned.MTU = 1400
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(&config.Config{}, nil, []config.RouteOverlayEntry{{
		Destination: "10.20.30.0/24", NextHop: "192.0.2.1", Policy: "wan-failover",
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "10.20.30.0/24", out)
	if len(hits) != 1 {
		t.Fatalf("want sole overlay route, got %d: %+v", len(hits), hits)
	}
	if hits[0].MTU != 1400 {
		t.Fatalf("overlay row MTU = %d, want learned constraint 1400: %+v", hits[0].MTU, hits[0])
	}
}

func TestRouteOverlayDoesNotInheritMTUFromDifferentNextHop13720(t *testing.T) {
	cfg := cfgWithStaticDefault("192.0.2.1")
	cfg.RoutingOptions.StaticRoutes[0].Preference = 5
	learned := learnedV4("0.0.0.0/0", "192.0.2.1")
	learned.Protocol = "static"
	learned.MTU = 1400
	withLearnedRoutes(t, fixedLearned(learned))

	out, _, err := buildRouteSnapshots(cfg, nil, []config.RouteOverlayEntry{{
		Destination: "0.0.0.0/0", NextHop: "192.0.2.254", Policy: "wan-failover",
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", out)
	if len(hits) != 1 {
		t.Fatalf("want sole overlay route, got %d: %+v", len(hits), hits)
	}
	if hits[0].MTU != 0 {
		t.Fatalf("different-path overlay MTU = %d, want 0: %+v", hits[0].MTU, hits[0])
	}
}
