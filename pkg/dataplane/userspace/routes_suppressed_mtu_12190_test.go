package userspace

import (
	"reflect"
	"testing"
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
