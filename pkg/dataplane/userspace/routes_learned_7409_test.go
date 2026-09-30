package userspace

import (
	"errors"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #7409 — kernel-learned routes reaching the helper FIB.
//
// buildRouteSnapshots derives the helper FIB from config statics, connected
// prefixes, the ip-rule leak mirror and the ip-monitoring overlay. Nothing
// read the kernel, so an FRR-installed or DHCP-learned route was invisible to
// the dataplane while the kernel routed it — and a transit packet toward such
// a destination either resolved NoRoute and was REINJECTED to the kernel with
// no zone policy, session, NAT or screen behind it, or was forwarded to a
// static default's next-hop instead of the learned one.
//
// These tests pin the importer wiring, preference-aware same-prefix behavior,
// and the overlay's replacement of imported routes.

// withLearnedRoutes installs a fake importer for the duration of a test.
//
// The production default is a DISABLED importer (nil), so every OTHER test in
// this package builds snapshots that cannot see the build host's routing
// table. That default is what keeps this suite hermetic — measured: a dev box
// carries a `default via ... proto dhcp` route which is RTN_UNICAST, has a
// gateway and an admitted RTPROT, so it satisfies every import predicate and
// would otherwise appear as a phantom default in unrelated snapshots.
func withLearnedRoutes(t *testing.T, fn func([]int) ([]routing.LearnedRoute, error)) {
	t.Helper()
	prev := learnedRouteImportFn
	learnedRouteImportFn = fn
	t.Cleanup(func() { learnedRouteImportFn = prev })
}

func fixedLearned(routes ...routing.LearnedRoute) func([]int) ([]routing.LearnedRoute, error) {
	return func([]int) ([]routing.LearnedRoute, error) { return routes, nil }
}

func learnedV4(dst, gw string) routing.LearnedRoute {
	return routing.LearnedRoute{
		TableID: 254, Family: netlink.FAMILY_V4,
		Destination: dst, NextHops: []string{gw}, Protocol: "bgp",
	}
}

// cfgWithStaticDefault returns a config carrying a v4 static default, the
// shape almost every shipped xpf config has.
func cfgWithStaticDefault(nextHop string) *config.Config {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: nextHop}}},
	}
	return cfg
}

func snapshotFor(t *testing.T, table, family, dest string, out []RouteSnapshot) []RouteSnapshot {
	t.Helper()
	var hits []RouteSnapshot
	for _, s := range out {
		if s.Table == table && s.Family == family && s.Destination == dest {
			hits = append(hits, s)
		}
	}
	return hits
}

// THE ACCEPTANCE CRITERION. A packet toward a learned prefix must be
// adjudicated rather than reinjected, and that starts with the route being in
// the FIB at all.
//
// RED on revert: delete the addLearnedRouteSnapshots call from
// buildRouteSnapshots and 10.20.30.0/24 disappears from the snapshot — which
// is exactly the state in which the dataplane resolves NoRoute for it and
// hands the packet to the kernel unadjudicated.
func TestLearnedRouteReachesTheSnapshot(t *testing.T) {
	withLearnedRoutes(t, fixedLearned(learnedV4("10.20.30.0/24", "192.0.2.1")))

	out, _, err := buildRouteSnapshots(&config.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "10.20.30.0/24", out)
	if len(hits) != 1 {
		t.Fatalf("want exactly 1 snapshot for the learned prefix, got %d (%+v)", len(hits), out)
	}
	if !reflect.DeepEqual(hits[0].NextHops, []string{"192.0.2.1"}) {
		t.Errorf("next-hops = %v, want [192.0.2.1]", hits[0].NextHops)
	}
	if hits[0].Preference != routing.LearnedRouteImportPreference {
		t.Errorf("preference = %d, want the learned-route preference %d",
			hits[0].Preference, routing.LearnedRouteImportPreference)
	}
}

// A better-preference config route remains the sole candidate when a learned
// route carries preference 200.
//
// FAIL-ON-REVERT: removing the preference comparison and always publishing
// imported routes makes both same-prefix candidates appear here.
func TestLearnedRouteDoesNotOverrideABetterPreferenceConfigRoute(t *testing.T) {
	cfg := cfgWithStaticDefault("192.0.2.1")
	cfg.RoutingOptions.StaticRoutes[0].Preference = 5
	withLearnedRoutes(t, fixedLearned(learnedV4("0.0.0.0/0", "198.51.100.254")))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", out)
	if len(hits) != 1 {
		t.Fatalf("preference-5 config default must be the only candidate, got %d: %+v", len(hits), hits)
	}
	if hits[0].Preference != 5 || !reflect.DeepEqual(hits[0].NextHops, []string{"192.0.2.1"}) {
		t.Fatalf("better-preference config route lost: %+v", hits[0])
	}
}

// A floating static with preference 250 is a fallback when FRR has selected a
// better learned route. The helper must publish both candidates so the Rust
// FIB's ascending-preference tie-break selects the imported route at 200.
//
// FAIL-ON-REVERT: restoring unconditional gap-fill suppression leaves only the
// config fallback, so helper traffic keeps taking the wrong next-hop.
func TestLearnedRouteOutranksWorsePreferenceConfigRoute(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0",
		Preference:  250,
		NextHops:    []config.NextHopEntry{{Address: "192.0.2.1"}},
	}}
	withLearnedRoutes(t, fixedLearned(learnedV4("0.0.0.0/0", "198.51.100.254")))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", out)
	if len(hits) != 2 {
		t.Fatalf("want learned route and floating-static fallback, got %d: %+v", len(hits), hits)
	}

	foundLearned, foundFallback := false, false
	for _, route := range hits {
		switch route.Preference {
		case routing.LearnedRouteImportPreference:
			foundLearned = reflect.DeepEqual(route.NextHops, []string{"198.51.100.254"})
		case 250:
			foundFallback = reflect.DeepEqual(route.NextHops, []string{"192.0.2.1"})
		default:
			t.Fatalf("unexpected same-prefix route: %+v", route)
		}
	}
	if !foundLearned {
		t.Errorf("the selected learned route at preference %d is missing: %+v",
			routing.LearnedRouteImportPreference, hits)
	}
	if !foundFallback {
		t.Errorf("the preference-250 fallback must remain available: %+v", hits)
	}
}

// A MIDDLE STATE, not an extreme: the same prefix is config-covered in ONE
// table and learned in ANOTHER. The gap-fill key is per (table, family,
// prefix), so the covered table keeps the operator's route and the uncovered
// one gains the learned route. A key that ignored the table would wrongly
// suppress the second.
func TestLearnedRouteGapFillIsPerTableNotGlobal(t *testing.T) {
	cfg := cfgWithStaticDefault("192.0.2.1")
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "blue", TableID: 100},
	}
	withLearnedRoutes(t, fixedLearned(
		learnedV4("0.0.0.0/0", "198.51.100.254"), // main — config-covered
		routing.LearnedRoute{
			TableID: 100, Family: netlink.FAMILY_V4,
			Destination: "0.0.0.0/0", NextHops: []string{"203.0.113.1"}, Protocol: "bgp",
		},
	))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	main := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", out)
	if len(main) != 1 || !reflect.DeepEqual(main[0].NextHops, []string{"192.0.2.1"}) {
		t.Errorf("main table must keep ONLY the config default, got %+v", main)
	}
	blue := snapshotFor(t, "blue.inet.0", "inet", "0.0.0.0/0", out)
	if len(blue) != 1 || !reflect.DeepEqual(blue[0].NextHops, []string{"203.0.113.1"}) {
		t.Errorf("blue.inet.0 must gain the learned default, got %+v", blue)
	}
}

// A table the config does not name must never be published into the helper
// FIB under a fabricated name — otherwise a foreign daemon's table could
// reach the fast path.
func TestLearnedRouteFromAnUnknownTableIsDropped(t *testing.T) {
	withLearnedRoutes(t, fixedLearned(routing.LearnedRoute{
		TableID: 4242, Family: netlink.FAMILY_V4,
		Destination: "10.7.0.0/16", NextHops: []string{"192.0.2.1"},
	}))

	out, _, err := buildRouteSnapshots(&config.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, s := range out {
		if s.Destination == "10.7.0.0/16" {
			t.Fatalf("a route from an unnamed kernel table reached the snapshot: %+v", s)
		}
	}
}

// THE OVERLAY BEATS AN IMPORTED ROUTE. An ip-monitoring failover route must
// win over whatever the kernel happens to hold for the same prefix, or #1827's
// whole-entry replacement contract is silently undone.
//
// HONEST LIMITATION: no single-line revert of the import code reds this, and
// that was measured, not assumed. TWO independent mechanisms enforce it — in
// the shipped order applyRouteOverlay's whole-entry replacement removes the
// imported entry, and in the reversed order the gap-fill sees the prefix
// already covered by the overlay. Deleting either one alone leaves this GREEN.
// It is a COMPOSITION fence, not a mutation-bound assertion: it fails if the
// two mechanisms ever stop covering each other (an imported entry the overlay
// cannot see, or an emission path that bypasses both). Stated rather than
// dressed up as a RED-on-revert claim it cannot support.
func TestOverlayStillReplacesAnImportedRoute(t *testing.T) {
	withLearnedRoutes(t, fixedLearned(learnedV4("10.20.30.0/24", "192.0.2.1")))

	overlay := []config.RouteOverlayEntry{{
		Destination: "10.20.30.0/24",
		NextHop:     "198.51.100.9",
		Policy:      "wan-failover",
	}}
	out, _, err := buildRouteSnapshots(&config.Config{}, nil, overlay)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hits := snapshotFor(t, "inet.0", "inet", "10.20.30.0/24", out)
	if len(hits) != 1 {
		t.Fatalf("overlay must REPLACE the imported entry set, got %d: %+v", len(hits), hits)
	}
	if !reflect.DeepEqual(hits[0].NextHops, []string{"198.51.100.9"}) {
		t.Fatalf("next-hop = %v, want the overlay's [198.51.100.9]", hits[0].NextHops)
	}
}

// FAIL CLOSED. An importer failure fails the whole snapshot build, so the
// apply path retains the prior dataplane state rather than shipping a FIB
// that silently omits a subset of learned destinations while the kernel keeps
// routing them. Same #3772 M9 reasoning as the ip-rule enumeration.
func TestLearnedRouteImportFailureFailsTheSnapshotClosed(t *testing.T) {
	sentinel := errors.New("netlink boom")
	withLearnedRoutes(t, func([]int) ([]routing.LearnedRoute, error) {
		return nil, sentinel
	})

	out, _, err := buildRouteSnapshots(cfgWithStaticDefault("192.0.2.1"), nil, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap %v", err, sentinel)
	}
	if out != nil {
		t.Fatalf("a failed build must return no snapshot, got %+v", out)
	}
}

// THE REGRESSION FENCE for every shipped config that has no learned routes.
// With the import disabled — the production default until Manager.Start arms
// it, and the state every other test in this package runs in — the snapshot
// must be byte-identical to the pre-#7409 build. An empty import must be
// identical too, so arming the feature on a box with nothing to import is a
// no-op rather than a subtle reordering.
func TestEmptyAndDisabledImportsProduceIdenticalSnapshots(t *testing.T) {
	cfg := cfgWithStaticDefault("192.0.2.1")

	withLearnedRoutes(t, nil)
	disabled, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build (disabled): %v", err)
	}

	withLearnedRoutes(t, fixedLearned())
	empty, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build (empty): %v", err)
	}

	if !reflect.DeepEqual(disabled, empty) {
		t.Fatalf("an empty import must be a no-op:\n disabled=%+v\n empty=%+v", disabled, empty)
	}
}

// DETERMINISM. The kernel dump order is not a stable function of content, and
// the builder's final sort tie-breaks on next-hops/next-table/discard/
// preference — all of which two learned routes for DIFFERENT prefixes share.
// Without the importer's own ordering pass, kernel order would leak through
// and produce snapshot-to-snapshot diffs (and a needless FIB re-install) for
// an unchanged routing table.
func TestLearnedRouteEmissionIsOrderIndependent(t *testing.T) {
	a := learnedV4("10.1.0.0/16", "192.0.2.1")
	b := learnedV4("10.2.0.0/16", "192.0.2.2")
	c := learnedV4("10.3.0.0/16", "192.0.2.3")

	withLearnedRoutes(t, fixedLearned(a, b, c))
	first, _, err := buildRouteSnapshots(&config.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	withLearnedRoutes(t, fixedLearned(c, a, b))
	second, _, err := buildRouteSnapshots(&config.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("kernel dump order leaked into the snapshot:\n first=%+v\n second=%+v", first, second)
	}
}

// CANONICALISATION OF THE PREFERENCE-AWARE KEY — a defect found by mutation,
// not by review.
//
// routeDestinationForWire passes a parseable CIDR through untouched, so a
// config static written with host bits set reaches the snapshot as the literal
// "10.20.30.1/24" while the kernel always reports the masked "10.20.30.0/24".
// A raw string comparison therefore misses the configured candidate's
// preference and emits the imported route even though the config route is
// better. The canonical key must find the preference before deciding whether
// the learned candidate should be included.
//
// RED on revert: drop the canonicalRoutePrefix call in learnedRouteGapKey.
func TestGapFillMatchesANonCanonicalConfigPrefix(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.20.30.1/24", NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}}},
	}
	withLearnedRoutes(t, fixedLearned(learnedV4("10.20.30.0/24", "198.51.100.254")))

	out, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var forPrefix []RouteSnapshot
	for _, s := range out {
		if s.Table == "inet.0" && s.Family == "inet" &&
			(s.Destination == "10.20.30.1/24" || s.Destination == "10.20.30.0/24") {
			forPrefix = append(forPrefix, s)
		}
	}
	if len(forPrefix) != 1 {
		t.Fatalf("the config route must be the ONLY entry for this prefix, got %d: %+v",
			len(forPrefix), forPrefix)
	}
	if !reflect.DeepEqual(forPrefix[0].NextHops, []string{"192.0.2.1"}) {
		t.Fatalf("surviving next-hop = %v, want the operator's [192.0.2.1]",
			forPrefix[0].NextHops)
	}
}
