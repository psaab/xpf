package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestBuildRouteSnapshotsSurfacesRuleListError verifies #3772 M9: a
// netlink RuleList failure is SURFACED as a build error, not swallowed.
// Swallowing it dropped every route-leak (rib-group / next-table)
// snapshot for that family while the kernel/FRR leak path stayed up,
// diverging the userspace FIB with no signal. On revert (the old
// `if err != nil { continue }`) buildRouteSnapshots returns a nil error
// and a partial snapshot.
func TestBuildRouteSnapshotsSurfacesRuleListError(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) {
		return nil, errors.New("simulated netlink RuleList failure")
	}

	cfg := &config.Config{}
	if _, _, err := buildRouteSnapshots(cfg, nil, nil); err == nil {
		t.Fatal("buildRouteSnapshots swallowed a RuleList failure; want a surfaced error")
	}
}

// TestBuildRouteSnapshotsRuleListSuccessNoError confirms the happy path
// still returns a nil error when the ip-rule enumeration succeeds.
func TestBuildRouteSnapshotsRuleListSuccessNoError(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.0.0.0/8", NextHops: []config.NextHopEntry{{Address: "10.1.1.1"}}},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("len(routes) = %d, want 1", len(routes))
	}
}

// TestCanonicalRoutePrefixEmptyOnUnparseable verifies #3772 M8: the
// function returns "" for an unparseable prefix (matching its doc
// comment and the caller's skip guard) and the canonical string for a
// valid CIDR.
func TestCanonicalRoutePrefixEmptyOnUnparseable(t *testing.T) {
	if got := canonicalRoutePrefix("not-a-cidr"); got != "" {
		t.Fatalf("canonicalRoutePrefix(bad) = %q, want \"\"", got)
	}
	if got := canonicalRoutePrefix("10.0.0.5/24"); got != "10.0.0.0/24" {
		t.Fatalf("canonicalRoutePrefix(10.0.0.5/24) = %q, want 10.0.0.0/24", got)
	}
}

// TestRouteOverlaySkipsUnparseableDestination verifies #3772 M8 end to
// end: a malformed overlay destination is SKIPPED rather than injected
// into the FIB as a garbage prefix. On revert (canonicalRoutePrefix
// returns the raw string) the "garbage" destination enters the overlay
// map and appears as a synthetic route.
func TestRouteOverlaySkipsUnparseableDestination(t *testing.T) {
	cfg := &config.Config{}
	overlay := []config.RouteOverlayEntry{
		{Destination: "garbage", NextHop: "1.2.3.4", Policy: "p"},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, overlay)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.Destination == "garbage" {
			t.Fatalf("unparseable overlay destination entered the FIB: %+v", r)
		}
	}
}
