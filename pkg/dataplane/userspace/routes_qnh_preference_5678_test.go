package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #5678: a static route's qualified-next-hop PREFERENCE (the Junos
// floating-static idiom — a primary next-hop plus a less-preferred backup)
// was dropped when the route was lowered into the AF_XDP snapshot. The
// lowering collapsed every next-hop onto ONE RouteSnapshot at the single
// route-level preference, so the backup was installed at EQUAL cost to the
// primary and the Rust FIB load-balanced (ECMP) across BOTH instead of using
// the backup only as a standby.
//
// The fix groups next-hops by their EFFECTIVE preference (per-next-hop when
// HasPreference, else route-level) and emits one RouteSnapshot per distinct
// preference. The Rust FIB tie-breaks same-prefix routes by preference (#2390)
// and first-match-selects the lowest, holding the higher-preference backup as
// a standby entry.
//
// FAIL-ON-REVERT: revert the preference-carry (collapse both next-hops onto one
// route-level-preference snapshot) and the primary + backup become a single
// equal-cost ECMP snapshot — this test then fails (two distinct-preference
// snapshots are no longer produced).
func TestQualifiedNextHopPreferenceLowersAsDistinctStandby_5678(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{
			Destination: "10.5.0.0/16",
			Preference:  5, // route-level distance for the primary next-hop
			NextHops: []config.NextHopEntry{
				// Primary: plain next-hop → route-level preference (5).
				{Address: "10.0.0.1"},
				// Backup: qualified-next-hop preference 250 (a floating
				// standby, per #3871).
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
			},
		},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	// Collect the snapshots for this prefix.
	var primary, backup *RouteSnapshot
	other := 0
	for i := range routes {
		r := &routes[i]
		if r.Destination != "10.5.0.0/16" {
			other++
			continue
		}
		switch {
		case len(r.NextHops) == 1 && r.NextHops[0] == "10.0.0.1":
			primary = r
		case len(r.NextHops) == 1 && r.NextHops[0] == "10.0.0.2":
			backup = r
		}
	}
	if other != 0 {
		t.Fatalf("unexpected extra snapshots for other prefixes: %d (routes=%+v)", other, routes)
	}

	// The floating static must lower as TWO snapshots, one per next-hop, at
	// DISTINCT preferences — NOT a single ECMP snapshot carrying both.
	if primary == nil || backup == nil {
		t.Fatalf("want a separate primary(10.0.0.1) and backup(10.0.0.2) snapshot; "+
			"the backup was folded into an equal-cost ECMP member with the primary. routes=%+v", routes)
	}
	if primary.Preference != 5 {
		t.Fatalf("primary preference = %d, want 5 (route-level)", primary.Preference)
	}
	if backup.Preference != 250 {
		t.Fatalf("backup preference = %d, want 250 (qualified-next-hop distance)", backup.Preference)
	}
	// The backup must be STRICTLY less-preferred (higher admin distance) than
	// the primary — a standby, not a co-equal ECMP member.
	if backup.Preference <= primary.Preference {
		t.Fatalf("backup preference %d must be strictly higher (less preferred) than primary %d",
			backup.Preference, primary.Preference)
	}
	// Neither snapshot may carry the OTHER tier's next-hop: proves the two are
	// not an equal-cost ECMP pair.
	for _, r := range []*RouteSnapshot{primary, backup} {
		if len(r.NextHops) != 1 {
			t.Fatalf("snapshot %+v has %d next-hops, want exactly 1 (no ECMP across tiers)", r, len(r.NextHops))
		}
	}
}

// #5678 no-regression: a route with genuinely equal next-hops (a plain
// `next-hop [ a b ]` list, no qualified preference) must still lower to a
// SINGLE equal-cost ECMP snapshot carrying both next-hops.
func TestPlainNextHopListStaysECMP_5678(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{
			Destination: "10.6.0.0/16",
			Preference:  5,
			NextHops: []config.NextHopEntry{
				{Address: "10.0.0.1"},
				{Address: "10.0.0.2"},
			},
		},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	var matches []RouteSnapshot
	for _, r := range routes {
		if r.Destination == "10.6.0.0/16" {
			matches = append(matches, r)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("plain next-hop list lowered to %d snapshots, want 1 ECMP snapshot: %+v", len(matches), matches)
	}
	got := matches[0]
	if len(got.NextHops) != 2 {
		t.Fatalf("ECMP snapshot has %d next-hops, want 2: %+v", len(got.NextHops), got)
	}
	if got.NextHops[0] != "10.0.0.1" || got.NextHops[1] != "10.0.0.2" {
		t.Fatalf("ECMP next-hops = %v, want [10.0.0.1 10.0.0.2]", got.NextHops)
	}
	if got.Preference != 5 {
		t.Fatalf("ECMP preference = %d, want 5", got.Preference)
	}
}

// #5678: two qualified next-hops at the SAME distance are still ECMP with each
// other (they share a preference group), but a third at a distinct distance is
// a separate standby. Guards the grouping (by preference, not per-next-hop).
func TestQualifiedNextHopsSamePreferenceGroupECMP_5678(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{
			Destination: "10.7.0.0/16",
			Preference:  5,
			NextHops: []config.NextHopEntry{
				{Address: "10.0.0.1", Preference: 10, HasPreference: true},
				{Address: "10.0.0.2", Preference: 10, HasPreference: true},
				{Address: "10.0.0.3", Preference: 250, HasPreference: true},
			},
		},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	byPref := map[int][]string{}
	for _, r := range routes {
		if r.Destination != "10.7.0.0/16" {
			continue
		}
		byPref[r.Preference] = r.NextHops
	}
	if len(byPref) != 2 {
		t.Fatalf("want 2 preference groups, got %d: %+v", len(byPref), byPref)
	}
	if nh := byPref[10]; len(nh) != 2 || nh[0] != "10.0.0.1" || nh[1] != "10.0.0.2" {
		t.Fatalf("preference-10 group = %v, want ECMP [10.0.0.1 10.0.0.2]", nh)
	}
	if nh := byPref[250]; len(nh) != 1 || nh[0] != "10.0.0.3" {
		t.Fatalf("preference-250 group = %v, want standby [10.0.0.3]", nh)
	}
}
