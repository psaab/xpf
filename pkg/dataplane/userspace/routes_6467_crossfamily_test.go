package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #6467 cross-family cap binding.
//
// The kernel programs global next-table leaks as ip rules from a SINGLE shared
// priority counter. Note where each half of that invariant actually lives:
// pkg/routing nextTableManager.Apply has NO family loop — it walks one flat
// []*config.StaticRoute, derives the family per route from the destination
// CIDR, and advances one `prio` across the whole slice against a family-blind
// cap. The v4-before-v6 ORDER is established by the caller, which concatenates
// the v4 statics then the v6 statics into that one slice:
//
//	pkg/daemon/daemon_apply_routing.go
//	  allRoutes = append(allRoutes, cfg.RoutingOptions.StaticRoutes...)      // v4 FIRST
//	  allRoutes = append(allRoutes, cfg.RoutingOptions.Inet6StaticRoutes...) // v6 SECOND
//
// So the 100-entry window is shared, not per-family, and it is drawn down
// v4-first. buildRouteSnapshots mirrors that by declaring
// `nextTableLeakCount` OUTSIDE the addRoutes closure (routes.go), so the two
// global calls — inet then inet6 — draw down the same budget.
//
// Every pre-existing #6467 fixture is v4-ONLY, so that shared-ness was never
// bound: moving `nextTableLeakCount := 0` into the addRoutes closure (making
// the window per-call) leaves the ENTIRE package green while a 60 v4 + 60 v6
// config publishes 120 FIB leaks against the kernel's 100 — the #6467
// kernel/dataplane verdict split silently restored in its cross-family form.
//
// This test is that missing binding. Note it asserts the per-family SPLIT
// (60 inet + 40 inet6), not merely a total of 100: a total-only assertion is
// also satisfied by a 50/50 split, which the kernel would never produce because
// it fills v4 first.
func TestBuildRouteSnapshotsNextTableCapIsSharedAcrossFamilies_6467(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	// Isolate the config-static next-table path: no kernel ip-rules to ingest.
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	// 60 + 60 straddles the 100-entry window: v4 fits entirely, v6 is truncated
	// to the remainder. Both counts are below the window on their own, so a
	// per-family counter would publish all 120 and cap neither.
	const v4Count = 60
	const v6Count = 60
	const wantV4 = v4Count                              // 60 — fits, filled first
	const wantV6 = config.NextTableRuleWindow - v4Count // 40 — the remainder

	// Straddle precondition. v4Count/v6Count are literals while the window is an
	// SSOT that types_system.go explicitly invites tuning. If the window ever
	// moves past v4Count+v6Count, NOTHING is capped, wantV6 collapses to v6Count,
	// and every assertion below becomes a tautology that passes even with the
	// per-family-counter regression applied — the test would lose 100% of its
	// mutation sensitivity SILENTLY, while staying green. Fail loudly instead.
	if v4Count+v6Count <= config.NextTableRuleWindow || v4Count >= config.NextTableRuleWindow {
		t.Fatalf("fixture no longer straddles the next-table window (%d): %d v4 + %d v6. "+
			"Re-derive the counts from config.NextTableRuleWindow so this test keeps "+
			"exercising the cap instead of silently asserting nothing",
			config.NextTableRuleWindow, v4Count, v6Count)
	}

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < v4Count; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "blue",
			})
	}
	for i := 0; i < v6Count; i++ {
		cfg.RoutingOptions.Inet6StaticRoutes = append(cfg.RoutingOptions.Inet6StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("2001:db8:%x::/48", i),
				NextTable:   "blue",
			})
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	var gotV4, gotV6 int
	for _, r := range routes {
		if r.NextTable != "blue" {
			continue
		}
		switch r.Family {
		case "inet":
			gotV4++
		case "inet6":
			gotV6++
		default:
			t.Fatalf("unexpected family %q on a next-table leak", r.Family)
		}
	}

	if total := gotV4 + gotV6; total != config.NextTableRuleWindow {
		t.Fatalf("the next-table window is SHARED across families: %d v4 + %d v6 routes must "+
			"publish exactly %d FIB leaks, got %d (%d inet + %d inet6). A per-family counter "+
			"publishes all %d and re-opens the #6467 kernel/dataplane verdict split — leak "+
			"#%d+ resolves into the target VRF on the AF_XDP fast path while a slow-path "+
			"packet resolves in the main table",
			v4Count, v6Count, config.NextTableRuleWindow, total, gotV4, gotV6,
			v4Count+v6Count, config.NextTableRuleWindow+1)
	}
	// The SPLIT, not just the total. The kernel fills v4 first and then spends
	// what remains on v6, so a 50/50 split would also total 100 while diverging
	// from what the kernel actually installs.
	if gotV4 != wantV4 || gotV6 != wantV6 {
		t.Fatalf("shared window must be drawn down v4-first like the kernel applier "+
			"(pkg/daemon/daemon_apply_routing.go concatenates v4 statics then v6 statics "+
			"into ONE slice; pkg/routing nextTableManager.Apply walks it on a single "+
			"family-blind prio counter): want %d inet + %d inet6, got %d inet + %d inet6",
			wantV4, wantV6, gotV4, gotV6)
	}
}

// TestBuildRouteSnapshotsV6OnlyNextTableCapped_6467 documents the mirror case
// the v4-only fixtures also leave unbound: a v6-only over-window config must be
// capped too.
//
// Honest accounting of its value: it is SUBSUMED by the cross-family test above
// for every mutation tried (counter-inside-closure, cap-only-first-call,
// cap-v4-leg-only, cap-v6-leg-only, off-by-one) — no mutation was found that
// this catches and the cross-family test misses. It is kept for two reasons
// that are not mutation coverage: it runs in 0.00s, and unlike its sibling it
// derives its fixture size from config.NextTableRuleWindow, so it stays
// sensitive at ANY window value rather than depending on a straddle
// precondition.
func TestBuildRouteSnapshotsV6OnlyNextTableCapped_6467(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	const n = config.NextTableRuleWindow + 50

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < n; i++ {
		cfg.RoutingOptions.Inet6StaticRoutes = append(cfg.RoutingOptions.Inet6StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("2001:db8:%x::/48", i),
				NextTable:   "blue",
			})
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	leaks := 0
	for _, r := range routes {
		if r.NextTable == "blue" {
			leaks++
		}
	}
	if leaks != config.NextTableRuleWindow {
		t.Fatalf("a v6-only over-window next-table config must cap at exactly %d leaks like "+
			"its v4 twin, got %d", config.NextTableRuleWindow, leaks)
	}
}
