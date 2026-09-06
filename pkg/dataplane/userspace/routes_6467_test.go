package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestBuildRouteSnapshotsCapsConfigStaticNextTableLeaks is the #6467 FIB-side
// fail-on-revert guard. The userspace FIB derives next-table leaks from BOTH the
// kernel ip-rule dump (naturally capped at config.NextTableRuleWindow because
// the applier installs at most that many) AND the config static routes. Before
// #6467 the config-static path was UNCAPPED, so a config with >100 global
// next-table routes published leak #101+ into the userspace FIB even though the
// kernel dropped it — a slow-path packet matching leak #101+ then resolved into
// the target VRF on the AF_XDP fast path but the main table in the kernel.
//
// This test isolates the config-static path (ruleListFn returns no kernel rules)
// and asserts the FIB never publishes more next-table leaks than the kernel cap.
//
// RED-on-revert: removing the config.NextTableRuleWindow cap in the
// buildRouteSnapshots config-static path publishes all 150 leaks, so the
// `leaks > config.NextTableRuleWindow` assertion fails.
func TestBuildRouteSnapshotsCapsConfigStaticNextTableLeaks(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	// Isolate the config-static next-table path: no kernel ip-rules to ingest.
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	const over = 50
	const n = config.NextTableRuleWindow + over // 150 global next-table routes

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < n; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
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
	if leaks > config.NextTableRuleWindow {
		t.Fatalf("userspace FIB published %d config-static next-table leaks, exceeding "+
			"the kernel cap of %d — leak #%d+ resolves into the target VRF on the fast "+
			"path but the main table in the kernel (#6467)",
			leaks, config.NextTableRuleWindow, config.NextTableRuleWindow+1)
	}
	// The cap must truncate at exactly the window, not drop everything.
	if leaks != config.NextTableRuleWindow {
		t.Fatalf("expected exactly %d next-table leaks at the cap, got %d",
			config.NextTableRuleWindow, leaks)
	}
}

// TestBuildRouteSnapshotsUncappedBelowWindow is the companion no-regression
// guard: a config with FEWER than the window's worth of global next-table routes
// publishes every one (the #6467 cap only truncates genuine over-subscription).
func TestBuildRouteSnapshotsUncappedBelowWindow(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	const n = 10 // well under config.NextTableRuleWindow
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	for i := 0; i < n; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.0.0/16", i),
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
	if leaks != n {
		t.Fatalf("expected all %d next-table leaks published below the cap, got %d", n, leaks)
	}
}

// TestBuildRouteSnapshotsFIBEligibilityMirrorsApplier is the #6467-fold
// fail-on-revert guard. The FIB window counter/publisher must apply the SAME
// eligibility the applier does: the applier (pkg/routing nextTableManager.Apply)
// SKIPS a next-table route whose target instance is unknown (`tableIDs` miss) or
// whose destination fails net.ParseCIDR — no prio++, no ip rule, no window slot
// consumed. Before the fold the FIB counted AND published EVERY global
// next-table route, so M dangling routes before the boundary consumed M window
// slots and published M ghost leaks the kernel never installs — squeezing M
// valid leaks out of the window (FIB missing valid leaks the kernel HAS while
// carrying ghosts the kernel LACKS).
//
// Canonical case: M dangling (unknown-instance) routes BEFORE N valid routes
// that exceed the window. The FIB's published next-table set must equal the
// valid set the applier installs — ZERO ghost entries, and the FULL window of
// valid leaks present (not squeezed out by ghosts eating the budget).
//
// RED-on-revert: dropping the definedInstances eligibility skip in
// buildRouteSnapshots makes the FIB publish 50 ghost + only 50 valid (the ghosts
// eat half the window), so BOTH assertions fail with a clean message.
func TestBuildRouteSnapshotsFIBEligibilityMirrorsApplier(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	// Isolate the config-static path: the kernel-dump path publishes only what
	// the kernel actually holds (valid rules), so no ghosts arrive from there.
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	const ghosts = 50                             // dangling: target instance NOT defined
	const valid = config.NextTableRuleWindow + 20 // exceeds the window, so the cap fires on valid routes

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	// M dangling next-table routes BEFORE the boundary (unknown instance).
	for i := 0; i < ghosts; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("172.16.%d.0/24", i),
				NextTable:   "ghost-vr", // NOT a defined RoutingInstance
			})
	}
	// N valid next-table routes exceeding the window.
	for i := 0; i < valid; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "blue",
			})
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	ghostLeaks, validLeaks := 0, 0
	for _, r := range routes {
		switch r.NextTable {
		case "ghost-vr":
			ghostLeaks++
		case "blue":
			validLeaks++
		}
	}
	// The applier skips dangling targets (tableIDs miss, no prio++), so the
	// kernel installs ZERO ghost leaks. The FIB must match — no ghost snapshots.
	if ghostLeaks != 0 {
		t.Errorf("FIB published %d ghost next-table leaks (dangling instance) the "+
			"kernel never installs — the FIB must mirror the applier's eligibility (#6467)", ghostLeaks)
	}
	// The ghosts consume NO window slot, so the full window of valid leaks is
	// present (not squeezed out). N > window, so exactly the window's worth.
	if validLeaks != config.NextTableRuleWindow {
		t.Errorf("FIB published %d valid next-table leaks, want %d — dangling routes "+
			"must not consume window slots and squeeze out valid leaks the kernel "+
			"installs (#6467)", validLeaks, config.NextTableRuleWindow)
	}
}

// TestBuildRouteSnapshotsSkipsMalformedCIDRNextTable binds the SECOND half of
// the FIB eligibility gate: a next-table route whose target instance IS defined
// but whose destination fails net.ParseCIDR must be skipped — the applier's
// top-of-loop net.ParseCIDR gate `continue`s such a route (no ip rule), so the
// FIB must not publish it either. The sibling ghost test only feeds parseable
// destinations, so without this the net.ParseCIDR half of the gate is unbound
// (removing it would leave that test green).
//
// RED-on-revert: removing ONLY the net.ParseCIDR check in the buildRouteSnapshots
// config-static eligibility gate makes the malformed routes publish, so this
// assertion fires.
func TestBuildRouteSnapshotsSkipsMalformedCIDRNextTable(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: 100}}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.1.0.0/16", NextTable: "blue"}, // valid → published
		{Destination: "not-a-cidr", NextTable: "blue"},  // DEFINED instance, UNPARSEABLE
		{Destination: "10.2.0.0/99", NextTable: "blue"}, // DEFINED instance, out-of-range mask
		{Destination: "10.3.0.0/16", NextTable: "blue"}, // valid → published
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, r := range routes {
		if r.NextTable == "blue" && (r.Destination == "not-a-cidr" || r.Destination == "10.2.0.0/99") {
			t.Errorf("FIB published a next-table leak with an unparseable destination %q — "+
				"the applier's net.ParseCIDR gate skips it (no ip rule), so the FIB must too (#6467)",
				r.Destination)
		}
	}
	// The two well-formed routes must STILL publish (no over-suppression).
	valid := 0
	for _, r := range routes {
		if r.NextTable == "blue" && (r.Destination == "10.1.0.0/16" || r.Destination == "10.3.0.0/16") {
			valid++
		}
	}
	if valid != 2 {
		t.Errorf("both well-formed next-table leaks must still publish, got %d", valid)
	}
}
