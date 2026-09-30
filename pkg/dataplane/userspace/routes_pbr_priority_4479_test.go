package userspace

import (
	"net"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #4479 (opus-172 M-2): the userspace FIB snapshot must NOT ingest a
// policy-based-routing / filter-based-forwarding (FBF) ip rule as a bare
// per-prefix NextTable leak.
//
// xpf installs FBF `then routing-instance` filter actions as ip rules in the
// current PBR priority band (config.PBRRulePriorityBase, 29000-29999) carrying
// match SELECTORS — source/dest address, DSCP, protocol, source/dest port — in
// addition to a Dst that points at a routing-instance table. The synthetic
// next-table snapshot can only express a per-prefix leak, so mirroring a PBR
// rule here would DROP the selectors and widen a constrained, source-scoped
// steer into an unconditional dst-only VRF leak — the exact fail-open the
// kernel FBF path was hardened against in #3730. buildRouteSnapshots fails
// CLOSED: a current or pre-#11319 PBR-band rule is skipped and left out of the
// userspace FIB (the kernel still applies the real, fully-qualified rule).
//
// RED-on-revert: without the PBR-band skip, the loop treats ANY ip rule whose
// Dst maps to a routing-instance table as a NextTable leak, so this rule is
// ingested as `10.0.61.0/24 -> blue.inet.0` in inet.0 and the assertion fails.
func TestBuildRouteSnapshotsSkipsPBRBandRule(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })

	const tableID = 100
	_, src, err := net.ParseCIDR("10.0.61.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, dst, err := net.ParseCIDR("172.16.80.0/24")
	if err != nil {
		t.Fatal(err)
	}

	// A realistic FBF rule: source-scoped, port-scoped, Dst matching the
	// routing-instance table, at a priority inside the current PBR band.
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family == syscall.AF_INET {
			return []netlink.Rule{{
				Priority: config.PBRRulePriorityBase,
				Src:      src,
				Dst:      dst,
				Sport:    &netlink.RulePortRange{Start: 5000, End: 5001},
				Table:    tableID,
			}}, nil
		}
		return nil, nil
	}

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "blue", TableID: tableID},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, r := range routes {
		if r.NextTable == "blue.inet.0" && r.Destination == "172.16.80.0/24" {
			t.Fatalf("a PBR-band FBF rule (selectors dropped) must NOT be "+
				"ingested as a bare dst-only NextTable leak, got %+v", r)
		}
		// Nothing in this config should have produced any NextTable leak.
		if r.NextTable != "" {
			t.Fatalf("unexpected NextTable leak from a PBR-only config: %+v", r)
		}
	}
}

// TestBuildRouteSnapshotsIngestsRouteLeakBandRule pins the no-regression half:
// a genuine per-prefix route-leak-band ip rule (next-table band, priority
// config.NextTableRulePriorityBase) with a Dst matching a routing-instance
// table is STILL ingested as a NextTable leak. These rules carry a pure
// per-prefix Dst with no selectors, so mirroring them into the userspace FIB
// is correct — the PBR-band skip must not touch next-table / rib-group rules.
func TestBuildRouteSnapshotsIngestsRouteLeakBandRule(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })

	const tableID = 100
	_, dst, err := net.ParseCIDR("10.20.30.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family == syscall.AF_INET {
			// Next-table leak band: pure per-prefix Dst, no selectors.
			return []netlink.Rule{{Priority: config.NextTableRulePriorityBase, Dst: dst, Table: tableID}}, nil
		}
		return nil, nil
	}

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "blue", TableID: tableID},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	found := false
	for _, r := range routes {
		if r.Table == "inet.0" && r.Family == "inet" &&
			r.Destination == "10.20.30.0/24" && r.NextTable == "blue.inet.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("route-leak-band rule was not ingested as a NextTable leak; "+
			"the PBR-band skip must not affect the next-table band, routes=%+v", routes)
	}
}

// TestBuildRouteSnapshotsSkipsLegacyPBRBandRule pins the in-place-upgrade
// case: until the routing applier clears the former 31000-31999 PBR band, its
// selector-bearing rules must not be widened into bare helper-FIB leaks.
func TestBuildRouteSnapshotsSkipsLegacyPBRBandRule(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })

	const tableID = 100
	_, dst, err := net.ParseCIDR("10.20.30.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family == syscall.AF_INET {
			return []netlink.Rule{{
				Priority: config.LegacyPBRRulePriorityBase,
				Src:      mustPrefix11319(t, "192.0.2.0/24"),
				Dst:      dst,
				Table:    tableID,
			}}, nil
		}
		return nil, nil
	}
	cfg := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{
		{Name: "blue", TableID: tableID},
	}}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, route := range routes {
		if route.Table == "inet.0" && route.Family == "inet" &&
			route.Destination == dst.String() && route.NextTable == "blue.inet.0" {
			t.Fatalf("legacy selector-bearing PBR rule widened into a helper leak: %+v", route)
		}
	}
}

func mustPrefix11319(t *testing.T, raw string) *net.IPNet {
	t.Helper()
	_, prefix, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", raw, err)
	}
	return prefix
}
