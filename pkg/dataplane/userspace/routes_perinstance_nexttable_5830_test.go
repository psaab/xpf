package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestBuildRouteSnapshotsDropsPerInstanceNextTable_5830 proves the userspace
// half of the #5830 fix: a `next-table` authored UNDER a routing-instance is
// NOT published as a live NextTable route in the instance's FIB table.
//
// Before the fix, buildRouteSnapshots copied every per-instance static route's
// NextTable into the helper snapshot, so the userspace dataplane leaked traffic
// the kernel/FRR forwarding plane never routes (daemon_apply feeds only global
// statics to ApplyNextTableRules, and the FRR renderer emits nothing for a
// NextTable route) — a control-plane/data-plane split-brain. Dropping the
// per-instance next-table makes both planes agree the route is ABSENT.
//
// FAIL-ON-REVERT: restoring the userspace-only publication (removing the
// `perInstance && route.NextTable != ""` skip in addRoutes) re-adds the
// NextTable snapshot into <inst>.inet.0 / <inst>.inet6.0, so the assertions
// below fire RED.
func TestBuildRouteSnapshotsDropsPerInstanceNextTable_5830(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	// Per-instance next-table is never programmed as a kernel ip-rule, so the
	// live rule table lists nothing for it.
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name:    "leaker",
			TableID: 101,
			StaticRoutes: []*config.StaticRoute{
				// The divergent case: a per-instance next-table leak.
				{Destination: "10.0.0.0/8", NextTable: "target", NextTableRaw: "target.inet.0"},
				// A legitimate per-instance forwarding route MUST still publish —
				// the fix drops only next-table, not the whole instance route set.
				{Destination: "192.0.2.0/24", NextHops: []config.NextHopEntry{{Address: "10.9.9.1"}}},
			},
			Inet6StaticRoutes: []*config.StaticRoute{
				{Destination: "2001:db8::/32", NextTable: "target", NextTableRaw: "target.inet6.0"},
			},
		},
		{Name: "target", TableID: 102},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	sawForwarding := false
	for _, r := range routes {
		if r.NextTable != "" {
			t.Fatalf("no per-instance next-table must be published, got %+v", r)
		}
		if r.Table == "leaker.inet.0" && r.Destination == "192.0.2.0/24" {
			sawForwarding = true
		}
	}
	if !sawForwarding {
		t.Fatal("a per-instance FORWARDING route must still be published; the fix must drop only next-table, not the whole instance route set")
	}
}

// TestBuildRouteSnapshotsKeepsGlobalNextTable_5830 guards against regression: a
// GLOBAL routing-options next-table IS programmed on the kernel (via ip rule)
// and MUST stay published in the userspace snapshot so the Rust FIB can
// cross-reference the target table. The #5830 fix drops ONLY per-instance
// next-table.
func TestBuildRouteSnapshotsKeepsGlobalNextTable_5830(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextTable: "Comcast", NextTableRaw: "Comcast.inet.0"},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "Comcast", TableID: 201},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	found := false
	for _, r := range routes {
		if r.Table == "inet.0" && r.Destination == "0.0.0.0/0" && r.NextTable == "Comcast" {
			found = true
		}
	}
	if !found {
		t.Fatal("a GLOBAL next-table route must remain published in the userspace snapshot")
	}
}
