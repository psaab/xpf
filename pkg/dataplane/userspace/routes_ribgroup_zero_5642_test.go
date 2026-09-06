package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestBuildRouteSnapshotsNoLeakAfterRuleCleared is the #5642 userspace half of
// the fix: once the synthetic rib-group leak ip-rule has been cleared from the
// kernel (the final-rib-group-removal reconcile in pkg/routing, driven by the
// daemon's now-unconditional ApplyRibGroupRules call), a rebuilt route snapshot
// carries NO NextTable leak into the (now un-leaked) instance table.
//
// This is the invariant the daemon's post-reconcile routes-only republish
// (reconcileRouteLeakSnapshot) relies on: delete the Linux ip-rule ⇒ the
// republished userspace FIB is leak-free. It complements
// TestBuildRouteSnapshotsCapturesRibGroupPerPrefixLeak (#3876), which proves the
// leak IS captured while the rule is still live — together they show the leak
// tracks the kernel ip-rule table in both directions.
func TestBuildRouteSnapshotsNoLeakAfterRuleCleared(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	// The rib-group has been removed; clear() deleted its per-prefix leak
	// rules, so the kernel ip-rule table no longer lists them.
	ruleListFn = func(family int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, r := range routes {
		if r.NextTable == "dmz-vr.inet.0" || r.NextTable == "dmz-vr.inet6.0" {
			t.Fatalf("a cleared rib-group must leave NO NextTable leak into dmz-vr, got %+v", r)
		}
	}
}
