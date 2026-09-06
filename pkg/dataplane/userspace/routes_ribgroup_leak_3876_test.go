package userspace

import (
	"net"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// mustCIDR parses a CIDR and returns the *net.IPNet, failing the test on
// error. Used to build the Dst of an injected ip rule.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil || n == nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

// TestBuildRouteSnapshotsCapturesRibGroupPerPrefixLeak is the #3876
// userspace-FIB half of the fix. The rib-group import leak now installs
// per-prefix `ip rule to <connected-prefix> lookup <sourceTable>` rules (see
// pkg/routing). Those rules carry a Dst, so the snapshot builder's existing
// (rule.Dst != nil + table→instance) loop must auto-capture them as a
// NextTable leak into the main table — putting the leak into the userspace
// FIB, not just the kernel FIB.
//
// RED-on-revert: with the pre-#3876 `from all lookup <sourceTable>` blanket
// rule (Dst==nil) the loop skips it (routes.go), so no NextTable snapshot is
// produced and the leak is absent from the userspace FIB.
func TestBuildRouteSnapshotsCapturesRibGroupPerPrefixLeak(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })

	// Per-prefix leak rules into the dmz-vr table (101): one v4, one v6.
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		switch family {
		case syscall.AF_INET:
			return []netlink.Rule{{Dst: mustCIDR(t, "10.0.30.0/24"), Table: 101, Priority: 30000}}, nil
		case syscall.AF_INET6:
			return []netlink.Rule{{Dst: mustCIDR(t, "2001:db8:30::/64"), Table: 101, Priority: 30001}}, nil
		}
		return nil, nil
	}

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	findNextTable := func(family, dest, nextTable string) bool {
		for _, r := range routes {
			if r.Table == "inet.0" && family == "inet" &&
				r.Destination == dest && r.NextTable == nextTable {
				return true
			}
			if r.Table == "inet6.0" && family == "inet6" &&
				r.Destination == dest && r.NextTable == nextTable {
				return true
			}
		}
		return false
	}

	if !findNextTable("inet", "10.0.30.0/24", "dmz-vr.inet.0") {
		t.Errorf("expected an IPv4 NextTable leak into inet.0 for 10.0.30.0/24 → dmz-vr.inet.0, routes=%+v", routes)
	}
	if !findNextTable("inet6", "2001:db8:30::/64", "dmz-vr.inet6.0") {
		t.Errorf("expected an IPv6 NextTable leak into inet6.0 for 2001:db8:30::/64 → dmz-vr.inet6.0, routes=%+v", routes)
	}
}

// TestBuildRouteSnapshotsSkipsDstlessRibGroupRule pins that a legacy
// `from all lookup <table>` (Dst==nil) rule is NOT turned into a NextTable
// leak — a whole-table fall-through cannot be represented as a per-prefix
// NextTable route, so it is correctly skipped (routes.go Dst==nil guard). The
// #3876 fix keeps that skip and relies on the per-prefix rules (which DO carry
// a Dst) instead.
func TestBuildRouteSnapshotsSkipsDstlessRibGroupRule(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family == syscall.AF_INET {
			// Legacy blanket rule: no Dst.
			return []netlink.Rule{{Table: 101, Priority: 33000}}, nil
		}
		return nil, nil
	}

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101},
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, r := range routes {
		if r.NextTable == "dmz-vr.inet.0" {
			t.Fatalf("a Dst-less blanket rule must NOT produce a NextTable leak, got %+v", r)
		}
	}
}
