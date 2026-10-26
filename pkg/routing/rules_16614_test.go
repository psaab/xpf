package routing

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// TestNextTableMissTerminatorInstalled16614: every admitted leak installs a
// target lookup and unreachable shadow per ingress iif. These helper rules do
// not consume admission slots (100 leaks still admit).
func TestNextTableMissTerminatorInstalled16614(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	routes := []*config.StaticRoute{{Destination: "10.0.0.0/8", NextTable: "red"}}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	if err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var legacyProbes, lookups, shadows int
	for _, r := range ops.rules[unix.AF_INET] {
		switch {
		case isNextTableLegacyMainProbeShape(r):
			legacyProbes++
		case isNextTableMissTerminatorShape(r):
			shadows++
			if r.Type != nl.FR_ACT_UNREACHABLE || r.Dst.String() != "10.0.0.0/8" || r.IifName == "" ||
				r.Priority != config.RouteLeakNextTableShadowPriority(8, 32) {
				t.Errorf("bad shadow: %+v", r)
			}
		default:
			lookups++
			if r.Table != 100 || r.Priority != config.RouteLeakNextTableLookupPriority(8, 32) {
				t.Errorf("bad target lookup: %+v", r)
			}
		}
	}
	if legacyProbes != 0 || lookups != 2 || shadows != 2 {
		t.Fatalf("legacy probes=%d lookups=%d shadows=%d, want 0, 2, 2", legacyProbes, lookups, shadows)
	}
	// Clear removes both rules per interface (re-apply keeps count stable).
	if err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"}); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 4 {
		t.Fatalf("re-apply count=%d, want 4 (no helper-rule leak)", got)
	}
	// Empty apply removes shadows as well as lookups.
	if err := nt.Apply(nil, nil, testNextTableIifs); err != nil {
		t.Fatalf("empty Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 0 {
		t.Fatalf("empty apply left %d rules, want 0", got)
	}
}

func TestNextTableStaticMainCarveouts17970(t *testing.T) {
	routes := []*config.StaticRoute{
		{Destination: "10.0.0.0/8", NextTable: "red"},
		{Destination: "10.1.0.0/16", Discard: true},
		{Destination: "10.2.0.0/16", NoInstall: true},
		{Destination: "0.0.0.0/0", Discard: true},
		{Destination: "2001:db8::/32", NextTable: "red"},
		{Destination: "2001:db8:1::/48", Reject: true},
		{Destination: "::/0", Reject: true},
		{Destination: "192.0.2.0/24", NextTable: "unknown"},
	}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	iifs := []string{"xwan", "xwan2"}
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	if err := nt.Apply(routes, instances, iifs); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	want := map[string]int{
		"10.1.0.0/16|xwan":      config.RouteLeakNextTableCarveoutPriority(16, 32),
		"10.1.0.0/16|xwan2":     config.RouteLeakNextTableCarveoutPriority(16, 32),
		"2001:db8:1::/48|xwan":  config.RouteLeakNextTableCarveoutPriority(48, 128),
		"2001:db8:1::/48|xwan2": config.RouteLeakNextTableCarveoutPriority(48, 128),
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, rule := range ops.rules[family] {
			if isNextTableLegacyMainProbeShape(rule) {
				t.Errorf("Apply emitted a suppress-prefixlen probe: %+v", rule)
			}
			if !isNextTableMainCarveoutShape(rule) {
				continue
			}
			key := rule.Dst.String() + "|" + rule.IifName
			priority, ok := want[key]
			if !ok {
				t.Errorf("unexpected static main-table carve-out: %+v", rule)
				continue
			}
			if rule.Table != mainTableID || rule.Priority != priority || rule.SuppressPrefixlen != -1 {
				t.Errorf("bad static main-table carve-out: %+v", rule)
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing configured static main-table carve-outs: %v", want)
	}

	// The rib-group owner only clears its unscoped destination rules; it must
	// leave the iif-scoped main carve-outs untouched.
	if err := (&ribGroupManager{ops: ops}).clear(); err != nil {
		t.Fatalf("rib-group clear: %v", err)
	}
	carveouts := 0
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, rule := range ops.rules[family] {
			if isNextTableMainCarveoutShape(rule) {
				carveouts++
			}
		}
	}
	if carveouts != 4 {
		t.Fatalf("rib-group clear removed or changed scoped carve-outs: got %d, want 4", carveouts)
	}

	// Stale pre-fix probes remain identifiable for upgrade cleanup, and clear
	// also removes the current slot-0 exception shape.
	_, oldDst, _ := net.ParseCIDR("10.0.0.0/8")
	oldProbe := netlink.NewRule()
	oldProbe.Dst = oldDst
	oldProbe.Table = mainTableID
	oldProbe.SuppressPrefixlen = 8
	oldProbe.Priority = config.RouteLeakNextTableCarveoutPriority(8, 32)
	oldProbe.Family = unix.AF_INET
	oldProbe.IifName = "xwan"
	if err := ops.RuleAdd(oldProbe); err != nil {
		t.Fatalf("inject stale probe: %v", err)
	}
	if err := nt.Apply(nil, nil, iifs); err != nil {
		t.Fatalf("empty Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 0 {
		t.Fatalf("clear left %d current/stale next-table rules", got)
	}
}
