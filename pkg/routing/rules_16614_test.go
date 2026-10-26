package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// TestNextTableMissTerminatorInstalled16614: every admitted leak installs a
// main-table probe, target lookup, and unreachable shadow per ingress iif.
// These helper rules do not consume admission slots (100 leaks still admit).
func TestNextTableMissTerminatorInstalled16614(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	routes := []*config.StaticRoute{{Destination: "10.0.0.0/8", NextTable: "red"}}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	if err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var probes, lookups, shadows int
	for _, r := range ops.rules[unix.AF_INET] {
		switch {
		case isNextTableMainProbeShape(r):
			probes++
			if r.Table != mainTableID || r.SuppressPrefixlen != 8 ||
				r.Priority != config.RouteLeakNextTableProbePriority(8, 32) {
				t.Errorf("bad main-table probe: %+v", r)
			}
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
	if probes != 2 || lookups != 2 || shadows != 2 {
		t.Fatalf("probes=%d lookups=%d shadows=%d, want 2 of each", probes, lookups, shadows)
	}
	// Clear removes all three rules per interface (re-apply keeps count stable).
	if err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"}); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 6 {
		t.Fatalf("re-apply count=%d, want 6 (no helper-rule leak)", got)
	}
	// Empty apply removes probes and shadows as well as lookups.
	if err := nt.Apply(nil, nil, testNextTableIifs); err != nil {
		t.Fatalf("empty Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 0 {
		t.Fatalf("empty apply left %d rules, want 0", got)
	}
}
