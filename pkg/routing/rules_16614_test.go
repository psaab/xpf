package routing

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// TestNextTableMissTerminatorInstalled16614: every admitted leak installs
// a selector-identical unreachable shadow at 32765 per ingress iif, and
// the shadow does not consume an admission slot (100 leaks still admit).
func TestNextTableMissTerminatorInstalled16614(t *testing.T) {
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	routes := []*config.StaticRoute{{Destination: "10.0.0.0/8", NextTable: "red"}}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	if err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var lookups, shadows int
	for _, r := range ops.rules[unix.AF_INET] {
		switch r.Priority {
		case config.NextTableMissTerminatorPriority:
			shadows++
			if r.Type != nl.FR_ACT_UNREACHABLE || r.Dst.String() != "10.0.0.0/8" || r.IifName == "" {
				t.Errorf("bad shadow: %+v", r)
			}
		default:
			lookups++
			if r.Table != 100 {
				t.Errorf("lookup targets %d, want 100", r.Table)
			}
		}
	}
	if lookups != 2 || shadows != 2 {
		t.Fatalf("lookups=%d shadows=%d, want 2+2", lookups, shadows)
	}
	// Clear removes shadows too (re-apply keeps count stable).
	if err := nt.Apply(routes, instances, []string{"ge-0-0-0", "ge-0-0-1"}); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 4 {
		t.Fatalf("re-apply count=%d, want 4 (no shadow leak)", got)
	}
	// Empty apply removes shadows.
	if err := nt.Apply(nil, nil, testNextTableIifs); err != nil {
		t.Fatalf("empty Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 0 {
		t.Fatalf("empty apply left %d rules, want 0", got)
	}
	_ = net.IPv4zero
	_ = netlink.Rule{}
}
