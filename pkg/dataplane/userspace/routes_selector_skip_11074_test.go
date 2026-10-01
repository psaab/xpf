package userspace

import (
	"net"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #11074: the FIB mirror can only represent destination-only route leaks. A
// kernel rule carrying an ingress selector must not be widened into an
// unconditional next-table route.
//
// RED-on-revert: the pre-fix mirror copies any matching Dst/Table pair, so this
// selector-bearing rule becomes a bare `10.74.0.0/16 -> blue` leak.
func TestBuildRouteSnapshotsSkipsSelectorCarryingIpRule_11074(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })

	const tableID = 100
	_, dst, err := net.ParseCIDR("10.74.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family == syscall.AF_INET {
			return []netlink.Rule{{
				Priority: config.NextTableRulePriorityBase,
				Dst:      dst,
				IifName:  "eth0",
				Table:    tableID,
			}}, nil
		}
		return nil, nil
	}

	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{Name: "blue", TableID: tableID}},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, route := range routes {
		if route.NextTable != "" {
			t.Fatalf("selector-bearing ip rule widened into a next-table route: %+v", route)
		}
	}
}
