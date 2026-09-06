package userspace

import (
	"net"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #3768 (H6): the synthetic ip-rule route-leak snapshots must derive the
// next-table name from the ROUTE's address family. An IPv6 leak into a
// routing-instance targets "<inst>.inet6.0" (the v6 table the Rust FIB
// keys routes_v6 by); an IPv4 leak targets "<inst>.inet.0". The pre-fix
// emitter built "<inst>.inet.0" once and reused it for the v6 pass, so a
// leaked IPv6 route pointed at the instance's IPv4 table -> the v6
// recursion missed -> the leak blackholed.
//
// This test installs a routing-instance and an ip-rule per family (the
// kernel/FRR leak mirror) and asserts each family's leak snapshot carries
// the correct main table, family, and next-table. On revert the v6
// next-table is emitted as "blue.inet.0" and the v6 assertion fails RED
// while the v4 assertion still passes (no regression).
func TestIPRuleLeakNextTablePerFamily(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })

	const tableID = 100
	_, v4Dst, err := net.ParseCIDR("10.20.30.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, v6Dst, err := net.ParseCIDR("2001:db8:1::/48")
	if err != nil {
		t.Fatal(err)
	}
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		switch family {
		case syscall.AF_INET:
			return []netlink.Rule{{Dst: v4Dst, Table: tableID}}, nil
		case syscall.AF_INET6:
			return []netlink.Rule{{Dst: v6Dst, Table: tableID}}, nil
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

	var v4Leak, v6Leak *RouteSnapshot
	for i := range routes {
		r := &routes[i]
		if r.NextTable == "" {
			continue
		}
		switch r.Destination {
		case "10.20.30.0/24":
			v4Leak = r
		case "2001:db8:1::/48":
			v6Leak = r
		}
	}

	if v4Leak == nil {
		t.Fatal("no IPv4 ip-rule leak snapshot emitted")
	}
	if v4Leak.Table != "inet.0" || v4Leak.Family != "inet" || v4Leak.NextTable != "blue.inet.0" {
		t.Fatalf("v4 leak = %+v, want Table=inet.0 Family=inet NextTable=blue.inet.0", *v4Leak)
	}

	if v6Leak == nil {
		t.Fatal("no IPv6 ip-rule leak snapshot emitted")
	}
	// The RED-on-revert assertion: pre-#3768 this was "blue.inet.0".
	if v6Leak.Table != "inet6.0" || v6Leak.Family != "inet6" || v6Leak.NextTable != "blue.inet6.0" {
		t.Fatalf("v6 leak = %+v, want Table=inet6.0 Family=inet6 NextTable=blue.inet6.0 "+
			"(pre-#3768 H6 emitted NextTable=blue.inet.0 -> Rust routes_v6 miss -> blackhole)", *v6Leak)
	}
}
