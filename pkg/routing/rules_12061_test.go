package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

func TestManagementInterfacesDoNotGetNextTableIngressRules_12061(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	for _, name := range []string{"ge-0/0/1", "ge-0/0/2", "fxp0", "em0", "fab0"} {
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{
			Name:  name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		}
	}
	instances := []*config.RoutingInstanceConfig{{Name: "vrf-a", TableID: 100}}
	ops := newFakeRuleOps()
	manager := &nextTableManager{ops: ops}
	if err := manager.Apply(
		[]*config.StaticRoute{{Destination: "10.0.0.0/24", NextTable: "vrf-a"}},
		instances,
		DefaultInstanceIngressIfaces(cfg),
	); err != nil {
		t.Fatalf("apply next-table rules: %v", err)
	}

	got := map[string]int{}
	count := 0
	for _, familyRules := range ops.rules {
		for _, rule := range familyRules {
			count++
			got[rule.IifName]++
		}
	}
	want := map[string]bool{"ge-0-0-1": true, "ge-0-0-2": true}
	if count != 2*len(want) || len(got) != len(want) {
		t.Fatalf("installed %d rules for ingress ifnames %v; want 2 each for only %v", count, got, want)
	}
	for iif := range want {
		if got[iif] != 2 {
			t.Errorf("ordinary ingress %q received %d rules, want lookup+shadow", iif, got[iif])
		}
	}
	for iif := range got {
		if config.IsManagementIfName(iif) {
			t.Errorf("management-class interface %q received a next-table rule", iif)
		}
	}
}

func TestDesiredPolicyRulePriorityCountsDeduplicatesNextTableShapes18005(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "red", TableID: 100},
		{Name: "blue", TableID: 200},
	}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "10.20.0.0/16", NextTable: "red"},
		{Destination: "10.20.0.0/16", NextTable: "red"},  // RuleAdd sees this identical shape as EEXIST.
		{Destination: "10.20.0.0/16", NextTable: "blue"}, // Same priority, distinct target table.
	}

	lookupPriority := config.RouteLeakNextTableLookupPriority(16, 32)
	shadowPriority := config.RouteLeakNextTableShadowPriority(16, 32)
	want := map[int]int{lookupPriority: 4, shadowPriority: 2}
	got := map[int]int{}
	for _, count := range DesiredPolicyRulePriorityCounts(cfg) {
		if count.Family != unix.AF_INET {
			t.Fatalf("unexpected family in IPv4-only inventory: %+v", count)
		}
		got[count.Priority] = count.Count
	}
	if len(got) != len(want) {
		t.Fatalf("inventory priorities = %v, want only lookup/shadow priorities %v", got, want)
	}
	for priority, count := range want {
		if got[priority] != count {
			t.Errorf("priority %d inventory count = %d, want %d distinct rule shapes", priority, got[priority], count)
		}
	}
}
