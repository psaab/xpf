package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
	if count != 3*len(want) || len(got) != len(want) {
		t.Fatalf("installed %d rules for ingress ifnames %v; want 3 each for only %v", count, got, want)
	}
	for iif := range want {
		if got[iif] != 3 {
			t.Errorf("ordinary ingress %q received %d rules, want probe+lookup+shadow", iif, got[iif])
		}
	}
	for iif := range got {
		if config.IsManagementIfName(iif) {
			t.Errorf("management-class interface %q received a next-table rule", iif)
		}
	}
}
