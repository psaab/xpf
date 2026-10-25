package daemon

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// nat_scope_fold_16826_test.go — #16826 two-node cell: a reth0.80
// session's NatScopeFold, stamped on node 0 from the LOGICAL child
// ifindex, resolves on node 1 to the (ge-7-0-2, 80) pair whose logical
// unit is ge-7-0-2.80 (pinned to ifindex 22 in the userspace receiver
// cell). FAIL-ON-REVERT: the pre-fix vlan-0 fold stamps fold(reth0).
func natScopeCfg16826(nodeID, slot int) *config.Config {
	c := &config.Config{}
	c.Chassis.Cluster = &config.ClusterConfig{NodeID: nodeID}
	wan := "ge-" + string(rune('0'+slot)) + "/0/2"
	lan := "ge-" + string(rune('0'+slot)) + "/0/1"
	c.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		wan:     {Name: wan, RedundantParent: "reth0"},
		lan:     {Name: lan, RedundantParent: "reth1"},
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{50: {Number: 50, VlanID: 50}, 80: {Number: 80, VlanID: 80}}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	return c
}

func TestNatScopeFoldTwoNodeRethVlan_16826(t *testing.T) {
	n0 := natScopeCfg16826(0, 0)
	n1 := natScopeCfg16826(1, 7)
	devs0 := []net.Interface{{Index: 10, Name: "ge-0-0-2"}, {Index: 12, Name: "ge-0-0-2.80"}}
	sender := cluster.NewSessionSync(":0", ":0", nil)
	sender.SetZoneOwnership(cluster.ZoneRGMap{}, nil, buildIngressFoldFnWithIfaces(n0, devs0))
	sender.SetNatScopeFoldFn(buildNatScopeFoldFnWithIfaces(n0, devs0))

	fold := sender.StampNatScopeFoldForTesting(12) // logical child ge-0-0-2.80
	if fold != config.StableIfaceID("reth0.80") {
		t.Fatalf("stamped fold = %d, want fold(reth0.80)=%d (fold(reth0)=%d truncates to parent)",
			fold, config.StableIfaceID("reth0.80"), config.StableIfaceID("reth0"))
	}
	if got := sender.StampNatScopeFoldForTesting(10); got != config.StableIfaceID("reth0") {
		t.Fatalf("parent fold = %d, want fold(reth0)=%d (control)", got, config.StableIfaceID("reth0"))
	}
	resolve := buildIngressFoldResolverWithIfaces(n1, []net.Interface{
		{Index: 20, Name: "ge-7-0-2"}, {Index: 22, Name: "ge-7-0-2.80"},
	})
	ifindex, vlan, ok := resolve(fold)
	if !ok || ifindex != 20 || vlan != 80 {
		t.Fatalf("node1 resolve = (%d,%d,%v), want (20,80,true) -> logical ge-7-0-2.80", ifindex, vlan, ok)
	}
	// Gate control: a config with no tagged RETH unit keeps legacy (nil folder).
	plain := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	if fn := buildNatScopeFoldFnWithIfaces(plain, devs0); fn != nil {
		t.Fatal("non-RETH-VLAN config must keep the legacy vlan-0 fold (nil pair folder)")
	}
}
