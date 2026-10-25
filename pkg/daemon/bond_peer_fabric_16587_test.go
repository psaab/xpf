package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #16587 daemon wiring: applyInterfaceReconcile must pass the cluster
// identity to ApplyClusterBonds so the shipped HA shape (fab0 local to
// node0, fab1 local to node1) creates no peer bond on either node, and
// the first reconcile of a process reaps an untracked pre-fix ghost.
// RED on revert: restoring plain ApplyBonds recreates fab1 on node0.

func shippedHAConfig16587(node int) *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: node}
	fab0 := &config.InterfaceConfig{Name: "fab0", FabricMembers: []string{"ge-0/0/0"}, BondMode: "active-backup"}
	fab1 := &config.InterfaceConfig{Name: "fab1", FabricMembers: []string{"ge-7/0/0"}, BondMode: "active-backup"}
	if node == 0 {
		fab0.LocalFabricMember = "ge-0/0/0"
	} else {
		fab1.LocalFabricMember = "ge-7/0/0"
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{"fab0": fab0, "fab1": fab1}
	return cfg
}

func TestApplyReconcileCreatesNoPeerFabricBond_16587(t *testing.T) {
	for _, node := range []int{0, 1} {
		ops := newReconcileFakeLinkOps()
		d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
		if err := d.applyInterfaceReconcile(shippedHAConfig16587(node)); err != nil {
			t.Fatalf("node %d: applyInterfaceReconcile = %v, want nil", node, err)
		}
		for name := range ops.links {
			t.Fatalf("node %d: reconcile created link %q, want no bond at all", node, name)
		}
	}
}

func TestApplyReconcileReapsUntrackedGhostOnFirstApply_16587(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	peer := "fab1"
	ops.links[peer] = &netlink.Bond{LinkAttrs: netlink.LinkAttrs{Name: peer, Index: 42}}
	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	cfg := shippedHAConfig16587(0)
	if err := d.applyInterfaceReconcile(cfg); err != nil {
		t.Fatalf("first applyInterfaceReconcile = %v, want nil", err)
	}
	if _, ok := ops.links[peer]; ok {
		t.Fatal("untracked ghost fab1 survived the first (upgrade) reconcile")
	}

	// Second reconcile must not reap a bond that appears later untracked
	// (e.g. an operator-created device): the reap is first-apply only.
	ops.links[peer] = &netlink.Bond{LinkAttrs: netlink.LinkAttrs{Name: peer, Index: 43}}
	if err := d.applyInterfaceReconcile(cfg); err != nil {
		t.Fatalf("second applyInterfaceReconcile = %v, want nil", err)
	}
	if _, ok := ops.links[peer]; !ok {
		t.Fatal("second reconcile reaped an untracked bond; reap must be first-apply only")
	}
}
