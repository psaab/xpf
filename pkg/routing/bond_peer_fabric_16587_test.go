package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #16587: in a chassis cluster the peer's fab (all members on the peer,
// LocalFabricMember empty) must not be realized as a local empty bond,
// while a standalone multi-member fab still bonds and a tracked ghost
// leaving the desired set is reaped. RED on revert: dropping the
// shouldBond cluster gate recreates fab1 on node0 / fab0 on node1.

// peerFabricIfaces mirrors the shipped HA config compiled per node:
// fab0 has the node0 member, fab1 the node1 member; the compiler sets
// LocalFabricMember only on the local fab.
func peerFabricIfaces(node int) []*config.InterfaceConfig {
	fab0 := bondFabricConfig("fab0", "ge-0/0/0")
	fab1 := bondFabricConfig("fab1", "ge-7/0/0")
	if node == 0 {
		fab0.LocalFabricMember = "ge-0/0/0"
	} else {
		fab1.LocalFabricMember = "ge-7/0/0"
	}
	return []*config.InterfaceConfig{fab0, fab1}
}

func TestPeerFabricCreatesNoBondOnEitherNode_16587(t *testing.T) {
	for _, node := range []int{0, 1} {
		ops := newFakeBondLinkOps()
		ops.seedMember("ge-0-0-0")
		b := &bondManager{ops: ops}
		if err := b.ApplyCluster(peerFabricIfaces(node), true, node, false); err != nil {
			t.Fatalf("node %d: ApplyCluster = %v, want nil", node, err)
		}
		if len(ops.addCalls) != 0 || len(ops.setUpCalls) != 0 {
			t.Fatalf("node %d: peer fab realized as a bond: addCalls=%v setUpCalls=%v, want none",
				node, ops.addCalls, ops.setUpCalls)
		}
		if len(b.bonds) != 0 {
			t.Fatalf("node %d: tracked bonds = %v, want none", node, b.bonds)
		}
	}
}

// The positive control: the same empty-LocalFabricMember shape outside a
// cluster is the #9872 standalone multi-member LAG and must still bond.
func TestStandaloneMultiMemberFabStillBonds_16587(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}
	ifc := bondFabricConfig("fab0", "ge-0/0/1", "ge-0/0/2")
	if err := b.ApplyCluster([]*config.InterfaceConfig{ifc}, false, 0, false); err != nil {
		t.Fatalf("ApplyCluster (no cluster) = %v, want nil", err)
	}
	if len(ops.addCalls) != 1 || ops.addCalls[0] != "fab0" {
		t.Fatalf("standalone fab addCalls = %v, want [fab0]", ops.addCalls)
	}
	// Plain Apply (no cluster identity ever set) must behave identically.
	ops2 := newFakeBondLinkOps()
	ops2.seedMember("ge-0-0-1")
	b2 := &bondManager{ops: ops2}
	if err := b2.Apply([]*config.InterfaceConfig{bondFabricConfig("fab0", "ge-0/0/1")}); err != nil {
		t.Fatalf("plain Apply = %v, want nil", err)
	}
	if len(ops2.addCalls) != 1 {
		t.Fatalf("plain Apply addCalls = %v, want one bond", ops2.addCalls)
	}
}

// A cluster node with two local members on one fab bonds it (>=2 local).
func TestClusterDualLocalMemberFabBonds_16587(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}
	ifc := bondFabricConfig("fab0", "ge-0/0/1", "ge-0/0/2")
	if err := b.ApplyCluster([]*config.InterfaceConfig{ifc}, true, 0, false); err != nil {
		t.Fatalf("ApplyCluster = %v, want nil", err)
	}
	if len(ops.addCalls) != 1 || ops.addCalls[0] != "fab0" {
		t.Fatalf("dual-local fab addCalls = %v, want [fab0]", ops.addCalls)
	}
}

// Tracked reap: a bond created under the old (pre-fix) desired set is
// deleted by the next cluster reconcile that no longer desires it.
func TestTrackedGhostBondReapedOnClusterApply_16587(t *testing.T) {
	ops := newFakeBondLinkOps()
	b := &bondManager{ops: ops}
	// Pre-fix process created the empty peer bond (no cluster gate).
	if err := b.Apply(peerFabricIfaces(0)); err != nil {
		t.Fatalf("pre-fix Apply = %v, want nil", err)
	}
	if _, ok := ops.links["fab1"]; !ok {
		t.Fatalf("premise: pre-fix Apply must create fab1, links=%v", ops.links)
	}
	ops.reset()
	if err := b.ApplyCluster(peerFabricIfaces(0), true, 0, false); err != nil {
		t.Fatalf("cluster ApplyCluster = %v, want nil", err)
	}
	if _, ok := ops.links["fab1"]; ok {
		t.Fatalf("tracked ghost fab1 still present after cluster reconcile: delCalls=%v", ops.delCalls)
	}
	if len(b.bonds) != 0 {
		t.Fatalf("tracked bonds = %v, want none after reap", b.bonds)
	}
}

// Untracked reap (upgrade): a ghost bond that outlived the pre-fix
// process is deleted on the first (reap-armed) cluster reconcile, and
// only then — a non-reap reconcile adopts nothing and deletes nothing,
// and the reap never touches a bond carrying members or a foreign link.
func TestUntrackedGhostBondReapedOnlyOnUpgrade_16587(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("fab1", 42) // slave-less ghost, no enslaved members
	b := &bondManager{ops: ops}
	if err := b.ApplyCluster(peerFabricIfaces(0), true, 0, false); err != nil {
		t.Fatalf("non-reap ApplyCluster = %v, want nil", err)
	}
	if _, ok := ops.links["fab1"]; !ok {
		t.Fatal("non-reap reconcile deleted the untracked bond; reap must be first-apply only")
	}
	if err := b.ApplyCluster(peerFabricIfaces(0), true, 0, true); err != nil {
		t.Fatalf("reap ApplyCluster = %v, want nil", err)
	}
	if _, ok := ops.links["fab1"]; ok {
		t.Fatal("untracked ghost fab1 still present after upgrade reap")
	}

	// A bond WITH members is never ghost-reaped.
	ops2 := newFakeBondLinkOps()
	ops2.seedBond("fab1", 42)
	ops2.seedEnslavedMember("ge-7-0-0", 42)
	b2 := &bondManager{ops: ops2}
	if err := b2.ApplyCluster(peerFabricIfaces(0), true, 0, true); err != nil {
		t.Fatalf("reap with members = %v, want nil", err)
	}
	if _, ok := ops2.links["fab1"]; !ok {
		t.Fatal("reap deleted a bond carrying members")
	}

	// A same-name foreign (non-bond) link is never touched.
	ops3 := newFakeBondLinkOps()
	ops3.links["fab1"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fab1", Index: 9}}
	b3 := &bondManager{ops: ops3}
	if err := b3.ApplyCluster(peerFabricIfaces(0), true, 0, true); err != nil {
		t.Fatalf("reap with foreign link = %v, want nil", err)
	}
	if _, ok := ops3.links["fab1"]; !ok {
		t.Fatal("reap deleted a foreign non-bond link wearing the fab name")
	}
}
