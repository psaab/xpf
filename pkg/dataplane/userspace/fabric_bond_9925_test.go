package userspace

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Issue 9925: a fabric interface with configured `fabric-options
// member-interfaces` but NO resolved local member gets no AF_XDP ingress
// target at all, so traffic on it never reaches userspace forwarding. Two
// mechanisms combine: no fabric snapshot (buildFabricSnapshotsFrom builds
// only from cc.FabricInterface/Fabric1Interface, which the compiler
// populates only when the local node has a member), and the `fab name`
// exclusion arm dropping every fab row by prefix.
//
// The fix narrows the `fab name` arm to fab-prefix-WITHOUT-FabricBond, where
// FabricBond is a shipped row flag set at row-build from
// configured-members-without-local-member. Bond-shape rows then bind the
// BOND MASTER through the existing row/VLAN machinery
// (pkg/dataplane/compiler_iface.go:153-160); no fabric snapshot is emitted
// for transit.
//
// FIXTURE RULE (#9872 caveat, Scout9925): slots 1/2 derive LOCAL on node 0
// (SlotToNodeID falls through to 0 for every non-7 slot), so the issue's
// verbatim members take the WITH-member path on node 0. Every bond-shape
// fixture here is therefore node-1 or clusterless — never node 0.

// bondFabFixture9925 is the issue's config compiled CLUSTERLESS: with no
// cluster stanza the compiler derivation never runs, LocalFabricMember stays
// empty, and (post-fix) both rows carry FabricBond.
func bondFabFixture9925() []string {
	return []string{
		"set interfaces fab0 mtu 1400",
		"set interfaces fab0 vlan-tagging",
		"set interfaces fab0 fabric-options member-interfaces ge-1/0/0",
		"set interfaces fab0 fabric-options member-interfaces ge-2/0/0",
		"set interfaces fab0 unit 10 vlan-id 10",
		"set security zones security-zone fabric interfaces fab0.10",
	}
}

// compileForNode9925 compiles set lines for an explicit node id. The #5619
// helper always compiles for node 0, which would derive the issue's members
// local; the node-1 shape needs the derivation to run and find nothing.
func compileForNode9925(t *testing.T, node int, lines ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigForNode(tree, node)
	if err != nil {
		t.Fatalf("CompileConfigForNode(%d): %v", node, err)
	}
	return cfg
}

// bondFabSnapshot9925 compiles the clusterless bond fixture with the bond
// and its tagged child live, and returns the publishable snapshot. The
// premises pin the shape under test: configured members, no local member,
// no fabric snapshot, VLAN child parented on the bond.
func bondFabSnapshot9925(t *testing.T) *ConfigSnapshot {
	t.Helper()
	defer stubLinkSnapshot5619(t, map[string]int{"fab0": 40, "fab0.10": 41})()
	defer stubXfrmNetdevs(t)()
	cfg := compileForTest5619(t, bondFabFixture9925()...)
	if cfg.Chassis.Cluster != nil {
		t.Fatal("premise broken: the bond fixture must be clusterless")
	}
	ifc := cfg.Interfaces.Interfaces["fab0"]
	if ifc == nil {
		t.Fatal("premise broken: fab0 did not compile")
	}
	if len(ifc.FabricMembers) != 2 || ifc.LocalFabricMember != "" {
		t.Fatalf("premise broken: members=%v local=%q, want 2 configured members and no local member",
			ifc.FabricMembers, ifc.LocalFabricMember)
	}
	snap := gateSnapshot(t, cfg)
	if len(snap.Fabrics) != 0 {
		t.Fatalf("premise broken: bond shape carries %d fabric snapshots, want 0 — "+
			"the fix must bind through rows, not through an emitted fabric snapshot", len(snap.Fabrics))
	}
	base, child := rowByName(t, snap.Interfaces, "fab0"), rowByName(t, snap.Interfaces, "fab0.10")
	if child.LinuxName != "fab0.10" || child.ParentLinuxName != "fab0" {
		t.Fatalf("premise broken: fab0.10 resolves to %q parent %q, want fab0.10 on fab0",
			child.LinuxName, child.ParentLinuxName)
	}
	if child.Zone != "fabric" {
		t.Fatalf("premise broken: fab0.10 zone = %q, want fabric", child.Zone)
	}
	if child.Ifindex != 41 || child.ParentIfindex != 40 || base.Ifindex != 40 {
		t.Fatalf("premise broken: base ifindex=%d child=%d parent=%d, want 40/41/40",
			base.Ifindex, child.Ifindex, child.ParentIfindex)
	}

	if !base.FabricBond || !child.FabricBond {
		t.Fatalf("premise broken: FabricBond base=%v child=%v, want both true",
			base.FabricBond, child.FabricBond)
	}
	return snap
}

// TestBondShapeFabIngressSetContainsBondMaster9925 is the core #9925 cell:
// the bond-shape fab contributes its master's ifindex to the
// ingress-adjudication map, plus the tagged child, plus the child→parent
// alias. Pre-fix all three are missing (the `fab name` arm drops both rows
// and no fabric snapshot supplies a target), so the interface forwards
// nothing. FAIL-ON-REVERT: restore the un-narrowed fab arm and the bond
// master leaves the set again.
func TestBondShapeFabIngressSetContainsBondMaster9925(t *testing.T) {
	snap := bondFabSnapshot9925(t)
	got := buildUserspaceIngressIfindexes(snap)
	if !slices.Contains(got, 40) {
		t.Errorf("ingress set %v lacks the bond master ifindex 40 — a fab0.10 frame "+
			"arrives on fab0's queues and leaves the adjudicated path (cpumap_or_pass)", got)
	}
	if !slices.Contains(got, 41) {
		t.Errorf("ingress set %v lacks the tagged child ifindex 41", got)
	}
	aliases := buildUserspaceIngressBindingAliases(snap)
	if aliases[41] != 40 {
		t.Errorf("binding alias for 41 = %d, want 40 (child→bond-master)", aliases[41])
	}
}

// TestBondShapeFabAllowlistContainsBondMaster9925 is the RSS-allowlist half
// of the same verdict: the D3 path must reshape the netdev the socket binds,
// which is the bond master. FAIL-ON-REVERT with the cell above.
func TestBondShapeFabAllowlistContainsBondMaster9925(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{"fab0": 40, "fab0.10": 41})()
	defer stubXfrmNetdevs(t)()
	cfg := compileForTest5619(t, bondFabFixture9925()...)
	got := UserspaceBoundLinuxInterfaces(cfg)
	if !slices.Contains(got, "fab0") {
		t.Errorf("allowlist %v lacks the bond master fab0", got)
	}
}

// TestBondShapeFabIsNotInTheRefusedIndex9925 pins the MECHANISM: post-fix no
// owning row calls the bond netdev unbindable, so the unanimous-refusal
// index must not refuse fab0 by name or by ifindex. Pre-fix the base row is
// the sole owner and votes unbindable, so both refuse. FAIL-ON-REVERT on the
// narrowing (and on any new voter that re-refuses the master).
func TestBondShapeFabIsNotInTheRefusedIndex9925(t *testing.T) {
	snap := bondFabSnapshot9925(t)
	refused := buildUserspaceRefusedNetdevs(snap)
	if refused.refusesName("fab0") {
		t.Error("refused index refuses fab0 by name — the VLAN child's redirect " +
			"onto the master is then dropped from every set")
	}
	if refused.refusesNetdev("fab0", 40) {
		t.Error("refused index refuses fab0 by (name, ifindex 40)")
	}
}

// TestBondShapeFabMissingBondLeavesIngressEmpty9925 pins that kernel truth
// still gates: with the bond (and its child) absent from the link dump, the
// admitted rows resolve to non-positive ifindexes and the existing guards
// keep them out of the ifindex-keyed set. Green before and after the fix;
// it fails only if the fix emits a phantom ifindex for a missing bond.
func TestBondShapeFabMissingBondLeavesIngressEmpty9925(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{})()
	defer stubXfrmNetdevs(t)()
	cfg := compileForTest5619(t, bondFabFixture9925()...)
	snap := gateSnapshot(t, cfg)
	if got := buildUserspaceIngressIfindexes(snap); len(got) != 0 {
		t.Errorf("ingress set with no live bond = %v, want empty — admitted rows "+
			"with non-positive ifindexes must stay out", got)
	}
}

// TestBondShapeFabPlanKeyCoversBondRows9925 pins that the same-plan key
// follows the layout: both admitted fab rows must hash, or a bond-fab commit
// classifies as "same plan" and publishes through the pending-XSK-startup
// window while the helper rebuilds underneath (#8901). The compiler's
// zone fan-up gives the base row the fabric zone, so both the bond master and
// tagged child participate. FAIL-ON-REVERT on the narrowing: pre-fix both
// rows are filtered and the key lacks them.
func TestBondShapeFabPlanKeyCoversBondRows9925(t *testing.T) {
	snap := bondFabSnapshot9925(t)
	key := snapshotBindingPlanKey(snap)
	for _, name := range []string{"fab0/", "fab0.10/"} {
		if !strings.Contains(key, "iface="+name) {
			t.Errorf("plan key lacks the admitted %s row: %q", name, key)
		}
	}
}

// TestNode1ClusteredBondShapeBindsMaster9925 is the second #9925 shape
// (#9872 shape b): clustered, compiled for node 1, members in slots 1/2 —
// which map to node 0, so node 1 derives no local member, auto-populates no
// FabricInterface, and builds no fabric snapshot. Same verdict as the
// clusterless shape. FAIL-ON-REVERT on the narrowing.
func TestNode1ClusteredBondShapeBindsMaster9925(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{"fab0": 40, "fab0.10": 41})()
	defer stubXfrmNetdevs(t)()
	lines := append([]string{
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
	}, bondFabFixture9925()...)
	cfg := compileForNode9925(t, 1, lines...)
	cc := cfg.Chassis.Cluster
	if cc == nil || cc.NodeID != 1 {
		t.Fatalf("premise broken: cluster=%+v, want node 1", cc)
	}
	ifc := cfg.Interfaces.Interfaces["fab0"]
	if len(ifc.FabricMembers) != 2 || ifc.LocalFabricMember != "" {
		t.Fatalf("premise broken: members=%v local=%q, want 2 remote members and no local member",
			ifc.FabricMembers, ifc.LocalFabricMember)
	}
	if cc.FabricInterface != "" || cc.Fabric1Interface != "" {
		t.Fatalf("premise broken: FabricInterface=%q Fabric1Interface=%q, want both empty — "+
			"node 1 has no member, so nothing auto-populates", cc.FabricInterface, cc.Fabric1Interface)
	}
	snap := gateSnapshot(t, cfg)
	if len(snap.Fabrics) != 0 {
		t.Fatalf("premise broken: node-1 bond shape carries %d fabric snapshots, want 0", len(snap.Fabrics))
	}
	if got := buildUserspaceIngressIfindexes(snap); !slices.Contains(got, 40) {
		t.Errorf("node-1 ingress set %v lacks the bond master ifindex 40", got)
	}
	if got := UserspaceBoundLinuxInterfaces(cfg); !slices.Contains(got, "fab0") {
		t.Errorf("node-1 allowlist %v lacks the bond master fab0", got)
	}
}

// TestFabricBondProtocolGate9925 pins the feature floor and its scope. A
// helper that has answered below v25 cannot reproduce the positive admission
// bit, while a memberless fab row does not need this gate.
func TestFabricBondProtocolGate9925(t *testing.T) {
	snap := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{FabricBond: true}},
	}
	m := New()
	m.setLastStatusLocked(ProcessStatus{
		ConfigSnapshotProtocolVersion: MinProtocolFabricBond - 1,
	})
	err := m.ensureFabricBondProtocolLocked(snap)
	if !errors.Is(err, ErrFabricBondProtocolIncompatible) {
		t.Fatalf("old helper gate error = %v, want %v", err, ErrFabricBondProtocolIncompatible)
	}

	m = New()
	m.setLastStatusLocked(ProcessStatus{
		ConfigSnapshotProtocolVersion: MinProtocolFabricBond,
	})
	if err := m.ensureFabricBondProtocolLocked(snap); err != nil {
		t.Fatalf("current helper rejected FabricBond snapshot: %v", err)
	}

	plain := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{Name: "fab0"}},
	}
	m = New()
	m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: 1})
	if err := m.ensureFabricBondProtocolLocked(plain); err != nil {
		t.Fatalf("memberless fab row incorrectly armed FabricBond gate: %v", err)
	}
}

// TestWithMemberFabVerdictsUnchanged9925 is the WITH-member negative
// control: fab0 with a LOCAL member keeps the exact pre-fix verdicts — the
// rows stay excluded (LocalFabric row half plus the narrowed `fab name`
// arm, which still fires without FabricBond) and the fabric parent loop
// still supplies the member NIC. Green before and after; it reds only if
// the narrowing leaks into the WITH-member shape. The expectations below
// were measured pre-fix and must stay bit-for-bit.
func TestWithMemberFabVerdictsUnchanged9925(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-3": 21, "fab0": 22, "fab0.7": 23,
	})()
	defer stubXfrmNetdevs(t)()
	cfg := compileForTest5619(t,
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/3",
		"set interfaces fab0 unit 7 vlan-id 100",
		"set security zones security-zone trust interfaces fab0.7",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
	)
	ifc := cfg.Interfaces.Interfaces["fab0"]
	if ifc.LocalFabricMember != "ge-0/0/3" {
		t.Fatalf("premise broken: LocalFabricMember = %q, want ge-0/0/3 (node-0 compile)",
			ifc.LocalFabricMember)
	}
	snap := gateSnapshot(t, cfg)
	if len(snap.Fabrics) != 1 {
		t.Fatalf("premise broken: WITH-member shape carries %d fabric snapshots, want 1", len(snap.Fabrics))
	}
	if base := rowByName(t, snap.Interfaces, "fab0"); base.FabricBond {
		t.Fatal("WITH-member fab0 unexpectedly carries FabricBond")
	}
	if got := buildUserspaceIngressIfindexes(snap); !slices.Equal(got, []uint32{21}) {
		t.Errorf("WITH-member ingress = %v, want [21] (fabric parent only, bit-for-bit)", got)
	}
	if got := UserspaceBoundLinuxInterfaces(cfg); !slices.Equal(got, []string{"ge-0-0-3"}) {
		t.Errorf("WITH-member allowlist = %v, want [ge-0-0-3] (bit-for-bit)", got)
	}
	if key := snapshotBindingPlanKey(snap); strings.Contains(key, "iface=fab0") {
		t.Errorf("WITH-member plan key covers a fab row, which neither plane admits: %q", key)
	}
}

// TestPlainFabNoMembersVerdictsUnchanged9925 is the memberless negative
// control: a plain fab0 with NO configured members keeps the conservative
// pre-fix verdict (excluded — no evidence either way, Scout9925 Q2c).
// FabricBond requires configured members, so the narrowed arm still fires.
// Green before and after; it reds only if the flag's "with members"
// conjunct is dropped.
func TestPlainFabNoMembersVerdictsUnchanged9925(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{"fab0": 40, "fab0.10": 41})()
	defer stubXfrmNetdevs(t)()
	cfg := compileForTest5619(t,
		"set interfaces fab0 unit 10 vlan-id 10",
		"set security zones security-zone fabric interfaces fab0.10",
	)
	ifc := cfg.Interfaces.Interfaces["fab0"]
	if len(ifc.FabricMembers) != 0 || ifc.LocalFabricMember != "" {
		t.Fatalf("premise broken: members=%v local=%q, want none",
			ifc.FabricMembers, ifc.LocalFabricMember)
	}
	snap := gateSnapshot(t, cfg)
	if base := rowByName(t, snap.Interfaces, "fab0"); base.FabricBond {
		t.Fatal("memberless fab0 unexpectedly carries FabricBond")
	}
	if got := buildUserspaceIngressIfindexes(snap); len(got) != 0 {
		t.Errorf("memberless fab0 ingress = %v, want empty (bit-for-bit)", got)
	}
	if got := UserspaceBoundLinuxInterfaces(cfg); len(got) != 0 {
		t.Errorf("memberless fab0 allowlist = %v, want empty (bit-for-bit)", got)
	}
	if key := snapshotBindingPlanKey(snap); strings.Contains(key, "iface=fab0") {
		t.Errorf("memberless fab0 plan key covers a fab row: %q", key)
	}
}
