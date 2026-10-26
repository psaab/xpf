package daemon

import (
	"net"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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

// TestNatScopeFoldUsesBuilderCollisionAssignments_17876 pins the sender fold
// to the synthetic ifindexes the snapshot builder actually assigned. The two
// valid RETH units have the same initial FNV slot, so the builder displaces
// the second one through its shared used-set. FAIL-ON-REVERT: independently
// recomputing each unit with a fresh set points both names at one ifindex;
// the folder then stamps one builder row with its sibling's VLAN and leaves
// the displaced row unknown, which can revoke an otherwise valid imported
// session. The parent fold is the named control.
func TestNatScopeFoldUsesBuilderCollisionAssignments_17876(t *testing.T) {
	parent, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	for _, vlan := range []int{205, 680} {
		if _, err := net.InterfaceByName("lo." + strconv.Itoa(vlan)); err == nil {
			t.Skipf("loopback VLAN lo.%d exists; fixture is not logical-only", vlan)
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"lo": {Name: "lo", RedundantParent: "reth0"},
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			205: {Number: 205, VlanID: 205},
			680: {Number: 680, VlanID: 680},
		}},
	}}}
	snapshots := dpuserspace.BuildInterfaceSnapshots(cfg)
	rows := make(map[string]dpuserspace.InterfaceSnapshot, 2)
	for _, row := range snapshots {
		if row.Name == "reth0.205" || row.Name == "reth0.680" {
			rows[row.Name] = row
		}
	}
	first, okFirst := rows["reth0.205"]
	second, okSecond := rows["reth0.680"]
	if !okFirst || !okSecond || !first.LogicalOnly || !second.LogicalOnly {
		t.Fatalf("builder rows = (%+v,%v), (%+v,%v), want both logical-only RETH units", first, okFirst, second, okSecond)
	}
	if first.Ifindex != 1073948161 || second.Ifindex != first.Ifindex+1 {
		t.Fatalf("builder collision assignments = (%d,%d), want (1073948161,1073948162)", first.Ifindex, second.Ifindex)
	}
	fold := buildNatScopeFoldFnWithIfaces(cfg, ifaces)
	if fold == nil {
		t.Fatal("NAT scope folder is nil for tagged RETH config")
	}
	sender := cluster.NewSessionSync(":0", ":0", nil)
	sender.SetNatScopeFoldFn(fold)
	for _, tc := range []struct {
		name string
		row  dpuserspace.InterfaceSnapshot
		want string
	}{
		{name: "reth0.205", row: first, want: "reth0.205"},
		{name: "reth0.680", row: second, want: "reth0.680"},
	} {
		if got, want := sender.StampNatScopeFoldForTesting(int32(tc.row.Ifindex)), config.StableIfaceID(tc.want); got != want {
			t.Errorf("%s synthetic ifindex %d stamped fold %d, want fold(%s)=%d",
				tc.name, tc.row.Ifindex, got, tc.want, want)
		}
	}
	if got, want := sender.StampNatScopeFoldForTesting(int32(parent.Index)), config.StableIfaceID("reth0"); got != want {
		t.Errorf("parent ifindex %d stamped fold %d, want parent control fold %d", parent.Index, got, want)
	}
}

// TestNatScopeFoldDoesNotMintUnboundRethVLAN_17876 matches the snapshot
// builder's resolved-parent guard: a reth-prefixed interface that resolves to
// itself is not a parent-bound logical-only VLAN. FAIL-ON-REVERT: without the
// guard the folder claims a synthetic index the builder never assigns, rather
// than preserving the unknown-scope fallback. The named parent control still
// folds as reth1.
func TestNatScopeFoldDoesNotMintUnboundRethVLAN_17876(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			80: {Number: 80, VlanID: 80},
		}},
	}}}
	ifaces := []net.Interface{{Index: 40, Name: "reth1"}}
	fold := buildNatScopeFoldFnWithIfaces(cfg, ifaces)
	if fold == nil {
		t.Fatal("NAT scope folder is nil for tagged RETH config")
	}
	synthetic := dpuserspace.SyntheticLogicalIfindexForUnit("reth1.80", 80, make(map[int]struct{}))
	if got := fold(int32(synthetic)); got != 0 {
		t.Fatalf("unbound reth1.80 synthetic index %d stamped fold %d, want unknown 0", synthetic, got)
	}
	if got, want := fold(40), config.StableIfaceID("reth1"); got != want {
		t.Fatalf("unbound reth1 parent control fold = %d, want %d", got, want)
	}
}

// TestNatScopeFoldUsesTunnelMappedRethUnit_17876 verifies that child-device
// lookup follows snapshotLinuxName's tunnel-before-VLAN precedence. The first
// colliding unit is tunnel-mapped, so the real builder does not consume the
// shared synthetic slot; the later logical-only sibling must keep that slot.
// FAIL-ON-REVERT: probing only parent.VLAN claims it for the tunnel unit and
// displaces the sibling from its actual builder index.
func TestNatScopeFoldUsesTunnelMappedRethUnit_17876(t *testing.T) {
	parent, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	if _, err := net.InterfaceByName("lo.680"); err == nil {
		t.Skip("loopback VLAN lo.680 exists; fixture is not logical-only")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	var tunnel net.Interface
	for _, ifc := range ifaces {
		if ifc.Index > 0 && ifc.Name != "" && ifc.Index != parent.Index {
			tunnel = ifc
			break
		}
	}
	if tunnel.Index == 0 {
		t.Skip("need a second live interface for the tunnel-mapped unit")
	}
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"lo": {Name: "lo", RedundantParent: "reth0"},
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			205: {Number: 205, VlanID: 205, Tunnel: &config.TunnelConfig{Name: tunnel.Name}},
			680: {Number: 680, VlanID: 680},
		}},
	}}}
	rows := dpuserspace.BuildInterfaceSnapshots(cfg)
	var tunnelRow, siblingRow *dpuserspace.InterfaceSnapshot
	for i := range rows {
		switch rows[i].Name {
		case "reth0.205":
			tunnelRow = &rows[i]
		case "reth0.680":
			siblingRow = &rows[i]
		}
	}
	if tunnelRow == nil || tunnelRow.LogicalOnly || tunnelRow.Ifindex != tunnel.Index || tunnelRow.ParentIfindex != parent.Index {
		t.Fatalf("builder tunnel row = %+v, want non-logical reth0.205 at tunnel ifindex %d, parent %d",
			tunnelRow, tunnel.Index, parent.Index)
	}
	if siblingRow == nil || !siblingRow.LogicalOnly || siblingRow.Ifindex != 1073948161 || siblingRow.ParentIfindex != parent.Index {
		t.Fatalf("builder sibling row = %+v, want logical-only reth0.680 at shared initial slot 1073948161, parent %d",
			siblingRow, parent.Index)
	}
	fold := buildNatScopeFoldFnWithIfaces(cfg, ifaces)
	if fold == nil {
		t.Fatal("NAT scope folder is nil for tagged RETH config")
	}
	if got, want := fold(int32(tunnelRow.Ifindex)), config.StableIfaceID("reth0.205"); got != want {
		t.Errorf("tunnel ifindex %d fold = %d, want reth0.205 fold %d", tunnelRow.Ifindex, got, want)
	}
	if got, want := fold(int32(siblingRow.Ifindex)), config.StableIfaceID("reth0.680"); got != want {
		t.Errorf("sibling synthetic ifindex %d fold = %d, want reth0.680 fold %d",
			siblingRow.Ifindex, got, want)
	}
	if got, want := fold(int32(parent.Index)), config.StableIfaceID("reth0"); got != want {
		t.Errorf("parent ifindex %d fold = %d, want control %d", parent.Index, got, want)
	}
}

// TestNatScopeFoldDoesNotMintForTunnelMappedRethUnit_17876 pins the
// child-present case to a real snapshot-builder row. FAIL-ON-REVERT: probing
// only parent.VLAN fails to recognize the mapped device and either leaves its
// ifindex unknown or claims the synthetic candidate as this unit.
func TestNatScopeFoldDoesNotMintForTunnelMappedRethUnit_17876(t *testing.T) {
	parent, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	var tunnel net.Interface
	for _, ifc := range ifaces {
		if ifc.Index > 0 && ifc.Name != "" && ifc.Index != parent.Index {
			tunnel = ifc
			break
		}
	}
	if tunnel.Index == 0 {
		t.Skip("need a second live interface for the tunnel-mapped unit")
	}
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"lo": {Name: "lo", RedundantParent: "reth0"},
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			205: {Number: 205, VlanID: 205, Tunnel: &config.TunnelConfig{Name: tunnel.Name}},
		}},
	}}}
	rows := dpuserspace.BuildInterfaceSnapshots(cfg)
	var child *dpuserspace.InterfaceSnapshot
	for i := range rows {
		if rows[i].Name == "reth0.205" {
			child = &rows[i]
			break
		}
	}
	if child == nil || child.LogicalOnly || child.Ifindex != tunnel.Index || child.ParentIfindex != parent.Index {
		t.Fatalf("builder child row = %+v, want non-logical reth0.205 at ifindex %d with parent %d",
			child, tunnel.Index, parent.Index)
	}
	fold := buildNatScopeFoldFnWithIfaces(cfg, ifaces)
	if got, want := fold(int32(child.Ifindex)), config.StableIfaceID("reth0.205"); got != want {
		t.Errorf("tunnel-mapped child ifindex %d fold = %d, want reth0.205 fold %d", child.Ifindex, got, want)
	}
	synthetic := dpuserspace.SyntheticLogicalIfindexForUnit("reth0.205", 205, make(map[int]struct{}))
	if got := fold(int32(synthetic)); got != 0 {
		t.Errorf("tunnel-mapped unit synthetic candidate %d stamped fold %d, want unknown 0", synthetic, got)
	}
	if got, want := fold(int32(parent.Index)), config.StableIfaceID("reth0"); got != want {
		t.Errorf("parent ifindex %d fold = %d, want control %d", parent.Index, got, want)
	}
}

// TestNatScopeFoldUsesKernelVlanChildAndDoesNotMint_17876 supplies the
// injected parent/VLAN child netdev shape. FAIL-ON-REVERT: if the folder
// allocates synthetic indices despite an existing child, the synthetic
// candidate incorrectly receives a confident fold too.
func TestNatScopeFoldUsesKernelVlanChildAndDoesNotMint_17876(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			80: {Number: 80, VlanID: 80},
		}},
	}}}
	fold := buildNatScopeFoldFnWithIfaces(cfg, []net.Interface{
		{Index: 10, Name: "ge-0-0-2"},
		{Index: 12, Name: "ge-0-0-2.80"},
	})
	if fold == nil {
		t.Fatal("NAT scope folder is nil for tagged RETH config")
	}
	if got, want := fold(12), config.StableIfaceID("reth0.80"); got != want {
		t.Errorf("VLAN child ifindex fold = %d, want reth0.80 fold %d", got, want)
	}
	synthetic := dpuserspace.SyntheticLogicalIfindexForUnit("reth0.80", 80, make(map[int]struct{}))
	if got := fold(int32(synthetic)); got != 0 {
		t.Errorf("kernel-child unit's synthetic candidate %d stamped fold %d, want unknown 0", synthetic, got)
	}
	if got, want := fold(10), config.StableIfaceID("reth0"); got != want {
		t.Errorf("parent ifindex fold = %d, want control %d", got, want)
	}
}
