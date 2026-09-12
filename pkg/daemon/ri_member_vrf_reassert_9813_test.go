package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// The acceptance cell from the issue, against the kernel: a member whose master
// is stripped outside an apply is bound again by the pass, with the real
// routing.Manager and real netlink. It reuses the fabric half's netns helper,
// and skips without CAP_NET_ADMIN.
func TestRIMemberIsReBoundInTheKernel_9813(t *testing.T) {
	enterPrivateNetns9813(t)
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue"}, Table: 100}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Skipf("cannot create a VRF device in this netns (is the vrf module loaded?): %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("vrf up: %v", err)
	}
	member := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-5"}}
	if err := netlink.LinkAdd(member); err != nil {
		t.Skipf("cannot create a dummy member in this netns: %v", err)
	}
	if err := netlink.LinkSetUp(member); err != nil {
		t.Fatalf("member up: %v", err)
	}
	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	d := &Daemon{routing: rt, linkByNameFn: netlink.LinkByName}

	master := func(what string) {
		t.Helper()
		m, err := netlink.LinkByName("ge-0-0-5")
		if err != nil {
			t.Fatalf("%s: member absent: %v", what, err)
		}
		v, err := netlink.LinkByName("vrf-blue")
		if err != nil {
			t.Fatalf("%s: vrf-blue absent: %v", what, err)
		}
		if m.Attrs().MasterIndex != v.Attrs().Index {
			t.Fatalf("#9813: %s, the member's master index is %d, want vrf-blue (%d). A member outside "+
				"its VRF forwards in the DEFAULT table until the next apply of any kind",
				what, m.Attrs().MasterIndex, v.Attrs().Index)
		}
	}

	// The apply's bind, then an out-of-band strip with no apply to repair it.
	d.rebindRIMembersOutsideTheirVRF(blueCfg9813())
	master("after the first pass bound a member the apply left unbound")

	live, err := netlink.LinkByName("ge-0-0-5")
	if err != nil {
		t.Fatalf("member: %v", err)
	}
	if err := netlink.LinkSetNoMaster(live); err != nil {
		t.Fatalf("nomaster: %v", err)
	}
	d.rebindRIMembersOutsideTheirVRF(blueCfg9813())
	master("after an out-of-band nomaster and one pass")

	// CONTROL: a second pass over a healthy member must be a no-op, not a
	// re-bind — the property the Info-logging cost rests on.
	before, err := netlink.LinkByName("ge-0-0-5")
	if err != nil {
		t.Fatalf("member: %v", err)
	}
	if got := d.riMembersOutsideTheirVRF(blueCfg9813()); len(got) != 0 {
		t.Errorf("a member already in its VRF (master %d) is reported as drifted: %v",
			before.Attrs().MasterIndex, got)
	}
}

// #9813 tenant half: a routing-instance list member re-created or unbound
// outside an apply is bound back into its VRF without waiting for the next
// apply. The cells drive the pure pass, as the #6805 cells drive the apply's
// bind loop; the store/applySem wrapper is pinned separately below.

// riVRFDaemon9813 is a daemon whose links come from ops and whose routing
// manager binds through ops.
func riVRFDaemon9813(ops *bindRecorderOps) *Daemon {
	return &Daemon{
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
}

// linkWithMaster9813 makes a device exist in the fake table with a master index.
func linkWithMaster9813(ops *bindRecorderOps, name string, index, master int) {
	ops.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name: name, Index: index, Flags: net.FlagUp, MasterIndex: master,
	}}
}

// blueCfg9813 is one vrf instance with a physical list member.
func blueCfg9813() *config.Config {
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 100, Interfaces: []string{"ge-0/0/5"},
	}}
	return cfg
}

func TestRIMemberOutsideItsVRFIsReBound_9813(t *testing.T) {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "ge-0-0-5", 10, 0) // out of band: nomaster
	d := riVRFDaemon9813(ops)

	d.rebindRIMembersOutsideTheirVRF(blueCfg9813())

	got := ops.recorded()
	if len(got) != 1 || got[0] != "ge-0-0-5->vrf-blue" {
		t.Fatalf("#9813: a member outside its VRF drew %v binds, want [ge-0-0-5->vrf-blue]. Nothing "+
			"re-asserts list-member VRF membership between applies, so the member forwards in the "+
			"DEFAULT table until the next apply of any kind", got)
	}
}

func TestRIMemberAlreadyInItsVRFIsLeftAlone_9813(t *testing.T) {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "ge-0-0-5", 10, 77) // already a member
	d := riVRFDaemon9813(ops)

	d.rebindRIMembersOutsideTheirVRF(blueCfg9813())

	if got := ops.recorded(); len(got) != 0 {
		t.Errorf("a member already in its VRF drew %v binds; BindInterfaceToVRF logs at Info on every "+
			"call, so a loop that re-binds unconditionally logs on every tick of a healthy node", got)
	}
}

func TestRIMemberReassertSkipsForwardingInstancesAndAbsentMembers_9813(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "fwd", InstanceType: "forwarding", TableID: 101, Interfaces: []string{"ge-0/0/6"}},
		{Name: "blue", InstanceType: "vrf", TableID: 100, Interfaces: []string{"ge-0/0/7"}},
	}
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "vrf-fwd", 78, 0)
	linkWithMaster9813(ops, "ge-0-0-6", 11, 0) // a forwarding instance has no VRF membership
	// ge-0-0-7 is absent: a member this chassis does not have.
	d := riVRFDaemon9813(ops)

	// The property is the DRIFTED SET, not the bind count: a bind attempt against
	// an absent link records nothing, so asserting only on binds cannot tell a
	// skipped member from one that was reported and then failed to bind.
	if got := d.riMembersOutsideTheirVRF(cfg); len(got) != 0 {
		t.Errorf("reported %v as drifted; a forwarding instance's member has no VRF device, and a "+
			"member absent on this chassis must not be reported — step 0a already treats absence as "+
			"best-effort, and reporting it would re-try it loudly on every tick", got)
	}

	d.rebindRIMembersOutsideTheirVRF(cfg)

	if got := ops.recorded(); len(got) != 0 {
		t.Errorf("binds = %v, want none: a forwarding instance's member has no VRF, and an absent "+
			"member must stay quiet rather than be re-tried loudly on every tick", got)
	}
}

func TestRIMemberReassertLeavesAStanzaTunnelToTheTunnelManager_9813(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Tunnel: &config.TunnelConfig{
				Name: "gr-0-0-0", Mode: "gre", Source: "10.0.0.1", Destination: "10.0.0.2",
				RoutingInstance: "blue",
			},
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 100, Interfaces: []string{"gr-0/0/0.0"},
	}}
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "gr-0-0-0", 12, 0)
	d := riVRFDaemon9813(ops)

	// CONTROL: the fixture's tunnel must actually be collected, or the skip
	// below is vacuous — a tunnel with no usable endpoints is dropped entirely.
	if !tunnelsWithTheirOwnRIStanza(cfg)["gr-0-0-0"] {
		t.Fatal("fixture: the stanza tunnel was not collected, so this cell would pass with the skip removed")
	}

	d.rebindRIMembersOutsideTheirVRF(cfg)

	if got := ops.recorded(); len(got) != 0 {
		t.Errorf("#9813: the loop bound %v, but a tunnel with its own routing-instance stanza is the "+
			"tunnel manager's claim (reconcileVRFClaimLocked case 1, recorded in appliedRI). Binding it "+
			"here moves the master with the claim bookkeeping left behind", got)
	}
}

// Run must start the loop, or every cell above passes while nothing re-asserts
// anything in production.
func TestRunStartsTheRIMemberVRFReassertLoop_9813(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon_run.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_run.go: %v", err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "riMemberVRFReassertLoop" {
			found = true
		}
		return true
	})
	if !found {
		t.Error("#9813: Run does not start riMemberVRFReassertLoop, so nothing re-asserts " +
			"routing-instance member VRF membership between applies")
	}
}

// The #4001 discipline, pinned the way the #6791 loop pins it: a tick that binds
// on a config read outside applySem can act on a pre-commit snapshot.
func TestRIMemberReassertTakesApplySemBeforeActing_9813(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "ri_member_vrf_reassert_9813.go"))
	body, ok := fabricFuncBody6791(src, "reassertRIMemberVRFOnce")
	if !ok {
		t.Fatal("could not locate reassertRIMemberVRFOnce")
	}
	acq := strings.Index(body, "d.applySem.Acquire(")
	if acq < 0 {
		t.Fatalf("reassertRIMemberVRFOnce does not acquire applySem; a tick can then bind a member a " +
			"concurrent commit just removed from its instance (#4001)")
	}
	if !strings.Contains(body, "defer d.applySem.Release(1)") {
		t.Errorf("reassertRIMemberVRFOnce acquires applySem without releasing it")
	}
	act := strings.Index(body, "d.rebindRIMembersOutsideTheirVRF(")
	if act < 0 {
		t.Fatal("could not find the binding pass")
	}
	if act < acq {
		t.Errorf("reassertRIMemberVRFOnce binds BEFORE acquiring applySem; the config it acts on can be " +
			"a pre-commit snapshot (#4001)")
	}
}
