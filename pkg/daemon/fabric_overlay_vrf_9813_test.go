package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"runtime"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/psaab/xpf/pkg/routing"
)

// #9813: a fabric overlay created or unbound outside an apply is bound back
// into the management VRF without waiting for the next apply.

// vrfBindRecorder9813 is the #5310 in-memory link table with LinkSetMaster
// recorded and applied, so the daemon's own MasterIndex check reads the result.
type vrfBindRecorder9813 struct {
	*reconcileFakeLinkOps
	mu    sync.Mutex
	binds []string
}

func (r *vrfBindRecorder9813) LinkSetMaster(link, master netlink.Link) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.binds = append(r.binds, link.Attrs().Name+"->"+master.Attrs().Name)
	link.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func (r *vrfBindRecorder9813) bound() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.binds...)
}

func (r *vrfBindRecorder9813) addFab0(masterIndex int) {
	r.links["fab0"] = &netlink.IPVlan{LinkAttrs: netlink.LinkAttrs{
		Name: "fab0", Index: 10, Flags: net.FlagUp, MasterIndex: masterIndex,
	}}
}

// mgmtVRFFabricDaemon9813 is the #6791 re-assert daemon (an active config with
// fab0 over ge-0/0/0) whose links come from the recorder: vrf-mgmt at index 77
// and no fab0. The last apply published fab0 in the management-VRF set, and the
// routing manager binds through the recorder.
func mgmtVRFFabricDaemon9813(t *testing.T) (*Daemon, *vrfBindRecorder9813) {
	t.Helper()
	ops := &vrfBindRecorder9813{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	ops.links[mgmtVRFDeviceName] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: mgmtVRFDeviceName, Index: 77}, Table: 1000,
	}
	d := newFabricReassertDaemon(t, fabricCfg6791())
	d.linkByNameFn = ops.LinkByName
	d.routing = routing.NewManagerWithLinkOpsForTest(ops)
	d.publishMgmtVRFIfaces(map[string]bool{"fab0": true})
	return d, ops
}

func TestFabricReassertBindsARecreatedOverlayToTheManagementVRF_9813(t *testing.T) {
	d, ops := mgmtVRFFabricDaemon9813(t)
	withFabricEnsure(t, func(parent, name string, addrs []string) error {
		ops.addFab0(0) // ensureFabricIPVLAN sets no master
		return nil
	})

	d.reassertFabricIPVLANOnce(context.Background())

	if got := ops.bound(); len(got) != 1 || got[0] != "fab0->vrf-mgmt" {
		t.Fatalf("#9813: the re-assert loop re-created fab0 and made %v binds, want [fab0->vrf-mgmt]. "+
			"The overlay carries the session-sync address, and session sync binds its sockets to "+
			"vrf-mgmt, so sync over this fabric stays down until the next apply", got)
	}
}

func TestFabricReassertRebindsAnOverlayThatLostItsMaster_9813(t *testing.T) {
	d, ops := mgmtVRFFabricDaemon9813(t)
	ops.addFab0(0) // present and up, but an out-of-band nomaster stripped the VRF
	ensured := 0
	withFabricEnsure(t, func(string, string, []string) error { ensured++; return nil })

	d.reassertFabricIPVLANOnce(context.Background())

	if got := ops.bound(); len(got) != 1 || got[0] != "fab0->vrf-mgmt" {
		t.Fatalf("#9813: fab0 is up but outside vrf-mgmt, and the re-assert pass made %v binds, "+
			"want [fab0->vrf-mgmt]. Nothing else binds it before the next apply", got)
	}
	if ensured != 0 {
		t.Errorf("an overlay that exists and is up was re-created (%d ensure calls); only its binding was lost", ensured)
	}
}

func TestFabricReassertLeavesAnEnslavedOverlayAlone_9813(t *testing.T) {
	d, ops := mgmtVRFFabricDaemon9813(t)
	ops.addFab0(77) // already a member of vrf-mgmt
	ensured := 0
	withFabricEnsure(t, func(string, string, []string) error { ensured++; return nil })

	d.reassertFabricIPVLANOnce(context.Background())

	if got := ops.bound(); len(got) != 0 || ensured != 0 {
		t.Errorf("a healthy, enslaved fab0 drew %v binds and %d ensure calls; the loop must be free on a healthy node",
			got, ensured)
	}
}

func TestFabricReassertBindsOnlyWhatTheApplyPutInTheManagementVRF_9813(t *testing.T) {
	d, ops := mgmtVRFFabricDaemon9813(t)
	ops.addFab0(0)
	d.publishMgmtVRFIfaces(nil) // the last apply did not manage vrf-mgmt

	d.reassertFabricIPVLANOnce(context.Background())

	if got := ops.bound(); len(got) != 0 {
		t.Errorf("fab0 was bound to vrf-mgmt (%v) although the last apply published no management-VRF set", got)
	}
}

func TestDeferredFabricOverlayIsBoundWhenCreated_9813(t *testing.T) {
	d, ops := mgmtVRFFabricDaemon9813(t)
	withFabricEnsure(t, func(parent, name string, addrs []string) error {
		ops.addFab0(0)
		return nil
	})

	d.createDeferredFabricOverlays([]deferredIPVLAN{{parent: "ge-0-0-0", name: "fab0", addrs: []string{"10.99.0.1/24"}}})

	if got := ops.bound(); len(got) != 1 || got[0] != "fab0->vrf-mgmt" {
		t.Fatalf("#9813: the deferred OnXSKBound creation made %v binds, want [fab0->vrf-mgmt]. It can "+
			"run after the apply's step-2.7 re-bind, so the overlay it creates would stay outside vrf-mgmt", got)
	}
}

// applyFabricIPVLAN's OnXSKBound callback must be the binding creator.
func TestApplyFabricIPVLANDefersThroughTheBindingCreator_9813(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon_apply_interfaces.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_apply_interfaces.go: %v", err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "SetOnXSKBound" || len(call.Args) != 1 {
			return true
		}
		ast.Inspect(call.Args[0], func(m ast.Node) bool {
			if c, ok := m.(*ast.CallExpr); ok {
				if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "createDeferredFabricOverlays" {
					found = true
				}
			}
			return true
		})
		return true
	})
	if !found {
		t.Errorf("#9813: applyFabricIPVLAN's OnXSKBound callback does not call createDeferredFabricOverlays, " +
			"so a deferred overlay is created without its management-VRF bind")
	}
}

// enterPrivateNetns9813 moves the test goroutine's locked OS thread into a fresh
// network namespace, and SKIPs when that is denied (it needs CAP_NET_ADMIN; run
// under `unshare -rn`).
func enterPrivateNetns9813(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read the current netns (%v)", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create a private netns; needs CAP_NET_ADMIN (run under `unshare -rn`): %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
}

// The acceptance cell from the issue, against the kernel: the real
// ensureFabricIPVLAN re-creates a missing fab0, the real routing manager binds
// it, and an out-of-band nomaster is undone without an apply.
func TestReassertBindsTheFabricOverlayInTheKernel_9813(t *testing.T) {
	enterPrivateNetns9813(t)
	parent := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-0"}}
	if err := netlink.LinkAdd(parent); err != nil {
		t.Skipf("cannot create a dummy parent in this netns: %v", err)
	}
	if err := netlink.LinkSetUp(parent); err != nil {
		t.Fatalf("parent up: %v", err)
	}
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: mgmtVRFDeviceName}, Table: 1000}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Skipf("cannot create a VRF device in this netns (is the vrf module loaded?): %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("vrf up: %v", err)
	}
	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	d := newFabricReassertDaemon(t, fabricCfg6791())
	d.linkByNameFn = netlink.LinkByName
	d.routing = rt
	d.publishMgmtVRFIfaces(map[string]bool{"fab0": true})

	master := func(what string) {
		t.Helper()
		fab, err := netlink.LinkByName("fab0")
		if err != nil {
			t.Fatalf("%s: fab0 is absent: %v", what, err)
		}
		v, err := netlink.LinkByName(mgmtVRFDeviceName)
		if err != nil {
			t.Fatalf("%s: vrf-mgmt is absent: %v", what, err)
		}
		if fab.Attrs().MasterIndex != v.Attrs().Index {
			t.Fatalf("#9813: %s, fab0's master index is %d, want vrf-mgmt (%d). Session sync binds its "+
				"sockets to vrf-mgmt, so sync over this fabric stays down until the next apply",
				what, fab.Attrs().MasterIndex, v.Attrs().Index)
		}
	}

	d.reassertFabricIPVLANOnce(context.Background())
	master("after the re-assert loop re-created a missing fab0")

	fab, err := netlink.LinkByName("fab0")
	if err != nil {
		t.Fatalf("fab0: %v", err)
	}
	if err := netlink.LinkSetNoMaster(fab); err != nil {
		t.Fatalf("nomaster: %v", err)
	}
	d.reassertFabricIPVLANOnce(context.Background())
	master("after an out-of-band nomaster and one re-assert pass")
}
