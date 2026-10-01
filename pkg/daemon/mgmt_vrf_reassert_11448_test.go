package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

type mgmtVRFBindRecorder11448 struct {
	*reconcileFakeLinkOps
	binds []string
}

func (r *mgmtVRFBindRecorder11448) LinkSetMaster(link, master netlink.Link) error {
	r.binds = append(r.binds, link.Attrs().Name+"->"+master.Attrs().Name)
	link.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func newMgmtVRFReassertDaemon11448(t *testing.T, masters map[string]int) (*Daemon, *mgmtVRFBindRecorder11448) {
	t.Helper()
	ops := &mgmtVRFBindRecorder11448{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{
		Name: config.ManagementVRFDeviceName, Index: 77,
	}}
	for i, name := range []string{"em0", "fxp0"} {
		ops.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Name: name, Index: i + 10, Flags: net.FlagUp, MasterIndex: masters[name],
		}}
	}
	d := &Daemon{
		applySem:     semaphore.NewWeighted(1),
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true, "fxp0": true})
	return d, ops
}

func TestMgmtVRFReassertRepairsUnboundManagementInterfaces11448(t *testing.T) {
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 45})
	var routeRefreshes int
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error {
		routeRefreshes++
		return nil
	}
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	d.reassertMgmtVRFOnce(context.Background())

	if len(ops.binds) != 2 || ops.binds[0] == ops.binds[1] {
		t.Fatalf("drifted management links were not each rebound exactly once: %v", ops.binds)
	}
	for _, name := range []string{"em0", "fxp0"} {
		if got := ops.links[name].Attrs().MasterIndex; got != ops.links[config.ManagementVRFDeviceName].Attrs().Index {
			t.Errorf("%s master index = %d, want vrf-mgmt index %d", name, got, ops.links[config.ManagementVRFDeviceName].Attrs().Index)
		}
	}
	if routeRefreshes != 1 {
		t.Errorf("management VRF routes refreshed %d times after binding drift, want once", routeRefreshes)
	}
	if !strings.Contains(logs.String(), "management interface outside the management VRF — re-binding") {
		t.Errorf("drift did not emit the required WARN: %s", logs.String())
	}
}

func TestMgmtVRFReassertLeavesHealthyManagementInterfacesAlone11448(t *testing.T) {
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 77, "fxp0": 77})
	var routeRefreshes int
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error {
		routeRefreshes++
		return nil
	}
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })

	d.reassertMgmtVRFOnce(context.Background())

	if len(ops.binds) != 0 {
		t.Errorf("healthy management-VRF members drew netlink binds: %v", ops.binds)
	}
	if routeRefreshes != 0 {
		t.Errorf("healthy management-VRF members refreshed routes %d times, want no writes", routeRefreshes)
	}
}

func TestMgmtVRFReassertLatchesRouteRefreshDebt11448(t *testing.T) {
	d, _ := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 77})
	routeErr := errors.New("injected management route refresh failure")
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return routeErr }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })

	d.reassertMgmtVRFOnce(context.Background())

	if owed, failures, last := d.RoutingReconcileDebt(); !owed ||
		failures != 1 || last != routeErr.Error() {
		t.Fatalf("route refresh failure must enter management-route debt: owed=%v failures=%d last=%q",
			owed, failures, last)
	}
}

func TestMgmtVRFReassertLoopConvergesAfterUnbind11448(t *testing.T) {
	previousInterval := mgmtVRFReassertInterval
	mgmtVRFReassertInterval = 10 * time.Millisecond
	t.Cleanup(func() { mgmtVRFReassertInterval = previousInterval })

	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 0})
	routeRefreshed := make(chan struct{}, 1)
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error {
		select {
		case routeRefreshed <- struct{}{}:
		default:
		}
		return nil
	}
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.mgmtVRFReassertLoop(ctx)
		close(done)
	}()

	select {
	case <-routeRefreshed:
	case <-time.After(time.Second):
		cancel()
		if !waitForMgmtVRFLoopExit11448(t, done) {
			return
		}
		t.Fatal("periodic management-VRF reassert did not refresh routes after drift")
	}
	cancel()
	if !waitForMgmtVRFLoopExit11448(t, done) {
		return
	}

	if len(ops.binds) != 2 {
		t.Fatalf("periodic reassert bound %d interfaces, want em0 and fxp0: %v", len(ops.binds), ops.binds)
	}
	for _, name := range []string{"em0", "fxp0"} {
		if got := ops.links[name].Attrs().MasterIndex; got != 77 {
			t.Errorf("%s master index after periodic reassert = %d, want vrf-mgmt index 77", name, got)
		}
	}
}

func waitForMgmtVRFLoopExit11448(t *testing.T, done <-chan struct{}) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(time.Second):
		t.Error("management-VRF reassert loop did not stop after cancellation")
		return false
	}
}

func TestMgmtVRFReassertUsesOnlyPublishedManagementSet11448(t *testing.T) {
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 0})
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})

	d.reassertMgmtVRFOnce(context.Background())

	if len(ops.binds) != 1 || ops.binds[0] != "fxp0->vrf-mgmt" {
		t.Errorf("reassert bound links outside the published management set: %v", ops.binds)
	}
}

func TestMgmtVRFReassertHonorsCancellation11448(t *testing.T) {
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 0})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d.reassertMgmtVRFOnce(ctx)

	if len(ops.binds) != 0 {
		t.Errorf("cancelled reassert pass bound links: %v", ops.binds)
	}
}

// This is the management-VRF counterpart to the #9813 kernel acceptance cell:
// the real netlink manager repairs a device after an out-of-band nomaster.
func TestMgmtVRFReassertRepairsOutOfBandUnbindInKernel11448(t *testing.T) {
	enterPrivateNetns9813(t)

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName},
		Table:     config.ManagementVRFTableID,
	}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Fatalf("cannot create management VRF in this netns (is the vrf module loaded?): %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("bring management VRF up: %v", err)
	}
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0"}}); err != nil {
		t.Fatalf("cannot create dummy fxp0 in this netns: %v", err)
	}
	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	d := &Daemon{
		applySem:     semaphore.NewWeighted(1),
		routing:      rt,
		linkByNameFn: netlink.LinkByName,
	}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	if err := rt.BindInterfaceToVRF("fxp0", config.ManagementVRFInstanceName); err != nil {
		t.Fatalf("initial management-VRF bind: %v", err)
	}
	fxp0, err := netlink.LinkByName("fxp0")
	if err != nil {
		t.Fatalf("lookup fxp0 before out-of-band unbind: %v", err)
	}
	if err := netlink.LinkSetNoMaster(fxp0); err != nil {
		t.Fatalf("out-of-band fxp0 nomaster: %v", err)
	}

	d.reassertMgmtVRFOnce(context.Background())

	fxp0, err = netlink.LinkByName("fxp0")
	if err != nil {
		t.Fatalf("lookup fxp0 after reassert: %v", err)
	}
	vrfLink, err := netlink.LinkByName(config.ManagementVRFDeviceName)
	if err != nil {
		t.Fatalf("lookup vrf-mgmt after reassert: %v", err)
	}
	if got := fxp0.Attrs().MasterIndex; got != vrfLink.Attrs().Index {
		t.Fatalf("fxp0 master index after out-of-band unbind and reassert = %d, want vrf-mgmt index %d",
			got, vrfLink.Attrs().Index)
	}
}
