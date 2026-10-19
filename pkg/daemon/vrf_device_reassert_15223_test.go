package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

// #15223 (A38-02): a VRF device deleted out of band between applies has no
// re-assert owner. Every #11448/#9813 loop skips when the device is absent,
// so members fall into the default VRF until the next apply. One tick of a
// 30s owner must re-create the desired device and then bind its members.

// vrfDeviceOps15223 wraps the shared fake table and records LinkAdd calls so
// a test can observe a VRF device being re-created.
type vrfDeviceOps15223 struct {
	*bindRecorderOps
	adds []string
}

func (o *vrfDeviceOps15223) LinkAdd(l netlink.Link) error {
	o.adds = append(o.adds, l.Attrs().Name)
	// The shared fake stores the link but leaves Index 0; give a created
	// VRF a stable index so member MasterIndex comparisons can converge.
	if vrf, ok := l.(*netlink.Vrf); ok && vrf.Attrs().Index == 0 {
		vrf.Attrs().Index = 77
	}
	return o.reconcileFakeLinkOps.LinkAdd(l)
}

// LinkSetMaster applies the master index, as the real kernel (and the
// #11448 recorder) does, so a test can assert the member actually landed
// in the re-created VRF. bindRecorderOps alone only records the call.
func (o *vrfDeviceOps15223) LinkSetMaster(link, master netlink.Link) error {
	if err := o.bindRecorderOps.LinkSetMaster(link, master); err != nil {
		return err
	}
	link.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func newVRFDeviceOps15223() *vrfDeviceOps15223 {
	return &vrfDeviceOps15223{bindRecorderOps: &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}}
}

// TestMgmtVRFReassertRecreatesDeletedDevice15223 is the acceptance cell from
// the issue: vrf-mgmt is deleted out of band, em0/fxp0 remain present but
// unbound, and one mgmt tick re-creates vrf-mgmt and binds them.
//
// FAIL-ON-REVERT: on origin/master mgmtVRFInterfacesOutsideVRF returns nil
// when the VRF lookup fails, so reassertMgmtVRFOnce returns before any
// LinkAdd/LinkSetMaster and this test fails.
func TestMgmtVRFReassertRecreatesDeletedDevice15223(t *testing.T) {
	ops := newVRFDeviceOps15223()
	// No vrf-mgmt link at all: deleted out of band. Members exist, unbound.
	linkWithMaster9813(ops.bindRecorderOps, "em0", 10, 0)
	linkWithMaster9813(ops.bindRecorderOps, "fxp0", 11, 0)
	d := &Daemon{
		applySem:     semaphore.NewWeighted(1),
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true, "fxp0": true})
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return nil }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })

	d.reassertMgmtVRFOnce(context.Background())

	if _, ok := ops.links[config.ManagementVRFDeviceName]; !ok {
		t.Fatalf("#15223: one mgmt reassert tick did not re-create %s after out-of-band deletion; adds=%v binds=%v",
			config.ManagementVRFDeviceName, ops.adds, ops.recorded())
	}
	for _, name := range []string{"em0", "fxp0"} {
		if got := ops.links[name].Attrs().MasterIndex; got != 77 {
			t.Errorf("%s master index = %d, want re-created vrf-mgmt index 77", name, got)
		}
	}
	if got := ops.recorded(); len(got) != 2 {
		t.Errorf("binds after VRF re-create = %v, want em0 and fxp0 bound to vrf-mgmt", got)
	}
}

// TestMgmtVRFReassertDoesNotCreateUnmanagedDevice15223 is the control: with
// no published management set the last apply did not manage vrf-mgmt, so a
// tick must not create it.
func TestMgmtVRFReassertDoesNotCreateUnmanagedDevice15223(t *testing.T) {
	ops := newVRFDeviceOps15223()
	linkWithMaster9813(ops.bindRecorderOps, "em0", 10, 0)
	d := &Daemon{
		applySem:     semaphore.NewWeighted(1),
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	// No publishMgmtVRFIfaces: vrf-mgmt is not managed.

	d.reassertMgmtVRFOnce(context.Background())

	if len(ops.adds) != 0 || len(ops.recorded()) != 0 {
		t.Errorf("unmanaged vrf-mgmt drew adds=%v binds=%v; want no writes", ops.adds, ops.recorded())
	}
}

// TestRIMemberReassertRecreatesDeletedDevice15223 is the tenant half: vrf-blue
// is deleted out of band and its list member exists unbound. One RI tick
// re-creates vrf-blue and binds the member.
//
// FAIL-ON-REVERT: on origin/master riMembersOutsideTheirVRF continues when
// the VRF lookup fails, so nothing is created or bound.
func TestRIMemberReassertRecreatesDeletedDevice15223(t *testing.T) {
	ops := newVRFDeviceOps15223()
	linkWithMaster9813(ops.bindRecorderOps, "ge-0-0-5", 10, 0)
	d := &Daemon{
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}

	d.rebindRIMembersOutsideTheirVRF(blueCfg9813())

	if _, ok := ops.links["vrf-blue"]; !ok {
		t.Fatalf("#15223: one RI reassert tick did not re-create vrf-blue after out-of-band deletion; adds=%v binds=%v",
			ops.adds, ops.recorded())
	}
	if got := ops.links["ge-0-0-5"].Attrs().MasterIndex; got != 77 {
		t.Errorf("ge-0-0-5 master index = %d, want re-created vrf-blue index 77", got)
	}
	if got := ops.recorded(); len(got) != 1 || got[0] != "ge-0-0-5->vrf-blue" {
		t.Errorf("binds after VRF re-create = %v, want [ge-0-0-5->vrf-blue]", got)
	}
}

// TestFabricReassertRecreatesDeletedMgmtDevice15223 covers the fabric path:
// fab0 exists outside a deleted vrf-mgmt. The fabric bind pass re-creates
// vrf-mgmt and binds fab0.
//
// FAIL-ON-REVERT: on origin/master fabricOverlayOutsideMgmtVRF returns false
// when the VRF lookup fails, so no bind is attempted.
func TestFabricReassertRecreatesDeletedMgmtDevice15223(t *testing.T) {
	ops := newVRFDeviceOps15223()
	linkWithMaster9813(ops.bindRecorderOps, "fab0", 10, 0)
	// No vrf-mgmt link.
	d := &Daemon{
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(map[string]bool{"fab0": true})
	d.rebindFabricOverlaysToMgmtVRF(fabricCfgWithFab0_15223())

	if _, ok := ops.links[config.ManagementVRFDeviceName]; !ok {
		t.Fatalf("#15223: fabric rebind did not re-create %s after out-of-band deletion; adds=%v binds=%v",
			config.ManagementVRFDeviceName, ops.adds, ops.recorded())
	}
	if got := ops.links["fab0"].Attrs().MasterIndex; got != 77 {
		t.Errorf("fab0 master index = %d, want re-created vrf-mgmt index 77", got)
	}
}

func fabricCfgWithFab0_15223() *config.Config {
	return fabricCfg6791()
}
