package routing

import (
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestReconcileVRFsRejectsDesiredNameForeignLink verifies that a non-VRF
// device occupying a desired VRF name fails closed instead of being deleted,
// brought up, or adopted as the desired VRF.
func TestReconcileVRFsRejectsDesiredNameForeignLink(t *testing.T) {
	ops := newFakeVRFOps()
	foreign := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: "vrf-mgmt"},
	}
	ops.overlay["vrf-mgmt"] = foreign
	ops.extraLinks = []netlink.Link{foreign}

	manager := &vrfManager{ops: ops}
	err := manager.Reconcile([]VRFSpec{{Name: "mgmt", TableID: 999}})
	if err == nil || !strings.Contains(err.Error(), "not a VRF") {
		t.Fatalf("Reconcile error = %v, want non-VRF occupant error", err)
	}
	if ops.dels != 0 {
		t.Errorf("LinkDel calls = %d, want 0 for a foreign non-VRF link", ops.dels)
	}
	if ops.adds != 0 {
		t.Errorf("LinkAdd calls = %d, want 0 when a foreign link occupies the name", ops.adds)
	}
	if ops.setUps != 0 {
		t.Errorf("LinkSetUp calls = %d, want 0 for a foreign non-VRF link", ops.setUps)
	}
	if len(manager.vrfs) != 0 {
		t.Errorf("tracked VRFs = %v, want no ownership of the foreign link", manager.vrfs)
	}
}

// TestReconcileVRFsSkipsDeleteForTrackedNotDesiredForeignLink verifies the
// tracked-but-not-desired delete loop also refuses a name swapped
// out-of-band for a non-VRF (GLM review, PR #12320): no LinkDel, no error
// storm — the foreign link is simply left alone.
func TestReconcileVRFsSkipsDeleteForTrackedNotDesiredForeignLink(t *testing.T) {
	ops := newFakeVRFOps()
	foreign := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: "vrf-old"},
	}
	ops.overlay["vrf-old"] = foreign
	ops.extraLinks = []netlink.Link{foreign}

	manager := &vrfManager{ops: ops, vrfs: []string{"vrf-old"}}
	err := manager.Reconcile([]VRFSpec{{Name: "mgmt", TableID: 999}})
	if err != nil {
		t.Fatalf("Reconcile error = %v, want nil (foreign skip is silent)", err)
	}
	if ops.dels != 0 {
		t.Errorf("LinkDel calls = %d, want 0 for a tracked-not-desired foreign link", ops.dels)
	}
}

// TestReconcileVRFsTrackedDesiredForeignReleasesOwnership verifies a
// tracked+desired name occupied by a non-VRF refuses (no del/add/setUp)
// and releases ownership (kills M9/M10-class regressions).
func TestReconcileVRFsTrackedDesiredForeignReleasesOwnership(t *testing.T) {
	ops := newFakeVRFOps()
	foreign := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: "vrf-mgmt"},
	}
	ops.overlay["vrf-mgmt"] = foreign
	ops.extraLinks = []netlink.Link{foreign}

	manager := &vrfManager{ops: ops, vrfs: []string{"vrf-mgmt"}}
	err := manager.Reconcile([]VRFSpec{{Name: "mgmt", TableID: 999}})
	if err == nil || !strings.Contains(err.Error(), "not a VRF") {
		t.Fatalf("Reconcile error = %v, want non-VRF occupant error", err)
	}
	if ops.dels != 0 {
		t.Errorf("LinkDel calls = %d, want 0 for a tracked+desired foreign link", ops.dels)
	}
	if ops.adds != 0 || ops.setUps != 0 {
		t.Errorf("LinkAdd/SetUp calls = %d/%d, want 0/0", ops.adds, ops.setUps)
	}
	if len(manager.vrfs) != 0 {
		t.Errorf("tracked VRFs = %v, want ownership released", manager.vrfs)
	}
}

// TestReconcileVRFsRefusalDoesNotBlockSiblings verifies a foreign occupant
// on one desired VRF neither blocks a sibling create nor skips the orphan
// sweep (kills M4 early-return regressions).
func TestReconcileVRFsRefusalDoesNotBlockSiblings(t *testing.T) {
	ops := newFakeVRFOps()
	foreign := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{Name: "vrf-mgmt"},
	}
	ops.overlay["vrf-mgmt"] = foreign
	ops.extraLinks = []netlink.Link{foreign}

	manager := &vrfManager{ops: ops}
	err := manager.Reconcile([]VRFSpec{{Name: "mgmt", TableID: 999}, {Name: "blue", TableID: 100}})
	if err == nil {
		t.Fatalf("Reconcile error = nil, want foreign-occupant error")
	}
	if len(manager.vrfs) != 1 || manager.vrfs[0] != "vrf-blue" {
		t.Errorf("tracked VRFs = %v, want [vrf-blue] (sibling created)", manager.vrfs)
	}
}
