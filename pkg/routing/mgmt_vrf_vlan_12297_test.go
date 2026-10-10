package routing

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

type childBindOps12297 struct {
	*fakeVRFOps
	masterCalls int
}

func (o *childBindOps12297) LinkSetMaster(iface, master netlink.Link) error {
	o.masterCalls++
	iface.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func TestBindManagementVLANDescendants12297(t *testing.T) {
	base := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 10}}
	child := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "fxp0.100", Index: 11, ParentIndex: 10}, VlanId: 100}
	grandchild := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "fxp0.100.200", Index: 12, ParentIndex: 11}, VlanId: 200}
	ordinaryChild := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ordinary0", Index: 13, ParentIndex: 10}}
	ops := &childBindOps12297{fakeVRFOps: newFakeVRFOps()}
	for _, link := range []netlink.Link{base, child, grandchild, ordinaryChild} {
		ops.overlay[link.Attrs().Name] = link
		ops.extraLinks = append(ops.extraLinks, link)
	}
	ops.seed("vrf-mgmt", 999)
	ops.links["vrf-mgmt"].LinkAttrs.Index = 99
	manager := &vrfManager{ops: ops}

	if err := manager.BindInterfaceToVRF("fxp0", "mgmt"); err != nil {
		t.Fatalf("BindInterfaceToVRF: %v", err)
	}
	for _, link := range []netlink.Link{base, child, grandchild} {
		if got := link.Attrs().MasterIndex; got != 99 {
			t.Errorf("%s master index = %d, want vrf-mgmt index 99", link.Attrs().Name, got)
		}
	}
	if got := ordinaryChild.Attrs().MasterIndex; got != 0 {
		t.Errorf("non-VLAN child master index = %d, want unchanged 0", got)
	}
	if ops.masterCalls != 3 {
		t.Fatalf("LinkSetMaster calls = %d, want parent and two VLAN descendants", ops.masterCalls)
	}
	if err := manager.BindInterfaceToVRF("fxp0", "mgmt"); err != nil {
		t.Fatalf("idempotent BindInterfaceToVRF: %v", err)
	}
	if ops.masterCalls != 3 {
		t.Errorf("already-bound links were rebound: LinkSetMaster calls = %d, want 3", ops.masterCalls)
	}
}
func TestBindManagementVLANDescendantsReportsLinkListFailure12297(t *testing.T) {
	base := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 10}}
	ops := &childBindOps12297{fakeVRFOps: newFakeVRFOps()}
	ops.overlay[base.Attrs().Name] = base
	ops.extraLinks = append(ops.extraLinks, base)
	ops.seed("vrf-mgmt", 999)
	ops.links["vrf-mgmt"].LinkAttrs.Index = 99
	listErr := errors.New("injected link-list failure")
	ops.linkListErr = listErr

	err := (&vrfManager{ops: ops}).BindInterfaceToVRF("fxp0", "mgmt")
	if !errors.Is(err, listErr) {
		t.Fatalf("BindInterfaceToVRF error = %v, want wrapped link-list failure", err)
	}
}
