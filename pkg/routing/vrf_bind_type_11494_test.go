package routing

import (
	"testing"

	"github.com/vishvananda/netlink"
)

type bindRecordingVRFOps11494 struct {
	*fakeVRFOps
	masterCalls int
}

func (f *bindRecordingVRFOps11494) LinkSetMaster(iface, master netlink.Link) error {
	f.masterCalls++
	iface.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func TestBindInterfaceToVRFRejectsNonVRFNameCollision11494(t *testing.T) {
	ops := &bindRecordingVRFOps11494{fakeVRFOps: newFakeVRFOps()}
	iface := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 5}}
	foreign := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "vrf-red", Index: 100}}
	ops.overlay[iface.Attrs().Name] = iface
	ops.overlay[foreign.Attrs().Name] = foreign

	if err := (&vrfManager{ops: ops}).BindInterfaceToVRF("eth0", "red"); err == nil {
		t.Fatal("BindInterfaceToVRF accepted a bridge named vrf-red")
	}
	if ops.masterCalls != 0 {
		t.Fatalf("LinkSetMaster calls = %d, want 0 for a non-VRF master", ops.masterCalls)
	}
	if got := iface.Attrs().MasterIndex; got != 0 {
		t.Fatalf("interface master index = %d, want unchanged 0", got)
	}
}

func TestBindInterfaceToVRFAcceptsVRF11494(t *testing.T) {
	ops := &bindRecordingVRFOps11494{fakeVRFOps: newFakeVRFOps()}
	iface := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 5}}
	ops.overlay[iface.Attrs().Name] = iface
	ops.seed("vrf-red", 100)
	ops.links["vrf-red"].LinkAttrs.Index = 100

	if err := (&vrfManager{ops: ops}).BindInterfaceToVRF("eth0", "red"); err != nil {
		t.Fatalf("BindInterfaceToVRF: %v", err)
	}
	if ops.masterCalls != 1 || iface.Attrs().MasterIndex != 100 {
		t.Fatalf("bind calls=%d master=%d, want one bind to VRF index 100", ops.masterCalls, iface.Attrs().MasterIndex)
	}
}
