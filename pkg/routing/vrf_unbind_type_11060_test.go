package routing

import (
	"testing"

	"github.com/vishvananda/netlink"
)

func TestUnbindInterfaceFromVRFsLeavesForeignMasterWithVRFName11060(t *testing.T) {
	ops := newFakeVRFOps()
	const masterIndex = 91
	iface := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name: "eth0", Index: 5, MasterIndex: masterIndex,
	}}
	foreignMaster := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name: "vrf-red", Index: masterIndex,
	}}
	ops.overlay["eth0"] = iface
	ops.overlay["vrf-red"] = foreignMaster

	manager := &vrfManager{ops: ops}
	unbound, err := manager.UnbindInterfaceFromVRFs("eth0", []string{"red"})
	if err != nil {
		t.Fatalf("UnbindInterfaceFromVRFs: %v", err)
	}
	if unbound {
		t.Fatal("unbound eth0 from a non-VRF link wearing a vrf-red name")
	}
	if ops.noMasters != 0 {
		t.Fatalf("LinkSetNoMaster calls = %d, want 0", ops.noMasters)
	}
	if got := iface.Attrs().MasterIndex; got != masterIndex {
		t.Fatalf("eth0 master index = %d, want foreign master %d to remain", got, masterIndex)
	}
}
