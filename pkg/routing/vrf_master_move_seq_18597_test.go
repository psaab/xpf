package routing

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

// #18597: the daemon restarts the cluster heartbeat after a management-VRF
// bind pass only when VRFMasterMoveSeq for the control link changed. These
// cells pin the counter's contract: a bind that actually changes IFLA_MASTER
// counts once, an idempotent bind of a link already in its VRF does not, a
// failed bind does not, and an unbind that detaches counts.
//
// FAIL-ON-REVERT: drop noteMasterMove from bindLinkToVRF and the first cell
// reds (the daemon would never restart the heartbeat after a real move); call
// it on the idempotent early return and the second cell reds (every commit
// would restart the heartbeat again, the #18597 defect).

type moveRecordingVRFOps18597 struct {
	*fakeVRFOps
	masterCalls int
	masterErr   error
}

func (f *moveRecordingVRFOps18597) LinkSetMaster(iface, master netlink.Link) error {
	f.masterCalls++
	if f.masterErr != nil {
		return f.masterErr
	}
	iface.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func newMoveFixture18597() (*moveRecordingVRFOps18597, *netlink.Dummy, *vrfManager) {
	ops := &moveRecordingVRFOps18597{fakeVRFOps: newFakeVRFOps()}
	em0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "em0", Index: 3}}
	ops.overlay["em0"] = em0
	ops.seed("vrf-mgmt", 999)
	ops.links["vrf-mgmt"].LinkAttrs.Index = 50
	return ops, em0, &vrfManager{ops: ops}
}

func TestVRFMasterMoveSeqCountsARealBind18597(t *testing.T) {
	ops, em0, v := newMoveFixture18597()
	if got := v.MasterMoveSeq("em0"); got != 0 {
		t.Fatalf("precondition: seq = %d before any bind, want 0", got)
	}
	if err := v.BindInterfaceToVRF("em0", "mgmt"); err != nil {
		t.Fatalf("BindInterfaceToVRF: %v", err)
	}
	if ops.masterCalls != 1 || em0.Attrs().MasterIndex != 50 {
		t.Fatalf("precondition: bind calls=%d master=%d, want one bind to index 50",
			ops.masterCalls, em0.Attrs().MasterIndex)
	}
	if got := v.MasterMoveSeq("em0"); got != 1 {
		t.Fatalf("seq after a bind that moved em0 = %d, want 1", got)
	}
	m := &Manager{vrf: v}
	if got := m.VRFMasterMoveSeq("em0"); got != 1 {
		t.Fatalf("Manager.VRFMasterMoveSeq = %d, want 1 (the exported read must see the same count)", got)
	}
}

func TestVRFMasterMoveSeqIgnoresAnIdempotentBind18597(t *testing.T) {
	ops, em0, v := newMoveFixture18597()
	em0.Attrs().MasterIndex = 50 // already in vrf-mgmt, as after every commit
	for i := 0; i < 3; i++ {
		if err := v.BindInterfaceToVRF("em0", "mgmt"); err != nil {
			t.Fatalf("BindInterfaceToVRF #%d: %v", i, err)
		}
	}
	if ops.masterCalls != 0 {
		t.Fatalf("precondition: LinkSetMaster calls = %d for an already-bound link, want 0", ops.masterCalls)
	}
	if got := v.MasterMoveSeq("em0"); got != 0 {
		t.Fatalf("seq after idempotent binds = %d, want 0: an unmoved link must not restart the heartbeat", got)
	}
}

func TestVRFMasterMoveSeqIgnoresAFailedBind18597(t *testing.T) {
	ops, _, v := newMoveFixture18597()
	ops.masterErr = errors.New("EBUSY")
	if err := v.BindInterfaceToVRF("em0", "mgmt"); err == nil {
		t.Fatal("precondition: bind with a failing LinkSetMaster returned nil")
	}
	if got := v.MasterMoveSeq("em0"); got != 0 {
		t.Fatalf("seq after a failed bind = %d, want 0", got)
	}
}

func TestVRFMasterMoveSeqCountsADetach18597(t *testing.T) {
	_, em0, v := newMoveFixture18597()
	em0.Attrs().MasterIndex = 50
	detached, err := v.UnbindInterfaceFromVRFs("em0", []string{"mgmt"})
	if err != nil || !detached {
		t.Fatalf("precondition: UnbindInterfaceFromVRFs = %v, %v; want detached", detached, err)
	}
	if got := v.MasterMoveSeq("em0"); got != 1 {
		t.Fatalf("seq after a detach = %d, want 1", got)
	}
	if got := v.MasterMoveSeq("fxp0"); got != 0 {
		t.Fatalf("seq for an untouched link = %d, want 0 (counts are per link)", got)
	}
}
