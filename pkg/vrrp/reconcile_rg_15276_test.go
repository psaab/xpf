package vrrp

import (
	"net"
	"testing"
	"time"
)

// #15276 (C10-01), VRRP-mode leg: after a RETH member's virtual MAC changes
// without a link cycle, only the owning RG's MASTER instances may re-announce
// (forced GARP/NA). ReconcileVIPs already forces a GARP per MASTER instance
// but is all-RG; ReconcileVIPsForRG scopes the same reconcile to one RG so a
// live MAC change on one RG's member does not re-announce every RG.
//
// RED-on-revert: point ReconcileVIPsForRG at every instance (drop the RG
// filter) and this fails at "RG2 was announced".

// masterRethInstance15276 builds a MASTER RETH instance (Family empty, as
// CollectRethInstances emits) with no VIPs, so reconcileVIP runs its epoch
// bump + forced sendGARP gate without any netlink or raw-socket I/O — the
// send still advances lastGARPEpoch, which is the observable.
func masterRethInstance15276(t *testing.T, iface string, vrid int) *vrrpInstance {
	t.Helper()
	vi := newInstance(Instance{
		Interface:        iface,
		GroupID:          vrid,
		Priority:         200,
		VirtualAddresses: nil,
	}, &net.Interface{Name: iface}, make(chan VRRPEvent, 8), nil)
	vi.setState(StateMaster)
	return vi
}

func managerWithRethMasters15276(t *testing.T) (*Manager, *vrrpInstance, *vrrpInstance) {
	t.Helper()
	m := NewManager()
	rg1 := masterRethInstance15276(t, "reth0", 101) // VRID 101 = RG 1
	rg2 := masterRethInstance15276(t, "reth1", 102) // VRID 102 = RG 2
	// A routine GARP completed for epoch 1 moments ago; a reconcile-driven
	// forced send must still advance past it (#2081 dampener bypass).
	for _, vi := range []*vrrpInstance{rg1, rg2} {
		vi.garpEpoch.Store(1)
		vi.lastGARPEpoch.Store(1)
		vi.lastGARPTime.Store(time.Now().Add(-50 * time.Millisecond).UnixNano())
	}
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "reth0", groupID: 101}: rg1,
		{iface: "reth1", groupID: 102}: rg2,
	}
	m.mu.Unlock()
	return m, rg1, rg2
}

func TestReconcileVIPsForRGAnnouncesOnlyThatRG_15276(t *testing.T) {
	m, rg1, rg2 := managerWithRethMasters15276(t)

	m.ReconcileVIPsForRG(1)

	if got := rg1.garpEpoch.Load(); got != 2 {
		t.Fatalf("RG1 garpEpoch = %d, want 2: the owning RG was not reconciled", got)
	}
	if got := rg1.lastGARPEpoch.Load(); got != 2 {
		t.Fatalf("RG1 lastGARPEpoch = %d, want 2: the forced post-MAC-change GARP "+
			"for the owning RG was not emitted (#15276)", got)
	}
	if got := rg2.garpEpoch.Load(); got != 1 {
		t.Fatalf("RG2 garpEpoch = %d, want 1: an unrelated RG was announced by a "+
			"MAC change on RG1's member (#15276)", got)
	}
	if got := rg2.lastGARPEpoch.Load(); got != 1 {
		t.Fatalf("RG2 lastGARPEpoch = %d, want 1: an unrelated RG emitted a GARP (#15276)", got)
	}
}

// TestReconcileVIPsForRGOutOfRangeIsNoop_15276 pins the VRID fence: an RG ID
// with no valid synthesized VRID must not announce anything (and must not
// alias VRID 0 or another RG's instances).
func TestReconcileVIPsForRGOutOfRangeIsNoop_15276(t *testing.T) {
	m, rg1, rg2 := managerWithRethMasters15276(t)

	for _, rgID := range []int{0, -1, 200} {
		m.ReconcileVIPsForRG(rgID)
	}
	for _, vi := range []*vrrpInstance{rg1, rg2} {
		if got := vi.lastGARPEpoch.Load(); got != 1 {
			t.Fatalf("out-of-range ReconcileVIPsForRG emitted a GARP: lastGARPEpoch = %d, want 1", got)
		}
	}
}
