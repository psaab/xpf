package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #9120: FenceAckOK's prose said the peer "confirms it relinquished every RG it
// knows about, which is the property a takeover gate should be built on".
//
// This cell PINS WHAT THE ACK ACTUALLY PROVES, so the gap cannot widen in
// silence and no future gate is built on the stronger reading:
//
//  1. the fence drives rg_active=false for every live-config RG   (it does)
//  2. it does NOT change cluster state — clusterPri stays true    (it does not)
//  3. it does NOT release VIPs                                    (it does not)
//  4. the very next reconcile pass re-drives rg_active=true       (it does)
//
// (4) is #6530's pinned behaviour and this cell is deliberately its COUNTERPART
// rather than its inversion: TestFenceRearmsReconcileRetry asserts the retry
// must re-drive, and it must keep passing. What #9120 adds is that the retry
// re-driving is the same event as the fence EXPIRING — so the durability of the
// relinquishment is one reconcile interval, not indefinite.
//
// AND THE REFRAMING THAT MATTERS FOR THE REAL FIX: the revert is NOT the fence
// being undone. `desired = clusterPri || allVrrpMaster`, and the fence changes
// NEITHER input — so the state machine correctly observes that desired is still
// true and retries an apply that never should have been reverted. #6530 is
// about retrying a FAILED apply; it does not exist to undo a fence, and a
// future fix that makes the fence a cluster-state event (dropping clusterPri)
// does not contradict it — it removes the input that keeps desired true.
func TestFenceAckProvesDataplaneSuppressionOnly9120(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9120",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	// #16746: a complete control link is now required, and with one the
	// private-RG election waits for the peer instead of electing a lone
	// node primary (the dual-primary shape the gate forbids). This cell
	// tests the daemon's fence/rg_active handling, not the election, so
	// it states the precondition directly.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)

	rec := &rearmRecorderHA{}
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cm,
		store:    store,
		vrrpMgr:  vrrp.NewManager(),
	}
	d.setDataplane(&rearmRecorderDP{Manager: dataplane.New(), ha: rec})

	if !cm.IsLocalPrimary(1) {
		t.Fatal("fixture: node 0 must be primary for RG1, else there is nothing to fence")
	}
	d.reconcileRGState()
	if got := rec.countOf(rgActiveWrite{rgID: 1, active: true}); got == 0 {
		t.Fatalf("fixture: the first reconcile never activated RG1; the cell would be vacuous")
	}
	rec.take()

	// Count the VIP resignations the fence performs. The production override
	// seam exists for exactly this kind of observation.
	resigns := 0
	d.resignRethRGFn = func(rgID int) vipReleaseBarrier {
		resigns++
		return nil
	}

	res := d.fenceAllRedundancyGroups(context.Background())

	// (1) what the ack REPORTS is true: every live-config RG was driven false.
	if res.RGsFenced != res.RGsTotal || res.RGsTotal == 0 {
		t.Errorf("fence reported %d/%d RGs; the ack claims every live-config RG (#9120)",
			res.RGsFenced, res.RGsTotal)
	}
	sawFence := false
	for _, w := range rec.take() {
		if w == (rgActiveWrite{rgID: 1, active: false}) {
			sawFence = true
		}
	}
	if !sawFence {
		t.Fatal("fixture: the fence never deactivated RG1")
	}

	// (2) THE ACK DOES NOT PROVE the node stopped believing it is primary.
	if !cm.IsLocalPrimary(1) {
		t.Log("NOTE: the fence now clears cluster primary. If that is deliberate, " +
			"FenceAckOK's guarantee has STRENGTHENED and this cell plus the docs in " +
			"sync_fence_ack_7147.go should be re-derived rather than edited (#9120)")
	}

	// (3) THE ACK DOES NOT PROVE the VIPs moved. This is the half an operator
	// selecting `disable-rg-confirmed` is most likely to assume.
	if resigns != 0 {
		t.Logf("NOTE: the fence now performs %d VIP resignation(s). Same as above: "+
			"the guarantee has strengthened and the documentation must be re-derived "+
			"(#9120)", resigns)
	}
	// POSITIVE CONTROL for the line above. `resigns == 0` has two readings —
	// "the fence performs no VIP resignation" and "my override was never
	// installed, so nothing could have counted" — and only one of them is a
	// statement about the fence. Drive the seam directly and require it to
	// move, so the zero above is a MEASUREMENT rather than a silence.
	d.resignRethRG(1)
	if resigns != 1 {
		t.Fatalf("positive control: resignRethRGFn did not fire (resigns=%d); the "+
			"VIP observation above was vacuous and asserts nothing (#9120)", resigns)
	}

	// (4) THE RELINQUISHMENT EXPIRES ON THE NEXT RECONCILE PASS. This is
	// #6530's required behaviour, asserted here as the DURABILITY BOUND of the
	// ack rather than as a defect.
	d.reconcileRGState()
	if got := rec.countOf(rgActiveWrite{rgID: 1, active: true}); got == 0 {
		t.Errorf("the reconcile after a fence did not re-drive rg_active=true: #6530's " +
			"retry is what bounds this ack's guarantee at one reconcile interval, and " +
			"TestFenceRearmsReconcileRetry pins it as required (#9120)")
	}
}
