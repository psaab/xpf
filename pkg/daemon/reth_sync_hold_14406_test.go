package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #14406 (DR12-H2): RETH VRRP sync-hold is bypassed by cluster promotion.
//
// The NoRETH sibling gates its identical startup hold through takeover
// readiness (checkNoRethTakeoverReadiness, #7162). The RETH branch of
// takeoverReadinessForRG consulted only RGVRRPReady (instance
// built-ness), so with sync-hold active, a healthy peer primary, and
// locally higher priority/preempt, cluster election promoted the
// boot-fresh node to Primary before bulk session sync; handleClusterEvent
// then called UpdateRGPriority(200)+ForceRGMaster, whose
// forcePreemptOnce bypasses the Preempt=false the hold installed.
// Gating ForceRGMaster alone is not sufficient because cluster-primary
// alone activates rg_active.
//
// RED on revert: drop the InSyncHold term in takeoverReadinessForRG
// (readiness cell goes ready while held) or the InSyncHold guard in
// handleClusterEvent (promotion cell activates rg_active while held).

func rethHoldDaemon14406(t *testing.T) *Daemon {
	t.Helper()
	d := newRethFenceDaemon(t, &actuationHA{}, newFakeVIPRelease())
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	return d
}

func TestRethSyncHoldBlocksTakeoverReadiness14406(t *testing.T) {
	d := rethHoldDaemon14406(t)
	// Precondition: without the hold, all other terms true => ready.
	// (No RETH interfaces in fence config => RGVRRPReady true via
	// !hasRETH; userspace/interface/fabric terms are passed true.)
	if ready, reasons := d.takeoverReadinessForRG(d.dataplane(), 1, true, nil, true, false); !ready {
		t.Fatalf("precondition: RG must be ready without hold, reasons=%v", reasons)
	}
	d.vrrpMgr.SetSyncHold(time.Hour)
	defer d.vrrpMgr.ReleaseSyncHold()

	ready, reasons := d.takeoverReadinessForRG(d.dataplane(), 1, true, nil, true, false)
	if ready {
		t.Fatal("sync-hold active: RETH RG must not be takeover-ready before bulk sync (#14406)")
	}
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "session sync startup hold") {
			found = true
		}
	}
	if !found {
		t.Fatalf("readiness reasons = %v, want session-sync startup hold reason", reasons)
	}

	d.vrrpMgr.ReleaseSyncHold()
	if ready, reasons := d.takeoverReadinessForRG(d.dataplane(), 1, true, nil, true, false); !ready {
		t.Fatalf("after ReleaseSyncHold the RG must be takeover-ready: reasons=%v", reasons)
	}
}

// Boot pin: fresh groups start StateSecondary (group_state.go), so the
// first promotion is Secondary->Primary — NOT the SecondaryHold->Primary
// exemption the pre-fix handleClusterEvent comment claimed. While held,
// that promotion must not activate the RG; after release it must.
func TestRethSyncHoldBootPromotion14406(t *testing.T) {
	d := rethHoldDaemon14406(t)
	ha := &actuationHA{}
	d.setDataplane(&actuationDP{ha: ha})

	if st := d.cluster.GroupState(1); st == nil || st.State != cluster.StateSecondary {
		t.Fatalf("boot posture: RG1 state = %v, want StateSecondary", st)
	}
	d.vrrpMgr.SetSyncHold(time.Hour)
	defer d.vrrpMgr.ReleaseSyncHold()

	if timer := d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil); timer != nil {
		timer.Stop()
	}
	if n := ha.writeCount(); n != 0 {
		t.Fatalf("sync-hold active: Secondary->Primary must not write rg_active, got %d writes %v (#14406)", n, ha.writes)
	}
	if d.getOrCreateRGState(1).IsActive() {
		t.Fatal("sync-hold active: RG must stay inactive/secondary in rgStateMachine (#14406)")
	}

	d.vrrpMgr.ReleaseSyncHold()
	if timer := d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil); timer != nil {
		timer.Stop()
	}
	if n := ha.writeCount(); n == 0 {
		t.Fatal("after ReleaseSyncHold, Secondary->Primary must activate the RG")
	}
	if active, ok := ha.lastWrite(); !ok || !active {
		t.Fatalf("after ReleaseSyncHold, last rg_active write = %v/%v, want true", active, ok)
	}
}

// #15258 (A89-02): the #14406 early return in handleClusterEvent drops
// the queued Primary event WITHOUT recording clusterPri, but the claim
// that "reconcile keeps desired inactive" was false: reconcileRGState
// re-derives clusterPri from d.cluster.IsLocalPrimary (which the
// election already set) and feeds it to s.Reconcile, bypassing the
// suppressed event entirely. Within one reconcile tick the held RG
// wrote rg_active=true. The fix mirrors InSyncHold into rgStateMachine
// (the #14404 kernel-upgrade-hold pattern) so event and reconcile share
// one predicate. Acceptance: held reconcile shows 0 writes; after
// ReleaseSyncHold + reconcile a true write lands.
func TestRethSyncHoldSurvivesReconcile15258(t *testing.T) {
	d := rethHoldDaemon14406(t)
	ha := &actuationHA{}
	d.setDataplane(&actuationDP{ha: ha})
	// Election has already made this node primary (the queued-event /
	// degraded-promotion shape the backstop exists for).
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.vrrpMgr.SetSyncHold(time.Hour)
	defer d.vrrpMgr.ReleaseSyncHold()

	if timer := d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil); timer != nil {
		timer.Stop()
	}
	d.reconcileRGState()
	if n := ha.writeCount(); n != 0 {
		t.Fatalf("sync-hold active: reconcile must not write rg_active, got %d writes %v (#15258)", n, ha.writes)
	}
	if d.getOrCreateRGState(1).IsActive() {
		t.Fatal("sync-hold active: RG must stay inactive after reconcile (#15258)")
	}

	d.vrrpMgr.ReleaseSyncHold()
	d.reconcileRGState()
	if active, ok := ha.lastWrite(); !ok || !active {
		t.Fatalf("after ReleaseSyncHold + reconcile, last rg_active write = %v/%v, want true (#15258)", active, ok)
	}
}
