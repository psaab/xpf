package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #16692 (R3-A34-03): in legacy no-private-rg-election mode,
// watchVRRPEvents never refreshed the #15258 sync-hold mirror. The
// preempt MASTER event that ReleaseSyncHold itself triggers was judged
// against syncHold=true (no rg_active write, no services), and the later
// syncRGSyncHold in handleClusterEvent / reconcileRGState discarded the
// transition its own SetSyncHold produced — so neither path saw
// tr.Changed and the RG's service edge was lost.
//
// Fix: every per-event handler (watchVRRPEvents, watchClusterEvents,
// handleClusterEvent) refreshes the mirror scoped to its RG before
// feeding its input and merges the refresh transition; reconcileRGState
// ORs the pass-wide refresh into each RG's tr.
//
// The services observable is the proxy-ARP nudge that
// applyRethServicesForRG always sends (and no other path in these
// handlers sends) — the same observable the source probe used.
//
// RED on revert: drop the mirror refresh/merge in watchVRRPEvents (held
// row: services=false, 0 writes), in watchClusterEvents/handleClusterEvent
// (promotion row), or the OR in reconcileRGState (release-only row).

// syncHoldVRRPDaemon16692 builds the legacy RETH-VRRP fixture: the
// #14406 fence daemon (no-private-rg-election, so isNoRethVRRP is false)
// plus the proxy-ARP nudge channel applyRethServicesForRG publishes to.
func syncHoldVRRPDaemon16692(t *testing.T, ha *actuationHA) *Daemon {
	t.Helper()
	d := newRethFenceDaemon(t, ha, newFakeVIPRelease())
	d.setDataplane(&actuationDP{ha: ha})
	d.proxyARPNudgeCh = make(chan struct{}, 16)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	return d
}

func countNudges16692(t *testing.T, d *Daemon) int {
	t.Helper()
	n := 0
	for {
		select {
		case <-d.proxyARPNudgeCh:
			n++
		default:
			return n
		}
	}
}

// primeHeldRG1MASTER16692 arms the sync hold, mirrors it onto RG1's
// state machine, and records the suppressed MASTER input — the posture
// Node B sits in just before bulk sync releases the hold and
// triggerPreemptNow produces the real MASTER event.
func primeHeldRG1MASTER16692(t *testing.T, d *Daemon) {
	t.Helper()
	d.vrrpMgr.SetSyncHold(time.Hour)
	t.Cleanup(d.vrrpMgr.ReleaseSyncHold)
	s := d.getOrCreateRGState(1)
	if !s.SyncHeld() {
		t.Fatal("setup: RG1 state created during hold must carry syncHold=true (#15258 seed)")
	}
	if tr := s.SetVRRP("reth1", true); tr.Changed || tr.Active {
		t.Fatalf("setup: held SetVRRP(MASTER) must be suppressed (Changed=false Active=false), got %+v", tr)
	}
	if s.IsActive() {
		t.Fatal("setup: held RG1 must be desired-inactive")
	}
}

// TestSyncHoldReleaseVRRPMasterRunsServices16692 is the probe's held row:
// hold armed and mirrored, ReleaseSyncHold, then the preempt MASTER event
// ReleaseSyncHold itself triggers must run rg_active + services.
func TestSyncHoldReleaseVRRPMasterRunsServices16692(t *testing.T) {
	ha := &actuationHA{}
	d := syncHoldVRRPDaemon16692(t, ha)
	primeHeldRG1MASTER16692(t, d)

	d.vrrpMgr.ReleaseSyncHold()
	d.handleVRRPEvent(context.Background(),
		vrrp.VRRPEvent{Interface: "reth1", GroupID: rethVRIDBase + 1, State: vrrp.StateMaster},
		rgTransition{})

	if active, ok := ha.lastWrite(); !ok || !active {
		t.Fatalf("#16692: post-release VRRP MASTER wrote no rg_active=true (writes=%v), want a true write", ha.writes)
	}
	if n := countNudges16692(t, d); n != 1 {
		t.Fatalf("#16692: post-release VRRP MASTER ran applyRethServicesForRG %d times (proxy-ARP nudges), want exactly 1 — the service edge is still lost", n)
	}
	if !d.getOrCreateRGState(1).IsActive() {
		t.Fatal("#16692: RG1 must be desired-active after the post-release MASTER event")
	}
}

// TestSyncHoldReleaseOnlyReconcileRunsServices16692 is the acceptance's
// release-only pass: VRRP already MASTER (retained while held), the hold
// releases, and a reconcile pass with no new event must run
// applyRethServicesForRG exactly once — the refresh transition ORed into
// tr, not discarded by syncRGSyncHold.
func TestSyncHoldReleaseOnlyReconcileRunsServices16692(t *testing.T) {
	ha := &actuationHA{}
	d := syncHoldVRRPDaemon16692(t, ha)
	primeHeldRG1MASTER16692(t, d)

	// While held, reconcile must neither write nor serve (control row).
	d.reconcileRGState()
	if n := ha.writeCount(); n != 0 {
		t.Fatalf("control: held reconcile wrote rg_active %d times, want 0 (#15258)", n)
	}
	if n := countNudges16692(t, d); n != 0 {
		t.Fatalf("control: held reconcile ran services %d times, want 0", n)
	}

	d.vrrpMgr.ReleaseSyncHold()
	d.reconcileRGState()

	if active, ok := ha.lastWrite(); !ok || !active {
		t.Fatalf("#16692: release-only reconcile wrote no rg_active=true (writes=%v), want a true write", ha.writes)
	}
	if n := countNudges16692(t, d); n != 1 {
		t.Fatalf("#16692: release-only reconcile ran applyRethServicesForRG %d times, want exactly 1 — syncRGSyncHold still discards its own transition", n)
	}

	// Steady state: a further pass must not re-run the edge.
	d.reconcileRGState()
	if n := countNudges16692(t, d); n != 0 {
		t.Fatalf("#16692: steady-state reconcile re-ran services %d times, want 0 (edge, not level)", n)
	}
}

// TestSyncHoldReleaseClusterPromotionActivates16692 covers the sibling
// producer on the cluster path: the promotion event is suppressed while
// held, and after release the same promotion must activate — the mirror
// refresh inside handleClusterEvent must not swallow the retained
// clusterPri edge.
func TestSyncHoldReleaseClusterPromotionActivates16692(t *testing.T) {
	ha := &actuationHA{}
	d := syncHoldVRRPDaemon16692(t, ha)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)

	d.vrrpMgr.SetSyncHold(time.Hour)
	defer d.vrrpMgr.ReleaseSyncHold()
	// Record clusterPri while held: desired stays suppressed.
	if tr := d.getOrCreateRGState(1).SetCluster(true); tr.Active {
		t.Fatalf("setup: held SetCluster(true) must stay inactive, got %+v", tr)
	}

	d.vrrpMgr.ReleaseSyncHold()
	if timer := d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil); timer != nil {
		timer.Stop()
	}
	if active, ok := ha.lastWrite(); !ok || !active {
		t.Fatalf("#16692: post-release cluster promotion wrote no rg_active=true (writes=%v), want a true write", ha.writes)
	}
	if !d.getOrCreateRGState(1).IsActive() {
		t.Fatal("#16692: RG1 must be desired-active after the post-release promotion")
	}
}

// TestSyncHoldWatcherRefreshScopesToHandledRG16692 pins the scoping:
// refreshing for RG1's event must not consume RG2's pending release
// edge. RG2 keeps its stale mirror until reconcile, which then actuates
// it — refresh-and-discard on an unrelated RG would lose that edge.
func TestSyncHoldWatcherRefreshScopesToHandledRG16692(t *testing.T) {
	ha := &actuationHA{}
	d := syncHoldVRRPDaemon16692(t, ha)
	// RG2 must exist in the cluster manager for reconcile to discover
	// it: UpdateConfig only creates groups named in the config, and
	// SetGroupStateForTesting is a no-op for an unknown group. The
	// daemon's ClusterConfig comes from cm.UpdateConfig (not the
	// store), so adding RG2 here does not change isNoRethVRRP.
	d.cluster.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
			{ID: 1, NodePriorities: map[int]int{0: 200}},
			{ID: 2, NodePriorities: map[int]int{0: 200}},
		},
	})
	d.vrrpMgr.SetSyncHold(time.Hour)
	defer d.vrrpMgr.ReleaseSyncHold()
	// The reconcile loop only visits RGs it can discover (existing
	// states, cluster groups, live VRRP instances); register RG2 with
	// the cluster manager as reconcile would see a configured group.
	// Its VRRP instance is simulated at the state-machine level (no live
	// instance in the manager), so reconcile re-feeds an empty VRRP set
	// and the retained edge must come from SetCluster(true) below.
	d.cluster.SetGroupStateForTesting(2, cluster.StatePrimary)
	for _, rgID := range []int{1, 2} {
		s := d.getOrCreateRGState(rgID)
		if tr := s.SetVRRP("reth1", true); tr.Active {
			t.Fatalf("setup: held RG%d SetVRRP(MASTER) must stay inactive, got %+v", rgID, tr)
		}
	}
	if tr := d.getOrCreateRGState(2).SetCluster(true); tr.Active {
		t.Fatalf("setup: held RG2 SetCluster(true) must stay inactive, got %+v", tr)
	}
	d.vrrpMgr.ReleaseSyncHold()

	// RG1's MASTER event refreshes RG1 only.
	s2 := d.getOrCreateRGState(2)
	_ = d.syncRGSyncHoldTransition(d.getOrCreateRGState(1))
	if !s2.SyncHeld() {
		t.Fatal("#16692: RG1's refresh cleared RG2's mirror — the pass-wide consume is back")
	}
	// Reconcile actuates RG2's retained edge.
	d.reconcileRGState()
	if s2.SyncHeld() {
		t.Fatal("#16692: reconcile must refresh RG2's mirror")
	}
	if !s2.IsActive() {
		t.Fatal("#16692: RG2 must be desired-active after the release-only reconcile")
	}
}
