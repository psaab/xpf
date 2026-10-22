package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"golang.org/x/sync/semaphore"
)

// #16124 equivalence precondition (test-only; must pass before the registry
// move and keep passing after it): the event route and the reconcile route
// must produce the same observable rg_active outcome for the same
// authoritative cluster state.
//
//   - EVENT: handleClusterEvent feeds a cluster transition through
//     rgStateMachine.SetCluster and actuates on the edge.
//   - RECONCILE: reconcileRGState re-derives cluster primary from
//     cluster.IsLocalPrimary and feeds rgStateMachine.Reconcile.
//
// The event-side observation is frozen BEFORE any reconciliation runs on the
// event daemon, so reconcile cannot repair a missing event-side actuation
// before the comparison. Each route is then compared against that frozen
// observation and the expected final state; only after those independent
// checks does reconciling the event daemon run as a separate fixed-point
// assertion.
//
// If the two routes disagree, a dropped event is not healed by the next
// reconcile pass — it is a silent divergence in who forwards.

// perRGActuationHA records writes per RG. actuationHA.writes is a flat
// interleaving across RGs, so the RG0 traffic reconcile also drives in
// these fixtures would corrupt a last-write comparison for RG1.
type perRGActuationHA struct {
	actuationHA
	byRG map[int][]bool
}

func (h *perRGActuationHA) SetRGActive(_ context.Context, rgID int, active bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.byRG == nil {
		h.byRG = make(map[int][]bool)
	}
	h.byRG[rgID] = append(h.byRG[rgID], active)
	h.writes = append(h.writes, active)
	return h.err
}

func (h *perRGActuationHA) writesFor(rgID int) []bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]bool(nil), h.byRG[rgID]...)
}

type perRGActuationDP struct {
	dataplane.RuntimeDataPlane
	ha *perRGActuationHA
}

func (d *perRGActuationDP) HA() dataplane.HAController      { return d.ha }
func (d *perRGActuationDP) Mode() dpuserspace.DataplaneMode { return dpuserspace.ModeUserspaceStrict }

func actuationWrites(ha *perRGActuationHA) []bool { return ha.writesFor(1) }

type actuationObservation16124 struct {
	writes  []bool
	desired bool
	applied bool
}

func observeActuation16124(t *testing.T, ha *perRGActuationHA, d *Daemon) actuationObservation16124 {
	t.Helper()
	s := d.getOrCreateRGState(1)
	return actuationObservation16124{
		writes:  actuationWrites(ha),
		desired: s.IsActive(),
		applied: s.AppliedActive(),
	}
}

func requireObservation16124(t *testing.T, route string, got actuationObservation16124, wantActive bool) {
	t.Helper()
	if len(got.writes) == 0 {
		t.Fatalf("%s route wrote no rg_active value, want final write %v", route, wantActive)
	}
	if got.writes[len(got.writes)-1] != wantActive {
		t.Fatalf("%s route final rg_active=%v want %v (writes=%v)", route, got.writes[len(got.writes)-1], wantActive, got.writes)
	}
	if got.desired != wantActive {
		t.Fatalf("%s route desired active=%v want %v", route, got.desired, wantActive)
	}
	if got.applied != wantActive {
		t.Fatalf("%s route applied active=%v want %v", route, got.applied, wantActive)
	}
}

func requireSameObservation16124(t *testing.T, route string, got, want actuationObservation16124, wantActive bool) {
	t.Helper()
	requireObservation16124(t, route, got, wantActive)
	if len(got.writes) == 0 || len(want.writes) == 0 {
		t.Fatalf("%s route writes=%v, frozen event writes=%v; both routes must write rg_active", route, got.writes, want.writes)
	}
	if got.writes[len(got.writes)-1] != want.writes[len(want.writes)-1] {
		t.Fatalf("%s route final rg_active=%v, frozen event final=%v (writes %s=%v event=%v)",
			route, got.writes[len(got.writes)-1], want.writes[len(want.writes)-1], route, got.writes, want.writes)
	}
	if got.desired != want.desired {
		t.Fatalf("%s route desired active=%v, frozen event desired=%v", route, got.desired, want.desired)
	}
	if got.applied != want.applied {
		t.Fatalf("%s route applied active=%v, frozen event applied=%v", route, got.applied, want.applied)
	}
}

// TestEventVsReconcileEquivalence16124: promotion and demotion each driven
// (a) by their cluster event and (b) by reconcile alone after the event is
// dropped (authoritative cluster state moved via SetGroupStateForTesting).
// The event result is asserted before the event daemon is reconciled; the
// reconcile-only result must independently match the frozen event result
// and the expected state, and reconciling the event daemon afterwards must
// be a fixed point.
func TestEventVsReconcileEquivalence16124(t *testing.T) {
	t.Run("promotion", func(t *testing.T) {
		// Both daemons start cluster-secondary; the only difference is how
		// the promotion is observed. Installing applySem covers the
		// post-edge republish goroutines handleClusterEvent schedules.
		haEvent := &perRGActuationHA{}
		dEvent := newActuationDaemon(t, &haEvent.actuationHA)
		dEvent.setDataplane(&perRGActuationDP{ha: haEvent})
		dEvent.applySem = semaphore.NewWeighted(1)
		haRecon := &perRGActuationHA{}
		dRecon := newActuationDaemon(t, &haRecon.actuationHA)
		dRecon.setDataplane(&perRGActuationDP{ha: haRecon})
		dRecon.applySem = semaphore.NewWeighted(1)
		for _, d := range []*Daemon{dEvent, dRecon} {
			d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
		}
		// Event route: authoritative state and delivered event agree.
		dEvent.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		if timer := dEvent.handleClusterEvent(context.Background(), cluster.ClusterEvent{
			GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
		}, nil); timer != nil {
			timer.Stop()
		}
		eventObs := observeActuation16124(t, haEvent, dEvent)
		requireObservation16124(t, "event", eventObs, true)

		// Reconcile route: authoritative state moves to primary, event
		// dropped; reconcile alone must reach the frozen event outcome.
		dRecon.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		for range 3 {
			dRecon.reconcileRGState()
		}
		requireSameObservation16124(t, "reconcile", observeActuation16124(t, haRecon, dRecon), eventObs, true)

		// Separate fixed-point check: reconciling the event daemon now
		// must not change its already-compared outcome.
		for range 3 {
			dEvent.reconcileRGState()
		}
		requireSameObservation16124(t, "event-after-reconcile", observeActuation16124(t, haEvent, dEvent), eventObs, true)
	})

	t.Run("demotion", func(t *testing.T) {
		// Event route: prime primary, then deliver the demotion event.
		haEvent := &perRGActuationHA{}
		dEvent := newActuationDaemon(t, &haEvent.actuationHA)
		dEvent.setDataplane(&perRGActuationDP{ha: haEvent})
		dEvent.applySem = semaphore.NewWeighted(1)
		primeRG1Primary(t, dEvent)
		demoteRG1(t, dEvent)
		eventObs := observeActuation16124(t, haEvent, dEvent)
		requireObservation16124(t, "event", eventObs, false)

		// Reconcile route: prime the state machine primary, then move only
		// the authoritative cluster state to secondary (event dropped) and
		// let reconcile reach the frozen event outcome.
		haRecon := &perRGActuationHA{}
		dRecon := newActuationDaemon(t, &haRecon.actuationHA)
		dRecon.setDataplane(&perRGActuationDP{ha: haRecon})
		dRecon.applySem = semaphore.NewWeighted(1)
		primeRG1Primary(t, dRecon)
		// ManualFailover moves RG1 to StateSecondaryHold, not StateSecondary.
		dRecon.cluster.SetGroupStateForTesting(1, cluster.StateSecondaryHold)
		for range 3 {
			dRecon.reconcileRGState()
		}
		requireSameObservation16124(t, "reconcile", observeActuation16124(t, haRecon, dRecon), eventObs, false)

		// Separate fixed-point check after the independent comparison.
		for range 3 {
			dEvent.reconcileRGState()
		}
		requireSameObservation16124(t, "event-after-reconcile", observeActuation16124(t, haEvent, dEvent), eventObs, false)
	})

	t.Run("held promotion reconciled after release", func(t *testing.T) {
		testHeldPromotionRoute16124(t)
	})
}

func testHeldPromotionRoute16124(t *testing.T) {
	t.Helper()
	// The shared-predicate case (#15258): with sync-hold armed, neither
	// route may activate the RG. Both fixtures receive the same
	// authoritative primary state before either route is presented; only
	// delivery differs. The event is captured pre-reconcile.
	haEvent := &perRGActuationHA{}
	dEvent := newRethFenceDaemon(t, &haEvent.actuationHA, newFakeVIPRelease())
	dEvent.setDataplane(&perRGActuationDP{ha: haEvent})
	haRecon := &perRGActuationHA{}
	dRecon := newRethFenceDaemon(t, &haRecon.actuationHA, newFakeVIPRelease())
	dRecon.setDataplane(&perRGActuationDP{ha: haRecon})
	for _, d := range []*Daemon{dEvent, dRecon} {
		d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		d.vrrpMgr.SetSyncHold(time.Hour)
		d.applySem = semaphore.NewWeighted(1)
	}
	if timer := dEvent.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil); timer != nil {
		timer.Stop()
	}
	eventHeldObs := observeActuation16124(t, haEvent, dEvent)
	if len(eventHeldObs.writes) != 0 {
		t.Fatalf("held event route wrote rg_active %v, want no writes", eventHeldObs.writes)
	}
	if eventHeldObs.desired || eventHeldObs.applied {
		t.Fatalf("held event route desired=%v applied=%v, want both false", eventHeldObs.desired, eventHeldObs.applied)
	}
	for range 3 {
		dRecon.reconcileRGState()
	}
	reconHeldObs := observeActuation16124(t, haRecon, dRecon)
	if len(reconHeldObs.writes) != 0 {
		t.Fatalf("held reconcile route wrote rg_active %v, want no writes", reconHeldObs.writes)
	}
	if reconHeldObs.desired || reconHeldObs.applied {
		t.Fatalf("held reconcile route desired=%v applied=%v, want both false", reconHeldObs.desired, reconHeldObs.applied)
	}
	for range 3 {
		dEvent.reconcileRGState()
	}
	eventHeldAfterRecon := observeActuation16124(t, haEvent, dEvent)
	if len(eventHeldAfterRecon.writes) != 0 || eventHeldAfterRecon.desired || eventHeldAfterRecon.applied {
		t.Fatalf("held event route after reconcile = %+v, want no writes and inactive", eventHeldAfterRecon)
	}

	dEvent.vrrpMgr.ReleaseSyncHold()
	dRecon.vrrpMgr.ReleaseSyncHold()
	dEvent.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	dRecon.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)

	for range 3 {
		dEvent.reconcileRGState()
		dRecon.reconcileRGState()
	}
	requireSameObservation16124(t, "released reconcile", observeActuation16124(t, haRecon, dRecon), observeActuation16124(t, haEvent, dEvent), true)
}
