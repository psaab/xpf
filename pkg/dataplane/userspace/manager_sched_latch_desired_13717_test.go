package userspace

import "testing"

// #13717 (D18-22): UpdatePolicyScheduleStateWithLatch and
// PublishRouteOverlaySnapshotWithLatch stage the desired scheduler map
// into m.policySchedulerDesired(+Set) but — unlike the sibling setter
// SetPolicySchedulerActiveStateWithLatch — never stage
// m.policySchedulerDesiredFailClosed. policySchedulerDesiredStateAndFailClosedSnapshot
// therefore pairs the new map with a stale latch, which a later Compile
// reads back, in both directions:
//
//   - latch activated (failClosed=true) through either setter while the
//     helper is down (early return before publish): the later Compile
//     lowers scheduled policies with stale false — retained stale permits.
//   - latch cleared (failClosed=false) through either setter after an
//     earlier Set...WithLatch latched true: Compile keeps failing closed.
//
// The live daemon scheduler-tick path is shielded by its immediate seed
// call, but the route-overlay callers and any early-return update are
// exposed. Both setters below run with cfg == nil and no published
// snapshot, hitting the converged early returns after staging.
func TestWithLatchSettersStageFailClosedForSubsequentCompile13717(t *testing.T) {
	seedMap := map[string]bool{"workhours": true}
	newMap := map[string]bool{"workhours": false}
	wantMap := func(t *testing.T, got map[string]bool) {
		t.Helper()
		if len(got) != 1 || got["workhours"] != false {
			t.Fatalf("desired map = %v; want staged %v", got, newMap)
		}
	}

	// Direction 1 (fail-open): latch activates fail-closed=true staging.
	t.Run("update_activates", func(t *testing.T) {
		m := New()
		m.SetPolicySchedulerActiveStateWithLatch(seedMap, false)
		if err := m.UpdatePolicyScheduleStateWithLatch(nil, newMap, true); err != nil {
			t.Fatalf("UpdatePolicyScheduleStateWithLatch: %v", err)
		}
		got, failClosed := m.policySchedulerDesiredStateAndFailClosedSnapshot()
		wantMap(t, got)
		if !failClosed {
			t.Fatal("UpdatePolicyScheduleStateWithLatch staged the map but left failClosed=false; a later Compile would lower scheduled policies fail-open")
		}
		if err := m.UpdatePolicyScheduleStateWithLatch(nil, newMap, false); err != nil {
			t.Fatalf("UpdatePolicyScheduleStateWithLatch(clear): %v", err)
		}
		if _, failClosed := m.policySchedulerDesiredStateAndFailClosedSnapshot(); failClosed {
			t.Fatal("UpdatePolicyScheduleStateWithLatch cleared the latch in its map but left failClosed=true; a later Compile would stay fail-closed")
		}
	})
	t.Run("overlay_activates", func(t *testing.T) {
		m := New()
		m.SetPolicySchedulerActiveStateWithLatch(seedMap, false)
		published, err := m.PublishRouteOverlaySnapshotWithLatch(nil, nil, newMap, true)
		if err != nil {
			t.Fatalf("PublishRouteOverlaySnapshotWithLatch: %v", err)
		}
		if published {
			t.Fatal("expected no publish with no snapshot/helper")
		}
		got, failClosed := m.policySchedulerDesiredStateAndFailClosedSnapshot()
		wantMap(t, got)
		if !failClosed {
			t.Fatal("PublishRouteOverlaySnapshotWithLatch staged the map but left failClosed=false; a later Compile would lower scheduled policies fail-open")
		}
		if _, err := m.PublishRouteOverlaySnapshotWithLatch(nil, nil, newMap, false); err != nil {
			t.Fatalf("PublishRouteOverlaySnapshotWithLatch(clear): %v", err)
		}
		if _, failClosed := m.policySchedulerDesiredStateAndFailClosedSnapshot(); failClosed {
			t.Fatal("PublishRouteOverlaySnapshotWithLatch cleared the latch in its map but left failClosed=true; a later Compile would stay fail-closed")
		}
	})

	// Direction pre-condition: a nil overlay schedulerState must not
	// clobber the staged latch (route-apply caller carries no state).
	t.Run("overlay_nil_keeps", func(t *testing.T) {
		m := New()
		m.SetPolicySchedulerActiveStateWithLatch(seedMap, true)
		if _, err := m.PublishRouteOverlaySnapshotWithLatch(nil, nil, nil, false); err != nil {
			t.Fatalf("PublishRouteOverlaySnapshotWithLatch(nil state): %v", err)
		}
		got, failClosed := m.policySchedulerDesiredStateAndFailClosedSnapshot()
		if len(got) != 1 || got["workhours"] != true || !failClosed {
			t.Fatalf("nil overlay scheduler state clobbered staged pair: map=%v failClosed=%t", got, failClosed)
		}
	})
}
