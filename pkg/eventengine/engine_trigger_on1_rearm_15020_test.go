package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Regression tests for #15020 (A14-01): `within N { trigger on 1; }` could
// never re-arm. evaluateEvent appends the current event to the window BEFORE
// withinMatches runs, so with TriggerOn==1 the in-window count (including
// the current event) is always >= 1 on every event that reaches
// withinMatches. The old re-arm branch — `counts[i] < wc.TriggerOn` — was
// therefore unreachable for N=1: once the first crossing latched
// rt.onLatched, no later event could ever clear it, and the policy fired
// exactly once per daemon lifetime (or per runtime carry across a
// same-revision Apply). The shipped lab pair in test/incus/xpf-test.conf —
// failover-on-probe-fail / restore-on-probe-success, both
// `within 60 { trigger on 1; }` — went dead after its first use.
//
// The fix re-arms on WINDOW DECAY: the count EXCLUDING the current event
// (which evaluateEvent already appended) is what must have dropped below
// the threshold. For N=1 that means "no prior event is still inside the
// window" — the previous occurrence has aged out, so this event is a fresh
// isolated edge. For N>1, while a sustained burst remains inside the
// window its pre-event count stays >= N (the in-window count never falls
// between events), so the sustained-level suppression is unchanged; the
// pre-event formulation only differs at the decaying tail, where the old
// code already re-armed one event earlier with the same observable
// outcome (suppressed below threshold, fire on the next crossing).
//
// These drive the real evaluate path (evaluateEvent) on a deterministic
// clock, mirroring feedEventsAtTicks / TestEdgeTriggerOn_*_3756.
// evaluateEvent does not arm the cooldown (the worker does, on commit), so
// no cooldown interferes with the counts below.

// TestTriggerOn1_FiresOnEachIsolatedEdge_15020 is the RED-on-revert core:
// two isolated `trigger on 1` events separated by more than the window must
// BOTH fire. Pre-fix the second is latch-suppressed forever (total 1).
func TestTriggerOn1_FiresOnEachIsolatedEdge_15020(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "on1-isolated",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 60, TriggerOn: 1}},
	}
	// t=0: first edge fires and latches. t=61: the t=0 occurrence has aged
	// out of the 60s window, so this is a fresh isolated edge and must fire
	// again. Pre-fix: total 1 (second suppressed by the never-cleared latch).
	ticks := []int64{0, 61}
	if got := feedEventsAtTicks(t, pol, ticks); got != 2 {
		t.Fatalf("isolated `trigger on 1` edges fired %d times; want 2 "+
			"(one per isolated edge) — the latch never re-armed after the "+
			"window decayed (#15020)", got)
	}
}

// TestTriggerOn1_LabPairAlternatesAcrossTwoOutages_15020 mirrors the shipped
// lab pair (failover on ping_test_failed, restore on ping_test_completed,
// both `within 60 { trigger on 1; }`): across two outages each policy must
// fire twice. Pre-fix each fires only on the first outage.
func TestTriggerOn1_LabPairAlternatesAcrossTwoOutages_15020(t *testing.T) {
	failover := &config.EventPolicy{
		Name:          "failover-on-probe-fail",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 60, TriggerOn: 1}},
	}
	restore := &config.EventPolicy{
		Name:          "restore-on-probe-success",
		Events:        []string{"ping_test_completed"},
		WithinClauses: []*config.EventWithin{{Seconds: 60, TriggerOn: 1}},
	}
	e := New(nil, nil)
	defer e.Close()
	base := time.Unix(1_700_000_000, 0)
	var cur int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(cur) * time.Second) }
	applyPolicies9984(e, []*config.EventPolicy{failover, restore})

	fired := map[string]int{}
	feed := func(at int64, event string) {
		cur = at
		for _, tp := range e.evaluateEvent(rpm.Event{Name: event, TestOwner: "isp-health", TestName: "icmp-check"}) {
			fired[tp.pol.Name]++
		}
	}
	// Outage 1: fail at t=0, recover at t=30.
	feed(0, "ping_test_failed")
	feed(30, "ping_test_completed")
	// Outage 2, well past the 60s window of the first cycle: fail at t=200,
	// recover at t=230. Both policies must fire a second time.
	feed(200, "ping_test_failed")
	feed(230, "ping_test_completed")

	if got := fired["failover-on-probe-fail"]; got != 2 {
		t.Fatalf("failover policy fired %d times across two outages; want 2 "+
			"— `trigger on 1` never re-armed after first use (#15020)", got)
	}
	if got := fired["restore-on-probe-success"]; got != 2 {
		t.Fatalf("restore policy fired %d times across two recoveries; want 2 "+
			"— `trigger on 1` never re-armed after first use (#15020)", got)
	}
}

// TestTriggerOn1_SustainedLevelStillFiresOnce_15020 is the adjacent control:
// a sustained stream inside the window must still fire exactly ONCE for
// `trigger on 1` (the #3756 edge semantics must not regress into
// level-triggered re-firing on every event). After the window decays, the
// next isolated event fires again.
func TestTriggerOn1_SustainedLevelStillFiresOnce_15020(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "on1-sustained",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 60, TriggerOn: 1}},
	}
	// Sustained: t=0 fires; t=1..5 are the same held level (a prior event
	// is still inside the window) and must stay suppressed. t=100 is past
	// the decay of every earlier occurrence (latest t=5 + 60s < 100) and
	// is a fresh edge: fires once more. Want exactly 2.
	ticks := []int64{0, 1, 2, 3, 4, 5, 100}
	if got := feedEventsAtTicks(t, pol, ticks); got != 2 {
		t.Fatalf("sustained `trigger on 1` level fired %d times; want 2 "+
			"(crossing at t=0, re-armed crossing at t=100) — sustained "+
			"events inside the window must not re-fire (#3756/#15020)", got)
	}
}

// TestTriggerOn1_MultiClauseRearm_15020 covers the multi-clause AND shape:
// `within 60 { trigger on 1; }` AND `within 300 { trigger on 2; }`. The
// latch is per (policy, event), so re-arm must require EVERY trigger-on
// clause to have decayed below its threshold — decided across all clauses
// (#7223), not by the trigger-on-1 clause alone. This cell also passes
// pre-fix (the 300s gate cleared the latch); it is an adjacent control
// against a fix that special-cases single-clause N=1.
func TestTriggerOn1_MultiClauseRearm_15020(t *testing.T) {
	pol := &config.EventPolicy{
		Name:   "on1-multi",
		Events: []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{
			{Seconds: 60, TriggerOn: 1},
			{Seconds: 300, TriggerOn: 2},
		},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})
	base := time.Unix(1_700_000_000, 0)
	var cur int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(cur) * time.Second) }

	var fired []int64
	for _, cur = range []int64{0, 1, 30, 400, 401, 430} {
		if n := len(e.evaluateEvent(rpm.Event{Name: "ping_probe_failed", TestOwner: "o", TestName: "t"})); n > 0 {
			fired = append(fired, cur)
		}
	}
	// t=0: counts (1,1) — the 300s clause is below 2, no fire.
	// t=1: counts (2,2) — AND satisfied, crossing fires, latch arms.
	// t=30: sustained level on both clauses, suppressed.
	// t=400: 60s window empty and the 300s count is 1 (< 2): the ANDed
	//        condition is false, the latch re-arms, no fire.
	// t=401: counts (2,2) with the latch clear — a new AND crossing, fires.
	// t=430: sustained again, suppressed.
	want := []int64{1, 401}
	if len(fired) != len(want) {
		t.Fatalf("multi-clause `trigger on 1` fired at %v; want %v (#15020)", fired, want)
	}
	for i := range want {
		if fired[i] != want[i] {
			t.Fatalf("multi-clause `trigger on 1` fired at %v; want %v (#15020)", fired, want)
		}
	}
}
