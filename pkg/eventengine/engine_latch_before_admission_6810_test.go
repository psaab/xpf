package eventengine

// engine_latch_before_admission_6810_test.go — #6810.
//
// evaluateEvent arms the #3756 edge latch under e.mu and returns the trigger.
// HandleEvent classifies and enqueues AFTERWARDS, outside that lock — and
// enqueue returned nothing, so a dropped action was indistinguishable from an
// admitted one at the call site.
//
// The consequence is not a delayed remediation, it is a LOST one. withinMatches
// suppresses every later at/above-threshold event while the latch is armed, and
// re-arms only when a clause's count falls BELOW its threshold. For the
// sustained fault an event-options policy exists to remediate, the level does
// not fall — so a transient queue saturation permanently consumed the crossing
// and the configured remediation simply never ran.
//
// These cells drive the REAL HandleEvent (classify + enqueue + rollback), not
// evaluateEvent, because the whole defect lives in the seam BETWEEN them: every
// pre-existing edge-latch test calls evaluateEvent directly and is structurally
// incapable of seeing it.

import (
	"fmt"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// newInertEngine6810 builds an engine on a deterministic clock whose action
// worker never starts, so the queue is inert and a full queue STAYS full.
// HandleEvent would normally start the worker via startOnce; consuming the
// once here is the same seam the #5853/#5062 queue tests rely on.
func newInertEngine6810(t *testing.T) (*Engine, func(int64)) {
	t.Helper()
	e := New(nil, nil)
	t.Cleanup(e.Close)
	e.startOnce.Do(func() {}) // the worker must never drain the queue
	base := time.Unix(1_700_000_000, 0)
	var cur int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(cur) * time.Second) }
	return e, func(tick int64) { cur = tick }
}

// edgePolicy6810 is an edge-triggered policy with a real `then` command, so
// classifyPlan yields a non-empty op list and the action actually reaches
// enqueue.
func edgePolicy6810(name, event string, triggerOn int) *config.EventPolicy {
	return &config.EventPolicy{
		Name:          name,
		Events:        []string{event},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: triggerOn}},
		ThenCommands:  []string{"set system host-name remediated-" + name},
	}
}

// saturateWithOtherPolicies6810 fills all 64 slots with DISTINCT other-policy
// actions — the exact shape R71 names. Distinct matters: supersede evicts a
// same-policy entry, so a burst from one policy occupies a single slot (#5853)
// and would never produce the capacity drop under test.
func saturateWithOtherPolicies6810(t *testing.T, e *Engine) {
	t.Helper()
	for i := 0; i < actionQueueDepth; i++ {
		if !e.enqueue(plannedAction{policyName: fmt.Sprintf("filler%03d", i)}) {
			t.Fatalf("filler %d was not admitted; the queue could not be saturated, "+
				"so this cell cannot reach the capacity drop it exists for", i)
		}
	}
	if got := int(e.counters.queueDepth.Load()); got != actionQueueDepth {
		t.Fatalf("queue depth = %d after saturation, want %d", got, actionQueueDepth)
	}
}

// TestQueueFullDropDoesNotConsumeTheCrossing6810 is the issue, end to end.
//
// FAIL-ON-REVERT: drop the releaseEdgeLatch call in HandleEvent (or make
// enqueue's verdict unconditional) and the latch stays armed over the dropped
// action — the post-drain crossing is then suppressed as "already fired" and
// the remediation never queues, so the final assertion goes RED.
func TestQueueFullDropDoesNotConsumeTheCrossing6810(t *testing.T) {
	e, at := newInertEngine6810(t)
	const event = "ping_probe_failed"
	pol := edgePolicy6810("remediate", event, 2)
	applyPolicies9984(e, []*config.EventPolicy{pol})

	saturateWithOtherPolicies6810(t, e)

	// Cross the threshold while the queue is full of OTHER policies. Event 1
	// takes the count to 1 (below), event 2 is the crossing.
	at(0)
	e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
	at(1)
	e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})

	// Precondition: the crossing really did produce a capacity drop. Without
	// this the cell would also pass on a run where nothing was ever dropped.
	if got := e.Stats().DroppedQueueFull; got != 1 {
		t.Fatalf("DroppedQueueFull = %d, want 1 — the crossing did not hit the "+
			"capacity drop this cell is about", got)
	}
	if names := drainPolicyNames(e); len(names) != actionQueueDepth {
		t.Fatalf("drained %d actions, want %d fillers and no remediation",
			len(names), actionQueueDepth)
	}

	// The worker has now caught up (queue drained). The fault is SUSTAINED, so
	// the next event keeps the count at/above the threshold — it does not
	// re-cross. Before #6810 the latch was still armed from the consumed
	// crossing, so withinMatches suppressed this and every later event, and the
	// remediation never ran.
	at(2)
	e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})

	queued := drainPolicyNames(e)
	if len(queued) != 1 || queued[0] != "remediate" {
		t.Fatalf("after a queue-full drop the remediation never re-queued (got %v). "+
			"The crossing was CONSUMED by the drop: withinMatches suppresses every "+
			"later at/above-threshold event while the edge latch is armed, and "+
			"re-arms only when the count falls BELOW the threshold — which, for "+
			"the sustained fault this policy exists to remediate, never happens "+
			"(#6810)", queued)
	}
}

// TestSustainedLevelStillFiresOnlyOnceWhenAdmitted6810 is the PAIRED control,
// and it is the cell that stops the fix from becoming a different bug.
//
// Rolling the latch back on a drop must not roll it back on a SUCCESS. If it
// did, `trigger on N` would degrade from edge- to level-triggered and re-fire
// on every above-threshold event — precisely the behaviour #3756 M1 removed.
// The sibling cell above cannot see that: it only ever exercises the drop path.
func TestSustainedLevelStillFiresOnlyOnceWhenAdmitted6810(t *testing.T) {
	e, at := newInertEngine6810(t)
	const event = "ping_probe_failed"
	applyPolicies9984(e, []*config.EventPolicy{edgePolicy6810("remediate", event, 2)})

	// Empty queue: every action is admitted.
	for tick := int64(0); tick < 10; tick++ {
		at(tick)
		e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
	}

	if got := e.Stats().DroppedQueueFull; got != 0 {
		t.Fatalf("DroppedQueueFull = %d, want 0 — this control must exercise the "+
			"ADMITTED path", got)
	}
	// One crossing, one queued action. Supersede collapses same-policy
	// duplicates, so the queue depth alone cannot distinguish "fired once" from
	// "fired ten times"; the superseded counter is what does.
	if st := e.Stats(); st.Superseded != 0 {
		t.Fatalf("Superseded = %d, want 0 — the sustained level re-fired %d extra "+
			"times, so `trigger on` degraded from EDGE- to LEVEL-triggered and the "+
			"#6810 rollback is clearing a latch that was legitimately armed (#3756 M1)",
			st.Superseded, st.Superseded)
	}
	if queued := drainPolicyNames(e); len(queued) != 1 {
		t.Fatalf("sustained above-threshold level queued %d actions, want exactly 1 "+
			"(one crossing): %v", len(queued), queued)
	}
}

// TestLatchRollbackIsRevisionGuarded6810 pins the ABA defence.
//
// A drop is reported by the goroutine that lost the race; by the time it rolls
// the latch back, a commit may have REDEFINED the policy and Apply installed a
// fresh, re-armed runtime for the successor. Clearing a latch then is a
// name-based ABA: it would touch state belonging to a generation this failure
// never authorized. The same guard armCooldown uses (#5311).
//
// Asserted through the observable contract rather than by reading onLatched: a
// successor generation is re-armed by Apply anyway, so the check is that a
// STALE revision's rollback does not disturb the live runtime's latch — the
// successor still fires exactly once on its own crossing.
func TestLatchRollbackIsRevisionGuarded6810(t *testing.T) {
	e, at := newInertEngine6810(t)
	const event = "ping_probe_failed"
	applyPolicies9984(e, []*config.EventPolicy{edgePolicy6810("remediate", event, 2)})

	// Cross the threshold on an empty queue: admitted, latch legitimately armed.
	at(0)
	e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
	at(1)
	e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
	if queued := drainPolicyNames(e); len(queued) != 1 {
		t.Fatalf("precondition: the crossing must fire once, got %v", queued)
	}

	// A stale rollback arrives, quoting a revision that is no longer live.
	e.releaseEdgeLatch("remediate", event, "stale-revision-that-never-existed")

	// The live latch is untouched: the sustained level is still suppressed.
	at(2)
	e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
	if queued := drainPolicyNames(e); len(queued) != 0 {
		t.Fatalf("a rollback quoting a STALE semantic revision cleared the live "+
			"policy's edge latch (got %v) — a predecessor's failure must not "+
			"disturb a generation it never authorized (#5311 ABA guard)", queued)
	}
}

// TestClassifyRejectAndEmptyPlanKeepTheLatch6810 historically pinned the
// #6810 decision NOT to roll back on classify-reject / empty-plan. #14724
// reverses that decision: every terminal non-commit exit releases the
// latch. The successor cell is
// TestHandleEventPreEnqueueReleasesLatch14724 — see docs/log/14724.md
// for the reversal rationale (per-event rejected churn is counted and
// accepted; a wedged latch on a sustained fault is not).
