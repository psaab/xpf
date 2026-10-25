package eventengine

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16658: the #15021 deferred worker never cleared pending.wakeAt. It
// seeded each iteration's wake from the stored wakeAt, the cooldown /
// budget candidate loops could only lower it, and drainDeferred never
// reset it — so after the first deferred edge or budget deferral had
// fully replayed, the stored wake lay in the past, the timer delay
// clamped to zero, and the worker spun on zero-length timers (taking
// pendingMu and e.mu via drainDeferred on every pass) for the rest of
// the daemon's life.
//
// These tests drive the canonical #15021 park -> replay sequences on
// the REAL clock (no nowFn), let the worker drain on its own timer,
// then count deferred-worker timers over a real-clock idle second.
// The fix recomputes wake from current parked state each iteration
// and stores zero when both maps are empty, so no timer is armed at
// all while idle: the count stays at the single timer that drove the
// replay. Pre-fix, the stale past wakeAt re-arms a zero-length timer
// on every iteration — hundreds of thousands of timers in a second.
//
// A count (not a CPU measurement) is the assertion: it is exact,
// deterministic modulo a generous ceiling, and directly names the
// defect (timers armed with nothing pending). A rusage/CPU probe
// would be scheduler-dependent and flaky under -race / loaded CI.

// countingTimer16658 installs a newTimerFn that counts every timer
// the engine arms and delegates to a real timer, so the deferred
// worker still wakes and drains for real. It returns the count
// accessor. Must be installed before the engine handles events.
func countingTimer16658(e *Engine) func() int {
	var mu sync.Mutex
	n := 0
	e.newTimerFn = func(d time.Duration) (<-chan time.Time, func() bool) {
		mu.Lock()
		n++
		mu.Unlock()
		t := time.NewTimer(d)
		return t.C, t.Stop
	}
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// idleTimerBudget16658 bounds the timers allowed during a one-second
// idle window after a full drain. The fixed worker arms zero timers
// while nothing is parked (it blocks on pendingWake); a handful of
// slack absorbs the one boundary timer that may be created just as
// the drain completes. The spinning worker arms orders of magnitude
// more (a zero-length timer per loop iteration).
const idleTimerBudget16658 = 16

func TestDeferredWorkerNoTimerSpinAfterCooldownReplay16658(t *testing.T) {
	s := newStore(t)
	e := New(s, nil)
	defer e.Close()
	timers := countingTimer16658(e)

	pol := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name recovered"}}
	applyPolicies9984(e, []*config.EventPolicy{pol})

	// t=0: first edge commits and arms the 30s cooldown.
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "first commit", func() bool { return e.Stats().Committed >= 1 })
	waitFor(t, "cooldown armed", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		rt := e.runtime["p"]
		return rt != nil && !rt.lastTrigger().IsZero()
	})

	// Second edge inside the cooldown: suppressed and parked. evaluateEvent
	// is the non-live path (live=true is reserved for in-worker replays,
	// which must fire past cooldown instead of re-parking). The first
	// commit has armed committedTrigger, so this edge is
	// cooldown-suppressed and becomes a parked hold; the parked hold
	// starts the deferred worker, which arms a timer for anchor+30s.
	e.evaluateEvent(eventFor("ping_test_failed"))
	if e.Stats().CooldownSuppressed == 0 {
		t.Fatalf("cooldown suppression not counted: %+v", e.Stats())
	}
	waitFor(t, "cooldown edge parked", func() bool { return e.Stats().PendingDeferred >= 1 })

	// Wait out the real 30s cooldown: the worker's timer must fire
	// and replay the parked edge with no test-side drain. The
	// replay goes through runAction, whose second commit is counted
	// even though the identical host-name set takes the no-change
	// skip path (still a committed generation). waitFor's 30s bound
	// is exactly the cooldown, so poll with a 45s budget instead.
	replayDeadline := time.Now().Add(45 * time.Second)
	for e.Stats().Committed < 2 && time.Now().Before(replayDeadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if e.Stats().Committed < 2 {
		t.Fatalf("deferred replay never committed: %+v", e.Stats())
	}
	waitFor(t, "parked set drained", func() bool { return e.Stats().PendingDeferred == 0 })

	// The invariant the spin violated: no parked work, no stored wake.
	if got := e.wakeAtLocked(); !got.IsZero() {
		t.Fatalf("wakeAt=%v after full drain; want zero (stale wake seeds zero-length timers)", got)
	}

	// One real-clock idle second: with nothing parked the fixed
	// worker blocks on pendingWake and arms no timers at all.
	before := timers()
	time.Sleep(time.Second)
	if delta := timers() - before; delta > idleTimerBudget16658 {
		t.Fatalf("deferred worker armed %d timers in 1s idle after drain (budget %d): stale wakeAt spin (#16658)",
			delta, idleTimerBudget16658)
	}
}

func TestDeferredWorkerNoTimerSpinAfterBudgetReplay16658(t *testing.T) {
	s := newStore(t)
	e := New(s, nil)
	defer e.Close()
	timers := countingTimer16658(e)

	// Deterministic budget drain, no 60s wall clock and no fake-clock
	// worker cap: park a budget hold directly against budget state
	// whose oldest slot has already expired. On the worker's first
	// pass the wake computation prunes the expired slots, and
	// drainDeferred's pre-check finds budget available — so the
	// worker replays (enqueues) the hold and both maps end empty.
	// Any later timer can only come from a stale stored wake.
	expired := time.Now().Add(-2 * globalActionBudgetWindow)
	e.budgetMu.Lock()
	for i := range globalActionBudget {
		e.budgetTimes[i] = expired.Add(time.Duration(i) * time.Second)
	}
	e.budgetStart = 0
	e.budgetCount = globalActionBudget
	e.budgetMu.Unlock()

	e.pendingMu.Lock()
	e.pending.budget["victim"] = plannedAction{policyName: "victim"}
	// The stale wake deferBudget would have stored for this hold:
	// its slot expiry, already in the past once the drain lands.
	e.pending.wakeAt = expired.Add(globalActionBudgetWindow)
	e.pendingMu.Unlock()
	e.counters.pendingDeferred.Add(1)
	e.startDeferredWorker()
	e.nudgePending()

	// The replay removes the (ops-less) hold from the parked set
	// (decrementing the gauge) before enqueueing it, so the parked
	// gauge returning to zero is the drain signal. The enqueued
	// action itself is consumed by the action worker or counted
	// abandoned at Close.
	waitFor(t, "budget hold drained", func() bool { return e.Stats().PendingDeferred == 0 })
	e.pendingMu.Lock()
	budgetLen, cooldownLen := len(e.pending.budget), len(e.pending.cooldown)
	e.pendingMu.Unlock()
	if budgetLen != 0 || cooldownLen != 0 {
		t.Fatalf("pending maps not drained: budget=%d cooldown=%d", budgetLen, cooldownLen)
	}
	if got := e.wakeAtLocked(); !got.IsZero() {
		t.Fatalf("wakeAt=%v after budget drain; want zero (stale wake seeds zero-length timers)", got)
	}

	// One real-clock idle second: with nothing parked the fixed
	// worker blocks on pendingWake and arms no timers at all.
	// Pre-fix it re-arms a zero-length timer per iteration off the
	// stale past wakeAt stored above.
	before := timers()
	time.Sleep(time.Second)
	if delta := timers() - before; delta > idleTimerBudget16658 {
		t.Fatalf("deferred worker armed %d timers in 1s idle after budget drain (budget %d): stale wakeAt spin (#16658)",
			delta, idleTimerBudget16658)
	}
}
