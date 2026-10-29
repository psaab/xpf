package eventengine

import (
	"sync/atomic"
	"testing"
	"time"
)

// #17727: when the last budget slot expires between a no-progress
// drainDeferred and the deferred worker's next wake recomputation,
// oldestBudgetExpiryLocked prunes it and returns no expiry, so the
// worker arms no timer even though a ready budget action stays parked.
// The nudge that parked it was already consumed by the no-progress
// drain, so with no further events the action is stranded forever.
//
// FAIL-ON-REVERT: freeze the first budget pre-check inside the drain,
// advance the fake clock past every slot's expiry, then release the
// pre-check to return false. The subsequent wake recomputation prunes
// all slots. Without the no-expiry fallback, the hold remains parked
// forever; with it, the worker immediately retries and drains it.
// The idle control (no parked work => no spinning timer) is covered by
// 16658 and re-asserted here cheaply.
func TestDeferredWorkerDrainsReadyBudgetHoldAfterLastSlotExpires17727(t *testing.T) {
	s := newStore(t)
	e := New(s, nil)
	defer e.Close()

	base := time.Unix(1_800_000_000, 0)
	var elapsed atomic.Int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(elapsed.Load()) * time.Second) }
	var timerCalls atomic.Int32
	timerArmed := make(chan struct{})
	e.newTimerFn = func(d time.Duration) (<-chan time.Time, func() bool) {
		if timerCalls.Add(1) == 1 {
			// Keep the initial live-expiry timer from racing the nudge;
			// the only way the worker can drain is consuming that nudge.
			close(timerArmed)
			return make(chan time.Time), func() bool { return true }
		}
		timer := time.NewTimer(d)
		return timer.C, timer.Stop
	}

	// Block the worker's first budget check, which belongs to the
	// no-progress drain after the one and only nudge. The next budget
	// check sees availability, but only after the worker's wake
	// recomputation has had a chance to discover the expired slots.
	entered := make(chan struct{})
	release := make(chan struct{})
	var checks atomic.Int32
	e.budgetSlotAvailableFn = func() bool {
		if checks.Add(1) == 1 {
			close(entered)
			<-release
			return false
		}
		return true
	}

	// Expiry is base+1s, while the initial clock is base.
	e.budgetMu.Lock()
	for i := range globalActionBudget {
		e.budgetTimes[i] = base.Add(time.Second - globalActionBudgetWindow)
	}
	e.budgetStart = 0
	e.budgetCount = globalActionBudget
	e.budgetMu.Unlock()

	// Park the budget hold directly, as deferBudget would.
	e.pendingMu.Lock()
	e.pending.budget["victim"] = plannedAction{policyName: "victim"}
	e.pendingMu.Unlock()
	e.counters.pendingDeferred.Add(1)
	e.startDeferredWorker()
	select {
	case <-timerArmed:
	case <-time.After(waitForTimeout):
		t.Fatal("deferred worker did not arm the initial live-expiry timer")
	}
	e.nudgePending()
	select {
	case <-entered:
	case <-time.After(waitForTimeout):
		t.Fatal("deferred worker did not enter its first budget check")
	}

	// The budget slot expiry passes while the no-progress drain is
	// blocked. No further external nudge is sent after releasing it.
	elapsed.Store(2)
	close(release)

	drainDeadline := time.Now().Add(5 * time.Second)
	for e.Stats().PendingDeferred != 0 && time.Now().Before(drainDeadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("PendingDeferred=%d after 5s with no external nudge; ready budget hold was stranded", got)
	}
	if got := checks.Load(); got < 2 {
		t.Fatalf("budget checks=%d, want at least 2 (no-progress drain then replay)", got)
	}

	e.pendingMu.Lock()
	budgetLen, cooldownLen := len(e.pending.budget), len(e.pending.cooldown)
	e.pendingMu.Unlock()
	if budgetLen != 0 || cooldownLen != 0 {
		t.Fatalf("pending maps not drained: budget=%d cooldown=%d", budgetLen, cooldownLen)
	}
	if got := e.wakeAtLocked(); !got.IsZero() {
		t.Fatalf("wakeAt=%v after drain; want zero (no parked work, #16658 invariant)", got)
	}

	// Idle control: nothing parked, so no spinning timer may appear.
	before := timerCalls.Load()
	time.Sleep(time.Second)
	if delta := timerCalls.Load() - before; delta > idleTimerBudget16658 {
		t.Fatalf("deferred worker armed %d timers in 1s idle after drain (budget %d): idle spin must stay fixed (#16658/#17727)",
			delta, idleTimerBudget16658)
	}
}
