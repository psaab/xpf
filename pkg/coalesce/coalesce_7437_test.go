package coalesce

import (
	"context"
	"sync"
	"testing"
	"time"
)

// #7437: the coalescing bound is the whole point of the type, so it is
// asserted as a RATE, not as "an actuation happened".
//
// A naive per-event implementation passes "a push occurred" trivially. Only a
// bound on how MANY distinguishes coalescing from not coalescing, and that is
// the difference between a bounded refresh and the control-plane brownout a
// per-event snapshot publish would cause under BGP churn.
//
// The clock is INJECTED. A rate assertion written with sleeps races wall time
// and fails intermittently in exactly the way that gets a guard widened until
// it proves nothing — the flaky-guard shape this repo keeps finding. With a
// fake clock every number below is exact, and stated before the run:
//
//	50 marks inside 100ms, then advance past the debounce -> EXACTLY 1
//	sustained marks across 10s at throttle 3s            -> AT MOST 4

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestLoop(t *testing.T, clk *fakeClock, actuate func(context.Context) bool) *Loop {
	t.Helper()
	l := New(actuate)
	l.SetClock(clk.now)
	l.SetTimings(DefaultDebounce, DefaultThrottle)
	return l
}

func TestBurstCollapsesToOneActuation7437(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var got int
	l := newTestLoop(t, clk, func(context.Context) bool { got++; return true })

	// 50 events inside 100ms — a BGP burst.
	for i := 0; i < 50; i++ {
		l.Mark()
		clk.advance(2 * time.Millisecond)
		// Sweeping during the burst must NOT actuate: the debounce has not
		// elapsed. Without this the test would only prove the final tick
		// fired once, not that the burst was held.
		l.Tick(context.Background())
	}
	if got != 0 {
		t.Fatalf("actuated %d times DURING the burst; the debounce is not holding, so "+
			"every route event would drive a full snapshot publish", got)
	}

	// Settle past the debounce.
	clk.advance(DefaultDebounce)
	l.Tick(context.Background())
	if got != 1 {
		t.Fatalf("actuations after the burst settled = %d, want exactly 1", got)
	}

	// Nothing further without a new mark.
	clk.advance(10 * time.Second)
	l.Tick(context.Background())
	if got != 1 {
		t.Fatalf("actuated again with nothing marked: %d", got)
	}
}

func TestSustainedChurnIsThrottled7437(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var got int
	l := newTestLoop(t, clk, func(context.Context) bool { got++; return true })

	// 10s of continuous churn, one event per 50ms = 200 events.
	const span = 10 * time.Second
	for elapsed := time.Duration(0); elapsed < span; elapsed += 50 * time.Millisecond {
		l.Mark()
		clk.advance(50 * time.Millisecond)
		l.Tick(context.Background())
	}

	// Stated before the run: debounce 1s then one per 3s throttle window ->
	// at most 4 across 10s. The bound is what matters, not the exact figure.
	const maxActuations = 4
	if got > maxActuations {
		t.Errorf("200 events over %v produced %d actuations, want <= %d; the throttle is "+
			"not bounding the publish rate and sustained route churn would starve "+
			"session installs on the shared control socket", span, got, maxActuations)
	}
	// Non-vacuity: it must still actuate. A loop that never fires trivially
	// satisfies every upper bound above.
	if got == 0 {
		t.Error("200 events over 10s produced NO actuation; the loop is not firing at all " +
			"and the bound above is satisfied for the wrong reason")
	}
}

// TestMarkDuringActuationIsNotLost7437 pins the dirtyGen half of the
// discipline. A change landing WHILE the actuator runs was not seen by it, so
// clearing the dirty bit afterwards would swallow it — the loop would go quiet
// holding stale state, which for a route listener means a learned route that
// never reaches the helper FIB.
func TestMarkDuringActuationIsNotLost7437(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var got int
	var l *Loop
	l = New(func(context.Context) bool {
		got++
		if got == 1 {
			l.Mark() // a route event arrives mid-publish
		}
		return true
	})
	l.SetClock(clk.now)
	l.SetTimings(DefaultDebounce, DefaultThrottle)

	l.Mark()
	clk.advance(DefaultDebounce)
	l.Tick(context.Background())
	if got != 1 {
		t.Fatalf("setup: first actuation count = %d, want 1", got)
	}

	// The mark that landed during actuation must still be pending.
	clk.advance(DefaultThrottle)
	l.Tick(context.Background())
	if got != 2 {
		t.Errorf("a Mark() during actuation was swallowed (actuations = %d, want 2); the "+
			"loop would go quiet holding state the actuator never saw", got)
	}
}

// TestFailedActuationRetriesButDoesNotHotLoop7437 pins the other half: a false
// return keeps the state dirty, and lastActuation advancing at fire time is
// what paces the retry to one per throttle window instead of spinning.
func TestFailedActuationRetriesButDoesNotHotLoop7437(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var got int
	l := newTestLoop(t, clk, func(context.Context) bool { got++; return false })

	l.Mark()
	clk.advance(DefaultDebounce)
	l.Tick(context.Background())
	if got != 1 {
		t.Fatalf("setup: %d actuations, want 1", got)
	}

	// Sweeping repeatedly without advancing time must NOT retry.
	for i := 0; i < 20; i++ {
		l.Tick(context.Background())
	}
	if got != 1 {
		t.Fatalf("a failed actuation hot-looped: %d attempts with no time advance", got)
	}

	// One throttle window later, exactly one retry.
	clk.advance(DefaultThrottle)
	l.Tick(context.Background())
	if got != 2 {
		t.Errorf("a failed actuation did not retry after the throttle window: %d", got)
	}
}

// TestMarkImmediatelyBypassesDebounceAndKeepsThrottle verifies the urgent
// failover path can act on a fresh verdict without weakening the loop's rate
// bound for repeated updates.
func TestMarkImmediatelyBypassesDebounceAndKeepsThrottle11414(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	var got int
	l := newTestLoop(t, clk, func(context.Context) bool { got++; return true })

	l.Mark()
	l.Tick(context.Background())
	if got != 0 {
		t.Fatalf("ordinary mark bypassed debounce: actuations = %d, want 0", got)
	}

	l.MarkImmediately()
	l.Tick(context.Background())
	if got != 1 {
		t.Fatalf("immediate mark did not bypass debounce: actuations = %d, want 1", got)
	}

	l.MarkImmediately()
	l.Tick(context.Background())
	if got != 1 {
		t.Fatalf("immediate mark bypassed throttle: actuations = %d, want 1 before throttle", got)
	}

	clk.advance(DefaultThrottle)
	l.Tick(context.Background())
	if got != 2 {
		t.Fatalf("throttled immediate mark did not actuate after throttle: got %d, want 2", got)
	}
}
