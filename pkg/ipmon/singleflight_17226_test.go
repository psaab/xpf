package ipmon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #17226 (fold of the dual-goroutine blocker): ipmon's actuation must be
// single-flighted. The engine's run() is the single actuation goroutine
// (ipmon.go's invariant); the coalesce loop must NOT also run its own
// sweep goroutine for ipmon, or two Tick calls race and the actuator is
// entered concurrently.
//
// The actuator blocks for 400ms — far longer than the coalesce run
// loop's 100ms sweep — so on the dual-goroutine shape a second Tick
// enters while the first is still in flight and maxInflight reaches 2
// (observed under -race on the pre-fold head). With only the engine
// ticking, its synchronous Tick cannot re-enter itself: exactly one
// entry, maxInflight == 1.
func TestIpmonActuationSingleFlight17226(t *testing.T) {
	var entries, inFlight, maxInFlight atomic.Int32
	entered := make(chan struct{})
	var once sync.Once
	e := New(func(ctx context.Context) bool {
		entries.Add(1)
		cur := inFlight.Add(1)
		for {
			m := maxInFlight.Load()
			if cur <= m || maxInFlight.CompareAndSwap(m, cur) {
				break
			}
		}
		once.Do(func() { close(entered) })
		// Block well past the coalesce sweep interval (100ms) and the
		// 1ms throttle below: any second Tick goroutine gets ample
		// opportunity to enter concurrently while this one is parked.
		time.Sleep(400 * time.Millisecond)
		inFlight.Add(-1)
		return true
	})
	e.debounce = time.Millisecond
	e.throttle = time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actuator was never entered")
	}
	// Outlast the 400ms blocking actuation plus several sweep
	// intervals, so a concurrent second entry (dual goroutine) or a
	// spurious re-entry after convergence would both be visible.
	time.Sleep(600 * time.Millisecond)
	if got := maxInFlight.Load(); got != 1 {
		t.Fatalf("maxInFlight = %d, want 1 (ipmon actuation is not single-flighted: a second goroutine is ticking the loop)", got)
	}
	if got := entries.Load(); got != 1 {
		t.Fatalf("entries = %d, want 1 (converged actuation with no mark during it must not re-enter)", got)
	}
}
