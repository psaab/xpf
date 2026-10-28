package coalesce_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/coalesce"
)

// #17226 (fold): Tick must be single-flighted even when driven from two
// goroutines at once — run() plus an external driver, or two drivers.
// The actuator blocks for 400ms while concurrent Ticks arrive with the
// throttle already elapsed; a Tick without the in-flight guard enters
// the actuator concurrently and maxInflight reaches 2. With the guard,
// the concurrent Ticks skip (dirty state untouched) and the actuator
// is entered exactly once.
func TestCoalesceConcurrentTicksSingleFlight17226(t *testing.T) {
	var entries, inFlight, maxInFlight atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	loop := coalesce.New(func(ctx context.Context) bool {
		entries.Add(1)
		cur := inFlight.Add(1)
		for {
			m := maxInFlight.Load()
			if cur <= m || maxInFlight.CompareAndSwap(m, cur) {
				break
			}
		}
		if entries.Load() == 1 {
			close(entered)
		}
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
		inFlight.Add(-1)
		return true
	})
	loop.SetTimings(0, 0)
	// Context-only: no run() goroutine — this cell drives Tick itself,
	// concurrently, which is exactly the shape the guard must bound.
	loop.StartContextOnly(context.Background())
	defer loop.Stop()
	loop.MarkImmediately()

	done := make(chan struct{})
	go func() {
		defer close(done)
		loop.Tick(loop.Context())
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actuator was never entered")
	}
	// The first actuation is blocked in flight (throttle 0, still
	// dirty until it returns): concurrent Ticks must all skip.
	for range 8 {
		loop.Tick(loop.Context())
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("first Tick did not return after release")
	}
	if got := maxInFlight.Load(); got != 1 {
		t.Fatalf("maxInFlight = %d, want 1 (Tick entered the actuator concurrently)", got)
	}
	if got := entries.Load(); got != 1 {
		t.Fatalf("entries = %d, want 1", got)
	}
}
