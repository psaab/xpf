package daemon

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/coalesce"
)

// #17226 daemon acceptance: hold applySem, mark the route-listener
// loop, then cancel the run ctx — the actuation parked in
// applySem.Acquire must abort (<1s for the listener goroutine to be
// joinable) instead of holding shutdown's wg.Wait for the 30s
// actuate timeout past TimeoutStopSec=20. This drives the shape
// daemon_run.go installs: routeListener(ctx, coalesce.New(...)) with
// the loop started from the run ctx, and actuateLearnedRouteRefresh's
// semaphore wait (the actuator below mirrors its first line).
func TestDaemonRouteListenerSemantics17226(t *testing.T) {
	// Production wiring guard: routeListener must start the loop from
	// the caller's ctx, not Background — otherwise cancelling the run
	// ctx cannot reach a parked Acquire.
	src, err := os.ReadFile("daemon_route_listener.go")
	if err != nil {
		t.Fatalf("read daemon_route_listener.go: %v", err)
	}
	if !strings.Contains(string(src), "loop.StartWithContext(ctx)") {
		t.Fatal("routeListener does not call loop.StartWithContext(ctx) (#17226: the run ctx must parent the loop's actuation context)")
	}
	if strings.Contains(string(src), "\tloop.Start()\n") {
		t.Fatal("routeListener still calls loop.Start() (#17226: Background-parented loop reintroduces the 30s shutdown hang)")
	}

	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("hold applySem: %v", err)
	}
	defer d.applySem.Release(1)

	entered := make(chan struct{})
	aborted := make(chan struct{})
	var enterOnce, abortOnce sync.Once
	// Mirror actuateLearnedRouteRefresh's blocking wait: the first
	// thing the real actuator does is applySem.Acquire(ctx,1).
	loop := coalesce.New(func(ctx context.Context) bool {
		enterOnce.Do(func() { close(entered) })
		if err := d.applySem.Acquire(ctx, 1); err != nil {
			abortOnce.Do(func() { close(aborted) })
			return false
		}
		d.applySem.Release(1)
		return true
	})
	loop.SetTimings(0, 0)

	ctx, cancel := context.WithCancel(context.Background())
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		// routeListener's loop lifetime, minus the netlink subscription
		// (not hermetic): start from ctx, mark, park, stop on cancel.
		loop.StartWithContext(ctx)
		defer loop.Stop()
		loop.MarkImmediately()
		<-ctx.Done()
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("route-refresh actuator was never entered")
	}
	start := time.Now()
	cancel()
	select {
	case <-aborted:
	case <-time.After(time.Second):
		t.Fatal("cancelling the run ctx did not abort the applySem-blocked actuation within 1s (#17226)")
	}
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("route-listener goroutine not joined within 1s of run-ctx cancel (#17226: wg.Wait would stall past TimeoutStopSec)")
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("listener joined after %v, want <1s (#17226 acceptance)", elapsed)
	}
}
