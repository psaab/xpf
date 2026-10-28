package coalesce_test

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

// #17226: Loop.Stop must cancel the in-flight actuation. This is the
// #3758 assertion moved from pkg/ipmon into the primitive that now
// owns the context: an actuator blocked on a held semaphore with the
// DEFAULT actuate timeout (30s) must see Stop return in <100ms, not
// after the timeout (the reporter's probe measured 30.023s on revert).
// The semaphore shape mirrors actuateLearnedRouteRefresh's
// applySem.Acquire(ctx,1) wait exactly.
func TestCoalesceStopAbortsBlockedActuation17226(t *testing.T) {
	sem := semaphore.NewWeighted(1)
	if err := sem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("hold semaphore: %v", err)
	}
	entered := make(chan struct{})
	var once sync.Once
	loop := coalesce.New(func(ctx context.Context) bool {
		once.Do(func() { close(entered) })
		if err := sem.Acquire(ctx, 1); err != nil {
			return false // aborted: do not half-actuate
		}
		sem.Release(1)
		return true
	})
	// Default actuate timeout deliberately: no SetActuateTimeout.
	loop.SetTimings(0, 0)
	loop.Start()
	loop.MarkImmediately()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		loop.Stop()
		sem.Release(1)
		t.Fatal("actuator was never entered")
	}

	start := time.Now()
	done := make(chan struct{})
	go func() {
		loop.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		sem.Release(1)
		t.Fatal("Loop.Stop hung behind a blocked actuation (#17226: Stop must cancel the actuation context, not wait out the 30s timeout)")
	}
	if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
		sem.Release(1)
		t.Fatalf("Loop.Stop took %v with a held semaphore and default timeouts, want <100ms (#17226 acceptance)", elapsed)
	}
	sem.Release(1)
}

// #17226: cancelling the StartWithContext parent must abort an
// in-flight actuation without Stop being called — the daemon route
// listener relies on this when the run ctx is cancelled and its
// goroutine is still parked inside Tick behind applySem.
func TestCoalesceParentCancelAbortsBlockedActuation17226(t *testing.T) {
	sem := semaphore.NewWeighted(1)
	if err := sem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("hold semaphore: %v", err)
	}
	defer sem.Release(1)
	entered := make(chan struct{})
	aborted := make(chan struct{})
	var once, abortOnce sync.Once
	loop := coalesce.New(func(ctx context.Context) bool {
		once.Do(func() { close(entered) })
		if err := sem.Acquire(ctx, 1); err != nil {
			abortOnce.Do(func() { close(aborted) })
			return false
		}
		sem.Release(1)
		return true
	})
	loop.SetTimings(0, 0)
	parent, cancelParent := context.WithCancel(context.Background())
	loop.StartWithContext(parent)
	defer loop.Stop()
	loop.MarkImmediately()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actuator was never entered")
	}
	cancelParent()
	select {
	case <-aborted:
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancel did not abort the blocked actuation (#17226: StartWithContext parent must reach the actuator)")
	}
	if err := loop.Context().Err(); err == nil {
		t.Fatal("loop.Context() not cancelled after parent cancel")
	}
}

// #17226 acceptance grep, pinned as a source guard: ipmon must not
// carry a private actuation cancel any more — Loop.Context() is the
// one implementation. A reintroduced actuateCancel would be a second
// copy that can diverge again.
func TestIpmonHasNoPrivateActuateCancel17226(t *testing.T) {
	for _, f := range []string{"../ipmon/ipmon.go", "../ipmon/ipmon_test.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			// Only meaningful inside the repo tree; elsewhere the
			// behavioural cells above are the guard.
			t.Skipf("read %s: %v", f, err)
		}
		if strings.Contains(string(b), "actuateCancel") {
			t.Fatalf("%s still references actuateCancel (#17226: ipmon must use loop.Context(), grep -n actuateCancel pkg/ipmon must be empty)", f)
		}
	}
}
