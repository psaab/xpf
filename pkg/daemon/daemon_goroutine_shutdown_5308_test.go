package daemon

// daemon_goroutine_shutdown_5308_test.go — #5308 regression coverage.
//
// Two daemon background loops bind to d.daemonCtx (context.Background() in
// production, never cancelled) rather than the run WaitGroup, so wg.Wait at
// shutdown does NOT cover them:
//
//   - the policy scheduler (startPolicySchedulerLoopLocked → scheduler.Run),
//     which republishes schedule state through the dataplane runtime
//     (UpdatePolicyScheduleState), and
//   - the RPM probe-pin retry loop (probePinRetryLoop), which runs routing-pin
//     syscalls through the routing/FRR manager.
//
// Before #5308 neither was cancelled/joined at shutdown, so a late tick could
// run against an already-torn-down subsystem, and both leaked outright for
// library callers where Run() returns. The shutdown sequence now cancels +
// joins BOTH (stopPolicySchedulerLoop / stopPinRetryLoop) BEFORE the dependent
// subsystems are torn down.
//
// The stop helpers are exercised in a goroutine guarded by a bounded select so
// a revert — pin-retry rebound to the never-cancelled d.daemonCtx, or the
// scheduler never cancelled at shutdown — turns the resulting hang into a FAST
// t.Fatal (RED) instead of wedging the suite.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/scheduler"
	"golang.org/x/sync/semaphore"
)

// joinWithin runs stop in a goroutine and fails the test if it does not return
// within d. A leaked/uncancelled loop makes the join block forever; the bound
// converts that into a fast, deterministic failure.
func joinWithin(t *testing.T, d time.Duration, stop func(), msg string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal(msg)
	}
}

// TestStopPinRetryLoopCancelsJoinsNoLateSyscall proves the RPM probe-pin retry
// loop is cancelled + joined at shutdown and runs NO routing-pin syscall past
// the join, even though its parent d.daemonCtx (context.Background here, as in
// production) is never cancelled.
//
// RED-on-revert: rebinding maybeStartPinRetryLoopLocked's goroutine to
// d.daemonCtx (the pre-#5308 `go d.probePinRetryLoop(d.daemonCtx)`) leaves the
// loop listening on a context that never fires, so stopPinRetryLoop's join
// blocks and joinWithin trips its 3s bound.
func TestStopPinRetryLoopCancelsJoinsNoLateSyscall(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	joined := false // set true only after the join returns (teardown marker)
	callsAfterJoin := 0

	d := &Daemon{
		rpm:                rpm.New(),
		daemonCtx:          context.Background(), // production: never cancelled
		probePinRetryEvery: 2 * time.Millisecond,
		probePinEgressStateFn: func(string) probePinEgressState { return probePinEgressUp },
	}
	d.probePinApply = func(pins []routing.ProbePin) map[string]error {
		mu.Lock()
		calls++
		if joined {
			callsAfterJoin++
		}
		mu.Unlock()
		// Keep failing so the loop never self-exits — only the shutdown
		// cancel may stop it.
		return map[string]error{pins[0].TestKey: fmt.Errorf("egress link down")}
	}
	defer d.rpm.StopAll()

	if !d.reconcileRPM(rpmPinnedTestConfig()) {
		t.Fatal("first reconcile must apply")
	}
	d.rpmMu.Lock()
	active := d.rpmPinRetryActive
	d.rpmMu.Unlock()
	if !active {
		t.Fatal("pin retry loop did not start after a failed pin install")
	}

	// Confirm the loop is genuinely ticking (not just the synchronous
	// first install from reconcileRPM).
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		c := calls
		mu.Unlock()
		if c >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pin retry loop never ticked past the initial install (calls=%d)", c)
		}
		time.Sleep(time.Millisecond)
	}

	// Shutdown cancel + join, bounded so a revert fails fast.
	joinWithin(t, 3*time.Second, d.stopPinRetryLoop,
		"stopPinRetryLoop did not cancel+join the loop — leaked / bound to the never-cancelled daemonCtx")

	// Mark the teardown boundary: no routing-pin syscall may run past here.
	mu.Lock()
	joined = true
	mu.Unlock()

	// Several retry intervals must elapse with ZERO further installer calls.
	time.Sleep(40 * time.Millisecond)
	mu.Lock()
	after := callsAfterJoin
	mu.Unlock()
	if after != 0 {
		t.Fatalf("pin retry loop ran %d routing-pin syscall(s) AFTER shutdown cancel+join", after)
	}

	// pinRetryStopped must latch: a late reconcile cannot restart the loop
	// (which would race pinRetryWg.Wait).
	d.rpmMu.Lock()
	d.rpmPinsFailed = true
	d.maybeStartPinRetryLoopLocked()
	restarted := d.rpmPinRetryActive
	d.rpmMu.Unlock()
	if restarted {
		t.Fatal("pin retry loop restarted after shutdown — pinRetryStopped did not latch")
	}
}

// TestStopPolicySchedulerLoopCancelsJoins proves the policy scheduler goroutine
// is cancelled + joined at shutdown and does not restart afterwards.
//
// RED-on-revert: dropping the cancel from stopPolicySchedulerLoop (the
// pre-#5308 behavior where schedulerCancel fires only on a config-replace, not
// at shutdown) leaves scheduler.Run parked on its 60s ticker with an
// uncancelled ctx, so the join blocks and joinWithin trips its 3s bound.
func TestStopPolicySchedulerLoopCancelsJoins(t *testing.T) {
	sched, _ := scheduler.NewPrimed(map[string]*config.SchedulerConfig{
		"always": {Name: "always"},
	}, func(context.Context, map[string]bool) error { return nil }, time.Now())

	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		daemonCtx: context.Background(), // production: never cancelled
	}
	d.scheduler.Store(sched)
	d.startPolicySchedulerLoopLocked()
	if d.schedulerCancel == nil {
		t.Fatal("scheduler loop did not start")
	}

	joinWithin(t, 3*time.Second, d.stopPolicySchedulerLoop,
		"stopPolicySchedulerLoop did not cancel+join the scheduler goroutine — leaked / not cancelled at shutdown")

	if d.schedulerCancel != nil {
		t.Fatal("schedulerCancel not cleared after stop")
	}

	// schedulerStopped must latch: a late reconcile-driven start must not
	// spin up a new generation (which would race schedulerWg.Wait).
	d.startPolicySchedulerLoopLocked()
	if d.schedulerCancel != nil {
		t.Fatal("scheduler loop restarted after shutdown — schedulerStopped did not latch")
	}
}

// TestStopLoopsIdempotentNilSafe proves both stop helpers are safe on a daemon
// whose loops were never started (feature disabled), and safe to call twice
// (the shutdown sequence runs them, then Run's defers run them again).
func TestStopLoopsIdempotentNilSafe(t *testing.T) {
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		daemonCtx: context.Background(),
	}
	// Never-started loops: nil cancel + empty WaitGroup must join instantly.
	joinWithin(t, time.Second, d.stopPinRetryLoop, "stopPinRetryLoop blocked with no loop running")
	joinWithin(t, time.Second, d.stopPolicySchedulerLoop, "stopPolicySchedulerLoop blocked with no loop running")
	// Double-stop must not panic and must still return promptly.
	joinWithin(t, time.Second, d.stopPinRetryLoop, "second stopPinRetryLoop blocked")
	joinWithin(t, time.Second, d.stopPolicySchedulerLoop, "second stopPolicySchedulerLoop blocked")
}
