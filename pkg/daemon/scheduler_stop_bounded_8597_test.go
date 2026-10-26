package daemon

import (
	"context"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

// #8597 (muse-004 K23) — stopPolicySchedulerLoop acquired applySem with
// context.Background(), so a wedged apply stalled the whole orderly shutdown.
//
// The initial drain, scheduler stop, and final host-tunable restore share
// Run's shutdown context and its single deadline. The timing and
// never-release-untaken-permit assertions below pin this site's contract.
// stopPinRetryLoop, the sibling cleanup called on the next line, does not
// touch applySem at all.
//
// What the stall costs: the scheduler is never cancelled, so shutdown never
// reaches the HA relinquish that follows, and systemd's TimeoutStopSec ends the
// process with SIGKILL — no rg_active clear, no priority-0 advert, no RA
// goodbye. A clean sub-second handover becomes a blackout.

// stopWithin runs stopPolicySchedulerLoop on a goroutine and waits at most
// budget for it.
//
// Every cell in this file that holds applySem MUST go through it. Under the
// mutation this file exists to catch, the call does not return at all — so a
// cell that invoked it inline would HANG rather than fail, and a hanging cell
// is a void: its mutant produces no verdict, only a timed-out package. The one
// cell that ran inline in the first draft did exactly that.
func stopWithin(t *testing.T, d *Daemon, budget time.Duration) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		d.stopPolicySchedulerLoop()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(budget):
		return false
	}
}

// TestStopPolicySchedulerLoopIsBoundedByAWedgedApply_8597 is the RED-on-revert
// core. applySem is held for longer than the shutdown budget, modelling the
// wedged apply; stopPolicySchedulerLoop must still return.
//
// Restoring context.Background() makes this hang rather than fail, so the cell
// runs the call on a goroutine and races it against a timer well beyond the
// budget. A cell that simply called it inline would be a void under its own
// mutant.
func TestStopPolicySchedulerLoopIsBoundedByAWedgedApply_8597(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	// The wedged apply: acquired and never released for the life of the test.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}

	start := time.Now()
	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return while an apply held applySem: " +
			"the shutdown-path acquire is unbounded, so a wedged apply stalls the " +
			"orderly shutdown past TimeoutStopSec and the process is SIGKILLed with " +
			"no rg_active clear, no priority-0 advert and no RA goodbye (#8597/K23)")
	}

	if elapsed := time.Since(start); elapsed < applyCloseoutDrainTimeout {
		t.Errorf("returned after %v, before the %v budget: it cannot have waited for the "+
			"semaphore at all, so this cell is not exercising the wedged-apply path",
			elapsed, applyCloseoutDrainTimeout)
	}
}

// TestStopPolicySchedulerLoopDoesNotReleaseASemaphoreItNeverTook_8597 is the
// correctness half of bounding an acquire, and the bug a careless bound
// introduces.
//
// The original released unconditionally, which was safe only because the
// acquire could not fail. Releasing a weight-1 semaphore that was never
// acquired raises its count above its capacity, so the NEXT acquirer proceeds
// while the wedged apply still holds it — two concurrent applies, from a
// shutdown path whose whole purpose is to serialise against them.
//
// After the timeout above, the semaphore must still be fully held by the wedged
// apply: a fresh non-blocking acquire must FAIL.
func TestStopPolicySchedulerLoopDoesNotReleaseASemaphoreItNeverTook_8597(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}

	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return; the acquire is unbounded (#8597/K23)")
	}

	if d.applySem.TryAcquire(1) {
		t.Fatal("applySem admitted a second holder after a timed-out stop: the stop " +
			"released a permit it never acquired, so the wedged apply now runs " +
			"concurrently with whatever acquires next")
	}
}

// TestStopPolicySchedulerLoopStillTakesTheSemaphoreWhenFree_8597 is the
// OVER-BROAD control. A "fix" that stopped acquiring altogether would pass both
// cells above and lose the mutual exclusion the acquire exists for — the
// schedulerCancel read/clear must happen under the same lock that guards it.
//
// It also pins the release: an acquire that succeeded and was not released
// would leave the semaphore permanently held, which on the Run()-returns path
// (where this is a defer rather than the shutdown sequence) wedges every later
// apply.
func TestStopPolicySchedulerLoopStillTakesTheSemaphoreWhenFree_8597(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	var heldDuringStop bool
	d.schedulerCancel = func() {
		// Runs after the release in the current shape; what matters is that by
		// the time stopPolicySchedulerLoop RETURNS the permit is back.
		heldDuringStop = !d.applySem.TryAcquire(1)
		if !heldDuringStop {
			d.applySem.Release(1)
		}
	}

	start := time.Now()
	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return on a FREE semaphore")
	}

	if elapsed := time.Since(start); elapsed >= applyCloseoutDrainTimeout {
		t.Errorf("took %v on a FREE semaphore: the acquire must succeed immediately when "+
			"no apply is in flight, not wait out the budget", elapsed)
	}
	if !d.applySem.TryAcquire(1) {
		t.Fatal("applySem is still held after stopPolicySchedulerLoop returned on a free " +
			"semaphore: an acquired permit was not released, and every later apply " +
			"blocks on it")
	}
	d.applySem.Release(1)
	if !d.schedulerStopped.Load() {
		t.Error("schedulerStopped must latch regardless of the semaphore outcome")
	}
}

// TestStopPolicySchedulerLoopCancelsEvenAfterTheTimeout_8597 pins the point of
// bounding the acquire: it is not that the call returns, it is that the call
// reaches the CANCEL. A bound that gave up and returned early would leave the
// scheduler goroutine running against a runtime the next lines tear down —
// exactly what #5308 ordered this call before the dataplane teardown to prevent.
func TestStopPolicySchedulerLoopCancelsEvenAfterTheTimeout_8597(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}

	cancelled := false
	d.schedulerCancel = func() { cancelled = true }

	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return; the acquire is unbounded (#8597/K23)")
	}

	if !cancelled {
		t.Fatal("the scheduler was never cancelled after the acquire timed out: bounding " +
			"the wait is only worth anything if the call goes on to do its job (#5308 " +
			"orders this before the dataplane teardown so no late tick runs against a " +
			"closed runtime)")
	}
	if d.schedulerCancel != nil {
		t.Error("schedulerCancel must be cleared so a second stop is a no-op")
	}
}

// #8660: THE JOIN. A tick parked inside the real scheduler goroutine behind a
// wedged apply must not stall `stopPolicySchedulerLoop`.
//
// This is the residual K23 documented and could not cover: its cells pin the
// bounded acquire that `stopPolicySchedulerLoop` performs itself, not the
// `schedulerWg.Wait()` that follows. The tick used to acquire with
// `d.daemonCtx` — the raw, production-uncancelled parent, with an
// uncancellable `context.Background()` fallback — so `schedulerCancel()`
// released nothing and the join blocked behind the same wedged apply that this
// function's own bound exists to survive.
//
// THE OBSERVABLE, named before the assertion was written: "the join returns".
// A cell that only asserts `stopPolicySchedulerLoop` returns within a timeout
// would pass on a fixture where the tick was NEVER PARKED — the vacuous shape,
// where the setup silently fails to create the condition and the assertion
// reports health. So the tick signals that it has ENTERED the publish, and this
// cell fails if that signal never arrives.
func TestStopPolicySchedulerLoopJoinsATickParkedOnAWedgedApply_8660(t *testing.T) {
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		// The production shape, deliberately: an UNCANCELLABLE parent. If the
		// publish ever reaches for this field again instead of the ctx it is
		// handed, the join has nothing to release it and this cell hangs.
		daemonCtx: context.Background(),
	}

	// The wedged apply: taken and never released.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}

	entered := make(chan struct{})
	var once sync.Once
	sched, _ := scheduler.NewPrimed(
		map[string]*config.SchedulerConfig{"always": {Name: "always"}},
		func(ctx context.Context, activeState map[string]bool) error {
			once.Do(func() { close(entered) })
			// The real publish, with the ctx the tick hands it.
			return d.publishPolicyScheduleState(ctx, 0, activeState)
		}, time.Now())
	sched.SetTickIntervalForTesting(time.Millisecond)
	// Between NewPrimed and the first tick nothing changes, so the tick would
	// correctly decline to notify. Latching the #3780 republish flag is how the
	// production error path forces a re-fire; used here so a real tick reaches
	// the publish.
	sched.LatchRepublishForTesting()
	d.scheduler.Store(sched)
	d.startPolicySchedulerLoopLocked()

	// FIXTURE ADEQUACY: the tick must actually be in flight and parked on the
	// semaphore. Without this the cell measures nothing — a scheduler that
	// never ticked joins instantly, and "returns fast" would read as "returns
	// correctly".
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the scheduler tick never entered publishPolicyScheduleState, so " +
			"no tick was parked on the wedged apply and this cell would pass " +
			"without exercising the join at all (#8660)")
	}

	if !stopWithin(t, d, applyCloseoutDrainTimeout+10*time.Second) {
		t.Fatal("stopPolicySchedulerLoop did not return with a tick parked in " +
			"publishPolicyScheduleState behind a wedged apply. schedulerCancel() " +
			"cancels the scheduler ctx, so the parked acquire is released ONLY if " +
			"the tick acquired with that ctx; acquiring with d.daemonCtx (the raw " +
			"production-uncancelled parent) leaves schedulerWg.Wait() blocked, " +
			"shutdown never reaches HA relinquish, and systemd SIGKILLs the " +
			"process — no rg_active clear, no priority-0 advert, no RA goodbye " +
			"(#8660)")
	}
}
