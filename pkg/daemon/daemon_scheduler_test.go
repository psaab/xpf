package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
	"golang.org/x/sync/semaphore"
)

func TestStartPolicySchedulerLoopLockedWaitsForDaemonContext(t *testing.T) {
	sched, _ := scheduler.NewPrimed(map[string]*config.SchedulerConfig{
		"always": {Name: "always"},
	}, func(context.Context, map[string]bool) error { return nil }, time.Now())

	d := &Daemon{}
	d.scheduler.Store(sched)
	d.startPolicySchedulerLoopLocked()
	if d.schedulerCancel != nil {
		t.Fatal("scheduler loop started before daemon context was available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.daemonCtx = ctx
	d.startPolicySchedulerLoopLocked()
	if d.schedulerCancel == nil {
		t.Fatal("scheduler loop did not start after daemon context became available")
	}
	d.schedulerCancel()
}

func TestReconcilePolicySchedulerLockedKeepsByteIdenticalScheduler(t *testing.T) {
	cfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"always": {Name: "always"},
		},
	}
	d := &Daemon{}

	first := d.reconcilePolicySchedulerLocked(cfg)
	if d.scheduler.Load() == nil {
		t.Fatal("scheduler was not created")
	}
	sched := d.scheduler.Load()
	epoch := d.policySchedulerEpoch.Load()

	second := d.reconcilePolicySchedulerLocked(&config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"always": {Name: "always"},
		},
	})
	if d.scheduler.Load() != sched {
		t.Fatal("byte-identical scheduler config recreated the scheduler")
	}
	if got := d.policySchedulerEpoch.Load(); got != epoch {
		t.Fatalf("epoch = %d, want unchanged %d", got, epoch)
	}
	if first["always"] != second["always"] {
		t.Fatalf("active state changed across identical reconcile: first=%v second=%v", first, second)
	}
}

func TestReconcilePolicySchedulerCarriesFailedRecoveryState(t *testing.T) {
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	oldCfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
		},
	}
	newCfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"workhours": {Name: "workhours", AllDay: true},
		},
	}
	old, initial := scheduler.NewPrimed(oldCfg.Schedulers, func(context.Context, map[string]bool) error { return nil }, now)
	if !initial["workhours"] {
		t.Fatal("old scheduler must start with the permit active")
	}
	failErr := errors.New("republish unavailable")
	old.RecordRepublishResult(failErr, now.Add(-6*time.Minute))
	old.RecordRepublishResult(failErr, now)
	if !old.RepublishFailClosed() || !old.RepublishPending() {
		t.Fatal("test setup did not establish a five-minute fail-closed retry streak")
	}

	oldHash, _ := policySchedulerConfigHash(oldCfg)
	d := &Daemon{policySchedulerConfigHash: oldHash}
	d.setDataplane(&policySchedulerApplyTestDP{})
	d.scheduler.Store(old)
	d.recordSchedulerRepublishResult(failErr)

	activeState := d.reconcilePolicySchedulerLockedAt(newCfg, now)
	replacement := d.scheduler.Load()
	if replacement == nil || replacement == old {
		t.Fatal("changed scheduler config did not replace the scheduler")
	}
	if !replacement.RepublishPending() || !replacement.RepublishFailClosed() {
		t.Fatal("scheduler reconciliation cleared the failed recovery streak")
	}
	if activeState["workhours"] || replacement.ActiveState()["workhours"] {
		t.Fatal("scheduler reconciliation exposed an active permit after fail-closed inheritance")
	}
	if !d.SchedulerRepublishFailed() {
		t.Fatal("scheduler replacement cleared the stale-republish metric")
	}
	d.publishInitialPolicySchedulerStateLocked(newCfg, activeState, nil)
	if !replacement.RepublishPending() || !replacement.RepublishFailClosed() ||
		replacement.ActiveState()["workhours"] {
		t.Fatal("nil-result apply did not retain the inherited deny state and bounded retry")
	}
}

// #8660: the property is unchanged — a cancelled context must release a publish
// parked on the apply semaphore — but WHICH context now matters, and that is the
// whole of the fix.
//
// Before #8660 this cell cancelled `d.daemonCtx` and the publish read that
// field. It passed, and it was TRUE OF A CONFIGURATION PRODUCTION NEVER HAS:
// `d.daemonCtx` is the raw parent (`daemon_run.go` says so twice), never
// cancelled in production, and the nil branch fell back to
// `context.Background()`, which is uncancellable too. So the cell verified a
// release path that no running daemon could take, while the path a running
// daemon DID take was unreleasable — green, and silent about the thing that
// mattered.
//
// The publish now takes the scheduler's ctx as a parameter, so this passes the
// cancelled ctx as the TICK would, and the assertion is about the production
// path rather than beside it.
func TestPublishPolicyScheduleStateReleasesOnSuppliedContext8660(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &Daemon{
		// Deliberately left uncancelled, and it is the control: if the publish
		// ever reads this field again instead of its parameter, the acquire
		// becomes unreleasable and this cell times out.
		daemonCtx: context.Background(),
		applySem:  semaphore.NewWeighted(1),
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire semaphore: %v", err)
	}
	defer d.applySem.Release(1)

	done := make(chan struct{})
	go func() {
		d.publishPolicyScheduleState(ctx, 0, map[string]bool{"always": true})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("publishPolicyScheduleState blocked on the apply semaphore " +
			"after its SUPPLIED context was cancelled. The scheduler tick hands " +
			"it the scheduler's ctx precisely so schedulerCancel() releases a " +
			"parked publish; without that, stopPolicySchedulerLoop's " +
			"schedulerWg.Wait() blocks behind a wedged apply and shutdown never " +
			"reaches HA relinquish (#8660)")
	}
}

// #8660 THE OVER-REJECT CONTROL, and it exists because a mutation showed
// nothing else could see it.
//
// Every other #8660 cell asserts that something RELEASES or RETURNS. That
// family is satisfied by a publish which never does its work at all: mutating
// publishPolicyScheduleState to acquire with an already-cancelled context —
// so it always bails at the acquire and never reaches the update — reds NOTHING
// in this package. The cells were pinning "returns fast", not "returns
// correctly", which is the exact distinction between bounding a stall and
// silently dropping the publish.
//
// So this asserts the other direction: with a LIVE context, the publish must
// WAIT for the apply semaphore rather than skip past it. It is the mirror of
// TestPublishPolicyScheduleStateReleasesOnSuppliedContext8660 — that one says a
// cancelled ctx must not block, this one says a live ctx must not proceed
// without the semaphore.
func TestPublishPolicyScheduleStateWaitsWhenItsContextIsLive8660(t *testing.T) {
	d := &Daemon{
		daemonCtx: context.Background(),
		applySem:  semaphore.NewWeighted(1),
	}
	// A wedged apply holds the only permit.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("precondition acquire: %v", err)
	}

	done := make(chan struct{})
	go func() {
		// Epoch 1 against the daemon's zero value, so the publish returns at
		// the epoch check IMMEDIATELY after the acquire — which is the point:
		// it proves the acquire happened without needing a store, dataplane and
		// config fixture for work this cell is not about. A matching epoch
		// walks into d.store.ActiveConfig() and nil-derefs on a bare Daemon.
		d.publishPolicyScheduleState(context.Background(), 1, map[string]bool{"always": true})
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("publishPolicyScheduleState returned while the apply semaphore was " +
			"held and its context was LIVE. It must wait for the permit — a " +
			"publish that skips the acquire has silently dropped the enforcement " +
			"snapshot, which is a worse failure than the stall #8660 removes and " +
			"is invisible to every cell that only asserts a prompt return (#8660)")
	case <-time.After(250 * time.Millisecond):
		// Still parked, which is correct. Release so the goroutine can finish.
	}
	d.applySem.Release(1)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publishPolicyScheduleState did not proceed after the permit was released")
	}
}
