package daemon

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
)

type policySchedulerActiveStateSetter interface {
	SetPolicySchedulerActiveState(map[string]bool)
}

type policyScheduleStateUpdater interface {
	UpdatePolicyScheduleState(*config.Config, map[string]bool) error
}

// reconcilePolicySchedulerLocked runs under applySem. It makes the scheduler
// lifecycle follow committed config instead of only daemon startup, and returns
// the active-state map that must be used for the same apply transaction.
func (d *Daemon) reconcilePolicySchedulerLocked(cfg *config.Config) map[string]bool {
	return d.reconcilePolicySchedulerLockedAt(cfg, time.Now())
}

func (d *Daemon) reconcilePolicySchedulerLockedAt(cfg *config.Config, now time.Time) map[string]bool {
	hash, hasSchedulers := policySchedulerConfigHash(cfg)
	if sched := d.scheduler.Load(); hasSchedulers && sched != nil && hash == d.policySchedulerConfigHash {
		d.startPolicySchedulerLoopLocked()
		return sched.ActiveState()
	}

	previous := d.scheduler.Load()
	if d.schedulerCancel != nil {
		d.schedulerCancel()
		d.schedulerCancel = nil
	}
	d.scheduler.Store(nil)
	epoch := d.policySchedulerEpoch.Add(1)

	if !hasSchedulers {
		// A removed scheduler set has nothing left to converge.
		d.clearSchedulerRepublishFailure()
		d.policySchedulerConfigHash = [32]byte{}
		return nil
	}

	sched, activeState := scheduler.NewPrimed(cfg.Schedulers, func(ctx context.Context, activeState map[string]bool) error {
		// #8660: the SCHEDULER'S ctx, handed to us by the tick. Not
		// `d.daemonCtx`, which is the raw production-uncancelled parent — a
		// tick parked on the semaphore with that one is released by nothing,
		// so `stopPolicySchedulerLoop`'s `schedulerWg.Wait()` blocked behind a
		// wedged apply and shutdown never reached HA relinquish.
		return d.publishPolicyScheduleState(ctx, epoch, activeState)
	}, now)
	sched.CarryRecoveryStateFrom(previous, now)
	activeState = sched.ActiveState()
	d.scheduler.Store(sched)
	d.policySchedulerConfigHash = hash
	d.startPolicySchedulerLoopLocked()
	return activeState
}

func (d *Daemon) policySchedulerActiveStateForApplyLocked(cfg *config.Config, now time.Time) map[string]bool {
	hash, hasSchedulers := policySchedulerConfigHash(cfg)
	if !hasSchedulers {
		return nil
	}
	if sched := d.scheduler.Load(); sched != nil && hash == d.policySchedulerConfigHash {
		return sched.ActiveState()
	}
	_, activeState := scheduler.NewPrimed(cfg.Schedulers, func(context.Context, map[string]bool) error { return nil }, now)
	return activeState
}

func policySchedulerConfigHash(cfg *config.Config) ([32]byte, bool) {
	if cfg == nil || len(cfg.Schedulers) == 0 {
		return [32]byte{}, false
	}
	h := sha256.New()
	names := make([]string, 0, len(cfg.Schedulers))
	for name := range cfg.Schedulers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writePolicySchedulerHashString(h, name)
		sched := cfg.Schedulers[name]
		if sched == nil {
			writePolicySchedulerHashString(h, "<nil>")
			continue
		}
		writePolicySchedulerHashString(h, sched.Name)
		writePolicySchedulerHashString(h, sched.StartTime)
		writePolicySchedulerHashString(h, sched.StopTime)
		writePolicySchedulerHashString(h, sched.StartDate)
		writePolicySchedulerHashString(h, sched.StopDate)
		writePolicySchedulerHashBool(h, sched.Daily)
		writePolicySchedulerHashBool(h, sched.AllDay)
		// Per-day windows, hashed in a stable weekday order so a change to
		// any per-day arm forces a scheduler re-evaluation.
		dayNames := make([]string, 0, len(sched.Days))
		for day := range sched.Days {
			dayNames = append(dayNames, day)
		}
		sort.Strings(dayNames)
		for _, day := range dayNames {
			writePolicySchedulerHashString(h, day)
			win := sched.Days[day]
			if win == nil {
				writePolicySchedulerHashString(h, "<nil>")
				continue
			}
			writePolicySchedulerHashString(h, win.StartTime)
			writePolicySchedulerHashString(h, win.StopTime)
			writePolicySchedulerHashBool(h, win.AllDay)
			writePolicySchedulerHashBool(h, win.Exclude)
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, true
}

func writePolicySchedulerHashBool(h interface{ Write([]byte) (int, error) }, b bool) {
	if b {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
}

func writePolicySchedulerHashString(h interface{ Write([]byte) (int, error) }, s string) {
	var lenBuf [8]byte
	for i := 0; i < len(lenBuf); i++ {
		lenBuf[i] = byte(uint64(len(s)) >> (8 * i))
	}
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}

func (d *Daemon) startPolicySchedulerLoopLocked() {
	// schedulerStopped latches at shutdown (stopPolicySchedulerLoop): once the
	// loop has been cancelled + joined, a late reconcile must NOT start a new
	// generation — that Add would race the shutdown's schedulerWg.Wait (#5308).
	// Capture the scheduler pointer at start time (a config-replace reconcile
	// may reassign d.scheduler) and track the goroutine on schedulerWg so
	// shutdown can join every generation after cancelling.
	sched := d.scheduler.Load()
	if d.schedulerStopped || d.daemonCtx == nil || sched == nil || d.schedulerCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(d.daemonCtx)
	d.schedulerCancel = cancel
	d.schedulerWg.Add(1)
	go func() {
		defer d.schedulerWg.Done()
		sched.Run(ctx)
	}()
}

// stopPolicySchedulerLoop cancels the policy-scheduler Run() goroutine and
// joins it. It is called from the shutdown sequence BEFORE the dataplane
// runtime the scheduler republishes into (UpdatePolicyScheduleState) is torn
// down, so a late scheduler tick can never run against a closed runtime
// (#5308). The applySem is acquired only to read+cancel schedulerCancel under
// the same lock that guards it, then RELEASED before the join: an in-flight
// tick blocked in publishPolicyScheduleState on applySem.Acquire must be able
// to complete so the goroutine can observe ctx.Done() — holding applySem
// across the join would deadlock. Idempotent / nil-safe: a never-started loop
// (feature disabled, or already cancelled by a config-replace) joins cleanly.
func (d *Daemon) stopPolicySchedulerLoop() {
	// #8597 (muse-004 K23): BOUNDED. This is a shutdown-path acquire, and
	// daemon_run_shutdown.go states the rule at its own drain — "bound it
	// defensively anyway so a wedged apply cannot block the whole shutdown past
	// the drain budget". This was the one shutdown acquire that was not: with
	// context.Background() a wedged apply held it forever, so the scheduler was
	// never cancelled, HA relinquish never ran, and systemd's TimeoutStopSec
	// ended the process with SIGKILL — no rg_active clear, no priority-0
	// advert, no RA goodbye. That is the difference between a sub-second
	// handover and a blackout.
	//
	// On timeout we proceed to cancel + join anyway. The acquire is only there
	// to read+cancel schedulerCancel under the lock that guards it; skipping it
	// costs the mutual exclusion, not correctness of the cancel itself, and a
	// shutdown that reaches the cancel late is strictly better than one that
	// never reaches it.
	//
	// #8660 CLOSED THE RESIDUAL this comment used to describe. A tick parked in
	// publishPolicyScheduleState now acquires with the SCHEDULER'S ctx — handed
	// to the daemon's updateFn as a parameter by the tick that calls it — so
	// the cancel below releases it and schedulerWg.Wait() returns. It used to
	// acquire with d.daemonCtx, the RAW production-uncancelled parent
	// (daemon_run.go states that twice), with a context.Background() fallback
	// that was uncancellable too: there was no configuration in which cancelling
	// released a parked tick, so this Wait could still block behind the same
	// wedged apply that this function's own bounded acquire exists to survive.
	//
	// Kept as a note rather than deleted because the ORDER below is what makes
	// it work: cancel() must run before Wait(), and the cancel is of the ctx the
	// tick is parked on. Reversing them, or handing the tick a different ctx,
	// reinstates the stall.
	acquired := false
	if d.applySem != nil {
		acqCtx, cancelAcq := context.WithTimeout(context.Background(), applyCloseoutDrainTimeout)
		if err := d.applySem.Acquire(acqCtx, 1); err == nil {
			acquired = true
		} else {
			slog.Warn("shutdown: timed out acquiring the apply semaphore to stop the "+
				"policy scheduler; cancelling it anyway", "err", err,
				"timeout", applyCloseoutDrainTimeout, "issue", "#8597")
		}
		cancelAcq()
	}
	d.schedulerStopped = true
	cancel := d.schedulerCancel
	d.schedulerCancel = nil
	if acquired {
		d.applySem.Release(1)
	}
	if cancel != nil {
		cancel()
	}
	d.schedulerWg.Wait()
}

// publishPolicyScheduleState is the scheduler's updateFn. It returns a
// non-nil error only when a live scheduler-driven republish did NOT
// converge, which the scheduler uses to retry autonomously on its next
// tick and which recordSchedulerRepublishResult surfaces as the
// xpf_scheduler_republish_failed metric (#3780). Shutdown / torn-down /
// nothing-to-publish cases return nil (no retry, no alarm).
// publishPolicyScheduleState republishes the enforcement snapshot for one
// scheduler tick.
//
// #8660: `ctx` is the SCHEDULER'S context, supplied by the tick that called us,
// and acquiring the semaphore with it is what makes shutdown able to join this
// goroutine. It previously read `d.daemonCtx` with a `context.Background()`
// fallback — and BOTH of those are uncancellable, so there was no configuration
// in which a parked acquire could be released. `stopPolicySchedulerLoop` cancels
// a CHILD of `d.daemonCtx` and then calls `schedulerWg.Wait()`; with the tick
// waiting on the uncancellable parent the cancel released nothing and the join
// blocked behind whatever wedged the apply, so shutdown never reached HA
// relinquish and systemd SIGKILLed the process — no `rg_active` clear, no
// priority-0 advert, no RA goodbye.
//
// The K23 fix bounded the OTHER acquire (`stopPolicySchedulerLoop`'s own). This
// closes the residual it documented rather than widening any timeout: a longer
// bound would still be a stall, and would satisfy a wall-clock cell while
// leaving the join blocked.
func (d *Daemon) publishPolicyScheduleState(ctx context.Context, epoch uint64, activeState map[string]bool) error {
	if ctx == nil {
		// Only a caller that is not the scheduler tick can reach this, and it
		// has no lifecycle to inherit. Kept total rather than panicking.
		ctx = context.Background()
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		// Daemon context cancelled — the daemon is shutting down and the
		// scheduler loop is stopping too. Nothing to retry.
		slog.Warn("scheduler: failed to acquire apply semaphore", "err", err)
		return nil
	}
	defer d.applySem.Release(1)

	if epoch != d.policySchedulerEpoch.Load() {
		// A reconcile replaced this scheduler instance; the new instance
		// owns republish. Do not latch a retry on the dead one.
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || d.dataplane() == nil {
		return nil
	}
	d.seedPolicySchedulerActiveStateLocked(activeState)
	err := d.updatePolicyScheduleStateLocked(cfg, activeState)
	d.recordSchedulerRepublishResult(err)
	return err
}

func (d *Daemon) seedPolicySchedulerActiveStateLocked(activeState map[string]bool) {
	if setter, ok := d.dataplane().(policySchedulerActiveStateSetter); ok {
		setter.SetPolicySchedulerActiveState(activeState)
	}
}

func (d *Daemon) updatePolicyScheduleStateLocked(cfg *config.Config, activeState map[string]bool) error {
	rt := d.dataplane()
	if rt == nil {
		return nil
	}
	// Both in-tree backends satisfy policyScheduleStateUpdater
	// directly: *dataplane.Manager via UpdatePolicyScheduleState in
	// pkg/dataplane/maps_policy.go
	// and *dataplane/userspace.LegacyDataPlaneAdapter via
	// pkg/dataplane/userspace/legacy_dataplane.go:161. The legacyDP()
	// fallback branch was dead code; removed in #1519.
	if updater, ok := rt.(policyScheduleStateUpdater); ok {
		return updater.UpdatePolicyScheduleState(cfg, activeState)
	}
	return nil
}

// recordPolicySchedulerInitialPublishResult keeps apply-transaction publishes
// and scheduler-tick publishes on the same recovery path.
func (d *Daemon) recordPolicySchedulerInitialPublishResult(err error) {
	if sched := d.scheduler.Load(); sched != nil {
		sched.RecordRepublishResult(err, time.Now())
	}
	d.recordSchedulerRepublishResult(err)
}

// recordSchedulerRepublishResult latches or clears the scheduler
// republish-failure metric from a republish result (#3780). This is the
// observability side of the scheduler self-heal: while a
// scheduler-driven republish keeps failing, xpf_scheduler_republish_failed
// reads 1 and xpf_scheduler_republish_stale_seconds climbs, so stale
// enforcement (a permit still live past its window, or a block that never
// engaged) is visible to monitoring instead of silent. The transition
// itself is retried by the scheduler on its next tick.
func (d *Daemon) recordSchedulerRepublishResult(err error) {
	if err != nil {
		if d.schedulerRepublishFailing.CompareAndSwap(false, true) {
			d.schedulerRepublishFirstFailNanos.Store(time.Now().UnixNano())
			slog.Error("scheduler: policy schedule republish FAILED; enforcement is stale (a permit may still be live past its window, or a scheduled block never engaged) — retrying on the next scheduler tick until it converges",
				"err", err)
		}
		return
	}
	if d.schedulerRepublishFailing.CompareAndSwap(true, false) {
		d.schedulerRepublishFirstFailNanos.Store(0)
		slog.Info("scheduler: policy schedule republish recovered; enforcement is back in sync with the schedule window")
	}
}

// clearSchedulerRepublishFailure resets the republish-failure metric when the
// scheduler set is removed.
func (d *Daemon) clearSchedulerRepublishFailure() {
	if d.schedulerRepublishFailing.Swap(false) {
		d.schedulerRepublishFirstFailNanos.Store(0)
	}
}

// SchedulerRepublishFailed reports whether the most recent
// scheduler-driven policy republish failed and has not yet converged
// (#3780). Lock-free; safe for the metrics collector goroutine.
func (d *Daemon) SchedulerRepublishFailed() bool {
	return d.schedulerRepublishFailing.Load()
}

// SchedulerRepublishStaleSeconds returns how long the current
// scheduler-republish failure streak has gone unconverged, in seconds
// (0 when healthy) (#3780).
func (d *Daemon) SchedulerRepublishStaleSeconds() float64 {
	if !d.schedulerRepublishFailing.Load() {
		return 0
	}
	first := d.schedulerRepublishFirstFailNanos.Load()
	if first == 0 {
		return 0
	}
	age := time.Now().UnixNano() - first
	if age < 0 {
		return 0
	}
	return time.Duration(age).Seconds()
}

// SchedulerRepublishFailClosed reports whether the scheduler has escalated from
// the #3780 silent retry to FAIL-CLOSED: once a scheduler-republish failure
// streak persists past scheduler.RepublishFailClosedAge the scheduler forces
// scheduled policies to the inactive (deny) disposition and emits a one-time
// alarm so a scheduled permit stops (re)opening while the dataplane cannot
// enforce the schedule (#5669).
//
// This reads the scheduler's OWN latch (RepublishFailClosed) rather than
// recomputing the age daemon-side, so the xpf_scheduler_republish_fail_closed
// gauge is the single source of truth with the scheduler's force-inactive/alarm
// decision — no second continuous-time timer that could read 1 up to one 60 s
// tick before the scheduler actually latches. Lock-free at the daemon level:
// d.scheduler is an atomic.Pointer, and RepublishFailClosed takes only the
// scheduler's own RLock (never applySem), so the metrics collector never blocks
// behind a long apply or a wedged republish. Returns false when no scheduler is
// installed (nil pointer).
func (d *Daemon) SchedulerRepublishFailClosed() bool {
	sched := d.scheduler.Load()
	if sched == nil {
		return false
	}
	return sched.RepublishFailClosed()
}
