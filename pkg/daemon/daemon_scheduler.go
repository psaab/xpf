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

type policySchedulerActiveStateLatchSetter interface {
	SetPolicySchedulerActiveStateWithLatch(map[string]bool, bool)
}
type policyScheduleFailClosedUpdater interface {
	UpdatePolicyScheduleStateWithLatch(*config.Config, map[string]bool, bool) error
}

type policyScheduleHeartbeatUpdater interface {
	HeartbeatPolicyScheduler(context.Context)
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

	var sched *scheduler.Scheduler
	loc := policySchedulerLocation(cfg, now)
	sched, activeState := scheduler.NewPrimedInLocation(cfg.Schedulers, func(ctx context.Context, activeState map[string]bool) error {
		// #8660: the SCHEDULER'S ctx, handed to us by the tick. Not
		// `d.daemonCtx`, which is the raw production-uncancelled parent — a
		// tick parked on the semaphore with that one is released by nothing,
		// so `stopPolicySchedulerLoop`'s `schedulerWg.Wait()` blocked behind a
		// wedged apply and shutdown never reached HA relinquish.
		failClosed := sched != nil && sched.PolicyFailClosed(time.Now())
		return d.publishPolicyScheduleStateWithLatch(ctx, epoch, activeState, failClosed)
	}, now, loc)
	sched.SetHeartbeatFn(func(ctx context.Context) {
		d.heartbeatPolicySchedule(ctx, epoch)
	})
	sched.CarryRecoveryStateFrom(previous, now)
	activeState = sched.ActiveState()
	d.scheduler.Store(sched)
	d.policySchedulerConfigHash = hash
	d.startPolicySchedulerLoopLocked()
	return activeState
}

func (d *Daemon) policySchedulerActiveStateForApplyLocked(cfg *config.Config, now time.Time) map[string]bool {
	activeState, _ := d.policySchedulerActiveStateAndFailClosedForApplyLocked(cfg, now)
	return activeState
}

func (d *Daemon) policySchedulerActiveStateAndFailClosedForApplyLocked(cfg *config.Config, now time.Time) (map[string]bool, bool) {
	hash, hasSchedulers := policySchedulerConfigHash(cfg)
	if !hasSchedulers {
		return nil, false
	}
	previous := d.scheduler.Load()
	failClosed := false
	if previous != nil {
		var previousState map[string]bool
		previousState, failClosed = previous.ActiveStateWithFailClosed()
		if previous.InRecoveryHold(now) {
			// #12885: a wall-clock recovery hold survives a scheduler
			// config change for apply seeding — prime nothing active.
			failClosed = true
		}
		if hash == d.policySchedulerConfigHash {
			failClosed = failClosed || previous.PolicyFailClosed(now)
			if failClosed {
				for name := range previousState {
					previousState[name] = false
				}
			}
			return previousState, failClosed
		}
	}
	loc := policySchedulerLocation(cfg, now)
	_, activeState := scheduler.NewPrimedInLocation(cfg.Schedulers, func(context.Context, map[string]bool) error { return nil }, now, loc)
	if failClosed || loc == nil {
		failClosed = true
		for name := range activeState {
			activeState[name] = false
		}
	}
	return activeState, failClosed
}

// policySchedulerLocation returns the committed system zone for scheduler
// evaluation. Empty configuration preserves the host-local behavior; an
// unavailable configured zone returns nil so the scheduler fails closed rather
// than inheriting a potentially stale process-local zone.
func policySchedulerLocation(cfg *config.Config, now time.Time) *time.Location {
	if cfg == nil || cfg.System.TimeZone == "" {
		return now.Location()
	}
	loc, err := time.LoadLocation(cfg.System.TimeZone)
	if err != nil {
		slog.Warn("scheduler: configured system time zone unavailable; scheduled policies will stay inactive",
			"timezone", cfg.System.TimeZone, "err", err)
		return nil
	}
	return loc
}

// policySchedulerPublicationState includes the action-aware fail-closed
// disposition on every partial snapshot path. During recovery, no scheduled
// permit may be active, while scheduled DENY/REJECT remain eligible.
func policySchedulerPublicationState(sched *scheduler.Scheduler, now time.Time) (map[string]bool, bool) {
	if sched == nil {
		return nil, false
	}
	activeState, failClosed := sched.ActiveStateWithFailClosed()
	failClosed = failClosed || sched.PolicyFailClosed(now)
	if failClosed {
		for name := range activeState {
			activeState[name] = false
		}
	}
	return activeState, failClosed
}

func policySchedulerConfigHash(cfg *config.Config) ([32]byte, bool) {
	if cfg == nil || len(cfg.Schedulers) == 0 {
		return [32]byte{}, false
	}
	h := sha256.New()
	// #10949: a configured timezone is scheduler input even when scheduler
	// windows themselves are unchanged. Hash it so a commit replaces the
	// scheduler generation and publishes state in the new location.
	config.WriteSchedulerHashString(h, cfg.System.TimeZone)
	names := make([]string, 0, len(cfg.Schedulers))
	for name := range cfg.Schedulers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		config.WriteSchedulerHashString(h, name)
		cfg.Schedulers[name].Fingerprint(h)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, true
}

func (d *Daemon) startPolicySchedulerLoopLocked() {
	// schedulerStopped latches at shutdown (stopPolicySchedulerLoop): once the
	// loop has been cancelled + joined, a late reconcile must NOT start a new
	// generation — that Add would race the shutdown's schedulerWg.Wait (#5308).
	// Capture the scheduler pointer at start time (a config-replace reconcile
	// may reassign d.scheduler) and track the goroutine on schedulerWg so
	// shutdown can join every generation after cancelling.
	sched := d.scheduler.Load()
	if d.schedulerStopped.Load() || d.daemonCtx == nil || sched == nil || d.schedulerCancel != nil {
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
// runtime the scheduler republishes into (UpdatePolicyScheduleStateWithLatch) is torn
// down, so a late scheduler tick can never run against a closed runtime
// (#5308). The applySem is acquired only to read+cancel schedulerCancel under
// the same lock that guards it, then RELEASED before the join: an in-flight
// tick blocked in publishPolicyScheduleState on applySem.Acquire must be able
// to complete so the goroutine can observe ctx.Done() — holding applySem
// across the join would deadlock. Idempotent / nil-safe: a never-started loop
// (feature disabled, or already cancelled by a config-replace) joins cleanly.
func (d *Daemon) stopPolicySchedulerLoop() {
	ctx, cancel := newShutdownApplyContext()
	defer cancel()
	d.stopPolicySchedulerLoopWithContext(ctx)
}

// stopPolicySchedulerLoopWithContext shares the shutdown apply deadline with
// the ordered teardown. The stopped latch is checked before acquiring
// applySem, so Run's defensive deferred call is an immediate no-op after the
// sequence has already stopped the scheduler.
func (d *Daemon) stopPolicySchedulerLoopWithContext(ctx context.Context) {
	if d.schedulerStopped.Load() || !d.schedulerStopped.CompareAndSwap(false, true) {
		return
	}

	// #8597 (muse-004 K23): BOUNDED. This is a shutdown-path acquire, and
	// daemon_run_shutdown.go shares one deadline across the drain, scheduler
	// stop, and tunable restore. Before #8597 this acquire used
	// context.Background(); with a wedged apply the scheduler was never
	// cancelled, HA relinquish never ran, and systemd's TimeoutStopSec ended
	// the process with SIGKILL — no rg_active clear, no priority-0 advert, no
	// RA goodbye. That is the difference between a sub-second handover and
	// a blackout.
	//
	// #8660 CLOSED THE RESIDUAL this comment used to describe. A tick parked
	// in publishPolicyScheduleState now acquires with the SCHEDULER'S ctx —
	// handed to the daemon's updateFn by the tick that calls it — so the
	// cancel below releases it and schedulerWg.Wait() returns. It used to
	// acquire with d.daemonCtx, the RAW production-uncancelled parent
	// (daemon_run.go states that twice), with a context.Background() fallback
	// that was uncancellable too: there was no configuration in which
	// cancelling released a parked tick, so this Wait could still block
	// behind the same wedged apply that this function's own bounded acquire
	// exists to survive.
	//
	// Kept as a note rather than deleted because the ORDER below is what
	// makes it work: cancel() must run before Wait(), and the cancel is of
	// the ctx the tick is parked on. Reversing them, or handing the tick a
	// different ctx, reinstates the stall.
	waitBudget := time.Duration(0)
	if deadline, ok := ctx.Deadline(); ok {
		waitBudget = time.Until(deadline)
		if waitBudget < 0 {
			waitBudget = 0
		}
	}
	acquired, acquireErr := d.acquireApplySemForShutdownContext(ctx)
	if d.applySem != nil && !acquired {
		slog.Warn("shutdown: timed out acquiring the apply semaphore to stop the "+
			"policy scheduler; cancelling it anyway", "err", acquireErr,
			"wait_budget", waitBudget, "issue", "#8597")
	}
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
	return d.publishPolicyScheduleStateWithLatch(ctx, epoch, activeState, false)
}

func (d *Daemon) publishPolicyScheduleStateWithLatch(ctx context.Context, epoch uint64, activeState map[string]bool, failClosed bool) error {
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
	d.seedPolicySchedulerActiveStateLocked(activeState, failClosed)
	err := d.updatePolicyScheduleStateWithLatchLocked(cfg, activeState, failClosed)
	d.recordSchedulerRepublishResult(err)
	return err
}

// heartbeatPolicySchedule refreshes the dataplane lease on an unchanged,
// converged scheduler tick. It is deliberately outside the republish result
// path: a heartbeat failure must not latch scheduler snapshot failure.
func (d *Daemon) heartbeatPolicySchedule(ctx context.Context, epoch uint64) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)

	if epoch != d.policySchedulerEpoch.Load() || ctx.Err() != nil {
		return
	}
	if d.store.ActiveConfig() == nil {
		return
	}
	if updater, ok := d.dataplane().(policyScheduleHeartbeatUpdater); ok {
		updater.HeartbeatPolicyScheduler(ctx)
	}
}

func (d *Daemon) seedPolicySchedulerActiveStateLocked(activeState map[string]bool, failClosed bool) {
	rt := d.dataplane()
	if setter, ok := rt.(policySchedulerActiveStateLatchSetter); ok {
		setter.SetPolicySchedulerActiveStateWithLatch(activeState, failClosed)
	}
}

// updatePolicyScheduleStateLocked is the apply-transaction publication: it
// carries no stale-republish latch, so it forwards failClosed=false to the
// latch updater every published backend satisfies (see the compile-time
// assertions in policy_scheduler_published_type_17082.go). Before #17082 the
// optional-interface fallback was needed only by the retired eBPF backend;
// both published userspace types also expose the non-latch method and satisfy
// the latch updater used here.
func (d *Daemon) updatePolicyScheduleStateLocked(cfg *config.Config, activeState map[string]bool) error {
	return d.updatePolicyScheduleStateWithLatchLocked(cfg, activeState, false)
}

func (d *Daemon) updatePolicyScheduleStateWithLatchLocked(cfg *config.Config, activeState map[string]bool, failClosed bool) error {
	rt := d.dataplane()
	if rt == nil {
		return nil
	}
	if updater, ok := rt.(policyScheduleFailClosedUpdater); ok {
		return updater.UpdatePolicyScheduleStateWithLatch(cfg, activeState, failClosed)
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

// SchedulerRepublishFailClosed reports whether the scheduler's bounded-age
// republish failure latch is set. The scheduler keeps its authoritative
// scheduled-policy state inactive while republish remains failed, but the
// last-known schedule in a wedged dataplane may still permit traffic because
// this latch cannot expire a published schedule independently (#10906).
//
// This reads the scheduler's OWN latch (RepublishFailClosed), not a separately
// recomputed daemon-side age, so the
// xpf_scheduler_republish_fail_open_stale gauge reports the same latch as the
// scheduler's alarm. Lock-free at the daemon level: d.scheduler is an
// atomic.Pointer, and RepublishFailClosed takes only the scheduler's RLock
// (never applySem), so the metrics collector never blocks behind a long apply
// or wedged republish. Returns false when no scheduler is installed.
func (d *Daemon) SchedulerRepublishFailClosed() bool {
	sched := d.scheduler.Load()
	if sched == nil {
		return false
	}
	return sched.RepublishFailClosed()
}
