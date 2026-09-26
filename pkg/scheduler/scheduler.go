package scheduler

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Scheduler periodically evaluates time windows for named schedulers
// and notifies a callback when any scheduler's active state changes.
type Scheduler struct {
	mu         sync.RWMutex
	schedulers map[string]*config.SchedulerConfig
	active     map[string]bool
	// #8660: updateFn receives the SCHEDULER'S ctx, not one it reaches for.
	//
	// The daemon's updateFn acquires a semaphore, and which ctx it acquires
	// with decides whether shutdown can join this goroutine. It used to reach
	// for `d.daemonCtx` — the raw, production-uncancelled parent — so
	// cancelling the scheduler released nothing and `schedulerWg.Wait()`
	// blocked behind a wedged apply. The cancellable ctx already existed one
	// frame up, in `Run`; it was simply not passed down.
	//
	// Taking it as a PARAMETER rather than storing it makes that a type
	// obligation: the next updateFn is handed the right ctx instead of having
	// to know which of two to reach for, which is the defect itself.
	updateFn func(ctx context.Context, activeState map[string]bool) error
	// #8660: the tick interval, defaulting to defaultTickInterval. It exists
	// so a test can bind `Run`'s ctx-threading END TO END rather than calling
	// `evaluate` directly — a cell that calls `evaluate` cannot see `Run`
	// handing down the wrong context, which is exactly the defect #8660 fixed.
	// Verified by mutation: with `Run` passing context.Background(), an
	// evaluate-level cell stays green.
	tickInterval     time.Duration
	lastEval         time.Time
	lastWallUnixNano int64
	unsafeUntil      time.Time

	// #3780: republish self-heal. A scheduler window transition
	// republishes the enforcement snapshot via updateFn. When that
	// republish FAILS the transition has NOT converged — a scheduled
	// permit whose window just closed would keep forwarding (fail-open),
	// or a scheduled block would never engage. updateFn returning a
	// non-nil error latches republishPending so the NEXT evaluate tick
	// re-fires updateFn even when the active-state map did not change,
	// retrying the transition on the scheduler's own throttle-paced
	// 60 s sweep until it converges. republishFirstFail records when the
	// current failure streak began (for stale-state age); republishFailures
	// is the cumulative failure count. All guarded by mu.
	republishPending   bool
	republishFirstFail time.Time
	republishFailures  uint64
	lastRepublishErr   error

	// #5669: bounded-age fail-closed. The #3780 self-heal retries a failed
	// republish every tick, but a PERSISTENTLY failing republish (a wedged
	// control socket, an incompatible helper) leaves the stale window
	// fail-OPEN — a scheduled permit still forwarding past its close — for as
	// long as the retry keeps failing, silently. Once the failure streak
	// exceeds republishFailClosedAge the streak can no longer be a single
	// transient stall, so the scheduler latches republishFailClosed: it emits
	// a one-time alert AND forces every scheduled policy to the INACTIVE
	// (deny) disposition in the published + authoritative active map, refusing
	// to keep or open any scheduled permit while enforcement is known-wedged.
	// This is safe because it engages ONLY while the republish is failing
	// (enforcement already broken — never a converged, genuinely-active
	// window) and clears on the next successful republish. Guarded by mu.
	republishFailClosed bool
}

const (
	wallClockDriftTolerance = 5 * time.Second
	wallClockRecoveryHold   = 2 * time.Minute

	// RepublishFailClosedAge bounds how long a scheduler-driven republish may
	// keep failing before the scheduler escalates from the #3780 silent retry
	// to a loud fail-closed posture (see the republishFailClosed field). Five
	// minutes is roughly five 60 s evaluate ticks: long enough to absorb a
	// burst of control-socket contention (status poll + HA sync + session
	// installs + snapshot sync share the socket, see CLAUDE.md) without a false
	// alarm, short enough that a genuinely stuck republish is surfaced and
	// failed closed promptly. Exported so the daemon's
	// xpf_scheduler_republish_fail_closed alarm shares this single bound
	// (#5669).
	RepublishFailClosedAge = 5 * time.Minute
)

// NewPrimed creates a Scheduler, evaluates the initial active-state map, and
// returns that map without firing updateFn from inside the constructor. Daemon
// apply paths use this when they already hold their own serialization lock and
// must publish the initial state as part of the same apply transaction.
func NewPrimed(schedulers map[string]*config.SchedulerConfig, updateFn func(ctx context.Context, activeState map[string]bool) error, now time.Time) (*Scheduler, map[string]bool) {
	s := &Scheduler{
		schedulers: schedulers,
		active:     make(map[string]bool),
		updateFn:   updateFn,
	}
	// notify=false: updateFn is not fired from the constructor, so this ctx
	// is never observed by a callback.
	s.evaluate(context.Background(), now, false)
	return s, s.ActiveState()
}

// New creates a Scheduler with the given scheduler configs and update callback.
// updateFn is called whenever any scheduler's active state changes, receiving
// the current active state of all schedulers.
func New(schedulers map[string]*config.SchedulerConfig, updateFn func(ctx context.Context, activeState map[string]bool) error) *Scheduler {
	s, _ := NewPrimed(schedulers, updateFn, time.Now())
	// Preserve the historical constructor contract: New notifies on initial
	// state. NewPrimed is the no-notify variant for callers that publish the
	// initial state under an external lock.
	if len(s.active) > 0 {
		// #8660: the constructor has no lifecycle of its own — the caller has
		// not started Run yet — so this notify is not something shutdown can
		// or needs to interrupt. `New` has no production caller in any case;
		// the daemon builds through NewPrimed.
		s.notifyActiveState(context.Background())
	}
	return s
}

// Run starts the evaluation loop, checking every 60 seconds. It blocks until
// the context is cancelled.
// defaultTickInterval is the production evaluation period. Unchanged by #8660;
// named so the seam beside it cannot drift from it silently.
const defaultTickInterval = 60 * time.Second

func (s *Scheduler) Run(ctx context.Context) {
	slog.Info("scheduler: starting evaluation loop")
	s.mu.RLock()
	interval := s.tickInterval
	s.mu.RUnlock()
	if interval <= 0 {
		interval = defaultTickInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler: stopping evaluation loop")
			return
		case t := <-ticker.C:
			s.evaluate(ctx, t, true)
		}
	}
}

// IsActive reports whether the named scheduler is currently active.
func (s *Scheduler) IsActive(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active[name]
}

// ActiveState returns a copy of the current active state for all schedulers.
func (s *Scheduler) ActiveState() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]bool, len(s.active))
	for k, v := range s.active {
		out[k] = v
	}
	return out
}

// Update replaces the scheduler configurations and re-evaluates immediately.
func (s *Scheduler) Update(schedulers map[string]*config.SchedulerConfig) {
	s.mu.Lock()
	s.schedulers = schedulers
	s.mu.Unlock()
	// #8660: no production caller — the daemon never calls Update, it builds a
	// fresh scheduler on reconcile. A background ctx keeps the signature total
	// rather than inventing a lifecycle this path does not have.
	s.evaluate(context.Background(), time.Now(), true)
}

// evaluate checks each scheduler against the current time and fires the
// callback if any state changed.
func (s *Scheduler) evaluate(ctx context.Context, now time.Time, notify bool) {
	s.mu.Lock()

	changed := false
	newActive := make(map[string]bool, len(s.schedulers))
	wallClockDiscontinuous := s.wallClockDiscontinuousLocked(now)
	wallClockUnsafe := wallClockDiscontinuous
	if !wallClockUnsafe && !s.unsafeUntil.IsZero() {
		if now.Before(s.unsafeUntil) {
			wallClockUnsafe = true
		} else {
			s.unsafeUntil = time.Time{}
		}
	}

	// #5669: while the republish has been failing past the bounded age
	// (republishFailClosed, latched in recordRepublishResultLocked), force
	// every scheduled policy to the INACTIVE (deny) disposition instead of
	// publishing or keeping an ACTIVE permit the wedged dataplane cannot
	// enforce. Read the latch once so the whole map is a coherent fail-closed
	// view; it clears on the next successful republish, after which the true
	// window state is republished and any legitimately-open permit reopens.
	failClosed := s.republishFailClosed
	for name, sched := range s.schedulers {
		cur := false
		if !wallClockUnsafe {
			cur = isWithinWindow(now, sched)
		}
		if failClosed {
			cur = false
		}
		newActive[name] = cur
		if prev, ok := s.active[name]; !ok || prev != cur {
			slog.Info("scheduler: state changed", "name", name, "active", cur)
			changed = true
		}
	}

	// Detect removed schedulers.
	for name := range s.active {
		if _, ok := newActive[name]; !ok {
			slog.Info("scheduler: removed", "name", name)
			changed = true
		}
	}

	s.active = newActive
	if wallClockDiscontinuous {
		s.unsafeUntil = now.Add(wallClockRecoveryHold)
	}
	s.lastEval = now
	s.lastWallUnixNano = now.UnixNano()

	// #3780: fire on a state change OR when a prior republish is still
	// pending. Re-firing on the pending flag is the self-heal: a
	// window transition whose republish failed is retried on the next
	// throttle-paced tick with the CURRENT active state, so the stale
	// enforcement (a permit past its window / a block that never
	// engaged) converges instead of persisting until the next unrelated
	// state change hours away.
	if (!changed && !s.republishPending) || !notify || s.updateFn == nil {
		s.mu.Unlock()
		return
	}
	cp := copyActiveState(newActive)
	updateFn := s.updateFn
	s.mu.Unlock()
	err := updateFn(ctx, cp)
	s.mu.Lock()
	s.recordRepublishResultLocked(err, now)
	s.mu.Unlock()
}

// recordRepublishResultLocked latches or clears the republish self-heal
// state from an updateFn result (#3780). MUST be called with s.mu held.
func (s *Scheduler) recordRepublishResultLocked(err error, now time.Time) {
	if err != nil {
		if !s.republishPending {
			s.republishFirstFail = now
		}
		s.republishPending = true
		s.republishFailures++
		s.lastRepublishErr = err
		// #5669: bounded-age fail-closed escalation. Once the failure streak
		// exceeds RepublishFailClosedAge the stale enforcement window has
		// persisted well beyond a single 60 s retry, so escalate ONCE from the
		// silent #3780 retry to a loud fail-closed alarm. The latch makes the
		// next evaluate publish an all-inactive (deny) map, so a scheduled
		// permit stops forwarding past its close instead of relying on an
		// eventual republish recovery that may never come.
		if !s.republishFailClosed && !s.republishFirstFail.IsZero() &&
			now.Sub(s.republishFirstFail) >= RepublishFailClosedAge {
			s.republishFailClosed = true
			slog.Warn("scheduler: republish FAIL-CLOSED — enforcement has been stale past the bounded age; forcing scheduled policies inactive (deny) and refusing to reopen them until republish recovers (a scheduled permit may still be forwarding past its window close in a wedged dataplane — investigate the helper/control socket)",
				"stale_for", now.Sub(s.republishFirstFail),
				"bound", RepublishFailClosedAge,
				"failures", s.republishFailures,
				"err", err)
		}
		return
	}
	if s.republishFailClosed {
		slog.Info("scheduler: republish recovered from fail-closed; republishing the true schedule window state",
			"failures", s.republishFailures)
	}
	s.republishPending = false
	s.republishFirstFail = time.Time{}
	s.republishFailClosed = false
	s.lastRepublishErr = nil
}

// RepublishPending reports whether the most recent scheduler-driven
// republish failed and is awaiting an autonomous retry on the next tick
// (#3780).
func (s *Scheduler) RepublishPending() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.republishPending
}

// RepublishFailureStatus returns the pending flag, the cumulative
// failure count, and the time the current failure streak began (zero
// when not pending). Feeds the scheduler_republish_failed metric and
// its stale-state age (#3780).
func (s *Scheduler) RepublishFailureStatus() (pending bool, failures uint64, since time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.republishPending, s.republishFailures, s.republishFirstFail
}

// RepublishFailClosed reports whether a scheduler-driven republish has been
// failing continuously for longer than RepublishFailClosedAge, i.e. the stale
// enforcement window has persisted past the bounded age and the scheduler has
// escalated to fail-closed: it forces every scheduled policy to the inactive
// (deny) disposition and has emitted the fail-closed alarm. Latched at the
// bound, cleared on the next successful republish. Feeds the
// xpf_scheduler_republish_fail_closed alarm (#5669).
func (s *Scheduler) RepublishFailClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.republishFailClosed
}

// CarryRecoveryStateFrom preserves the safety and retry state when a config
// change replaces this scheduler. The replacement has already been primed for
// its new config; an active state computed during an inherited clock hold or
// fail-closed streak must therefore be suppressed before it can be published.
func (s *Scheduler) CarryRecoveryStateFrom(previous *Scheduler, now time.Time) {
	if s == nil || previous == nil || s == previous {
		return
	}

	previous.mu.RLock()
	lastEval := previous.lastEval
	lastWallUnixNano := previous.lastWallUnixNano
	unsafeUntil := previous.unsafeUntil
	republishPending := previous.republishPending
	republishFirstFail := previous.republishFirstFail
	republishFailures := previous.republishFailures
	lastRepublishErr := previous.lastRepublishErr
	republishFailClosed := previous.republishFailClosed
	previous.mu.RUnlock()

	s.mu.Lock()
	s.lastEval = lastEval
	s.lastWallUnixNano = lastWallUnixNano
	s.unsafeUntil = unsafeUntil
	s.republishPending = republishPending
	s.republishFirstFail = republishFirstFail
	s.republishFailures = republishFailures
	s.lastRepublishErr = lastRepublishErr
	s.republishFailClosed = republishFailClosed
	if republishFailClosed || (!unsafeUntil.IsZero() && now.Before(unsafeUntil)) {
		for name := range s.active {
			s.active[name] = false
		}
	}
	s.mu.Unlock()
}

// RecordRepublishResult records the result of an initial publish performed by
// the daemon's apply transaction rather than by evaluate's retry callback.
func (s *Scheduler) RecordRepublishResult(err error, now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.recordRepublishResultLocked(err, now)
	s.mu.Unlock()
}

func (s *Scheduler) wallClockDiscontinuousLocked(now time.Time) bool {
	if s.lastEval.IsZero() {
		return false
	}
	wallElapsed := time.Duration(now.UnixNano() - s.lastWallUnixNano)
	if wallElapsed < 0 {
		slog.Warn("scheduler: wall clock moved backward, failing closed during recovery hold",
			"previous", s.lastEval, "current", now)
		return true
	}
	monoElapsed := now.Sub(s.lastEval)
	if monoElapsed < 0 {
		slog.Warn("scheduler: monotonic clock moved backward, failing closed during recovery hold",
			"previous", s.lastEval, "current", now)
		return true
	}
	delta := wallElapsed - monoElapsed
	if delta < 0 {
		delta = -delta
	}
	if delta > wallClockDriftTolerance {
		slog.Warn("scheduler: wall clock drift exceeded tolerance, failing closed during recovery hold",
			"wall_elapsed", wallElapsed, "monotonic_elapsed", monoElapsed, "tolerance", wallClockDriftTolerance)
		return true
	}
	return false
}

func (s *Scheduler) notifyActiveState(ctx context.Context) {
	s.mu.RLock()
	if s.updateFn == nil {
		s.mu.RUnlock()
		return
	}
	cp := copyActiveState(s.active)
	updateFn := s.updateFn
	s.mu.RUnlock()
	err := updateFn(ctx, cp)
	s.mu.Lock()
	s.recordRepublishResultLocked(err, time.Now())
	s.mu.Unlock()
}

func copyActiveState(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// isWithinWindow determines whether now falls within the time window defined
// by sched.
//
// Fail-closed (#3849): an ABSENT window is INACTIVE, never always-on. A
// scheduler that resolves to no window at all — no daily window, no per-day
// window for today, and no date-only range — returns false. This is the
// security half of the fix: a policy `scheduler-name` bound to a window that
// failed to compile (or was left empty) must DENY, not permit 24/7. The old
// "no times configured => active" shortcut was the fail-open bug.
func isWithinWindow(now time.Time, sched *config.SchedulerConfig) bool {
	// Date-range gate (outer). A configured calendar range that now falls
	// outside of closes the scheduler regardless of any time-of-day window.
	inRange, ok := withinDateRange(now, sched)
	if !ok {
		return false // unparseable date -> fail closed
	}
	if !inRange {
		return false
	}

	// Resolve the window that applies to today (a per-day override wins over
	// the daily window).
	win, have := effectiveDayWindow(sched, now.Weekday())
	if !have {
		// No time-of-day window applies today. A scheduler scoped ONLY by a
		// date range (no daily/per-day time restriction) is active for the
		// entire range; anything else has no window and fails CLOSED.
		if schedulerHasDateRange(sched) && !schedulerHasTimeWindow(sched) {
			return true
		}
		return false
	}

	if win.Exclude {
		return false
	}
	if win.AllDay {
		return true
	}
	// A half-specified window (only one of start/stop) is unparseable ->
	// fail closed.
	if win.StartTime == "" || win.StopTime == "" {
		slog.Warn("scheduler: incomplete time window, failing closed",
			"name", sched.Name, "start", win.StartTime, "stop", win.StopTime)
		return false
	}
	return withinTimeOfDay(now, sched.Name, win.StartTime, win.StopTime)
}

// withinDateRange reports whether now is inside sched's calendar range.
// ok is false when a configured date fails to parse (caller fails closed).
//
// #3988: the calendar boundary is interpreted in the SYSTEM LOCAL time zone,
// matching the Junos convention that a scheduler start-date/stop-date is a
// local wall-clock date. The date is parsed in now.Location() rather than with
// time.Parse (which defaults to UTC): every production caller supplies now from
// time.Now() or the evaluation ticker, both of which carry time.Local, so the
// date boundary lands on LOCAL midnight. Parsing as UTC shifted the boundary by
// the local UTC offset (e.g. a start-date 2026-07-01 range under UTC-7 went
// active at 17:00 local on 2026-06-30 — 7h early). Deriving the zone from now
// keeps the boundary consistent with the same clock the window is compared
// against, needs no global seam, and leaves a UTC-offset-0 host unchanged
// (local == UTC).
func withinDateRange(now time.Time, sched *config.SchedulerConfig) (inRange, ok bool) {
	loc := now.Location()
	if sched.StartDate != "" {
		startDate, err := time.ParseInLocation("2006-01-02", sched.StartDate, loc)
		if err != nil {
			slog.Warn("scheduler: invalid start date", "name", sched.Name, "date", sched.StartDate, "err", err)
			return false, false
		}
		if now.Before(startDate) {
			return false, true
		}
	}
	if sched.StopDate != "" {
		stopDate, err := time.ParseInLocation("2006-01-02", sched.StopDate, loc)
		if err != nil {
			slog.Warn("scheduler: invalid stop date", "name", sched.Name, "date", sched.StopDate, "err", err)
			return false, false
		}
		// StopDate is inclusive: active through the entire stop date.
		if now.After(stopDate.AddDate(0, 0, 1)) {
			return false, true
		}
	}
	return true, true
}

// effectiveDayWindow resolves the window applying to weekday wd: a per-day
// override if one exists, otherwise the scheduler's daily window. have is
// false when neither is configured.
func effectiveDayWindow(sched *config.SchedulerConfig, wd time.Weekday) (config.SchedulerDayWindow, bool) {
	if len(sched.Days) > 0 {
		if win := sched.Days[strings.ToLower(wd.String())]; win != nil {
			return *win, true
		}
	}
	if sched.AllDay || sched.StartTime != "" || sched.StopTime != "" {
		return config.SchedulerDayWindow{
			StartTime: sched.StartTime,
			StopTime:  sched.StopTime,
			AllDay:    sched.AllDay,
		}, true
	}
	return config.SchedulerDayWindow{}, false
}

// schedulerHasTimeWindow reports whether the scheduler carries any
// time-of-day restriction (daily window or per-day arms).
func schedulerHasTimeWindow(sched *config.SchedulerConfig) bool {
	return sched.AllDay || sched.StartTime != "" || sched.StopTime != "" || len(sched.Days) > 0
}

func schedulerHasDateRange(sched *config.SchedulerConfig) bool {
	return sched.StartDate != "" || sched.StopDate != ""
}

// withinTimeOfDay reports whether now's clock time falls within
// [start, stop), handling overnight (wraparound) windows. An unparseable
// bound fails closed. Equal bounds (start == stop) take the wraparound branch
// and therefore mean always-active. Use the corresponding explicit all-day
// arm (`daily all-day` for a daily window or `<weekday> all-day` for a per-day
// arm) when that intent is explicit.
func withinTimeOfDay(now time.Time, name, start, stop string) bool {
	startTOD, err := parseTimeOfDay(start)
	if err != nil {
		slog.Warn("scheduler: invalid start time", "name", name, "time", start, "err", err)
		return false
	}
	stopTOD, err := parseTimeOfDay(stop)
	if err != nil {
		slog.Warn("scheduler: invalid stop time", "name", name, "time", stop, "err", err)
		return false
	}

	nowTOD := timeOfDay(now)

	if !startTOD.before(stopTOD) {
		// Wraparound: e.g. 22:00:00 - 06:00:00 means overnight.
		// Active if now >= start OR now < stop.
		return !nowTOD.before(startTOD) || nowTOD.before(stopTOD)
	}

	// Normal range: active if now >= start AND now < stop.
	return !nowTOD.before(startTOD) && nowTOD.before(stopTOD)
}

// tod represents a time of day as hours, minutes, seconds for clean comparison.
type tod struct {
	h, m, s int
}

func (t tod) before(other tod) bool {
	if t.h != other.h {
		return t.h < other.h
	}
	if t.m != other.m {
		return t.m < other.m
	}
	return t.s < other.s
}

func parseTimeOfDay(s string) (tod, error) {
	t, err := time.Parse("15:04:05", s)
	if err != nil {
		return tod{}, err
	}
	return tod{h: t.Hour(), m: t.Minute(), s: t.Second()}, nil
}

// timeOfDay extracts t's wall-clock hour/minute/second in t's own location.
//
// #3988 audit: the daily start-time/stop-time window is zone-safe as-is. Both
// sides of the comparison use wall-clock components — parseTimeOfDay reads the
// H/M/S of the configured "HH:MM:SS", and timeOfDay reads now's LOCAL H/M/S
// (now carries time.Local in every production caller). No instant is formed, so
// the configured 09:00:00 is compared against 09:00:00 local regardless of the
// UTC offset. Only the calendar date-range parse (withinDateRange) formed a
// UTC instant and had to move to now.Location().
func timeOfDay(t time.Time) tod {
	return tod{h: t.Hour(), m: t.Minute(), s: t.Second()}
}
