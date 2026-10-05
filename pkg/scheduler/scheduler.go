package scheduler

import (
	"context"
	"fmt"
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
	// #11285: unchanged, converged ticks refresh the dataplane's bounded
	// scheduled-policy lease without republishing the snapshot.
	heartbeatFn func(ctx context.Context)
	// #10949: a committed system time-zone change must not depend on Go's
	// process-cached time.Local. The daemon supplies the committed location,
	// which stays fixed for this scheduler generation. Ticks convert their
	// instants into it before evaluating date and time windows.
	loc             *time.Location
	zoneUnavailable bool
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
	// A successful latch snapshot uses action-aware disposition: permits stay
	// inactive while denies remain eligible. Force one follow-up publication
	// without the latch override so the actual window state replaces that view.
	republishRecoveryPending bool

	// #5669: bounded-age FAIL-OPEN-STALE escalation (#10906 honest naming:
	// the latch alone cannot revoke an already-published schedule). The #3780
	// self-heal retries a failed republish every tick, but a PERSISTENTLY
	// failing republish (a wedged control socket or incompatible helper) can
	// leave a scheduled permit live. Once the failure streak exceeds
	// republishFailClosedAge, the scheduler latches republishFailClosed: it emits a
	// one-time alarm, marks every scheduler inactive in its authoritative map, and
	// attempts to publish that state. The userspace
	// snapshot builder interprets this latch per action: scheduled permits
	// remain inactive, while DENY/REJECT rules stay eligible. A current #11285
	// helper applies the same deny-first interpretation when its independent
	// heartbeat lease expires; older helpers retain the stale-window limitation.
	// Guarded by mu.
	republishFailClosed bool
}

const (
	wallClockDriftTolerance = 5 * time.Second
	wallClockRecoveryHold   = 2 * time.Minute

	// RepublishFailClosedAge bounds how long a scheduler-driven republish may
	// keep failing before the scheduler escalates from the #3780 silent retry
	// to the FAIL-OPEN-STALE latch (see republishFailClosed and #10906). Five
	// minutes is roughly five 60 s evaluate ticks: long enough to absorb a
	// burst of control-socket contention (status poll + HA sync + session
	// installs + snapshot sync share the socket, see CLAUDE.md) without a false
	// alarm, short enough that a genuinely stuck republish is surfaced
	// promptly. This is the bound behind the
	// xpf_scheduler_republish_fail_open_stale gauge (#5669).
	RepublishFailClosedAge = 5 * time.Minute
)

// NewPrimed creates a Scheduler, evaluates the initial active-state map, and
// returns that map without firing updateFn from inside the constructor. Daemon
// apply paths use this when they already hold their own serialization lock and
// must publish the initial state as part of the same apply transaction.
func NewPrimed(schedulers map[string]*config.SchedulerConfig, updateFn func(ctx context.Context, activeState map[string]bool) error, now time.Time) (*Scheduler, map[string]bool) {
	return NewPrimedInLocation(schedulers, updateFn, now, now.Location())
}

// NewPrimedInLocation is NewPrimed with an explicit committed system time zone.
// A nil location means the configured zone could not be loaded, so scheduled
// policies stay inactive rather than inheriting this process's stale time.Local.
func NewPrimedInLocation(schedulers map[string]*config.SchedulerConfig, updateFn func(ctx context.Context, activeState map[string]bool) error, now time.Time, loc *time.Location) (*Scheduler, map[string]bool) {
	zoneUnavailable := loc == nil
	if zoneUnavailable {
		// Keep the internal time representation total; evaluate fails closed
		// while this flag is set and does not use the placeholder for windows.
		loc = time.UTC
	}
	s := &Scheduler{
		schedulers:      schedulers,
		active:          make(map[string]bool),
		updateFn:        updateFn,
		loc:             loc,
		zoneUnavailable: zoneUnavailable,
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

// SetHeartbeatFn installs the best-effort callback used on unchanged,
// converged scheduler ticks. It is distinct from updateFn: heartbeat failure
// must not latch a failed snapshot republish.
func (s *Scheduler) SetHeartbeatFn(fn func(ctx context.Context)) {
	s.mu.Lock()
	s.heartbeatFn = fn
	s.mu.Unlock()
}

// evaluate checks each scheduler against the current time and fires the
// callback if any state changed.
func (s *Scheduler) evaluate(ctx context.Context, now time.Time, notify bool) {
	now = now.In(s.loc)
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
	// every scheduler inactive in the authoritative map and attempt to publish
	// that state. The userspace builder keeps latch-inactive DENY/REJECT rules
	// eligible while permits remain inactive. A successful latch publication
	// clears the latch and schedules exactly one normal-disposition publication
	// before heartbeats resume.
	failClosed := s.republishFailClosed
	for name, sched := range s.schedulers {
		cur := false
		if !wallClockUnsafe && !s.zoneUnavailable {
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
	if !notify {
		s.mu.Unlock()
		return
	}
	if !changed && !s.republishPending && !s.republishRecoveryPending {
		heartbeatFn := s.heartbeatFn
		s.mu.Unlock()
		if heartbeatFn != nil {
			heartbeatFn(ctx)
		}
		return
	}
	if s.updateFn == nil {
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
		// #5669: bounded-age FAIL-OPEN-STALE escalation. Once the failure streak
		// passes the bound, alert once and keep the scheduler's authoritative map
		// inactive while republish remains wedged. The snapshot builder preserves
		// scheduled DENY/REJECT rules in the latch view while leaving permits
		// inactive; current helpers also use the lease's deny-first fallback
		// after five minutes without a heartbeat.
		if !s.republishFailClosed && !s.republishFirstFail.IsZero() &&
			now.Sub(s.republishFirstFail) >= RepublishFailClosedAge {
			s.republishFailClosed = true
			slog.Warn("scheduler: republish FAIL-OPEN-STALE — enforcement has been stale past the bounded age; forcing scheduler state inactive while preserving scheduled denies/rejects and keeping permits inactive in the published policy view (investigate the helper/control socket)",
				"stale_for", now.Sub(s.republishFirstFail),
				"bound", RepublishFailClosedAge,
				"failures", s.republishFailures,
				"err", err)
		}
		return
	}
	recoveredFailClosed := s.republishFailClosed
	if recoveredFailClosed {
		slog.Info("scheduler: republish recovered from fail-closed; one normal-disposition snapshot will follow",
			"failures", s.republishFailures)
	}
	s.republishPending = false
	s.republishFirstFail = time.Time{}
	s.republishFailClosed = false
	s.lastRepublishErr = nil
	if recoveredFailClosed {
		s.republishRecoveryPending = true
	} else if s.republishRecoveryPending {
		s.republishRecoveryPending = false
	}
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

// RepublishFailClosed reports whether the scheduler's bounded-age republish
// failure latch is set. The authoritative scheduler map stays inactive while
// latched; the userspace snapshot preserves scheduled DENY/REJECT rules and
// leaves permits inactive. The current helper also expires stale scheduled
// permits while keeping denies/rejects eligible. A successful latch republish
// clears the latch and schedules one normal-disposition republish before the
// daemon resumes heartbeats. The daemon exposes the latch as the
// xpf_scheduler_republish_fail_open_stale gauge (#5669, #10906).
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
	republishRecoveryPending := previous.republishRecoveryPending
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
	s.republishRecoveryPending = republishRecoveryPending
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
// window for today, and no date range — returns false. This is the
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
// ok is false when a configured bound fails to parse (caller fails closed).
//
// Scheduler dates and times are interpreted in the local zone, matching the
// Junos convention. Production evaluate converts each tick into the committed
// system time zone before calling this function; direct/package callers retain
// the location carried by now.
func withinDateRange(now time.Time, sched *config.SchedulerConfig) (inRange, ok bool) {
	loc := now.Location()
	if sched.StartDate != "" {
		start, _, err := parseSchedulerDateBound(sched.StartDate, loc)
		if err != nil {
			slog.Warn("scheduler: invalid start date", "name", sched.Name, "date", sched.StartDate, "err", err)
			return false, false
		}
		if now.Before(start) {
			return false, true
		}
	}
	if sched.StopDate != "" {
		stop, hasTime, err := parseSchedulerDateBound(sched.StopDate, loc)
		if err != nil {
			slog.Warn("scheduler: invalid stop date", "name", sched.Name, "date", sched.StopDate, "err", err)
			return false, false
		}
		if hasTime {
			// Junos date-time stop bounds are exclusive, like daily stop-time.
			if !now.Before(stop) {
				return false, true
			}
		} else {
			// Date-only StopDate remains inclusive through the full date.
			if now.After(stop.AddDate(0, 0, 1)) {
				return false, true
			}
		}
	}
	return true, true
}

func parseSchedulerDateBound(raw string, loc *time.Location) (time.Time, bool, error) {
	if strings.Contains(raw, ".") {
		if len(raw) != len("2006-01-02.15:04") {
			return time.Time{}, true, fmt.Errorf("invalid scheduler date-time %q", raw)
		}
		t, err := time.ParseInLocation("2006-01-02.15:04", raw, loc)
		return t, true, err
	}
	t, err := time.ParseInLocation("2006-01-02", raw, loc)
	return t, false, err
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
// bound fails closed. Equal bounds (start == stop) are never-active per
// Junos parity: a zero window matches nothing (#11089 — previously the
// wraparound branch below made them always-active, fail-open for
// time-gated permits). Use the corresponding explicit all-day arm
// (`daily all-day` for a daily window or `<weekday> all-day` for a per-day
// arm) when always-on is intended.
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

	if startTOD == stopTOD {
		// #11089: degenerate zero window. Junos treats start == stop as
		// never-active (an empty [start, stop) range matches nothing), so
		// fail closed here instead of falling into the wraparound branch,
		// which is true for every clock time and permitted 24/7.
		return false
	}
	if stopTOD.before(startTOD) {
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
	var t time.Time
	var err error
	switch strings.Count(s, ":") {
	case 1:
		if len(s) != len("15:04") {
			return tod{}, fmt.Errorf("invalid scheduler time %q", s)
		}
		t, err = time.Parse("15:04", s)
	case 2:
		t, err = time.Parse("15:04:05", s)
	default:
		return tod{}, fmt.Errorf("invalid scheduler time %q", s)
	}
	if err != nil {
		return tod{}, err
	}
	return tod{h: t.Hour(), m: t.Minute(), s: t.Second()}, nil
}

// timeOfDay extracts t's wall-clock hour/minute/second in t's own location.
//
// #3988/#10949 audit: the daily start-time/stop-time window is zone-safe.
// Both sides are wall-clock components — parseTimeOfDay reads the configured
// H/M/S and timeOfDay reads now's H/M/S in its location. Production evaluation
// converts now into the committed system zone before this comparison; no
// instant is formed, and the configured 09:00:00 stays 09:00:00 local
// regardless of UTC offset.
func timeOfDay(t time.Time) tod {
	return tod{h: t.Hour(), m: t.Minute(), s: t.Second()}
}
