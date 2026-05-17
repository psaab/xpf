package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Scheduler periodically evaluates time windows for named schedulers
// and notifies a callback when any scheduler's active state changes.
type Scheduler struct {
	mu               sync.RWMutex
	schedulers       map[string]*config.SchedulerConfig
	active           map[string]bool
	updateFn         func(activeState map[string]bool)
	lastEval         time.Time
	lastWallUnixNano int64
	unsafeUntil      time.Time
}

const (
	wallClockDriftTolerance = 5 * time.Second
	wallClockRecoveryHold   = 2 * time.Minute
)

// NewPrimed creates a Scheduler, evaluates the initial active-state map, and
// returns that map without firing updateFn from inside the constructor. Daemon
// apply paths use this when they already hold their own serialization lock and
// must publish the initial state as part of the same apply transaction.
func NewPrimed(schedulers map[string]*config.SchedulerConfig, updateFn func(activeState map[string]bool), now time.Time) (*Scheduler, map[string]bool) {
	s := &Scheduler{
		schedulers: schedulers,
		active:     make(map[string]bool),
		updateFn:   updateFn,
	}
	s.evaluate(now, false)
	return s, s.ActiveState()
}

// New creates a Scheduler with the given scheduler configs and update callback.
// updateFn is called whenever any scheduler's active state changes, receiving
// the current active state of all schedulers.
func New(schedulers map[string]*config.SchedulerConfig, updateFn func(activeState map[string]bool)) *Scheduler {
	s, _ := NewPrimed(schedulers, updateFn, time.Now())
	// Preserve the historical constructor contract: New notifies on initial
	// state. NewPrimed is the no-notify variant for callers that publish the
	// initial state under an external lock.
	if len(s.active) > 0 {
		s.notifyActiveState()
	}
	return s
}

// Run starts the evaluation loop, checking every 60 seconds. It blocks until
// the context is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	slog.Info("scheduler: starting evaluation loop")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("scheduler: stopping evaluation loop")
			return
		case t := <-ticker.C:
			s.evaluate(t, true)
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
	s.evaluate(time.Now(), true)
}

// evaluate checks each scheduler against the current time and fires the
// callback if any state changed.
func (s *Scheduler) evaluate(now time.Time, notify bool) {
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

	for name, sched := range s.schedulers {
		cur := false
		if !wallClockUnsafe {
			cur = isWithinWindow(now, sched)
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

	if !changed || !notify || s.updateFn == nil {
		s.mu.Unlock()
		return
	}
	cp := copyActiveState(newActive)
	updateFn := s.updateFn
	s.mu.Unlock()
	updateFn(cp)
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

func (s *Scheduler) notifyActiveState() {
	s.mu.RLock()
	if s.updateFn == nil {
		s.mu.RUnlock()
		return
	}
	cp := copyActiveState(s.active)
	updateFn := s.updateFn
	s.mu.RUnlock()
	updateFn(cp)
}

func copyActiveState(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// isWithinWindow determines whether now falls within the time window defined
// by sched. It returns true (active) if no times are configured.
func isWithinWindow(now time.Time, sched *config.SchedulerConfig) bool {
	if sched.StartTime == "" && sched.StopTime == "" {
		return true
	}

	// Check date range if configured.
	if sched.StartDate != "" {
		startDate, err := time.Parse("2006-01-02", sched.StartDate)
		if err != nil {
			slog.Warn("scheduler: invalid start date", "name", sched.Name, "date", sched.StartDate, "err", err)
			return false
		}
		if now.Before(startDate) {
			return false
		}
	}
	if sched.StopDate != "" {
		stopDate, err := time.Parse("2006-01-02", sched.StopDate)
		if err != nil {
			slog.Warn("scheduler: invalid stop date", "name", sched.Name, "date", sched.StopDate, "err", err)
			return false
		}
		// StopDate is inclusive: the scheduler is active through the entire stop date.
		if now.After(stopDate.AddDate(0, 0, 1)) {
			return false
		}
	}

	// If only date range is set (no times), active for the entire date range.
	if sched.StartTime == "" && sched.StopTime == "" {
		return true
	}

	// Parse start and stop times of day.
	startTOD, err := parseTimeOfDay(sched.StartTime)
	if err != nil {
		slog.Warn("scheduler: invalid start time", "name", sched.Name, "time", sched.StartTime, "err", err)
		return false
	}
	stopTOD, err := parseTimeOfDay(sched.StopTime)
	if err != nil {
		slog.Warn("scheduler: invalid stop time", "name", sched.Name, "time", sched.StopTime, "err", err)
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

func timeOfDay(t time.Time) tod {
	return tod{h: t.Hour(), m: t.Minute(), s: t.Second()}
}
