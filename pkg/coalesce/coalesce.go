// Package coalesce provides a debounced, throttled, dirty-bit actuation loop.
//
// WHY THIS EXISTS AS ITS OWN PACKAGE (#7437). The discipline below was written
// once, in pkg/ipmon, and is the in-tree precedent for "a burst of events must
// collapse into a bounded number of expensive actuations". The #7437 kernel
// route listener needs exactly it: every publish is a FULL snapshot replace
// over a control socket whose deadline scales with payload size, and
// CLAUDE.md's control-socket rule is explicit that a new caller above 1/s
// starves session installs during bulk sync. A per-event push under BGP churn
// is a control-plane brownout, not a latency tail.
//
// It was written as the type ipmon WOULD adopt, because ipmon already
// implemented this discipline and a second copy in the route listener would
// have been a divergence with a delay fuse — whichever copy is edited first is
// right, and nothing tells the other. The extraction was deliberately NOT done
// inside #7437's feature PR: ipmon's Engine entangles the loop with policy
// state, next-hop resolution and `publishEnabled` (the HA-standby publication
// gate), and refactoring an HA-gated engine there would have put any regression
// on the cluster rather than in review, and attributed it to the route
// listener.
//
// #8354 completed the adoption: ipmon.Engine now drives this loop, so there is
// ONE implementation. What stayed in ipmon is what is genuinely ipmon's —
// policy evaluation, next-hop resolution, recovery hold-downs, and the
// publishEnabled gate. The seam is `OnConverged` / `OnFailed`: an adopter that
// must act on "the actuator converged AND nothing was marked while it ran"
// cannot compute that condition, because half of it lives in here.
package coalesce

import (
	"context"
	"sync"
	"time"
)

// DefaultDebounce and DefaultThrottle mirror pkg/ipmon's values, which are the
// in-tree precedent rather than an independent choice: a burst settles for
// Debounce before it actuates, and two actuations are never closer than
// Throttle.
const (
	DefaultDebounce       = 1 * time.Second
	DefaultThrottle       = 3 * time.Second
	DefaultActuateTimeout = 30 * time.Second
)

// Loop coalesces Mark() calls into bounded actuations.
//
// The actuator returns whether it CONVERGED. A false return keeps the state
// dirty and the loop retries on the next throttle-paced sweep — it does not
// hot-loop, because lastActuation advances when the attempt starts, not when
// it succeeds.
type Loop struct {
	// #8354: fired after a CONVERGED / a FAILED actuation respectively. See
	// OnConverged and OnFailed.
	onConverged   func()
	onFailed      func()
	mu            sync.Mutex
	dirtySince    time.Time // zero = clean
	dirtyGen      uint64
	lastActuation time.Time

	debounce       time.Duration
	throttle       time.Duration
	actuateTimeout time.Duration
	now            func() time.Time

	actuate func(context.Context) bool

	kick     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	started  bool
	stopped  bool
	actuated uint64 // observability + tests
}

// New returns a Loop that calls actuate when a marked change has settled.
func New(actuate func(context.Context) bool) *Loop {
	return &Loop{
		debounce:       DefaultDebounce,
		throttle:       DefaultThrottle,
		actuateTimeout: DefaultActuateTimeout,
		now:            time.Now,
		actuate:        actuate,
		kick:           make(chan struct{}, 1),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}
}

// SetTimings overrides the debounce/throttle. Intended for tests and for a
// caller whose actuation cost differs materially from a snapshot publish.
func (l *Loop) SetTimings(debounce, throttle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debounce, l.throttle = debounce, throttle
}

// SetClock injects a clock. Tests use it so a rate assertion is DETERMINISTIC
// rather than a race against wall time — a coalescing bound asserted with
// sleeps is the flaky-guard shape this repo keeps finding.
// SetActuateTimeout bounds a single actuate() call; 0 disables the bound.
//
// #8354: exported for an adopter that owns its own timeout knob. ipmon's is
// operator-visible through the engine, and a test drives it down to observe
// the bounded-timeout retry -- so the value must reach the loop that applies
// it, or the bound silently becomes the loop's default.
//
// Set before Start.
func (l *Loop) SetActuateTimeout(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.actuateTimeout = d
}

func (l *Loop) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Mark records that something changed.
//
// dirtyGen increments on EVERY mark, including while already dirty. The run
// loop snapshots it before actuating and clears the dirty bit only when it is
// unchanged afterwards, so a change landing DURING an actuation is not lost —
// it keeps the state dirty for the next sweep instead of being swallowed by
// the actuation that did not see it.
func (l *Loop) Mark() {
	l.mu.Lock()
	if l.dirtySince.IsZero() {
		l.dirtySince = l.now()
	}
	l.dirtyGen++
	l.mu.Unlock()
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

// MarkImmediately records a change whose consequence must not wait for the
// debounce window. The normal throttle still bounds actuation frequency.
func (l *Loop) MarkImmediately() {
	l.mu.Lock()
	l.dirtySince = l.now().Add(-l.debounce)
	l.dirtyGen++
	l.mu.Unlock()
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

// Actuations reports how many times the actuator has been invoked.
func (l *Loop) Actuations() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.actuated
}

// Start begins the loop. Idempotent.
func (l *Loop) Start() {
	l.mu.Lock()
	if l.started || l.stopped {
		l.mu.Unlock()
		return
	}
	l.started = true
	l.mu.Unlock()
	go l.run()
}

// Stop halts the loop and waits for it to exit.
func (l *Loop) Stop() {
	l.mu.Lock()
	if l.stopped || !l.started {
		l.stopped = true
		l.mu.Unlock()
		return
	}
	l.stopped = true
	l.mu.Unlock()
	close(l.stop)
	<-l.done
}

// Tick evaluates one sweep without running the loop goroutine. Exported for
// tests driving an injected clock: it is the whole loop body, so a test using
// it exercises the real decision rather than a model of it.
func (l *Loop) Tick(ctx context.Context) {
	l.mu.Lock()
	now := l.now()
	fire := false
	var gen uint64
	if !l.dirtySince.IsZero() &&
		now.Sub(l.dirtySince) >= l.debounce &&
		now.Sub(l.lastActuation) >= l.throttle {
		fire = true
		gen = l.dirtyGen
		// Advance BEFORE the actuation, not after: this is what paces a
		// FAILING actuation's retry to one per throttle window instead of a
		// hot loop.
		l.lastActuation = now
	}
	l.mu.Unlock()
	if !fire {
		return
	}

	ok := true
	if l.actuate != nil {
		actCtx := ctx
		var cancel context.CancelFunc
		if l.actuateTimeout > 0 {
			actCtx, cancel = context.WithTimeout(ctx, l.actuateTimeout)
		}
		ok = l.actuate(actCtx)
		if cancel != nil {
			cancel()
		}
	}

	l.mu.Lock()
	l.actuated++
	// Clear only when the actuation converged AND nothing was marked while it
	// ran. Either condition failing leaves the state dirty for the next sweep.
	converged := ok && l.dirtyGen == gen
	if converged {
		l.dirtySince = time.Time{}
	}
	onConverged := l.onConverged
	onFailed := l.onFailed
	l.mu.Unlock()

	// #8354: the two hooks exist because an adopter needs to act on exactly the
	// condition this loop decides, and cannot recompute it.
	//
	// `converged` is `ok && dirtyGen unchanged` -- both halves live in here, and
	// the second is invisible to an actuator, which sees only its own return.
	// ipmon records its APPLIED overlay under precisely this condition (#3761
	// H8): "the actuator published exactly what it read" is true only when no
	// newer change landed mid-actuation. Without the hook an adopter must either
	// duplicate the generation tracking -- which is the duplication #8354 exists
	// to remove -- or widen the condition to plain `ok` and record a desired
	// state as an applied one.
	//
	// Called OUTSIDE the lock, like `actuate` itself, so a hook may take the
	// adopter's own mutex without ordering against this one.
	if converged {
		if onConverged != nil {
			onConverged()
		}
		return
	}
	if !ok && onFailed != nil {
		onFailed()
	}
}

// NextWake reports how long the loop may sleep before its own state could
// next permit an actuation: the later of the debounce and throttle deadlines
// for a pending dirty bit, or `idle` when nothing is pending.
//
// #8354: exported because an adopter with its OWN wakeup sources (ipmon has
// recovery hold-down expiries) must combine them with this one, and the
// deadlines are computed from `dirtySince`/`lastActuation`/`debounce`/
// `throttle` -- all of which live in here. Recomputing them outside would be
// the same duplication, moved.
//
// Never returns less than a millisecond for a pending deadline, so a caller
// cannot spin on a deadline that has just passed.
func (l *Loop) NextWake(idle time.Duration) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dirtySince.IsZero() {
		return idle
	}
	now := l.now()
	debounceAt := l.dirtySince.Add(l.debounce)
	throttleAt := l.lastActuation.Add(l.throttle)
	at := debounceAt
	if throttleAt.After(debounceAt) {
		at = throttleAt
	}
	d := at.Sub(now)
	if d < time.Millisecond {
		d = time.Millisecond
	}
	if d > idle {
		return idle
	}
	return d
}

// Dirty reports whether a change is pending actuation. For status surfaces and
// for an adopter deciding whether to schedule its own wakeup.
func (l *Loop) Dirty() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.dirtySince.IsZero()
}

// OnConverged registers a callback fired after an actuation that CONVERGED --
// the actuator returned true AND no change was marked while it ran.
//
// Not "the actuator returned true". The second half is the point: it is what
// distinguishes "the state I published is the current state" from "the state I
// published was already stale when I finished", and only this loop knows it.
//
// Called outside the loop's lock. Set before Start.
func (l *Loop) OnConverged(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onConverged = fn
}

// OnFailed registers a callback fired after an actuation whose actuator
// returned false. A NON-convergence caused by a concurrent mark (actuator
// returned true, generation moved) does NOT fire it -- nothing failed there,
// the work is simply not finished, and counting it as a failure would make a
// flap storm look like an outage.
//
// Called outside the loop's lock. Set before Start.
func (l *Loop) OnFailed(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onFailed = fn
}

func (l *Loop) run() {
	defer close(l.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A short sweep interval relative to the debounce: the loop is cheap when
	// clean, and the bound that matters is the throttle, not the poll.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-l.kick:
		case <-ticker.C:
		}
		l.Tick(ctx)
	}
}
