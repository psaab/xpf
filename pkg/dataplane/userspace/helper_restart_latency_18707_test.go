package userspace

// #18707: a helper crash restart must not sit on fixed delays.
//
// Three delays used to stand between an isolated helper crash and transit:
//
//   - the FIRST retry waited helperRestartBackoffBase (1s) after the dead
//     child was already reaped and the shim already disarmed;
//   - the replacement's status loop waited a full statusLoopInterval before
//     its first pass, and that pass is what republishes the snapshot the
//     workers bind from;
//   - the load-bearing NAPI fill-ring bootstrap was a timer fixed at 3s after
//     spawn, and a 2s debounce could swallow it behind the ctrl-enable
//     prewarm, leaving late-bound queues unprobed.
//
// The cells below pin the replacements by COUNTS and by the order of
// observable events, never by elapsed wall-clock: the backoff schedule as
// values, the immediate pass with a one-hour tick interval (only the
// immediate pass can produce a poll), and the NAPI trigger as a function of
// binding state with no time passing between the status and the arm.

import (
	"os/exec"
	"sync"
	"testing"
	"time"
)

// The schedule: 0 for the first attempt, then base doubling to the cap — and
// the crash-loop verdict needs exactly as much cumulative wait as it did before
// the immediate first retry was inserted, so HA's CrashLooping response is not
// reached any sooner (process_supervisor.go, helperRestartBackoffBase).
func TestHelperRestartScheduleImmediateFirstThenExponential18707(t *testing.T) {
	base, maxDelay := helperRestartBackoffBase, helperRestartBackoffMax
	if base != time.Second || maxDelay != 60*time.Second {
		t.Fatalf("premise: shipped backoff is base=%v max=%v; this cell pins the 1s/60s schedule", base, maxDelay)
	}
	want := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second}
	for i, w := range want {
		if got := helperRestartDelay(i + 1); got != w {
			t.Fatalf("helperRestartDelay(%d) = %v, want %v (schedule %v)", i+1, got, w, want)
		}
	}
	if got := helperCrashLoopAttempt(); got != 8 {
		t.Fatalf("helperCrashLoopAttempt() = %d, want 8 (one more than the pre-#18707 7)", got)
	}

	// The pre-#18707 schedule, written out independently of the production
	// function: base*2^(n-1) saturating at the cap.
	oldDelay := func(n int) time.Duration {
		d := base
		for i := 1; i < n; i++ {
			d *= 2
			if d >= maxDelay {
				return maxDelay
			}
		}
		return d
	}
	oldLoop := 1
	for oldDelay(oldLoop) < maxDelay {
		oldLoop++
	}
	var oldWait, newWait time.Duration
	for n := 1; n < oldLoop; n++ {
		oldWait += oldDelay(n)
	}
	for n := 1; n < helperCrashLoopAttempt(); n++ {
		newWait += helperRestartDelay(n)
	}
	if newWait != oldWait {
		t.Fatalf("cumulative backoff before the crash-loop cap = %v, pre-#18707 = %v; "+
			"the immediate first retry must not make CrashLooping trip sooner", newWait, oldWait)
	}
}

type delayRecorder18707 struct {
	mu     sync.Mutex
	delays []time.Duration
	retry  func()
}

func (r *delayRecorder18707) arm(d time.Duration, fn func()) {
	r.mu.Lock()
	r.delays = append(r.delays, d)
	r.retry = fn
	r.mu.Unlock()
}

func (r *delayRecorder18707) fire(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	fn := r.retry
	r.retry = nil
	r.mu.Unlock()
	if fn == nil {
		t.Fatal("supervisor did not arm a retry callback")
	}
	fn()
}

func (r *delayRecorder18707) snapshot() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.delays...)
}

// The production supervisor, on a real child: the first unexpected exit of an
// episode arms an immediate retry, and repeats inside the same episode back
// off from the base. Shipped constants; the timer seam records the delay and
// is fired by hand, so nothing waits.
func TestFirstCrashRestartsImmediatelyRepeatsBackOff18707(t *testing.T) {
	statusLoopIntervalForTest18707(t, time.Hour)
	rec := &delayRecorder18707{}
	m := startNMHelper12159(t, nmPersistentHelper12159, rec.arm)
	joinStatusLoopAtCleanup18707(t, m)
	waitNMSupervisorRunning12159(t, m)

	for i, want := range []time.Duration{0, helperRestartBackoffBase, 2 * helperRestartBackoffBase} {
		killNMSupervisedChild12159(t, m)
		delays := rec.snapshot()
		if len(delays) != i+1 {
			t.Fatalf("after exit %d the supervisor armed %d retries (%v), want %d", i+1, len(delays), delays, i+1)
		}
		if delays[i] != want {
			t.Fatalf("exit %d of one episode armed delay %v, want %v (schedule so far %v)",
				i+1, delays[i], want, delays)
		}
		rec.fire(t)
		waitNMSupervisorRunning12159(t, m)
	}
}

// A crash restart's status loop runs its first pass NOW. The tick interval is
// an hour, so a status poll can only come from the immediate pass.
func TestCrashRestartRunsFirstStatusPassImmediately18707(t *testing.T) {
	statusLoopIntervalForTest18707(t, time.Hour)
	rec := &delayRecorder18707{}
	m := startNMHelper12159(t, nmPersistentHelper12159, rec.arm)
	joinStatusLoopAtCleanup18707(t, m)
	waitNMSupervisorRunning12159(t, m)

	polled := make(chan struct{}, 1)
	m.mu.Lock()
	if m.syncCancel != nil {
		m.mu.Unlock()
		t.Fatal("premise: a status loop is already running before the crash; the cell could observe its tick")
	}
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if status != nil {
			status.PID = 4242
		}
		if req.Type == "status" {
			select {
			case polled <- struct{}{}:
			default:
			}
		}
		return nil
	}
	m.mu.Unlock()

	killNMSupervisedChild12159(t, m)
	rec.fire(t)
	waitNMSupervisorRunning12159(t, m)
	m.mu.Lock()
	looping := m.syncCancel != nil
	m.mu.Unlock()
	if !looping {
		t.Fatal("the crash restart did not start a status loop for the replacement helper")
	}
	// Failure bound only: the pass condition is the poll itself.
	select {
	case <-polled:
	case <-time.After(10 * time.Second):
		t.Fatal("the restarted helper's status loop did not poll before its first tick (interval 1h); " +
			"the first reconcile pass — the one that republishes the snapshot — still waits a tick (#18707)")
	}
}

// joinStatusLoopAtCleanup18707 stops the helper and JOINS the status loop the
// crash restart started, before the earlier-registered cleanup restores
// statusLoopInterval: the loop reads that var as it starts, so restoring it
// while the goroutine may still be starting is a data race. t.Cleanup is
// LIFO, so registering this after startNMHelper12159 runs it first.
func joinStatusLoopAtCleanup18707(t *testing.T, m *Manager) {
	t.Helper()
	t.Cleanup(func() {
		m.mu.Lock()
		m.stopLocked()
		done := m.syncDone
		m.mu.Unlock()
		if done != nil {
			<-done
		}
	})
}

func statusLoopIntervalForTest18707(t *testing.T, d time.Duration) {
	t.Helper()
	old := statusLoopInterval
	statusLoopInterval = d
	t.Cleanup(func() { statusLoopInterval = old })
}

func napiStatus18707(bound bool) *ProcessStatus {
	s := readyHelperStatus()
	s.Bindings[0].Bound = bound
	return s
}

// napiManager18707 is seamedManager with a live generation, so the status path
// reaches the generation-fenced NAPI arm. lastSnapshot stays nil: the
// bootstrap callback records lastNAPIBootstrap and submits no probe I/O.
func napiManager18707(t *testing.T, gen uint64) *Manager {
	t.Helper()
	m, _ := seamedManager(t)
	cmd := exec.Command("true")
	m.proc = cmd
	m.procGen = gen
	m.procSup = &helperGeneration{gen: gen, cmd: cmd, exited: make(chan struct{})}
	return m
}

// waitNAPIBootstrapRecorded18707 waits for an armed callback to run. Failure
// bound only.
func waitNAPIBootstrapRecorded18707(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		done := !m.lastNAPIBootstrap.IsZero()
		m.mu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("armed NAPI bootstrap callback never ran")
}

func TestNAPIBootstrapFiresOnAllBindingsBound18707(t *testing.T) {
	// No number of not-yet-bound passes arms the bound bootstrap. Positive
	// control in the same cell: the pass DID reach the prewarm, whose
	// debounced fallback bootstrap stamps lastNAPIBootstrap synchronously, so
	// "not armed" is not an unreached branch.
	t.Run("not_bound_never_arms", func(t *testing.T) {
		m := napiManager18707(t, 1)
		m.mu.Lock()
		for i := 0; i < 50; i++ {
			if err := m.applyHelperStatusLocked(napiStatus18707(false)); err != nil {
				m.mu.Unlock()
				t.Fatalf("pass %d: %v", i, err)
			}
		}
		armed, prewarmed := m.napiBoundBootstrapGen, !m.lastNAPIBootstrap.IsZero()
		m.mu.Unlock()
		if !prewarmed {
			t.Fatal("control: the not-bound passes never reached the ctrl-enable prewarm")
		}
		if armed != 0 {
			t.Fatalf("bound NAPI bootstrap armed for generation %d while a binding was still unbound", armed)
		}
	})

	// The first pass in which every binding is bound arms it, in that pass,
	// for that generation — and the prewarm does not stack its own debounced
	// bootstrap on top. Both are read inside the same lock hold as the apply:
	// no time passes, so there is no timer that could have fired.
	t.Run("first_bound_pass_arms_once", func(t *testing.T) {
		m := napiManager18707(t, 1)
		m.mu.Lock()
		if err := m.applyHelperStatusLocked(napiStatus18707(true)); err != nil {
			m.mu.Unlock()
			t.Fatal(err)
		}
		armed, prewarmStamp := m.napiBoundBootstrapGen, m.lastNAPIBootstrap
		// Read the second arm's channel while m.mu is still held: an armed
		// callback cannot run (and close it) until the lock is released, so
		// only the not-armed path returns it already closed.
		againClosed := chanClosed18707(m.ensureXSKBoundNAPIBootstrapLocked())
		m.mu.Unlock()
		if armed != 1 {
			t.Fatalf("all-bound status pass armed generation %d, want 1", armed)
		}
		if !prewarmStamp.IsZero() {
			t.Fatal("the prewarm armed its debounced bootstrap in the same all-bound pass; " +
				"the probes would fire twice")
		}
		if !againClosed {
			t.Fatal("a second arm in the same generation scheduled another bootstrap; it must fire once per generation")
		}
		waitNAPIBootstrapRecorded18707(t, m)
	})

	// The hole the debounce opened: the prewarm fires while a binding is still
	// unbound, and the all-bound bootstrap moments later must not be swallowed
	// by bootstrapNAPIQueuesAsyncLocked's 2s debounce.
	t.Run("late_bound_after_prewarm_not_debounced", func(t *testing.T) {
		m := napiManager18707(t, 1)
		m.mu.Lock()
		if err := m.applyHelperStatusLocked(napiStatus18707(false)); err != nil {
			m.mu.Unlock()
			t.Fatal(err)
		}
		prewarmed := !m.lastNAPIBootstrap.IsZero()
		if err := m.applyHelperStatusLocked(napiStatus18707(true)); err != nil {
			m.mu.Unlock()
			t.Fatal(err)
		}
		armed := m.napiBoundBootstrapGen
		m.mu.Unlock()
		if !prewarmed {
			t.Fatal("premise: the not-bound pass did not fire the debounced prewarm bootstrap")
		}
		if armed != 1 {
			t.Fatalf("all-bound bootstrap armed generation %d after a prewarm inside the debounce window, want 1", armed)
		}
	})

	// A new generation re-arms.
	t.Run("new_generation_rearms", func(t *testing.T) {
		m := napiManager18707(t, 1)
		m.mu.Lock()
		if err := m.applyHelperStatusLocked(napiStatus18707(true)); err != nil {
			m.mu.Unlock()
			t.Fatal(err)
		}
		m.mu.Unlock()
		waitNAPIBootstrapRecorded18707(t, m)
		m.mu.Lock()
		cmd := exec.Command("true")
		m.proc = cmd
		m.procGen = 2
		m.procSup = &helperGeneration{gen: 2, cmd: cmd, exited: make(chan struct{})}
		if err := m.applyHelperStatusLocked(napiStatus18707(true)); err != nil {
			m.mu.Unlock()
			t.Fatal(err)
		}
		armed := m.napiBoundBootstrapGen
		m.mu.Unlock()
		if armed != 2 {
			t.Fatalf("generation 2's all-bound pass armed generation %d, want 2", armed)
		}
	})
}

// napiTwoBindings18707 is a two-binding status: the second binding is a sibling
// queue on the same interface. Every single-binding cell above reads "all
// bound" and "any bound" as the same predicate; this fixture separates them.
func napiTwoBindings18707(firstBound, secondBound bool) *ProcessStatus {
	s := readyHelperStatus()
	b := s.Bindings[0]
	b.Bound = firstBound
	second := b
	second.Slot, second.QueueID, second.Bound = 1, 1, secondBound
	s.Bindings = []BindingStatus{b, second}
	return s
}

// The bound bootstrap waits for EVERY binding, not the first one to bind.
func TestNAPIBootstrapWaitsForEveryBinding18707(t *testing.T) {
	m := napiManager18707(t, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < 50; i++ {
		if err := m.applyHelperStatusLocked(napiTwoBindings18707(true, false)); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	if m.napiBoundBootstrapGen != 0 {
		t.Fatalf("all-bound bootstrap armed for generation %d with one of two bindings still unbound", m.napiBoundBootstrapGen)
	}
	if err := m.applyHelperStatusLocked(napiTwoBindings18707(true, true)); err != nil {
		t.Fatal(err)
	}
	if m.napiBoundBootstrapGen != 1 {
		t.Fatalf("all-bound bootstrap armed generation %d once both bindings bound, want 1", m.napiBoundBootstrapGen)
	}
}

// The partial-bind floor (review scenario): one binding binds, its sibling
// stays registered-but-unbound for the whole generation, and ctrl enables
// anyway. The bound queue must still get a post-bind probe. Elapsed time is
// simulated by moving the generation's first-bound stamp back by the floor
// between passes; nothing waits on the clock.
func TestNAPIPartialBindFloorProbesBoundQueues18707(t *testing.T) {
	m, ctrl := seamedManager(t)
	cmd := exec.Command("true")
	m.proc = cmd
	m.procGen = 1
	m.procSup = &helperGeneration{gen: 1, cmd: cmd, exited: make(chan struct{})}
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.applyHelperStatusLocked(napiTwoBindings18707(true, false)); err != nil {
		t.Fatal(err)
	}
	if m.napiFirstBoundGen != 1 {
		t.Fatalf("first pass with a bound binding did not open the floor window (napiFirstBoundGen=%d)", m.napiFirstBoundGen)
	}
	if m.napiFloorBootstrapGen != 0 {
		t.Fatal("partial-bind floor armed in the very pass that opened its window")
	}
	if !ctrl.haveStored || ctrl.stored.Enabled != 1 {
		t.Fatal("premise: ctrl did not enable with the second binding registered-but-unbound; " +
			"the hole this floor covers needs ctrl ENABLED")
	}

	m.napiFirstBoundAt = m.napiFirstBoundAt.Add(-napiPartialBindFloor)
	if err := m.applyHelperStatusLocked(napiTwoBindings18707(true, false)); err != nil {
		t.Fatal(err)
	}
	if m.napiFloorBootstrapGen != 1 {
		t.Fatalf("partial-bind floor did not arm %v after the first bind (napiFloorBootstrapGen=%d); "+
			"the bound queue is never probed while its sibling stays unbound", napiPartialBindFloor, m.napiFloorBootstrapGen)
	}
	if m.napiBoundBootstrapGen != 0 {
		t.Fatal("all-bound bootstrap armed while a binding is still unbound")
	}

	// The stuck binding binds late: it needs its own probe, so the all-bound
	// bootstrap still fires after the floor did.
	if err := m.applyHelperStatusLocked(napiTwoBindings18707(true, true)); err != nil {
		t.Fatal(err)
	}
	if m.napiBoundBootstrapGen != 1 {
		t.Fatalf("late all-bound pass armed generation %d after the floor fired, want 1", m.napiBoundBootstrapGen)
	}
}

// The floor's own predicate, with the clock injected: no window before a
// binding is bound, the boundary at exactly napiPartialBindFloor, once per
// generation, and retired by the all-bound bootstrap.
func TestNAPIPartialBindFloorWindow18707(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)

	t.Run("nothing_bound_never_opens", func(t *testing.T) {
		m := napiManager18707(t, 1)
		m.mu.Lock()
		defer m.mu.Unlock()
		for i := 0; i < 10; i++ {
			m.ensurePartialBindNAPIBootstrapFloorLocked(false, t0.Add(time.Duration(i)*time.Hour))
		}
		if m.napiFirstBoundGen != 0 || m.napiFloorBootstrapGen != 0 {
			t.Fatalf("floor opened/armed with no binding bound: firstBoundGen=%d floorGen=%d",
				m.napiFirstBoundGen, m.napiFloorBootstrapGen)
		}
	})

	t.Run("boundary_and_once", func(t *testing.T) {
		m := napiManager18707(t, 1)
		m.mu.Lock()
		m.ensurePartialBindNAPIBootstrapFloorLocked(true, t0)
		m.ensurePartialBindNAPIBootstrapFloorLocked(true, t0.Add(napiPartialBindFloor-time.Nanosecond))
		before := m.napiFloorBootstrapGen
		armed := m.ensurePartialBindNAPIBootstrapFloorLocked(true, t0.Add(napiPartialBindFloor))
		at := m.napiFloorBootstrapGen
		armedClosed := chanClosed18707(armed)
		againClosed := chanClosed18707(m.ensurePartialBindNAPIBootstrapFloorLocked(true, t0.Add(10*napiPartialBindFloor)))
		m.mu.Unlock()
		if before != 0 {
			t.Fatalf("floor armed before %v elapsed", napiPartialBindFloor)
		}
		if at != 1 || armedClosed {
			t.Fatalf("floor did not arm at exactly %v (floorGen=%d, callback scheduled=%v)",
				napiPartialBindFloor, at, !armedClosed)
		}
		if !againClosed {
			t.Fatal("floor armed a second bootstrap in the same generation")
		}
		<-armed
	})

	t.Run("all_bound_retires_floor", func(t *testing.T) {
		m := napiManager18707(t, 1)
		m.mu.Lock()
		done := m.ensureXSKBoundNAPIBootstrapLocked()
		m.ensurePartialBindNAPIBootstrapFloorLocked(true, t0)
		lateClosed := chanClosed18707(m.ensurePartialBindNAPIBootstrapFloorLocked(true, t0.Add(10*napiPartialBindFloor)))
		m.mu.Unlock()
		<-done
		if !lateClosed {
			t.Fatal("partial-bind floor armed after the generation's all-bound bootstrap already fired")
		}
	})
}

// chanClosed18707 reports whether an arm returned an already-closed channel,
// i.e. scheduled nothing. Call it while m.mu is held: a scheduled callback
// needs the lock before it can close its channel.
func chanClosed18707(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
