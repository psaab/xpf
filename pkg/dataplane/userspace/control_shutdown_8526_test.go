package userspace

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// #8526 regression cells for the stop bound on control-socket round trips.
//
// WHAT THE INSTRUMENT WOULD SAY IF THE PROPERTY WERE FALSE. Every cell here
// is time-bounded with an explicit `select`, because the failure mode under
// test is a HANG: a mutant that reintroduces the unbounded hold does not
// return a wrong value, it fails to return. A cell that waited on an
// unbuffered channel would be a VOID (the mutation neither passes nor fails),
// so each bound is chosen strictly between the fixed behaviour (sub-second)
// and the mutant behaviour (the full scaled deadline, ~10s here).
//
// stalledRoundTripFloor sizes the request so the scaled round-trip deadline is
// far larger than any bound below: a mutant that loses the cut runs for
// controlRoundtripDeadline(bodyLen), and that must be unmistakably longer than
// the assertion window or the cell is measuring noise.
const stalledRoundTripFloor = 10 << 20

// cutShortBound is the window a cut-short round trip must complete in. It is
// controlShutdownCutover plus generous slack for a loaded CI box, and is
// asserted below to be far under the scaled deadline a mutant would run for.
const cutShortBound = 3 * time.Second

// stalledControlSocket returns the path of a unix socket whose server accepts
// one connection, DRAINS the whole request (so the client's write completes
// and it is genuinely blocked reading the response), and then never replies.
// This models the hung helper the deadline exists for.
func stalledControlSocket(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(shortSockDir9322(t), "control.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var got ControlRequest
				_ = json.NewDecoder(conn).Decode(&got)
				// Never reply. Hold the connection open until the client
				// gives up or the test ends.
				<-t.Context().Done()
			}()
		}
	}()
	return sock
}

// inFlightControlConns reports how many control round trips the manager
// currently has registered. The test reads the field directly rather than
// through a production accessor added for testing.
func inFlightControlConns(m *Manager) int {
	m.ctrlIOMu.Lock()
	defer m.ctrlIOMu.Unlock()
	return len(m.ctrlIOConns)
}

// startStalledRoundTrip launches a control round trip that will never be
// answered, under m.mu exactly as production does, and returns once the
// manager has REGISTERED it as in flight. The returned channel closes when the
// round trip returns and m.mu is released.
func startStalledRoundTrip(t *testing.T) (*Manager, <-chan struct{}, time.Duration) {
	t.Helper()
	req, bodyLen := largeApplySnapshotBody(t, stalledRoundTripFloor)
	scaled := controlRoundtripDeadline(bodyLen)
	// The fixture precondition: without a cut, the hold lasts this long. If it
	// is not comfortably past every bound below, a green cell proves nothing.
	if scaled <= 3*cutShortBound {
		t.Fatalf("scaled deadline %v is not far enough past the %v assertion window "+
			"for a lost cut to be distinguishable — raise stalledRoundTripFloor",
			scaled, cutShortBound)
	}

	m := New()
	m.cfg.ControlSocket = stalledControlSocket(t)

	released := make(chan struct{})
	go func() {
		defer close(released)
		m.mu.Lock()
		defer m.mu.Unlock()
		_, _ = m.requestDetailedLocked(req)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for inFlightControlConns(m) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the round trip never registered as in flight — the fixture never " +
				"entered the state under test")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return m, released, scaled
}

// TestBeginControlShutdownCutsAnInFlightRoundTrip8526 is the core cell: a
// goroutine holding m.mu across a stalled control round trip must release it
// promptly once a stop is declared, so the teardown that needs m.mu completes
// inside the unit's stop budget instead of being resolved by SIGKILL.
//
// MUTATION: delete the `for conn := range m.ctrlIOConns { conn.SetDeadline }`
// loop in BeginControlShutdown. The waiter then blocks for the full scaled
// deadline (~10s) and this cell fails at cutShortBound with a clean message.
func TestBeginControlShutdownCutsAnInFlightRoundTrip8526(t *testing.T) {
	m, released, scaled := startStalledRoundTrip(t)

	// The hazard, expressed as the thing that actually breaks: something that
	// must acquire m.mu to shut the daemon down.
	acquired := make(chan struct{})
	go func() {
		defer close(acquired)
		m.mu.Lock()
		m.mu.Unlock() //nolint:staticcheck // acquisition is the observation
	}()

	// NEGATIVE CONTROL. If the waiter can acquire m.mu right now, the round
	// trip is not holding it and every assertion below would pass without the
	// mechanism doing anything.
	select {
	case <-acquired:
		t.Fatal("a waiter acquired m.mu while a control round trip was in flight — " +
			"the fixture is not in the state under test, so the cut below proves nothing")
	case <-time.After(500 * time.Millisecond):
	}

	start := time.Now()
	m.BeginControlShutdown()

	select {
	case <-acquired:
	case <-time.After(cutShortBound):
		t.Fatalf("a waiter on m.mu was still blocked %v after BeginControlShutdown; "+
			"the in-flight control round trip was not cut short and will hold the lock "+
			"for its full %v deadline — 3.35x the unit's TimeoutStopSec (#8526)",
			cutShortBound, scaled)
	}
	if elapsed := time.Since(start); elapsed > cutShortBound {
		t.Fatalf("m.mu released %v after the stop was declared, want < %v", elapsed, cutShortBound)
	}

	select {
	case <-released:
	case <-time.After(cutShortBound):
		t.Fatal("the cut round trip never returned")
	}
	if n := inFlightControlConns(m); n != 0 {
		t.Fatalf("%d control conns still registered after the round trip returned; "+
			"releaseControlIO is not running and the set grows without bound", n)
	}
}

// TestControlShutdownCapsARoundTripStartedAfterTheStop8526 covers the residual
// the cutover alone leaves: a large publish that starts AFTER the stop was
// declared would otherwise get the full scaled deadline and reintroduce the
// same overrun.
//
// MUTATION: drop the `if m.ctrlShutdown && d > controlShutdownCeiling` clamp in
// armControlIO. The request then runs its full scaled deadline (~10s) and this
// cell fails at the bound.
func TestControlShutdownCapsARoundTripStartedAfterTheStop8526(t *testing.T) {
	req, bodyLen := largeApplySnapshotBody(t, stalledRoundTripFloor)
	scaled := controlRoundtripDeadline(bodyLen)

	// The bound: the ceiling, plus the 2s dial allowance, plus slack. A mutant
	// runs for `scaled`, which must be clearly past it.
	bound := controlShutdownCeiling + 4*time.Second
	if scaled <= bound {
		t.Fatalf("scaled deadline %v does not exceed the %v assertion window — a lost "+
			"clamp would be indistinguishable from the fix", scaled, bound)
	}

	m := New()
	m.cfg.ControlSocket = stalledControlSocket(t)
	m.BeginControlShutdown()

	start := time.Now()
	m.mu.Lock()
	_, err := m.requestDetailedLocked(req)
	m.mu.Unlock()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a stalled helper must fail the round trip, not succeed")
	}
	if elapsed > bound {
		t.Fatalf("a round trip started after the stop ran %v (bound %v, unclamped %v); "+
			"the shutdown ceiling is not applied to requests that begin after "+
			"BeginControlShutdown (#8526)", elapsed, bound, scaled)
	}
}

// TestBeginControlShutdownDoesNotAcquireManagerMutex8526 asserts the lock-order
// rule the whole mechanism rests on: ctrlIOMu is a leaf, and
// BeginControlShutdown must be callable by a goroutine while another holds
// m.mu — which is the only situation it is ever useful in.
//
// MUTATION: add `m.mu.Lock(); defer m.mu.Unlock()` to BeginControlShutdown.
// Without the timer this would deadlock the whole test binary; with it the cell
// fails in 2s, so the mutation is a KILL rather than a void.
func TestBeginControlShutdownDoesNotAcquireManagerMutex8526(t *testing.T) {
	m := New()

	m.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.BeginControlShutdown()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		m.mu.Unlock()
		t.Fatal("BeginControlShutdown blocked while m.mu was held — it acquires the " +
			"manager mutex, which makes it unusable for the one job it has: cutting " +
			"short a round trip that is ITSELF holding m.mu (#8526)")
	}
	m.mu.Unlock()
}

// TestLegacyAdapterForwardsBeginControlShutdown8526 binds the WIRING the daemon
// actually uses. userspace.Boot returns a *LegacyDataPlaneAdapter, not a
// *Manager, so the daemon's optional-interface assertion matches the adapter.
// A missing or no-op forwarder leaves every Manager-level cell above green
// while production stops bounding anything.
//
// MUTATION: make LegacyDataPlaneAdapter.BeginControlShutdown a no-op body. The
// in-flight round trip is not cut and this cell fails at the bound.
func TestLegacyAdapterForwardsBeginControlShutdown8526(t *testing.T) {
	m, released, scaled := startStalledRoundTrip(t)
	adapter := NewLegacyDataPlaneAdapter(m)

	adapter.BeginControlShutdown()

	select {
	case <-released:
	case <-time.After(cutShortBound):
		t.Fatalf("the in-flight round trip was still running %v after "+
			"LegacyDataPlaneAdapter.BeginControlShutdown; the adapter does not forward "+
			"to the manager, so the daemon's bound is dead in production while the "+
			"Manager-level cells stay green (full deadline %v, #8526)",
			cutShortBound, scaled)
	}
}

// TestManagerCloseBoundsAnInFlightRoundTrip8526 pins the ORDERING inside
// Close: the bound is armed BEFORE m.mu is taken. That ordering is the entire
// mechanism — armed after the acquisition it could never run, because the
// acquisition is what is blocked.
//
// MUTATION: move `m.BeginControlShutdown()` below `m.mu.Lock()` in Close.
// Close then blocks for the full scaled deadline and this cell fails at the
// bound instead of hanging the binary.
func TestManagerCloseBoundsAnInFlightRoundTrip8526(t *testing.T) {
	m, released, scaled := startStalledRoundTrip(t)

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_ = m.Close()
	}()

	select {
	case <-closed:
	case <-time.After(cutShortBound):
		t.Fatalf("Manager.Close was still blocked %v after it was called; it waits on "+
			"m.mu, which the in-flight control round trip holds for its full %v "+
			"deadline. Close must declare the stop before acquiring the lock (#8526)",
			cutShortBound, scaled)
	}
	select {
	case <-released:
	case <-time.After(cutShortBound):
		t.Fatal("the cut round trip never returned")
	}
}

// deadlineRecorder is a net.Conn that records only what armControlIO does to
// it. The embedded interface is nil: nothing here performs I/O, so an
// accidental read/write panics loudly instead of passing silently.
type deadlineRecorder struct {
	net.Conn
	deadline time.Time
}

func (c *deadlineRecorder) SetDeadline(t time.Time) error { c.deadline = t; return nil }

// budget returns the deadline armControlIO chose, as a duration from now.
func (c *deadlineRecorder) budget() time.Duration { return time.Until(c.deadline) }

// closeEnough allows for the microseconds between armControlIO's time.Now()
// and the test's.
func closeEnough(got, want time.Duration) bool {
	d := got - want
	return d > -250*time.Millisecond && d < 250*time.Millisecond
}

// TestArmControlIOClampsOnlyAfterAStopIsDeclared8526 is the precise
// counterpart to the wall-clock ceiling cell above: it reads the deadline
// armControlIO actually chose instead of timing a socket, so the "unchanged in
// normal operation" half of the contract is asserted too — a clamp that fired
// all the time would be a #4036 regression, and a wall-clock cell that only
// measures the shutdown case cannot see it.
//
// MUTATION: drop `m.ctrlShutdown &&` from the clamp condition and the
// before-stop case reds; drop the whole clamp and the after-stop case reds.
func TestArmControlIOClampsOnlyAfterAStopIsDeclared8526(t *testing.T) {
	m := New()
	const scaled = 30 * time.Second
	if scaled <= controlShutdownCeiling {
		t.Fatalf("fixture: scaled %v must exceed the ceiling %v to tell the two apart",
			scaled, controlShutdownCeiling)
	}

	before := &deadlineRecorder{}
	m.armControlIO(before, scaled)
	if got := before.budget(); !closeEnough(got, scaled) {
		t.Fatalf("before any stop, armControlIO gave %v, want the full scaled %v — the "+
			"#8526 clamp is firing in normal operation, which re-opens the #4036 "+
			"false-timeout on a large apply", got, scaled)
	}
	m.releaseControlIO(before)

	m.BeginControlShutdown()

	after := &deadlineRecorder{}
	m.armControlIO(after, scaled)
	if got := after.budget(); !closeEnough(got, controlShutdownCeiling) {
		t.Fatalf("after the stop was declared, armControlIO gave %v, want the ceiling %v",
			got, controlShutdownCeiling)
	}
	m.releaseControlIO(after)
}

// TestCloseAndTeardownDoNotLatchTheShutdownCeiling8526 pins a decision that is
// invisible from the shutdown path and wrong in exactly one place.
//
// Manager.Teardown is NOT terminal: the bootstrap rollback
// (enterBootstrapMode, pkg/daemon/bootstrap.go) tears the dataplane down and
// deliberately KEEPS the object — "so a later confirmed commit re-arms it via
// runBootstrapExitStartup". If Teardown latched the shutdown ceiling, every
// apply for the rest of the daemon's life would be capped at
// controlShutdownCeiling, and the first feed-heavy commit after a bootstrap
// rollback would hit the #4036 false timeout again: Go reports the apply
// FAILED while the helper applied it live.
//
// Close is treated the same way rather than reasoned about separately, because
// the argument for latching it is "it happens to be terminal today".
//
// MUTATION: change either method back to m.BeginControlShutdown() and this
// reds, naming the method.
func TestCloseAndTeardownDoNotLatchTheShutdownCeiling8526(t *testing.T) {
	const scaled = 30 * time.Second
	for _, tc := range []struct {
		name string
		stop func(m *Manager) error
	}{
		{"Close", (*Manager).Close},
		{"Teardown", (*Manager).Teardown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			// The bpf-shim half of Teardown needs root (it unpins
			// /sys/fs/bpf/xpf) and fails under an unprivileged `go test`. That
			// is irrelevant here: the #8526 call is the FIRST statement in both
			// methods, so it has already run either way, and the property under
			// test is what it did to the ctrl-IO state.
			if err := tc.stop(m); err != nil {
				t.Logf("%s returned %v (expected unprivileged bpffs failure; the "+
					"#8526 call precedes it)", tc.name, err)
			}
			rec := &deadlineRecorder{}
			m.armControlIO(rec, scaled)
			if got := rec.budget(); !closeEnough(got, scaled) {
				t.Fatalf("after %s, armControlIO gave %v instead of the full scaled %v: "+
					"%s latched the shutdown ceiling. The bootstrap rollback tears the "+
					"dataplane down and REUSES this object, so the next feed-heavy "+
					"commit would be capped and false-timeout (#4036 / #8526)",
					tc.name, got, scaled, tc.name)
			}
			m.releaseControlIO(rec)
			if m.ctrlShutdown {
				t.Fatalf("%s set the terminal-stop latch; only BeginControlShutdown may",
					tc.name)
			}
		})
	}
}
