package userspace

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Supervision of a helper that dies AFTER reporting ready (#5838).
//
// Every case here drives the PRODUCTION supervisor against a REAL spawned child
// that is really killed. The seams injected are only (a) which restart delay is
// used and (b) whether the scheduled restart is allowed to run — never the
// detection, the reaping, or the fail-closed bookkeeping, which is the part
// under test.
//
// What these do NOT claim: they do not test that transit stops flowing. It
// already does — the XDP shim drops transit for a dead helper through three
// independent degraded-path gates (binding not ready, heartbeat stale within
// USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS = 5000, XSK redirect error), all of
// which are in userspace-xdp and none of which depend on the manager noticing.
// The property under test is that the MANAGER stops claiming a dead helper is a
// working one — above all to takeoverReadyLocked, which an HA peer consults
// before handing this node an RG.

// restartRecorder records the delays a Manager arms, without ever running the
// restart body. It is guarded because the supervisor goroutine arms them.
type restartRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (r *restartRecorder) arm(d time.Duration, _ func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delays = append(r.delays, d)
}

func (r *restartRecorder) snapshot() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.delays...)
}

// spawnSupervisedChild starts a real long-lived child under the production
// supervisor and returns it. The manager is left in the state a helper that has
// reached readiness would leave it: proc set, status healthy, liveness proven.
func spawnSupervisedChild(t *testing.T) (*Manager, *exec.Cmd, *restartRecorder) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "u5838")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	es := NewEventStream(filepath.Join(dir, "e.sock"))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := es.Start(ctx); err != nil {
		t.Fatalf("event stream start: %v", err)
	}

	rec := &restartRecorder{}
	m := New()
	m.restartTimerFn = rec.arm
	m.mode = ModeUserspaceCompat
	m.eventStream = es
	m.eventStreamCancel = cancel
	m.cfg.ControlSocket = filepath.Join(dir, "c.sock")
	m.lastStatus = ProcessStatus{
		Enabled:         true,
		ForwardingArmed: true,
		Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
	}
	m.xskLivenessProven = true

	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	m.mu.Lock()
	m.proc = cmd
	m.startHelperSupervisorLocked(cmd)
	m.mu.Unlock()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return m, cmd, rec
}

// awaitSupervisor blocks until the generation's waiter has reaped the child AND
// finished its post-exit bookkeeping under m.mu.
func awaitSupervisor(t *testing.T, m *Manager, exited <-chan struct{}) {
	t.Helper()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("supervisor never reaped the child: no waiter owns this generation (#5838)")
	}
	// The waiter closes `exited` before taking m.mu, so acquiring the lock here
	// does not prove its bookkeeping ran. Poll the observable outcome instead.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		done := m.proc == nil
		m.mu.Unlock()
		if done {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("supervisor reaped the child but never cleared m.proc")
}

// procState reads a pid's kernel state letter; "" means the pid is gone.
func procState(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	f := strings.Fields(string(b))
	if len(f) > 2 {
		return f[2]
	}
	return ""
}

// TestHelperCrashIsReapedAndFailsClosed5838 is the issue itself: a helper that
// exits after reporting ready must be reaped, must stop being reported as
// running, and must stop the node advertising itself as a takeover target.
//
// RED on revert: delete startHelperSupervisorLocked's call site in
// ensureProcessLocked, or make handleUnexpectedHelperExitLocked skip
// resetAfterHelperGoneLocked.
func TestHelperCrashIsReapedAndFailsClosed5838(t *testing.T) {
	m, cmd, _ := spawnSupervisedChild(t)
	pid := cmd.Process.Pid

	// NEGATIVE CONTROL. Without this the crash assertion below is satisfiable
	// by a manager that is never takeover-ready for some unrelated reason.
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("premise broken: a healthy supervised helper is not takeover-ready (%v)", reasons)
	}
	// The production death path must wake daemon transit reassertion through
	// the RuntimeDataPlane adapter after publishing stopped/backoff state.
	adapter := NewLegacyDataPlaneAdapter(m)
	if running, crashLooping := adapter.HelperSupervisorState(); !running || crashLooping {
		t.Fatalf("healthy supervisor state = (running=%v, crashLooping=%v), want (true,false)",
			running, crashLooping)
	}

	observed := make(chan struct{}, 1)
	adapter.SetHelperSupervisorObserver(func() {
		select {
		case observed <- struct{}{}:
		default:
		}
	})

	m.mu.Lock()
	exited := m.procSup.exited
	m.mu.Unlock()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	awaitSupervisor(t, m, exited)
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("production supervisor-death path did not notify its observer")
	}
	if running, crashLooping := adapter.HelperSupervisorState(); running || crashLooping {
		t.Fatalf("single failed restart state = (running=%v, crashLooping=%v), want (false,false)",
			running, crashLooping)
	}

	if st := procState(pid); st == "Z" {
		t.Errorf("child pid %d is still a ZOMBIE after the supervisor ran: nothing reaped it", pid)
	}
	m.mu.Lock()
	proc, crash := m.proc, m.helperCrash
	m.mu.Unlock()
	if proc != nil {
		t.Error("m.proc is still set after the helper died; every `m.proc == nil` liveness test still reads TRUE")
	}
	if !crash.LastExitWasCrash {
		t.Error("no crash recorded for an unexpected exit")
	}
	if !strings.Contains(crash.Detail, "signal") {
		t.Errorf("crash detail %q does not name the signal that killed the helper", crash.Detail)
	}
	if crash.PID != pid {
		t.Errorf("crash record names pid %d, want the dead child %d", crash.PID, pid)
	}

	ready, reasons := m.TakeoverReady()
	if ready {
		t.Fatalf("TakeoverReady() = true with a DEAD helper — an HA peer may hand RG "+
			"mastership to a node that cannot forward (#5838); reasons=%v", reasons)
	}
	if len(reasons) == 0 {
		t.Error("TakeoverReady() denied without naming a reason")
	}
}

// TestExactlyOneWaitPerGeneration5838 pins invariant 1. If a second waiter
// existed, one of the two would lose the reap and see ECHILD; the supervisor's
// own Wait must be the one that succeeded.
func TestExactlyOneWaitPerGeneration5838(t *testing.T) {
	m, cmd, _ := spawnSupervisedChild(t)

	m.mu.Lock()
	g := m.procSup
	m.mu.Unlock()

	_ = cmd.Process.Kill()
	awaitSupervisor(t, m, g.exited)

	// A SIGKILLed child legitimately reaps as *exec.ExitError ("signal:
	// killed"). What proves the waiter OWNED the reap is that it got a real
	// wait status; a loser in a two-waiter race gets ECHILD instead, which is
	// not an ExitError at all.
	var exitErr *exec.ExitError
	if g.waitErr != nil && !errors.As(g.waitErr, &exitErr) {
		t.Errorf("the generation's waiter did not own the reap: Wait returned %v "+
			"(a second waiter took the child)", g.waitErr)
	}
	if g.state == nil {
		t.Fatal("the waiter recorded no ProcessState, so nothing reaped the child")
	}
	// A second Wait on the same Cmd must now fail — which is exactly what the
	// pre-#5838 stopLocked would have been doing as waiter number two.
	if err := cmd.Wait(); err == nil {
		t.Error("a SECOND cmd.Wait() succeeded; the generation does not have a unique waiter")
	}
}

// TestIntentionalStopDoesNotScheduleRestart5838 pins invariant 5: a deliberate
// teardown performs one Wait, one teardown, and NO restart. A supervisor that
// treated every exit as a crash would fight stopLocked and respawn a helper the
// operator just stopped.
//
// RED on revert: remove the stoppingHelper guard AND the procSup fence from
// superviseHelper.
func TestIntentionalStopDoesNotScheduleRestart5838(t *testing.T) {
	m, cmd, rec := spawnSupervisedChild(t)
	pid := cmd.Process.Pid

	m.mu.Lock()
	g := m.procSup
	m.stopLocked()
	proc, sup := m.proc, m.procSup
	m.mu.Unlock()

	select {
	case <-g.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("stopLocked returned without the child being reaped")
	}
	if proc != nil || sup != nil {
		t.Error("stopLocked left proc/procSup set")
	}
	if st := procState(pid); st == "Z" {
		t.Errorf("child pid %d left a zombie after an intentional stop", pid)
	}
	// Give a mistakenly-armed crash path time to fire.
	time.Sleep(100 * time.Millisecond)
	m.mu.Lock()
	crash := m.helperCrash
	m.mu.Unlock()
	if crash.LastExitWasCrash {
		t.Errorf("an INTENTIONAL stop was recorded as a crash: %+v", crash)
	}
	if len(rec.snapshot()) != 0 {
		t.Errorf("an intentional stop scheduled %d restart(s) %v; it must schedule none", len(rec.snapshot()), rec.snapshot())
	}
}

// TestStaleWaiterCannotMutateNewerGeneration5838 pins invariant 3 directly at
// the production site: superviseHelper is exactly what the spawned goroutine
// runs, so driving it with a stale generation is the real race, not a model of
// it.
func TestStaleWaiterCannotMutateNewerGeneration5838(t *testing.T) {
	m, _, rec := spawnSupervisedChild(t)

	// A finished child belonging to an OLDER generation.
	old := exec.Command("sh", "-c", "exit 7")
	if err := old.Start(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	live := m.procSup
	stale := &helperGeneration{gen: m.procGen - 1, cmd: old, exited: make(chan struct{})}
	m.mu.Unlock()

	m.superviseHelper(stale)

	m.mu.Lock()
	proc, sup, crash := m.proc, m.procSup, m.helperCrash
	m.mu.Unlock()

	if proc == nil {
		t.Error("a stale generation-N waiter cleared generation N+1's process")
	}
	if sup != live {
		t.Error("a stale waiter replaced the live generation's supervisor record")
	}
	if crash.LastExitWasCrash {
		t.Errorf("a stale waiter recorded a crash against the live generation: %+v", crash)
	}
	if len(rec.snapshot()) != 0 {
		t.Errorf("a stale waiter scheduled a restart: %v", rec.snapshot())
	}
}

// TestHelperRestartBackoffIsBounded5838 pins invariant 4's fork-storm half.
func TestHelperRestartBackoffIsBounded5838(t *testing.T) {
	prev := time.Duration(0)
	for attempt := 1; attempt <= 20; attempt++ {
		d := helperRestartDelay(attempt)
		if d < helperRestartBackoffBase {
			t.Fatalf("attempt %d delay %v is below the base %v — a crash loop would fork-storm",
				attempt, d, helperRestartBackoffBase)
		}
		if d > helperRestartBackoffMax {
			t.Fatalf("attempt %d delay %v exceeds the cap %v", attempt, d, helperRestartBackoffMax)
		}
		if d < prev {
			t.Fatalf("attempt %d delay %v went BACKWARDS from %v", attempt, d, prev)
		}
		prev = d
	}
	if helperRestartDelay(20) != helperRestartBackoffMax {
		t.Errorf("backoff never reaches its cap: attempt 20 = %v, want %v",
			helperRestartDelay(20), helperRestartBackoffMax)
	}
}

// TestFailedRestartRetainsDebtAndStaysFailClosed5838 pins the other half of
// invariant 4: a restart that cannot bring the helper up must keep retrying on
// a LONGER delay and must not clear the crash state, because clearing it is
// what would let takeoverReadyLocked go true again.
func TestFailedRestartRetainsDebtAndStaysFailClosed5838(t *testing.T) {
	m, cmd, rec := spawnSupervisedChild(t)
	// Prime the episode one failed attempt below the crash-loop cap. The
	// first real child exit must remain a fast-restart case; a failed retry
	// below will cross the cap and notify the daemon.
	loopAttempt := 1
	for helperRestartDelay(loopAttempt) < helperRestartBackoffMax {
		loopAttempt++
	}
	observed := make(chan struct{}, 2)
	m.SetHelperSupervisorObserver(func() {
		select {
		case observed <- struct{}{}:
		default:
		}
	})
	// A binary that cannot exist, so the restart's ensureProcessLocked fails at
	// findBinary without spawning anything.
	m.mu.Lock()
	m.helperCrash.Restarts = loopAttempt - 2
	m.cfg.Binary = filepath.Join(t.TempDir(), "no-such-helper")
	gen := m.procGen
	exited := m.procSup.exited
	m.mu.Unlock()

	_ = cmd.Process.Kill()
	awaitSupervisor(t, m, exited)
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("initial supervisor death did not notify daemon")
	}
	if running, looping := m.HelperSupervisorState(); running || looping {
		t.Fatalf("single-crash state = (running=%v, looping=%v), want (false,false)", running, looping)
	}

	if len(rec.snapshot()) != 1 {
		t.Fatalf("crash scheduled %d restarts, want exactly 1: %v", len(rec.snapshot()), rec.snapshot())
	}
	first := rec.snapshot()[0]

	// Run the scheduled restart; it must fail, cross the cap, and notify again.
	m.restartHelperAfterCrash(gen)
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("failed restart crossing the crash-loop cap did not notify daemon")
	}
	if running, looping := m.HelperSupervisorState(); running || !looping {
		t.Fatalf("capped retry state = (running=%v, looping=%v), want (false,true)", running, looping)
	}

	if len(rec.snapshot()) != 2 {
		t.Fatalf("a FAILED restart did not re-arm: delays=%v", rec.snapshot())
	}
	if rec.snapshot()[1] <= first {
		t.Errorf("retry delay %v did not grow past %v; a failing helper would be retried at a fixed tight rate",
			rec.snapshot()[1], first)
	}
	m.mu.Lock()
	crash := m.helperCrash
	m.mu.Unlock()
	if !crash.LastExitWasCrash {
		t.Error("a FAILED restart cleared the crash state; the node would advertise itself ready again")
	}
	if ready, _ := m.TakeoverReady(); ready {
		t.Error("TakeoverReady() = true while the helper is still down after a failed restart")
	}
}

// TestBringUpDetectsAChildThatDiesBeforeReady5838 binds the PRODUCTION WIRING
// rather than the supervisor primitives: it drives ensureProcessLocked, the
// function that actually spawns the helper, with a binary that exits
// immediately.
//
// The other cases in this file install the supervisor themselves, so they would
// all still pass if ensureProcessLocked stopped starting one. This is the case
// that cannot: without a supervisor there is no waiter, nothing ever observes
// the exit, and bring-up can only fall out of its 5s readiness deadline. The
// assertion is therefore on the ELAPSED TIME and the disposition, not merely on
// "an error was returned" — the pre-#5838 code also returned an error here, it
// just took the full deadline to do it and could not say why.
//
// RED on revert: delete `m.startHelperSupervisorLocked(cmd)` from
// ensureProcessLocked.
func TestBringUpDetectsAChildThatDiesBeforeReady5838(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "u5838b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// A real, existing binary that exits non-zero at once and never binds a
	// control socket — an assert/panic on startup, modelled exactly.
	bin := filepath.Join(dir, "helper")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.restartTimerFn = (&restartRecorder{}).arm
	cfg := config.UserspaceConfig{
		Binary:        bin,
		ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile:     filepath.Join(dir, "state.json"),
		EventSocket:   filepath.Join(dir, "e.sock"),
	}

	start := time.Now()
	m.mu.Lock()
	err = m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ensureProcessLocked reported success for a helper that exited immediately")
	}
	if elapsed > 2*time.Second {
		t.Errorf("bring-up took %v to notice a child that exited immediately; with no waiter "+
			"owning the generation nothing observes the exit and bring-up can only "+
			"time out on its 5s readiness deadline (#5838)", elapsed)
	}
	if !strings.Contains(err.Error(), "exited before becoming ready") {
		t.Errorf("bring-up error %q does not report that the child EXITED; an operator "+
			"cannot tell a crashed helper from a slow one", err)
	}
	if !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("bring-up error %q does not carry the child's disposition", err)
	}
	m.mu.Lock()
	proc, sup := m.proc, m.procSup
	m.mu.Unlock()
	if proc != nil || sup != nil {
		t.Error("a failed bring-up left proc/procSup set")
	}
}

// TestCrashClearsHelperDerivedState5838 binds resetAfterHelperGoneLocked
// itself, which TestHelperCrashIsReapedAndFailsClosed5838 does NOT: that case
// asserts TakeoverReady() goes false, and `m.proc = nil` alone is enough to
// satisfy it, because the nil-proc gate is the FIRST reason
// takeoverReadyLocked appends. A crash path that dropped the process handle and
// cleared nothing else therefore passed it — verified, by mutation, before this
// case was written.
//
// The rest of the reset is not decoration. m.lastStatus is what every other
// consumer reads (the forwarding-state sync, the standby neighbour prewarm
// gate, chassis status rendering), so leaving it at its last-good values means
// they all keep believing a dead helper is enabled and armed. And the event
// stream is a BOUND LISTENER: not closing it leaks a socket and an fd per
// crash, while leaving takeoverReadyLocked's event-stream gate satisfied by a
// listener whose helper is gone.
//
// RED on revert: delete `m.resetAfterHelperGoneLocked()` from
// handleUnexpectedHelperExitLocked.
func TestCrashClearsHelperDerivedState5838(t *testing.T) {
	m, cmd, _ := spawnSupervisedChild(t)

	// Premise: the manager really is holding helper-derived state to clear.
	m.mu.Lock()
	m.publishedSnapshot = 42
	if !m.lastStatus.Enabled || !m.lastStatus.ForwardingArmed || m.eventStream == nil || !m.xskLivenessProven {
		m.mu.Unlock()
		t.Fatal("premise broken: the fixture is not holding the state this case is about")
	}
	exited := m.procSup.exited
	m.mu.Unlock()

	_ = cmd.Process.Kill()
	awaitSupervisor(t, m, exited)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastStatus.Enabled || m.lastStatus.ForwardingArmed {
		t.Errorf("crash left lastStatus describing a live helper (Enabled=%v ForwardingArmed=%v); "+
			"every consumer that reads it still believes the dataplane is up",
			m.lastStatus.Enabled, m.lastStatus.ForwardingArmed)
	}
	if m.lastStatus.Capabilities.ForwardingSupported {
		t.Error("crash left stale helper capabilities")
	}
	if m.eventStream != nil {
		t.Error("crash left the event-stream listener bound: one leaked socket and fd per crash, " +
			"and takeoverReadyLocked's event-stream gate stays satisfied by a listener with no helper")
	}
	if m.xskLivenessProven {
		t.Error("crash left xskLivenessProven set; the replacement helper inherits a liveness proof it never earned")
	}
	if m.publishedSnapshot != 0 {
		t.Errorf("crash left publishedSnapshot = %d; the replacement helper would be treated as "+
			"already carrying that snapshot and never receive it", m.publishedSnapshot)
	}
}

// TestRestartUsesTheCurrentConfigNotTheDeadGeneration5838 pins the acceptance
// bullet "a crash concurrent with a config replacement cannot resurrect the old
// config": the restart re-runs the ORDINARY bring-up against m.cfg as it stands
// when the restart fires, not against the argv the dead generation was launched
// with.
//
// The discriminator is the control-socket path, which bring-up reports in its
// failure. A restart that replayed the dead generation's launch arguments would
// name the OLD path.
//
// RED on revert: make restartHelperAfterCrash re-exec the dead generation's
// cmd.Args / captured config instead of calling ensureProcessLocked(m.cfg).
func TestRestartUsesTheCurrentConfigNotTheDeadGeneration5838(t *testing.T) {
	m, cmd, rec := spawnSupervisedChild(t)
	loopAttempt := 1
	for helperRestartDelay(loopAttempt) < helperRestartBackoffMax {
		loopAttempt++
	}

	m.mu.Lock()
	oldSocket := m.cfg.ControlSocket
	gen := m.procGen
	m.helperCrash.Restarts = loopAttempt - 2
	exited := m.procSup.exited
	m.mu.Unlock()

	_ = cmd.Process.Kill()
	awaitSupervisor(t, m, exited)
	if len(rec.snapshot()) != 1 {
		t.Fatalf("crash scheduled %d restarts, want 1", len(rec.snapshot()))
	}

	// The config is REPLACED while the helper is down — a commit landing during
	// the outage. A helper binary that exits at once keeps the case fast and
	// makes bring-up report the socket path it actually tried.
	dir, err := os.MkdirTemp("/tmp", "u5838r")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := filepath.Join(dir, "helper")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	newSocket := filepath.Join(dir, "new-control.sock")
	// The observable that proves WHICH config bring-up ran against, rather than
	// merely which one is still stored: ensureProcessLocked MkdirAll's the
	// state file's parent, and this one does not exist yet. A restart that
	// replayed the dead generation's arguments never creates it.
	newStateDir := filepath.Join(dir, "gen2-state")
	m.mu.Lock()
	m.cfg = config.UserspaceConfig{
		Binary:        bin,
		ControlSocket: newSocket,
		StateFile:     filepath.Join(newStateDir, "state.json"),
		EventSocket:   filepath.Join(dir, "e.sock"),
	}
	m.mu.Unlock()
	if _, err := os.Stat(newStateDir); !os.IsNotExist(err) {
		t.Fatalf("premise broken: %s already exists, so its later presence proves nothing", newStateDir)
	}

	m.restartHelperAfterCrash(gen)

	m.mu.Lock()
	usedSocket := m.cfg.ControlSocket
	crash := m.helperCrash
	m.mu.Unlock()
	if usedSocket != newSocket {
		t.Fatalf("restart overwrote the desired config: cfg.ControlSocket = %q, want %q", usedSocket, newSocket)
	}
	if _, err := os.Stat(newStateDir); err != nil {
		t.Errorf("restart did not run bring-up against the CURRENT config: %s was never created (%v). "+
			"A restart that replays the dead generation's launch arguments resurrects the "+
			"pre-crash config and silently ignores a commit that landed during the outage (#5838)",
			newStateDir, err)
	}
	if oldSocket == newSocket {
		t.Fatal("premise broken: the two configs are not distinguishable")
	}
	if !crash.LastExitWasCrash {
		t.Error("the failed restart cleared the crash state")
	}
	// It really did attempt a spawn with the NEW config: the attempt count grew
	// and a fresh retry is armed.
	if len(rec.snapshot()) != 2 {
		t.Errorf("restart did not re-arm after failing against the new config: %v", rec.snapshot())
	}
	if crash.Restarts != loopAttempt {
		t.Errorf("restart attempts = %d, want %d", crash.Restarts, loopAttempt)
	}
	if running, looping := m.HelperSupervisorState(); running || !looping {
		t.Fatalf("failed readiness at retry cap state = (running=%v, looping=%v), want (false,true)",
			running, looping)
	}
}
