package userspace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// process_supervisor.go owns the lifetime of a spawned helper process (#5838).
//
// # What was missing
//
// ensureProcessLocked spawned `xpf-userspace-dp`, waited for control-socket
// readiness and returned. Nothing called cmd.Wait() for the RUNNING generation
// — the only Wait in the package was created inside stopLocked, i.e. only for
// an INTENTIONAL stop. A helper that died after reporting ready (OOM, assert,
// SIGKILL, panic) therefore:
//
//   - stayed a zombie, because nobody reaped it;
//   - left m.proc non-nil, so every `m.proc == nil` liveness test read TRUE;
//   - left m.lastStatus at its last-good values, because the 1 Hz status poll's
//     failure branch only logged;
//   - and was noticed only if some later compile/sync path happened to call
//     ensureProcessLocked. On a stable config and a stable FIB, nothing does,
//     so the state persisted indefinitely.
//
// cmd.ProcessState is not populated until Wait, so it was not a valid liveness
// detector either — which is why the pre-existing readiness loop's
// `cmd.ProcessState != nil` check could only ever fire for a child that died
// before becoming ready.
//
// # What this is NOT
//
// It is not a fix for "the box forwards without policy after a helper crash",
// because the box does not do that. The XDP shim stays attached and is owned by
// xpfd, not the helper, and it drops transit through THREE independent
// degraded-path gates, verified in userspace-xdp/src/lib.rs:
//
//   - a missing or not-ready binding row -> drop_degraded_transit;
//   - a missing or STALE heartbeat -> drop_degraded_transit
//     (USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS = 5000, and the dead helper stops
//     writing USERSPACE_HEARTBEAT immediately);
//   - a failed XSK redirect -> drop_degraded_transit.
//
// All three PASS proven local/control traffic (pass_local_control) so the node
// stays manageable, and DROP transit. The post-crash failure mode is therefore
// a transit blackhole, not unadjudicated kernel forwarding. That is the safer
// failure and it is why this file's job is availability and honesty rather than
// closing a forwarding hole.
//
// The honesty half is the security-relevant one: takeoverReadyLocked gates on
// `m.proc == nil` and on m.lastStatus, and BOTH were stale after a crash, so
// TakeoverReady() returned true — with no reasons — for a node whose dataplane
// was dead. In a chassis cluster the peer consults exactly that to decide
// whether an RG ownership move can rely on this node for forwarding, so a
// crashed node advertised itself as a valid failover target and would blackhole
// every flow handed to it.

// helperGeneration is one spawned helper process and the SINGLE Wait that owns
// it.
//
// exited is closed by the waiter goroutine BEFORE it acquires m.mu. That
// ordering is what lets stopLocked block on it while holding m.mu without
// deadlocking against the waiter's own bookkeeping.
type helperGeneration struct {
	gen    uint64
	cmd    *exec.Cmd
	exited chan struct{}
	// waitErr and state are written by the waiter before it closes exited, so
	// a reader that has observed the close may read them without a lock.
	waitErr error
	state   *os.ProcessState
}

// describeExit renders a reaped child's disposition for a log line and the
// operator-facing crash record. Read only after exited is closed.
func (g *helperGeneration) describeExit() string {
	if g.state == nil {
		if g.waitErr != nil {
			return "wait failed: " + g.waitErr.Error()
		}
		return "unknown"
	}
	if ws, ok := g.state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return fmt.Sprintf("killed by signal %v", ws.Signal())
	}
	return fmt.Sprintf("exit status %d", g.state.ExitCode())
}

// exitCodeAndSignal returns the child's disposition as two separable values:
// the exit status (or -1) and the signal name (or ""). #7250 — describeExit
// folds both into one prose string that a renderer cannot take apart again.
func (g *helperGeneration) exitCodeAndSignal() (int, string) {
	if g.state == nil {
		return -1, ""
	}
	if ws, ok := g.state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return -1, ws.Signal().String()
	}
	return g.state.ExitCode(), ""
}

// HelperCrashRecord is the operator-visible record of the last unexpected exit
// and the backoff it drives.
//
// #7250: EXPORTED, because the previous unexported `HelperCrashRecord` could be
// returned but not NAMED by an out-of-package caller — and a status surface is
// exactly such a caller. It could hold the value and not declare a variable, a
// struct field or a parameter for it, which made the accessor unusable for the
// thing it exists to feed. The type is named ...Record rather than ...State so
// it does not collide with the Manager.HelperCrashState() accessor.
type HelperCrashRecord struct {
	// LastExitWasCrash is set while the manager is between an unexpected exit
	// and a successful restart. It is what makes the staleness observable
	// instead of having to be inferred from a nil pointer.
	//
	// #7250: renamed from `Crashed`, which was read as BOTH "the last exit was
	// unexpected" and "a restart is coming" — two facts that diverge. This is
	// the first one, and it is deliberately NOT cleared by an intentional stop:
	// `ensureProcessLocked` calls the same `stopLocked` when a spawn misses its
	// readiness wait, and the retry path depends on this flag as its debt
	// (clearing it turned TestRestartUsesTheCurrentConfigNotTheDeadGeneration5838
	// red). Use RestartPending for the other fact.
	LastExitWasCrash bool
	// Detail is the reaped disposition ("exit status 101", "killed by signal
	// killed"). Never carries a secret. Kept for display; prefer ExitCode /
	// Signal when deciding anything.
	Detail string
	// ExitCode is the child's exit status, or -1 when it was signalled or the
	// status could not be read (#7250). Exactly one of ExitCode >= 0 and
	// Signal != "" is meaningful, and Signal is the discriminator.
	//
	// Split out because Detail folded the two into one string, and a renderer
	// cannot reliably take them apart again — "killed by signal killed" and
	// "exit status 101" have no common grammar to parse.
	ExitCode int
	// Signal is the signal name when the child was killed by one, otherwise "".
	Signal string
	// PID is the dead child, kept so an operator can correlate with journald.
	PID int
	// At is when the exit was observed.
	At time.Time
	// Restarts counts consecutive restart ATTEMPTS since the last helper that
	// reached readiness.
	Restarts int
	// NextRestart is when the armed retry is due. Only meaningful when
	// RestartPending is true — after an intentional stop this is a time in the
	// PAST with no timer behind it (#7250).
	NextRestart time.Time

	// LastRestartAttempt is when a restart was last ATTEMPTED — the moment
	// `restartHelperAfterCrash` called into `ensureProcessLocked`, whatever the
	// outcome. Zero when none has been attempted in this episode.
	//
	// #7967 / #5838: episode-scoped like every other field here, and cleared by
	// the same successful-restart wipe. That was raised as an objection to the
	// field existing at all — that it would be "wiped by the very event it
	// records" — but the objection applies equally to `Restarts`, `NextRestart`,
	// `ExitCode`, `Detail` and `LastExitWasCrash`, all of which are shipped and
	// rendered. A rejection that would also reject five existing fields is not a
	// reason to omit the sixth.
	//
	// What it buys is ergonomic rather than informational: the scheduling time
	// was always DERIVABLE, since `helperRestartDelay` is a pure function of
	// `Restarts` and both it and `NextRestart` are on the surface, so
	// `NextRestart - helperRestartDelay(Restarts)` recovers it. A status surface
	// that requires the reader to reimplement the backoff function in their head
	// is one that gets misread. Stating the fact is not the same as making it
	// recoverable.
	LastRestartAttempt time.Time
	// RestartPending reports whether a retry is actually armed and will fire.
	//
	// #7250: DERIVED in HelperCrashState() from the live generation rather than
	// stored, because a stored flag is exactly what went stale. An intentional
	// stop advances procGen, which orphans the armed timer without clearing the
	// crash record — so before this, a renderer would have reported a restart
	// that was never going to happen.
	RestartPending bool
	// restartGen is the process generation the pending retry was armed for.
	// Unexported: it is an internal fence, not something a renderer should see
	// or construct.
	restartGen uint64
}

// CrashLooping reports whether the helper should be treated as not coming back.
//
// #7250 asked for "a predicate an operator or a health surface can read", and
// noted it needs deciding rather than plumbing. The decision: crash-looping is
// BACKOFF AT THE CAP, not a raw restart count.
//
// A count threshold is time-blind — twenty restarts over a week and twenty in a
// minute are different situations and a bare counter cannot tell them apart.
// The backoff already encodes the time dimension: it doubles from
// helperRestartBackoffBase and saturates at helperRestartBackoffMax, so reaching
// the cap means the supervisor has exhausted its escalation and is now retrying
// at its slowest rate. With the shipped 1s base and 60s cap that is roughly two
// minutes of uninterrupted failure, and it does not fire for a helper that
// crashed once an hour ago.
//
// Derived, never stored, for the same reason RestartPending is: a stored
// judgement about the present is the thing that goes stale.
func (r HelperCrashRecord) CrashLooping() bool {
	return r.LastExitWasCrash && helperRestartDelay(r.Restarts) >= helperRestartBackoffMax
}

// Helper restart backoff. Bounded exponential from base to max, so a helper
// that cannot start (a corrupt binary, a NIC that will not bind) retries
// forever at a fixed low rate instead of fork-storming, and a one-off crash
// recovers in about a second.
//
// They are vars rather than consts purely so a test can drive many real
// restarts without spending wall-clock seconds; production never reassigns
// them. Same seam idiom as statusLoopInterval in process_status.go.
var (
	helperRestartBackoffBase = time.Second
	helperRestartBackoffMax  = 60 * time.Second
)

// helperRestartDelay is the backoff for attempt n (1-based).
func helperRestartDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := helperRestartBackoffBase
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= helperRestartBackoffMax {
			return helperRestartBackoffMax
		}
	}
	return d
}

// scheduleRestartTimer arms fn to run after d.
//
// It is a per-Manager field rather than a package var deliberately: a package
// var is shared by every Manager in the process, so a supervisor goroutine from
// one test can land on another test's seam after t.Cleanup restored it —
// appending a phantom restart to a slice that test is asserting on, from a
// goroutine that does not hold that test's lock. That is a cross-test mutation
// channel and a data race at the same time. Production leaves it nil.
func (m *Manager) scheduleRestartTimer(d time.Duration, fn func()) {
	if m.restartTimerFn != nil {
		m.restartTimerFn(d, fn)
		return
	}
	time.AfterFunc(d, fn)
}

// startHelperSupervisorLocked allocates the next process generation for cmd and
// starts the ONE goroutine that owns its Wait.
//
// Called with m.mu held, immediately after a successful cmd.Start().
func (m *Manager) startHelperSupervisorLocked(cmd *exec.Cmd) {
	m.procGen++
	// Keep the helper-session epoch ahead of any sender while this new process
	// is still being published. The subsequent snapshot publication records
	// the same live generation together with its capability and inventory.
	m.haWatchdogProcessGen.Add(1)
	g := &helperGeneration{gen: m.procGen, cmd: cmd, exited: make(chan struct{})}
	m.procSup = g
	go m.superviseHelper(g)
}

// superviseHelper is the single waiter for one generation.
//
// It reaps the child, publishes the result, and only THEN takes m.mu — so a
// stopLocked that is parked on g.exited while holding m.mu is released before
// this goroutine needs the lock.
func (m *Manager) superviseHelper(g *helperGeneration) {
	g.waitErr = g.cmd.Wait()
	g.state = g.cmd.ProcessState
	close(g.exited)

	m.mu.Lock()
	defer m.mu.Unlock()
	// Generation fence, and the ONLY thing that distinguishes an expected exit
	// from a crash.
	//
	// An INTENTIONAL teardown clears procSup under m.mu before releasing it,
	// and this goroutine cannot acquire m.mu until that release — so a stop is
	// already `m.procSup != g` by the time we get here and takes the same exit
	// as a stale generation. An earlier draft also carried a `stoppingHelper`
	// flag for that case; it was removed because no input made it decide
	// anything the fence had not already decided, and a branch whose condition
	// never varies is untestable code pretending to be a safeguard.
	if m.procSup != g || m.procGen != g.gen {
		return
	}
	m.handleUnexpectedHelperExitLocked(g)
}

// handleUnexpectedHelperExitLocked fails the node closed after a crash and
// schedules a bounded restart.
//
// Order matters. The shim is disarmed FIRST, before any bookkeeping that could
// fail, because that is the step that stops the XDP program redirecting into a
// dead XSK; every later step is about not lying to an operator or to the
// cluster peer.
func (m *Manager) handleUnexpectedHelperExitLocked(g *helperGeneration) {
	detail := g.describeExit()
	pid := 0
	if g.cmd.Process != nil {
		pid = g.cmd.Process.Pid
	}
	slog.Error("userspace dataplane helper exited unexpectedly; failing closed and scheduling restart (#5838)",
		"pid", pid, "disposition", detail, "generation", g.gen)

	// Retire the independent helper-session epoch immediately, but keep the
	// explicit fail-closed disarm FIRST. The restart timer must continue to use
	// g.gen for its procGen fence, so incrementing procGen here would cancel the
	// legitimate retry; this separate epoch closes stale sends without changing
	// that contract.
	m.haWatchdogProcessGen.Add(1)

	// Disarm the shim explicitly rather than relying on it noticing. The
	// degraded gates in userspace-xdp already drop transit for a dead helper —
	// stale heartbeat within 5s, and a failing XSK redirect immediately — but
	// this closes the window deterministically and clears the binding rows, so
	// the shim has nothing READY to redirect to at all. It is the same
	// primitive the intentional teardown uses (#5486).
	_ = m.disableCtrlBeforeTeardownLocked()

	// Drain any sender that was already in flight before the crash before
	// reset/restart can publish a replacement process. Senders queued after the
	// epoch bump take the lock but fail their final epoch check before dialing.
	m.sessionMu.Lock()
	m.sessionMu.Unlock()

	// The child is reaped; drop the handle so every `m.proc == nil` liveness
	// test in the package — takeoverReadyLocked's first gate among them — reads
	// the truth.
	m.proc = nil
	m.resetAfterHelperGoneLocked()

	exitCode, signal := g.exitCodeAndSignal()
	m.helperCrash = HelperCrashRecord{
		LastExitWasCrash: true,
		Detail:           detail,
		ExitCode:         exitCode,
		Signal:           signal,
		PID:              pid,
		At:               time.Now(),
		Restarts:         m.helperCrash.Restarts,
		// #7250: the generation this retry is fenced on, so
		// HelperCrashState() can tell an armed restart from an orphaned one.
		restartGen: g.gen,
	}
	m.scheduleHelperRestartLocked(g.gen)
}

// scheduleHelperRestartLocked arms the next restart attempt for the generation
// that just died, fenced on gen so a later intentional Stop cancels it by
// simply advancing procGen.
func (m *Manager) scheduleHelperRestartLocked(gen uint64) {
	m.helperCrash.Restarts++
	delay := helperRestartDelay(m.helperCrash.Restarts)
	m.helperCrash.NextRestart = time.Now().Add(delay)
	slog.Warn("userspace dataplane helper restart scheduled",
		"attempt", m.helperCrash.Restarts, "delay", delay)
	m.scheduleRestartTimer(delay, func() { m.restartHelperAfterCrash(gen) })
}

// restartHelperAfterCrash re-runs the ORDINARY bring-up for the current desired
// config.
//
// It deliberately calls ensureProcessLocked rather than re-executing the dead
// generation's argv: bring-up is where the binding / XSK-liveness / capability /
// event-stream readiness gates live, and a restart that skipped them would
// re-arm forwarding on a helper that had not proved any of them. m.cfg is the
// CURRENT desired config, so a config replacement that landed while the helper
// was down is what gets started, not the stale generation's.
func (m *Manager) restartHelperAfterCrash(gen uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Fences: a newer generation exists (someone already restarted or Stop ran
	// and respawned), or a helper is running again, or the crash was cleared.
	if m.procGen != gen || m.proc != nil || !m.helperCrash.LastExitWasCrash {
		return
	}
	// #7967: record the ATTEMPT, before its outcome is known. On failure the
	// record survives and carries it; on success the whole record is cleared,
	// which is the episode-scoped contract every field here shares.
	m.helperCrash.LastRestartAttempt = time.Now()
	if err := m.ensureProcessLocked(m.cfg); err != nil {
		slog.Error("userspace dataplane helper restart failed; will retry",
			"attempt", m.helperCrash.Restarts, "err", err)
		// ensureProcessLocked may have advanced procGen on a spawn that then
		// failed readiness; re-fence the retry on whatever is current so the
		// timer chain cannot fork.
		m.scheduleHelperRestartLocked(m.procGen)
		return
	}
	slog.Info("userspace dataplane helper restarted after unexpected exit",
		"attempts", m.helperCrash.Restarts)
	// #8397: this is the ONE moment an episode is known to have ended in
	// recovery, and the next line destroys the only record of it. Append
	// before the wipe, not after.
	m.recordRecoveredCrashEpisodeLocked(time.Now())
	m.helperCrash = HelperCrashRecord{}
	// The crash tore the 1 Hz reconcile loop down with the generation it was
	// polling; the replacement needs its own.
	m.ensureStatusLoopLocked()
}

// HelperCrashState returns the last unexpected-exit record, for status
// rendering and tests. The zero value means no crash is on record.
func (m *Manager) HelperCrashState() HelperCrashRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.helperCrash
	// #7250: DERIVE RestartPending here rather than storing it. An armed retry
	// is fenced on the generation that died; an intentional stop advances
	// procGen and orphans the timer WITHOUT clearing the crash record, so a
	// stored flag would report a restart that will never fire. The fence is the
	// same one restartHelperAfterCrash applies, read at the moment the caller
	// asks.
	rec.RestartPending = rec.LastExitWasCrash &&
		m.proc == nil &&
		m.procGen == rec.restartGen
	return rec
}
