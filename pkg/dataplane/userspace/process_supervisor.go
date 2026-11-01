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
// This is not a packet-policy fallback. The XDP shim stays attached and is
// owned by xpfd, not the helper, and it drops transit through THREE independent
// degraded-path gates, verified in userspace-xdp/src/lib.rs:
//
//   - a missing or not-ready binding row -> drop_degraded_transit;
//   - a missing or STALE heartbeat -> drop_degraded_transit
//     (USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS = 5000, and the dead helper stops
//     writing USERSPACE_HEARTBEAT immediately);
//   - a failed XSK redirect -> drop_degraded_transit.
//
// All three PASS proven local/control traffic (pass_local_control), keeping
// management available while dropping transit. The daemon observes supervisor
// death, closes the host transit gate immediately, and applies full election
// debt only when the restart backoff reaches its crash-loop cap. A fast
// recovery reopens the gate without flapping ownership.
//
// The supervisor also keeps TakeoverReady honest: an unexpected exit clears
// m.proc and stale status before the peer can hand this node an RG. Before
// #5838, those stale fields let a crashed node advertise itself as a valid
// failover target, blackholing every flow handed to it.

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
	// LastExitWasCrash records that an unexpected exit remains in the open
	// crash episode. A supervisor retry landing does not clear the record:
	// the process can still crash before the quiet window ends. Ordinary
	// generation-advancing Compile recovery closes the episode.
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
	// Restarts counts consecutive restart ATTEMPTS in this crash episode.
	// A quiet interval longer than two maximum backoffs or a successful
	// generation-advancing Compile ends the episode and resets the count.
	Restarts int
	// NextRestart is when the armed retry is due. Only meaningful when
	// RestartPending is true — after an intentional stop this is a time in the
	// PAST with no timer behind it (#7250).
	NextRestart time.Time

	// LastRestartAttempt is when a restart was last ATTEMPTED — the moment
	// `restartHelperAfterCrash` called into `ensureProcessLocked`, whatever the
	// outcome. Zero when none has been attempted in this episode.
	//
	// This field is episode-scoped and cleared when ordinary Compile recovery
	// ends that episode. A landed supervisor retry retains it alongside the
	// last-exit record until the quiet window expires, so status can report the
	// live recovery and the episode can still be journaled accurately.
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
	// RecoveredSinceCrash reports that a supervisor retry LANDED while the
	// episode debt is still on the books. The render distinguishes this
	// running helper from a stopped process with a crash record. Cleared when
	// the episode ends or when an intentional stop makes the helper non-live.
	RecoveredSinceCrash bool
	// RecoveredAt records when the retry first proved ready in this open
	// episode; quiet-window closure may journal it later.
	RecoveredAt time.Time
	// restartGen is the process generation the pending retry was armed for.
	// Unexported: it is an internal fence, not something a renderer should see
	// or construct.
	restartGen uint64
}

// CrashLooping reports whether the helper should be treated as not coming back.
//
// #7250 asked for "a predicate an operator or a health surface can read", and
// noted it needs deciding rather than plumbing. The decision: crash-looping is
// BACKOFF AT THE CAP within one open crash episode, not a lifetime count.
//
// Restarts advances for consecutive failed retry attempts. A quiet interval
// longer than twice the maximum backoff resets that count, so isolated crashes
// do not accumulate into a false loop. The first retry is immediate; after it
// the backoff doubles from helperRestartBackoffBase and saturates at
// helperRestartBackoffMax (#18707); reaching the cap means the supervisor
// exhausted its escalation and is retrying at its slowest rate.
//
// Derived, never stored, for the same reason RestartPending is: a stored
// judgement about the present is the thing that goes stale.
func (r HelperCrashRecord) CrashLooping() bool {
	return r.LastExitWasCrash && helperRestartDelay(r.Restarts) >= helperRestartBackoffMax
}

// Helper restart backoff. The FIRST unexpected exit of a crash episode is
// retried immediately; every further exit in the same episode backs off
// exponentially from base to max, so a helper that cannot start (a corrupt
// binary, a NIC that will not bind) retries forever at a fixed low rate
// instead of fork-storming.
//
// #18707: the first retry used to wait helperRestartBackoffBase (1s) too.
// That second bought nothing an isolated crash needs: the dead child is
// already reaped when the supervisor schedules the retry, the shim was
// disarmed fail-closed before it, and bring-up's own readiness gates (ready
// ping, event stream, binding / XSK liveness) still run before forwarding is
// re-armed. It was pure outage on the node that crashed. An immediate first
// retry adds exactly ONE fast attempt to an episode: the schedule becomes
// 0, base, 2*base, ... instead of base, 2*base, ..., so a helper that dies
// on every start still reaches the cap after the same cumulative wait
// (0+1+2+4+8+16+32 = 63s, the same as 1+2+4+8+16+32 before) and the
// CrashLooping verdict is not reached any sooner in wall-clock terms — it
// just takes one more attempt to get there (helperCrashLoopAttempt).
//
// They are vars rather than consts purely so a test can drive many real
// restarts without spending wall-clock seconds; production never reassigns
// them. Same seam idiom as statusLoopInterval in process_status.go.
var (
	helperRestartBackoffBase = time.Second
	helperRestartBackoffMax  = 60 * time.Second
)

// helperCrashLoopAttempt is the first restart count whose backoff reaches the cap.
func helperCrashLoopAttempt() int {
	for attempt := 1; ; attempt++ {
		if helperRestartDelay(attempt) >= helperRestartBackoffMax {
			return attempt
		}
	}
}

// helperRestartDelay is the backoff for attempt n (1-based): zero for the
// first attempt of an episode (#18707), then helperRestartBackoffBase doubling
// per attempt up to helperRestartBackoffMax.
func helperRestartDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return 0
	}
	d := helperRestartBackoffBase
	for i := 2; i < attempt; i++ {
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
	m.bindOwedInventoryDebtLocked()
	// Keep the helper-session epoch ahead of any sender while this new process
	// is still being published. The subsequent snapshot publication records
	// the same live generation together with its capability and inventory.
	m.haWatchdogProcessGen.Add(1)
	g := &helperGeneration{gen: m.procGen, cmd: cmd, exited: make(chan struct{})}
	m.procSup = g
	go m.superviseHelper(g)
}

// bindOwedInventoryDebtLocked binds reset-marked inventory debt to the
// currently allocated generation. Called with m.mu held, by
// startHelperSupervisorLocked after the procGen bump (and directly by tests
// that must not start a supervisor goroutine).
func (m *Manager) bindOwedInventoryDebtLocked() {
	// Bind owed inventory debt to the ALLOCATED generation (Opus F1): the
	// reset marked it owed without knowing this number.
	if m.sessionInventoryDebtOwed {
		m.sessionInventoryDebtGen = m.procGen
		m.sessionInventoryDebtOwed = false
		m.sessionInventoryRequestAt = time.Time{}
	}
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
	// A planned stop retires its generation under m.mu before sending helper
	// shutdown requests or signals. Only exits from the still-current
	// generation are unexpected and enter crash accounting.
	if m.procSup != g || m.procGen != g.gen {
		return
	}
	m.handleUnexpectedHelperExitLocked(g)
}

// resetQuietHelperCrashEpisodeLocked closes an episode after the quiet window.
// The status loop calls it while a recovered helper is still running; the
// next unexpected exit also calls it before starting a new episode. Thus a
// healthy recovery is journaled on the existing periodic health tick without
// a separate expiry timer.
//
// Caller must hold m.mu.
func (m *Manager) resetQuietHelperCrashEpisodeLocked(now time.Time) bool {
	if m.helperCrashLastAt.IsZero() ||
		now.Sub(m.helperCrashLastAt) <= 2*helperRestartBackoffMax {
		return false
	}
	if m.helperCrash.LastExitWasCrash && m.helperCrash.RecoveredSinceCrash {
		m.recordRecoveredCrashEpisodeLocked(now)
	}
	m.helperCrash = HelperCrashRecord{}
	m.helperCrashLastAt = time.Time{}
	return true
}

// handleUnexpectedHelperExitLocked fails the node closed after a crash and
// schedules a bounded restart.
//
// Order matters. The shim is disarmed FIRST, before any bookkeeping that could
// fail, because that is the step that stops the XDP program redirecting into a
// dead XSK; every later step is about not lying to an operator or to the
// cluster peer.
func (m *Manager) handleUnexpectedHelperExitLocked(g *helperGeneration) {
	now := time.Now()
	// The Prometheus counter is per unexpected exit, not per completed
	// episode; otherwise a persistent loop inside the quiet window is silent.
	m.helperCrashUnexpectedExitsTotal++
	// A later observation closes the old episode before this exit begins a
	// fresh one; quiet recovery may also have closed it on the status tick.
	m.resetQuietHelperCrashEpisodeLocked(now)
	m.helperCrash.RecoveredSinceCrash = false
	m.helperCrash.RecoveredAt = time.Time{}
	m.helperCrashLastAt = now
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
	m.procSup = nil
	m.resetAfterHelperGoneLocked()

	exitCode, signal := g.exitCodeAndSignal()
	m.helperCrash = HelperCrashRecord{
		LastExitWasCrash:   true,
		Detail:             detail,
		ExitCode:           exitCode,
		Signal:             signal,
		PID:                pid,
		At:                 now,
		Restarts:           m.helperCrash.Restarts,
		LastRestartAttempt: m.helperCrash.LastRestartAttempt,
		// #7250: the generation this retry is fenced on, so
		// HelperCrashState() can tell an armed restart from an orphaned one.
		restartGen: g.gen,
	}
	m.scheduleHelperRestartLocked(g.gen)
	m.notifyHelperSupervisorLocked()
}

// scheduleHelperRestartLocked arms the next restart attempt for the generation
// that just died, fenced on gen so a later intentional Stop cancels it by
// simply advancing procGen.
func (m *Manager) scheduleHelperRestartLocked(gen uint64) {
	m.helperCrash.Restarts++
	// Keep the state predicate fenced to the retry just armed. A failed
	// readiness attempt can retire its spawned generation before we get here.
	m.helperCrash.restartGen = gen
	delay := helperRestartDelay(m.helperCrash.Restarts)
	m.helperCrash.NextRestart = time.Now().Add(delay)
	slog.Warn("userspace dataplane helper restart scheduled",
		"attempt", m.helperCrash.Restarts, "delay", delay)
	m.scheduleRestartTimer(delay, func() { m.restartHelperAfterCrash(gen) })
}

// rearmHelperRestartLocked preserves an already-counted crash attempt while
// fencing its replacement timer on the current process generation. It is used
// when Compile bring-up retires the generation carrying an armed retry.
func (m *Manager) rearmHelperRestartLocked() {
	if !m.helperCrash.LastExitWasCrash || m.proc != nil {
		return
	}
	gen := m.procGen
	m.helperCrash.restartGen = gen
	delay := helperRestartDelay(m.helperCrash.Restarts)
	m.helperCrash.NextRestart = time.Now().Add(delay)
	slog.Warn("userspace dataplane helper crash retry re-armed after bring-up failure",
		"attempt", m.helperCrash.Restarts, "delay", delay, "generation", gen)
	m.scheduleRestartTimer(delay, func() { m.restartHelperAfterCrash(gen) })
	m.notifyHelperSupervisorLocked()
}

// completeHelperCrashRecoveryLocked ends the current episode after ordinary
// Compile bring-up proves a helper ready. Supervisor retries preserve the
// crash window and perform their own episode accounting instead.
func (m *Manager) completeHelperCrashRecoveryLocked(at time.Time) {
	if m.helperCrash.LastExitWasCrash {
		m.recordRecoveredCrashEpisodeLocked(at)
		m.helperCrash = HelperCrashRecord{}
	}
	m.helperCrashLastAt = time.Time{}
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
	// #7967: record the ATTEMPT, before its outcome is known.
	m.helperCrash.LastRestartAttempt = time.Now()
	attempts := m.helperCrash.Restarts
	m.restartAttemptInProgress = true
	err := m.ensureProcessLocked(m.cfg)
	m.restartAttemptInProgress = false
	if err != nil {
		slog.Error("userspace dataplane helper restart failed; will retry",
			"attempt", attempts, "err", err)
		// ensureProcessLocked re-arms the consumed retry on the generation
		// left after a failed readiness attempt.
		return
	}
	slog.Info("userspace dataplane helper restarted after unexpected exit",
		"attempts", attempts)
	// A landed retry proves READY, not STABLE — preserve its attempt count
	// until the quiet window expires or an ordinary Compile advances the
	// generation. The current helper is live, so the status surface must not
	// describe it as stopped. Episode history is appended only when recovery
	// actually ends the episode.
	m.helperCrash.RecoveredSinceCrash = true
	m.helperCrash.RecoveredAt = time.Now()
	m.notifyHelperSupervisorLocked()
	// The crash tore the 1 Hz reconcile loop down with the generation it was
	// polling; the replacement needs its own, and its first pass — the one
	// that republishes the snapshot the workers bind from — runs now rather
	// than a tick from now (#18707).
	m.ensureStatusLoopFirstPassNowLocked()
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

// HelperSupervisorState reports whether a helper process is currently
// supervised and whether an armed retry for its unexpected-exit episode has
// reached the restart-backoff cap. An intentional stop or cancelled retry is
// not a crash loop even though the crash record remains available for status.
func (m *Manager) HelperSupervisorState() (running, crashLooping bool) {
	if m == nil {
		return false, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	running = m.proc != nil && m.proc.Process != nil
	if running {
		return running, false
	}
	// Only the retry count arm contributes to the HA verdict. It is fenced
	// to the generation whose retry is armed, so an intentional stop cannot
	// turn a stale crash record into current election debt.
	crashLooping = m.procGen == m.helperCrash.restartGen && m.helperCrash.CrashLooping()
	return running, crashLooping
}

// SetHelperSupervisorObserver installs a wake-only state-change observer.
// The callback runs under m.mu and must not call back into Manager.
func (m *Manager) SetHelperSupervisorObserver(fn func()) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.helperSupervisorObserver = fn
}

func (m *Manager) notifyHelperSupervisorLocked() {
	if m.helperSupervisorObserver != nil {
		m.helperSupervisorObserver()
	}
}
