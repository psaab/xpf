package userspace

import (
	"errors"
	"log/slog"
	"time"
)

// #9651: restart a helper that answers nothing, observed from the Go side.
//
// The helper's control-socket accept loop retries resource errors (#9172 V031),
// so transient fd or memory pressure no longer drops forwarding. The cost is
// that a genuine descriptor leak at RLIMIT_NOFILE leaves the helper alive and
// forwarding on its last state, with a control socket that accepts nothing, and
// no process exit for the supervisor to act on. Three helper-side recovery
// designs failed review, because an accept result cannot tell a leak from
// recovering pressure (#9651 lists them).
//
// The daemon already polls status every second, and the supervisor already
// owns fail-closed restart with backoff (#5838). So the signal is the one that
// observes the condition directly: consecutive status polls that got no answer
// at all. An in-band refusal is an answer, so it resets the count just as a
// success does. That reset is what spares a helper under RECOVERING pressure,
// because any poll that gets through starts the count over.
//
// When the count and a minimum wall-clock span are both reached, the helper is
// killed, and the supervisor's unexpected-exit path does the rest: disarm the
// shim, record the crash, restart with backoff. Nothing here restarts anything
// itself. The kill is deferred briefly after an RG activation, so a failover's
// own control-socket load cannot turn into a restart in the middle of it.
const (
	// helperWedgeFailedPolls is how many consecutive unanswered status polls
	// (1/s) make a helper wedged.
	helperWedgeFailedPolls = 30
	// helperWedgeMinSpan bounds how fast that count can be reached, so a burst
	// of immediate failures cannot restart a helper sooner than a timed-out
	// one would.
	helperWedgeMinSpan = 30 * time.Second
	// helperWedgeRGGrace defers the kill after an update_ha_state.
	helperWedgeRGGrace = 10 * time.Second
)

// helperLiveness counts consecutive unanswered status polls. Guarded by m.mu.
type helperLiveness struct {
	failures     int
	firstFailure time.Time
	kills        uint64
}

// noteStatusPollResultLocked records one status poll and reports whether the
// helper should now be killed as wedged. err is the poll's error: nil for an
// answer, a helper rejection for an in-band refusal (also an answer).
func (m *Manager) noteStatusPollResultLocked(err error, now time.Time) bool {
	if err == nil || errors.Is(err, errHelperRejected) {
		m.liveness.failures = 0
		m.liveness.firstFailure = time.Time{}
		return false
	}
	if m.liveness.failures == 0 {
		m.liveness.firstFailure = now
	}
	m.liveness.failures++
	if m.liveness.failures < helperWedgeFailedPolls || now.Sub(m.liveness.firstFailure) < helperWedgeMinSpan {
		return false
	}
	if !m.lastRGActivateTime.IsZero() && now.Sub(m.lastRGActivateTime) < helperWedgeRGGrace {
		return false
	}
	return true
}

// killWedgedHelperLocked kills the helper process and leaves recovery to the
// supervisor (#5838), which reaps it as an unexpected exit.
func (m *Manager) killWedgedHelperLocked(now time.Time) {
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	slog.Error("userspace dataplane helper answers no status poll; killing it so the supervisor fails closed and restarts it (#9651)",
		"consecutive_failed_polls", m.liveness.failures,
		"unanswered_for", now.Sub(m.liveness.firstFailure).Round(time.Second).String(),
		"pid", m.proc.Process.Pid)
	m.liveness.failures = 0
	m.liveness.firstFailure = time.Time{}
	m.liveness.kills++
	_ = m.proc.Process.Kill()
}
