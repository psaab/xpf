package userspace

import (
	"errors"
	"log/slog"
	"sync/atomic"
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
// observes the condition directly: control requests that got no answer at all
// (since #18685, any verb, measured in TIME rather than as a count of status
// polls). An in-band refusal is an answer, so it clears the silence just as a
// success does. That reset is what spares a helper under RECOVERING pressure,
// because any request that gets through starts the silence over.
//
// #18293: an answered-but-undecodable status is also an answer. The helper
// wrote bytes and Go failed to decode them (wire drift, a partial status, or
// our own response cap). That proves the accept loop is alive, so it must NOT
// advance the silence — otherwise a healthy, answering helper is SIGKILLed
// for a Go/Rust wire mismatch. It surfaces instead as a decode error: the
// statusLoop Warn names it, and StatusPollDecodeErrors (exported as
// xpf_status_poll_decode_errors_total) counts it for alerting. Unlike a
// successful decode or an in-band refusal, it does NOT reset an in-progress
// silence either: it is neither silence nor a usable answer, so the prior
// genuine-silence streak stays exactly as it was.
//
// When the helper has answered nothing for helperWedgeMinSpan, it is killed,
// and the supervisor's unexpected-exit path does the rest: disarm the
// shim, record the crash, restart with backoff. Nothing here restarts anything
// itself. The kill is deferred briefly after an RG activation, so a failover's
// own control-socket load cannot turn into a restart in the middle of it.

// statusPollDecodeErrors counts status polls the helper ANSWERED but Go
// could not decode (#18293), process-lifetime. Per-manager counts live on
// helperLiveness.decodeErrors; this atomic is the Prometheus source, in the
// BindingWedgeGiveups shape.
var statusPollDecodeErrors atomic.Uint64

// StatusPollDecodeErrors reports answered-but-undecodable status polls.
func StatusPollDecodeErrors() uint64 { return statusPollDecodeErrors.Load() }

// #18685 replaced the poll COUNT with time. The 30-poll rule assumed one poll a
// second, but a wedged helper makes every queued control caller burn its
// deadline first, so polls arrived about every 90 s and 30 of them took ~45
// minutes (loss, #18658: 26 failures in 37 minutes, no kill). The evidence and
// the decision now live in helper_liveness_18685.go: silence is measured across
// every control round trip, and a per-generation watchdog kills without m.mu.
// The status loop keeps the #18293 decode accounting below and still asks the
// same tracker, as a second path to the same kill.
const (
	// helperWedgeMinSpan is how long the helper must answer nothing (at least
	// helperWedgeMinSilentTrips silent round trips) before it is killed.
	helperWedgeMinSpan = 30 * time.Second
	// helperWedgeRGGrace defers the kill after an update_ha_state.
	helperWedgeRGGrace = 10 * time.Second
)

// helperLiveness keeps the #18293 decode-error count. Guarded by m.mu.
type helperLiveness struct {
	// decodeErrors counts answered-but-undecodable status polls (#18293).
	// The process-lifetime Prometheus counter is statusPollDecodeErrors
	// (this file).
	decodeErrors uint64
}

// noteStatusPollResultLocked records one status poll's #18293 accounting and
// reports whether the helper should now be killed as wedged.
//
// The poll's own round trip has already been recorded by
// requestDetailedAtSocket (#18685), so this does NOT count silence itself: an
// answered-but-undecodable poll (#18293) is counted as a decode error and never
// asks for a kill; anything else defers to the time-based tracker.
func (m *Manager) noteStatusPollResultLocked(err error, now time.Time) bool {
	if err == nil || errors.Is(err, errHelperRejected) {
		return false
	}
	if errors.Is(err, errStatusDecode) {
		m.liveness.decodeErrors++
		statusPollDecodeErrors.Add(1)
		return false
	}
	due, _ := m.liveTrack.killDue(now)
	return due && m.wedgeKilledGen.Load() != m.procGen+1
}

// killWedgedHelperLocked kills the helper process and leaves recovery to the
// supervisor (#5838), which reaps it as an unexpected exit. It is the status
// loop's path to the same kill the #18685 watchdog makes; whichever runs first
// marks the generation, and the other then does nothing.
func (m *Manager) killWedgedHelperLocked(now time.Time) {
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	if m.wedgeKilledGen.Swap(m.procGen+1) == m.procGen+1 {
		return
	}
	_, span := m.liveTrack.killDue(now)
	slog.Error("userspace dataplane helper answered no control request; killing it so the supervisor fails closed and restarts it (#18685)",
		"unanswered_for", span.Round(time.Second).String(),
		"pid", m.proc.Process.Pid, "generation", m.procGen)
	m.liveTrack.kills.Add(1)
	_ = m.proc.Process.Kill()
}
