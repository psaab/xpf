package userspace

import (
	"time"
)

// #18791: a bounded grace before the #18697 unexpected-exit election debt.
//
// Since #18697 an unexpected helper exit on the RG primary raised election
// debt at once, so the healthy peer took the data RGs. With the #18717
// zero-delay restart the crashed helper recovers locally FASTER than the move
// it triggers. Measured on udp (docs/log/18707.md, three crashes on the RG
// primary): the debt was held 0.09 s after the exit was observed, the move cost
// 1.8-2.9 s of loss (0 TCP resets), and a local-only recovery took 1.58-1.77 s
// after SIGKILL over 7 samples.
//
// So the exit raises debt only if the replacement is not ARMED within
// helperExitGrace of the exit. Inside the grace the node keeps the RGs at full
// weight. A replacement that arms inside it ends the episode with no debt and
// no move. One that has not armed by the end raises the debt then, which moves
// the RGs exactly as before.
//
// No grace (debt at once, the #18697 behaviour) when:
//   - another unexpected exit was observed within helperExitCrashLoopWindow,
//     or the previous exit's episode is still open (the replacement died
//     before arming): a crash loop must move promptly;
//   - the dying generation already carried a raised verdict (a wedge, or the
//     wedge kill itself): the RGs were already leaving.
//
// The wedge verdict (#18685) is unchanged: it is a separate, silence-based
// signal and raises debt at once, also during the grace.
//
// The cost is paid by a helper that is truly dead or slow to arm. Its traffic
// stays black-holed on this node for up to helperExitGrace longer than before,
// and the move then starts.

// helperExitGrace is how long an unexpectedly exited helper's replacement may
// take to report ForwardingArmed before the exit raises election debt. The
// measured local recovery (first forwarded ping) was 1.58-1.77 s after the
// SIGKILL, and the exit is observed about 0.47-0.51 s after it. The
// replacement is therefore armed within about 1.3 s of the point this grace
// is measured from. 2.5 s gives that about 1.9x headroom for a loaded host
// (the samples were taken at host loadavg 15-28). With 2 s, a restart slowed
// by load would move AND pay the grace, the worst of both.
//
// A var only so a cell can shrink it; production never changes it.
var helperExitGrace = 2500 * time.Millisecond

// helperExitCrashLoopWindow: an unexpected exit within this long of the
// previous one is a crash loop and gets no grace.
const helperExitCrashLoopWindow = 30 * time.Second

// helperExitGraceWakeSlack is added to the grace before the wake fires, so the
// re-evaluation it triggers sees the deadline as passed.
const helperExitGraceWakeSlack = 50 * time.Millisecond

// noteUnexpectedExitGraceLocked decides the grace for the exit observed at now
// and publishes it BEFORE helperDownUnexpected is raised, so a lock-free reader
// that sees the flag also sees this exit's deadline. Called with m.mu held, by
// handleUnexpectedHelperExitLocked.
func (m *Manager) noteUnexpectedExitGraceLocked(now time.Time) {
	prev := m.lastUnexpectedExitNs.Swap(now.UnixNano())
	waive, why := false, ""
	switch {
	case m.helperDownUnexpected.Load() || m.liveTrack.exitEpisodeOpen():
		waive, why = true, "the previous exit's replacement died before arming"
	case prev != 0 && now.Sub(time.Unix(0, prev)) < helperExitCrashLoopWindow:
		waive, why = true, "another unexpected exit within "+helperExitCrashLoopWindow.String()
	case m.liveTrack.suspectedNow():
		waive, why = true, "the helper was already judged wedged"
	}
	if waive {
		m.exitGraceDeadlineNs.Store(0)
		m.exitGraceWaiveReason.Store(&why)
		return
	}
	m.exitGraceDeadlineNs.Store(now.Add(helperExitGrace).UnixNano())
	m.exitGraceWaiveReason.Store(nil)
	// Wake the daemon's transit gate when the grace ends, so a replacement
	// that has not armed by then raises the debt at the deadline and not at
	// the next 1 s transit tick. The observer is the daemon's non-blocking,
	// Manager-free wake (SetHelperSupervisorObserver), so firing it from the
	// timer goroutine without m.mu is safe.
	if wake := m.helperSupervisorObserver; wake != nil {
		afterFunc := m.exitGraceAfterFunc
		if afterFunc == nil {
			afterFunc = func(d time.Duration, f func()) { time.AfterFunc(d, f) }
		}
		afterFunc(helperExitGrace+helperExitGraceWakeSlack, wake)
	}
}

// handOffExitVerdictLocked starts generation gen's liveness tracking and
// carries an unexpected exit's verdict into it, in the order load, reset, then
// clear (seat AE on #18717). The old form passed helperDownUnexpected.Swap
// (false) as an ARGUMENT, which cleared the flag before reset took the tracker
// lock. A lock-free reader in between saw the flag false AND the dead
// generation's healthy verdict, so HelperElectionNotReady read false for one
// sample. With the #18717 restart about 25 ms after the exit, that sample
// lands inside the daemon's reaction to the exit. In this order every reader
// sees the raised flag or the inherited tracker. #18791: the inherited verdict
// runs under the exit's grace deadline. Called with m.mu held.
func (m *Manager) handOffExitVerdictLocked(gen uint64, now time.Time) {
	inherit := m.helperDownUnexpected.Load()
	if hook := m.testAfterExitFlagRead; hook != nil {
		hook()
	}
	m.liveTrack.resetWithGrace(gen, now, inherit, m.exitGraceDeadline())
	m.helperDownUnexpected.Store(false)
}

// exitGraceOpen reports whether the current unexpected-exit episode is still
// inside its grace at now. Lock-free.
func (m *Manager) exitGraceOpen(now time.Time) bool {
	d := m.exitGraceDeadlineNs.Load()
	return d != 0 && now.UnixNano() < d
}

// exitGraceDeadline is the current episode's grace deadline, or zero for none.
func (m *Manager) exitGraceDeadline() time.Time {
	if d := m.exitGraceDeadlineNs.Load(); d != 0 {
		return time.Unix(0, d)
	}
	return time.Time{}
}

// HelperExitedUnexpectedly reports that the helper exited unexpectedly and its
// replacement has not started yet, so no helper is running to answer control
// requests. It holds inside the grace too, unlike HelperElectionNotReady: the
// daemon's VIP-first demotion keys on it, so a peer-requested transfer during
// the grace releases the VIPs first instead of blocking on the restarting
// helper (#18791). Never takes m.mu.
func (m *Manager) HelperExitedUnexpectedly() bool {
	if m == nil {
		return false
	}
	return m.helperDownUnexpected.Load()
}

// exitEpisodeOpen reports whether a generation started after an unexpected
// exit is still inside its grace without having armed. Its death is then part
// of the same episode, and a crash loop.
func (t *helperLivenessTracker) exitEpisodeOpen() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inherited && !t.suspected && !t.graceUntil.IsZero() && !t.armedSeen
}

// suspectedNow reports the raised verdict without re-evaluating it.
func (t *helperLivenessTracker) suspectedNow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.suspected
}

// evaluateExitGraceLocked advances a generation's unexpected-exit grace: an
// arm inside it ends the episode with no debt, and its expiry without an arm
// raises the debt (from then on the #18697 rule, "clear once armed and
// healthy", applies). Caller holds t.mu.
func (t *helperLivenessTracker) evaluateExitGraceLocked(now time.Time) {
	if !t.inherited || t.suspected || t.graceUntil.IsZero() {
		return
	}
	if t.armedSeen {
		t.pendingLogs = append(t.pendingLogs, trackerLog{
			msg:  "userspace: helper recovered locally within the restart grace after an unexpected exit; no failover (#18791)",
			args: []any{"generation", t.gen, "grace_left", t.graceUntil.Sub(now).Round(10 * time.Millisecond).String()}})
		t.inherited = false
		t.graceUntil = time.Time{}
		return
	}
	if now.Before(t.graceUntil) {
		return
	}
	t.suspected = true
	t.suspectedSince = now
	t.reason = "replacement helper not armed within the " + helperExitGrace.String() + " restart grace after an unexpected exit"
	t.graceUntil = time.Time{}
	t.pendingLogs = append(t.pendingLogs, trackerLog{warn: true,
		msg:  "userspace: helper not armed within the restart grace after an unexpected exit; raising election debt so a healthy peer takes the data RGs (#18791)",
		args: []any{"generation", t.gen, "grace", helperExitGrace.String()}})
}
