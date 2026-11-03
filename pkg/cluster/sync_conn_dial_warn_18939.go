package cluster

import "time"

// fabricDialWarnNowNanos is the injectable clock for the fabric dial-failure
// warning limiter. Same seam idiom as heartbeatRejectWarnNowNanos
// (heartbeat_reject_warn.go), and for the same reason: the interval is the
// thing under test, so a test must be able to step across it without
// sleeping. Production never replaces it.
var fabricDialWarnNowNanos = MonotonicNanos

// fabricDialWarnInterval bounds how often an UNCHANGED fabric dial failure
// reaches the log. It matches heartbeatRejectWarnInterval so the two lines
// that describe the same "peer is unreachable" condition cannot disagree
// about their rate.
const fabricDialWarnInterval = 30 * time.Second

// fabricDialFailMsg18939 is the dial-failure warning's message, shared by
// the wiring in sync_conn.go and the cells that count its emissions.
const fabricDialFailMsg18939 = "cluster sync: dial to peer failed"

// fabricDialWarnLimiter rate-limits fabricConnectLoop's dial-failure warning
// (#18939): the first failure logs, repeats of an UNCHANGED error are
// suppressed (and counted, reported with the next emission so the bound does
// not conceal the volume), a CHANGED error logs at once, and an ongoing
// unchanged failure re-logs once per fabricDialWarnInterval. Before #18939
// the loop swallowed dial errors entirely, so a peer that could never be
// dialed retried invisibly every second — exactly what hid the #18038
// testguard lo-down rot behind a "never connected" deadline in #18933.
//
// Unlike heartbeatRejectWarnLimiter it carries no mutex: a limiter is
// loop-local state owned by exactly ONE fabricConnectLoop goroutine (one per
// fabric, started once per session incarnation in Start), so goroutine
// confinement — not a lock — is the invariant. A fresh loop is a fresh
// incarnation, and its first dial failure is news again by design.
type fabricDialWarnLimiter struct {
	lastErr    string
	started    bool
	lastNanos  int64
	suppressed uint64
}

// admit reports whether the dial-failure warning should be emitted for err
// and, when it should, how many failures were suppressed since the previous
// emission. A changed error always emits: an error whose TEXT changes every
// second describes a genuinely changing network, which is itself the signal
// an operator needs, and its volume is still bounded by the loop's one
// attempt per second.
func (l *fabricDialWarnLimiter) admit(err string) (emit bool, suppressed uint64) {
	now := fabricDialWarnNowNanos()
	if l.started && err == l.lastErr && now-l.lastNanos < int64(fabricDialWarnInterval) {
		l.suppressed++
		return false, 0
	}
	suppressed, l.suppressed = l.suppressed, 0
	l.started = true
	l.lastNanos = now
	l.lastErr = err
	return true, suppressed
}
