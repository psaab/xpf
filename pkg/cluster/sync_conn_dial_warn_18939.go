package cluster

import "time"

// fabricDialWarnNowNanos is the injectable clock for the fabric dial-failure
// warning limiter. Same seam idiom as heartbeatRejectWarnNowNanos
// (heartbeat_reject_warn.go), and for the same reason: the interval is the
// thing under test, so a test must be able to step across it without
// sleeping. Production never replaces it.
var fabricDialWarnNowNanos = MonotonicNanos

// fabricDialWarnInterval bounds how often a fabric dial failure reaches the
// log — across error-text CHANGES too. It matches heartbeatRejectWarnInterval
// so the two lines that describe the same "peer is unreachable" condition
// cannot disagree about their rate.
const fabricDialWarnInterval = 30 * time.Second

// fabricDialFailMsg18939 is the dial-failure warning's message, shared by
// the wiring in sync_conn.go and the cells that count its emissions.
const fabricDialFailMsg18939 = "cluster sync: dial to peer failed"

// fabricDialWarnLimiter rate-limits fabricConnectLoop's dial-failure warning
// (#18939): the first failure logs; every failure inside the following
// fabricDialWarnInterval is suppressed and counted, whatever its text; at or
// after the interval the CURRENT error logs together with how many failures
// were suppressed since the previous emission, so the bound never conceals
// the volume and error-change visibility survives at interval granularity
// (the emission names the error it currently sees). Before #18939 the loop
// swallowed dial errors entirely, so a peer that could never be dialed
// retried invisibly every second — exactly what hid the #18038 testguard
// lo-down rot behind a "never connected" deadline in #18933.
//
// The fold for PR #18950 removed an earlier "a CHANGED error always emits"
// arm: with the loop dialing once per second, an error oscillating A-B-A
// (two overlapping failures, a DNS flap, a VRF rebinding) changed its TEXT
// on every attempt and therefore emitted on every attempt — unbounded, the
// exact flood #18939 set out to bound. The interval now binds the VOLUME;
// the CURRENT-error attribute keeps the diagnosis.
//
// Unlike heartbeatRejectWarnLimiter it carries no mutex: a limiter is
// loop-local state owned by exactly ONE fabricConnectLoop goroutine (one per
// fabric, started once per session incarnation in Start), so goroutine
// confinement — not a lock — is the invariant. A fresh loop is a fresh
// incarnation, and its first dial failure is news again by design.
type fabricDialWarnLimiter struct {
	started    bool
	lastNanos  int64
	suppressed uint64
}

// admit reports whether the dial-failure warning should be emitted and, when
// it should, how many failures were suppressed since the previous emission.
// It takes no error text by design: the rate is a pure function of TIME, and
// the emitted LINE names the error the caller currently sees (the wiring
// passes the live err as the log attribute), so change visibility survives
// at interval granularity without letting text oscillation unbind the rate.
func (l *fabricDialWarnLimiter) admit() (emit bool, suppressed uint64) {
	now := fabricDialWarnNowNanos()
	if l.started && now-l.lastNanos < int64(fabricDialWarnInterval) {
		l.suppressed++
		return false, 0
	}
	suppressed, l.suppressed = l.suppressed, 0
	l.started = true
	l.lastNanos = now
	return true, suppressed
}
