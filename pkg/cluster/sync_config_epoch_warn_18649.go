package cluster

import (
	"log/slog"
	"time"
)

// staleConfigRefusalWarnNowNanos is the test clock for the #18649 refusal
// warning limiter. Production leaves it bound to the monotonic clock.
var staleConfigRefusalWarnNowNanos = MonotonicNanos

const staleConfigRefusalWarnInterval = time.Minute

const staleConfigRefusalWarnMessage = "cluster sync: stale-config session install refusals are growing while local config is current (#18649)"

// staleConfigRefusalWarnLimiter admits a warning only for a new rise in the
// refusal counter while ConfigStale is false, and no more than once per minute.
// One limiter is shared by both address families and both epoch branches so a
// paired v4/v6 stream cannot double the operator-facing rate. Its state is
// protected by applyMu, which serializes both install families.
type staleConfigRefusalWarnLimiter struct {
	lastObserved  uint64
	lastWarnNanos int64
	started       bool
	suppressed    uint64
}

// admit is called only from the install refusal paths while applyMu is held.
// It records the latest counter value, including while config is stale so an
// old stale-period rise cannot trigger a later warning. It returns whether to
// emit and the number of current-config refusals suppressed since the previous
// warning.
func (l *staleConfigRefusalWarnLimiter) admit(refusals uint64, configStale bool) (emit bool, suppressed uint64) {
	if refusals <= l.lastObserved {
		return false, 0
	}
	growth := refusals - l.lastObserved
	l.lastObserved = refusals
	if configStale {
		return false, 0
	}
	now := staleConfigRefusalWarnNowNanos()
	if l.started && now-l.lastWarnNanos < int64(staleConfigRefusalWarnInterval) {
		l.suppressed += growth
		return false, 0
	}
	l.started = true
	l.lastWarnNanos = now
	suppressed, l.suppressed = l.suppressed, 0
	return true, suppressed
}

// configStaleNow is the lock-free ConfigStale projection used at the refusal
// hot path. It mirrors TransferReadinessSnapshot.ConfigStale without taking
// TransferReadiness's unrelated bulk-ack/receive locks.
func (s *SessionSync) configStaleNow() bool {
	return (TransferReadinessSnapshot{
		PeerConfigGen:               s.lastRecvConfigGen.Load(),
		AppliedConfigGen:            s.lastAppliedConfigGen.Load(),
		RejectedAsAuthorityConfigGen: s.rejectedAsAuthorityConfigGen.Load(),
		LocalConfigAuthority:         s.localConfigAuthority(),
	}).ConfigStale()
}

// maybeWarnStaleConfigRefusal reports a growing refusal counter only when the
// readiness snapshot's config-stale predicate is false. The count advances
// unconditionally at the refusal sites; this warning is diagnostic only.
func (s *SessionSync) maybeWarnStaleConfigRefusal(epoch, threshold uint64, thresholdKind, branch string, rg0Authority bool, refusals uint64) {
	emit, suppressed := s.staleConfigRefusalWarn.admit(refusals, s.configStaleNow())
	if !emit {
		return
	}
	slog.Warn(staleConfigRefusalWarnMessage,
		"sessions_stale_config_ignored", refusals,
		"session_config_epoch", epoch&configEpochGenMask,
		"session_config_epoch_tagged", epoch&configEpochReverseTag != 0,
		"threshold", threshold,
		"threshold_kind", thresholdKind,
		"branch", branch,
		"rg0_authority", rg0Authority,
		"suppressed_since_last", suppressed)
}
