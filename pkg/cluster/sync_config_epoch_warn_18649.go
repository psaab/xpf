package cluster

import (
	"log/slog"
	"time"
)

const staleConfigRefusalWarnInterval = time.Minute

const staleConfigRefusalWarnMessage = "cluster sync: stale-config session install refusals are growing while local config is current (#18649)"

// staleConfigRefusalWarnLimiter admits one warning for a new refusal-counter
// increase while ConfigStale is false, then suppresses further increases for
// one minute. This is counter-growth detection, not a rate derivative: a
// sustained stream continues to warn once per minute. One limiter is shared
// across both address families and epoch branches. Its state is protected by
// applyMu, which serializes both install families.
type staleConfigRefusalWarnLimiter struct {
	lastObserved  uint64
	lastWarnNanos int64
	started       bool
	suppressed    uint64
}

// admit is called only from install refusal paths while applyMu is held. It
// records the latest counter even when config is stale, so stale-period growth
// cannot trigger a later warning after the config catches up.
func (l *staleConfigRefusalWarnLimiter) admit(refusals uint64, configStale bool, now int64) (emit bool, suppressed uint64) {
	if refusals <= l.lastObserved {
		return false, 0
	}
	growth := refusals - l.lastObserved
	l.lastObserved = refusals
	if configStale {
		return false, 0
	}
	if l.started && now-l.lastWarnNanos < int64(staleConfigRefusalWarnInterval) {
		l.suppressed += growth
		return false, 0
	}
	l.started = true
	l.lastWarnNanos = now
	suppressed, l.suppressed = l.suppressed, 0
	return true, suppressed
}

type staleConfigRefusalWarnRecord struct {
	refusals      uint64
	epoch         uint64
	threshold     uint64
	thresholdKind string
	branch        string
	rg0Authority  bool
	suppressed    uint64
}

// emit runs after installClusterSyncedV4/V6 release applyMu. Keeping slog
// outside the receive-apply critical section avoids letting an operator log
// sink extend serialization of session installs.
func (w staleConfigRefusalWarnRecord) emit() {
	slog.Warn(staleConfigRefusalWarnMessage,
		"sessions_stale_config_ignored", w.refusals,
		"session_config_epoch", w.epoch&configEpochGenMask,
		"session_config_epoch_tagged", w.epoch&configEpochReverseTag != 0,
		"threshold", w.threshold,
		"threshold_kind", w.thresholdKind,
		"branch", w.branch,
		"rg0_authority", w.rg0Authority,
		"suppressed_since_last", w.suppressed)
}

// configStaleNow is the lock-free ConfigStale projection used at the refusal
// hot path. It mirrors TransferReadinessSnapshot.ConfigStale without taking
// TransferReadiness's unrelated bulk-ack/receive locks.
func (s *SessionSync) configStaleNow() bool {
	return (TransferReadinessSnapshot{
		PeerConfigGen:                s.lastRecvConfigGen.Load(),
		AppliedConfigGen:             s.lastAppliedConfigGen.Load(),
		RejectedAsAuthorityConfigGen: s.rejectedAsAuthorityConfigGen.Load(),
		LocalConfigAuthority:         s.localConfigAuthority(),
	}).ConfigStale()
}

// prepareStaleConfigRefusalWarning records a counter increase while holding
// applyMu and returns warning data for emission after that lock is released.
func (s *SessionSync) prepareStaleConfigRefusalWarning(epoch, threshold uint64, thresholdKind, branch string, rg0Authority bool, refusals uint64) (staleConfigRefusalWarnRecord, bool) {
	emit, suppressed := s.staleConfigRefusalWarn.admit(refusals, s.configStaleNow(), s.nowMono())
	if !emit {
		return staleConfigRefusalWarnRecord{}, false
	}
	return staleConfigRefusalWarnRecord{
		refusals:      refusals,
		epoch:         epoch,
		threshold:     threshold,
		thresholdKind: thresholdKind,
		branch:        branch,
		rg0Authority:  rg0Authority,
		suppressed:    suppressed,
	}, true
}
