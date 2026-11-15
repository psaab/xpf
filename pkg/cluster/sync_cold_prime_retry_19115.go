package cluster

import (
	"errors"
	"log/slog"
	"time"
)

// #19115 (design v3, issue comment 6886177377): an owed cold-prime debt with
// no bulk in flight is re-driven inside the manual-failover admission window,
// at a backed-off cadence that the maintenance sweep's own frequency cannot
// bypass.
//
// Before this, the sweep's owed re-drive was the only consumer of a debt left
// on a live connection, and it ran only on the sweep timer: 15 s active / 60 s
// idle under the userspace profile, backing off after a failed re-drive, and a
// wake RESET that timer, postponing it. A transient first-bulk failure (or a
// debt armed with no attempt at all: the peer-reboot edge, a capable
// discovery) therefore outlived every 5 s admission window that started
// inside it, and ISSU drains were refused.
//
// The model is state-derived, with one admission rule:
//
//   - ELIGIBILITY: the owed re-drive may START only when debt is owed, no ack
//     for it is young, the bulk is not fenced now, and the retry deadline has
//     passed (owedColdPrimeRetryEligible). The re-drive branch checks it, so a
//     sweep that ticks faster (negotiated liveness) cannot bypass the backoff.
//   - DEADLINE: advanced only by an authoritative bulk that ENDS in a non-fence
//     error while debt is owed (1 s, 2 s, then 4 s); reset by a new debt
//     generation, a discharge, or a bulk whose pending ack was published. It
//     never touches the #18752 owed age or last failure.
//   - SCHEDULING: the sweep timer is lowered to the debt's due time
//     (nextSweepDelay); a wake only ever moves the timer EARLIER.
//   - WAKES: every transition that makes debt retryable wakes the loop: an
//     arm, every bulk completion (success or failure), the lift of a capability
//     fence, and the runtime being wired. A young ack's 35 s expiry is part of
//     the due time, not an event.
//   - ADMISSION: the re-drive takes bulkSendMu and RECHECKS eligibility under
//     it before exporting. Every authoritative bulk serializes on that lock, so
//     a re-drive that waited behind another bulk sees its outcome (a published
//     pending ack, or an advanced deadline) and does not stack a second bulk.

const (
	// coldPrimeRetryBase is the first retry delay after a failed owed bulk,
	// and the floor of the sweep timer while a debt is due.
	coldPrimeRetryBase = time.Second
	// coldPrimeRetryMaxShift caps the backoff at coldPrimeRetryBase << 2 = 4 s,
	// so every 5 s admission window holds at least one retry.
	coldPrimeRetryMaxShift = 2
)

// coldPrimeRetryReset clears the retry schedule: the debt is eligible at once.
func (s *SessionSync) coldPrimeRetryReset() {
	s.coldPrimeRetryMu.Lock()
	s.coldPrimeRetryNotBefore = 0
	s.coldPrimeRetryFailures = 0
	s.coldPrimeRetryMu.Unlock()
}

// coldPrimeRetryNotBeforeNs is the earliest nowMono() an owed re-drive may
// start, or 0.
func (s *SessionSync) coldPrimeRetryNotBeforeNs() int64 {
	s.coldPrimeRetryMu.Lock()
	defer s.coldPrimeRetryMu.Unlock()
	return s.coldPrimeRetryNotBefore
}

// noteColdPrimeRetryResult applies a completed authoritative bulk to the retry
// schedule. A success resets it; a fence leaves it alone (the debt is not
// eligible while fenced, see bulkFenceNow); any other failure while debt is
// owed backs it off.
func (s *SessionSync) noteColdPrimeRetryResult(err error) {
	switch {
	case err == nil:
		s.coldPrimeRetryReset()
	case errors.Is(err, errBulkFencedForPeer) || errors.Is(err, errBulkFencedForIpsecPeer):
	case s.needColdPrime.Load():
		s.coldPrimeRetryMu.Lock()
		shift := s.coldPrimeRetryFailures
		if shift > coldPrimeRetryMaxShift {
			shift = coldPrimeRetryMaxShift
		}
		s.coldPrimeRetryFailures++
		s.coldPrimeRetryNotBefore = s.nowMono() + int64(coldPrimeRetryBase<<shift)
		s.coldPrimeRetryMu.Unlock()
	}
}

// bulkFenceNow reports the fence an authoritative bulk would hit now, with the
// same predicates bulkSyncWindow applies (sync_bulk.go): a latched install-table
// fence while the peer is not install-table capable, or a latched IPsec fence
// while the peer is not discriminator capable. nil when unfenced. It clears no
// latch: bulkSyncWindow's revalidate-on-consume stays the authority.
func (s *SessionSync) bulkFenceNow() error {
	st := s.peerIncarnationState()
	if st.bulkFencedForPeer.Load() && !s.InstallTableIdentityCapable() {
		return errBulkFencedForPeer
	}
	if st.bulkFencedForIpsecPeer.Load() && !(s.peerCapabilitiesLearned() && s.IpsecTunnelDiscriminatorCapable()) {
		return errBulkFencedForIpsecPeer
	}
	return nil
}

// owedColdPrimeRetryDue reports the nowMono() at which the owed re-drive may
// next start, and whether one is due at all: debt owed and not fenced. The due
// time is the later of the retry deadline and, while an ack for the current
// debt is young, that ack's BulkAckPendingRetryAfter expiry.
func (s *SessionSync) owedColdPrimeRetryDue() (int64, bool) {
	if !s.needColdPrime.Load() || s.bulkFenceNow() != nil {
		return 0, false
	}
	due := s.coldPrimeRetryNotBeforeNs()
	if s.coldPrimeAckAwaited() {
		if since := s.pendingBulkAckSince.Load(); since != 0 {
			due = max(due, since+int64(BulkAckPendingRetryAfter))
		}
	}
	return due, true
}

// owedColdPrimeRetryEligible reports whether the owed re-drive may start now.
func (s *SessionSync) owedColdPrimeRetryEligible() bool {
	due, ok := s.owedColdPrimeRetryDue()
	return ok && !s.coldPrimeAckAwaited() && s.nowMono() >= due
}

// nextSweepDelay is the sweep timer for the current interval, lowered to an
// owed debt's due time.
//
// A due time in the FUTURE (a backoff deadline, a young ack's expiry) is the
// timer itself, so the retry lands on it. A due time already PASSED gets
// coldPrimeRetryBase instead of zero. That covers a debt just armed (the
// first re-drive of a debt armed with no attempt in flight comes about 1 s
// after its arm), and a debt whose re-drive could not run on this tick (a nil
// store, not connected), which would otherwise spin the loop.
func (s *SessionSync) nextSweepDelay(interval time.Duration) time.Duration {
	d := s.capSweepIntervalForLiveness(interval)
	if due, ok := s.owedColdPrimeRetryDue(); ok {
		wait := time.Duration(due - s.nowMono())
		if wait <= 0 {
			wait = coldPrimeRetryBase
		}
		d = min(d, wait)
	}
	return d
}

// redriveOwedColdPrime runs one owed re-drive. The caller holds
// bulkRedriveInFlight (shared with the survivor and aged-ack re-drives).
//
// Admission: take bulkSendMu and RECHECK eligibility under it. Every
// authoritative bulk serializes on bulkSendMu, so a re-drive that waited behind
// one (the connect-time cold prime, a forced resync, a survivor re-drive, a
// daemon prime) sees its outcome: a published pending ack makes the debt
// ack-awaited, a failure advanced the deadline. Either way it does not stack a
// second snapshot. No eligibility read before the wait is trusted.
func (s *SessionSync) redriveOwedColdPrime() {
	s.bulkSendMu.Lock()
	if !s.owedColdPrimeRetryEligible() {
		s.bulkSendMu.Unlock()
		return
	}
	slog.Warn("cluster sync: re-driving owed cold-prime bulk on the live connection (first attempt did not complete)")
	err := s.doBulkSyncWithBulkSend(true)
	s.bulkSendMu.Unlock()
	if err == nil {
		return
	}
	// #9752 round 4 / #17113: quiet when fenced (see the forced-resync twin).
	if errors.Is(err, errBulkFencedForPeer) || errors.Is(err, errBulkFencedForIpsecPeer) {
		slog.Debug("cluster sync: owed cold-prime re-drive fenced for peer; waiting for disconnect or capable discovery")
	} else {
		slog.Warn("cluster sync: owed cold-prime re-drive failed, will retry", "err", err,
			"retry_in", time.Duration(max(s.coldPrimeRetryNotBeforeNs()-s.nowMono(), 0)).Round(time.Millisecond))
	}
}
