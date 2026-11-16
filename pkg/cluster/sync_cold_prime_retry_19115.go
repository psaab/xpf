package cluster

import (
	"errors"
	"log/slog"
	"time"
)

// #19115 (design v4, narrowed 2026-11-15): an owed cold-prime debt with no
// bulk in flight is re-driven inside the manual-failover admission window, at
// a backed-off cadence that no sweep frequency can bypass, and no
// authoritative bulk is sent twice for one obligation.
//
// Before this, the sweep's owed re-drive was the only consumer of a debt left
// on a live connection, and it ran only on the sweep timer: 15 s active / 60 s
// idle under the userspace profile, backing off after a failed re-drive, and a
// wake RESET that timer, postponing it. A transient first-bulk failure (or a
// debt armed with no attempt at all: the peer-reboot edge, a capable
// discovery) therefore outlived every 5 s admission window that started
// inside it, and ISSU drains were refused.
//
// The model:
//
//   - THE BACKOFF, bulkRetryNotBefore, holds back ONLY the owed cold-prime
//     re-drive. It is advanced by ANY authoritative bulk that ends in a
//     non-fence error, along coldPrimeRetrySchedule (1 s, 2 s, 4 s, then a
//     long tail of 8 s, 16 s and 30 s) after that failure COMPLETED (a
//     failed attempt's own duration adds to the start-to-start gap). It is
//     reset by a SUCCESSFUL send (the window wrote BulkEnd; publishing
//     pending state alone is not success), by a discharge, by the runtime
//     being wired and by a new debt generation, which is eligible at once
//     (the next sweep tick sends it, as the #9626/#10387/#9618 contracts
//     require) and whose first re-drive is SCHEDULED coldPrimeFirstRetryDelay
//     after its arm. It never touches the #18752 owed age or last failure.
//     The other retries keep their pre-#19115 cadence, by the user's decision
//     of 2026-11-15 (Codex findings 1 and 17 on design v4; #19135): a forced
//     resync re-armed after a failure and the aged-ack re-drive retry on the
//     next sweep tick, the barrier-fence re-prime on the next refused
//     barrier, the daemon prime on its own schedule.
//   - OWED ELIGIBILITY: while a cold-prime debt is owed, the sweep's retry is
//     the owed re-drive or nothing. It may start only when no young ack covers
//     the debt, the bulk is not fenced, and the backoff deadline has passed;
//     the aged-ack branch never runs on its behalf.
//   - SCHEDULING: the sweep timer is lowered to the debt's due time, the later
//     of the deadline and a young ack's 35 s expiry, armed EXACTLY at it. A due
//     time already passed is scheduled at the end of a new debt's first delay,
//     or else means the re-drive could not run (nil store, not connected):
//     re-check at coldPrimeRetryPollDelay, never spin. A wake only
//     moves the loop's deadline EARLIER.
//   - WAKES: an arm, every bulk completion, the lift of a capability fence and
//     the runtime being wired wake the loop.
//   - ADMISSION: every authoritative bulk runs with bulkSendMu held across the
//     whole bulk AND its result hook (doBulkSyncAdmitted), so the next caller
//     to take the lock sees the outcome: a published pending ack, or an
//     advanced deadline. Each caller rechecks ITS OWN obligation under the
//     lock before exporting: the owed re-drive its eligibility, the
//     connect-time cold prime that its debt is not already covered by a
//     pending bulk, the aged-ack re-drive that the aged bulk is still owed
//     and no debt is, the daemon prime that no young bulk is pending, the
//     barrier-fence re-prime that the fence still needs it. A peer's bulk
//     request and a forced resync always export.

// coldPrimeRetrySchedule is the owed re-drive's backoff after the Nth
// consecutive failed authoritative bulk of an owed episode, measured from that
// failure's END (the user's decision of 2026-11-15: a long tail):
//
//   - 1 s, 2 s, 4 s: the admission phase. From the first failure, attempts
//     start about 1 s, 3 s and 7 s later (plus each failed attempt's own
//     duration), so every gap stays at most 4 s while the episode is young.
//     Measured from an observed completed failure, the next attempt reaches
//     a qualifying pending bulk inside a 5 s admission window when the
//     remaining backoff, the scheduling and lock delay and that attempt's
//     own successful time-to-pending add up to less than 5 s. This is what
//     admits a drain after a transient (the #19115 lab, D-B).
//   - 8 s, 16 s, then 30 s, the cap: sustained failure. The tail starts at
//     the FOURTH consecutive failure, about 7 s into the episode (the third
//     still earns the 4 s step), and a drain opened then would be refused
//     for the debt anyway unless the very next attempt succeeds. Growing
//     the backoff cuts the cost of a
//     persistently failing export, a full owner-RG export attempt each time
//     (the lab measured +3.7 % of a core at 10k sessions and +7.3 % at about
//     24.6k at the 4 s cadence), to one attempt per 30 s at the cap. The
//     price: a drain whose window opens during the tail can be refused even
//     if the export has just recovered, until the next attempt succeeds. That
//     attempt starts after up to 30 s of backoff from the moment the failed
//     attempt completes, plus scheduling and lock delay; a window that opens
//     during a failing attempt also waits for that attempt to end. The
//     operator retries the drain.
//
// A success (BulkEnd written), a discharge, the runtime being wired and a new
// debt generation reset it to the first step; it never touches the #18752
// owed age or last failure.
var coldPrimeRetrySchedule = [...]time.Duration{
	1 * time.Second, 2 * time.Second, 4 * time.Second,
	8 * time.Second, 16 * time.Second, 30 * time.Second,
}

const (
	// coldPrimeFirstRetryDelay schedules a NEW debt generation's first sweep
	// re-drive (the debt itself is eligible at once): a debt armed with no
	// attempt in flight (the peer-reboot edge, a capable discovery) is
	// re-driven 100 ms after its arm. On a reconnect the connect path drives
	// the cold prime itself; the delay lets it usually go first, and the
	// admission recheck makes either order safe.
	coldPrimeFirstRetryDelay = 100 * time.Millisecond
	// coldPrimeRetryPollDelay re-checks a debt that is due but whose re-drive
	// could not run (nil store, not connected), without spinning.
	coldPrimeRetryPollDelay = time.Second
)

// bulkRetryReset clears the retry backoff: a retry is eligible at once.
func (s *SessionSync) bulkRetryReset() {
	s.bulkRetryMu.Lock()
	s.bulkRetryNotBefore = 0
	s.bulkRetryFailures = 0
	s.bulkRetryMu.Unlock()
}

// bulkRetryArmNewDebt makes a new debt generation eligible at once, whatever
// an older generation's failures backed off to, and schedules its first sweep
// re-drive coldPrimeFirstRetryDelay from now.
func (s *SessionSync) bulkRetryArmNewDebt() {
	s.bulkRetryMu.Lock()
	s.bulkRetryNotBefore = 0
	s.bulkRetryFailures = 0
	s.coldPrimeFreshUntil = s.nowMono() + int64(coldPrimeFirstRetryDelay)
	s.bulkRetryMu.Unlock()
}

// coldPrimeFreshUntilNs is when a new debt's first sweep re-drive is scheduled.
func (s *SessionSync) coldPrimeFreshUntilNs() int64 {
	s.bulkRetryMu.Lock()
	defer s.bulkRetryMu.Unlock()
	return s.coldPrimeFreshUntil
}

// bulkRetryNotBeforeNs is the earliest nowMono() the owed re-drive may start,
// or 0.
func (s *SessionSync) bulkRetryNotBeforeNs() int64 {
	s.bulkRetryMu.Lock()
	defer s.bulkRetryMu.Unlock()
	return s.bulkRetryNotBefore
}

// bulkRetryBackoffOpen reports whether the owed re-drive's backoff has elapsed.
func (s *SessionSync) bulkRetryBackoffOpen() bool {
	return s.nowMono() >= s.bulkRetryNotBeforeNs()
}

// noteBulkRetryResult applies a completed authoritative bulk to the backoff.
// It runs from noteBulkResult, under bulkSendMu (doBulkSyncAdmitted), so the
// next caller to take the lock sees it. A success resets the backoff; a fence
// leaves it alone (a fenced debt is not eligible at all, see bulkFenceNow);
// any other failure backs it off.
func (s *SessionSync) noteBulkRetryResult(err error) {
	switch {
	case err == nil:
		s.bulkRetryReset()
	case errors.Is(err, errBulkFencedForPeer) || errors.Is(err, errBulkFencedForIpsecPeer):
	default:
		s.bulkRetryMu.Lock()
		step := coldPrimeRetrySchedule[min(int(s.bulkRetryFailures), len(coldPrimeRetrySchedule)-1)]
		if s.bulkRetryFailures < uint32(len(coldPrimeRetrySchedule)) {
			s.bulkRetryFailures++
		}
		s.bulkRetryNotBefore = s.nowMono() + int64(step)
		s.bulkRetryMu.Unlock()
	}
}

// bulkFenceNow reports the fence an authoritative bulk would hit now, with
// EXACTLY the predicates bulkSyncWindow applies (sync_bulk.go): a latched
// install-table fence while the peer is not install-table capable, or a
// latched IPsec fence unless the peer's capabilities are LEARNED and it is
// discriminator capable. nil when unfenced. It clears no latch:
// bulkSyncWindow's revalidate-on-consume stays the authority.
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
	due := s.bulkRetryNotBeforeNs()
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

// coldPrimeCovered reports whether the current cold-prime debt needs no new
// bulk: none is owed, or a bulk stamped with the current generation is
// pending and young.
func (s *SessionSync) coldPrimeCovered() bool {
	return !s.needColdPrime.Load() || s.coldPrimeAckAwaited()
}

// nextSweepDelay is the sweep timer for the current interval, lowered to an
// owed debt's due time: EXACTLY that time when it is in the future (a backoff
// deadline, a young ack's expiry). A debt already due is scheduled at the end
// of its first delay when it was armed within coldPrimeFirstRetryDelay;
// otherwise its re-drive could not run on the last tick (a nil store, not
// connected) and is re-checked at coldPrimeRetryPollDelay.
func (s *SessionSync) nextSweepDelay(interval time.Duration) time.Duration {
	d := s.capSweepIntervalForLiveness(interval)
	if due, ok := s.owedColdPrimeRetryDue(); ok {
		now := s.nowMono()
		wait := time.Duration(due - now)
		if wait <= 0 {
			if fresh := s.coldPrimeFreshUntilNs(); fresh > now {
				wait = time.Duration(fresh - now)
			} else {
				wait = coldPrimeRetryPollDelay
			}
		}
		d = min(d, wait)
	}
	return d
}

// doBulkSyncAdmitted runs one authoritative bulk under bulkSendMu, held across
// the whole bulk AND its result hook (noteBulkResult, deferred inside
// doBulkSyncWithBulkSend), so the next caller to take the lock sees this
// bulk's outcome. stillOwed, when not nil, is the caller's OWN obligation,
// rechecked under the lock: false skips the bulk (sent == false, nil error).
func (s *SessionSync) doBulkSyncAdmitted(stillOwed func() bool) (sent bool, err error) {
	s.bulkSendMu.Lock()
	defer s.bulkSendMu.Unlock()
	if stillOwed != nil && !stillOwed() {
		return false, nil
	}
	return true, s.doBulkSyncWithBulkSend(true)
}

// redriveOwedColdPrime runs one owed re-drive. The caller has taken
// bulkRedriveInFlight (shared with the survivor and aged-ack re-drives); it is
// released here on EVERY path. Eligibility is rechecked under bulkSendMu.
func (s *SessionSync) redriveOwedColdPrime() {
	defer s.bulkRedriveInFlight.Store(false)
	sent, err := s.doBulkSyncAdmitted(s.owedColdPrimeRetryEligible)
	if !sent || err == nil {
		return
	}
	// #9752 round 4 / #17113: quiet when fenced (see the forced-resync twin).
	if errors.Is(err, errBulkFencedForPeer) || errors.Is(err, errBulkFencedForIpsecPeer) {
		slog.Debug("cluster sync: owed cold-prime re-drive fenced for peer; waiting for disconnect or capable discovery")
	} else {
		slog.Warn("cluster sync: owed cold-prime re-drive failed, will retry", "err", err,
			"retry_in", time.Duration(max(s.bulkRetryNotBeforeNs()-s.nowMono(), 0)).Round(time.Millisecond))
	}
}

// redriveAgedBulk re-sends an aged, unacknowledged authoritative bulk that
// carries no cold-prime debt (a forced resync withheld at BulkEnd). The caller
// has taken bulkRedriveInFlight; it is released here on EVERY path. Under
// bulkSendMu it rechecks its own obligation (the aged bulk is still owed, and
// no debt has been armed meanwhile: an owed debt is the owed re-drive's to
// send) before clearing the pending ack and exporting. It keeps its
// pre-#19115 cadence: the retry backoff does not hold it back.
func (s *SessionSync) redriveAgedBulk() {
	defer s.bulkRedriveInFlight.Store(false)
	s.bulkSendMu.Lock()
	if s.needColdPrime.Load() || !(s.bulkAckRetryOwed.Load() || s.forcedBulkRetryDue()) {
		s.bulkSendMu.Unlock()
		return
	}
	slog.Warn("cluster sync: re-driving aged unacknowledged bulk on the live connection")
	s.bulkAckRetryOwed.Store(true)
	s.clearPendingBulkAck()
	err := s.doBulkSyncWithBulkSend(true)
	s.bulkSendMu.Unlock()
	if err != nil {
		s.bulkAckRetryOwed.Store(true)
		if errors.Is(err, errBulkFencedForPeer) || errors.Is(err, errBulkFencedForIpsecPeer) {
			slog.Debug("cluster sync: unacknowledged bulk retry fenced for peer; waiting for disconnect or capable discovery")
		} else {
			slog.Warn("cluster sync: unacknowledged bulk retry failed, will retry", "err", err)
		}
	}
}

// DoPrimeBulkSync is the daemon's bulk-prime retry (#15686): an authoritative
// bulk sent only if, under bulkSendMu, no bulk sent since the daemon decided
// to retry is still young and awaiting its ack. sent reports whether one went.
func (s *SessionSync) DoPrimeBulkSync() (sent bool, err error) {
	return s.doBulkSyncAdmitted(func() bool {
		_, age, ok := s.PendingBulkAck()
		return !ok || age >= BulkAckPendingRetryAfter
	})
}
