package cluster

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *SessionSync) StartSyncSweep(ctx context.Context) {
	s.lastSweepTime = monotonicSeconds()
	s.lastPrimaryLivenessSweepTime = s.lastSweepTime
	s.primaryLivenessScanIntervalSeconds = initialPrimaryLivenessScanIntervalSeconds

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		activeInterval, idleInterval := s.sweepIntervals()
		interval := s.capSweepIntervalForLiveness(activeInterval)
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				activeInterval, idleInterval = s.sweepIntervals()
				synced := s.syncSweep()
				if synced > 0 || s.syncBackfillNeeded.Load() {
					interval = activeInterval
				} else {
					interval = min(interval*2, idleInterval)
				}
				timer.Reset(s.capSweepIntervalForLiveness(interval))
			}
		}
	}()
	slog.Info("cluster sync: sweep started")
}

// capSweepIntervalForLiveness keeps exponential idle backoff from skipping
// the next negotiated liveness scan. It uses the same adaptive interval as
// the scanner rather than introducing a separate timer cadence.
func (s *SessionSync) capSweepIntervalForLiveness(interval time.Duration) time.Duration {
	if !s.PrimaryLivenessCapable() {
		return interval
	}
	scanSeconds := s.primaryLivenessScanIntervalSeconds
	if scanSeconds == 0 {
		scanSeconds = initialPrimaryLivenessScanIntervalSeconds
	}
	return min(interval, time.Duration(scanSeconds)*time.Second)
}
func (s *SessionSync) sweepIntervals() (time.Duration, time.Duration) {
	if s.sessions != nil {
		if source := s.sessions.SessionDeltas(); source != nil {
			return sweepIntervalsForDataPlane(source)
		}
	}
	return sweepIntervalsForDataPlane(nil)
}
func sweepIntervalsForDataPlane(dp any) (time.Duration, time.Duration) {
	activeInterval := time.Second
	idleInterval := 10 * time.Second
	if profiler, ok := dp.(sessionSyncSweepProfiler); ok {
		if enabled, active, idle := profiler.SessionSyncSweepProfile(); enabled {
			if active > 0 {
				activeInterval = active
			}
			if idle > 0 {
				idleInterval = idle
			}
		}
	}
	if idleInterval < activeInterval {
		idleInterval = activeInterval
	}
	return activeInterval, idleInterval
}

func (s *SessionSync) ShouldSyncZone(zoneID uint16) bool {
	if s.IsPrimaryForRGFn != nil {
		s.zoneRGMu.RLock()
		zoneRG := s.zoneRGMap
		s.zoneRGMu.RUnlock()
		return zoneSetSyncs(zoneID, zoneRG, s.IsPrimaryForRGFn, s.IsPrimaryFn)
	}
	if s.IsPrimaryFn != nil {
		return s.IsPrimaryFn()
	}
	return false
}
func (s *SessionSync) sweepNow() uint64 {
	if s != nil && s.testSweepNow != nil {
		return s.testSweepNow()
	}
	return monotonicSeconds()
}

// stampSweepV4 rechecks a batch-read mirror row while holding the same
// generation fence used by queue-time deletes. A close that wins the recheck
// removes the row and is skipped; a close that races after the recheck waits
// for this stamp and draws a strictly newer delete generation.
func (s *SessionSync) stampSweepV4(
	key dataplane.SessionKey,
	threshold, livenessThreshold, now uint64,
	primaryLiveness bool,
) (dataplane.SessionValue, bool) {
	s.bulkSnapshotGenMu.Lock()
	defer s.bulkSnapshotGenMu.Unlock()
	current, err := s.sessions.GetV4(key)
	if err != nil ||
		current.IsReverse != 0 ||
		(!primaryLiveness && current.Created < threshold) ||
		current.Created > now ||
		(primaryLiveness && (!s.PrimaryLivenessCapable() ||
			!primaryLivenessDue(current.Created, current.Timeout, current.AppTimeout, current.SessionID, livenessThreshold, now))) ||
		!s.ShouldSyncSessionV4(current) {
		return dataplane.SessionValue{}, false
	}
	current.PrimaryLiveness = primaryLiveness
	s.stampInstallGenV4(key, &current)
	return current, true
}

// stampSweepV6 is the IPv6 twin of stampSweepV4.
func (s *SessionSync) stampSweepV6(
	key dataplane.SessionKeyV6,
	threshold, livenessThreshold, now uint64,
	primaryLiveness bool,
) (dataplane.SessionValueV6, bool) {
	s.bulkSnapshotGenMu.Lock()
	defer s.bulkSnapshotGenMu.Unlock()
	current, err := s.sessions.GetV6(key)
	if err != nil ||
		current.IsReverse != 0 ||
		(!primaryLiveness && current.Created < threshold) ||
		current.Created > now ||
		(primaryLiveness && (!s.PrimaryLivenessCapable() ||
			!primaryLivenessDue(current.Created, current.Timeout, current.AppTimeout, current.SessionID, livenessThreshold, now))) ||
		!s.ShouldSyncSessionV6(current) {
		return dataplane.SessionValueV6{}, false
	}
	current.PrimaryLiveness = primaryLiveness
	s.stampInstallGenV6(key, &current)
	return current, true
}

const (
	initialPrimaryLivenessScanIntervalSeconds = uint64(1)
	maxPrimaryLivenessScanIntervalSeconds     = uint64(10)
	maxPrimaryLivenessIntervalSeconds         = uint64(60 * 60)
)

func primaryLivenessTimeout(timeout, appTimeout uint32) uint64 {
	if appTimeout > 0 && appTimeout <= 86_400 {
		return uint64(appTimeout)
	}
	return uint64(timeout)
}

func primaryLivenessScanInterval(timeout, appTimeout uint32) uint64 {
	period := primaryLivenessTimeout(timeout, appTimeout)
	if period == 0 {
		return maxPrimaryLivenessScanIntervalSeconds
	}
	return max(initialPrimaryLivenessScanIntervalSeconds,
		min(maxPrimaryLivenessScanIntervalSeconds, period/2))
}

// primaryLivenessDue schedules a stable, per-session refresh phase from
// creation time. Presence in the primary session map is the liveness evidence:
// LastSeen is only mirrored into that map on a budgeted, multi-second cycle.
// The previous watermark advances only after a complete scan, so one scan
// emits at most one refresh even if it crosses multiple periods.
func primaryLivenessDue(created uint64, timeout, appTimeout uint32, sessionID, previous, now uint64) bool {
	idleTimeout := primaryLivenessTimeout(timeout, appTimeout)
	if idleTimeout == 0 || created > now {
		return false
	}
	period := min(idleTimeout, maxPrimaryLivenessIntervalSeconds)
	phase := sessionID % period
	first := created + period + phase
	if first < created || now < first {
		return false
	}
	if previous < first {
		return true
	}
	return (now-first)/period > (previous-first)/period
}

func (s *SessionSync) syncSweep() int {
	if s.IsPrimaryFn == nil && s.IsPrimaryForRGFn == nil {
		return 0
	}
	if s.incrementalPauseDepth.Load() > 0 {
		return 0
	}
	if !s.stats.Connected.Load() {
		return 0
	}
	// #3926: converge journaled deletes while CONNECTED. A delete generated
	// during a connected-but-backpressured moment (sendCh full) is journaled by
	// QueueDeleteV4/V6 but was previously flushed ONLY on a full
	// disconnect/reconnect (handleNewConnection) — the install-replay below
	// never carried it, so a journaled-while-connected delete never reached the
	// standby until an unrelated disconnect, leaving the standby with a dead
	// session (wrong forwarding on failover). Mirror the install-replay here:
	// flush the delete journal every sweep tick while connected so the standby
	// converges to the primary's DELETED set without requiring a disconnect.
	// flushDeleteJournal is a no-op when the journal is empty, re-sends each
	// entry at most once (take-all under the journal lock, DeletesSent counted
	// on success), preserves the encoded #2170/#2221 delete generation, and
	// re-journals any un-sent tail if sendCh is still full (retried next tick,
	// #2121). The delete backpressure that journaled the entry set
	// syncBackfillNeeded, which holds the sweep at the ACTIVE cadence, so
	// convergence is bounded by one active sweep interval. (#7842: that cadence
	// is 1s only for the eBPF default; under the userspace dataplane
	// SessionSyncSweepProfile makes it 15s, so the bound is the profile's
	// active interval rather than a fixed second.) This flush is
	// independent of the kernel session iteration below and runs even when
	// s.sessions is nil.
	s.flushDeleteJournal()
	if s.sessions == nil {
		return 0
	}
	// #5450: a delete-journal overflow (rejournalTail/journalDelete dropped
	// records) armed forceResync — the standby may still hold sessions the
	// primary already closed. Recover by sending a full authoritative bulk
	// snapshot so the peer's reconcileStaleSessions deletes them. Consume the
	// arm exactly once (CAS true->false); re-arm on failure so a later sweep or
	// reconnect retries. flushDeleteJournal already ran this tick, so any tail
	// still queued replays before this snapshot's window closes.
	if s.forceResync.CompareAndSwap(true, false) {
		slog.Warn("cluster sync: forcing full bulk resync after delete-journal overflow (standby may retain stale sessions)")
		if err := s.doBulkSync(); err != nil {
			s.forceResync.Store(true)
			// #9752 round 4: a fenced bulk is a quiet skip (the fence
			// already counted and warned once), not a hot retry loop.
			if errors.Is(err, errBulkFencedForPeer) {
				slog.Debug("cluster sync: forced resync bulk fenced for peer; waiting for disconnect or capable discovery")
			} else {
				slog.Warn("cluster sync: forced resync bulk failed, will retry", "err", err)
			}
		}
	} else if s.needColdPrime.Load() && !s.coldPrimeAckAwaited() && s.bulkRedriveInFlight.CompareAndSwap(false, true) {
		// #82: an OWED cold prime had exactly two consumers — installConn (a
		// reconnect) and handleDisconnect's survivor re-drive. Both are
		// disconnect-edge triggered, so a first bulk that failed WITHOUT
		// dropping the connection left the obligation armed with no consumer
		// for the life of that connection.
		//
		// BulkSync's own preconditions produce exactly that shape: it returns
		// "session store not ready" (nil s.sessions) or "no peer connection"
		// BEFORE it writes a byte, so no handleDisconnect follows. The startup
		// window is the real trigger — the daemon starts session sync and only
		// then wires the dataplane runtime, so a peer that connects in between
		// drives the cold prime against a nil session store.
		//
		// The incremental path below cannot cover for it. StartSyncSweep seeds
		// lastSweepTime to "now" and the sweep only queues sessions with
		// Created >= threshold, so every session that existed before the sweep
		// started is permanently invisible to it — and only a BulkStart ->
		// BulkEnd window drives the peer's authoritative
		// reconcileStaleSessions. Re-drive here, past the s.sessions nil guard
		// above so the store is known wired. The peer's matching BulkAck
		// discharges the arm (#9626), and a failure leaves it in place so the
		// next tick retries.
		//
		// #9626: because the discharge now waits for the peer, a bulk already
		// sent for THIS debt and still inside BulkAckPendingRetryAfter is not
		// re-sent every tick (coldPrimeAckAwaited). Past that bound the ack is
		// treated as lost and the bulk goes again.
		//
		// else-if, not a second independent block: a forced resync sends the
		// same authoritative snapshot, so at most one bulk leaves per tick.
		//
		// Share bulkRedriveInFlight with the survivor-fabric re-drive so the
		// two cannot stack a second bulk on top of an in-flight one; the CAS
		// simply skips this tick when that re-drive owns the flag, and the arm
		// it is still holding brings us back on the next one.
		slog.Warn("cluster sync: re-driving owed cold-prime bulk on the live connection (first attempt did not complete)")
		err := s.doBulkSync()
		s.bulkRedriveInFlight.Store(false)
		if err != nil {
			// #9752 round 4: quiet when fenced (see the forced-resync twin).
			if errors.Is(err, errBulkFencedForPeer) {
				slog.Debug("cluster sync: owed cold-prime re-drive fenced for peer; waiting for disconnect or capable discovery")
			} else {
				slog.Warn("cluster sync: owed cold-prime re-drive failed, will retry", "err", err)
			}
		}
	} else if (s.bulkAckRetryOwed.Load() || s.forcedBulkRetryDue()) &&
		s.bulkRedriveInFlight.CompareAndSwap(false, true) {
		// A forced resync or another authoritative bulk may be withheld at
		// BulkEnd without discharging cold-prime debt. Re-send an aged,
		// unacknowledged snapshot so that a recovered receiver can complete
		// reconciliation. The sender-side timeout is bounded by the same retry
		// interval as cold-prime, and the shared in-flight guard prevents
		// overlapping survivor/cold-prime retries.
		slog.Warn("cluster sync: re-driving aged unacknowledged bulk on the live connection")
		s.bulkAckRetryOwed.Store(true)
		s.bulkSendMu.Lock()
		s.clearPendingBulkAck()
		err := s.doBulkSyncWithBulkSend(true)
		s.bulkSendMu.Unlock()
		s.bulkRedriveInFlight.Store(false)
		if err != nil {
			s.bulkAckRetryOwed.Store(true)
			if errors.Is(err, errBulkFencedForPeer) {
				slog.Debug("cluster sync: unacknowledged bulk retry fenced for peer; waiting for disconnect or capable discovery")
			} else {
				slog.Warn("cluster sync: unacknowledged bulk retry failed, will retry", "err", err)
			}
		}
	}
	now := s.sweepNow()

	livenessThreshold := s.lastPrimaryLivenessSweepTime
	livenessCapable := s.PrimaryLivenessCapable()
	livenessScanInterval := s.primaryLivenessScanIntervalSeconds
	if livenessScanInterval == 0 {
		livenessScanInterval = initialPrimaryLivenessScanIntervalSeconds
	}
	livenessScanDue := livenessCapable &&
		(livenessThreshold == 0 ||
			(now >= livenessThreshold && now-livenessThreshold >= livenessScanInterval))
	if s.lastSweepEmpty && !s.syncBackfillNeeded.Load() && !livenessScanDue {
		if s.telemetry != nil {
			newCtr, err1 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
			closedCtr, err2 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
			if err1 == nil && err2 == nil && newCtr == s.lastNewCounter && closedCtr == s.lastClosedCounter {
				s.lastSweepTime = now
				return 0
			}
			s.lastNewCounter = newCtr
			s.lastClosedCounter = closedCtr
		}
	}
	threshold := s.lastSweepTime

	// now is also the plausibility ceiling for Created in the filters below:
	// saturated (MaxUint64) rows are known corrupt/far-future values and must
	// not re-queue every sweep. A non-saturated row just beyond this scan's
	// start can instead be a legitimate session born while map enumeration
	// yields between batches. Keep the sweep non-empty for that case, so an
	// unchanged telemetry counter cannot advance lastSweepTime past the row
	// before a later tick sees it.
	var count int
	var overflow bool
	var future bool
	minimumLivenessScanInterval := maxPrimaryLivenessScanIntervalSeconds
	replaying := s.syncBackfillNeeded.Load()
	if err := s.sessions.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created > now && val.Created != ^uint64(0) {
			future = true
			return true
		}
		regular := val.Created >= threshold && val.Created <= now
		liveness := livenessScanDue && val.Created < threshold &&
			primaryLivenessDue(val.Created, val.Timeout, val.AppTimeout, val.SessionID, livenessThreshold, now)
		syncable := false
		if livenessCapable || regular {
			syncable = s.ShouldSyncSessionV4(val)
		}
		if livenessCapable && syncable {
			minimumLivenessScanInterval = min(minimumLivenessScanInterval,
				primaryLivenessScanInterval(val.Timeout, val.AppTimeout))
		}
		if (regular || liveness) && syncable {
			announced := s.installTableAnnouncedV4(key)
			var ok bool
			val, ok = s.stampSweepV4(key, threshold, livenessThreshold, now, liveness)
			if !ok {
				return true
			}
			if s.suppressStampedInstallForIncapablePeer(val.InstallTableDomain, val.InstallTableCheck, "sweep_v4") {
				return true
			}
			if s.suppressIpsecDiscriminatorInstallForIncapablePeer(val.TunnelDiscriminator) {
				return true
			}
			if val.InstallTableDomain == 0 && val.InstallTableCheck == 0 &&
				suppressUnannouncedForPBRActivePeer(s, announced, "sweep_v4") {
				return true
			}
			msg := encodeSessionV4(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v4") {
				s.stats.SweepSessionsSent.Add(1)
				count++
			} else {
				overflow = true
			}
		}
		return true
	}); err != nil {
		slog.Warn("cluster sync: sweep v4 iteration failed", "err", err)
		s.stats.Errors.Add(1)
		return count
	}
	if err := s.sessions.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created > now && val.Created != ^uint64(0) {
			future = true
			return true
		}
		regular := val.Created >= threshold && val.Created <= now
		liveness := livenessScanDue && val.Created < threshold &&
			primaryLivenessDue(val.Created, val.Timeout, val.AppTimeout, val.SessionID, livenessThreshold, now)
		syncable := false
		if livenessCapable || regular {
			syncable = s.ShouldSyncSessionV6(val)
		}
		if livenessCapable && syncable {
			minimumLivenessScanInterval = min(minimumLivenessScanInterval,
				primaryLivenessScanInterval(val.Timeout, val.AppTimeout))
		}
		if (regular || liveness) && syncable {
			announced := s.installTableAnnouncedV6(key)
			var ok bool
			val, ok = s.stampSweepV6(key, threshold, livenessThreshold, now, liveness)
			if !ok {
				return true
			}
			if s.suppressStampedInstallForIncapablePeer(val.InstallTableDomain, val.InstallTableCheck, "sweep_v6") {
				return true
			}
			if s.suppressIpsecDiscriminatorInstallForIncapablePeer(val.TunnelDiscriminator) {
				return true
			}
			if val.InstallTableDomain == 0 && val.InstallTableCheck == 0 &&
				suppressUnannouncedForPBRActivePeer(s, announced, "sweep_v6") {
				return true
			}
			msg := encodeSessionV6(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v6") {
				s.stats.SweepSessionsSent.Add(1)
				count++
			} else {
				overflow = true
			}
		}
		return true
	}); err != nil {
		slog.Warn("cluster sync: sweep v6 iteration failed", "err", err)
		s.stats.Errors.Add(1)
		return count
	}
	if overflow {
		s.syncBackfillNeeded.Store(true)
		slog.Warn("cluster sync: sweep queue overflow, replaying previous window", "threshold", threshold, "queued", count, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		return count
	}
	if future && count == 0 {
		// The row was born after this scan's watermark. Do not mark the
		// sweep empty or move lastSweepTime past it: telemetry counters can
		// already include the row, making the unchanged-counter fast path
		// otherwise skip it forever. Saturated MaxUint64 rows intentionally
		// do not set future above, so known corrupt timestamps still follow
		// the existing one-time skip behavior.
		s.lastSweepEmpty = false
		slog.Debug("cluster sync: sweep saw a session born during enumeration; retaining the prior window", "threshold", threshold, "now", now)
		return 0
	}
	if replaying {
		s.syncBackfillNeeded.Store(false)
		slog.Info("cluster sync: sweep replay recovered", "queued", count, "threshold", threshold)
	}
	if livenessCapable {
		s.primaryLivenessScanIntervalSeconds = minimumLivenessScanInterval
		if livenessScanDue {
			s.lastPrimaryLivenessSweepTime = now
		}
	}

	s.lastSweepTime = now
	s.lastSweepEmpty = (count == 0)
	if count == 0 && s.telemetry != nil {
		newCtr, err1 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
		closedCtr, err2 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
		if err1 == nil && err2 == nil {
			s.lastNewCounter = newCtr
			s.lastClosedCounter = closedCtr
		}
	}
	if count > 0 {
		// Debug, not Info: this fires on every 1s sweep tick under steady
		// session churn (CLAUDE.md: never slog.Info per poll tick).
		slog.Debug("cluster sync: sweep synced sessions", "count", count)
	}
	return count
}
