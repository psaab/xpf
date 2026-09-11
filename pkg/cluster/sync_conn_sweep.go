package cluster

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *SessionSync) StartSyncSweep(ctx context.Context) {
	s.lastSweepTime = monotonicSeconds()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		activeInterval, idleInterval := s.sweepIntervals()
		interval := activeInterval
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
				timer.Reset(interval)
			}
		}
	}()
	slog.Info("cluster sync: sweep started")
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
		rgID, ok := s.zoneRGMap[zoneID]
		s.zoneRGMu.RUnlock()
		if ok {
			return s.IsPrimaryForRGFn(rgID)
		}
	}
	if s.IsPrimaryFn != nil {
		return s.IsPrimaryFn()
	}
	return false
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
			slog.Warn("cluster sync: forced resync bulk failed, will retry", "err", err)
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
			slog.Warn("cluster sync: owed cold-prime re-drive failed, will retry", "err", err)
		}
	}
	if s.lastSweepEmpty && !s.syncBackfillNeeded.Load() {
		if s.telemetry != nil {
			newCtr, err1 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
			closedCtr, err2 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
			if err1 == nil && err2 == nil && newCtr == s.lastNewCounter && closedCtr == s.lastClosedCounter {
				s.lastSweepTime = monotonicSeconds()
				return 0
			}
			s.lastNewCounter = newCtr
			s.lastClosedCounter = closedCtr
		}
	}
	threshold := s.lastSweepTime
	now := monotonicSeconds()
	var count int
	var overflow bool
	replaying := s.syncBackfillNeeded.Load()
	if err := s.sessions.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created >= threshold && s.ShouldSyncZone(val.IngressZone) {
			s.stampInstallGenV4(key, &val)
			msg := encodeSessionV4(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v4") {
				// #7842: attribute this send to the sweep. A sub-total of
				// SessionsSent, not a separate population -- the delta
				// stream's share is SessionsSent - SweepSessionsSent.
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
		if val.Created >= threshold && s.ShouldSyncZone(val.IngressZone) {
			s.stampInstallGenV6(key, &val)
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
	if replaying {
		s.syncBackfillNeeded.Store(false)
		slog.Info("cluster sync: sweep replay recovered", "queued", count, "threshold", threshold)
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
