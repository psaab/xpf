package cluster

import (
	"log/slog"
	"time"
)

// #18521 (D): a bulk whose stale-session reconcile was SKIPPED because the
// zone-ownership map changed while the bulk was in flight (#9655: judging by
// the old map's answers could delete sessions this node now owns) withholds
// its BulkAck. The skip says "the next bulk reconciles", but no next bulk was
// owed by anything on either node except the sender's 35s
// BulkAckPendingRetryAfter retry. During startup churn after a peer restart
// the map moves repeatedly (every SetZoneOwnership advances the generation),
// so the sender's barrier fence — which only a BulkAck can discharge — refused
// every manual failover for the whole window.
//
// The receiver is the side that knows why it withheld the ack, so it asks for
// the replacement: once the map has been unchanged for zoneMapSettleWindow
// (capped at zoneMapSettleMax of continuous churn), it queues a BulkRequest.
// The sender's handleBulkRequest runs an ordinary authoritative bulk whose
// BulkStart snapshot is taken under the settled map. Acking anyway is NOT the
// fix: the ack certifies a reconciled table, and this one was not.
//
// Bounded by construction: one request per skipped bulk (the skip happens only
// at a BulkEnd), single-flighted, and the sender coalesces concurrent
// requests (bulkRequestInFlight). A peer that predates BulkRequest ignores the
// unknown frame and keeps the 35s retry.

const (
	zoneMapSettleWindow = time.Second
	zoneMapSettleMax    = 30 * time.Second
	zoneMapSettlePoll   = 100 * time.Millisecond
)

func (s *SessionSync) zoneMapSettleWindows() (window, limit time.Duration) {
	window, limit = zoneMapSettleWindow, zoneMapSettleMax
	if s.testZoneMapSettle > 0 {
		window = s.testZoneMapSettle
	}
	if s.testZoneMapSettleMax > 0 {
		limit = s.testZoneMapSettleMax
	}
	return window, limit
}

func (s *SessionSync) currentZoneMapGen() uint64 {
	s.zoneRGMu.RLock()
	defer s.zoneRGMu.RUnlock()
	return s.zoneRGMapGen
}

// scheduleSettledBulkRerequest requests a fresh bulk from the peer once the
// zone map settles. snapshotGen is the generation the skipped bulk was judged
// against, for the log.
func (s *SessionSync) scheduleSettledBulkRerequest(snapshotGen uint64) {
	if !s.bulkRerequestInFlight.CompareAndSwap(false, true) {
		return
	}
	window, limit := s.zoneMapSettleWindows()
	poll := zoneMapSettlePoll
	if poll > window {
		poll = window
	}
	done := s.runDone
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.bulkRerequestInFlight.Store(false)
		start := time.Now()
		gen := s.currentZoneMapGen()
		stableSince := start
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for time.Since(stableSince) < window && time.Since(start) < limit {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			if g := s.currentZoneMapGen(); g != gen {
				gen = g
				stableSince = time.Now()
			}
		}
		if !s.stats.Connected.Load() {
			// A disconnect re-primes on reconnect; nothing to ask for here.
			return
		}
		if !s.enqueueQueuedFrame(encodeRawMessage(syncMsgBulkRequest, nil)) {
			s.stats.Errors.Add(1)
			slog.Warn("cluster sync: could not queue a bulk re-request after a reconcile skipped for a "+
				"zone-map change (send queue full); the peer's 35s bulk-ack retry remains the fallback",
				"snapshot_map_gen", snapshotGen, "map_gen", gen)
			return
		}
		slog.Info("cluster sync: requested a fresh bulk from the peer: the previous bulk's reconcile was "+
			"skipped because the zone map changed mid-bulk, and its BulkAck stays withheld (#18521)",
			"snapshot_map_gen", snapshotGen, "map_gen", gen,
			"settled_after", time.Since(start).Round(time.Millisecond).String(),
			"settled", time.Since(stableSince) >= window)
	}()
}
