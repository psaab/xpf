package cluster

import (
	"log/slog"
	"time"
)

// #18521 (D): a receiver that WITHHOLDS its BulkAck owes the sender a reason
// to send another bulk. The ack certifies a reconciled table, so a bulk the
// receiver could not reconcile correctly gets no ack — but until now nothing
// on either node asked for the replacement except the sender's 35s
// BulkAckPendingRetryAfter retry. The sender's barrier fence, which only a
// BulkAck can discharge, refused every manual failover meanwhile, and the
// admission window is 5s.
//
// Every withholding outcome of a COMPLETED window schedules one re-request
// (handleBulkEnd): the reconcile was skipped (zone map changed mid-bulk, no
// zone snapshot, no dataplane) or failed, the window was aborted (cap or
// deadline), or rows hit transient helper-install failures (expected right
// after a restart, while the helper is still coming up). An ignored BulkEnd
// (wrong epoch, foreign connection, retired incarnation, no window) does not:
// it closes no window, and the bulk it would complete is either still
// streaming or superseded by a newer one whose own BulkEnd decides.
//
// The request is a BulkRequest; the sender's handleBulkRequest runs an
// ordinary authoritative bulk. Bounds:
//   - single-flight (bulkRerequestInFlight);
//   - exponential backoff per consecutive withheld bulk (1s doubling to
//     30s), reset by the next bulk that reconciles and acks, so a helper
//     that stays unready is not hammered with full tables;
//   - the zone map must also have been stable for zoneMapSettleWindow, so a
//     map still churning does not void the replacement the same way (capped
//     at zoneMapSettleMax);
//   - skipped when a newer bulk than the latest withheld one was accepted
//     meanwhile (bulkRecvSerial moved): that bulk, completed or in flight, is
//     the replacement, and a request now would only replace its pending epoch
//     on the sender;
//   - the sender coalesces concurrent requests (bulkRequestInFlight).
//
// A peer that predates BulkRequest ignores the unknown frame and keeps the 35s
// retry.

const (
	zoneMapSettleWindow  = time.Second
	zoneMapSettleMax     = 30 * time.Second
	zoneMapSettlePoll    = 100 * time.Millisecond
	bulkRerequestBackoff = time.Second
	bulkRerequestMax     = 30 * time.Second
)

// bulkRerequestDelay is the backoff for the streak-th consecutive withheld
// bulk (1-based): 1s, 2s, 4s, ... capped at bulkRerequestMax.
func bulkRerequestDelay(streak uint64) time.Duration {
	d := bulkRerequestBackoff
	for i := uint64(1); i < streak && d < bulkRerequestMax; i++ {
		d *= 2
	}
	if d > bulkRerequestMax {
		d = bulkRerequestMax
	}
	return d
}

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

func (s *SessionSync) currentBulkRecvSerial() uint64 {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	return s.bulkRecvSerial
}

// noteBulkReconciled resets the re-request backoff after a bulk reconciled
// and was acked.
func (s *SessionSync) noteBulkReconciled() {
	s.bulkRerequestStreak.Store(0)
}

// scheduleBulkRerequest asks the peer for a replacement bulk after a withheld
// BulkAck. serial is the withheld bulk's bulkRecvSerial; reason is logged.
//
// The newest withheld serial is recorded even when a request is already in
// flight, and the in-flight request compares the accepted serial with THAT,
// so back-to-back withheld bulks still produce one request for the latest of
// them (not zero: the first would otherwise see its own bulk superseded and
// drop, while the second lost the single-flight race).
func (s *SessionSync) scheduleBulkRerequest(reason string, serial uint64) {
	s.bulkRerequestSerial.Store(serial)
	if !s.bulkRerequestInFlight.CompareAndSwap(false, true) {
		return
	}
	streak := s.bulkRerequestStreak.Add(1)
	backoff := bulkRerequestDelay(streak)
	if s.testBulkRerequestBackoff > 0 {
		backoff = s.testBulkRerequestBackoff
	}
	window, limit := s.zoneMapSettleWindows()
	if limit < backoff {
		limit = backoff
	}
	poll := zoneMapSettlePoll
	if poll > window {
		poll = window
	}
	if poll > backoff {
		poll = backoff
	}
	done := s.runDone
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		handled := uint64(0)
		defer func() {
			s.bulkRerequestInFlight.Store(false)
			// A bulk withheld after this request decided (and lost the
			// single-flight race) still owes a request of its own.
			if latest := s.bulkRerequestSerial.Load(); handled != 0 && latest != handled &&
				s.stats.Connected.Load() {
				s.scheduleBulkRerequest(reason, latest)
			}
		}()
		start := time.Now()
		gen := s.currentZoneMapGen()
		stableSince := start
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for (time.Since(start) < backoff || time.Since(stableSince) < window) && time.Since(start) < limit {
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
		withheld := s.bulkRerequestSerial.Load()
		handled = withheld
		if cur := s.currentBulkRecvSerial(); cur != withheld {
			slog.Debug("cluster sync: bulk re-request dropped: a newer bulk was accepted meanwhile",
				"withheld_serial", withheld, "current_serial", cur, "reason", reason)
			return
		}
		if !s.enqueueQueuedFrame(encodeRawMessage(syncMsgBulkRequest, nil)) {
			s.stats.Errors.Add(1)
			slog.Warn("cluster sync: could not queue a bulk re-request after withholding a BulkAck "+
				"(send queue full); the peer's 35s bulk-ack retry remains the fallback",
				"reason", reason)
			return
		}
		s.stats.BulkRerequestsSent.Add(1)
		slog.Info("cluster sync: requested a fresh bulk from the peer after withholding its BulkAck (#18521)",
			"reason", reason, "streak", streak, "backoff", backoff.String(),
			"waited", time.Since(start).Round(time.Millisecond).String(),
			"zone_map_settled", time.Since(stableSince) >= window)
	}()
}
