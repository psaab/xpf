package cluster

import (
	"encoding/binary"
	"log/slog"
	"net"
	"time"
)

// Receive handlers for bulk-transfer frames, extracted verbatim from
// handleMessage (#16168). BulkStart is extracted last, in
// sync_bulkstart_recv.go, preserving its ORDER MATTERS sequence.
// Dispatch, counters, and lock choreography are unchanged.
func (s *SessionSync) handleBulkRequest(conn net.Conn, payload []byte) bool {
	// Request-triggered sends use the same authoritative source selection
	// as cold-prime bulks. Coalesce concurrent requests before they reach
	// bulkSendMu, without blocking this receive loop.
	if s.bulkRequestInFlight.CompareAndSwap(false, true) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.bulkRequestInFlight.Store(false)
			if err := s.doBulkSync(); err != nil {
				slog.Debug("cluster sync: requested bulk sync failed; will retry on next request",
					"err", err)
			}
		}()
	}
	return true
}

func (s *SessionSync) handleBulkEnd(conn net.Conn, payload []byte) bool {
	var epoch uint64
	if len(payload) >= 8 {
		epoch = binary.LittleEndian.Uint64(payload[:8])
	}
	// #9174 V013: the sender's boot incarnation, when it sent one. Same
	// length-gated trailing extension BulkStart has carried since #5084;
	// the legacy 8-byte form parses to the zero value and fails open.
	endInc := parseBootIncarnation(payload)
	s.bulkMu.Lock()
	if !s.bulkInProgress {
		// #5272: a BulkEnd with NO bulk transfer actually in progress
		// on our side is spurious or replayed — a buggy / mixed-version
		// / replaying peer frame, or a BulkEnd that arrives after we
		// tore the transfer down on disconnect. Completing it here would
		// reconcile-as-done, ACK, latch bulkEverCompleted, and fire
		// OnBulkSyncReceived, which RELEASES the VRRP sync hold: the node
		// would become MASTER-eligible while forwarding with an empty /
		// stale peer session table (stateful failover broken — a mid-
		// session failover blackholes). Only a real BulkStart -> ... ->
		// BulkEnd transfer may release the safety gate. This is LOCAL
		// state (no wire field, no version bump), so a legacy peer's
		// legitimate bulk still completes.
		s.bulkMu.Unlock()
		slog.Debug("cluster sync: ignoring BulkEnd with no bulk transfer in progress", "got", epoch)
		return false
	}
	if s.bulkRecvEpoch != epoch {
		// #5718 (codex-182 C-HA C01b): snapshot the mutex-protected
		// expected epoch BEFORE releasing bulkMu. Reading s.bulkRecvEpoch
		// in the log arguments after Unlock races a concurrent BulkStart
		// on another fabric receive loop (which writes bulkRecvEpoch under
		// bulkMu, sync_conn_read.go BulkStart handler) — a diagnostic-only
		// data race the Go memory model forbids and go test -race flags.
		want := s.bulkRecvEpoch
		s.bulkMu.Unlock()
		slog.Warn("cluster sync: ignoring BulkEnd with mismatched epoch", "expected", want, "got", epoch)
		return false
	}
	// #9174 V013: the epoch alone does not identify a bulk. The peer's send
	// counter restarts at zero when it reboots, so an end marker buffered on
	// the DEAD boot's still-ESTABLISHED socket can carry the same epoch as
	// the bulk its own replacement has just started — and completing it here
	// reconciles against a partly-received table, latches bulkEverCompleted
	// and releases the VRRP sync hold. The node becomes MASTER-eligible
	// while forwarding with sessions it never received.
	//
	// FAIL OPEN on either side being un-incarnated, which is a decision and
	// not a default: a peer on an older build sends the 8-byte form, and a
	// bulk primed without an incarnation recorded nothing to compare
	// against. In both cases this is exactly today's epoch-only matching —
	// the #5084 posture, for the same reason (failing closed would strand
	// the standby for the whole rolling-upgrade window).
	if endInc.known() && s.bulkRecvIncarnation.known() && endInc != s.bulkRecvIncarnation {
		started := s.bulkRecvIncarnation
		s.bulkMu.Unlock()
		s.stats.BulkEndsDeadIncarnationDropped.Add(1)
		slog.Warn("cluster sync: ignoring BulkEnd from a retired peer boot incarnation",
			"epoch", epoch, "end_incarnation", endInc.String(),
			"bulk_started_by", started.String(),
			"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		return false
	}
	// #9716: the incarnation check above fails open whenever either side is
	// un-incarnated: a peer on an older build, or a bulk primed without one.
	// Every peer process restarts its epoch at 1, so a BulkEnd buffered on a
	// dead peer process's still-ESTABLISHED socket then completes the live
	// bulk on a colliding epoch.
	//
	// The connection closes that without a wire change. BulkSync pins one
	// connection for a whole bulk, so a legitimate end marker never arrives
	// on another one. A legacy peer's bulk, started and ended on one
	// connection, still completes.
	if s.bulkRecvConn != nil && conn != s.bulkRecvConn {
		s.bulkMu.Unlock()
		s.stats.BulkEndsForeignConnDropped.Add(1)
		slog.Warn("cluster sync: ignoring BulkEnd on a connection other than the one that started the bulk",
			"epoch", epoch, "end_incarnation", endInc.String(),
			"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		return false
	}
	// #9716: a completion the incarnation check could not judge is matched on
	// epoch and connection alone. Count it, so a half-upgraded pair is visible.
	if !endInc.known() || !s.bulkRecvIncarnation.known() {
		s.stats.BulkEndsEpochOnlyMatched.Add(1)
	}
	bulkSerial := s.bulkRecvSerial
	failedV4, failedV6 := len(s.bulkInstallFailedV4), len(s.bulkInstallFailedV6)
	// #16039: an invalid window (accumulator overflow) or a window held
	// open past its deadline is aborted here, never reconciled. The
	// window closes, but bulkIncomplete keeps the readiness debt until
	// a later bulk reconciles successfully.
	invalid := s.bulkRecvInvalid
	late := !s.bulkRecvStartedAt.IsZero() &&
		s.bulkRecvNow().Sub(s.bulkRecvStartedAt) > bulkRecvWindowTimeout
	if late && !invalid {
		s.bulkRecvInvalid = true
		invalid = true
		s.stats.BulkRecvAborted.Add(1)
	}
	if invalid || late {
		s.bulkInProgress = false
		s.bulkIncomplete = true
		s.inventoryActive = false
		s.inventoryActiveGeneration = 0
		s.bulkRecvV4 = nil
		s.bulkRecvV6 = nil
		s.bulkInstallFailedV4 = nil
		s.bulkInstallFailedV6 = nil
		s.bulkZoneSnapshot = nil
		s.bulkRecvStartedAt = time.Time{}
		s.bulkRecvInvalid = false
	}
	s.bulkMu.Unlock()
	if invalid || late {
		slog.Warn("cluster sync: bulk receive window aborted; withholding BulkAck and failover release",
			"epoch", epoch, "late", late,
			"aborted_total", s.stats.BulkRecvAborted.Load(),
			"capped_total", s.stats.BulkRecvCapped.Load(),
			"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		s.scheduleBulkRerequest("bulk receive window aborted", bulkSerial)
		return false
	}
	if failedV4+failedV6 > 0 {
		// Do not reconcile this incomplete authoritative snapshot: absent
		// rows would be deleted. Keeping the receive window open also keeps
		// transfer readiness blocked until the sender's bounded bulk retry
		// re-requests the table. Semantic refusals are excluded from these
		// sets and retain their intentional-ACK behavior.
		slog.Warn("cluster sync: bulk contains transient helper install failures; withholding BulkAck and failover release",
			"epoch", epoch, "failed_v4", failedV4, "failed_v6", failedV6)
		s.scheduleBulkRerequest("transient helper install failures", bulkSerial)
		return false
	}
	reconciled, inventoryGen, inventoryRequested := s.reconcileStaleSessions(bulkSerial)
	if !reconciled {
		slog.Warn("cluster sync: bulk reconcile did not complete; withholding BulkAck and failover release",
			"epoch", epoch)
		s.scheduleBulkRerequest("bulk reconcile did not complete", bulkSerial)
		return false
	}
	s.noteBulkReconciled()
	s.stats.BulkSyncEndTime.Store(time.Now().UnixNano())
	slog.Info("cluster sync: bulk transfer complete", "epoch", epoch, "sessions", s.stats.BulkSyncSessions.Load(), "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
	s.sendBulkAck(conn, epoch)
	s.bulkEverCompleted.Store(true)
	if s.OnBulkSyncReceived != nil {
		go s.OnBulkSyncReceived()
	}
	if inventoryRequested {
		s.bulkMu.Lock()
		// A retry for the same helper generation is already covered by
		// this successful full inventory. A newer helper generation stays
		// pending and requires its own accepted bulk window.
		if s.inventoryPending && s.inventoryPendingGeneration == inventoryGen {
			s.inventoryPending = false
			s.inventoryPendingGeneration = 0
		}
		s.bulkMu.Unlock()
		if cb := s.OnSessionInventoryBulkReceived; cb != nil {
			go cb(inventoryGen)
		}
	}
	return true
}

func (s *SessionSync) handleBulkAck(conn net.Conn, payload []byte) bool {
	if len(payload) < 8 {
		slog.Warn("cluster sync: bulk ack message too short")
		return false
	}
	epoch := binary.LittleEndian.Uint64(payload[:8])
	stats := s.Stats()
	slog.Info("cluster sync: bulk ack received", "epoch", epoch, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	// #9508: load the capture BEFORE the pending epoch (barrierFence.pendingBulk).
	fenceCapture := s.fence.pendingBulk.Load()
	pending := s.pendingBulkAckEpoch.Load()
	// #9177 V053: `!=`, not `<`. The authority here is LOCAL --
	// pendingBulkAckEpoch is set by our OWN send path under bulkSendMu
	// (sync_bulk.go, record-then-send) BEFORE the BulkEnd write, so it is by
	// construction the largest epoch this node has ever put on the wire. A
	// conforming peer cannot echo a larger one, so a FUTURE epoch is not an
	// ack for anything; accepting it cleared `pending`, latched
	// bulkEverCompleted / outboundBulkAcked and fired OnBulkSyncAckReceived,
	// releasing the #3912 failover gate on a bulk that never completed.
	// Reachability is honest: this needs a non-conforming or compromised
	// peer past the #5303 pre-auth admission. It is fixed because the
	// comparator has no reason to be loose and the tightening costs one
	// operator and no new input.
	if pending == 0 || epoch != pending {
		// #5272: a BulkAck with no matching pending outbound bulk (we
		// never sent a bulk we are awaiting the ack for, or this ack is
		// for a stale/older epoch) is spurious or replayed. Setting
		// bulkEverCompleted / outboundBulkAcked and firing
		// OnBulkSyncAckReceived would release the outbound-bulk safety
		// gate (and suppress the #4090/#4360 stranded-bulk re-drive) with
		// no real outbound transfer having been acknowledged. Ignore it.
		// The gate is LOCAL pending-outbound state (recorded before we
		// write the BulkEnd, #3912) — no wire field, no version bump — so
		// a legacy peer's legitimate ack of our outbound bulk still
		// completes.
		slog.Debug("cluster sync: ignoring BulkAck with no pending outbound bulk", "got", epoch, "pending", pending)
		return false
	}
	owed := s.pendingBulkOwed.Load() // #9626: the debt this bulk was sent to pay
	s.clearPendingBulkAck()
	s.bulkAckRetryOwed.Store(false)
	s.bulkEverCompleted.Store(true)
	// #4360: the peer acked OUR outbound bulk — record it on the
	// outbound-only flag so a stranded outbound bulk can be re-driven on a
	// survivor fabric independently of whether an inbound bulk (which also
	// sets bulkEverCompleted at syncMsgBulkEnd) completed first.
	s.outboundBulkAcked.Store(true)
	// #9626: discharge the cold-prime debt before publishing fence
	// clearance. A barrier may sample both states in that handoff.
	s.dischargeColdPrime(owed)
	// #9508: only expose the re-prime's fence clearance after its matching
	// cold-prime debt is discharged.
	s.dischargeBarrierFence(fenceCapture)
	if s.OnBulkSyncAckReceived != nil {
		go s.OnBulkSyncAckReceived()
	}
	return true
}
