package cluster

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// malformedRecordWarnDetector bounds the "dropping malformed session record"
// warnings (v4/v6 arms in handleMessage, #10724 DR-26:A5-F5). Shape mirrors
// monitorTruncationDetector: the per-record count advances on every occurrence
// via stats.MalformedRecordsDropped, while the log emits once per family per
// SessionSync lifetime — the receive path runs per record, so an unguarded
// Warn lets a corrupt or hostile peer flood the log (CLAUDE.md logging rules).
// Separate Once guards per family so a v4 flood cannot silence the first v6
// occurrence and vice versa.
type malformedRecordWarnDetector struct {
	v4 sync.Once
	v6 sync.Once
}

// observeV4 records one malformed v4 session record of nbytes, emitting the
// warning only for the first occurrence. droppedTotal is the running
// MalformedRecordsDropped count, reported so the single emission still shows
// the volume behind it.
func (d *malformedRecordWarnDetector) observeV4(nbytes int, droppedTotal uint64) {
	d.v4.Do(func() {
		slog.Warn("cluster sync: dropping malformed v4 session record — no session installed",
			"bytes", nbytes, "dropped_total", droppedTotal)
	})
}

// observeV6 is the v6 twin of observeV4.
func (d *malformedRecordWarnDetector) observeV6(nbytes int, droppedTotal uint64) {
	d.v6.Do(func() {
		slog.Warn("cluster sync: dropping malformed v6 session record — no session installed",
			"bytes", nbytes, "dropped_total", droppedTotal)
	})
}

func (s *SessionSync) receiveLoop(ctx context.Context, conn net.Conn) {
	// #18521: every return below names itself. exit is logged ONCE per
	// connection and becomes the disconnect reason; before this, three of
	// the exits (a non-timeout header read error at Debug, a payload read
	// error and a heartbeat-probe write error with no log at all) left the
	// journal with a bare "fabric N disconnected".
	exit := recvExit{reason: "unknown"}
	diag := syncConnDiagFor(conn)
	watchDone := make(chan struct{})
	s.startConnWatch(ctx, conn, watchDone)
	defer func() {
		close(watchDone)
		s.logReceiveLoopExit(conn, exit)
		s.disconnectConnNow(conn, "receive loop: "+exit.reason, exit.err)
	}()
	hdrBuf := make([]byte, syncHeaderSize)
	readDeadline := s.readDeadlineDuration()
	missedHeartbeats := 0
	// #16041 fold: the read deadline is ABSOLUTE per connection epoch,
	// not restarted per frame. It is armed once here, re-armed only when
	// a heartbeat timeout is handled below, and cleared-recomputed only
	// on semantic acceptance (handleMessage == true) — never on a
	// rejected frame. Before this, every well-framed rejected frame
	// restarted the full window, so a peer streaming junk at any rate
	// below one frame per window never produced a single timeout, the
	// missed-heartbeat teardown never ran, and the peer's heartbeat
	// probes were never even sent. With an absolute deadline the junk
	// stream hits the timeout on the original schedule, the teardown
	// counts it, and only an accepted frame (typically the peer's
	// HeartbeatAck answering our probe) earns the next window.
	nextReadDeadline := time.Now().Add(readDeadline)
	for {
		select {
		case <-ctx.Done():
			exit = recvExit{reason: recvExitContextDone}
			return
		default:
		}
		conn.SetReadDeadline(nextReadDeadline)
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if ctx.Err() != nil {
				exit = recvExit{reason: recvExitContextDone}
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// #16039 fold 2: the read-timeout tick is the timer for a
				// silent peer, which by definition sends no next frame for
				// the on-receive check to run on. Expire the bulk window
				// here (before the heartbeat-ack teardown, so the tick
				// that closes the connection still expires exactly once).
				s.expireBulkWindowIfStale()
				if s.peerIncarnationState().peerHeartbeatAckEver.Load() {
					missedHeartbeats++
				}
				if missedHeartbeats >= 2 {
					slog.Warn("cluster sync: heartbeat ack timeout, closing stale connection", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "missed_heartbeats", missedHeartbeats)
					exit = recvExit{reason: "heartbeat ack timeout"}
					return
				}
				s.writeMu.Lock()
				err := writeMsg(conn, syncMsgHeartbeat, nil)
				s.writeMu.Unlock()
				if err != nil {
					exit = recvExit{reason: "heartbeat probe write failed", err: err}
					return
				}
				// The probe earns the peer one fresh absolute window to
				// answer in; without this the already-expired deadline
				// would spin-timeout without ever reading the ack.
				nextReadDeadline = time.Now().Add(readDeadline)
				continue
			}
			slog.Debug("cluster sync: read header error", "err", err)
			exit = classifyRecvReadErr("header", err)
			return
		}
		var hdr syncHeader
		copy(hdr.Magic[:], hdrBuf[:4])
		hdr.Type = hdrBuf[4]
		hdr.Length = binary.LittleEndian.Uint32(hdrBuf[8:12])
		if hdr.Magic != syncMagic {
			slog.Warn("cluster sync: bad magic")
			s.stats.Errors.Add(1)
			exit = recvExit{reason: "bad magic"}
			return
		}
		// #16041: per-type payload cap, decided from the header BEFORE the
		// payload is allocated or read. A known type declaring more than
		// its encoder can emit is non-conforming; the length desyncs the
		// stream, so the connection drops (the global-cap posture refined
		// per type). Unknown types keep only the global bound below: a
		// newer peer's additive type must stay forward-compatible.
		if cap, known := syncPayloadCap(hdr.Type); known && hdr.Length > uint32(cap) {
			s.refuseOversizeFrame(hdr.Type, hdr.Length, cap)
			exit = recvExit{reason: "oversize frame for type " + syncMsgName(hdr.Type)}
			return
		}
		var payload []byte
		if hdr.Length > 0 {
			if hdr.Length > maxSyncPayload {
				s.stats.Errors.Add(1)
				slog.Warn("cluster sync: payload too large", "len", hdr.Length)
				exit = recvExit{reason: "payload too large"}
				return
			}
			payload = make([]byte, hdr.Length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				if ctx.Err() != nil {
					exit = recvExit{reason: recvExitContextDone}
					return
				}
				exit = classifyRecvReadErr("payload", err)
				return
			}
		}
		// #4107 F23: on an authenticated connection every frame carries a
		// per-connection sequence + HMAC trailer. Read and verify it before the
		// message is trusted; a bad HMAC (forgery/tamper) or a non-increasing
		// sequence (replay/regression) drops the connection.
		if ac, ok := conn.(*authConn); ok && ac.readAuthed() {
			trailer := make([]byte, syncAuthFrameTrailerSize)
			if _, err := io.ReadFull(conn, trailer); err != nil {
				if ctx.Err() != nil {
					exit = recvExit{reason: recvExitContextDone}
					return
				}
				slog.Debug("cluster sync: read auth trailer error", "err", err)
				exit = classifyRecvReadErr("auth trailer", err)
				return
			}
			if err := ac.verifyFrame(hdrBuf, payload, trailer); err != nil {
				slog.Warn("cluster sync: frame authentication failed, dropping connection",
					"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "err", err)
				s.stats.Errors.Add(1)
				exit = recvExit{reason: "frame authentication failed", err: err}
				return
			}
		}
		// #16041: liveness refreshes ONLY on semantic accept. A
		// well-framed but rejected frame (unknown type, malformed,
		// stale, superseded, downstream-refused) must not reset the
		// missed-heartbeat count, the last-receive stamp, or the
		// absolute read deadline, or a faulty keyed peer sending junk
		// forever would mask its own failover trigger.
		if s.handleFrame(conn, diag, hdr.Type, payload) {
			// #18521 review round 2: frames drained after the peer reset
			// the connection were sent before it did; they prove nothing
			// about the peer being alive NOW, and counting them would hold
			// off the heartbeat-timeout peer-loss decision for a peer that
			// stopped.
			if diag == nil || !diag.peerReset.Load() {
				s.notePeerLiveness(&missedHeartbeats)
			}
			nextReadDeadline = time.Now().Add(readDeadline)
		}
	}
}

// handleFrame runs one handleMessage call with the #18521 instrumentation:
// frame/byte/handler-time counters for the per-connection summary, the
// in-flight marker the watchdog reports a stuck call from, and a report of a
// call that kept the loop off the socket for the slow threshold — at most one
// per syncSlowHandlerLogInterval per connection, the rest counted
// (noteSlowHandler). Nothing here logs per message. Timed on s.nowMono, the
// clock the watchdog reads the in-flight marker with.
func (s *SessionSync) handleFrame(conn net.Conn, diag *syncConnDiag, msgType uint8, payload []byte) bool {
	if diag == nil {
		return s.handleMessage(conn, msgType, payload)
	}
	diag.framesRead.Add(1)
	diag.bytesRead.Add(uint64(syncHeaderSize + len(payload)))
	start := s.nowMono()
	diag.beginHandler(msgType, start)
	accepted := s.handleMessage(conn, msgType, payload)
	elapsed, stallWarned := diag.endHandler(msgType, start, s.nowMono())
	if elapsed >= s.slowHandlerThreshold() {
		diag.slowCalls.Add(1)
		s.noteSlowHandler(conn, diag, msgType, elapsed, false, stallWarned)
	}
	return accepted
}

// bulkReceiveProgress reports whether this session record is bulk
// traffic and, on the 1st/64th counted record, logs progress. #15254
// (A82-03): key on bulkInProgress, the live receive window, NOT the
// BulkSyncStartTime/BulkSyncEndTime telemetry pair. The pair is what
// status renders and lags the window at its edges (an abandoned bulk
// left End zero until the disconnect stamp; status reads the pair,
// counting must read the window). Records counted here are exactly the
// records the install arm below accumulates into bulkRecvV4/V6 under
// the same flag.
func (s *SessionSync) bulkReceiveProgress(typ string, conn net.Conn) {
	s.bulkMu.Lock()
	inProgress := s.bulkInProgress
	epoch := s.bulkRecvEpoch
	s.bulkMu.Unlock()
	if !inProgress {
		return
	}
	count := s.stats.BulkSyncSessions.Add(1)
	if count == 1 || count%64 == 0 {
		slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", typ, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
	}
}

// handleMessage dispatches one framed message to its receive handler and
// reports whether the frame was semantically accepted (#16041): the handler
// consumed it as a valid instance of its type (applied, queued, or matched
// a live waiter/incarnation). Rejected frames — unknown type, malformed,
// stale, out-of-order, superseded, undecryptable — return false, and
// receiveLoop refreshes peer liveness only on true. See
// sync_payload_caps_16041.go for the acceptance contract.
func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) bool {
	// #16039 fold: the window deadline is enforced on receive, not only
	// at BulkEnd — any inbound frame after the deadline expires the open
	// window. Fold 2 adds the timer arm: receiveLoop calls the same
	// expiry on every read-timeout tick, so a silent peer (no next
	// frame) still loses its window.
	s.expireBulkWindowIfStale()
	switch msgType {
	case syncMsgSessionV4:
		return s.handleSessionV4(conn, payload)
	case syncMsgSessionV6:
		return s.handleSessionV6(conn, payload)
	case syncMsgDeleteV4:
		return s.handleDeleteV4(conn, payload)
	case syncMsgDeleteV6:
		return s.handleDeleteV6(conn, payload)
	case syncMsgBulkRequest:
		return s.handleBulkRequest(conn, payload)
	case syncMsgBulkStart:
		return s.handleBulkStart(conn, payload)
	case syncMsgBulkEnd:
		return s.handleBulkEnd(conn, payload)
	case syncMsgBulkAck:
		return s.handleBulkAck(conn, payload)
	case syncMsgConfigApplyNack:
		return s.handleConfigApplyNack(conn, payload)
	case syncMsgConfigApplyAck:
		return s.handleConfigApplyAck(conn, payload)
	case syncMsgHeartbeat:
		return s.handleHeartbeat(conn, payload)
	case syncMsgHeartbeatAck:
		return s.handleHeartbeatAck(conn, payload)
	case syncMsgConfig:
		return s.handleConfig(conn, payload)
	case syncMsgConfigEncrypted:
		return s.handleConfigEncrypted(conn, payload)
	case syncMsgConfigKeyExchange:
		return s.handleConfigKeyExchangeFrame(conn, payload)
	case syncMsgAuthUpgradeRequest:
		return s.handleAuthUpgradeRequestFrame(conn, payload)
	case syncMsgAuthUpgradeHello:
		return s.handleAuthUpgradeHelloFrame(conn, payload)
	case syncMsgAuthUpgradeProof:
		return s.handleAuthUpgradeProofFrame(conn, payload)
	case syncMsgAuthUpgradeConfirm:
		return s.handleAuthUpgradeConfirmFrame(conn, payload)
	case syncMsgIPsecSA:
		return s.handleIPsecSA(conn, payload)
	case syncMsgIPsecSAChunk:
		return s.handleIPsecSAChunk(conn, payload)
	case syncMsgPersistentNatLease:
		return s.handlePersistentNatLease(conn, payload)
	case syncMsgPersistentNatLeaseScoped:
		return s.handlePersistentNatLeaseScoped(conn, payload)
	case syncMsgPersistentNatLeaseGeneration, syncMsgPersistentNatLeaseDeterministic,
		syncMsgPersistentNatLeaseProvenance, syncMsgPersistentNatLeaseDeterministicProvenance,
		syncMsgPersistentNatLeaseTypedPool, syncMsgPersistentNatLeaseDeterministicTypedPool:
		return s.handlePersistentNatLeaseGeneration(conn, msgType, payload)
	case syncMsgDHCPLeaseV4:
		return s.handleDHCPLeaseV4(conn, payload)
	case syncMsgDHCPLeaseV6:
		return s.handleDHCPLeaseV6(conn, payload)
	case syncMsgDHCPLeaseV4Chunk, syncMsgDHCPLeaseV6Chunk:
		return s.handleDHCPLeaseChunk(conn, msgType, payload)
	case syncMsgFailover:
		return s.handleFailover(conn, payload)
	case syncMsgFailoverAck:
		return s.handleFailoverAck(conn, payload)
	case syncMsgFailoverCommit:
		return s.handleFailoverCommitFrame(conn, payload)
	case syncMsgFailoverCommitAck:
		return s.handleFailoverCommitAck(conn, payload)
	case syncMsgFailoverBatch:
		return s.handleFailoverBatchFrame(conn, payload)
	case syncMsgFailoverBatchAck:
		return s.handleFailoverBatchAck(conn, payload)
	case syncMsgFailoverBatchCommit:
		return s.handleFailoverBatchCommitFrame(conn, payload)
	case syncMsgFailoverBatchCommitAck:
		return s.handleFailoverBatchCommitAck(conn, payload)
	case syncMsgFailoverAbort:
		return s.handleFailoverAbortFrame(conn, payload)
	case syncMsgFailoverBatchAbort:
		return s.handleFailoverBatchAbortFrame(conn, payload)
	case syncMsgFence:
		return s.handleFence(conn, payload)
	case syncMsgFenceAck:
		return s.handleFenceAck(conn, payload)
	case syncMsgPeerCapabilities:
		return s.handlePeerCapabilities(conn, payload)
	case syncMsgClockSync:
		return s.handleClockSync(conn, payload)
	case syncMsgBarrier:
		return s.handleBarrier(conn, payload)
	case syncMsgBarrierAck:
		return s.handleBarrierAck(conn, payload)
	}
	return false
}

// handleConfigPayload processes a decoded config-sync payload, whether it
// arrived in the clear (syncMsgConfig) or sealed (syncMsgConfigEncrypted,
// #6629). Both arms funnel here because the receiver-side ordering, the
// generation high-water accounting and the apply-queue admission must be
// identical for the two — a divergence between them is always a bug, so the
// behaviour is single-sourced rather than duplicated and kept in agreement.
// The conn parameter is #5084: the payload is stamped with the boot incarnation
// the CONNECTION primed under, so a payload queued from a peer's prior boot can
// be dropped at apply time rather than applying across a reset and stranding
// the high-water.
func (s *SessionSync) handleConfigPayload(conn net.Conn, payload []byte, cleartext bool) bool {
	s.stats.ConfigsReceived.Add(1)
	if cleartext {
		// Latch reception as well as sends: this node has the same exposure
		// fact even when the peer selected the fallback.
		s.stats.ConfigsReceivedCleartext.Add(1)
		s.stats.CleartextSyncAlarmLatched.Store(true)
	}
	s.stats.LastConfigSyncTime.Store(time.Now().UnixNano())
	configText, gen, ancestry := decodeConfigPayloadWithAncestry(payload)
	s.stats.LastConfigSyncSize.Store(uint64(len(configText)))
	slog.Info("cluster sync: config received from peer", "size", len(configText), "gen", gen)
	// #5563: advance the received-config high-water BEFORE enqueue. This is
	// the receiver's view of the peer's current committed generation and
	// gates manual-failover readiness against lastAppliedConfigGen. Record it
	// even if the enqueue below drops the payload (queue full) so the standby
	// stays flagged config-stale until the apply actually lands on a re-push.
	// It stays a monotonic max so a reordered older frame cannot pull it
	// down. #5084: the load/compare/store moved into recordRecvConfigGen and
	// is taken under configGenMu — the prior justification here ("the
	// receiveLoop is single-threaded per connection, so the load/store pair
	// needs no CAS") holds per connection but there are TWO receive loops,
	// so a raise driven by one fabric raced resetRecvGen's clear driven by
	// the other and could re-raise the mark that clear had just zeroed.
	// #5084: a payload arriving under a peer boot incarnation that a re-prime
	// has ALREADY replaced is dead, and has to be refused here as well as at
	// apply. recordRecvConfigGen below is a monotone max that gates
	// manual-failover readiness (#5563 refuses promotion while PeerConfigGen >
	// AppliedConfigGen), and a dead incarnation's generation is drawn from the
	// peer's PRE-reboot counter, so it is far higher than anything the live
	// incarnation can produce. Raising the received mark for a payload the
	// apply loop is then going to drop would strand the standby reading
	// config-stale, with nothing able to close the gap short of another
	// re-prime — trading the #5084 divergence for a different silent wedge.
	//
	// The apply-time check is NOT made redundant by this one. This site sees
	// only payloads that ARRIVE after the switch; the apply-time site catches a
	// payload that was already QUEUED when the re-prime landed, which is the
	// reported defect ("resetRecvGen does not drain items already queued from
	// the prior boot"). Neither site subsumes the other.
	authenticated := false
	if ac, ok := conn.(*authConn); ok {
		authenticated = ac.readAuthed()
	}
	item := configApplyItem{
		gen: gen, text: configText, ancestry: ancestry,
		incarnation: s.connBootIncarnation(conn), authenticated: authenticated,
		conn: conn,
	}
	if s.configItemIncarnationStale(item) {
		s.stats.ConfigsDeadIncarnationDropped.Add(1)
		slog.Warn("cluster sync: dropping config received under a replaced peer boot "+
			"incarnation — the peer rebooted and re-primed, so this payload's generation "+
			"is incomparable with the current one (#5084)",
			"item_incarnation", item.incarnation.String(),
			"current_incarnation", s.PeerBootIncarnation().String(),
			"gen", gen, "size", len(configText), "remote", connRemoteAddrString(conn))
		return false
	}
	s.recordRecvConfigGen(gen)
	// #3931: enqueue onto the single-consumer ordered apply queue instead
	// of spawning a racing `go OnConfigReceived`. The receiveLoop is
	// single-threaded per connection, so this preserves receive order;
	// configApplyLoop then applies only strictly-newer generations. The
	// enqueue is non-blocking so a slow apply never stalls session sync /
	// heartbeats on this connection.
	if s.configApplyCh != nil {
		// #16041 fold: a queue-full config was dropped, not queued — the
		// downstream result is rejection, so it must not refresh liveness
		// even though the payload decoded and the high-water was raised
		// (the config-stale gate above is deliberately unchanged).
		queued := true
		select {
		case s.configApplyCh <- item:
		default:
			// #6778: the ordered apply queue is full. The non-blocking send
			// discards the INCOMING payload — which is the NEWEST generation
			// the peer has sent — while the queue retains the older ones, so
			// this node ends the drain applying a SUPERSEDED config. That
			// inversion is what makes the drop a wedge rather than a blip: the
			// received high-water was already raised above (deliberately, so
			// the node reads config-stale and #5563 refuses manual-failover
			// promotion), and before this fix nothing on either node was
			// driving the missing generation back.
			//
			// The queue-full drop is treated as the same class of event as an
			// apply failure, because the operator consequence is identical (the
			// standby is behind the primary's committed config) and the repair
			// is the one this repo already built:
			//
			//   counter  ConfigsQueueFullDropped, rendered in cluster status —
			//            distinct from ConfigsApplyFailed because the apply
			//            never ran, and from the generic Errors counter because
			//            a stale standby is its own operator action.
			//   debt     noteConfigApplyFailure arms the #6387 grace timer, so a
			//            drop that does NOT re-converge inside the grace raises
			//            the CF config-sync health annotation on its own — no
			//            further delivery required. A drop that re-converges
			//            cancels the timer on the successful apply, so a
			//            transient saturation never flaps the flag.
			//   retry    sendConfigApplyNack re-arms the SENDER's #5863
			//            (epoch x generation) push marker via
			//            OnPeerConfigApplyFailed, and the sender's existing
			//            30s configSyncReconcileLoop re-pushes. No new retry
			//            queue: buffering the dropped payload here is exactly
			//            the unbounded growth the non-blocking send exists to
			//            avoid, and the payload is the peer's ACTIVE config, so
			//            re-asking for it is strictly better than holding a
			//            copy that may already be superseded.
			//
			// Writing the nack from the receive loop is the established shape
			// in this switch (the heartbeat ack and sendBulkAck do the same
			// under writeMu). It is rate-bounded by the peer's push rate, which
			// is itself bounded by the queue depth that produced the drop.
			s.stats.ConfigsQueueFullDropped.Add(1)
			s.stats.Errors.Add(1)
			slog.Error("cluster sync: config apply queue full, dropping the NEWEST config generation — "+
				"this node stays on a superseded config until the peer re-pushes (#6778)",
				"gen", gen, "size", len(configText),
				"queue_len", len(s.configApplyCh), "queue_cap", cap(s.configApplyCh))
			s.noteConfigApplyFailure(errConfigApplyQueueFull)
			s.sendConfigApplyNack(gen)
			queued = false
		}
		return queued
	}
	return true
}

// bulkRecvWindowTimeout bounds one accepted bulk receive window (#16039).
// A legitimate full-table bulk is re-driven by the sender after
// BulkAckPendingRetryAfter (35s) when its ack is withheld, and the daemon
// retry can take up to ~150s; an hour is two orders of magnitude beyond
// that cadence, so only a peer holding the window open trips it. The
// deadline is enforced on receive (expireBulkWindowIfStale, called at
// the top of handleMessage) and again at BulkEnd: expiry closes the
// window, frees its maps, and latches bulkIncomplete readiness debt
// until a later bulk reconciles successfully.
const bulkRecvWindowTimeout = time.Hour

// bulkRecvNow returns the bulk window clock (test-overridable).
func (s *SessionSync) bulkRecvNow() time.Time {
	if s != nil && s.testBulkRecvNow != nil {
		return s.testBulkRecvNow()
	}
	return time.Now()
}

// bulkRecvCap is the ceiling for the combined distinct keys in one bulk
// receive window (#16039): the forward-session table capacity. Forward
// keys are half of dataplane.MaxSessions, which counts forward+reverse
// entries; the wired helper capacity (SetGenGuardSessionCap) replaces
// the ceiling when known, exactly as maxCap clamps the gen-guard caps.
// A zero result (only reachable via a zero genGuardMapCeilingOverride
// with an empty wired report, which maxCap never returns) admits nothing.
func (s *SessionSync) bulkRecvCap() int {
	if s == nil {
		return 0
	}
	return s.maxCap()
}

// expireBulkWindowIfStale aborts an open bulk window whose deadline has
// passed (#16039 fold). It has two callers, and both are load-bearing:
// the top of every handleMessage (a peer that never sends BulkEnd loses
// its window on its next frame), and receiveLoop's read-timeout branch
// (fold 2: a peer that goes fully silent sends no next frame, so the
// read-deadline tick — every readDeadlineDuration, 10s by default — is
// the timer that fires the expiry). Aborting closes the window and
// frees the accumulators, but latches bulkIncomplete so
// TransferReadiness keeps blocking manual failover until a later bulk
// reconciles. Exactly one abort is counted per window (guarded by
// bulkRecvInvalid under bulkMu); concurrent callers on the two fabric
// loops and the timeout tick serialize on bulkMu.
func (s *SessionSync) expireBulkWindowIfStale() {
	if s == nil {
		return
	}
	s.bulkMu.Lock()
	if !s.bulkInProgress || s.bulkRecvInvalid || s.bulkRecvStartedAt.IsZero() ||
		s.bulkRecvNow().Sub(s.bulkRecvStartedAt) <= bulkRecvWindowTimeout {
		s.bulkMu.Unlock()
		return
	}
	epoch := s.bulkRecvEpoch
	s.bulkRecvInvalid = true
	s.stats.BulkRecvAborted.Add(1)
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
	s.bulkMu.Unlock()
	slog.Warn("cluster sync: bulk receive window expired past deadline; window aborted, awaiting successful bulk reconcile",
		"epoch", epoch, "aborted_total", s.stats.BulkRecvAborted.Load())
}

// removeBulkRecvV4 frees key's slot in the receive window on a successful
// delete (#16039 fold): the cap is on live occupancy, so a deleted key
// no longer counts against it and a replacement install may take its
// place. No-op outside a window or for a key the window never held.
func (s *SessionSync) removeBulkRecvV4(key dataplane.SessionKey) {
	s.bulkMu.Lock()
	if s.bulkInProgress && s.bulkRecvV4 != nil {
		delete(s.bulkRecvV4, key)
	}
	s.bulkMu.Unlock()
}

// removeBulkRecvV6 is the IPv6 twin of removeBulkRecvV4.
func (s *SessionSync) removeBulkRecvV6(key dataplane.SessionKeyV6) {
	s.bulkMu.Lock()
	if s.bulkInProgress && s.bulkRecvV6 != nil {
		delete(s.bulkRecvV6, key)
	}
	s.bulkMu.Unlock()
}

// admitBulkRecvV4 records key in the active bulk window unless the window
// is invalid or full (#16039). Admission precedes the install verdict
// because a key whose helper install fails transiently must still count
// as received (its retry marker lives in bulkInstallFailedV4); the cap is
// what keeps that pre-verdict accumulation bounded. A distinct key past
// the cap invalidates the window exactly once; further distinct keys are
// counted and dropped without storing. Duplicate keys are free.
func (s *SessionSync) admitBulkRecvV4(key dataplane.SessionKey) {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	if !s.bulkInProgress {
		return
	}
	if s.bulkRecvInvalid {
		s.stats.BulkRecvCapped.Add(1)
		return
	}
	if _, ok := s.bulkRecvV4[key]; ok {
		return
	}
	if len(s.bulkRecvV4)+len(s.bulkRecvV6) >= s.bulkRecvCap() {
		s.bulkRecvInvalid = true
		s.stats.BulkRecvCapped.Add(1)
		s.stats.BulkRecvAborted.Add(1)
		slog.Warn("cluster sync: bulk receive window exceeds table capacity; window aborted",
			"cap", s.bulkRecvCap(), "recv_v4", len(s.bulkRecvV4), "recv_v6", len(s.bulkRecvV6),
			"epoch", s.bulkRecvEpoch)
		return
	}
	if s.bulkRecvV4 == nil {
		s.bulkRecvV4 = make(map[dataplane.SessionKey]struct{})
	}
	s.bulkRecvV4[key] = struct{}{}
}

// admitBulkRecvV6 is the IPv6 twin of admitBulkRecvV4.
func (s *SessionSync) admitBulkRecvV6(key dataplane.SessionKeyV6) {
	s.bulkMu.Lock()
	defer s.bulkMu.Unlock()
	if !s.bulkInProgress {
		return
	}
	if s.bulkRecvInvalid {
		s.stats.BulkRecvCapped.Add(1)
		return
	}
	if _, ok := s.bulkRecvV6[key]; ok {
		return
	}
	if len(s.bulkRecvV4)+len(s.bulkRecvV6) >= s.bulkRecvCap() {
		s.bulkRecvInvalid = true
		s.stats.BulkRecvCapped.Add(1)
		s.stats.BulkRecvAborted.Add(1)
		slog.Warn("cluster sync: bulk receive window exceeds table capacity; window aborted",
			"cap", s.bulkRecvCap(), "recv_v4", len(s.bulkRecvV4), "recv_v6", len(s.bulkRecvV6),
			"epoch", s.bulkRecvEpoch)
		return
	}
	if s.bulkRecvV6 == nil {
		s.bulkRecvV6 = make(map[dataplane.SessionKeyV6]struct{})
	}
	s.bulkRecvV6[key] = struct{}{}
}
