package cluster

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
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
	defer func() {
		s.handleDisconnect(conn)
	}()
	hdrBuf := make([]byte, syncHeaderSize)
	readDeadline := s.readDeadlineDuration()
	missedHeartbeats := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(readDeadline))
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if s.peerHeartbeatAckEver.Load() {
					missedHeartbeats++
				}
				if missedHeartbeats >= 2 {
					slog.Warn("cluster sync: heartbeat ack timeout, closing stale connection", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "missed_heartbeats", missedHeartbeats)
					return
				}
				s.writeMu.Lock()
				err := writeMsg(conn, syncMsgHeartbeat, nil)
				s.writeMu.Unlock()
				if err != nil {
					return
				}
				continue
			}
			slog.Debug("cluster sync: read header error", "err", err)
			return
		}
		var hdr syncHeader
		copy(hdr.Magic[:], hdrBuf[:4])
		hdr.Type = hdrBuf[4]
		hdr.Length = binary.LittleEndian.Uint32(hdrBuf[8:12])
		if hdr.Magic != syncMagic {
			slog.Warn("cluster sync: bad magic")
			s.stats.Errors.Add(1)
			return
		}
		var payload []byte
		if hdr.Length > 0 {
			if hdr.Length > maxSyncPayload {
				s.stats.Errors.Add(1)
				slog.Warn("cluster sync: payload too large", "len", hdr.Length)
				return
			}
			payload = make([]byte, hdr.Length)
			if _, err := io.ReadFull(conn, payload); err != nil {
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
					return
				}
				slog.Debug("cluster sync: read auth trailer error", "err", err)
				return
			}
			if err := ac.verifyFrame(hdrBuf, payload, trailer); err != nil {
				slog.Warn("cluster sync: frame authentication failed, dropping connection",
					"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "err", err)
				s.stats.Errors.Add(1)
				return
			}
		}
		missedHeartbeats = 0
		s.lastPeerRxMono.Store(MonotonicNanos())
		s.handleMessage(conn, hdr.Type, payload)
	}
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
func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) {
	switch msgType {
	case syncMsgSessionV4:
		s.handleSessionV4(conn, payload)
	case syncMsgSessionV6:
		s.handleSessionV6(conn, payload)
	case syncMsgDeleteV4:
		s.handleDeleteV4(conn, payload)
	case syncMsgDeleteV6:
		s.handleDeleteV6(conn, payload)
	case syncMsgBulkRequest:
		s.handleBulkRequest(conn, payload)
	case syncMsgBulkStart:
		s.handleBulkStart(conn, payload)
	case syncMsgBulkEnd:
		s.handleBulkEnd(conn, payload)
	case syncMsgBulkAck:
		s.handleBulkAck(conn, payload)
	case syncMsgConfigApplyNack:
		s.handleConfigApplyNack(conn, payload)
	case syncMsgConfigApplyAck:
		s.handleConfigApplyAck(conn, payload)
	case syncMsgHeartbeat:
		s.handleHeartbeat(conn, payload)
	case syncMsgHeartbeatAck:
		s.handleHeartbeatAck(conn, payload)
	case syncMsgConfig:
		s.handleConfig(conn, payload)
	case syncMsgConfigEncrypted:
		s.handleConfigEncrypted(conn, payload)
	case syncMsgConfigKeyExchange:
		s.handleConfigKeyExchangeFrame(conn, payload)
	case syncMsgAuthUpgradeRequest:
		s.handleAuthUpgradeRequestFrame(conn, payload)
	case syncMsgAuthUpgradeHello:
		s.handleAuthUpgradeHelloFrame(conn, payload)
	case syncMsgAuthUpgradeProof:
		s.handleAuthUpgradeProofFrame(conn, payload)
	case syncMsgAuthUpgradeConfirm:
		s.handleAuthUpgradeConfirmFrame(conn, payload)
	case syncMsgIPsecSA:
		s.handleIPsecSA(conn, payload)
	case syncMsgPersistentNatLease:
		s.handlePersistentNatLease(conn, payload)
	case syncMsgPersistentNatLeaseScoped:
		s.handlePersistentNatLeaseScoped(conn, payload)
	case syncMsgPersistentNatLeaseGeneration, syncMsgPersistentNatLeaseDeterministic:
		s.handlePersistentNatLeaseGeneration(conn, msgType, payload)
	case syncMsgDHCPLeaseV4:
		s.handleDHCPLeaseV4(conn, payload)
	case syncMsgDHCPLeaseV6:
		s.handleDHCPLeaseV6(conn, payload)
	case syncMsgDHCPLeaseV4Chunk, syncMsgDHCPLeaseV6Chunk:
		s.handleDHCPLeaseChunk(conn, msgType, payload)
	case syncMsgFailover:
		s.handleFailover(conn, payload)
	case syncMsgFailoverAck:
		s.handleFailoverAck(conn, payload)
	case syncMsgFailoverCommit:
		s.handleFailoverCommitFrame(conn, payload)
	case syncMsgFailoverCommitAck:
		s.handleFailoverCommitAck(conn, payload)
	case syncMsgFailoverBatch:
		s.handleFailoverBatchFrame(conn, payload)
	case syncMsgFailoverBatchAck:
		s.handleFailoverBatchAck(conn, payload)
	case syncMsgFailoverBatchCommit:
		s.handleFailoverBatchCommitFrame(conn, payload)
	case syncMsgFailoverBatchCommitAck:
		s.handleFailoverBatchCommitAck(conn, payload)
	case syncMsgFailoverAbort:
		s.handleFailoverAbortFrame(conn, payload)
	case syncMsgFailoverBatchAbort:
		s.handleFailoverBatchAbortFrame(conn, payload)
	case syncMsgFence:
		s.handleFence(conn, payload)
	case syncMsgFenceAck:
		s.handleFenceAck(conn, payload)
	case syncMsgPeerCapabilities:
		s.handlePeerCapabilities(conn, payload)
	case syncMsgClockSync:
		s.handleClockSync(conn, payload)
	case syncMsgBarrier:
		s.handleBarrier(conn, payload)
	case syncMsgBarrierAck:
		s.handleBarrierAck(conn, payload)
	}
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
func (s *SessionSync) handleConfigPayload(conn net.Conn, payload []byte, cleartext bool) {
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
		return
	}
	s.recordRecvConfigGen(gen)
	// #3931: enqueue onto the single-consumer ordered apply queue instead
	// of spawning a racing `go OnConfigReceived`. The receiveLoop is
	// single-threaded per connection, so this preserves receive order;
	// configApplyLoop then applies only strictly-newer generations. The
	// enqueue is non-blocking so a slow apply never stalls session sync /
	// heartbeats on this connection.
	if s.configApplyCh != nil {
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
		}
	}
}
