package cluster

import (
	"encoding/binary"
	"log/slog"
	"net"
	"time"
)

// Receive handlers for failover, fence, capability, clock, and barrier
// frames, extracted verbatim from handleMessage (#16168). The *Frame
// suffix avoids colliding with the pre-existing handleRemoteFailover*
// workers these delegates spawn. All go statements, counters, and
// lock choreography are unchanged.
func (s *SessionSync) handleFailover(conn net.Conn, payload []byte) bool {
	if len(payload) < 9 {
		slog.Warn("cluster sync: failover message too short")
		return false
	}
	rgID := int(payload[0])
	reqID := binary.LittleEndian.Uint64(payload[1:9])
	slog.Info("cluster sync: remote failover request received", "rg", rgID, "req_id", reqID)
	go s.handleRemoteFailover(conn, rgID, reqID)
	return true
}

func (s *SessionSync) handleFailoverAck(conn net.Conn, payload []byte) bool {
	if len(payload) < 10 {
		slog.Warn("cluster sync: failover ack message too short")
		return false
	}
	rgID := int(payload[0])
	status := payload[1]
	reqID := binary.LittleEndian.Uint64(payload[2:10])
	detail := string(payload[10:])
	slog.Info("cluster sync: failover ack received", "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
	return s.completeFailoverWait(rgID, reqID, failoverAck{status: status, detail: detail})
}

func (s *SessionSync) handleFailoverCommitFrame(conn net.Conn, payload []byte) bool {
	if len(payload) < 9 {
		slog.Warn("cluster sync: failover commit message too short")
		return false
	}
	rgID := int(payload[0])
	reqID := binary.LittleEndian.Uint64(payload[1:9])
	slog.Info("cluster sync: remote failover commit received", "rg", rgID, "req_id", reqID)
	go s.handleRemoteFailoverCommit(conn, rgID, reqID)
	return true
}

func (s *SessionSync) handleFailoverCommitAck(conn net.Conn, payload []byte) bool {
	if len(payload) < 10 {
		slog.Warn("cluster sync: failover commit ack message too short")
		return false
	}
	rgID := int(payload[0])
	status := payload[1]
	reqID := binary.LittleEndian.Uint64(payload[2:10])
	detail := string(payload[10:])
	slog.Info("cluster sync: failover commit ack received", "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
	return s.completeFailoverCommitWait(rgID, reqID, failoverAck{status: status, detail: detail})
}

func (s *SessionSync) handleFailoverBatchFrame(conn net.Conn, payload []byte) bool {
	rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
	if err != nil {
		slog.Warn("cluster sync: batch failover message decode failed", "err", err)
		return false
	}
	slog.Info("cluster sync: remote batch failover request received", "rgs", rgIDs, "req_id", reqID)
	go s.handleRemoteFailoverBatch(conn, rgIDs, reqID)
	return true
}

func (s *SessionSync) handleFailoverBatchAck(conn net.Conn, payload []byte) bool {
	rgIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
	if err != nil {
		slog.Warn("cluster sync: batch failover ack decode failed", "err", err)
		return false
	}
	slog.Info("cluster sync: batch failover ack received", "rgs", rgIDs, "req_id", reqID, "status", status, "detail", detail)
	return s.completeFailoverBatchWait(failoverBatchKey(rgIDs), reqID, failoverAck{status: status, detail: detail})
}

func (s *SessionSync) handleFailoverBatchCommitFrame(conn net.Conn, payload []byte) bool {
	rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
	if err != nil {
		slog.Warn("cluster sync: batch failover commit message decode failed", "err", err)
		return false
	}
	slog.Info("cluster sync: remote batch failover commit received", "rgs", rgIDs, "req_id", reqID)
	go s.handleRemoteFailoverCommitBatch(conn, rgIDs, reqID)
	return true
}

func (s *SessionSync) handleFailoverBatchCommitAck(conn net.Conn, payload []byte) bool {
	rgIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
	if err != nil {
		slog.Warn("cluster sync: batch failover commit ack decode failed", "err", err)
		return false
	}
	slog.Info("cluster sync: batch failover commit ack received", "rgs", rgIDs, "req_id", reqID, "status", status, "detail", detail)
	return s.completeFailoverBatchCommitWait(failoverBatchKey(rgIDs), reqID, failoverAck{status: status, detail: detail})
}

func (s *SessionSync) handleFailoverAbortFrame(conn net.Conn, payload []byte) bool {
	if len(payload) < 9 {
		slog.Warn("cluster sync: failover abort message too short")
		return false
	}
	rgID := int(payload[0])
	reqID := binary.LittleEndian.Uint64(payload[1:9])
	slog.Info("cluster sync: remote failover abort received", "rg", rgID, "req_id", reqID)
	go s.handleRemoteFailoverAbort(rgID, reqID)
	return true
}

func (s *SessionSync) handleFailoverBatchAbortFrame(conn net.Conn, payload []byte) bool {
	rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
	if err != nil {
		slog.Warn("cluster sync: batch failover abort message decode failed", "err", err)
		return false
	}
	slog.Info("cluster sync: remote batch failover abort received", "rgs", rgIDs, "req_id", reqID)
	go s.handleRemoteFailoverAbortBatch(rgIDs, reqID)
	return true
}

func (s *SessionSync) handleFence(conn net.Conn, payload []byte) bool {
	s.stats.FencesReceived.Add(1)
	// #7147: a fence may carry an 8-byte sequence number asking for a
	// confirmation. A pre-#7147 sender writes a nil payload, which decodes
	// to seq 0 = "no ack requested" — the reserved value SendFenceAwait
	// never allocates (its sequences start at 1). Reading the payload
	// leniently is what makes the new field additive on an existing type.
	var fenceSeq uint64
	if len(payload) >= 8 {
		fenceSeq = binary.LittleEndian.Uint64(payload[:8])
	}
	slog.Warn("cluster sync: fence received from peer — disabling all RGs", "seq", fenceSeq)
	var fenceRes FenceResult
	if s.OnFenceReceived != nil {
		// Synchronous on purpose: the ack below must not claim a fence
		// that has not been applied yet.
		fenceRes = s.OnFenceReceived()
	}
	if fenceSeq != 0 {
		s.sendFenceAck(conn, fenceSeq, fenceRes)
	}
	return true
}

func (s *SessionSync) handleFenceAck(conn net.Conn, payload []byte) bool {
	// #7147. A malformed or truncated ack is DROPPED rather than partially
	// decoded: a short frame zero-filled into RGsFenced/RGsTotal/Status
	// would decode to status 0 == FenceAckOK, i.e. a corrupt frame would
	// read as a successful confirmation. The sender's timeout covers the
	// drop and fails open.
	ack, ok := decodeFenceAckPayload(payload)
	if !ok {
		slog.Warn("cluster sync: fence ack message too short", "len", len(payload))
		return false
	}
	return s.completeFenceAckWait(ack)
}

func (s *SessionSync) handlePeerCapabilities(conn net.Conn, payload []byte) bool {
	// #6650. Length-gated with the #2170 trailing-field discipline: a
	// SHORTER frame than we expect is a peer we cannot interpret, so it is
	// ignored (leaving the 0 = incapable default) rather than partially
	// decoded; a LONGER one is a newer peer with extra fields we skip.
	if len(payload) < 2 {
		slog.Warn("cluster sync: peer capabilities message too short", "len", len(payload))
		return false
	}
	peerProto := binary.LittleEndian.Uint16(payload[:2])
	oldProto := s.peerSnaps.peerSnapshotProtocol.Load()
	// #7147: capability flags ride in the trailing byte under the same
	// discipline — a 2-byte frame is a pre-#7147 peer, and 0 flags is the
	// correct reading of it (advertises no capabilities).
	var peerFlags uint8
	if len(payload) >= 3 {
		peerFlags = payload[2]
	}
	oldFlags := s.peerIncarnationState().peerCapabilityFlags.Load()
	// #7990: the peer's session-sync WIRE version rides as a trailing u16
	// under the same discipline — a payload shorter than 5 bytes is a
	// pre-#7990 peer and leaves 0 = UNKNOWN, which callers must handle
	// explicitly rather than reading as a version.
	var peerWire uint16
	if len(payload) >= 5 {
		peerWire = binary.LittleEndian.Uint16(payload[3:5])
	}
	oldWire := s.peerIncarnationState().peerSessionSyncWire.Load()
	// #9818: the sender's process identity rides after the existing
	// capabilities fields. Old peers ignore this trailing extension; a
	// short frame leaves the connection unattributed and therefore on the
	// old stamp-based corpse path.
	var peerIdentity peerProcessIdentity
	if len(payload) >= 5+bootIncarnationLen {
		copy(peerIdentity.boot[:], payload[5:5+bootIncarnationLen])
		if len(payload) >= 5+bootIncarnationLen+8 {
			peerIdentity.epoch = binary.LittleEndian.Uint64(payload[5+bootIncarnationLen:])
			if len(payload) >= 5+bootIncarnationLen+8+8 {
				peerIdentity.token = binary.LittleEndian.Uint64(payload[5+bootIncarnationLen+8:])
			}
		}
	}
	// #16756: the second capability byte rides AFTER the identity tail.
	// It cannot sit at [5]: a pre-#9818 peer sends a 5-byte frame whose
	// [5] does not exist, while a #9818 peer's [5:21] is its boot id —
	// a fixed offset would misread a boot byte as capabilities. The
	// sender appends exactly one byte after however much identity it
	// sent, so the byte is at len-1 iff the frame is longer than every
	// pre-#16756 layout (5, 21, 29, 37). A shorter frame is a peer that
	// predates the byte: flags2 = 0, incapable, which is true of it.
	var peerFlags2 uint8
	if len(payload) > 5+bootIncarnationLen+8+8 {
		peerFlags2 = payload[len(payload)-1]
	}
	oldFlags2 := s.peerIncarnationState().peerCapabilityFlags2.Load()
	capabilityChanged := oldProto != uint32(peerProto) ||
		oldFlags != uint32(peerFlags) || oldWire != uint32(peerWire) ||
		oldFlags2 != uint32(peerFlags2)
	// noteConn runs for every frame (as before): it may PROMOTE a
	// pending-retirement connection to current (#9818), so it must
	// precede the membership gate below — gating first would leave
	// the promotion unrunnable and the conn to die on timer expiry.
	s.noteConnPeerCapabilities(conn, peerIdentity)
	// #10512: arm the GLOBAL learned state only from the current
	// incarnation's connection (the noteHeartbeatAck discipline): an
	// in-flight frame from a superseded connection must not re-arm
	// learned state the advance just cleared. Checked AND stored under
	// s.mu so a racing install serializes either fully before (then
	// cleared) or fully after (then rejected). nil conn is the
	// deliberate unit-test seam and always stores; production read
	// loops pass their live conn.
	s.mu.Lock()
	if conn != nil && !s.connIsCurrentIncarnationLocked(conn) {
		s.mu.Unlock()
		slog.Debug("cluster sync: ignoring capabilities from a superseded connection")
		return false
	}
	if ac, ok := conn.(*authConn); ok {
		ac.peerSnapshotVersion = peerProto
		ac.peerCapabilityFlags = peerFlags
		ac.peerSessionSyncWire = peerWire
		ac.peerCapabilityFlags2 = peerFlags2
	}
	s.peerSnaps.peerSnapshotProtocolWriteMu.Lock()
	if s.peerSnaps.peerSnapshotProtocol.Load() != uint32(peerProto) {
		s.peerSnaps.peerSnapshotProtocolGeneration++
	}
	s.peerSnaps.peerSnapshotProtocol.Store(uint32(peerProto))
	s.peerSnaps.peerSnapshotProtocolWriteMu.Unlock()
	s.peerIncarnationState().peerCapabilityFlags.Store(uint32(peerFlags))
	s.storePeerCapabilityFlags2(uint32(peerFlags2))
	s.peerIncarnationState().peerSessionSyncWire.Store(uint32(peerWire))
	s.mu.Unlock()
	// #10512 learn-trigger: learning completed (capable or not) —
	// flush unconditionally and let the flush retain (unlearned),
	// drop + count (incapable), or send (capable) internally.
	// Gating this call on capability here would strand the
	// incapable-drop path unreachable.
	s.flushScopedDeleteJournal()
	if capabilityChanged {
		if cb := s.OnPeerCapabilitiesChanged; cb != nil {
			go cb()
		}
	}
	// #9752 round 4: a capable discovery re-arms the bulk. A window that
	// aborted during the discovery race must not stay latched once the
	// peer proves capable — the next redrive completes it.
	if s.InstallTableIdentityCapable() {
		s.peerIncarnationState().bulkFencedForPeer.Store(false)
		// #9752 round 5 item 5: suppressed installs are never retried
		// by the sweep (its Created>=threshold window advances past
		// them), so transfer the suppress debt into a cold-prime
		// re-arm: the redriven bulk snapshot carries full state and
		// heals every withheld install at once. The debt is consumed
		// whenever a prime is already owed (that redrive carries it)
		// or armed here; future suppressions re-set it. Both checked
		// under s.mu with the arm so a concurrent ack discharge
		// cannot interleave a redundant bulk.
		if s.peerIncarnationState().installTableSuppressDebt.Load() {
			s.mu.Lock()
			if s.peerIncarnationState().installTableSuppressDebt.Load() {
				s.peerIncarnationState().installTableSuppressDebt.Store(false)
				if !s.needColdPrime.Load() {
					s.armColdPrimeLocked()
					slog.Info("cluster sync: re-arming cold prime after capable discovery with withheld installs")
				}
			}
			s.mu.Unlock()
		}
	}
	if s.IpsecTunnelDiscriminatorCapable() {
		s.peerIncarnationState().bulkFencedForIpsecPeer.Store(false)
	}
	if s.IpsecTunnelDiscriminatorCapable() && s.peerIncarnationState().ipsecDiscriminatorSuppressDebt.Load() {
		s.mu.Lock()
		if s.peerIncarnationState().ipsecDiscriminatorSuppressDebt.Load() {
			s.peerIncarnationState().ipsecDiscriminatorSuppressDebt.Store(false)
			if !s.needColdPrime.Load() {
				s.armColdPrimeLocked()
				slog.Info("cluster sync: re-arming cold prime after capable IPsec discriminator discovery")
			}
		}
		s.mu.Unlock()
	}
	slog.Info("cluster sync: peer advertised capabilities",
		"version", peerProto, "flags", peerFlags, "session_sync_wire", peerWire)
	return true
}

func (s *SessionSync) handleClockSync(conn net.Conn, payload []byte) bool {
	if len(payload) < 8 {
		slog.Warn("cluster sync: clock sync message too short")
		return false
	}
	peerMono := binary.LittleEndian.Uint64(payload[:8])
	localMono := s.clockSyncLocalMono()
	// #9653: the offset rebases Created/LastSeen of every session installed
	// from this peer, and it used to be stored with no bound. peerMono 2^63-1
	// rebased every later install to 0, so the standby aged the sessions out;
	// 0 against a long local uptime put them in the future, so they never
	// aged. Refuse a reading no running peer can send, and keep the previous
	// offset.
	if !plausiblePeerMonoSeconds(peerMono) {
		n := s.stats.ClockSyncsRefused.Add(1)
		if n == 1 || n%64 == 0 {
			slog.Warn("cluster sync: refusing clock sync with an impossible peer monotonic clock; the previous offset stays in force",
				"peer_mono", peerMono, "local_mono", localMono, "refused_total", n, "remote", connRemoteAddrString(conn))
		}
		return false
	}
	offset := int64(localMono) - int64(peerMono)
	// A bound cannot tell a plausible false reading from a true one, so the
	// offset belongs to the connection that carried it: it rebases only the
	// sessions that connection carries (clockOffsetFor). Publication is gated
	// on the connection still being installed and current: a frame already
	// read off a conn that retired (disconnect, supersession, incarnation
	// advance) must not republish the dead incarnation's offset.
	if !s.publishClockSyncIfCurrent(conn, offset) {
		slog.Debug("cluster sync: dropping clock sync from a retired connection; the current incarnation's offset stays in force",
			"peer_mono", peerMono, "local_mono", localMono, "remote", connRemoteAddrString(conn))
		return false
	}
	slog.Info("cluster sync: clock synced with peer", "peer_mono", peerMono, "local_mono", localMono, "offset", offset)
	return true
}

func (s *SessionSync) handleBarrier(conn net.Conn, payload []byte) bool {
	if len(payload) < 8 {
		slog.Warn("cluster sync: barrier message too short")
		return false
	}
	seq := binary.LittleEndian.Uint64(payload[:8])
	stats := s.Stats()
	slog.Info("cluster sync: barrier received", "seq", seq, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	s.sendBarrierAck(conn, seq)
	return true
}

func (s *SessionSync) handleBarrierAck(conn net.Conn, payload []byte) bool {
	if len(payload) < 8 {
		slog.Warn("cluster sync: barrier ack message too short")
		return false
	}
	seq := binary.LittleEndian.Uint64(payload[:8])
	stats := s.Stats()
	peerSessionsReceived := uint64(0)
	peerSessionsInstalled := uint64(0)
	if len(payload) >= 24 {
		peerSessionsReceived = binary.LittleEndian.Uint64(payload[8:16])
		peerSessionsInstalled = binary.LittleEndian.Uint64(payload[16:24])
	}
	slog.Info("cluster sync: barrier ack received", "seq", seq, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "peer_sessions_received", peerSessionsReceived, "peer_sessions_installed", peerSessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	advanced := false
	for {
		current := s.barrierAckSeq.Load()
		if seq <= current {
			break
		}
		if s.barrierAckSeq.CompareAndSwap(current, seq) {
			advanced = true
			break
		}
	}
	matched := s.completeBarrierWait(seq)
	// Unchanged legacy semantics: every well-formed barrier ack stamps
	// the last-ack time (status observability only, not liveness).
	s.stats.LastFenceAckAt.Store(time.Now().UnixNano())
	// #16041 fold: a duplicate/stale barrier ack (seq already covered)
	// that matches no live waiter is downstream-rejected — it applied
	// nothing new, so it must not refresh liveness either.
	return matched && advanced
}
