package cluster

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// PauseIncrementalSync temporarily disables background sweep-driven session
// replication. Explicit sync producers may continue queueing messages.
func (s *SessionSync) PauseIncrementalSync(reason string) {
	depth := s.incrementalPauseDepth.Add(1)
	if depth == 1 {
		stats := s.Stats()
		slog.Info("cluster sync: incremental sync paused", "reason", reason, "depth", depth, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	}
}

// ResumeIncrementalSync releases a previous PauseIncrementalSync call.
func (s *SessionSync) ResumeIncrementalSync(reason string) {
	depth := s.incrementalPauseDepth.Add(-1)
	if depth < 0 {
		s.incrementalPauseDepth.Store(0)
		depth = 0
	}
	if depth == 0 {
		stats := s.Stats()
		slog.Info("cluster sync: incremental sync resumed", "reason", reason, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	}
}
func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool {
	if !s.stats.Connected.Load() {
		return false
	}
	select {
	case s.sendCh <- msg:
		sentCounter.Add(1)
		return true
	default:
		s.stats.Errors.Add(1)
		if s.syncBackfillNeeded.CompareAndSwap(false, true) {
			slog.Warn("cluster sync: send queue full, enabling sweep replay", "source", source, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		}
		return false
	}
}

// QueueSessionV4 queues a v4 session for synchronization to the peer. The
// session is stamped with a fresh #2170 install generation so the matching
// delete can echo it and the peer can refuse a stale superseded delete.
func (s *SessionSync) QueueSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	s.stampInstallGenV4(key, &val)
	msg := encodeSessionV4(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v4")
}

// QueueSessionV6 queues a v6 session for synchronization to the peer.
func (s *SessionSync) QueueSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	s.stampInstallGenV6(key, &val)
	msg := encodeSessionV6(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v6")
}

// QueueDeleteV4 queues a v4 session deletion for synchronization. If the peer
// is disconnected, the delete is journaled for replay on reconnect. The delete
// draws a fresh generation strictly greater than the install it cancels
// (takeDeleteGenV4, #2170 + #2221) so (a) a journaled delete that replays after
// a same-key replacement was re-synced is refused by the peer (its generation
// is strictly older than the live entry) and (b) a delete reordered ahead of
// its own install out-ranks it, letting the peer's tombstone refuse the late
// install of the cancelled session.
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) {
	gen := s.takeDeleteGenV4(key)
	msg := encodeDeleteV4(key, gen)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v4") {
		s.journalDelete(msg)
	}
}

// QueueDeleteV6 queues a v6 session deletion for synchronization. If the peer
// is disconnected, the delete is journaled for replay on reconnect.
func (s *SessionSync) QueueDeleteV6(key dataplane.SessionKeyV6) {
	gen := s.takeDeleteGenV6(key)
	msg := encodeDeleteV6(key, gen)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v6") {
		s.journalDelete(msg)
	}
}

// armDeleteResync marks that a delete-journal overflow dropped session-delete
// records the standby still needs, arming a full authoritative bulk resync
// (#5450). It is a pure atomic CAS — safe to call while holding
// deleteJournalMu because it never blocks and performs no I/O — and idempotent:
// repeated drops in one overflow episode re-arm the already-set flag as a
// no-op. The arm is consumed once by whichever of the sweep loop (syncSweep) or
// the next reconnect (handleNewConnection) runs first; both send a full
// BulkSync so the peer's reconcileStaleSessions deletes the sessions the
// primary already closed. Returns true only on the false->true transition so
// the caller can log the episode exactly once (outside the lock).
func (s *SessionSync) armDeleteResync() bool {
	return s.forceResync.CompareAndSwap(false, true)
}

// journalDelete stores a delete message in the bounded ring buffer for replay
// on reconnect. If the journal is full, the oldest entry is evicted,
// DeletesDropped is incremented, and a full bulk resync is armed (#5450) so the
// standby does not silently retain the session the evicted delete would have
// torn down.
func (s *SessionSync) journalDelete(msg []byte) {
	s.deleteJournalMu.Lock()
	cap := s.deleteJournalCap
	if cap <= 0 {
		cap = deleteJournalDefaultCap
	}
	armed := false
	if len(s.deleteJournal) >= cap {
		s.deleteJournal = s.deleteJournal[1:]
		s.stats.DeletesDropped.Add(1)
		armed = s.armDeleteResync()
	}
	s.deleteJournal = append(s.deleteJournal, msg)
	s.deleteJournalMu.Unlock()
	if armed {
		slog.Warn("cluster sync: delete journal full, evicted oldest delete and armed full bulk resync to reconcile standby",
			"deletes_dropped_total", s.stats.DeletesDropped.Load(),
			"journal_cap", cap)
	}
}

func (s *SessionSync) flushDeleteJournal() {
	s.deleteJournalMu.Lock()
	journal := s.deleteJournal
	s.deleteJournal = nil
	s.deleteJournalMu.Unlock()
	if len(journal) == 0 {
		return
	}
	var flushed int
	// Replay journaled deletes through the ordered send stream. queueMessage
	// is non-blocking and increments DeletesSent on success; on a full sendCh
	// (or a peer disconnect) it returns false. Mirror the QueueDeleteV4
	// contract: re-journal (retain) the un-sent tail instead of dropping it,
	// so it replays on the next reconnect flush. Previously a full sendCh
	// here silently dropped the un-sent deletes (the journal was already
	// nil'd), leaving stale sessions on the peer (#2121).
	for i, msg := range journal {
		if s.queueMessage(msg, &s.stats.DeletesSent, "journal_flush") {
			flushed++
			continue
		}
		// queueMessage returned false — the send queue is full or the peer
		// disconnected (queueMessage checks Connected first). Either way the
		// remaining messages would also fail, so re-journal this message and
		// the rest (FIFO-prepended ahead of any deletes concurrently journaled
		// during the flush) and stop. Stopping keeps the un-sent suffix
		// contiguous and ordered; they replay on the next reconnect flush.
		s.rejournalTail(journal[i:])
		// "unsent_tail" is the count handed to rejournalTail; some of those
		// may still be evicted there if the journal is over cap — that loss is
		// counted in DeletesDropped (logged here as the running total), so
		// this field is the tail size, not a guarantee that all were retained.
		slog.Warn("cluster sync: delete journal flush could not enqueue (queue full or disconnected), re-journaled un-sent tail for next reconnect",
			"total", len(journal), "flushed", flushed, "unsent_tail", len(journal)-i,
			"deletes_dropped_total", s.stats.DeletesDropped.Load(),
			"connected", s.stats.Connected.Load(),
			"queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		return
	}
	slog.Info("cluster sync: flushed delete journal", "total", len(journal), "flushed", flushed)
}

// rejournalTail re-inserts the un-sent delete tail at the FRONT of the
// delete journal so it replays before any deletes that were concurrently
// journaled (by QueueDeleteV4/V6) while the flush ran, preserving FIFO
// order. On overflow it drops the OLDEST entries from the front of the
// merged list (the tail is older than the concurrently-journaled deletes,
// so the tail is evicted first; only if the entire tail is dropped does it
// also evict the oldest of the concurrent deletes, e.g. when the journal
// was already at cap), counting the dropped entries in DeletesDropped.
// Acquires deleteJournalMu exactly once. Used by flushDeleteJournal when
// the send stream is full or disconnected; the retained deletes replay on
// the next reconnect flush.
func (s *SessionSync) rejournalTail(tail [][]byte) {
	if len(tail) == 0 {
		return
	}
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()
	capN := s.deleteJournalCap
	if capN <= 0 {
		capN = deleteJournalDefaultCap
	}
	total := len(tail) + len(s.deleteJournal)
	if total <= capN {
		merged := make([][]byte, 0, total)
		merged = append(merged, tail...)
		merged = append(merged, s.deleteJournal...)
		s.deleteJournal = merged
		return
	}
	dropped := total - capN
	s.stats.DeletesDropped.Add(uint64(dropped))
	// #5450: the evicted deletes are session teardowns the standby still needs;
	// they are gone from our local table, so no incremental install sweep can
	// re-derive them. Arm a full authoritative bulk resync (consumed by the
	// sweep loop / next reconnect) so the peer's reconcileStaleSessions deletes
	// the sessions we already closed instead of carrying ghosts until the next
	// far-off full reconcile. Pure atomic CAS under deleteJournalMu — no I/O,
	// idempotent, armed once per overflow episode.
	s.armDeleteResync()
	merged := make([][]byte, 0, capN)
	if dropped < len(tail) {
		// Drop the oldest prefix of the tail; keep the rest plus all of the
		// newer concurrently-journaled deletes.
		merged = append(merged, tail[dropped:]...)
		merged = append(merged, s.deleteJournal...)
	} else {
		// The entire tail is evicted; also drop the oldest prefix of the
		// concurrently-journaled deletes to fit the cap.
		merged = append(merged, s.deleteJournal[dropped-len(tail):]...)
	}
	s.deleteJournal = merged
}

// SendLivenessKeepalive writes a sync-level heartbeat to the active peer
// connection so the peer's last-receive timestamp (lastPeerRxMono, read by
// LastPeerReceiveAge) is refreshed immediately. Used around the local
// heartbeat-socket restart window (Manager.RestartHeartbeat): while our UDP
// heartbeat sockets are torn down and rebound, the peer's only evidence that
// this node is still alive is sync traffic — and the sync-level heartbeat is
// normally emitted only on the 10s read-timeout cadence, far coarser than
// the 2s recency window of the peer's heartbeat-timeout suppression guard
// (shouldSuppressPeerHeartbeatTimeout). Best-effort: a no-op when no peer
// connection exists; a write error follows the standard sender pattern and
// triggers reconnect via handleDisconnect.
func (s *SessionSync) SendLivenessKeepalive() {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgHeartbeat, nil)
	s.writeMu.Unlock()
	if err != nil {
		slog.Debug("cluster sync: liveness keepalive send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
	}
}

// sendClockSync exchanges the local monotonic clock over the sync channel.
func (s *SessionSync) sendClockSync(conn net.Conn) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], monotonicSeconds())
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgClockSync, buf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.handleDisconnect(conn)
		slog.Warn("cluster sync: failed to send clock sync", "err", err)
	}
}

// sendCapabilities advertises this node's config-snapshot protocol version to
// the peer (#6650). Called once per installed connection.
//
// #7147 CHANGED THE SEND CONDITION. This used to return early when the
// snapshot version was 0, on the reasoning that silence is a more honest
// encoding of "not wired" than a literal 0. That reasoning was sound for a
// frame carrying only the version, but the frame now also carries capability
// FLAGS, which are a property of the BINARY and are always true for this
// build. Suppressing the whole frame on an unrelated field being 0 would have
// made #7147's fence-ack capability silently depend on
// `userspace.ProtocolVersion` staying nonzero — and if it ever were 0 the
// confirmed-fence gate would quietly stop arming, which is indistinguishable
// from a healthy pre-#7147 peer. Wrong failure to have.
//
// Sending an explicit 0 version is behaviourally identical to sending nothing:
// the receiver has no way to distinguish "frame absent" from "frame with
// version 0" — both leave peerSnapshotProtocol at 0 — and #6650's own contract
// already states that 0 means INCAPABLE rather than unknown. So the version
// semantics are preserved exactly; only the encoding changed.
//
// A send failure is logged and NOT escalated to handleDisconnect: unlike the
// clock sync this is advisory metadata, and dropping a live fabric because an
// advisory frame did not fit would trade a narrowing risk for a sync outage.
// The receiver's 0-means-incapable default already fails closed.
func (s *SessionSync) sendCapabilities(conn net.Conn) {
	v := s.localSnapshotProtocol.Load()
	var buf [5]byte
	binary.LittleEndian.PutUint16(buf[:2], uint16(v))
	buf[2] = localCapabilityFlags
	// #7990: the sender's session-sync WIRE version, as a trailing u16 under
	// the same #2170 discipline the flags byte rides. Advertised from the
	// compile-time constant rather than a settable field on purpose — there is
	// no bring-up call to forget, and no way for the advertised value to
	// disagree with the frames this process actually writes.
	//
	// This does NOT bump SessionSyncWireVersion. Bumping the version in order
	// to advertise the version would be self-defeating: the mixed-base gate
	// compares it for exact equality, so the bump would refuse session sync
	// across exactly the upgrade that first carries the field.
	binary.LittleEndian.PutUint16(buf[3:5], SessionSyncWireVersion)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgPeerCapabilities, buf[:])
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: failed to advertise capabilities", "err", err)
	}
}

func (s *SessionSync) sendLoop(ctx context.Context) {
	sendOne := func(msg []byte) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn := s.getActiveConn()
			if conn == nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.writeMu.Lock()
			moved := s.noteStreamConnLocked(conn) // #9508: before the write
			err := writeFull(conn, msg)
			s.writeMu.Unlock()
			if moved {
				s.onStreamMoved(true)
			}
			if err != nil {
				slog.Debug("cluster sync: send error", "err", err)
				s.stats.Errors.Add(1)
				s.handleDisconnect(conn)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-s.sendCh:
			sendOne(msg)
		}
	}
}
