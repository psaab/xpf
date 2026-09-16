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
	// #9752 round 3: after the stamp — the memo may have restored an
	// identity the mirror could not carry, and THAT is what the fence judges.
	if s.suppressStampedInstallForIncapablePeer(val.InstallTableDomain, val.InstallTableCheck, "session_v4") {
		return
	}
	msg := encodeSessionV4(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v4")
}

// QueueSessionV6 queues a v6 session for synchronization to the peer.
func (s *SessionSync) QueueSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	s.stampInstallGenV6(key, &val)
	if s.suppressStampedInstallForIncapablePeer(val.InstallTableDomain, val.InstallTableCheck, "session_v6") {
		return
	}
	msg := encodeSessionV6(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v6")
}

// pacedQueuePoll is how often a paced enqueue re-checks the connection while
// it waits for room in the send queue.
const pacedQueuePoll = 10 * time.Millisecond

// QueueSessionV4Paced queues a v4 session like QueueSessionV4, except that a
// full send queue makes it wait up to maxWait for room instead of dropping the
// message (#9767). It reports whether the session reached the queue. The
// FullResync export uses it because its frame is acknowledged to the helper
// only once the whole export is queued: waiting lets the writer pace a burst
// larger than the queue, in order, where QueueSessionV4 discards its tail.
func (s *SessionSync) QueueSessionV4Paced(key dataplane.SessionKey, val dataplane.SessionValue, maxWait time.Duration) bool {
	s.stampInstallGenV4(key, &val)
	// #9752 round 3: false is honest — the frame did not reach the queue,
	// and the caller counts it missed (no retry loop to spin).
	if s.suppressStampedInstallForIncapablePeer(val.InstallTableDomain, val.InstallTableCheck, "session_v4") {
		return false
	}
	return s.queueMessagePaced(encodeSessionV4(key, val), &s.stats.SessionsSent, "session_v4", maxWait)
}

// QueueSessionV6Paced is the v6 form of QueueSessionV4Paced.
func (s *SessionSync) QueueSessionV6Paced(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, maxWait time.Duration) bool {
	s.stampInstallGenV6(key, &val)
	if s.suppressStampedInstallForIncapablePeer(val.InstallTableDomain, val.InstallTableCheck, "session_v6") {
		return false
	}
	return s.queueMessagePaced(encodeSessionV6(key, val), &s.stats.SessionsSent, "session_v6", maxWait)
}

// queueMessagePaced is queueMessage with a bounded wait for room. A disconnect
// ends the wait at once, as it refuses queueMessage. When maxWait passes with
// the queue still full, the last attempt is queueMessage itself, so a dropped
// message is counted exactly as a lossy producer's drop is.
func (s *SessionSync) queueMessagePaced(msg []byte, sentCounter *atomic.Uint64, source string, maxWait time.Duration) bool {
	deadline := time.Now().Add(maxWait)
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for s.stats.Connected.Load() {
		select {
		case s.sendCh <- msg:
			sentCounter.Add(1)
			return true
		default:
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return s.queueMessage(msg, sentCounter, source)
		}
		poll := min(remaining, pacedQueuePoll)
		if timer == nil {
			timer = time.NewTimer(poll)
		} else {
			timer.Reset(poll)
		}
		select {
		case s.sendCh <- msg:
			sentCounter.Add(1)
			return true
		case <-timer.C:
		}
	}
	return false
}

// QueueDeleteV4 queues a v4 session deletion for synchronization. If the peer
// is disconnected, the delete is journaled for replay on reconnect. The delete
// draws a fresh generation strictly greater than the install it cancels
// (takeDeleteGenV4, #2170 + #2221) so (a) a journaled delete that replays after
// a same-key replacement was re-synced is refused by the peer (its generation
// is strictly older than the live entry) and (b) a delete reordered ahead of
// its own install out-ranks it, letting the peer's tombstone refuse the late
// install of the cancelled session.
//
// forwardOnly (#9752) marks a purge-retirement delete: the peer must retract
// exactly the named key, skipping companion deletes. It is withheld from a
// peer that never advertised the capability (same drop-not-journal shape as
// suppressDeleteForIncapablePeer: journaling would escalate to a bulk resync
// whose reconcile deletes unmarked on the protected peer).
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey, forwardOnly bool) {
	if s.suppressDeleteForIncapablePeer("delete_v4") {
		return
	}
	if forwardOnly && s.suppressForwardOnlyDeleteForIncapablePeer("delete_v4") {
		return
	}
	gen := s.takeDeleteGenV4(key)
	msg := encodeDeleteV4(key, gen, forwardOnly)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v4") {
		s.journalDelete(msg)
	}
}

// suppressForwardOnlyDeleteForIncapablePeer reports whether an outgoing
// FORWARD-ONLY session delete must be WITHHELD because the peer never
// advertised capFlagPurgeRetirementForwardOnly (#9752).
//
// Such a peer derives companions for every delete, so our purge-retirement
// close would destroy sessions the purge deliberately preserved. Withholding
// leaves them on the peer until they idle out or the upgrade completes —
// the same visible-leak-over-invisible-teardown trade the #9714 suppressor
// makes, with its own counter and one-shot warning. Ordinary (non-forward-
// only) deletes are never withheld here; see suppressDeleteForIncapablePeer.
func (s *SessionSync) suppressForwardOnlyDeleteForIncapablePeer(source string) bool {
	if s == nil || !s.peerCapabilitiesLearned() || s.PurgeRetirementForwardOnlyCapable() {
		return false
	}
	s.stats.DeletesSuppressedPurgeRetirement.Add(1)
	if s.purgeRetirementSuppressionWarned.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: withholding forward-only session deletes — the peer does not advertise "+
			"#9752 forward-only deletes, so it would derive companions and destroy sessions the purge "+
			"deliberately preserved. That peer will retain sessions this node has retired until they "+
			"idle out. Completing the upgrade on both nodes restores delete sync.",
			"source", source,
			"peer_snapshot_protocol", s.peerSnapshotProtocol.Load(),
			"peer_capability_flags", uint8(s.peerCapabilityFlags.Load()))
	}
	return true
}

// suppressStampedInstallForIncapablePeer reports whether an outgoing STAMPED
// session install must be WITHHELD because the peer cannot take it (#9752
// round 3, hardened round 4).
//
// Such a peer installs every session stamp-less: it decodes no tail and
// re-resolves in the default table. Sending it a stamped install would plant
// a session that silently wrong-tables after failover — the defect in the
// other direction. Withholding leaves the session off the peer; a later miss
// there re-establishes it in the right table. Unstamped installs are never
// withheld (the peer handles them exactly as before).
//
// Round 4: an UNLEARNED peer is gated too — the transport is connected
// before the capability exchange, so pass-through-during-discovery would
// plant the lie on every connect to an old peer. This is deliberately
// stricter than the delete suppressors' reconnect rule, and safe where
// theirs would not be: deletes are one-shot, but installs repeat — the
// sweep re-sends a withheld install on the next tick after learning, so
// default-deny during discovery delays, never drops.
func (s *SessionSync) suppressStampedInstallForIncapablePeer(domain, check uint32, source string) bool {
	if domain == 0 && check == 0 {
		return false
	}
	if s == nil || s.InstallTableIdentityCapable() {
		return false
	}
	s.stats.InstallsSuppressedNoPeerInstallTable.Add(1)
	s.installTableSuppressDebt.Store(true)
	if s.installTableSuppressionWarned.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: withholding stamped session installs — the peer has not advertised "+
			"#9752 install-table identity (incapable or not yet discovered), so it would install them "+
			"stamp-less and wrong-table after failover. That peer will miss these sessions until a miss "+
			"re-establishes them or the upgrade completes on both nodes.",
			"source", source,
			"peer_snapshot_protocol", s.peerSnapshotProtocol.Load(),
			"peer_capability_flags", uint8(s.peerCapabilityFlags.Load()))
	}
	return true
}

// suppressUnannouncedForPBRActivePeer reports whether a mirror-sourced (0,0)
// install must be WITHHELD because it was never announced on a node that
// does PBR (#9752 round 5 item 1).
//
// A (0,0) rebuilt from the BPF mirror is AMBIGUOUS: genuinely-non-PBR, or a
// PBR session whose memo record is missing (sweep raced the announcing
// delta, foreign row, or post-cap). Sending it to an incapable peer
// installs a possibly-PBR session stamp-less (default-table resolution).
// On a node that announced stamps this incarnation, fail closed: withhold
// it (the delta announces + records, the sweep retries, the bulk carries
// helper truth). On a node that never announced (kernel dataplanes always
// land here — only userspace convert stamps), (0,0) is genuine: send.
//
// ONLY for mirror-derived sends (sweep + store-walk bulk). Delta/queue
// (0,0)s are authoritative (the helper said default) and helper-truth bulk
// snapshots carry real stamps — neither consults this. Same counter and
// one-shot warning as the stamped suppressor (one alarm per incarnation
// for both withholding reasons).
//
// `announced` is memo membership captured BEFORE stamping: stamping records
// (round 5 item 1 records everything announced), which would destroy the
// miss signal if re-read after. A concurrent record landing between the
// capture and this decision fails closed (a redundant withhold; the
// announcing send carries the session anyway).
func suppressUnannouncedForPBRActivePeer(s *SessionSync, announced bool, source string) bool {
	if announced {
		return false
	}
	if s == nil || !s.pbrAnnouncedForFence.Load() || s.InstallTableIdentityCapable() {
		return false
	}
	s.stats.InstallsSuppressedNoPeerInstallTable.Add(1)
	s.installTableSuppressDebt.Store(true)
	if s.installTableSuppressionWarned.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: withholding unannounced session installs — this node does PBR and "+
			"these mirror-sourced (0,0)s were never announced (in-race delta, foreign row, or memo "+
			"at cap), so the peer would install possibly-PBR sessions stamp-less. They flow once "+
			"announced, or on upgrade.",
			"source", source,
			"peer_snapshot_protocol", s.peerSnapshotProtocol.Load(),
			"peer_capability_flags", uint8(s.peerCapabilityFlags.Load()))
	}
	return true
}

// suppressDeleteForIncapablePeer reports whether an outgoing session delete must be
// WITHHELD because the peer's helper cannot refuse a peer-marked delete (#9714 F5).
//
// A peer without capFlagPeerDeleteOwnership applies our delete unconditionally, so
// in a dual-primary split it tears down the flow it is still forwarding — #9714's
// defect reached from the other side of the wire. An upgraded node is already safe
// from the peer's deletes; this closes the remaining direction.
//
// It DROPS rather than journals, and that is the opposite of what the obvious
// reading of "suppress" suggests. journalDelete would hold the message for replay,
// but an incapable peer does not become capable without reconnecting, so the bounded
// journal (deleteJournalDefaultCap, 10000) fills on any busy node. The overflow
// evicts and arms forceResync, which sends a full BulkSync — and the peer's
// reconcileStaleSessions then deletes every session absent from that set, unmarked,
// on the very peer being protected. Journalling therefore escalates a per-flow
// hazard into a whole-set teardown. Dropping fails toward KEEPING sessions, the
// direction this codebase already chooses for deletes.
//
// The cost is real, which is why this is counted and alarmed rather than silent: the
// peer retains sessions this node has closed until they idle out.
//
// UNKNOWN IS NOT INCAPABLE. peerCapabilityFlags reads 0 both for an old peer and for
// the window before this incarnation's advertisement arrives, so gating on the flag
// alone would discard deletes on every reconnect of a matched pair. The gate
// therefore fires only once capabilities have actually been LEARNED, and before that
// behaves exactly as it did before #9714 — the status quo, not a new exposure.
//
// The gate is unavoidably COARSE: it cannot be narrowed to an observed dual-primary,
// because IsPrimaryForRGFn reports only the LOCAL node, and a split is definitionally
// the state in which neither node can see the other's truth.
func (s *SessionSync) suppressDeleteForIncapablePeer(source string) bool {
	if s == nil || !s.peerCapabilitiesLearned() || s.PeerDeleteOwnershipCapable() {
		return false
	}
	s.stats.DeletesSuppressedPeerIncapable.Add(1)
	if s.deleteSuppressionWarned.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: withholding session deletes — the peer does not advertise #9714 peer-delete "+
			"ownership, so it would apply them unconditionally and could tear down a flow it is still "+
			"forwarding. That peer will retain sessions this node has closed until they idle out. "+
			"Completing the upgrade on both nodes restores delete sync.",
			"source", source,
			"peer_snapshot_protocol", s.peerSnapshotProtocol.Load(),
			"peer_capability_flags", uint8(s.peerCapabilityFlags.Load()))
	}
	return true
}

// QueueDeleteV6 queues a v6 session deletion for synchronization. If the peer
// is disconnected, the delete is journaled for replay on reconnect.
// forwardOnly (#9752): v6 twin of the QueueDeleteV4 marker.
func (s *SessionSync) QueueDeleteV6(key dataplane.SessionKeyV6, forwardOnly bool) {
	if s.suppressDeleteForIncapablePeer("delete_v6") {
		return
	}
	if forwardOnly && s.suppressForwardOnlyDeleteForIncapablePeer("delete_v6") {
		return
	}
	gen := s.takeDeleteGenV6(key)
	msg := encodeDeleteV6(key, gen, forwardOnly)
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
