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

// enqueueQueuedFrame appends one frame to sendCh and advances the accepted
// watermark while holding queuedFrameMu. The same mutex is held around
// BulkStart's write, making the watermark an exact wire-order cut: frames
// accepted before that write belong to the gap; later frames are post-marker.
func (s *SessionSync) enqueueQueuedFrame(msg []byte) bool {
	_, _, ok := s.enqueueQueuedFrameWithWatermark(msg)
	return ok
}

func (s *SessionSync) enqueueQueuedFrameWithWatermark(msg []byte) (seq, failures uint64, ok bool) {
	s.queuedFrameMu.Lock()
	defer s.queuedFrameMu.Unlock()
	select {
	case s.sendCh <- msg:
		s.queuedFrameSeq++
		return s.queuedFrameSeq, s.queuedFrameFailures, true
	default:
		return 0, s.queuedFrameFailures, false
	}
}

func (s *SessionSync) queuedFrameWriteStarted() {
	s.queuedFrameMu.Lock()
	s.queuedFrameStarted++
	s.queuedFrameMu.Unlock()
}

func (s *SessionSync) queuedFrameDelivered() {
	s.queuedFrameMu.Lock()
	s.queuedFrameResolved++
	s.queuedFrameMu.Unlock()
}

func (s *SessionSync) queuedFrameFailed() {
	s.queuedFrameMu.Lock()
	s.queuedFrameResolved++
	s.queuedFrameFailures++
	s.queuedFrameMu.Unlock()
}

func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool {
	if !s.stats.Connected.Load() {
		return false
	}
	if s.enqueueQueuedFrame(msg) {
		sentCounter.Add(1)
		return true
	}
	s.stats.Errors.Add(1)
	if s.syncBackfillNeeded.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: send queue full, enabling sweep replay", "source", source, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	}
	return false
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
		if s.enqueueQueuedFrame(msg) {
			sentCounter.Add(1)
			return true
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
		// A timer wake only retries the bounded enqueue. The helper owns the
		// watermark lock for the actual channel send, so no accepted frame can
		// race the BulkStart cut.
		<-timer.C
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

// QueueDeleteScopedV4 queues a SCOPED (domain + expected RT_FLOW id)
// policy delete (#10512). Gates: #9714 peer-delete ownership AND the
// scoped capability. UNKNOWN (unlearned) journals as deferred debt —
// never withheld (withholding here would discard the delete on every
// disconnect window); only learned-incapable withholds. Scoped is never
// downgraded to bare. On queue failure the frame journals the same way.
func (s *SessionSync) QueueDeleteScopedV4(domain uint32, key dataplane.SessionKey, expectedID uint64) {
	// Identity-missing (plan §2.1): a scoped delete without an identity
	// names nothing — fail closed LOUDLY before capability checks,
	// generation draws, or journaling (a frame the receiver would reject
	// as malformed must never be created).
	if expectedID == 0 {
		s.stats.Errors.Add(1)
		slog.Error("cluster sync: scoped delete without expected identity (caller bug); dropping",
			"source", "delete_scoped_v4", "domain", domain)
		return
	}
	if s.suppressDeleteForIncapablePeer("delete_scoped_v4") {
		return
	}
	if !s.peerCapabilitiesLearned() {
		s.enqueueScopedV4(domain, key, expectedID)
		return
	}
	if s.suppressScopedDeleteForIncapablePeer("delete_scoped_v4") {
		return
	}
	s.enqueueScopedV4(domain, key, expectedID)
}

// enqueueScopedV4 draws a fresh generation, encodes, and queues-or-journals
// one scoped delete. Shared by the unlearned-defer and capable-send paths
// (which differ only in gating, decided by the caller).
func (s *SessionSync) enqueueScopedV4(domain uint32, key dataplane.SessionKey, expectedID uint64) {
	gen := s.takeDeleteGenScopedV4(domain, key)
	msg := encodeDeleteScopedV4(key, gen, false, domain, expectedID)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_scoped_v4") {
		s.journalScopedDelete(msg)
	}
}

// QueueDeleteScopedV6 is the IPv6 twin of QueueDeleteScopedV4.
func (s *SessionSync) QueueDeleteScopedV6(domain uint32, key dataplane.SessionKeyV6, expectedID uint64) {
	// Identity-missing (plan §2.1): fail closed loudly (see the v4 twin).
	if expectedID == 0 {
		s.stats.Errors.Add(1)
		slog.Error("cluster sync: scoped delete without expected identity (caller bug); dropping",
			"source", "delete_scoped_v6", "domain", domain)
		return
	}
	if s.suppressDeleteForIncapablePeer("delete_scoped_v6") {
		return
	}
	if !s.peerCapabilitiesLearned() {
		s.enqueueScopedV6(domain, key, expectedID)
		return
	}
	if s.suppressScopedDeleteForIncapablePeer("delete_scoped_v6") {
		return
	}
	s.enqueueScopedV6(domain, key, expectedID)
}

// enqueueScopedV6 is the IPv6 twin of enqueueScopedV4.
func (s *SessionSync) enqueueScopedV6(domain uint32, key dataplane.SessionKeyV6, expectedID uint64) {
	gen := s.takeDeleteGenScopedV6(domain, key)
	msg := encodeDeleteScopedV6(key, gen, false, domain, expectedID)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_scoped_v6") {
		s.journalScopedDelete(msg)
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

// suppressScopedDeleteForIncapablePeer reports whether an outgoing SCOPED
// (domain + expected RT_FLOW id) session delete must be WITHHELD because
// the peer never advertised capFlagScopedPolicyDelete (#10512).
//
// Such a peer applies deletes unconditionally by bare tuple, so our scoped
// delete would destroy a surviving tenant's session sharing the tuple —
// the #10512 over+under. Withholding leaves the deleted tenant's session
// on the peer until it idles out or the upgrade completes — the same
// visible-leak-over-invisible-teardown trade the #9714/#9752 suppressors
// make, with its own counter and one-shot warning. Bare deletes are never
// withheld here; see suppressDeleteForIncapablePeer. A scoped delete is
// NEVER downgraded to bare for an incapable peer: bare would mis-delete
// (over+under) or refuse silently-looking; withhold is explicit + counted.
func (s *SessionSync) suppressScopedDeleteForIncapablePeer(source string) bool {
	if s == nil {
		return false
	}
	// Default-deny while UNLEARNED (unlike #9714/#9752 delete suppressors):
	// an old peer decodes the legacy prefix and bare-deletes — the exact
	// downgrade the NEVER rule forbids — so discovery pass-through is not
	// an option despite deletes being one-shot. A matched-pair reconnect
	// may drop a commit-time delete (repaired by bulk reconcile's
	// authoritative-absent, else idled out); an over-delete of a survivor
	// is the worse trade by far.
	if !s.peerCapabilitiesLearned() || !s.ScopedPolicyDeleteCapable() {
		s.stats.DeletesSuppressedScopedPolicy.Add(1)
		if s.scopedPolicySuppressionWarned.CompareAndSwap(false, true) {
			slog.Warn("cluster sync: withholding scoped session deletes — the peer does not advertise "+
				"#10512 scoped policy deletes, so it would apply them by bare tuple and destroy a surviving "+
				"tenant's session. That peer will retain sessions this node has revoked until they "+
				"idle out. Completing the upgrade on both nodes restores delete sync.",
				"source", source,
				"peer_snapshot_protocol", s.peerSnapshotProtocol.Load(),
				"peer_capability_flags", uint8(s.peerCapabilityFlags.Load()))
		}
		return true
	}
	return false
}

// holdScopedDeleteForUnverifiedPeer enforces the #10512 NEVER-downgrade
// invariant at WRITE time: a scoped delete frame (37/61-byte payload) must
// never be written unless the CURRENT peer incarnation learned capabilities
// and advertised the scoped bit. UNLEARNED frames are re-journaled as
// deferred debt (a later learn-trigger flushes them); only
// LEARNED-INCAPABLE frames are dropped + counted (withhold — that peer
// will never take them). Returns true when the frame was held here (by
// either disposition); bare, non-delete, and malformed frames, plus
// verified scoped frames, return false.
func (s *SessionSync) holdScopedDeleteForUnverifiedPeer(msg []byte) bool {
	if len(msg) < syncHeaderSize+1 {
		return false
	}
	msgType := msg[4]
	payloadLen := binary.LittleEndian.Uint32(msg[8:12])
	scoped := (msgType == syncMsgDeleteV4 && payloadLen == 37) ||
		(msgType == syncMsgDeleteV6 && payloadLen == 61)
	if !scoped {
		return false
	}
	if s.peerCapabilitiesLearned() && s.ScopedPolicyDeleteCapable() {
		return false
	}
	if !s.peerCapabilitiesLearned() {
		// Transient: keep as deferred debt (takes deleteJournalMu; no
		// reverse edge exists — journal paths never take s.mu/writeMu).
		s.journalScopedDelete(msg)
		return true
	}
	s.suppressScopedDeleteForIncapablePeer("send_retry")
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

// journalScopedDelete stores a scoped delete frame as deferred debt for
// learn-triggered replay (plan §1.3 literal). Same cap/evict/count/resync
// discipline as journalDelete, in the separate scoped slice so the bare
// flush never touches scoped bytes.
func (s *SessionSync) journalScopedDelete(msg []byte) {
	s.deleteJournalMu.Lock()
	cap := s.scopedDeleteJournalCap
	if cap <= 0 {
		cap = deleteJournalDefaultCap
	}
	armed := false
	if len(s.scopedDeleteJournal) >= cap {
		s.scopedDeleteJournal = s.scopedDeleteJournal[1:]
		s.stats.DeletesDropped.Add(1)
		armed = s.armDeleteResync()
	}
	s.scopedDeleteJournal = append(s.scopedDeleteJournal, msg)
	s.deleteJournalMu.Unlock()
	if armed {
		slog.Warn("cluster sync: scoped delete journal full, evicted oldest delete and armed full bulk resync to reconcile standby",
			"deletes_dropped_total", s.stats.DeletesDropped.Load(),
			"journal_cap", cap)
	}

	// Post-append re-check (learn/flush race): a flush that took an empty
	// journal just before this append would otherwise strand the debt
	// with no later trigger (caps arrive once per conn). Flush whenever
	// learned — the flush itself drops (incapable) or sends (capable);
	// either ordering settles exactly once (take+nil under the journal
	// mutex). Unlearned debt waits for the next learn.
	if s.peerCapabilitiesLearned() {
		s.flushScopedDeleteJournal()
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

// flushScopedDeleteJournal replays deferred scoped deletes — ONLY when the
// current peer positively advertised the scoped bit. Called on the
// learn-trigger (caps arm); also safe to call spuriously (empty or
// unverified drains nothing). Unverified (unlearned) debt is RETAINED,
// not dropped: a later learn-trigger flushes it. Learned-incapable debt
// is DROPPED + counted (withhold semantics — the peer will never take
// it; bulk reconcile bounds the resulting staleness). Failed enqueues
// re-journal the tail like the bare flush.
func (s *SessionSync) flushScopedDeleteJournal() {
	if !s.peerCapabilitiesLearned() {
		return
	}
	if hook := s.testBeforeScopedJournalTake; hook != nil {
		s.testBeforeScopedJournalTake = nil
		hook()
	}
	if !s.ScopedPolicyDeleteCapable() {
		s.deleteJournalMu.Lock()
		dropped := len(s.scopedDeleteJournal)
		s.scopedDeleteJournal = nil
		s.deleteJournalMu.Unlock()
		if dropped > 0 {
			s.stats.DeletesSuppressedScopedPolicy.Add(uint64(dropped))
			slog.Warn("cluster sync: dropped deferred scoped deletes for an incapable peer",
				"dropped", dropped)
		}
		return
	}
	s.deleteJournalMu.Lock()
	journal := s.scopedDeleteJournal
	s.scopedDeleteJournal = nil
	s.deleteJournalMu.Unlock()
	if len(journal) == 0 {
		return
	}
	var flushed int
	for i, msg := range journal {
		if s.queueMessage(msg, &s.stats.DeletesSent, "scoped_journal_flush") {
			flushed++
			continue
		}
		s.rejournalScopedTail(journal[i:])
		slog.Warn("cluster sync: scoped delete journal flush could not enqueue, re-journaled un-sent tail",
			"total", len(journal), "flushed", flushed, "unsent_tail", len(journal)-i)
		return
	}
	slog.Info("cluster sync: flushed scoped delete journal", "total", len(journal), "flushed", flushed)
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

// rejournalScopedTail is the scoped-journal twin of rejournalTail: FIFO
// prepend with oldest-first eviction, DeletesDropped counting, and bulk
// resync arming. The retained deletes replay on the next learn-triggered
// flush to a capable peer.
func (s *SessionSync) rejournalScopedTail(tail [][]byte) {
	if len(tail) == 0 {
		return
	}
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()
	capN := s.scopedDeleteJournalCap
	if capN <= 0 {
		capN = deleteJournalDefaultCap
	}
	total := len(tail) + len(s.scopedDeleteJournal)
	if total <= capN {
		merged := make([][]byte, 0, total)
		merged = append(merged, tail...)
		merged = append(merged, s.scopedDeleteJournal...)
		s.scopedDeleteJournal = merged
		return
	}
	dropped := total - capN
	s.stats.DeletesDropped.Add(uint64(dropped))
	s.armDeleteResync() // #5450: see the bare twin.
	merged := make([][]byte, 0, capN)
	if dropped < len(tail) {
		merged = append(merged, tail[dropped:]...)
		merged = append(merged, s.scopedDeleteJournal...)
	} else {
		merged = append(merged, s.scopedDeleteJournal[dropped-len(tail):]...)
	}
	s.scopedDeleteJournal = merged
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
func (s *SessionSync) localProcessIdentity() peerProcessIdentity {
	s.localIdentityOnce.Do(func() {
		s.localIdentity = peerProcessIdentity{boot: localBootIncarnation()}
		if s.LocalBootEpochFn != nil {
			s.localIdentity.epoch = s.LocalBootEpochFn()
		}
		if s.LocalProcessTokenFn != nil {
			s.localIdentity.token = s.LocalProcessTokenFn()
		}
	})
	return s.localIdentity
}

func (s *SessionSync) sendCapabilities(conn net.Conn) {
	v := s.localSnapshotProtocol.Load()
	var buf [5 + bootIncarnationLen + 8 + 8]byte
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

	// #9818: advertise the sender's process identity on EVERY installed
	// connection, before the connection's BulkStart. The boot id distinguishes
	// OS boots; the ordered boot epoch distinguishes daemon restarts that keep
	// the OS boot id; and the Manager-scoped token prevents a persistence
	// collision from making two daemon processes look equal. Each trailing
	// field is length-gated for old peers and omitted when unavailable, so an
	// unreadable identity remains the pre-#9818 fail-open class rather than an
	// explicit all-zero identity.
	identity := s.localProcessIdentity()
	if identity.boot.known() {
		copy(buf[5:5+bootIncarnationLen], identity.boot[:])
	}
	n := 5
	if identity.boot.known() {
		n += bootIncarnationLen
	}
	if identity.epoch != 0 || identity.token != 0 {
		// Ordered identity fields need a fixed-width boot field so receivers
		// can decode the epoch and token even when boot id lookup failed.
		if n == 5 {
			n += bootIncarnationLen
		}
		binary.LittleEndian.PutUint64(buf[n:n+8], identity.epoch)
		n += 8
		if identity.token != 0 {
			binary.LittleEndian.PutUint64(buf[n:n+8], identity.token)
			n += 8
		}
	}
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgPeerCapabilities, buf[:n])
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: failed to advertise capabilities", "err", err)
	}
}

func (s *SessionSync) sendLoop(ctx context.Context) {
	sendOne := func(msg []byte) {
		delivered := false
		writeStarted := false
		defer func() {
			if delivered {
				s.queuedFrameDelivered()
			} else {
				// A frame abandoned because the send loop is cancelled never
				// satisfies a bulk watermark. The pending bulk sees the
				// failure and aborts before BulkEnd instead of reconciling an
				// incomplete set.
				s.queuedFrameFailed()
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// #10283: take the gate before selecting the connection. A
			// snapshot may hold it across a slow source read; selecting first
			// could leave this frame bound to a connection that moved while
			// the sender waited.
			s.bulkStartMu.Lock()
			conn := s.getActiveConn()
			if conn == nil {
				s.bulkStartMu.Unlock()
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if hook := s.testBeforeQueuedWrite; hook != nil {
				s.testBeforeQueuedWrite = nil
				hook()
			}
			select {
			case <-ctx.Done():
				s.bulkStartMu.Unlock()
				return
			default:
			}
			// #10283: doBulkSync holds bulkStartMu while reading the
			// table-truth snapshot and writing BulkStart. Take the same mutex
			// for the actual ordered-stream write, not merely while queueing:
			// otherwise a gap-opened incremental can win the writeMu race,
			// install before bulkInProgress, and be deleted at BulkEnd. Lock
			// every queued frame so existing sendCh order is preserved for a
			// gap open followed by a close (no install can be replayed after
			// its delete).
			s.writeMu.Lock()
			// #10512 write-time gate, INSIDE writeMu immediately before the
			// write: testBeforeQueuedWrite (above) plus real churn can move
			// flags after an earlier check, so approval binds to THIS write.
			// A drop unlocks both mutexes and counts as delivered
			// (intentional, not a transport failure) so bulk watermarks move.
			// Race audit: s.mu is deliberately NOT held across the write.
			// Replacement always closes the selected conn, so a write past
			// replacement fails and the retry re-gates; learned+incapable
			// is reachable only via reconnect (new conn) since no downgrade
			// is re-advertised mid-connection. Holding s.mu across a
			// blocking write would risk deadlock for no safety gain.
			if s.holdScopedDeleteForUnverifiedPeer(msg) {
				s.writeMu.Unlock()
				s.bulkStartMu.Unlock()
				delivered = true
				return
			}
			moved := s.noteStreamConnLocked(conn) // #9508: before the write
			if !writeStarted {
				s.queuedFrameWriteStarted()
				writeStarted = true
			}
			err := writeFull(conn, msg)
			s.writeMu.Unlock()
			s.bulkStartMu.Unlock()
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
			delivered = true
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
