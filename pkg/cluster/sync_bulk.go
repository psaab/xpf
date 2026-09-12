package cluster

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// doBulkSync delivers the cold-start / survivor-fabric re-drive bulk session
// snapshot to the peer.
//
// #5085: the RECEIVER's authoritative stale-session reconcile
// (reconcileStaleSessions) runs against exactly the key set delimited by a
// BulkStart -> SessionV4/V6... -> BulkEnd window (bulkRecvV4/bulkRecvV6). It is
// therefore only correct when that window carries a COMPLETE, authoritative
// snapshot: a session merely absent from the window is treated as stale and
// DELETED. The window is built with LOSSLESS direct writes under writeMu (no
// lossy sendCh drops), so doBulkSync ALWAYS ends with one — BulkSyncSnapshot
// when a table-truth source is wired (#6031), BulkSync's store walk otherwise.
//
// BulkSyncOverride, if set, is a best-effort fast-population pre-step (the #418
// event-stream export). It is NO LONGER wired in production (see
// startClusterComms) and is retained only as a test/extension seam. Event-stream
// delivery is async and LOSSY (QueueSessionV4/V6 -> non-blocking sendCh, cap
// 4096): under load it drops session frames, and reconciling against that
// incomplete set would DELETE live peer-owned sessions merely dropped in transit.
// Historically the override path sent an EMPTY BulkStart/BulkEnd here
// (sendBulkMarkers), so the receiver recorded zero keys and skipped stale
// reconciliation entirely — a stale peer-owned session the standby held survived
// cold-prime (the #5085 bug). Whether or not an override runs, the trailing
// BulkSync() now guarantees the receiver always sees an authoritative window.
// #5272 is preserved: BulkSync sends a real BulkStart (sets the receiver's
// bulkInProgress), so only a genuine transfer — never a spurious no-transfer
// BulkEnd — reconciles.
//
// #6031: when BulkSnapshotSource is wired, the authoritative window is framed
// from the caller-supplied TABLE-TRUTH snapshot instead of BulkSync's walk of
// the `sessions`/`sessions_v6` BPF conntrack maps. Those maps are a best-effort
// DISPLAY mirror under the userspace dataplane — the Rust helper's transit
// forward install never publishes there — so the walk cannot see the transit
// sessions that dominate a forwarding node, and since #5085 the receiver
// DELETES every eligible session the window omits. Framing cold prime from the
// mirror therefore wipes the standby's live peer-owned transit sessions.
//
// The source failing is NOT a reason to fall back to the mirror: an incomplete
// authoritative window is destructive, whereas skipping this bulk only defers
// the reconcile and every caller re-arms its cold-prime / resync obligation.
func (s *SessionSync) doBulkSync() error {
	if s.BulkSyncOverride != nil {
		slog.Info("cluster sync: running bulk sync override (fast-population pre-step)")
		if err := s.BulkSyncOverride(); err != nil {
			slog.Warn("cluster sync: bulk sync override failed; authoritative BulkSync still runs", "err", err)
		}
	}
	if src := s.BulkSnapshotSource; src != nil {
		// #9508: capture the fence BEFORE the snapshot is read; only a snapshot
		// read after the capture holds every delta written before it.
		fence := s.captureBarrierFenceForBulk()
		snap, err := src()
		if err != nil {
			// Fail closed — see the doc comment above.
			return fmt.Errorf("bulk sync table-truth snapshot: %w", err)
		}
		walk := snapshotBulkWalk(snap)
		walk.fence = fence
		return s.bulkSyncWindow(walk)
	}
	return s.BulkSync()
}

// BulkSnapshot is a caller-supplied, already-filtered set of locally-owned
// forward sessions for one authoritative bulk window (#6031). Its entries are
// framed verbatim — see SessionSync.BulkSnapshotSource for why the zone filter
// is deliberately NOT re-applied on top of the caller's owner-RG filter.
type BulkSnapshot struct {
	V4 []dataplane.SessionEntryV4
	V6 []dataplane.SessionEntryV6
}

// BulkSync sends all locally-owned forward sessions to the peer inside a
// BulkStart -> sessions -> BulkEnd window, using lossless direct writes so the
// receiver reconciles stale peer-owned sessions against the true snapshot.
//
// The session set comes from the backend session store, filtered by
// ShouldSyncZone. Under the userspace dataplane that store is the BPF conntrack
// DISPLAY mirror and is NOT table truth (#6031) — prefer BulkSyncSnapshot,
// which doBulkSync selects automatically whenever BulkSnapshotSource is wired.
func (s *SessionSync) BulkSync() error {
	if s.sessions == nil {
		return fmt.Errorf("session store not ready")
	}
	return s.bulkSyncWindow(s.storeBulkWalk())
}

// BulkSyncSnapshot frames the caller-supplied table-truth snapshot inside the
// same lossless BulkStart -> sessions -> BulkEnd direct-write window BulkSync
// uses (#6031). It needs no backend session store: the snapshot IS the source.
func (s *SessionSync) BulkSyncSnapshot(snap BulkSnapshot) error {
	return s.bulkSyncWindow(snapshotBulkWalk(snap))
}

// bulkWalk supplies the forward sessions one authoritative window frames. Each
// walk applies its own eligibility filter before yielding: the store walk drops
// reverse entries and zones this node does not own, while a caller-supplied
// snapshot is already filtered and is yielded verbatim.
type bulkWalk struct {
	forEachV4 func(func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	forEachV6 func(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	// source names the walk in the bulk-sync logs so an operator can tell a
	// table-truth window from a mirror-sourced one at a glance.
	source string
	// skipped counts entries the walk's own filter dropped, for the same logs.
	skipped int
	// fence is the #9508 barrier-fence capture this window may discharge
	// (epoch+1; 0 = none). It must be taken BEFORE the source is read: a caller
	// that read its snapshot first gets none unless it captured first, as
	// doBulkSync does. readsDuringWindow walks read after BulkStart, so the
	// window captures for them there.
	fence             uint64
	readsDuringWindow bool
}

func (s *SessionSync) storeBulkWalk() *bulkWalk {
	w := &bulkWalk{source: "store-mirror", readsDuringWindow: true}
	w.forEachV4 = func(yield func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
		return s.sessions.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if val.IsReverse != 0 {
				return true
			}
			if !s.ShouldSyncZone(val.IngressZone) {
				w.skipped++
				return true
			}
			return yield(key, val)
		})
	}
	w.forEachV6 = func(yield func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
		return s.sessions.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if val.IsReverse != 0 {
				return true
			}
			if !s.ShouldSyncZone(val.IngressZone) {
				w.skipped++
				return true
			}
			return yield(key, val)
		})
	}
	return w
}

func snapshotBulkWalk(snap BulkSnapshot) *bulkWalk {
	w := &bulkWalk{source: "table-truth"}
	w.forEachV4 = func(yield func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
		for _, e := range snap.V4 {
			if !yield(e.Key, e.Value) {
				return nil
			}
		}
		return nil
	}
	w.forEachV6 = func(yield func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
		for _, e := range snap.V6 {
			if !yield(e.Key, e.Value) {
				return nil
			}
		}
		return nil
	}
	return w
}

// bulkSyncWindow is the single lossless send core behind BulkSync and
// BulkSyncSnapshot: it owns the epoch, the BulkStart/BulkEnd markers, the
// install-generation stamping, the record-then-send bulk-ack discipline
// (#3912), and the writeMu direct writes. Only the session SOURCE differs.
func (s *SessionSync) bulkSyncWindow(walk *bulkWalk) error {
	s.bulkSendMu.Lock()
	defer s.bulkSendMu.Unlock()

	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("no peer connection")
	}
	// #9626: the cold-prime debt this bulk is sent to pay, taken when it STARTS.
	// An arm that lands after this point is a newer debt, and this bulk's ack
	// must not discharge it.
	owed := s.coldPrimeOwedGen()

	// Assign a monotonically increasing epoch to this bulk transfer.
	epoch := s.bulkSendNext.Add(1)
	var epochBuf [8]byte
	binary.LittleEndian.PutUint64(epochBuf[:], epoch)

	stats := s.Stats()
	slog.Info("cluster sync: bulk sync starting",
		"epoch", epoch,
		"source", walk.source,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn),
		"sessions_sent", stats.SessionsSent,
		"sessions_received", stats.SessionsReceived,
		"sessions_installed", stats.SessionsInstalled,
		"queue_len", len(s.sendCh),
		"queue_cap", cap(s.sendCh))

	// Send bulk start marker with epoch, plus this node's boot incarnation
	// (#5084). The payload grows 8 -> 24 bytes as a length-gated trailing
	// extension: an old receiver reads payload[:8] and ignores the tail, which
	// is the same #2170 discipline the delete frames use. BulkStart is the
	// carrier because the prime IS the claim event — the incarnation arrives in
	// the frame that declares it current, so no connection is ever installed
	// with an unknown incarnation.
	startPayload := appendBootIncarnation(epochBuf[:], localBootIncarnation())
	s.writeMu.Lock()
	moved := s.noteStreamConnLocked(conn) // #9508
	if walk.readsDuringWindow {
		walk.fence = s.fence.epoch.Load() + 1
	}
	err := writeMsg(conn, syncMsgBulkStart, startPayload)
	s.writeMu.Unlock()
	if moved {
		s.onStreamMoved(false)
	}
	if err != nil {
		s.clearPendingBulkAck()
		s.handleDisconnect(conn)
		return err
	}

	var count int
	slog.Info("cluster sync: bulk sync iterating v4", "epoch", epoch, "source", walk.source)
	// Send owned v4 forward sessions.
	err = walk.forEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		s.stampInstallGenV4(key, &val)
		msg := encodeSessionV4Payload(key, val)
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgSessionV4, msg)
		s.writeMu.Unlock()
		if err != nil {
			s.handleDisconnect(conn)
			slog.Warn("bulk sync v4 write error", "err", err)
			return false
		}
		count++
		// Yield briefly every 64 sessions to let barrier/bulk ack
		// writers acquire writeMu. Go's mutex is not fair — a tight
		// lock/unlock loop can starve other goroutines waiting on
		// the same mutex.
		if count%64 == 0 {
			runtime.Gosched()
		}
		return true
	})
	if err != nil {
		s.clearPendingBulkAck()
		return fmt.Errorf("bulk sync v4 iterate: %w", err)
	}
	slog.Info("cluster sync: bulk sync iterated v4",
		"epoch", epoch,
		"source", walk.source,
		"sessions", count,
		"skipped", walk.skipped)

	// Send owned v6 forward sessions.
	slog.Info("cluster sync: bulk sync iterating v6", "epoch", epoch, "source", walk.source, "sessions", count, "skipped", walk.skipped)
	err = walk.forEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		s.stampInstallGenV6(key, &val)
		msg := encodeSessionV6Payload(key, val)
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgSessionV6, msg)
		s.writeMu.Unlock()
		if err != nil {
			s.handleDisconnect(conn)
			slog.Warn("bulk sync v6 write error", "err", err)
			return false
		}
		count++
		if count%64 == 0 {
			runtime.Gosched()
		}
		return true
	})
	if err != nil {
		s.clearPendingBulkAck()
		return fmt.Errorf("bulk sync v6 iterate: %w", err)
	}
	slog.Info("cluster sync: bulk sync iterated v6",
		"epoch", epoch,
		"source", walk.source,
		"sessions", count,
		"skipped", walk.skipped)

	// Record the pending bulk-ack epoch BEFORE writing the BulkEnd marker
	// to the wire (record-then-send, mirroring the #2170/#2198 gen-guard
	// discipline). The peer's ack is processed on the read goroutine
	// (handleMessage, syncMsgBulkAck), which is independent of this send
	// goroutine. If we stored the pending epoch AFTER the write, a fast
	// peer could ack the BulkEnd and have the read goroutine process the
	// ack (seeing pendingBulkAckEpoch==0, so it drops it) before this
	// goroutine recorded the pending state. We would then latch a phantom
	// pending epoch that no future ack ever clears — permanently blocking
	// manual failover (#3912). Recording first guarantees the ack can only
	// ever observe the pending epoch already in place.
	// #9626: the debt stamp BEFORE the epoch, so an ack that observes the epoch
	// also observes the generation this bulk pays.
	s.pendingBulkOwed.Store(owed)
	s.pendingBulkAckEpoch.Store(epoch)
	s.fence.pendingBulk.Store(walk.fence) // #9508: AFTER the epoch; see barrierFence.pendingBulk
	s.pendingBulkAckSince.Store(time.Now().UnixNano())

	// Send bulk end marker with matching epoch, plus this node's boot
	// incarnation (#9174 V013). The payload grows 8 -> 24 bytes as a
	// length-gated trailing extension, exactly as BulkStart's did in #5084 and
	// the delete frames' generations did in #2170: an old receiver reads
	// payload[:8] and ignores the tail, so a mixed-version pair keeps working
	// for the whole rolling upgrade. ADDING a field, never redefining one.
	//
	// Why BulkEnd needs it at all: the epoch counter restarts at zero when the
	// peer reboots, so an end marker buffered on a dead boot's socket can carry
	// the SAME epoch as the bulk its own replacement has just started. Matched
	// on epoch alone that frame completes the live transfer, and the standby
	// reconciles against a partly-received table and releases the VRRP sync
	// hold. A node that cannot read its own boot id appends nothing and gets
	// today's epoch-only matching (appendBootIncarnation's fail-open arm).
	endPayload := appendBootIncarnation(epochBuf[:], localBootIncarnation())
	slog.Info("cluster sync: bulk sync writing end marker", "epoch", epoch, "source", walk.source, "sessions", count, "skipped", walk.skipped)
	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgBulkEnd, endPayload)
	s.writeMu.Unlock()
	if err != nil {
		s.clearPendingBulkAck()
		s.handleDisconnect(conn)
		return err
	}

	s.stats.BulkSyncs.Add(1)
	slog.Info("cluster sync: bulk sync complete", "source", walk.source, "sessions", count, "skipped", walk.skipped, "epoch", epoch)
	return nil
}

// PendingBulkAck reports the latest outbound bulk epoch that is still awaiting
// peer acknowledgement, if any.
func (s *SessionSync) PendingBulkAck() (epoch uint64, age time.Duration, ok bool) {
	epoch = s.pendingBulkAckEpoch.Load()
	if epoch == 0 {
		return 0, 0, false
	}
	since := s.pendingBulkAckSince.Load()
	if since == 0 {
		return epoch, 0, true
	}
	age = time.Since(time.Unix(0, since))
	if age < 0 {
		age = 0
	}
	return epoch, age, true
}

// BulkAckPendingRetryAfter is how long an outbound bulk may await its BulkAck
// before a retry treats it as lost (#9626). The daemon's bulk-prime retry loop
// (startSessionSyncPrimeRetry) and the sweep's owed cold-prime re-drive both
// wait this long, so there is one number for "the ack is late".
const BulkAckPendingRetryAfter = 35 * time.Second

// clearPendingBulkAck forgets the pending outbound bulk: its epoch, its start
// time, and the cold-prime generation it was sent to pay (#9626). Every path
// that abandons a pending bulk goes through here, so a stale stamp cannot
// survive to discharge a later debt.
func (s *SessionSync) clearPendingBulkAck() {
	s.pendingBulkAckEpoch.Store(0)
	s.pendingBulkAckSince.Store(0)
	s.pendingBulkOwed.Store(0)
}

// armColdPrimeLocked records a cold-prime obligation under a NEW generation
// (#9626). Callers hold s.mu.
func (s *SessionSync) armColdPrimeLocked() {
	s.coldPrimeGen.Add(1)
	s.needColdPrime.Store(true)
}

// coldPrimeOwedGen is the generation of the outstanding cold-prime debt, or 0
// when none is owed. It is read under s.mu, so it is consistent with the arms.
func (s *SessionSync) coldPrimeOwedGen() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.needColdPrime.Load() {
		return 0
	}
	return s.coldPrimeGen.Load()
}

// dischargeColdPrime clears the cold-prime obligation on the peer's
// acknowledgement of a bulk that was sent to pay generation stamp (#9626). It
// does nothing when that bulk paid no debt (stamp 0), or when a newer arm has
// happened since the bulk started: that debt belongs to a later bulk's ack.
func (s *SessionSync) dischargeColdPrime(stamp uint64) {
	if stamp == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coldPrimeGen.Load() == stamp {
		s.needColdPrime.Store(false)
	}
}

// coldPrimeAckAwaited reports whether the owed cold prime has already been sent
// and its ack may still be on the way (#9626): the pending bulk was stamped
// with the CURRENT debt and is younger than BulkAckPendingRetryAfter. The
// sweep's owed re-drive skips while it holds, instead of re-bulking the peer
// every tick while a healthy ack is in flight.
func (s *SessionSync) coldPrimeAckAwaited() bool {
	stamp := s.pendingBulkOwed.Load()
	if stamp == 0 || stamp != s.coldPrimeOwedGen() {
		return false
	}
	_, age, ok := s.PendingBulkAck()
	return ok && age < BulkAckPendingRetryAfter
}

// TransferReadiness snapshots the sync state that makes manual failover
// timing-sensitive: an unacked outbound bulk, an in-progress inbound bulk, or
// (#5563) a config-stale standby that has received a newer config generation
// from the peer than it has successfully applied.
func (s *SessionSync) TransferReadiness() TransferReadinessSnapshot {
	snap := TransferReadinessSnapshot{
		Connected: s.stats.Connected.Load(),
	}
	if epoch, age, ok := s.PendingBulkAck(); ok {
		snap.PendingBulkAckEpoch = epoch
		snap.PendingBulkAckAge = age
	}
	s.bulkMu.Lock()
	snap.BulkReceiveInProgress = s.bulkInProgress
	snap.BulkReceiveEpoch = s.bulkRecvEpoch
	snap.BulkReceiveSessions = len(s.bulkRecvV4) + len(s.bulkRecvV6)
	s.bulkMu.Unlock()
	// #5563: config-sync generations for the planned-failover staleness gate.
	// PeerConfigGen is the highest generation received from the peer (its
	// current committed config as observed here); AppliedConfigGen is the
	// highest generation successfully applied. A receiver behind the primary
	// (PeerConfigGen > AppliedConfigGen) is refused promotion.
	snap.PeerConfigGen = s.lastRecvConfigGen.Load()
	snap.AppliedConfigGen = s.lastAppliedConfigGen.Load()
	return snap
}

func (s *SessionSync) sendBarrierAck(conn net.Conn, seq uint64) {
	if conn == nil {
		return
	}
	// Write barrier ack directly under writeMu. If the send loop is
	// blocked behind bulk/session writes, routing the ack through sendCh
	// would delay the response behind traffic that doesn't need FIFO
	// ordering with the ack itself.
	var payload [24]byte
	binary.LittleEndian.PutUint64(payload[:], seq)
	stats := s.Stats()
	binary.LittleEndian.PutUint64(payload[8:16], stats.SessionsReceived)
	binary.LittleEndian.PutUint64(payload[16:24], stats.SessionsInstalled)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgBarrierAck, payload[:])
	s.writeMu.Unlock()
	if err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: barrier ack write failed", "seq", seq, "err", err)
		return
	}
	slog.Info("cluster sync: barrier ack sent",
		"seq", seq,
		"sessions_received", stats.SessionsReceived,
		"sessions_installed", stats.SessionsInstalled)
}

// barrierWaiter is one pending WaitForPeerBarrier.
//
// #9822: `fenced` records that the waiter was released by the stream-move sweep
// rather than by an ack, so a woken barrier is TOLD why it woke instead of
// inferring it from the fence epoch. The inference had a window. Every caller of
// noteStreamConnLocked bumps the epoch under writeMu, RELEASES writeMu, and only
// then calls onStreamMoved, so the sweep can land arbitrarily late; a barrier
// that starts in that gap — admissible because an acked re-prime discharged the
// fence — captures the ALREADY-BUMPED epoch, sees no change at wake-up, and
// reported "session sync disconnected during barrier wait" for a connection that
// never went away. The caller's remedy for a fenced barrier is to re-prime and
// retry, and its remedy for a disconnect is not, so the misreport is not
// cosmetic.
type barrierWaiter struct {
	ch chan struct{}
	// fenced is written under barrierWaitMu before ch is closed, and read under
	// it after the wake, so the reason cannot race the wake-up.
	fenced bool
}

func (s *SessionSync) completeBarrierWait(seq uint64) {
	s.barrierWaitMu.Lock()
	waiter := s.barrierWaiters[seq]
	delete(s.barrierWaiters, seq)
	s.barrierWaitMu.Unlock()
	if waiter != nil {
		close(waiter.ch)
	}
}

func (s *SessionSync) sendBulkAck(conn net.Conn, epoch uint64) {
	if conn == nil {
		slog.Debug("cluster sync: skipping bulk ack on nil connection", "epoch", epoch)
		return
	}
	// Write bulk ack directly under writeMu — same rationale as
	// sendBarrierAck.
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], epoch)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgBulkAck, payload[:])
	s.writeMu.Unlock()
	if err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: bulk ack write failed", "epoch", epoch, "err", err)
		return
	}
	slog.Info("cluster sync: bulk ack sent",
		"epoch", epoch,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn))
}

func (s *SessionSync) writeBarrierMessage(payload []byte, timeout time.Duration) error {
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("session sync not connected")
	}
	// Barrier requests go through sendCh to preserve ordering with
	// already-queued session messages. The peer's ack must prove it
	// processed every earlier delta, not just the barrier itself.
	msg := encodeRawMessage(syncMsgBarrier, payload)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case s.sendCh <- msg:
	case <-timer.C:
		return fmt.Errorf("timed out queueing session sync barrier")
	}
	seq := binary.LittleEndian.Uint64(payload)
	slog.Info("cluster sync: barrier queued (ordered)",
		"seq", seq,
		"local", connLocalAddrString(conn),
		"remote", connRemoteAddrString(conn))
	return nil
}

// WaitForPeerBarrier queues an ordered marker on the session-sync stream and
// waits until the peer acknowledges that it processed all earlier messages.
func (s *SessionSync) WaitForPeerBarrier(timeout time.Duration) error {
	if !s.stats.Connected.Load() {
		return fmt.Errorf("session sync not connected")
	}
	// #9508: snapshot the fence epoch BEFORE checking it, so a move between the
	// two is still seen at wake-up.
	fence := s.fence.epoch.Load()
	if s.barrierFenced() {
		s.scheduleBarrierFenceReprime("barrier refused")
		return barrierFencedError(0)
	}
	seq := s.barrierSeq.Add(1)
	waiter := &barrierWaiter{ch: make(chan struct{})}
	s.barrierWaitMu.Lock()
	if s.barrierWaiters == nil {
		s.barrierWaiters = make(map[uint64]*barrierWaiter)
	}
	s.barrierWaiters[seq] = waiter
	s.barrierWaitMu.Unlock()

	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], seq)
	stats := s.Stats()
	slog.Info("cluster sync: queueing barrier",
		"seq", seq,
		"sessions_sent", stats.SessionsSent,
		"sessions_received", stats.SessionsReceived,
		"sessions_installed", stats.SessionsInstalled,
		"queue_len", len(s.sendCh),
		"queue_cap", cap(s.sendCh))
	if err := s.writeBarrierMessage(payload[:], timeout/2); err != nil {
		s.barrierWaitMu.Lock()
		delete(s.barrierWaiters, seq)
		s.barrierWaitMu.Unlock()
		return err
	}
	// Record the install fence sequence for status observability (#311).
	s.stats.LastFenceSeq.Store(seq)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-waiter.ch:
		// The waiter channel can be closed by either completeBarrierWait
		// (barrier acked) or handleDisconnect (connection lost). Check
		// whether the barrier was actually acknowledged.
		//
		// #9508: an ACK proves the peer processed the stream on ONE connection.
		// If the stream moved while this barrier was pending, earlier frames may
		// be on another connection, unprocessed or lost, so the ACK is not
		// readiness.
		// #9822: the sweep says so directly. The epoch comparison below still
		// catches a move this waiter was registered BEFORE, but it cannot see one
		// whose sweep landed after this barrier captured the bumped epoch.
		s.barrierWaitMu.Lock()
		sweptByMove := waiter.fenced
		s.barrierWaitMu.Unlock()
		if sweptByMove || s.fence.epoch.Load() != fence {
			s.scheduleBarrierFenceReprime("barrier refused")
			return barrierFencedError(seq)
		}
		if s.barrierAckSeq.Load() >= seq {
			return nil
		}
		return fmt.Errorf("session sync disconnected during barrier wait seq=%d", seq)
	case <-timer.C:
		s.barrierWaitMu.Lock()
		delete(s.barrierWaiters, seq)
		s.barrierWaitMu.Unlock()
		stats := s.Stats()
		return fmt.Errorf(
			"timed out waiting for session sync barrier ack seq=%d sessions_sent=%d sessions_received=%d sessions_installed=%d queue_len=%d",
			seq,
			stats.SessionsSent,
			stats.SessionsReceived,
			stats.SessionsInstalled,
			len(s.sendCh),
		)
	}
}

// WaitForPeerBarriersDrained waits until all still-pending barrier waiters have
// been acknowledged by the peer. Timed-out barriers are not treated as
// permanently blocking: a later barrier ack is cumulative, so retries should
// not get stuck on stale sequence numbers after the original waiter was removed.
func (s *SessionSync) WaitForPeerBarriersDrained(timeout time.Duration) error {
	s.barrierWaitMu.Lock()
	target := uint64(0)
	for seq := range s.barrierWaiters {
		if seq > target {
			target = seq
		}
	}
	s.barrierWaitMu.Unlock()
	if target == 0 || s.barrierAckSeq.Load() >= target {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.barrierAckSeq.Load() >= target {
			return nil
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return fmt.Errorf(
				"timed out waiting for previous session sync barriers acked through seq=%d last_acked=%d",
				target,
				s.barrierAckSeq.Load(),
			)
		}
	}
}

// bulkStartStaleLocked reports whether an inbound BulkStart must be REFUSED as
// stale. Caller holds s.bulkMu.
//
// #8966 established the within-a-bulk half: BulkEnd refuses an epoch that does
// not match the in-progress one, BulkStart compared nothing, so a delayed or
// reordered start carrying a lower epoch discarded the newer bulk's accumulated
// receive set and the newer BulkEnd was then rejected as mismatched.
//
// #9174 V015 is the half that guard could not reach. `reconcileStaleSessions`
// clears `bulkInProgress` at BulkEnd and leaves `bulkRecvEpoch` standing, so
// BETWEEN two bulks the `s.bulkInProgress` conjunct made the whole condition
// false and any epoch was accepted — reopening a receive window for a transfer
// that had already finished, resetting the accumulators, and driving a reconcile
// against a set that was never received. Two consecutive bulks CAN pin different
// fabrics (`BulkSync` pins `getActiveConn` once), which is the ordinary route to
// a reordered pair.
//
// THE BETWEEN-BULKS ARM REQUIRES AN INCARNATION ON THE FRAME, and that is the
// load-bearing part of this predicate rather than a hedge. Within a bulk,
// refusing a not-newer start costs at most one re-prime, because a bulk is
// already in flight. Between bulks there is nothing in flight, so a wrong
// refusal is terminal for that transfer — and a peer that REBOOTED legitimately
// restarts its epoch counter lower (#2198 F2). `switched` separates the two, but
// only when the peer sends an incarnation at all. With no incarnation on the
// wire, "the peer rebooted and restarted its counter" and "this start is stale"
// are the same bytes, so the answer is today's accept: the #5084 fail-open, for
// the same reason (failing closed strands the standby of a peer on an older
// build for the whole rolling-upgrade window).
//
// `bulkRecvEpoch != 0` keeps a peer that never sent an epoch at all out of the
// arm: its high-water stays 0, so its epoch-0 starts are never compared against
// a value they cannot exceed.
func (s *SessionSync) bulkStartStaleLocked(epoch uint64, inc bootIncarnation, switched bool) bool {
	if switched {
		// #2198 F2: across a boot-incarnation change a LOWER epoch is
		// legitimate — the peer rebooted and its counter restarted — and
		// accept-and-reset is the correct treatment.
		return false
	}
	if epoch > s.bulkRecvEpoch {
		// Strictly newer is always admissible.
		return false
	}
	if s.bulkInProgress {
		// #8966: within one bulk, a start that is not strictly newer is a
		// retransmit or a cross-fabric reorder. `<=` rather than `<` because a
		// duplicate at the SAME epoch resets the accumulators for a bulk
		// already in progress and then fails its own BulkEnd.
		return true
	}
	return s.bulkRecvEpoch != 0 && inc.known()
}
