package cluster

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

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
			if hdr.Length > 16*1024*1024 {
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
func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) {
	switch msgType {
	case syncMsgSessionV4:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			count := s.stats.BulkSyncSessions.Add(1)
			if count == 1 || count%64 == 0 {
				s.bulkMu.Lock()
				epoch := s.bulkRecvEpoch
				s.bulkMu.Unlock()
				slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", "v4", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
			}
		}
		if s.sessions != nil {
			key, val, ok := decodeSessionV4Payload(payload)
			if !ok {
				// #7175: a truncated record used to decode ok=true with PolicyID,
				// both zone ids and the NAT fields left at zero. It is now
				// rejected — and counted, because a silently skipped install is
				// how fabric corruption or a version-skewed peer hides.
				s.stats.MalformedRecordsDropped.Add(1)
				slog.Warn("cluster sync: dropping malformed v4 session record — no session installed",
					"bytes", len(payload))
			} else {
				if val.IsReverse == 0 {
					s.bulkMu.Lock()
					if s.bulkInProgress {
						s.bulkRecvV4[key] = struct{}{}
					}
					s.bulkMu.Unlock()
				}
				offset := s.clockOffsetFor(conn)
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
				s.installClusterSyncedV4(key, val)
			}
		}
	case syncMsgSessionV6:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			count := s.stats.BulkSyncSessions.Add(1)
			if count == 1 || count%64 == 0 {
				s.bulkMu.Lock()
				epoch := s.bulkRecvEpoch
				s.bulkMu.Unlock()
				slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", "v6", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
			}
		}
		if s.sessions != nil {
			key, val, ok := decodeSessionV6Payload(payload)
			if !ok {
				// #7175: a truncated record used to decode ok=true with PolicyID,
				// both zone ids and the NAT fields left at zero. It is now
				// rejected — and counted, because a silently skipped install is
				// how fabric corruption or a version-skewed peer hides.
				s.stats.MalformedRecordsDropped.Add(1)
				slog.Warn("cluster sync: dropping malformed v6 session record — no session installed",
					"bytes", len(payload))
			} else {
				if val.IsReverse == 0 {
					s.bulkMu.Lock()
					if s.bulkInProgress {
						s.bulkRecvV6[key] = struct{}{}
					}
					s.bulkMu.Unlock()
				}
				offset := s.clockOffsetFor(conn)
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
				s.installClusterSyncedV6(key, val)
			}
		}
	case syncMsgDeleteV4:
		s.stats.DeletesReceived.Add(1)
		if s.sessions != nil && len(payload) >= 16 {
			var key dataplane.SessionKey
			copy(key.SrcIP[:], payload[0:4])
			copy(key.DstIP[:], payload[4:8])
			key.SrcPort = binary.LittleEndian.Uint16(payload[8:10])
			key.DstPort = binary.LittleEndian.Uint16(payload[10:12])
			key.Protocol = payload[12]
			// #2170: length-gated trailing install generation (absent on a
			// legacy peer → 0 → unconditional delete in the apply guard).
			var gen uint64
			if len(payload) >= 24 {
				gen = binary.LittleEndian.Uint64(payload[16:24])
			}
			s.deleteClusterSyncedV4(key, gen)
		}
	case syncMsgDeleteV6:
		s.stats.DeletesReceived.Add(1)
		if s.sessions != nil && len(payload) >= 40 {
			var key dataplane.SessionKeyV6
			copy(key.SrcIP[:], payload[0:16])
			copy(key.DstIP[:], payload[16:32])
			key.SrcPort = binary.LittleEndian.Uint16(payload[32:34])
			key.DstPort = binary.LittleEndian.Uint16(payload[34:36])
			key.Protocol = payload[36]
			// #2170: length-gated trailing install generation.
			var gen uint64
			if len(payload) >= 48 {
				gen = binary.LittleEndian.Uint64(payload[40:48])
			}
			s.deleteClusterSyncedV6(key, gen)
		}
	case syncMsgBulkStart:
		var epoch uint64
		if len(payload) >= 8 {
			epoch = binary.LittleEndian.Uint64(payload[:8])
		}
		// #5084: the peer's boot incarnation, when it sent one. Recorded on the
		// CONNECTION so every config payload arriving on it is stamped with the
		// incarnation that primed it, and compared against the receiver-wide
		// current incarnation to decide a namespace switch.
		//
		// ORDER MATTERS: both records land BEFORE resetRecvGen below. Reversing
		// them opens a window in which the high-waters are already zeroed while
		// the current incarnation is still the DEAD one, so a prior-boot payload
		// dequeued by configApplyLoop in that window passes the fence and
		// records its (large) generation — the exact defect this exists to
		// close. In this order there is no such window.
		//
		// Not covered by a test, and deliberately called out rather than left
		// implied: binding it would mean interleaving the apply-loop goroutine
		// between two adjacent statements here, which no deterministic fixture
		// in this package can do. A mutation moving both records after the
		// reset leaves the whole suite green.
		inc := parseBootIncarnation(payload)
		s.noteConnBootIncarnation(conn, inc)
		// #6910: capture the PRIOR incarnation before the note overwrites it —
		// distinguishing a first prime (zero -> X) from a reboot (X -> Y)
		// requires the old value, and notePeerBootIncarnation's bool does not
		// carry it.
		priorInc := s.PeerBootIncarnation()
		switched := s.notePeerBootIncarnation(inc)
		// #2198 F2: the peer is re-priming its authoritative live set. Reset
		// our stored generations so a rebooted peer's bulk (whose genCounter
		// restarted lower) is accepted by the install guard instead of being
		// refused as stale (stale-RETAIN, the inverse of #2170).
		zoneSnap := s.snapshotZoneOwnership()
		s.bulkMu.Lock()
		// #8966: GUARD THE START THE WAY THE END IS GUARDED.
		//
		// `BulkEnd` at the bottom of this function refuses an epoch that does
		// not match the in-progress one. `BulkStart` compared nothing: it
		// assigned `bulkRecvEpoch` unconditionally and reset the accumulators,
		// so a delayed or reordered BulkStart carrying a LOWER epoch -- the
		// ordinary case with two fabric streams -- discarded the newer bulk's
		// accumulated receive set, after which the newer BulkEnd was rejected
		// as mismatched. Two handlers disagreeing about which epoch is
		// authoritative, and only one of them checking.
		//
		// THE #2198 F2 RATIONALE ABOVE IS TRUE AND COVERS A DIFFERENT CASE. A
		// rebooted peer legitimately restarts its genCounter lower, and
		// refusing that bulk would strand the standby. But the code could not
		// tell "the peer rebooted and is re-priming" from "an older BulkStart
		// arrived late on the other stream", and applied the reboot treatment
		// to both.
		//
		// `switched` -- already computed above for #6910's fabric preference --
		// is exactly that discriminator, so the information was in hand and
		// simply not consulted by the code that needed it. Across an
		// incarnation change, keep accept-and-reset: that IS the #2198 case.
		// Within one incarnation, a BulkStart must be strictly newer.
		//
		// #9174 V015: the same question is asked BETWEEN bulks, where the
		// original guard could not reach. See bulkStartStaleLocked.
		if s.bulkStartStaleLocked(epoch, inc, switched) {
			inProgress := s.bulkRecvEpoch
			active := s.bulkInProgress
			v4, v6 := len(s.bulkRecvV4), len(s.bulkRecvV6)
			s.bulkMu.Unlock()
			slog.Warn("cluster sync: ignoring stale BulkStart within the same boot incarnation",
				"in_progress_epoch", inProgress, "got_epoch", epoch,
				"bulk_in_progress", active,
				"accumulated_v4", v4, "accumulated_v6", v6,
				"peer_incarnation", inc)
			break
		}
		s.bulkInProgress = true
		s.bulkRecvEpoch = epoch
		// #9174 V013: remember WHICH BOOT started this bulk, so its end marker
		// can be matched on more than the epoch. Recorded on the accepted path
		// only, beside the epoch it belongs to.
		s.bulkRecvIncarnation = inc
		// #9716: and WHICH CONNECTION carried it. Its BulkEnd is accepted only
		// there; see the BulkEnd arm.
		s.bulkRecvConn = conn
		s.bulkRecvV4 = make(map[dataplane.SessionKey]struct{})
		s.bulkRecvV6 = make(map[dataplane.SessionKeyV6]struct{})
		s.bulkZoneSnapshot = zoneSnap
		s.bulkMu.Unlock()
		// The generation reset moves to the ACCEPTED path only. It is the
		// #2198 F2 remedy for a re-priming peer, and running it for a stale
		// BulkStart discarded the generations of a bulk that was still valid.
		//
		// It stays OUTSIDE `bulkMu`, where it has always been. `resetRecvGen`
		// takes `recvGenMu`, and pulling it inside would add a bulkMu ->
		// recvGenMu edge to the lock graph as a side effect of a correctness
		// fix -- a change nothing here needs and nobody would look for.
		s.resetRecvGen()
		// #9177 V052: the bulk TELEMETRY belongs on the accepted path too, and
		// it used to run above the accept. A REFUSED BulkStart -- the reordered
		// one #8966's own text calls "the ordinary case" with two fabric
		// streams -- re-stamped BulkSyncStartTime and zeroed BulkSyncEndTime on
		// its way to being rejected. `show chassis cluster information` then
		// read "Bulk sync in progress since ..." indefinitely, because the
		// BulkEnd that would set an end time belongs to a bulk that was never
		// accepted; and the session handlers' `StartTime > 0 && EndTime == 0`
		// test read TRUE, so every subsequent INCREMENTAL install was counted
		// as bulk traffic.
		//
		// This is a statement-ORDERING defect, not an epoch-validation one: the
		// accept itself is correct. The #8966 author moved `resetRecvGen` below
		// the accept for exactly this reason and left these three where they
		// were, which is why they now sit beside it.
		s.stats.BulkSyncStartTime.Store(time.Now().UnixNano())
		s.stats.BulkSyncEndTime.Store(0)
		s.stats.BulkSyncSessions.Store(0)
		// #6910: ACT on the switch, do not merely report it. Until now
		// `switched` reached only this log line, so a reboot whose replacement
		// primed on the alternate fabric left the corpse installed, stamped
		// current, and winning fab0 preference in preferredFabricLocked — the
		// consequence the issue is actually about.
		//
		// This is peer-supplied evidence, not a local inference: the boot id on
		// the wire changed, which only a new peer boot produces. installConn
		// deliberately refuses to guess from slot occupancy; here there is
		// nothing to guess.
		//
		// Scoped to the connection that PRIMED. A replacement that never primes
		// carries no boot id (connBootIncarnation is zero for it, fail-open by
		// design), so this cannot reach that case — see the LIMIT comment in
		// installConn and #7762.
		//
		// GUARDED ON THE PRIOR VALUE BEING KNOWN, and this is not a nicety.
		// notePeerBootIncarnation reports `switched` for zero -> X as well as
		// for X -> Y, because both change the recorded incarnation. Only the
		// second is a REBOOT; the first is simply the first incarnated prime
		// this SessionSync has seen. Acting on it would advance the incarnation
		// and evict the peer's OTHER fabric — a healthy connection from the same
		// boot — which is the routine second-fabric case #5718's tests exist to
		// protect. So the remedy needs "we knew a DIFFERENT boot before", which
		// `switched` alone does not say.
		// #9636: this switch is one of TWO reboot classifiers, and
		// classifyPrimeLocked reconciles it with installConn's epoch arm. It
		// also settles an epoch retirement on a prime whose boot id did not
		// change, so it runs for every accepted BulkStart, not only a switch.
		s.mu.Lock()
		pc := s.classifyPrimeLocked(conn, switched, priorInc.known())
		s.mu.Unlock()
		if pc.announce && s.OnPeerConnected != nil {
			// No install classified this reboot, so the new process's
			// OnPeerConnected comes from here.
			slog.Info("cluster sync: scheduling OnPeerConnected callback for a peer reboot classified by its boot id",
				"remote", connRemoteAddrString(conn))
			go s.OnPeerConnected()
		}
		slog.Info("cluster sync: bulk transfer starting", "epoch", epoch,
			"peer_boot_incarnation", inc.String(), "incarnation_switched", switched,
			"retired_incarnation", pc.retired, "reboot_already_retired", pc.consumed,
			"evicted_stale_incarnation_conn", pc.evicted,
			"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		// #5084: a peer that primes without an incarnation gets today's
		// generation-only ordering (fail open). Warn ONCE per connection, not
		// per frame — a silent fallback is how a half-upgraded cluster hides,
		// and the CLAUDE.md logging rule forbids the per-frame version.
		if !inc.known() {
			s.warnUnincarnatedPrimeOnce(conn)
		}
	case syncMsgBulkEnd:
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
			break
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
			break
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
			break
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
			break
		}
		// #9716: a completion the incarnation check could not judge is matched on
		// epoch and connection alone. Count it, so a half-upgraded pair is visible.
		if !endInc.known() || !s.bulkRecvIncarnation.known() {
			s.stats.BulkEndsEpochOnlyMatched.Add(1)
		}
		s.bulkMu.Unlock()
		s.stats.BulkSyncEndTime.Store(time.Now().UnixNano())
		s.reconcileStaleSessions()
		slog.Info("cluster sync: bulk transfer complete", "epoch", epoch, "sessions", s.stats.BulkSyncSessions.Load(), "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		s.sendBulkAck(conn, epoch)
		s.bulkEverCompleted.Store(true)
		if s.OnBulkSyncReceived != nil {
			go s.OnBulkSyncReceived()
		}
	case syncMsgBulkAck:
		if len(payload) < 8 {
			slog.Warn("cluster sync: bulk ack message too short")
			return
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
			return
		}
		owed := s.pendingBulkOwed.Load() // #9626: the debt this bulk was sent to pay
		s.clearPendingBulkAck()
		s.bulkEverCompleted.Store(true)
		// #4360: the peer acked OUR outbound bulk — record it on the
		// outbound-only flag so a stranded outbound bulk can be re-driven on a
		// survivor fabric independently of whether an inbound bulk (which also
		// sets bulkEverCompleted at syncMsgBulkEnd) completed first.
		s.outboundBulkAcked.Store(true)
		s.dischargeBarrierFence(fenceCapture)
		// #9626: the peer now holds the table this bulk carried, which is what
		// discharges an owed cold prime, and only the one the bulk was sent for.
		s.dischargeColdPrime(owed)
		if s.OnBulkSyncAckReceived != nil {
			go s.OnBulkSyncAckReceived()
		}
	case syncMsgConfigApplyNack:
		// #7328: the peer did not apply a config generation this node pushed.
		// Length-gated: a short/absent payload is ignored rather than treated
		// as generation 0, which would be a valid-looking "legacy" value.
		if len(payload) < 8 {
			slog.Debug("cluster sync: short config-apply nack ignored", "len", len(payload))
			return
		}
		nackedGen := binary.LittleEndian.Uint64(payload[:8])
		// Only a nack for the generation this node most recently sent can
		// re-arm the push marker. An older generation is a straggler for a
		// push already superseded by a newer one; acting on it would re-push
		// a config the peer may already have applied.
		if sent := s.lastSentConfigGen.Load(); nackedGen != sent {
			slog.Debug("cluster sync: ignoring stale config-apply nack",
				"nacked_gen", nackedGen, "last_sent_gen", sent)
			return
		}
		s.stats.ConfigApplyNacksReceived.Add(1)
		slog.Warn("cluster sync: peer did not apply the config generation we pushed — re-arming the push marker",
			"gen", nackedGen)
		if s.OnPeerConfigApplyFailed != nil {
			s.OnPeerConfigApplyFailed(nackedGen)
		}
	case syncMsgHeartbeat:
		if conn == nil {
			return
		}
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgHeartbeatAck, nil)
		s.writeMu.Unlock()
		if err != nil {
			slog.Debug("cluster sync: heartbeat ack send error", "err", err)
			s.stats.Errors.Add(1)
			s.handleDisconnect(conn)
		}
	case syncMsgHeartbeatAck:
		// #5718 C01a (fold F1): bind the capability to the peer INCARNATION
		// that proved it — only a currently-installed fabric connection can
		// speak for the current one. See noteHeartbeatAck (sync_conn.go).
		s.noteHeartbeatAck(conn)
	case syncMsgConfig:
		s.handleConfigPayload(conn, payload)
	case syncMsgConfigEncrypted:
		// #6629: same payload, sealed under this connection's ephemeral key.
		// Decrypt, then hand the plaintext to the SAME handler — the two arms
		// must never diverge in ordering, generation accounting or apply
		// admission, and a divergence there would always be a bug, so there is
		// one implementation rather than two kept in agreement.
		key := s.configKeyForConn(conn)
		if key == nil {
			// A sealed payload arrived on a connection with no derived key:
			// either the exchange never completed or this is a stale
			// connection the slots no longer reference. Either way it cannot
			// be opened, and it must NOT be opened with another connection's
			// key. Drop it; the sender re-pushes on the next reconcile tick.
			//
			// NOT BOUND BY A TEST, and deliberately recorded as such: removing
			// this branch changes nothing observable, because
			// openConfigPayload fails closed on a nil key (aes.NewCipher(nil)
			// errors) and the decrypt-failure branch below drops the payload
			// anyway. It is kept for the DIAGNOSTIC — "we never negotiated"
			// and "it did not decrypt" send an operator to entirely different
			// places — and as defence in depth if openConfigPayload ever grows
			// a path that tolerates a short key. The safety property (an
			// unopenable payload never reaches the apply path) is bound by
			// TestConfigCryptoDropsUndecryptablePayload6629.
			s.stats.Errors.Add(1)
			slog.Error("cluster sync: encrypted config received but no key was negotiated on "+
				"this connection — dropping (#6629)", "remote", connRemoteAddrString(conn))
			return
		}
		plaintext, err := openConfigPayload(key, payload)
		if err != nil {
			s.stats.Errors.Add(1)
			slog.Error("cluster sync: could not decrypt config payload — dropping (#6629)",
				"err", err, "remote", connRemoteAddrString(conn))
			return
		}
		s.handleConfigPayload(conn, plaintext)
	case syncMsgConfigKeyExchange:
		s.handleConfigKeyExchange(conn, payload)
	case syncMsgAuthUpgradeRequest:
		// #6628: the responder-role peer committed a key and is asking THIS
		// node (the initiator by node id) to start the exchange.
		s.handleAuthUpgradeRequest(conn, payload)
	case syncMsgAuthUpgradeHello:
		// #6628: the peer committed a key and is offering to authenticate this
		// established connection in place. Never drops it.
		s.handleAuthUpgradeHello(conn, payload)
	case syncMsgAuthUpgradeProof:
		s.handleAuthUpgradeProof(conn, payload)
	case syncMsgAuthUpgradeConfirm:
		s.handleAuthUpgradeConfirm(conn, payload)
	case syncMsgIPsecSA:
		s.stats.IPsecSAReceived.Add(1)
		// #5706: split off the (incarnation, seq) ordering trailer and admit
		// only a strictly-newer full-set. A stale set reordered across the
		// redundant fabric streams is dropped so it cannot regress the held SA
		// set. A legacy peer sends no trailer -> (0,0) -> accept-always.
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.ipsecRecvSeq.admit(incarnation, seq)
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.IPsecSAStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order IPsec SA set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		// #5706 review fold: strip the '\n' delimiter a new sender inserts
		// between the SA name list and the trailer so a new->new roundtrip
		// leaves no trailing empty name. A legacy / pre-fold frame has no
		// delimiter, so this is a no-op for it.
		names, malformed := decodeIPsecSAPayload(stripIPsecFullSetDelim(base))
		if malformed {
			// #9061: same refusal the persistent-NAT and DHCP full-set arms
			// make, for the same reason -- a full set REPLACES, so installing a
			// truncated one is worse than installing nothing. The standby keeps
			// the set it has until a good frame arrives, rather than
			// reinitiating a SUBSET on takeover and appearing to succeed.
			slog.Warn("cluster sync: refusing a malformed IPsec SA full set",
				"payload_bytes", len(payload), "incarnation", incarnation, "seq", seq)
			return
		}
		s.peerIPsecSAsMu.Lock()
		s.peerIPsecSAs = names
		s.peerIPsecSAsMu.Unlock()
		slog.Debug("cluster sync: received IPsec SA list", "count", len(names), "incarnation", incarnation, "seq", seq)
		if s.OnIPsecSAReceived != nil {
			s.OnIPsecSAReceived(names)
		}
	case syncMsgPersistentNatLease:
		// #8121: a full IDLE persistent-NAT lease set. Same two refusals the
		// DHCP full-set arms make, and for the same reason: a full set
		// REPLACES, so installing a stale or truncated one is worse than
		// installing nothing. The standby simply keeps rebuilding leases from
		// sessions (#7360) until a good set arrives.
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.persistentNatLeaseRecvSeq.admit(incarnation, seq)
		s.recvSeqMu.Unlock()
		if !admit {
			slog.Warn("cluster sync: dropping out-of-order persistent-NAT lease set (stale sequence)",
				"incarnation", incarnation, "seq", seq)
			return
		}
		leases, ok := decodePersistentNatLeasePayload(base)
		if !ok {
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed persistent-NAT lease set",
				"incarnation", incarnation, "seq", seq, "bytes", len(base))
			return
		}
		slog.Debug("cluster sync: received persistent-NAT idle lease set",
			"count", len(leases), "incarnation", incarnation, "seq", seq)
		if s.OnPersistentNatLeasesReceived != nil {
			s.OnPersistentNatLeasesReceived(leases)
		}
	case syncMsgDHCPLeaseV4:
		s.stats.DHCPLeasesReceived.Add(1)
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.dhcpV4RecvSeq.admit(incarnation, seq)
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP v4 lease set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		leases, ok := decodeDHCPLeasePayload(base)
		if !ok {
			// #7175: a full-set push REPLACES the set, so storing a truncated
			// prefix would delete every lease past the truncation point. Retain
			// the prior set, exactly as the stale-sequence guard above does.
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP v4 lease set — standby retains previous set",
				"incarnation", incarnation, "seq", seq, "bytes", len(base))
			return
		}
		s.storePeerDHCPLeases(4, leases)
		slog.Debug("cluster sync: received DHCP v4 lease set", "count", len(leases), "incarnation", incarnation, "seq", seq)
		if s.OnDHCPLeasesReceived != nil {
			s.OnDHCPLeasesReceived(4, leases)
		}
	case syncMsgDHCPLeaseV6:
		s.stats.DHCPLeasesReceived.Add(1)
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.dhcpV6RecvSeq.admit(incarnation, seq)
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP v6 lease set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		leases, ok := decodeDHCPLeasePayload(base)
		if !ok {
			// #7175: a full-set push REPLACES the set, so storing a truncated
			// prefix would delete every lease past the truncation point. Retain
			// the prior set, exactly as the stale-sequence guard above does.
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP v6 lease set — standby retains previous set",
				"incarnation", incarnation, "seq", seq, "bytes", len(base))
			return
		}
		s.storePeerDHCPLeases(6, leases)
		slog.Debug("cluster sync: received DHCP v6 lease set", "count", len(leases), "incarnation", incarnation, "seq", seq)
		if s.OnDHCPLeasesReceived != nil {
			s.OnDHCPLeasesReceived(6, leases)
		}
	case syncMsgFailover:
		if len(payload) < 9 {
			slog.Warn("cluster sync: failover message too short")
			return
		}
		rgID := int(payload[0])
		reqID := binary.LittleEndian.Uint64(payload[1:9])
		slog.Info("cluster sync: remote failover request received", "rg", rgID, "req_id", reqID)
		go s.handleRemoteFailover(conn, rgID, reqID)
	case syncMsgFailoverAck:
		if len(payload) < 10 {
			slog.Warn("cluster sync: failover ack message too short")
			return
		}
		rgID := int(payload[0])
		status := payload[1]
		reqID := binary.LittleEndian.Uint64(payload[2:10])
		detail := string(payload[10:])
		slog.Info("cluster sync: failover ack received", "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverWait(rgID, reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverCommit:
		if len(payload) < 9 {
			slog.Warn("cluster sync: failover commit message too short")
			return
		}
		rgID := int(payload[0])
		reqID := binary.LittleEndian.Uint64(payload[1:9])
		slog.Info("cluster sync: remote failover commit received", "rg", rgID, "req_id", reqID)
		go s.handleRemoteFailoverCommit(conn, rgID, reqID)
	case syncMsgFailoverCommitAck:
		if len(payload) < 10 {
			slog.Warn("cluster sync: failover commit ack message too short")
			return
		}
		rgID := int(payload[0])
		status := payload[1]
		reqID := binary.LittleEndian.Uint64(payload[2:10])
		detail := string(payload[10:])
		slog.Info("cluster sync: failover commit ack received", "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverCommitWait(rgID, reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverBatch:
		rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover message decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: remote batch failover request received", "rgs", rgIDs, "req_id", reqID)
		go s.handleRemoteFailoverBatch(conn, rgIDs, reqID)
	case syncMsgFailoverBatchAck:
		rgIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover ack decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: batch failover ack received", "rgs", rgIDs, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverBatchWait(failoverBatchKey(rgIDs), reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverBatchCommit:
		rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover commit message decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: remote batch failover commit received", "rgs", rgIDs, "req_id", reqID)
		go s.handleRemoteFailoverCommitBatch(conn, rgIDs, reqID)
	case syncMsgFailoverBatchCommitAck:
		rgIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover commit ack decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: batch failover commit ack received", "rgs", rgIDs, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverBatchCommitWait(failoverBatchKey(rgIDs), reqID, failoverAck{status: status, detail: detail})
	case syncMsgFence:
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
	case syncMsgFenceAck:
		// #7147. A malformed or truncated ack is DROPPED rather than partially
		// decoded: a short frame zero-filled into RGsFenced/RGsTotal/Status
		// would decode to status 0 == FenceAckOK, i.e. a corrupt frame would
		// read as a successful confirmation. The sender's timeout covers the
		// drop and fails open.
		ack, ok := decodeFenceAckPayload(payload)
		if !ok {
			slog.Warn("cluster sync: fence ack message too short", "len", len(payload))
			return
		}
		s.completeFenceAckWait(ack)
	case syncMsgPeerCapabilities:
		// #6650. Length-gated with the #2170 trailing-field discipline: a
		// SHORTER frame than we expect is a peer we cannot interpret, so it is
		// ignored (leaving the 0 = incapable default) rather than partially
		// decoded; a LONGER one is a newer peer with extra fields we skip.
		if len(payload) < 2 {
			slog.Warn("cluster sync: peer capabilities message too short", "len", len(payload))
			return
		}
		peerProto := binary.LittleEndian.Uint16(payload[:2])
		s.peerSnapshotProtocol.Store(uint32(peerProto))
		// #7147: capability flags ride in the trailing byte under the same
		// discipline — a 2-byte frame is a pre-#7147 peer, and 0 flags is the
		// correct reading of it (advertises no capabilities).
		var peerFlags uint8
		if len(payload) >= 3 {
			peerFlags = payload[2]
		}
		s.peerCapabilityFlags.Store(uint32(peerFlags))
		// #7990: the peer's session-sync WIRE version rides as a trailing u16
		// under the same discipline — a payload shorter than 5 bytes is a
		// pre-#7990 peer and leaves 0 = UNKNOWN, which callers must handle
		// explicitly rather than reading as a version.
		var peerWire uint16
		if len(payload) >= 5 {
			peerWire = binary.LittleEndian.Uint16(payload[3:5])
		}
		s.peerSessionSyncWire.Store(uint32(peerWire))
		slog.Info("cluster sync: peer advertised capabilities",
			"version", peerProto, "flags", peerFlags, "session_sync_wire", peerWire)
	case syncMsgClockSync:
		if len(payload) < 8 {
			slog.Warn("cluster sync: clock sync message too short")
			return
		}
		peerMono := binary.LittleEndian.Uint64(payload[:8])
		localMono := monotonicSeconds()
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
			return
		}
		offset := int64(localMono) - int64(peerMono)
		// A bound cannot tell a plausible false reading from a true one, so the
		// offset belongs to the connection that carried it: it rebases only the
		// sessions that connection carries (clockOffsetFor).
		if ac, ok := conn.(*authConn); ok {
			ac.clockOffset.Store(offset)
			ac.clockSynced.Store(true)
		}
		s.peerClockOffset.Store(offset)
		s.clockSynced.Store(true)
		slog.Info("cluster sync: clock synced with peer", "peer_mono", peerMono, "local_mono", localMono, "offset", offset)
	case syncMsgPrepareActivation:
		if len(payload) < 1 {
			slog.Warn("cluster sync: prepare_activation message too short")
			return
		}
		rgID := int(payload[0])
		slog.Info("cluster sync: prepare_activation received from demoting peer", "rg", rgID)
		if s.OnPrepareActivation != nil {
			go s.OnPrepareActivation(rgID)
		}
	case syncMsgBarrier:
		if len(payload) < 8 {
			slog.Warn("cluster sync: barrier message too short")
			return
		}
		seq := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		slog.Info("cluster sync: barrier received", "seq", seq, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		s.sendBarrierAck(conn, seq)
	case syncMsgBarrierAck:
		if len(payload) < 8 {
			slog.Warn("cluster sync: barrier ack message too short")
			return
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
		for {
			current := s.barrierAckSeq.Load()
			if seq <= current || s.barrierAckSeq.CompareAndSwap(current, seq) {
				break
			}
		}
		s.stats.LastFenceAckAt.Store(time.Now().UnixNano())
		s.completeBarrierWait(seq)
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
func (s *SessionSync) handleConfigPayload(conn net.Conn, payload []byte) {
	s.stats.ConfigsReceived.Add(1)
	s.stats.LastConfigSyncTime.Store(time.Now().UnixNano())
	configText, gen := decodeConfigPayload(payload)
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
	item := configApplyItem{gen: gen, text: configText, incarnation: s.connBootIncarnation(conn)}
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
