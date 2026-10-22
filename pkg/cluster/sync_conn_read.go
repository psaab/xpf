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
	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcpserver"
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
		s.bulkRecvSerial++
		if s.bulkRecvSerial == 0 {
			s.bulkRecvSerial++
		}
		s.inventoryActive = s.inventoryPending
		s.inventoryActiveGeneration = s.inventoryPendingGeneration
		if !s.inventoryActive {
			s.inventoryActiveGeneration = 0
		}
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
		s.bulkInstallFailedV4 = make(map[dataplane.SessionKey]struct{})
		s.bulkInstallFailedV6 = make(map[dataplane.SessionKeyV6]struct{})
		s.bulkZoneSnapshot = zoneSnap
		s.bulkMu.Unlock()
		// The generation reset moves to the ACCEPTED path only. It is the
		// #2198 F2 remedy for a re-priming peer. A DIFFERENT known boot
		// incarnation, or an un-incarnated legacy BulkStart, has no comparable
		// generation namespace and therefore gets the historical full reset.
		// A SAME known incarnation still reclaims live high-waters from the
		// previous authoritative window while retaining delete tombstones for
		// post-fence stale rows.
		//
		// It stays OUTSIDE `bulkMu`, where it has always been. `resetRecvGen`
		// takes `recvGenMu`, and pulling it inside would add a bulkMu ->
		// recvGenMu edge to the lock graph as a side effect of a correctness
		// fix -- a change nothing here needs and nobody would look for.
		if !inc.known() || (switched && priorInc.known()) {
			s.resetRecvGen()
		} else {
			s.reclaimRecvLiveGen()
		}
		// #9177 V052: the bulk TELEMETRY belongs on the accepted path too, and
		// it used to run above the accept. A REFUSED BulkStart -- the reordered
		// one #8966's own text calls "the ordinary case" with two fabric
		// streams -- re-stamped BulkSyncStartTime and zeroed BulkSyncEndTime on
		// its way to being rejected. `show chassis cluster information` then
		// read "Bulk sync in progress since ..." indefinitely, because the
		// BulkEnd that would set an end time belongs to a bulk that was never
		// accepted; and while that pair read open, every subsequent INCREMENTAL
		// install was counted as bulk traffic (the session handlers now key
		// that count on bulkInProgress, #15254, but the pair is still what
		// status renders).
		//
		// This is a statement-ORDERING defect, not an epoch-validation one: the
		// accept itself is correct. The #8966 author moved `resetRecvGen` below
		// the accept for exactly this reason and left these three where they
		// were, which is why they now sit beside it. The abandoned-accept twin
		// (#15254: accepted, then every fabric drops) is closed at the other
		// edge: handleDisconnect stamps an end when it clears a live window.
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
		if pc.retired && !pc.announce {
			// The connection's install already dispatched OnPeerConnected.
			// Its capability callback may have reconciled before this switch
			// and been rejected by the incarnation generation change, so
			// trigger one fresh pass against the restored per-connection state.
			if cb := s.OnPeerCapabilitiesChanged; cb != nil {
				go cb()
			}
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
		s.stats.IPsecSAReceived.Add(1)
		// #5706: split off the (incarnation, seq) ordering trailer. Check
		// against the last-applied pair before decoding, but do not advance
		// the high-water mark until a complete set commits. Decode is outside
		// the apply lock; the epoch fence prevents a frame spanning a receiver
		// reset from resurrecting a cleared guard.
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.ipsecRecvSeq.newer(incarnation, seq)
		commitEpoch := s.recvEpoch
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
			// #9061: refuse a malformed IPsec SA full set. Unlike the additive
			// persistent-NAT lease channel, IPsec replaces the held set, so a
			// truncated prefix must not overwrite it; the standby keeps its prior
			// state until a complete frame arrives. Crucially, this does not
			// consume the sequence number.
			slog.Warn("cluster sync: refusing a malformed IPsec SA full set",
				"payload_bytes", len(payload), "incarnation", incarnation, "seq", seq)
			return
		}
		// Serialize high-water advance, held-set replacement, and callback so
		// concurrent fabric receivers cannot commit/callback out of order.
		s.ipsecApplyMu.Lock()
		s.recvSeqMu.Lock()
		applied := s.recvEpoch == commitEpoch &&
			s.ipsecRecvSeq.advanceIfNewer(incarnation, seq)
		if applied {
			s.peerIPsecSAsMu.Lock()
			s.peerIPsecSAs = names
			s.peerIPsecSAsMu.Unlock()
		}
		s.recvSeqMu.Unlock()
		if !applied {
			s.ipsecApplyMu.Unlock()
			s.stats.IPsecSAStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order IPsec SA set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		slog.Debug("cluster sync: received IPsec SA list", "count", len(names), "incarnation", incarnation, "seq", seq)
		if s.OnIPsecSAReceived != nil {
			s.OnIPsecSAReceived(names)
		}
		s.ipsecApplyMu.Unlock()
	case syncMsgPersistentNatLease:
		// #10018 migration fence: type 38 is the pre-scope format.
		slog.Warn("cluster sync: ignoring legacy unscoped persistent-NAT lease set",
			"bytes", len(payload))
	case syncMsgPersistentNatLeaseScoped:
		// Type 39 predates durable clear generations. Admitting it would
		// bypass the receiver's permanent replay floor.
		slog.Warn("cluster sync: ignoring persistent-NAT lease set without clear generation",
			"bytes", len(payload))
	case syncMsgPersistentNatLeaseGeneration, syncMsgPersistentNatLeaseDeterministic:
		// #11486: generation-bearing idle-lease batch. Sequence ordering handles
		// transport reordering within one peer incarnation; the daemon persists
		// origin generation independently across reconnects and process restarts.
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := s.persistentNatLeaseRecvSeq.newer(incarnation, seq)
		commitEpoch := s.recvEpoch
		s.recvSeqMu.Unlock()
		if !admit {
			slog.Warn("cluster sync: dropping out-of-order persistent-NAT generation batch",
				"incarnation", incarnation, "seq", seq)
			return
		}
		var batch userspace.PersistentNatLeaseBatch
		var ok bool
		if msgType == syncMsgPersistentNatLeaseDeterministic {
			batch, ok = decodePersistentNatLeaseBatchPayloadDeterministic(base)
		} else {
			batch, ok = decodePersistentNatLeaseBatchPayload(base)
		}
		if !ok {
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed persistent-NAT generation batch",
				"incarnation", incarnation, "seq", seq, "bytes", len(base))
			return
		}
		s.persistentNatLeaseApplyMu.Lock()
		s.recvSeqMu.Lock()
		applied := s.recvEpoch == commitEpoch &&
			s.persistentNatLeaseRecvSeq.advanceIfNewer(incarnation, seq)
		s.recvSeqMu.Unlock()
		if !applied {
			s.persistentNatLeaseApplyMu.Unlock()
			slog.Warn("cluster sync: dropping out-of-order persistent-NAT generation batch",
				"incarnation", incarnation, "seq", seq)
			return
		}
		slog.Debug("cluster sync: received persistent-NAT generation batch",
			"count", len(batch.Leases), "generation", batch.Generation,
			"incarnation", incarnation, "seq", seq)
		if s.OnPersistentNatLeasesReceived != nil {
			s.OnPersistentNatLeasesReceived(batch)
		}
		s.persistentNatLeaseApplyMu.Unlock()
	case syncMsgDHCPLeaseV4:
		s.stats.DHCPLeasesReceived.Add(1)
		base, incarnation, seq := stripFullSetSeq(payload)
		// #9915 F-117 review: do the cheap sequence admission BEFORE
		// metadata/lease decoding, but advance only when the set applies.
		s.recvSeqMu.Lock()
		admit := s.dhcpV4RecvSeq.newer(incarnation, seq)
		commitEpoch := s.recvEpoch
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP v4 lease set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		leasePayload, snapshot, metadataPresent, metadataValid := stripDHCPLeaseSnapshotMeta(base)
		if !metadataValid || (metadataPresent && !validDHCPLeaseSnapshotFamily(snapshot, 4)) {
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP v4 lease authority snapshot")
			return
		}
		leases, ok := decodeDHCPLeasePayload(leasePayload)
		if !ok {
			// #7175: a full-set push REPLACES the set, so storing a truncated
			// prefix would delete every lease past the truncation point. Retain
			// the prior set. The mark does not advance (see above).
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP v4 lease set — standby retains previous set",
				"incarnation", incarnation, "seq", seq, "bytes", len(leasePayload))
			return
		}
		// Every decoded set is identity-filtered, legacy or sequenced alike:
		// the filter judges records, not senders. Legacy (untrailered) only
		// affects ordering (admit-always, never advances the mark).
		origCount := len(leases)
		var semanticallyDropped int
		leases, semanticallyDropped = filterDHCPLeasesBySemantics(4, leases)
		if semanticallyDropped > 0 {
			s.stats.MalformedRecordsDropped.Add(uint64(semanticallyDropped))
			slog.Warn("cluster sync: dropping semantically invalid DHCP v4 lease records — keeping the rest",
				"dropped", semanticallyDropped, "kept", len(leases), "incarnation", incarnation, "seq", seq)
		}
		leases, dropped := filterDHCPLeasesByIdentity(4, leases)
		if dropped > 0 {
			s.stats.DHCPLeasesDroppedNoIdentity.Add(uint64(dropped))
			slog.Warn("cluster sync: dropping DHCP v4 lease records without family identity — keeping the rest",
				"dropped", dropped, "kept", len(leases), "incarnation", incarnation, "seq", seq)
		}
		if len(leases) == 0 && origCount > 0 {
			// #9915 F-117: a filtered-to-empty set retains the prior held set
			// (the #7175 posture) — only a genuine count==0 push clears. The
			// mark does not advance (see above).
			slog.Warn("cluster sync: DHCP v4 lease set filtered to empty — standby retains previous set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		// Atomic commit (#9915 F-117 review): the high-water advance, the
		// held-set replacement, and the callback are serialized by
		// dhcpApplyMu, so commit order == callback order: split out, seq 10
		// can advance, seq 11 advance+store+callback, then seq 10 store or
		// callback and regress the held set or its consumer.
		// Locking: recvSeqMu covers only mark+store inside (nesting
		// peerDHCPLeasesMu — the only direction that order is taken, so no
		// cycle); the callback runs under dhcpApplyMu AFTER recvSeqMu is
		// released, so a consumer can never deadlock on the widely-taken
		// receive mutex. Lock order dhcpApplyMu -> recvSeqMu ->
		// peerDHCPLeasesMu, taken only here.
		if s.testDHCPPreCommit != nil {
			s.testDHCPPreCommit()
		}
		s.dhcpApplyMu.Lock()
		s.recvSeqMu.Lock()
		applied := s.recvEpoch == commitEpoch && s.dhcpV4RecvSeq.advanceIfNewer(incarnation, seq)
		if applied {
			snapshot.Leases = leases
			snapshot.Received = true
			s.storePeerDHCPLeaseSnapshot(4, snapshot)
			// #15160: a committed legacy set supersedes every in-flight
			// chunk assembly for this family (its seq is newer by the
			// guard that just advanced).
			s.dhcpChunkState4.discardAll()
		}
		s.recvSeqMu.Unlock()
		if !applied {
			s.dhcpApplyMu.Unlock()
			// Lost a duplicate-fabric race to a newer set that already
			// applied, or lapped by a receiver reset (epoch changed under
			// us): drop rather than regress the held set or resurrect a
			// dead high-water.
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP v4 lease set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		slog.Debug("cluster sync: received DHCP v4 lease set", "count", len(leases), "incarnation", incarnation, "seq", seq)
		if s.OnDHCPLeasesReceived != nil {
			s.OnDHCPLeasesReceived(4, leases)
		}
		s.dhcpApplyMu.Unlock()
	case syncMsgDHCPLeaseV6:
		s.stats.DHCPLeasesReceived.Add(1)
		base, incarnation, seq := stripFullSetSeq(payload)
		// #9915 F-117 review: do the cheap sequence admission BEFORE
		// metadata/lease decoding, but advance only when the set applies.
		s.recvSeqMu.Lock()
		admit := s.dhcpV6RecvSeq.newer(incarnation, seq)
		commitEpoch := s.recvEpoch
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP v6 lease set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		leasePayload, snapshot, metadataPresent, metadataValid := stripDHCPLeaseSnapshotMeta(base)
		if !metadataValid || (metadataPresent && !validDHCPLeaseSnapshotFamily(snapshot, 6)) {
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP v6 lease authority snapshot")
			return
		}
		leases, ok := decodeDHCPLeasePayload(leasePayload)
		if !ok {
			// #7175: see the v4 twin — retain, no advance.
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP v6 lease set — standby retains previous set",
				"incarnation", incarnation, "seq", seq, "bytes", len(leasePayload))
			return
		}
		// Every decoded set is filtered: see the v4 twin.
		origCount := len(leases)
		var semanticallyDropped int
		leases, semanticallyDropped = filterDHCPLeasesBySemantics(6, leases)
		if semanticallyDropped > 0 {
			s.stats.MalformedRecordsDropped.Add(uint64(semanticallyDropped))
			slog.Warn("cluster sync: dropping semantically invalid DHCP v6 lease records — keeping the rest",
				"dropped", semanticallyDropped, "kept", len(leases), "incarnation", incarnation, "seq", seq)
		}
		leases, dropped := filterDHCPLeasesByIdentity(6, leases)
		if dropped > 0 {
			s.stats.DHCPLeasesDroppedNoIdentity.Add(uint64(dropped))
			slog.Warn("cluster sync: dropping DHCP v6 lease records without family identity — keeping the rest",
				"dropped", dropped, "kept", len(leases), "incarnation", incarnation, "seq", seq)
		}
		if len(leases) == 0 && origCount > 0 {
			// #9915 F-117: see the v4 twin — retain, no advance.
			slog.Warn("cluster sync: DHCP v6 lease set filtered to empty — standby retains previous set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		// Atomic commit: see the v4 twin (dhcpApplyMu spans commit+callback;
		// recvSeqMu only mark+store; the callback must not reenter DHCP
		// receive paths).
		if s.testDHCPPreCommit != nil {
			s.testDHCPPreCommit()
		}
		s.dhcpApplyMu.Lock()
		s.recvSeqMu.Lock()
		applied := s.recvEpoch == commitEpoch && s.dhcpV6RecvSeq.advanceIfNewer(incarnation, seq)
		if applied {
			snapshot.Leases = leases
			snapshot.Received = true
			s.storePeerDHCPLeaseSnapshot(6, snapshot)
			s.dhcpChunkState6.discardAll()
		}
		s.recvSeqMu.Unlock()
		if !applied {
			s.dhcpApplyMu.Unlock()
			// Lost a duplicate-fabric race or lapped by a reset: see the v4 twin.
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP v6 lease set (stale sequence) — standby retains newer set",
				"incarnation", incarnation, "seq", seq)
			return
		}
		slog.Debug("cluster sync: received DHCP v6 lease set", "count", len(leases), "incarnation", incarnation, "seq", seq)
		if s.OnDHCPLeasesReceived != nil {
			s.OnDHCPLeasesReceived(6, leases)
		}
		s.dhcpApplyMu.Unlock()
	case syncMsgDHCPLeaseV4Chunk, syncMsgDHCPLeaseV6Chunk:
		// #15160: one chunk of an over-cap DHCP full-set. Chunks are
		// admitted in per-frame seq order, assembled by
		// (incarnation, generation), and committed atomically only
		// when the last chunk lands; anything else leaves the held
		// set and high-water untouched.
		family := 4
		guard := &s.dhcpV4RecvSeq
		state := &s.dhcpChunkState4
		if msgType == syncMsgDHCPLeaseV6Chunk {
			family = 6
			guard = &s.dhcpV6RecvSeq
			state = &s.dhcpChunkState6
		}
		s.stats.DHCPLeasesReceived.Add(1)
		base, incarnation, seq := stripFullSetSeq(payload)
		s.recvSeqMu.Lock()
		admit := guard.newer(incarnation, seq)
		commitEpoch := s.recvEpoch
		s.recvSeqMu.Unlock()
		if !admit {
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP lease chunk (stale sequence)",
				"family", family, "incarnation", incarnation, "seq", seq)
			return
		}
		// The #10170 authority trailer rides the last chunk only; strip
		// it (from the reassembled base tail) before header parsing is
		// impossible — it sits AFTER the chunk body, so parse the chunk
		// header first from the front, then strip the trailer from the
		// body tail.
		generation, index, total, totalLeases, chunkBody, ok := decodeDHCPLeaseChunkHeader(base)
		if !ok {
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP lease chunk header",
				"family", family, "incarnation", incarnation, "seq", seq, "bytes", len(base))
			return
		}
		var snapshot dhcpserver.LeaseSyncSnapshot
		isLast := index == total-1
		if isLast {
			var metadataPresent, metadataValid bool
			chunkBody, snapshot, metadataPresent, metadataValid = stripDHCPLeaseSnapshotMeta(chunkBody)
			if !metadataValid || (metadataPresent && !validDHCPLeaseSnapshotFamily(snapshot, family)) {
				s.stats.MalformedRecordsDropped.Add(1)
				slog.Warn("cluster sync: dropping malformed DHCP lease chunk authority snapshot", "family", family)
				return
			}
		}
		leases, decoded := decodeDHCPLeasePayload(chunkBody)
		if !decoded {
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP lease chunk — prior set retained",
				"family", family, "generation", generation, "index", index)
			return
		}
		origCount := len(leases)
		var semanticallyDropped int
		leases, semanticallyDropped = filterDHCPLeasesBySemantics(family, leases)
		if semanticallyDropped > 0 {
			s.stats.MalformedRecordsDropped.Add(uint64(semanticallyDropped))
		}
		var identityDropped int
		leases, identityDropped = filterDHCPLeasesByIdentity(family, leases)
		if identityDropped > 0 {
			s.stats.DHCPLeasesDroppedNoIdentity.Add(uint64(identityDropped))
		}
		if len(leases) == 0 && origCount > 0 {
			// A chunk filtered to empty can never satisfy totalLeases;
			// refuse the generation outright (the sender counts drops
			// at encode time, so this is a corrupt/forged stream).
			slog.Warn("cluster sync: DHCP lease chunk filtered to empty — generation refused, prior set retained",
				"family", family, "generation", generation, "index", index)
			return
		}
		// Advance the per-frame high-water for every admitted chunk
		// (monotone stream), then assemble; commit only on completion.
		if s.testDHCPPreCommit != nil {
			s.testDHCPPreCommit()
		}
		s.dhcpApplyMu.Lock()
		s.recvSeqMu.Lock()
		chunkApplied := s.recvEpoch == commitEpoch && guard.advanceIfNewer(incarnation, seq)
		if !chunkApplied {
			s.recvSeqMu.Unlock()
			s.dhcpApplyMu.Unlock()
			s.stats.DHCPLeasesStaleIgnored.Add(1)
			slog.Warn("cluster sync: dropping out-of-order DHCP lease chunk (stale sequence) — prior set retained",
				"family", family, "incarnation", incarnation, "seq", seq)
			return
		}
		key := dhcpChunkGeneration{incarnation: incarnation, generation: generation}
		complete, closed := state.addChunk(key, index, total, totalLeases, leases)
		if !closed {
			s.recvSeqMu.Unlock()
			s.dhcpApplyMu.Unlock()
			return
		}
		snapshot.Leases = complete
		snapshot.Received = true
		s.storePeerDHCPLeaseSnapshot(family, snapshot)
		s.recvSeqMu.Unlock()
		slog.Debug("cluster sync: received chunked DHCP lease set", "family", family,
			"count", len(complete), "chunks", total, "incarnation", incarnation, "generation", generation)
		if s.OnDHCPLeasesReceived != nil {
			s.OnDHCPLeasesReceived(family, complete)
		}
		s.dhcpApplyMu.Unlock()
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
	case syncMsgFailoverAbort:
		if len(payload) < 9 {
			slog.Warn("cluster sync: failover abort message too short")
			return
		}
		rgID := int(payload[0])
		reqID := binary.LittleEndian.Uint64(payload[1:9])
		slog.Info("cluster sync: remote failover abort received", "rg", rgID, "req_id", reqID)
		go s.handleRemoteFailoverAbort(rgID, reqID)
	case syncMsgFailoverBatchAbort:
		rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover abort message decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: remote batch failover abort received", "rgs", rgIDs, "req_id", reqID)
		go s.handleRemoteFailoverAbortBatch(rgIDs, reqID)
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
		oldProto := s.peerSnapshotProtocol.Load()
		// #7147: capability flags ride in the trailing byte under the same
		// discipline — a 2-byte frame is a pre-#7147 peer, and 0 flags is the
		// correct reading of it (advertises no capabilities).
		var peerFlags uint8
		if len(payload) >= 3 {
			peerFlags = payload[2]
		}
		oldFlags := s.peerCapabilityFlags.Load()
		// #7990: the peer's session-sync WIRE version rides as a trailing u16
		// under the same discipline — a payload shorter than 5 bytes is a
		// pre-#7990 peer and leaves 0 = UNKNOWN, which callers must handle
		// explicitly rather than reading as a version.
		var peerWire uint16
		if len(payload) >= 5 {
			peerWire = binary.LittleEndian.Uint16(payload[3:5])
		}
		oldWire := s.peerSessionSyncWire.Load()
		capabilityChanged := oldProto != uint32(peerProto) ||
			oldFlags != uint32(peerFlags) || oldWire != uint32(peerWire)
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
			return
		}
		if ac, ok := conn.(*authConn); ok {
			ac.peerSnapshotVersion = peerProto
			ac.peerCapabilityFlags = peerFlags
			ac.peerSessionSyncWire = peerWire
		}
		s.peerSnapshotProtocolWriteMu.Lock()
		if s.peerSnapshotProtocol.Load() != uint32(peerProto) {
			s.peerSnapshotProtocolGeneration++
		}
		s.peerSnapshotProtocol.Store(uint32(peerProto))
		s.peerSnapshotProtocolWriteMu.Unlock()
		s.peerCapabilityFlags.Store(uint32(peerFlags))
		s.peerSessionSyncWire.Store(uint32(peerWire))
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
			s.bulkFencedForPeer.Store(false)
			// #9752 round 5 item 5: suppressed installs are never retried
			// by the sweep (its Created>=threshold window advances past
			// them), so transfer the suppress debt into a cold-prime
			// re-arm: the redriven bulk snapshot carries full state and
			// heals every withheld install at once. The debt is consumed
			// whenever a prime is already owed (that redrive carries it)
			// or armed here; future suppressions re-set it. Both checked
			// under s.mu with the arm so a concurrent ack discharge
			// cannot interleave a redundant bulk.
			if s.installTableSuppressDebt.Load() {
				s.mu.Lock()
				if s.installTableSuppressDebt.Load() {
					s.installTableSuppressDebt.Store(false)
					if !s.needColdPrime.Load() {
						s.armColdPrimeLocked()
						slog.Info("cluster sync: re-arming cold prime after capable discovery with withheld installs")
					}
				}
				s.mu.Unlock()
			}
		}
		if s.IpsecTunnelDiscriminatorCapable() {
			s.bulkFencedForIpsecPeer.Store(false)
		}
		if s.IpsecTunnelDiscriminatorCapable() && s.ipsecDiscriminatorSuppressDebt.Load() {
			s.mu.Lock()
			if s.ipsecDiscriminatorSuppressDebt.Load() {
				s.ipsecDiscriminatorSuppressDebt.Store(false)
				if !s.needColdPrime.Load() {
					s.armColdPrimeLocked()
					slog.Info("cluster sync: re-arming cold prime after capable IPsec discriminator discovery")
				}
			}
			s.mu.Unlock()
		}
		slog.Info("cluster sync: peer advertised capabilities",
			"version", peerProto, "flags", peerFlags, "session_sync_wire", peerWire)
	case syncMsgClockSync:
		if len(payload) < 8 {
			slog.Warn("cluster sync: clock sync message too short")
			return
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
			return
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
			return
		}
		slog.Info("cluster sync: clock synced with peer", "peer_mono", peerMono, "local_mono", localMono, "offset", offset)
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
