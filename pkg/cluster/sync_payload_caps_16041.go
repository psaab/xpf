package cluster

import "log/slog"

// Per-type payload caps and semantic-accept liveness (#16041).
//
// Before #16041 receiveLoop refreshed peer liveness (missedHeartbeats=0 and
// lastPeerRxMono) for ANY well-framed frame — magic, the global
// maxSyncPayload bound and, on an authenticated connection, the HMAC/sequence
// trailer verified — before handleMessage ran. A keyed peer could therefore
// keep sending well-framed but semantically rejected frames (an unknown type,
// a truncated session record, a stale full-set, an impossible clock reading)
// forever and this node would never age it out: PeerHealthy kept reporting a
// live peer and the missed-heartbeat teardown never fired, masking the
// failover trigger the silence exists to arm. HMAC bounds this to the
// keyed-peer fault class, which is why the severity is Low, but a faulty
// keyed peer is exactly the peer failover must detect.
//
// The fix has two halves:
//
//  1. handleMessage now reports whether the frame was semantically accepted,
//     and receiveLoop refreshes liveness only on acceptance. "Accepted" means
//     the DOWNSTREAM result, not merely a clean decode: a session install
//     rejected as stale-generation/stale-config/helper-refused, a delete
//     refused by its generation guard or failing in the dataplane, an ack
//     (failover/commit/batch/fence/barrier/bulk/config) matching no live
//     waiter, a duplicate barrier ack, a stale or undecryptable config, and
//     a DHCP chunk whose assembly is inconsistent (mismatched totals,
//     duplicate index, over/under-total) are all REJECTED even though they
//     decoded. Frames applied, queued, recorded into a chunk assembly, or
//     matched to a waiter are accepted. Deliberate exception: retired
//     persistent-NAT types 38/39 count as accepted — an old peer sending only
//     those is alive and speaking a known type; its frames are ignored by
//     migration design, not rejected as junk.
//
//  2. Every known type has a payload cap derived from its encoder, checked
//     in receiveLoop BEFORE the payload is allocated/read (the header alone
//     decides), so a keyed peer can no longer force a 16 MiB allocation and
//     HMAC pass for a heartbeat-sized type. Over-cap frames are refused with
//     OversizeFramesRefused (and Errors) and the connection is dropped —
//     the same posture as the pre-existing global-cap refusal, since a
//     length that desyncs the stream cannot be skipped without reading it.
//     Unknown types keep only the global cap (a newer peer's additive type
//     must stay forward-compatible: ignored, never liveness) — they are
//     bounded by maxSyncPayload for the read, then dropped unaccepted.
//
// Trailing-field discipline (#2170): several types accept length-gated
// trailing extensions from newer peers, so caps carry headroom over today's
// encoder where the decoder tolerates trailing bytes. The caps below cite
// the encoder each is derived from; a sender must never exceed its type cap
// for the same reason it must never exceed maxSyncPayload.

// Known sync message types that carry no payload at all in any sender.
// Their cap is 0: any payload byte is non-conforming.
func syncPayloadCap(msgType uint8) (int, bool) {
	switch msgType {
	case syncMsgHeartbeat, syncMsgHeartbeatAck, syncMsgFence, syncMsgBulkRequest:
		// writeMsg(..., nil) at every sender; handleFence reads an optional
		// 8-byte sequence, so Fence is capped with the fixed group below.
		if msgType == syncMsgFence {
			return 8, true
		}
		return 0, true
	case syncMsgSessionV4:
		// encodeSessionV4Payload: fixed body plus the length-gated tail
		// (rule ID <= 65535 by the u16 length prefix). 64 KiB covers the
		// fixed ~240B, the maximal rule-ID tail and future trailing fields.
		return 64 * 1024, true
	case syncMsgSessionV6:
		// encodeSessionV6Payload: 512B buffer plus the same metadata tail.
		return 64 * 1024, true
	case syncMsgDeleteV4:
		// encodeDeleteScopedV4 payload is 37B (bare form 25B).
		return 64, true
	case syncMsgDeleteV6:
		// encodeDeleteScopedV6 payload is 61B (bare form 49B).
		return 96, true
	case syncMsgBulkStart, syncMsgBulkEnd:
		// appendBootIncarnation(epochBuf[8]): 8 or 8+bootIncarnationLen.
		return 8 + bootIncarnationLen, true
	case syncMsgBulkAck, syncMsgBarrier:
		// sendBulkAck / barrier sender: one u64.
		return 8, true
	case syncMsgBarrierAck:
		// sendBarrierAck: seq + two u64 counters.
		return 24, true
	case syncMsgConfigApplyNack, syncMsgConfigApplyAck:
		// One generation u64.
		return 8, true
	case syncMsgFailover, syncMsgFailoverCommit, syncMsgFailoverAbort:
		// rgID u8 + reqID u64.
		return 9, true
	case syncMsgFailoverAck, syncMsgFailoverCommitAck:
		// rgID + status + reqID + free-form detail from the handler's error
		// string (sendFailoverAckFrame). The detail is peer-visible text, not
		// bulk data; 4 KiB bounds it without truncating real errors.
		return 4096, true
	case syncMsgFailoverBatch, syncMsgFailoverBatchCommit, syncMsgFailoverBatchAbort:
		// encodeFailoverBatchRequestPayload: count + <=255 RG ids + reqID.
		return 1 + maxFailoverBatchRGCount + 8, true
	case syncMsgFailoverBatchAck, syncMsgFailoverBatchCommitAck:
		// encodeFailoverBatchAckPayload: request shape + status + detail.
		return 1 + maxFailoverBatchRGCount + 1 + 8 + 4096, true
	case syncMsgFenceAck:
		return fenceAckPayloadLen, true
	case syncMsgPeerCapabilities:
		// sendCapabilities: 5 + bootIncarnationLen + epoch + token
		// + flags2 (#16756 appended the flags2 byte after #16041
		// sized this cap; without it every production frame is
		// dropped pre-dispatch and peer wire version is never
		// learned, #18032).
		return 5 + bootIncarnationLen + 8 + 8 + 1, true
	case syncMsgClockSync:
		// One peer-monotonic u64.
		return 8, true
	case syncMsgConfigKeyExchange:
		// Version byte + X25519 public key.
		return 1 + syncConfigECDHPubSize, true
	case syncMsgAuthUpgradeRequest:
		// One version byte.
		return 1, true
	case syncMsgAuthUpgradeHello, syncMsgAuthUpgradeProof:
		// Version byte + one Noise message (48B msg1; msg2 same class).
		// 1 KiB leaves handshake-extension headroom; the Noise layer
		// rejects anything that is not a well-formed message.
		return 1024, true
	case syncMsgAuthUpgradeConfirm:
		// Version byte + HMAC-SHA256.
		return 1 + syncAuthUpgradeConfirmLen, true
	case syncMsgConfig, syncMsgConfigEncrypted:
		// encodeConfigPayloadWithAncestry: the full committed config text
		// plus generation/ancestry trailers. Config is the one legitimately
		// large control payload; it keeps the global cap as its per-type cap.
		return maxSyncPayload, true
	case syncMsgIPsecSA, syncMsgIPsecSAChunk, syncMsgPersistentNatLease, syncMsgPersistentNatLeaseScoped,
		syncMsgPersistentNatLeaseGeneration, syncMsgPersistentNatLeaseDeterministic,
		syncMsgPersistentNatLeaseProvenance, syncMsgPersistentNatLeaseDeterministicProvenance,
		syncMsgDHCPLeaseV4, syncMsgDHCPLeaseV6, syncMsgDHCPLeaseV4Chunk, syncMsgDHCPLeaseV6Chunk:
		// Full-set / chunked-set types: encoders chunk below maxSyncPayload
		// (encodePersistentNatLeaseBatchFrames, DHCP chunk splitter), so
		// the global cap IS the per-type cap for these.
		return maxSyncPayload, true
	}
	return 0, false
}

// notePeerLiveness records a semantically accepted inbound frame: it resets
// the caller's missed-heartbeat count and stamps the last-peer-receive
// monotonic time read by PeerHealthy / PeerRecentlyActive. Called by
// receiveLoop only, and only when handleMessage accepted the frame (#16041).
func (s *SessionSync) notePeerLiveness(missedHeartbeats *int) {
	*missedHeartbeats = 0
	s.lastPeerRxMono.Store(MonotonicNanos())
}

// refuseOversizeFrame counts a per-type over-cap refusal (#16041). The
// caller drops the connection: the payload length is what desyncs the
// stream, and it cannot be skipped unread without trusting it.
func (s *SessionSync) refuseOversizeFrame(msgType uint8, length uint32, cap int) {
	s.stats.OversizeFramesRefused.Add(1)
	s.stats.Errors.Add(1)
	slog.Warn("cluster sync: per-type payload cap exceeded, dropping connection (#16041)",
		"type", msgType, "len", length, "cap", cap)
}
