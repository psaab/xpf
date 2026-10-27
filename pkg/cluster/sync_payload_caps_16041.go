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
// Trailing-field discipline (#2170) and headroom (#17093): the #16041
// table copied each encoder's current maximum with ZERO headroom, so
// the next additive trailing field on a growable type exceeded its cap
// and receiveLoop dropped the session-sync connection on every
// reconnect for the whole mixed-version window (#18032 was exactly
// that, one byte). Caps now derive from ONE descriptor table: each row
// records the encoder maximum (encoderMax, cited per row) and whether
// the decoder tolerates trailing bytes (growable). A growable row's
// maxLen is encoderMax + syncExtensionReserve; a fixed row's maxLen IS
// its encoderMax (any trailing byte is non-conforming there, because
// the decoder does not length-gate it). Session/Delete/AuthUpgrade
// rows already carried slack: that slack is now expressed the same
// way (encoderMax is the encoder's true bound, maxLen keeps the
// historical cap). A sender must never exceed its type cap, so the
// failover-ack encoders clamp their free-form detail at encode time
// (clampFailoverAckPayload / encodeFailoverBatchAckPayload).

// syncExtensionReserve is the trailing-extension headroom granted to
// every growable sync type (#17093). 256 B is far above any single
// additive field (the capabilities record grew 5->38 B across four
// extensions in 27 days) and far below maxSyncPayload, so the cap
// still bounds the header-time allocation a keyed peer can force.
const syncExtensionReserve = 256

// syncMsgDescriptor is one row of the sync message-type table.
type syncMsgDescriptor struct {
	id         uint8
	name       string
	encoderMax int  // largest payload today's encoder emits / decoder's fixed size
	maxLen     int  // header cap enforced in receiveLoop
	growable   bool // decoder length-gates trailing bytes (skips them)
}

// growableCap builds a growable row: maxLen = encoderMax + reserve.
func growableCap(id uint8, name string, encoderMax int) syncMsgDescriptor {
	return syncMsgDescriptor{id: id, name: name, encoderMax: encoderMax, maxLen: encoderMax + syncExtensionReserve, growable: true}
}

// fixedCap builds a fixed-forever row: maxLen == encoderMax.
func fixedCap(id uint8, name string, encoderMax int) syncMsgDescriptor {
	return syncMsgDescriptor{id: id, name: name, encoderMax: encoderMax, maxLen: encoderMax}
}

// syncMsgDescriptors is the single source for per-type payload caps.
// encoderMax values cite the encoder/decoder each is derived from.
var syncMsgDescriptors = []syncMsgDescriptor{
	// Fixed, zero-payload: writeMsg(..., nil) at every sender.
	fixedCap(syncMsgHeartbeat, "Heartbeat", 0),
	fixedCap(syncMsgHeartbeatAck, "HeartbeatAck", 0),
	fixedCap(syncMsgBulkRequest, "BulkRequest", 0),
	// handleFence reads only payload[:8] when present (pre-#7147 nil
	// form stays legal); a longer fence is a newer peer's extension.
	growableCap(syncMsgFence, "Fence", 8),
	// encodeSessionV4/V6Payload: fixed body plus a length-gated tail
	// (rule ID <= 65535 by the u16 length prefix) the decoder skips
	// past; 64 KiB is the historical cap over the ~240/512 B body.
	{id: syncMsgSessionV4, name: "SessionV4", encoderMax: 64 * 1024, maxLen: 64 * 1024, growable: true},
	{id: syncMsgSessionV6, name: "SessionV6", encoderMax: 64 * 1024, maxLen: 64 * 1024, growable: true},
	// encodeDeleteScopedV4/V6: 37/61 B (bare 25/49). The parser
	// length-gates its tails but FAILS CLOSED on gap lengths, and a
	// trailing byte past the scoped form would be silently ignored
	// rather than decoded — so deletes get bounded slack, not the
	// full reserve: 64/96 are the historical caps.
	{id: syncMsgDeleteV4, name: "DeleteV4", encoderMax: 37, maxLen: 64},
	{id: syncMsgDeleteV6, name: "DeleteV6", encoderMax: 61, maxLen: 96},
	// appendBootIncarnation(epochBuf[8]): 8 or 8+bootIncarnationLen;
	// parseBootIncarnation length-gates the tail.
	growableCap(syncMsgBulkStart, "BulkStart", 8+bootIncarnationLen),
	growableCap(syncMsgBulkEnd, "BulkEnd", 8+bootIncarnationLen),
	// BulkAck/Barrier/ClockSync/ConfigApplyAck/Nack handlers read only
	// the leading u64 and never inspect the tail.
	growableCap(syncMsgBulkAck, "BulkAck", 8),
	growableCap(syncMsgBarrier, "Barrier", 8),
	// sendBarrierAck: seq + two u64 counters; handler gates on >=24.
	growableCap(syncMsgBarrierAck, "BarrierAck", 24),
	growableCap(syncMsgConfigApplyNack, "ConfigApplyNack", 8),
	growableCap(syncMsgConfigApplyAck, "ConfigApplyAck", 8),
	// rgID u8 + reqID u64; handlers read payload[:9] only.
	growableCap(syncMsgFailover, "Failover", 9),
	growableCap(syncMsgFailoverCommit, "FailoverCommit", 9),
	growableCap(syncMsgFailoverAbort, "FailoverAbort", 9),
	// rgID + status + reqID + free-form detail (sendFailoverResult,
	// detail clamped at encode). Detail is peer-visible text, not
	// bulk data; 4 KiB total is the historical cap.
	{id: syncMsgFailoverAck, name: "FailoverAck", encoderMax: 4096, maxLen: 4096, growable: true},
	{id: syncMsgFailoverCommitAck, name: "FailoverCommitAck", encoderMax: 4096, maxLen: 4096, growable: true},
	// encodeFailoverBatchRequestPayload: count + <=255 RG ids + reqID;
	// the decoder reads exactly 1+count+8, trailing bytes ignored.
	growableCap(syncMsgFailoverBatch, "FailoverBatch", 1+maxFailoverBatchRGCount+8),
	growableCap(syncMsgFailoverBatchCommit, "FailoverBatchCommit", 1+maxFailoverBatchRGCount+8),
	growableCap(syncMsgFailoverBatchAbort, "FailoverBatchAbort", 1+maxFailoverBatchRGCount+8),
	// encodeFailoverBatchAckPayload: request shape + status + detail
	// (detail clamped at encode); decoder takes the rest as detail.
	{id: syncMsgFailoverBatchAck, name: "FailoverBatchAck", encoderMax: 1 + maxFailoverBatchRGCount + 1 + 8 + 4096, maxLen: 1 + maxFailoverBatchRGCount + 1 + 8 + 4096, growable: true},
	{id: syncMsgFailoverBatchCommitAck, name: "FailoverBatchCommitAck", encoderMax: 1 + maxFailoverBatchRGCount + 1 + 8 + 4096, maxLen: 1 + maxFailoverBatchRGCount + 1 + 8 + 4096, growable: true},
	// decodeFenceAckPayload gates on >= fenceAckPayloadLen and reads
	// the fixed 13-byte prefix; trailing bytes are skipped.
	growableCap(syncMsgFenceAck, "FenceAck", fenceAckPayloadLen),
	// sendCapabilities: 5 + bootIncarnationLen + epoch + token + flags2
	// (#16756/#18032). handlePeerCapabilities is the archetypal
	// #2170 length-gated decoder: longer = newer peer, skip the tail.
	growableCap(syncMsgPeerCapabilities, "PeerCapabilities", 5+bootIncarnationLen+8+8+1),
	growableCap(syncMsgClockSync, "ClockSync", 8),
	// Version byte + X25519 public key; handleConfigKeyExchange reads
	// payload[1:1+32] and never inspects the tail (#2170 contract).
	growableCap(syncMsgConfigKeyExchange, "ConfigKeyExchange", 1+syncConfigECDHPubSize),
	// One version byte; the handler gates on payload[0] only.
	growableCap(syncMsgAuthUpgradeRequest, "AuthUpgradeRequest", 1),
	// Version byte + one Noise message (48 B msg1; msg2 same class).
	// 1 KiB is the historical cap; the Noise layer rejects anything
	// that is not a well-formed message.
	{id: syncMsgAuthUpgradeHello, name: "AuthUpgradeHello", encoderMax: 1 + 48, maxLen: 1024, growable: true},
	{id: syncMsgAuthUpgradeProof, name: "AuthUpgradeProof", encoderMax: 1 + 48, maxLen: 1024, growable: true},
	// Version byte + HMAC-SHA256, compared whole (hmac.Equal on the
	// exact expected length): fixed-forever.
	fixedCap(syncMsgAuthUpgradeConfirm, "AuthUpgradeConfirm", 1+syncAuthUpgradeConfirmLen),
	// encodeConfigPayloadWithAncestry: the full committed config text
	// plus generation/ancestry trailers. Config is the one legitimately
	// large control payload; it keeps the global cap as its per-type cap.
	{id: syncMsgConfig, name: "Config", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgConfigEncrypted, name: "ConfigEncrypted", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	// Full-set / chunked-set types: encoders chunk below maxSyncPayload
	// (encodePersistentNatLeaseBatchFrames, DHCP chunk splitter), so
	// the global cap IS the per-type cap for these.
	{id: syncMsgIPsecSA, name: "IPsecSA", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgIPsecSAChunk, name: "IPsecSAChunk", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgPersistentNatLease, name: "PersistentNatLease", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgPersistentNatLeaseScoped, name: "PersistentNatLeaseScoped", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgPersistentNatLeaseGeneration, name: "PersistentNatLeaseGeneration", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgPersistentNatLeaseDeterministic, name: "PersistentNatLeaseDeterministic", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgPersistentNatLeaseProvenance, name: "PersistentNatLeaseProvenance", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgPersistentNatLeaseDeterministicProvenance, name: "PersistentNatLeaseDeterministicProvenance", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgDHCPLeaseV4, name: "DHCPLeaseV4", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgDHCPLeaseV6, name: "DHCPLeaseV6", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgDHCPLeaseV4Chunk, name: "DHCPLeaseV4Chunk", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
	{id: syncMsgDHCPLeaseV6Chunk, name: "DHCPLeaseV6Chunk", encoderMax: maxSyncPayload, maxLen: maxSyncPayload, growable: true},
}

var syncPayloadCapsByType = func() map[uint8]int {
	m := make(map[uint8]int, len(syncMsgDescriptors))
	for _, d := range syncMsgDescriptors {
		m[d.id] = d.maxLen
	}
	return m
}()

// syncPayloadCap returns the per-type payload cap for a known sync
// message type. Unknown types have no per-type cap (known=false): a
// newer peer's additive type must stay forward-compatible — bounded
// by maxSyncPayload for the read, then dropped unaccepted.
func syncPayloadCap(msgType uint8) (int, bool) {
	c, known := syncPayloadCapsByType[msgType]
	return c, known
}

// clampFailoverAckPayload truncates a single-RG failover ack's
// free-form detail (payload[10:]) so the payload fits its type cap
// (#17093 acceptance (d)): a sender must never emit over its cap, or
// a #16041-or-later peer drops the connection on the ack. Payloads
// at or under the cap, and non-ack types, pass through unchanged.
func clampFailoverAckPayload(msgType uint8, payload []byte) []byte {
	c, known := syncPayloadCap(msgType)
	if !known || len(payload) <= c {
		return payload
	}
	return payload[:c]
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
