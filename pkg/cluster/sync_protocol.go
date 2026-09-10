package cluster

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"net"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"golang.org/x/sys/unix"
)

// monotonicSeconds returns the monotonic clock in seconds.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// MonotonicNanos returns the monotonic clock (CLOCK_MONOTONIC) in
// nanoseconds. Liveness timestamps must be stored and compared in this
// domain instead of time.Now().UnixNano(): round-tripping wall-clock
// nanos through time.Unix(0, n) strips Go's monotonic reading, so every
// age computed from the stored value moves with wall-clock steps (NTP
// makestep, manual date -s, VM pause/resume) — a forward step larger
// than the heartbeat timeout falsely declares the peer lost (#1792).
// Exported because pkg/daemon's heartbeat suppression guard lives in
// the same liveness domain.
func MonotonicNanos() int64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano()
}

// rebaseTimestamp adjusts a peer timestamp to the local monotonic clock domain.
func rebaseTimestamp(peerTS uint64, offset int64) uint64 {
	v := int64(peerTS) + offset
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// writeFull loops until all bytes are written or an error occurs, handling
// short writes from TCP backpressure.
//
// writeFull is the single chokepoint through which every outgoing sync frame
// passes (writeMsg builds a frame then calls writeFull; the send loop calls it
// with pre-encoded frames). On an AUTHENTICATED connection (#4107 F23) it seals
// each complete frame with a per-connection sequence + HMAC trailer here, once,
// so the seal covers all writers uniformly. All callers hold s.writeMu, so the
// assigned sequence order equals the on-wire order. Frames on an
// unauthenticated (dual-accept) connection are written unchanged.
func writeFull(conn net.Conn, buf []byte) error {
	if ac, ok := conn.(*authConn); ok && ac.writeAuthed() {
		buf = ac.sealFrame(buf)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(syncWriteDeadline)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}
func writeMsg(conn net.Conn, msgType uint8, payload []byte) error {
	buf := make([]byte, syncHeaderSize+len(payload))
	copy(buf[:4], syncMagic[:])
	buf[4] = msgType
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(payload)))
	copy(buf[syncHeaderSize:], payload)
	return writeFull(conn, buf)
}
func encodeSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) []byte {
	payload := encodeSessionV4Payload(key, val)
	return encodeRawMessage(syncMsgSessionV4, payload)
}
func encodeRawMessage(msgType uint8, payload []byte) []byte {
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = msgType
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	return append(hdr, payload...)
}
func encodeSessionV4Payload(key dataplane.SessionKey, val dataplane.SessionValue) []byte {
	keySize := 16
	valSize := 160
	// +8 for the #2170 install Generation, +8 for the #3301 trailing
	// AppTimeout(u32)+PolicyCounterIdx(u32), +8 for the #5274 ConfigEpoch, +8 for
	// the #5212 RTFlowSessionID, +4 for the #7095 IngressIfaceFold, +8 for the
	// #7188 TunnelDiscriminator. All length-gated: an old decoder stops after
	// the field it knows and ignores the rest.
	// #7239 RoutingDomain (4) and #9412 TCPCloseClass (1) ride behind the
	// fields above. Over-allocating is harmless: the result is buf[:off].
	buf := make([]byte, keySize+valSize+8+8+8+8+4+8+4+1)
	off := 0
	copy(buf[off:], key.SrcIP[:])
	off += 4
	copy(buf[off:], key.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], key.DstPort)
	off += 2
	buf[off] = key.Protocol
	off += 4
	buf[off] = val.State
	off++
	// #5460: SessionValue.Flags is uint16, but the HA sync wire carries only the
	// low byte here. All SESS_FLAG_* bits currently set on a session are 0-7
	// (SNAT..NAT64); bit 8 (SessFlagNPTV6) is never set today, so truncating to a
	// byte is loss-free. If session-level NPTv6 flagging is ever added, carry the
	// high byte as a trailing length-gated field (like Generation) rather than
	// widening this fixed-offset byte in place — that would be a wire flag-day.
	buf[off] = byte(val.Flags)
	off++
	buf[off] = val.TCPState
	off++
	buf[off] = val.IsReverse
	off += 5
	binary.LittleEndian.PutUint64(buf[off:], val.SessionID)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.Created)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.LastSeen)
	off += 8
	binary.LittleEndian.PutUint32(buf[off:], val.Timeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyID)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.IngressZone)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.EgressZone)
	off += 2
	binary.LittleEndian.PutUint32(buf[off:], val.NATSrcIP)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.NATDstIP)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.NATSrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.NATDstPort)
	off += 2
	binary.LittleEndian.PutUint64(buf[off:], val.FwdPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.FwdBytes)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevBytes)
	off += 8
	copy(buf[off:], val.ReverseKey.SrcIP[:])
	off += 4
	copy(buf[off:], val.ReverseKey.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.DstPort)
	off += 2
	buf[off] = val.ReverseKey.Protocol
	off += 4
	buf[off] = val.ALGType
	off++
	buf[off] = val.LogFlags
	off += 3
	binary.LittleEndian.PutUint32(buf[off:], val.FibIfindex)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.FibVlanID)
	off += 2
	copy(buf[off:], val.FibDmac[:])
	off += 6
	copy(buf[off:], val.FibSmac[:])
	off += 6
	binary.LittleEndian.PutUint16(buf[off:], val.FibGen)
	off += 2
	// #2170: install generation (length-gated trailing field).
	binary.LittleEndian.PutUint64(buf[off:], val.Generation)
	off += 8
	// #3301: per-application idle timeout (seconds) + per-rule hit-counter
	// handle (length-gated trailing fields). Old decoders stop after the
	// generation and ignore these; absent => 0 (global timeout / no counter).
	binary.LittleEndian.PutUint32(buf[off:], val.AppTimeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyCounterIdx)
	off += 4
	// #5274: admitting config epoch (length-gated trailing field). The cluster
	// receiver refuses an install whose epoch is strictly older than its
	// lastAppliedConfigGen (a stale permit across a config that now denies the
	// session). Old decoders stop after PolicyCounterIdx and ignore it; absent
	// => 0 (legacy peer / check disabled).
	binary.LittleEndian.PutUint64(buf[off:], val.ConfigEpoch)
	off += 8
	// #5212: the originating node's stable RT_FLOW session id (length-gated
	// trailing field). A peer-synced session ADOPTS this id on import instead of
	// minting a fresh node-local one, so its RT_FLOW SESSION_CREATE/CLOSE records
	// correlate across HA nodes. Old decoders stop after ConfigEpoch and ignore
	// it; absent => 0 (legacy peer / fresh-local-id fallback).
	binary.LittleEndian.PutUint64(buf[off:], val.RTFlowSessionID)
	off += 8
	// #7095: the CLUSTER-STABLE fold of the session's ingress interface name
	// (length-gated trailing field). The #4983 ingress identity is an
	// IFINDEX, which is node-local and would name a different NIC on the
	// importing node, so what rides the wire is a fold of the RETH-RELATIVE
	// name both chassis agree on. Old decoders stop after RTFlowSessionID and
	// ignore it; absent => 0, which is also what a session with no
	// cluster-stable ingress name and a fabric-redirected session (#7096)
	// send. All three fall back to the #4792 zone approximation.
	binary.LittleEndian.PutUint32(buf[off:], val.IngressIfaceFold)
	off += 4
	// #7188: the tunnel session-identity discriminator (length-gated trailing
	// field). GRE is protocol 47 and has no L4 ports, so two RFC 2890 tunnels
	// between one pair of outer endpoints are ONE 5-tuple and one wire key; this
	// value is what the peer helper folds into the key it reconstructs so they
	// stay two sessions. Opaque here — the tag is defined by the helper's
	// TunnelDiscriminator::to_wire. Old decoders stop after IngressIfaceFold and
	// ignore it; absent => 0, the RESERVED "not carried" tag, on which the peer
	// helper WITHHOLDS a protocol-47 session rather than importing it aliased
	// (#7188 decision 2). Every other protocol is unaffected.
	binary.LittleEndian.PutUint64(buf[off:], val.TunnelDiscriminator)
	off += 8
	// #7239 (#7160/#2387): the session key's ROUTING DOMAIN (length-gated
	// trailing field). CARRIED rather than derived on the peer: the importing
	// node used to resolve the domain from IngressIfaceFold above, and that
	// fold is stamped on the SEND path against the CURRENT config, so an
	// ifindex recycled onto a sibling between install and sync imported the
	// session into the SIBLING's routing domain — a cross-tenant mis-file in
	// the field #7160 added to prevent one. This value is stamped at INSTALL
	// from the interface the flow actually arrived on, so no later recycle can
	// move it. Old decoders stop after TunnelDiscriminator; absent => 0, the
	// default routing instance, which is legal and is the pre-#7160 behaviour.
	// Like every trailing field since #2170 it does NOT bump
	// SessionSyncWireVersion.
	binary.LittleEndian.PutUint32(buf[off:], val.RoutingDomain)
	off += 4
	// #9412: the TCP close class (u8), length-gated after the routing domain.
	// 0 = not carried or not closing. A decoder that predates this byte stops
	// after RoutingDomain and imports the session exactly as before. Like every
	// trailing field since #2170 it does NOT bump SessionSyncWireVersion.
	buf[off] = val.TCPCloseClass
	off++
	return buf[:off]
}
func encodeSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) []byte {
	payload := encodeSessionV6Payload(key, val)
	hdr := make([]byte, syncHeaderSize)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgSessionV6
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	return append(hdr, payload...)
}
func encodeSessionV6Payload(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) []byte {
	buf := make([]byte, 512)
	off := 0
	copy(buf[off:], key.SrcIP[:])
	off += 16
	copy(buf[off:], key.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], key.DstPort)
	off += 2
	buf[off] = key.Protocol
	off += 4
	buf[off] = val.State
	off++
	// #5460: SessionValue.Flags is uint16, but the HA sync wire carries only the
	// low byte here. All SESS_FLAG_* bits currently set on a session are 0-7
	// (SNAT..NAT64); bit 8 (SessFlagNPTV6) is never set today, so truncating to a
	// byte is loss-free. If session-level NPTv6 flagging is ever added, carry the
	// high byte as a trailing length-gated field (like Generation) rather than
	// widening this fixed-offset byte in place — that would be a wire flag-day.
	buf[off] = byte(val.Flags)
	off++
	buf[off] = val.TCPState
	off++
	buf[off] = val.IsReverse
	off += 5
	binary.LittleEndian.PutUint64(buf[off:], val.SessionID)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.Created)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.LastSeen)
	off += 8
	binary.LittleEndian.PutUint32(buf[off:], val.Timeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyID)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.IngressZone)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.EgressZone)
	off += 2
	copy(buf[off:], val.NATSrcIP[:])
	off += 16
	copy(buf[off:], val.NATDstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], val.NATSrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.NATDstPort)
	off += 2
	binary.LittleEndian.PutUint64(buf[off:], val.FwdPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.FwdBytes)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevPackets)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], val.RevBytes)
	off += 8
	copy(buf[off:], val.ReverseKey.SrcIP[:])
	off += 16
	copy(buf[off:], val.ReverseKey.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], val.ReverseKey.DstPort)
	off += 2
	buf[off] = val.ReverseKey.Protocol
	off += 4
	buf[off] = val.ALGType
	off++
	buf[off] = val.LogFlags
	off += 3
	binary.LittleEndian.PutUint32(buf[off:], val.FibIfindex)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], val.FibVlanID)
	off += 2
	copy(buf[off:], val.FibDmac[:])
	off += 6
	copy(buf[off:], val.FibSmac[:])
	off += 6
	binary.LittleEndian.PutUint16(buf[off:], val.FibGen)
	off += 2
	// #2170: install generation (length-gated trailing field).
	binary.LittleEndian.PutUint64(buf[off:], val.Generation)
	off += 8
	// #3301: per-application idle timeout + per-rule hit-counter handle
	// (length-gated trailing fields; see encodeSessionV4Payload).
	binary.LittleEndian.PutUint32(buf[off:], val.AppTimeout)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], val.PolicyCounterIdx)
	off += 4
	// #4565: NAT64 translated pool SOURCE (4-byte IPv4), length-gated trailing
	// field. Non-zero marks a NAT64 cross-family session so a peer-PROMOTED
	// node rebuilds its reverse (v4->v6) BIB after failover. Only V6 sessions
	// carry this (a NAT64 forward flow is keyed on the original IPv6 5-tuple).
	// An old decoder stops after PolicyCounterIdx and ignores it (=> not NAT64).
	copy(buf[off:off+4], val.Nat64SnatV4[:])
	off += 4
	// #5274: admitting config epoch (length-gated trailing field; see
	// encodeSessionV4Payload). Old decoders stop after Nat64SnatV4 and ignore
	// it; absent => 0 (legacy peer / check disabled).
	binary.LittleEndian.PutUint64(buf[off:], val.ConfigEpoch)
	off += 8
	// #5212: originating node's stable RT_FLOW session id (length-gated trailing
	// field; see encodeSessionV4Payload). Old decoders stop after ConfigEpoch;
	// absent => 0 (legacy peer / fresh-local-id fallback on import).
	binary.LittleEndian.PutUint64(buf[off:], val.RTFlowSessionID)
	off += 8
	// #7095: the CLUSTER-STABLE fold of the session's ingress interface name
	// (length-gated trailing field). The #4983 ingress identity is an
	// IFINDEX, which is node-local and would name a different NIC on the
	// importing node, so what rides the wire is a fold of the RETH-RELATIVE
	// name both chassis agree on. Old decoders stop after RTFlowSessionID and
	// ignore it; absent => 0, which is also what a session with no
	// cluster-stable ingress name and a fabric-redirected session (#7096)
	// send. All three fall back to the #4792 zone approximation.
	binary.LittleEndian.PutUint32(buf[off:], val.IngressIfaceFold)
	off += 4
	// #7188: the tunnel session-identity discriminator (length-gated trailing
	// field; see encodeSessionV4Payload for why identity needs it). Old decoders
	// stop after IngressIfaceFold; absent => 0, the RESERVED "not carried" tag.
	binary.LittleEndian.PutUint64(buf[off:], val.TunnelDiscriminator)
	off += 8
	// #7239 (#7160/#2387): the session key's ROUTING DOMAIN (length-gated
	// trailing field). CARRIED rather than derived on the peer: the importing
	// node used to resolve the domain from IngressIfaceFold above, and that
	// fold is stamped on the SEND path against the CURRENT config, so an
	// ifindex recycled onto a sibling between install and sync imported the
	// session into the SIBLING's routing domain — a cross-tenant mis-file in
	// the field #7160 added to prevent one. This value is stamped at INSTALL
	// from the interface the flow actually arrived on, so no later recycle can
	// move it. Old decoders stop after TunnelDiscriminator; absent => 0, the
	// default routing instance, which is legal and is the pre-#7160 behaviour.
	// Like every trailing field since #2170 it does NOT bump
	// SessionSyncWireVersion.
	binary.LittleEndian.PutUint32(buf[off:], val.RoutingDomain)
	off += 4
	// #9412: the TCP close class (u8), length-gated after the routing domain.
	// 0 = not carried or not closing. A decoder that predates this byte stops
	// after RoutingDomain and imports the session exactly as before. Like every
	// trailing field since #2170 it does NOT bump SessionSyncWireVersion.
	buf[off] = val.TCPCloseClass
	off++
	return buf[:off]
}

// encodeDeleteV4 emits a delete message for a v4 session key. The 16-byte
// 5-tuple payload grows to 24 bytes with a length-gated trailing #2170
// install Generation: an old decoder reads only the first 16 bytes (its
// `len(payload) >= 16` check tolerates the longer payload) and ignores the
// generation; a new decoder reads the trailing uint64 when present. A
// generation of 0 means "unknown / legacy" and the receiver falls back to
// today's unconditional delete.
func encodeDeleteV4(key dataplane.SessionKey, gen uint64) []byte {
	hdr := make([]byte, syncHeaderSize+24)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgDeleteV4
	binary.LittleEndian.PutUint32(hdr[8:12], 24)
	off := syncHeaderSize
	copy(hdr[off:], key.SrcIP[:])
	off += 4
	copy(hdr[off:], key.DstIP[:])
	off += 4
	binary.LittleEndian.PutUint16(hdr[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(hdr[off:], key.DstPort)
	off += 2
	hdr[off] = key.Protocol
	off += 4 // 5-tuple block is 16 bytes total (1 proto byte + 3 pad)
	binary.LittleEndian.PutUint64(hdr[off:], gen)
	return hdr
}
func encodeDeleteV6(key dataplane.SessionKeyV6, gen uint64) []byte {
	hdr := make([]byte, syncHeaderSize+48)
	copy(hdr[:4], syncMagic[:])
	hdr[4] = syncMsgDeleteV6
	binary.LittleEndian.PutUint32(hdr[8:12], 48)
	off := syncHeaderSize
	copy(hdr[off:], key.SrcIP[:])
	off += 16
	copy(hdr[off:], key.DstIP[:])
	off += 16
	binary.LittleEndian.PutUint16(hdr[off:], key.SrcPort)
	off += 2
	binary.LittleEndian.PutUint16(hdr[off:], key.DstPort)
	off += 2
	hdr[off] = key.Protocol
	off += 4 // 5-tuple block is 40 bytes total (1 proto byte + 3 pad)
	binary.LittleEndian.PutUint64(hdr[off:], gen)
	return hdr
}

// decodeSessionV4Payload decodes a v4 session from wire format. It returns the
// decoded key, value, and an ok flag. The layout must match encodeSessionV4Payload.
func decodeSessionV4Payload(payload []byte) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	var key dataplane.SessionKey
	var val dataplane.SessionValue
	if len(payload) < 16 {
		return key, val, false
	}
	off := 0
	copy(key.SrcIP[:], payload[off:off+4])
	off += 4
	copy(key.DstIP[:], payload[off:off+4])
	off += 4
	key.SrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.DstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.Protocol = payload[off]
	off += 4
	if off+8 > len(payload) {
		return key, val, false
	}
	val.State = payload[off]
	off++
	// #5460: low byte only — see the encoder. Flags is uint16; the high byte
	// (bits >=8, SessFlagNPTV6) is not carried on the wire and defaults to 0.
	val.Flags = uint16(payload[off])
	off++
	val.TCPState = payload[off]
	off++
	val.IsReverse = payload[off]
	off += 5
	// #7175: a payload that stops here is MALFORMED, not a legacy peer. This
	// block carries SessionID, PolicyID, both zone ids and all four NAT fields
	// — the values the session MEANS — and no encoder version has ever omitted
	// them (every length-gated extension sits after the counters block; see
	// encodeSessionV4Payload). Accepting a short read here returned ok=true with
	// all of them left at ZERO, and zero is not "missing": these are values the
	// standby installs and carries, and they become live forwarding state on the
	// next failover.
	//
	// CORRECTION (was wrong in the original #7175 comment): this used to cite
	// #6682 for the claim that zone id 0 against zone id 0 is matched by a
	// `from-zone any to-zone any permit` rule with no zone guard. TWO mechanisms make it false, and both
	// predate #7175: #3110 fenced every rule tier against zone 0, so a wildcard
	// never reaches a zero pair in the first place, and #6682 then made an unzoned
	// INGRESS an explicit deny before the implicit default. `policy.rs`'s own
	// comment records the first — the rule-tier block "is skipped entirely when
	// either zone id is 0, which correctly stops every rule tier ... from
	// matching". The claim I cited was the PROBLEM STATEMENT of a closed issue.
	//
	// The corrected version was already written down in this repo, at
	// compiler_wireguard_plaintext_warn_5618_test.go, before I asserted the
	// superseded one.
	//
	// The fix stands on its own terms without it: a decoder must not report
	// success for input it did not decode, and installing a session whose
	// identity, policy attribution and NAT translation are all fabricated zeros
	// is wrong state regardless of what any one downstream consumer then does
	// with it. What is NOT established — and must not be asserted without
	// measuring — is whether an installed zero-zone session's subsequent packets
	// re-enter policy evaluation at all or take a session fast path.
	if off+48 > len(payload) {
		return key, val, false
	}
	val.SessionID = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Created = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.LastSeen = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Timeout = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.PolicyID = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.IngressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.EgressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.NATSrcIP = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.NATDstIP = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.NATSrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.NATDstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	if off+32 > len(payload) {
		return key, val, true
	}
	val.FwdPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.FwdBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	if off+16 <= len(payload) {
		copy(val.ReverseKey.SrcIP[:], payload[off:off+4])
		off += 4
		copy(val.ReverseKey.DstIP[:], payload[off:off+4])
		off += 4
		val.ReverseKey.SrcPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.DstPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.Protocol = payload[off]
		off += 4
	}
	if off+2 <= len(payload) {
		val.ALGType = payload[off]
		off++
		val.LogFlags = payload[off]
		off += 3
	}
	if off+20 <= len(payload) {
		val.FibIfindex = binary.LittleEndian.Uint32(payload[off:])
		off += 4
		val.FibVlanID = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		copy(val.FibDmac[:], payload[off:off+6])
		off += 6
		copy(val.FibSmac[:], payload[off:off+6])
		off += 6
		val.FibGen = binary.LittleEndian.Uint16(payload[off:])
		off += 2
	}
	// #2170: install generation (length-gated; absent → 0 = legacy peer).
	if off+8 <= len(payload) {
		val.Generation = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #3301: per-application idle timeout + per-rule hit-counter handle
	// (length-gated; absent → 0 = legacy peer / global timeout / no counter).
	if off+4 <= len(payload) {
		val.AppTimeout = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	if off+4 <= len(payload) {
		val.PolicyCounterIdx = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	// #5274: admitting config epoch (length-gated; absent → 0 = legacy peer /
	// config-epoch check disabled).
	if off+8 <= len(payload) {
		val.ConfigEpoch = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #5212: originating node's stable RT_FLOW session id (length-gated; absent →
	// 0 = legacy peer, receiver allocs a fresh local id on import).
	if off+8 <= len(payload) {
		val.RTFlowSessionID = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #7095: cluster-stable ingress-interface fold (length-gated; absent → 0 =
	// legacy peer / no stable name / fabric-redirected, all of which fall back
	// to the zone approximation).
	if off+4 <= len(payload) {
		val.IngressIfaceFold = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	// #7188: tunnel session-identity discriminator (length-gated; absent → 0 =
	// the RESERVED "not carried" tag, on which the peer helper withholds a
	// protocol-47 session rather than importing it aliased onto another RFC 2890
	// tunnel's key).
	if off+8 <= len(payload) {
		val.TunnelDiscriminator = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #7239: length-gated trailing routing domain. Absent => 0 (the default
	// routing instance), which is what a peer predating this field sends and
	// what every deployment with no routing-instance interface membership
	// carries.
	if off+4 <= len(payload) {
		val.RoutingDomain = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	// #9412: length-gated trailing close class. Absent => 0 (not carried),
	// which is what a peer predating this field sends.
	if off+1 <= len(payload) {
		val.TCPCloseClass = payload[off]
		off++
	}
	return key, val, true
}

// decodeSessionV6Payload decodes a v6 session from wire format. It returns the
// decoded key, value, and an ok flag. The layout must match encodeSessionV6Payload.
func decodeSessionV6Payload(payload []byte) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	var key dataplane.SessionKeyV6
	var val dataplane.SessionValueV6
	if len(payload) < 40 {
		return key, val, false
	}
	off := 0
	copy(key.SrcIP[:], payload[off:off+16])
	off += 16
	copy(key.DstIP[:], payload[off:off+16])
	off += 16
	key.SrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.DstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	key.Protocol = payload[off]
	off += 4
	if off+8 > len(payload) {
		return key, val, false
	}
	val.State = payload[off]
	off++
	// #5460: low byte only — see the encoder. Flags is uint16; the high byte
	// (bits >=8, SessFlagNPTV6) is not carried on the wire and defaults to 0.
	val.Flags = uint16(payload[off])
	off++
	val.TCPState = payload[off]
	off++
	val.IsReverse = payload[off]
	off += 5
	// #7175: mandatory — see decodeSessionV4Payload for the reasoning. SessionID,
	// PolicyID and both zone ids; a short read here zeroed every one of them and
	// still reported success.
	if off+48 > len(payload) {
		return key, val, false
	}
	val.SessionID = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Created = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.LastSeen = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.Timeout = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.PolicyID = binary.LittleEndian.Uint32(payload[off:])
	off += 4
	val.IngressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.EgressZone = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	// #7175: mandatory. v6 gives NAT its own block because the addresses are 16
	// bytes; it is the same forwarding-semantic data the v4 48-byte block carries
	// inline, so it gets the same treatment. A short read here left the session
	// with no NAT translation while reporting success.
	if off+36 > len(payload) {
		return key, val, false
	}
	copy(val.NATSrcIP[:], payload[off:off+16])
	off += 16
	copy(val.NATDstIP[:], payload[off:off+16])
	off += 16
	val.NATSrcPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	val.NATDstPort = binary.LittleEndian.Uint16(payload[off:])
	off += 2
	if off+32 > len(payload) {
		return key, val, true
	}
	val.FwdPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.FwdBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevPackets = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	val.RevBytes = binary.LittleEndian.Uint64(payload[off:])
	off += 8
	if off+40 <= len(payload) {
		copy(val.ReverseKey.SrcIP[:], payload[off:off+16])
		off += 16
		copy(val.ReverseKey.DstIP[:], payload[off:off+16])
		off += 16
		val.ReverseKey.SrcPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.DstPort = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		val.ReverseKey.Protocol = payload[off]
		off += 4
	}
	if off+2 <= len(payload) {
		val.ALGType = payload[off]
		off++
		val.LogFlags = payload[off]
		off += 3
	}
	if off+20 <= len(payload) {
		val.FibIfindex = binary.LittleEndian.Uint32(payload[off:])
		off += 4
		val.FibVlanID = binary.LittleEndian.Uint16(payload[off:])
		off += 2
		copy(val.FibDmac[:], payload[off:off+6])
		off += 6
		copy(val.FibSmac[:], payload[off:off+6])
		off += 6
		val.FibGen = binary.LittleEndian.Uint16(payload[off:])
		off += 2
	}
	// #2170: install generation (length-gated; absent → 0 = legacy peer).
	if off+8 <= len(payload) {
		val.Generation = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #3301: per-application idle timeout + per-rule hit-counter handle
	// (length-gated; absent → 0 = legacy peer / global timeout / no counter).
	if off+4 <= len(payload) {
		val.AppTimeout = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	if off+4 <= len(payload) {
		val.PolicyCounterIdx = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	// #4565: NAT64 translated pool SOURCE (length-gated; absent => all-zero =
	// not NAT64, the rolling-upgrade-safe default from a legacy peer).
	if off+4 <= len(payload) {
		copy(val.Nat64SnatV4[:], payload[off:off+4])
		off += 4
	}
	// #5274: admitting config epoch (length-gated; absent → 0 = legacy peer /
	// config-epoch check disabled).
	if off+8 <= len(payload) {
		val.ConfigEpoch = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #5212: originating node's stable RT_FLOW session id (length-gated; absent →
	// 0 = legacy peer, receiver allocs a fresh local id on import).
	if off+8 <= len(payload) {
		val.RTFlowSessionID = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #7095: cluster-stable ingress-interface fold (length-gated; absent → 0 =
	// legacy peer / no stable name / fabric-redirected, all of which fall back
	// to the zone approximation).
	if off+4 <= len(payload) {
		val.IngressIfaceFold = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	// #7188: tunnel session-identity discriminator (length-gated; absent → 0 =
	// the RESERVED "not carried" tag, on which the peer helper withholds a
	// protocol-47 session rather than importing it aliased onto another RFC 2890
	// tunnel's key).
	if off+8 <= len(payload) {
		val.TunnelDiscriminator = binary.LittleEndian.Uint64(payload[off:])
		off += 8
	}
	// #7239: length-gated trailing routing domain. Absent => 0 (the default
	// routing instance), which is what a peer predating this field sends and
	// what every deployment with no routing-instance interface membership
	// carries.
	if off+4 <= len(payload) {
		val.RoutingDomain = binary.LittleEndian.Uint32(payload[off:])
		off += 4
	}
	// #9412: length-gated trailing close class. Absent => 0 (not carried),
	// which is what a peer predating this field sends.
	if off+1 <= len(payload) {
		val.TCPCloseClass = payload[off]
		off++
	}
	return key, val, true
}

// encodeIPsecSAPayload encodes a list of IPsec connection names as
// newline-separated bytes.
func encodeIPsecSAPayload(names []string) []byte {
	if len(names) == 0 {
		return nil
	}
	joined := ""
	for i, name := range names {
		if i > 0 {
			joined += "\n"
		}
		joined += name
	}
	return []byte(joined)
}

// Bounds on a peer-supplied IPsec SA full set (#9061).
//
// The only bound in the chain was the 16 MiB frame ceiling in sync_conn_read.go,
// and the old decoder was `strings.Split(string(payload), "\n")`. Measured at
// the ceiling:
//
//	16 MiB of "\n"    -> 16,777,217 parts, 272.1 MB transient, 0 names retained
//	16 MiB of "a\n"   -> 8,388,609 parts,  674.8 MB transient, 128 MB RETAINED
//
// The retained set is the sharper end, twice over. Every one-byte name produced
// by strings.Split is a SUBSTRING sharing the payload's backing array, so the
// whole 16 MiB stays reachable for as long as any name does. And
// reinitiateIPsecSAs iterates the retained set ON TAKEOVER, calling
// InitiateConnection per name -- 8.4 M exec-shaped calls on the failover path,
// so the cost lands exactly when the cluster is least able to absorb it.
//
// The listener binds the fabric address and HMAC verification runs before this,
// so in a keyed cluster the sender is authenticated. It is not always keyed:
// sync_auth_strict_7441.go records that an unkeyed connection is a pass-through
// and that a stream admitted while unkeyed keeps injecting frames after a key is
// committed unless `chassis cluster strict-session-auth` is set.
const (
	// maxIPsecSANames bounds the element count. A chassis carrying more than
	// four thousand IPsec connections is far outside what this product targets,
	// and the sender is the peer's own live SA list -- not a set an operator
	// grows by accident.
	maxIPsecSANames = 4096
	// maxIPsecSANameLen bounds one name. strongSwan connection names are
	// identifiers; 256 bytes is well past any real one and stops a single
	// enormous "name" standing in for the element bound.
	maxIPsecSANameLen = 256
)

// decodeIPsecSAPayload decodes a newline-separated list of IPsec connection
// names, and reports whether the frame is malformed.
//
// MALFORMED MEANS REFUSE, NOT TRUNCATE, and the arm beside this one in
// sync_conn_read.go already states why for its own full set: "a full set
// REPLACES, so installing a stale or truncated one is worse than installing
// nothing." A truncated SA set would make the standby reinitiate a SUBSET on
// takeover and look like it succeeded. Keeping the previous set is the
// recoverable outcome -- the next good frame replaces it.
//
// Each name is COPIED. strings.Split would hand back substrings of the payload,
// so a single retained one-byte name pins the entire frame; scanning and
// converting per name is what makes the retained size proportional to the names
// rather than to the frame.
func decodeIPsecSAPayload(payload []byte) ([]string, bool) {
	if len(payload) == 0 {
		return nil, false
	}
	var names []string
	for len(payload) > 0 {
		line := payload
		if i := bytes.IndexByte(payload, '\n'); i >= 0 {
			line, payload = payload[:i], payload[i+1:]
		} else {
			payload = nil
		}
		if len(line) == 0 {
			continue
		}
		if len(line) > maxIPsecSANameLen {
			return nil, true
		}
		if len(names) >= maxIPsecSANames {
			return nil, true
		}
		// string(line) copies; the frame's backing array is not retained.
		names = append(names, string(line))
	}
	return names, false
}

// --- #3931 config-sync generation wire codec ------------------------------
//
// The config-sync payload historically was the raw UTF-8 config text with no
// framing. #3931 appends a monotonic config generation so the receiver can
// order a rapid commit pair (C1 then C2) and refuse a reordered older config.
// Because the config text is arbitrary bytes (no fixed layout to length-gate a
// leading field against), the generation is carried as a TRAILING framing:
//
//	[config text bytes][configGenMagic (8)][gen (uint64 LE, 8)]
//
// A NEW receiver (decodeConfigPayload) detects the magic at the tail and peels
// off the trailing 16 bytes; a payload without the magic is a LEGACY sender's
// raw config text and decodes with gen=0 (applied unconditionally, preserving
// the pre-#3931 behavior). The magic bytes are deliberately non-printable so
// they cannot collide with real Junos config text. NOTE the one asymmetric
// direction: a NEW sender's framed payload reaching a LEGACY receiver (only
// possible in the brief mixed-version ISSU window) is treated by that old
// receiver as config text with 16 trailing binary bytes, which its Junos
// parser rejects — the config-sync apply fails and the old node retains its
// current config (fail-safe, no crash, no divergence worse than today). This
// is why #3931 does NOT bump SessionSyncWireVersion: that gate governs whether
// SESSIONS sync at all across a mixed pair, and bumping it would break session
// sync for the whole mixed-base window (the #2239 lesson). Config-gen is
// additive and self-detecting via the magic.
var configGenMagic = [8]byte{0x00, 0xff, 'x', 'p', 'f', 'C', 'G', 0x00}

// encodeConfigPayload builds a config-sync payload carrying the config text
// and a trailing generation (see the codec note above).
func encodeConfigPayload(configText string, gen uint64) []byte {
	buf := make([]byte, 0, len(configText)+16)
	buf = append(buf, configText...)
	buf = append(buf, configGenMagic[:]...)
	buf = binary.LittleEndian.AppendUint64(buf, gen)
	return buf
}

// decodeConfigPayload splits a config-sync payload into its config text and
// generation. A payload without the trailing configGenMagic is a legacy
// sender's raw config text and yields gen=0.
func decodeConfigPayload(payload []byte) (configText string, gen uint64) {
	if len(payload) >= 16 && bytes.Equal(payload[len(payload)-16:len(payload)-8], configGenMagic[:]) {
		gen = binary.LittleEndian.Uint64(payload[len(payload)-8:])
		return string(payload[:len(payload)-16]), gen
	}
	return string(payload), 0
}

// --- #5706 full-set state-sync ordering wire codec ------------------------
//
// IPsec SA and DHCP-server lease sync are FULL-SET pushes: each message
// REPLACES the peer's held set wholesale. Two fabric receiveLoops
// (conn0/conn1) process a peer's frames concurrently, so a full-set can be
// delivered OUT OF ORDER across the redundant streams — a stale older set
// could then overwrite a newer one (a state REGRESSION). To order them, each
// full-set carries a trailing (incarnation, seq) framing analogous to the
// #3931 config-generation trailer:
//
//	[ base payload ][ fullSetSeqMagic (8) ][ incarnation (8 LE) ][ seq (8 LE) ]
//
// incarnation is the SENDER's process epoch (constant for a boot; a restart
// draws a fresh one); seq is a per-type strictly-monotonic counter. The
// receiver admits only a strictly-newer (incarnation, seq) per stream and
// drops a stale reorder (see fullSetSeqGuard).
//
// Backward compatibility (mixed-version ISSU): the trailer is ADDITIVE and
// self-detecting via the magic, so NO SessionSyncWireVersion bump — the same
// reasoning as #2239/#3931 (bumping it would make the #1930 mixed-base gate
// refuse SESSION sync across the pair). A legacy sender emits no trailer, so
// stripFullSetSeq returns (base, 0, 0) and the guard accept-always for that
// peer (a zero incarnation/seq is the legacy sentinel). New sender -> old
// receiver: the DHCP lease decoder reads exactly its record count and IGNORES
// the trailing bytes (fully clean).
//
// The IPsec name payload is newline-JOINED with no terminator, so gluing the
// trailer directly onto it would FUSE the 24-byte trailer onto the LAST
// connection name — an old newline-decoder (no stripFullSetSeq) would recover a
// corrupted final name it can no longer `swanctl --initiate`, silently dropping
// the last tunnel on a mixed-version ISSU takeover. To avoid that, the IPsec
// full-set inserts a single '\n' DELIMITER between the name list and the
// trailer (appendIPsecFullSetSeq): the old decoder then sees the trailer as a
// SEPARATE trailing element (a bogus name it merely warns it cannot initiate —
// harmless) and EVERY real SA name decodes cleanly. A new receiver strips the
// trailer (stripFullSetSeq) and the delimiter (stripIPsecFullSetDelim), so a
// new->new roundtrip decodes to exactly the sent names with no trailing empty
// name. DHCP keeps the delimiter-free appendFullSetSeq (binary count-prefixed;
// its old decoder already ignores the trailer). All of this is confined to the
// brief mixed-version window and self-heals once both nodes are upgraded.
var fullSetSeqMagic = [8]byte{0x00, 0xff, 'x', 'p', 'f', 'F', 'S', 0x00}

const fullSetSeqTrailerLen = 8 + 8 + 8 // magic + incarnation + seq

// appendFullSetSeq appends the (incarnation, seq) ordering trailer to a
// full-set payload. incarnation and seq MUST both be nonzero on a real sender
// so the receiver never mistakes a stamped frame for a legacy one.
func appendFullSetSeq(base []byte, incarnation, seq uint64) []byte {
	out := make([]byte, 0, len(base)+fullSetSeqTrailerLen)
	out = append(out, base...)
	out = append(out, fullSetSeqMagic[:]...)
	out = binary.LittleEndian.AppendUint64(out, incarnation)
	out = binary.LittleEndian.AppendUint64(out, seq)
	return out
}

// stripFullSetSeq splits a full-set payload into its base bytes and the
// trailing (incarnation, seq). A payload WITHOUT the trailer (a legacy
// pre-#5706 sender) yields the whole payload as base and (0, 0), which the
// guard treats as accept-always.
func stripFullSetSeq(payload []byte) (base []byte, incarnation, seq uint64) {
	n := len(payload)
	if n >= fullSetSeqTrailerLen &&
		bytes.Equal(payload[n-fullSetSeqTrailerLen:n-16], fullSetSeqMagic[:]) {
		incarnation = binary.LittleEndian.Uint64(payload[n-16 : n-8])
		seq = binary.LittleEndian.Uint64(payload[n-8:])
		return payload[:n-fullSetSeqTrailerLen], incarnation, seq
	}
	return payload, 0, 0
}

// ipsecFullSetDelim separates the newline-joined IPsec SA name list from its
// trailing (incarnation, seq) full-set trailer. encodeIPsecSAPayload joins
// names with '\n' and appends NO terminator, so without this delimiter
// appendFullSetSeq would glue the 24-byte trailer directly onto the LAST
// connection name. An OLD pre-#5706 receiver has no stripFullSetSeq: it
// newline-splits the whole frame, so a fused last name can no longer be
// `swanctl --initiate`d and that tunnel is silently NOT re-initiated on a
// mixed-version ISSU takeover. With the delimiter the old decoder sees the
// trailer as a SEPARATE trailing element (a bogus name it merely warns it
// cannot initiate — harmless) and EVERY real SA name decodes cleanly.
const ipsecFullSetDelim = '\n'

// appendIPsecFullSetSeq stamps the (incarnation, seq) ordering trailer onto an
// IPsec SA payload, inserting ipsecFullSetDelim between the name list and the
// trailer (see ipsecFullSetDelim). A NEW receiver removes the trailer with
// stripFullSetSeq and the delimiter with stripIPsecFullSetDelim, so a new->new
// roundtrip decodes to exactly the sent names (no trailing empty name). The
// delimiter is inserted only for a non-empty name list — an empty payload has
// no last name to protect, so it stays the bare trailer, matching the DHCP and
// empty-set behavior. DHCP does NOT use this: its payload is binary
// count-prefixed and its old decoder already ignores the trailer, so it keeps
// the delimiter-free appendFullSetSeq.
func appendIPsecFullSetSeq(names []byte, incarnation, seq uint64) []byte {
	base := names
	if len(names) > 0 {
		base = make([]byte, 0, len(names)+1)
		base = append(base, names...)
		base = append(base, ipsecFullSetDelim)
	}
	return appendFullSetSeq(base, incarnation, seq)
}

// stripIPsecFullSetDelim removes the single trailing ipsecFullSetDelim a NEW
// sender inserts between the SA name list and the (already-stripped) trailer.
// It is the receive-side symmetric partner of appendIPsecFullSetSeq so a
// new->new roundtrip leaves no trailing empty connection name. A frame from a
// legacy or #5706-pre-fold sender carries no delimiter — the newline-JOINED
// name list never ends in '\n' — so nothing is trimmed and those frames decode
// unchanged.
func stripIPsecFullSetDelim(base []byte) []byte {
	if n := len(base); n > 0 && base[n-1] == ipsecFullSetDelim {
		return base[:n-1]
	}
	return base
}

// --- #2239 HA DHCP-server lease sync wire codec ---------------------------
//
// A DHCP-lease payload is a full-set push of the active leases this node serves
// for one family. The framing is a 4-byte lease COUNT followed by COUNT
// length-prefixed lease records. Each record is itself length-gated so the
// schema can grow: a decoder reads only the fields the inner length covers,
// tolerating a longer record from a newer peer (trailing fields ignored) and a
// shorter record from an older peer (absent fields default to zero, EXCEPT the
// #5073 PreferredRemaining trailing field which defaults to Remaining so an
// older peer's lease is not wrongly deprecated) — the same length-gated-
// trailing-field discipline as #2170 sessions. The lease wire carries REMAINING
// LIFETIME (not absolute expiry) so the receiver re-anchors to its local clock
// at seed (the #2239 clock invariant). The trailing field order is, after the
// FQDN flags byte: PreferredRemaining (uint32 LE, #5073). Adding a field here is
// append-only and does NOT bump SessionSyncWireVersion.

// putLeaseString appends a uint16-length-prefixed string. It FAILS CLOSED when
// s exceeds the uint16 wire prefix (math.MaxUint16 = 65535 bytes): the prefix
// would otherwise silently narrow (uint16(len(s)) wraps to the low 16 bits) and
// the peer's getLeaseString would read a truncated string, then misread the
// record's trailing bytes as later fields — a cross-node lease-sync misframe
// that corrupts the lease's identity/type/prefix-length/hostname on the standby
// (#4892). The wire format is unchanged (getLeaseString still trusts the uint16
// prefix); the writer simply never emits an oversized field — the encoder
// rejects the whole lease instead. Real DHCP identifiers/DUIDs/hostnames are far
// below 64 KiB, so this is defensive validation, not an expected path.
func putLeaseString(b []byte, s string) ([]byte, error) {
	if len(s) > math.MaxUint16 {
		return nil, fmt.Errorf("lease-sync string field length %d exceeds uint16 wire limit %d", len(s), math.MaxUint16)
	}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...), nil
}

// getLeaseString reads a uint16-length-prefixed string at off, returning the
// value, the new offset, and ok. ok is false if the buffer is too short
// (truncated record — caller stops decoding that record's remaining fields).
func getLeaseString(buf []byte, off int) (string, int, bool) {
	if off+2 > len(buf) {
		return "", off, false
	}
	n := int(binary.LittleEndian.Uint16(buf[off:]))
	off += 2
	if off+n > len(buf) {
		return "", off, false
	}
	return string(buf[off : off+n]), off + n, true
}

// encodeOneLease serializes one SyncLease into a self-describing record body
// (without the outer record-length prefix). Field order is fixed and append-
// only; decoders read what the record length covers. It returns an error when
// any variable-length field exceeds the uint16 wire prefix (#4892): the lease is
// rejected from the sync push rather than emitted misframed. err names the field
// so the caller's warning is actionable.
func encodeOneLease(l dhcpserver.SyncLease) ([]byte, error) {
	b := make([]byte, 0, 96)
	b = append(b, byte(l.Family))
	var err error
	if b, err = putLeaseString(b, l.Address); err != nil {
		return nil, fmt.Errorf("encode lease Address: %w", err)
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(l.SubnetID))
	b = binary.LittleEndian.AppendUint32(b, uint32(l.ValidLife))
	b = binary.LittleEndian.AppendUint32(b, uint32(l.Remaining))
	b = append(b, byte(l.State))
	// identity + naming (variable). v4: hwaddr, clientid. v6: duid, iaid,
	// leasetype, prefixlen. Both families carry all slots; the unused ones
	// are empty/zero so the record layout is family-uniform and append-only.
	if b, err = putLeaseString(b, l.HWAddress); err != nil {
		return nil, fmt.Errorf("encode lease HWAddress: %w", err)
	}
	if b, err = putLeaseString(b, l.ClientID); err != nil {
		return nil, fmt.Errorf("encode lease ClientID: %w", err)
	}
	if b, err = putLeaseString(b, l.DUID); err != nil {
		return nil, fmt.Errorf("encode lease DUID: %w", err)
	}
	b = binary.LittleEndian.AppendUint32(b, l.IAID)
	if b, err = putLeaseString(b, l.LeaseType); err != nil {
		return nil, fmt.Errorf("encode lease LeaseType: %w", err)
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(l.PrefixLen))
	if b, err = putLeaseString(b, l.Hostname); err != nil {
		return nil, fmt.Errorf("encode lease Hostname: %w", err)
	}
	var flags byte
	if l.FQDNFwd {
		flags |= 0x01
	}
	if l.FQDNRev {
		flags |= 0x02
	}
	b = append(b, flags)
	// #5073 APPEND-ONLY trailing field: PreferredRemaining (seconds of preferred
	// lifetime left). It MUST stay last so an older decoder (whose record ends at
	// the FQDN flags byte) simply ignores it, and a newer decoder defaults it to
	// Remaining when an older sender omits it (see decodeOneLease). This is a
	// length-gated trailing field like the #3931 config-gen — it does NOT bump
	// SessionSyncWireVersion.
	b = binary.LittleEndian.AppendUint32(b, uint32(l.PreferredRemaining))
	return b, nil
}

// decodeOneLease parses a record body produced by encodeOneLease. It is
// length-gated: each field read checks bounds and stops at the first short
// read, so a legacy (shorter) record yields zero values for absent trailing
// fields and a future (longer) record's extra fields are ignored.
func decodeOneLease(buf []byte) dhcpserver.SyncLease {
	var l dhcpserver.SyncLease
	off := 0
	if off >= len(buf) {
		return l
	}
	l.Family = int(buf[off])
	off++
	var ok bool
	if l.Address, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off+4 > len(buf) {
		return l
	}
	l.SubnetID = int(binary.LittleEndian.Uint32(buf[off:]))
	off += 4
	if off+4 > len(buf) {
		return l
	}
	l.ValidLife = int(binary.LittleEndian.Uint32(buf[off:]))
	off += 4
	if off+4 > len(buf) {
		return l
	}
	l.Remaining = int(binary.LittleEndian.Uint32(buf[off:]))
	off += 4
	// #5073: default PreferredRemaining to the valid Remaining (preferred==valid,
	// the pre-#5073 behavior). This is LOAD-BEARING and set BEFORE any later
	// early-return: an OLDER peer's record ends at the FQDN flags byte with NO
	// trailing PreferredRemaining, and defaulting to Remaining (NOT 0) avoids
	// wrongly deprecating every lease synced from that peer. The trailing-field
	// read at the tail overrides this only when a newer sender actually supplied
	// the field.
	l.PreferredRemaining = l.Remaining
	if off >= len(buf) {
		return l
	}
	l.State = int(buf[off])
	off++
	if l.HWAddress, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if l.ClientID, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if l.DUID, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off+4 > len(buf) {
		return l
	}
	l.IAID = binary.LittleEndian.Uint32(buf[off:])
	off += 4
	if l.LeaseType, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off+4 > len(buf) {
		return l
	}
	l.PrefixLen = int(binary.LittleEndian.Uint32(buf[off:]))
	off += 4
	if l.Hostname, off, ok = getLeaseString(buf, off); !ok {
		return l
	}
	if off < len(buf) {
		flags := buf[off]
		l.FQDNFwd = flags&0x01 != 0
		l.FQDNRev = flags&0x02 != 0
		off++ // advance past flags so the #5073 trailing field can follow
	}
	// #5073 append-only trailing field. PRESENT (a newer peer) → read it;
	// ABSENT (an older peer whose record stopped at the FQDN flags byte) → leave
	// the preferred==valid default set above. Guarded by remaining length so a
	// truncated tail never over-reads.
	if off+4 <= len(buf) {
		l.PreferredRemaining = int(binary.LittleEndian.Uint32(buf[off:]))
		off += 4
	}
	return l
}

// encodeDHCPLeasePayload serializes a full-set lease push: a 4-byte count
// followed by length-prefixed lease records. An empty set encodes as a 4-byte
// zero count (a legitimate "I serve no leases" message, distinct from a legacy
// peer that never sends this type at all).
func encodeDHCPLeasePayload(leases []dhcpserver.SyncLease) []byte {
	// Encode records first so an oversized field (which encodeOneLease rejects,
	// #4892) DROPS just that lease — fail-closed — while the count prefix stays
	// consistent with the records actually emitted. Dropping one unencodable
	// lease is strictly safer than either misframing the peer's decode or
	// blocking the entire push; the standby simply lacks that one lease (the
	// client re-DHCPs on takeover) instead of seeding a corrupted identity.
	recs := make([][]byte, 0, len(leases))
	for _, l := range leases {
		rec, err := encodeOneLease(l)
		if err != nil {
			slog.Warn("cluster sync: dropping unencodable DHCP lease from sync push",
				"family", l.Family, "address", l.Address, "err", err)
			continue
		}
		recs = append(recs, rec)
	}
	b := make([]byte, 0, 8+len(recs)*64)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(recs)))
	for _, rec := range recs {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
		b = append(b, rec...)
	}
	return b
}

// decodeDHCPLeasePayload parses a full-set lease push. A truncated payload
// stops decoding at the last complete record (fail-safe: a partial message
// yields the leases that fully arrived rather than erroring the whole push).
// #7175 (C179-075): the bool reports whether the payload decoded COMPLETELY.
// A full-set push REPLACES the peer lease set, so returning a truncated prefix
// silently deleted every lease past the truncation point on the standby. The
// caller must retain its prior set when this is false rather than storing a
// partial one — the same disposition the stale-sequence guard already applies
// one branch above ("standby retains newer set").
// minDHCPLeaseRecordLen is the smallest record that can carry a real lease
// (#9507): the #2239 layout with a one-byte address and every other string empty.
// That is 1 family, a 2-byte address length plus 1 address byte, 12 bytes of
// SubnetID/ValidLife/Remaining, 1 state, three 2-byte hwaddr/clientid/duid
// lengths, 4 IAID, a 2-byte lease-type length, 4 prefix length, a 2-byte hostname
// length and 1 FQDN flags byte: 36. #5073 later appended PreferredRemaining (4). A
// rolling upgrade can still deliver the #2239 form, so the floor stays there. A
// record with an EMPTY address (35 bytes) is rejected separately, so a shorter
// record could only carry a truncated lease.
const minDHCPLeaseRecordLen = 36

func decodeDHCPLeasePayload(payload []byte) ([]dhcpserver.SyncLease, bool) {
	if len(payload) < 4 {
		return nil, false
	}
	count := int(binary.LittleEndian.Uint32(payload[:4]))
	// count is untrusted on-wire data. Each record consumes at least its 4-byte
	// length prefix, so a frame holds at most len(payload)/4 of them.
	// #7175: a count exceeding what the payload can physically hold is not a
	// short valid set; no encoder produces it, so the frame is malformed.
	// #9507: say so BEFORE allocating anything. The result (nil, false) is the one
	// the pre-#9507 clamp-then-loop reached anyway, after a len/4-sized make().
	if maxRecords := len(payload) / 4; count > maxRecords {
		return nil, false
	}
	// #9507 pass 1: validate the framing of every record the count names, with
	// NO allocation. The old decoder preallocated `count` 168-byte leases before
	// reading a record, and accepted zero-length records, so 4 wire bytes bought
	// a retained lease: 42x the frame, about 672 MiB at the 16 MiB cap.
	whole := 0
	off := 4
	for i := 0; i < count; i++ {
		if off+4 > len(payload) {
			// The buffer ended while the count still expected records. Every
			// record that DID arrive is whole; only the sender's count was
			// wrong. So this stays recoverable, which is the contract
			// TestDHCPLeasePayload_TruncatedStream pins. Deliberately NOT
			// malformed: nothing was lost mid-record.
			break
		}
		recLen := int(binary.LittleEndian.Uint32(payload[off:]))
		off += 4
		if recLen < minDHCPLeaseRecordLen {
			// #9507: shorter than any record an encoder has ever emitted (a
			// zero-length record is the 42x lever). Corrupt data, not a short
			// set.
			return nil, false
		}
		if off+recLen > len(payload) {
			// A record is CUT: its declared length runs past the buffer, so part
			// of a lease is gone. This is the C179-075 case. The full-set push
			// REPLACES the peer set, so returning the prefix would delete every
			// lease after the cut on the standby.
			return nil, false
		}
		// #9507: every encoder writes the lease's address first, after the
		// family byte. A record whose address is empty, or overruns the record,
		// decodes to a lease with no address, which is not a lease.
		if addrLen := int(binary.LittleEndian.Uint16(payload[off+1:])); addrLen == 0 || 3+addrLen > recLen {
			return nil, false
		}
		off += recLen
		whole++
	}
	// Pass 2: decode exactly the records pass 1 validated, into exact capacity.
	// A retained lease therefore costs at least 4+minDHCPLeaseRecordLen wire bytes
	// (168/40, about 4.2x the frame), and an impossible frame allocates nothing.
	// Trailing bytes after the last record are NOT malformed: the #5073 full-set
	// seq trailer is appended exactly so an old decoder walks its records and
	// ignores the remainder (TestFullSetSeqDHCPTrailerIgnoredByOldDecoder).
	out := make([]dhcpserver.SyncLease, 0, whole)
	off = 4
	for i := 0; i < whole; i++ {
		recLen := int(binary.LittleEndian.Uint32(payload[off:]))
		off += 4
		out = append(out, decodeOneLease(payload[off:off+recLen]))
		off += recLen
	}
	return out, true
}
