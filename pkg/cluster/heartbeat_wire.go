package cluster

// heartbeat_wire.go is the heartbeat wire codec: the on-wire layout of
// HeartbeatPacket and the encode/decode + auth-trailer signing functions.
// It is split in-package from heartbeat.go (#16169) so the wire contract —
// documented in pkg/cluster/README.md (#10775) — has one reviewable home
// with golden byte vectors (heartbeat_wire_golden_test.go). Admission,
// anti-replay state, transport, and liveness policy stay in heartbeat.go
// and the heartbeat_epoch_*.go / heartbeat_auth_replay.go files; this file
// only encodes, decodes, and signs frames. No new packages, interfaces, or
// per-heartbeat copies are introduced: the move is verbatim.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
)

const (
	// heartbeatMagic identifies xpf cluster heartbeat packets.
	heartbeatMagic = "BPFX"

	// heartbeatVersion is the current protocol version.
	heartbeatVersion = 1

	// LegacyHAProtocolVersion is the compatibility version implicitly used by
	// older heartbeats that predate explicit HA protocol advertisement.
	LegacyHAProtocolVersion uint16 = 1

	// CurrentHAProtocolVersion is the HA/session-transfer compatibility version
	// used to decide whether mixed software builds can still hand off RGs. Bump
	// this only when heartbeat/session-sync/failover wire semantics change in a
	// way that breaks mixed-version interoperability.
	CurrentHAProtocolVersion = LegacyHAProtocolVersion

	// MinCompatHAProtocolVersion is the OLDEST HA protocol version
	// CurrentHAProtocolVersion can still interoperate with — the back-compat
	// floor the #1930 INC-3 mixed-base image-replace gate advertises. It is NOT
	// LegacyHAProtocolVersion: legacy is a fixed historical constant (1), whereas
	// this is the deliberate "how far back are we compatible" decision that an
	// author MUST re-evaluate on every CurrentHAProtocolVersion bump. They are
	// equal today (this build speaks 1 and is compatible back to 1); a future
	// incompatible bump raises Current AND sets this floor to the oldest peer the
	// new build can still sync with (which may equal Current if no back-compat).
	//
	// #7925: a SESSION-WIRE-only change does not touch this. SessionSyncWireVersion
	// is its own counter now, so widening the session key bumps that alone and
	// leaves this window intact for the heartbeat/failover semantics that did not
	// change. Re-evaluate this floor only on a CurrentHAProtocolVersion bump.
	MinCompatHAProtocolVersion = CurrentHAProtocolVersion
	// heartbeatEchoProtocolVersion gates the additive, optional peer-heard
	// echo trailer. The trailer is backward-compatible; peers without it use a
	// bounded local lease rather than being rejected.
	heartbeatEchoProtocolVersion = CurrentHAProtocolVersion

	// maxHeartbeatSize is the max packet size we'll read/write.
	// 1472 = 1500 MTU - 20 IP header - 8 UDP header.
	maxHeartbeatSize = 1472

	// heartbeatEchoMagic marks the optional peer-heard echo section. It is
	// placed before the fixed-tail epoch/auth trailers so old readers may ignore
	// it without changing their trailer offsets.
	heartbeatEchoMagic = "XPFE"
	// heartbeatEchoTrailerSize is magic(4) plus sender and echoed peer
	// session/sequence pairs (four uint64 values).
	heartbeatEchoTrailerSize = 4 + 8*4
	// heartbeatAuthMagic marks the optional #4107 PSK/HMAC auth trailer.
	// Distinct from heartbeatMagic ("BPFX") so a reader can unambiguously
	// detect a trailer at the tail of a frame. The trailer is appended AFTER
	// the optional version trailer; UnmarshalHeartbeat ignores any bytes past
	// the version section, so a signed frame is wire-compatible with a legacy
	// or not-yet-keyed peer (dual-accept during a rolling upgrade).
	heartbeatAuthMagic = "XPFA"

	// heartbeatAuthMACSize is the HMAC-SHA256 digest length.
	heartbeatAuthMACSize = 32

	// heartbeatAuthTrailerSize = magic(4) + session(8) + counter(8) + HMAC(32).
	// session+counter are the anti-replay nonce: a random per-sender-process
	// session id plus a monotonic per-session counter.
	heartbeatAuthTrailerSize = 4 + 8 + 8 + heartbeatAuthMACSize
)

// HeartbeatPacket is the wire format for cluster heartbeats.
// Layout:
//
//	[0:4]   Magic "BPFX"
//	[4]     Version (1)
//	[5]     NodeID
//	[6:8]   ClusterID (little-endian uint16)
//	[8]     NumGroups
//	[9..]   Per-group entries (5 bytes each):
//	          [0] GroupID
//	          [1:3] Priority (little-endian uint16)
//	          [3] Weight
//	          [4] State
//	After groups:
//	  NumMonitors (1 byte)
//	  Per-monitor:
//	    [0] RGID
//	    [1] Flags (bit0=up)
//	    [2] Weight
//	    [3] NameLen
//	    [4..4+NameLen] Interface name
//	After monitors:
//	  Optional VersionTrailer:
//	    [0] VersionLen
//	    [1..1+VersionLen] SoftwareVersion bytes
//	    [..] uint16 little-endian HAProtocolVersion
//	  Optional "XPFE" echo trailer: sender session/sequence and the last
//	  peer session/sequence received by the sender.
//
// The echo trailer is additive and appears before optional fixed-tail
// authentication/epoch trailers. Older readers ignore it after the version
// section.
//
// The trailing version trailer is optional; packets may end after the monitor
// section. When present, the trailer always starts with a length byte, even if
// the software version string is empty, so newer readers can unambiguously find
// the HA protocol version. Older readers ignore any bytes after the optional
// software-version field, and newer readers treat a missing trailer as the
// legacy protocol version.
type HeartbeatPacket struct {
	NodeID                uint8
	ClusterID             uint16
	Groups                []HeartbeatGroup
	Monitors              []HeartbeatMonitor
	SoftwareVersion       string
	HAProtocolVersion     uint16
	HeartbeatSession      uint64
	HeartbeatSequence     uint64
	PeerHeartbeatSession  uint64
	PeerHeartbeatSequence uint64
}

// HeartbeatGroup is a per-RG entry in the heartbeat.
type HeartbeatGroup struct {
	GroupID  uint8
	Priority uint16
	Weight   uint8
	State    uint8
}

// HeartbeatMonitor is a per-interface monitor entry in the heartbeat.
type HeartbeatMonitor struct {
	RGID      uint8
	Weight    uint8
	Up        bool
	Interface string
}

// heartbeatHeaderSize is Magic(4) + Version(1) + NodeID(1) + ClusterID(2) + NumGroups(1).
const heartbeatHeaderSize = 9

// heartbeatGroupSize is GroupID(1) + Priority(2) + Weight(1) + State(1).
const heartbeatGroupSize = 5

// maxHeartbeatGroups is the largest number of redundancy-group entries the
// heartbeat wire format can carry. The group-count field (buf[8]) and every
// per-group id byte are uint8, so a 256th group would overflow the count to 0
// and desync it from the records still written; and the frame is a fixed
// maxHeartbeatSize buffer written as 9 + N*5 bytes, so ~293 groups index past
// it and panic. 255 is the binding uint8 count limit and also fits the buffer
// (9 + 255*5 = 1284 <= maxHeartbeatSize). The commit-time gate
// config.validateChassisClusterStrict rejects any config above this; the
// marshaler caps here as a defensive backstop so it stays panic-safe and the
// count byte always matches the body even on a leniently-loaded / peer-synced
// config (#4434).
const maxHeartbeatGroups = 255

// maxHeartbeatMonitors and maxHeartbeatMonitorNameSize are the monitor
// section counterparts of maxHeartbeatGroups (#14704). NumMonitors and each
// per-monitor NameLen are uint8 on the wire, so a 256th monitor or a
// 256-byte interface name would wrap its length/count byte (256 -> 0,
// 260 -> 4) while the full payload was still written. The receiver trusts
// those bytes, so it then parsed monitor payload as the version trailer and
// never reached the "XPFE" echo trailer — poisoning SoftwareVersion /
// HAProtocolVersion and silently losing the echo lease. The commit gate
// rejects unsupported names/counts in the normal path; these caps are the
// defensive backstop for a leniently-loaded / peer-synced config, matching
// the group and software-version clamps in marshalHeartbeatBody.
const maxHeartbeatMonitors = 255

const maxHeartbeatMonitorNameSize = 255

const maxHeartbeatSoftwareVersionSize = 255

// oversizeHeartbeatGroupsWarn logs the defensive group-count truncation in
// marshalHeartbeatBody at most once per process. Once
// config.validateChassisClusterStrict gates commits this path should never
// fire, but the heartbeat sender runs every heartbeat-interval, so an
// unguarded per-send log would flood journald (#4434).
var oversizeHeartbeatGroupsWarn sync.Once

// monitorTruncationDetector is the monitor-section counterpart to
// oversizeHeartbeatGroupsWarn (#7171), with one deliberate difference: the
// DECISION that a truncation happened is separated from the once-guarded
// EMISSION of the warning.
//
// The group warning above is a bare sync.Once, and a bare Once cannot be
// tested. Whether it fires depends on which test ran first in the package
// binary rather than on the input under test, so a cell asserting it passes or
// fails on test ORDER. That is why the #4434 warning has never been asserted,
// and repeating the shape would have shipped this file's own subject -- a
// silent guard -- one level up: if the condition were unreachable, or not the
// shape expected here, the operator would get exactly the silence this exists
// to remove and nothing would say so.
//
// Splitting them also fixes something the once-guard alone gets wrong for the
// operator. A condition that RECURS is different information from one that
// happened once, and a Once reports both identically. observe counts every
// occurrence while the log still emits once, so the count is the thing tests
// and future status surfaces can read.
//
// Silence is the wrong default here because the effect is not local: the peer
// consumes NumMonitors to compute weight-based failover, so a node whose
// monitor list did not fit advertises a SMALLER monitored set than it actually
// has, and the peer's arithmetic runs on an incomplete picture.
type monitorTruncationDetector struct {
	occurrences atomic.Uint64
	warn        sync.Once
}

// observe records one marshal outcome and reports whether the monitor section
// was truncated. advertised is what was written, want is what the caller had.
// The log is once per process -- the heartbeat sender runs every
// heartbeat-interval and an unguarded log here would flood journald
// (CLAUDE.md logging rules) -- but the count advances on every occurrence.
func (d *monitorTruncationDetector) observe(want, advertised int) bool {
	if advertised >= want {
		return false
	}
	d.occurrences.Add(1)
	d.warn.Do(func() {
		slog.Warn("cluster: monitored-interface list exceeds heartbeat wire "+
			"limit; advertising only the entries that fit",
			"monitors", want, "advertised", advertised,
			"wire_limit", maxHeartbeatSize)
	})
	return true
}

// count returns how many truncations have been observed, across all
// occurrences rather than only the first.
func (d *monitorTruncationDetector) count() uint64 { return d.occurrences.Load() }

var heartbeatMonitorTruncations monitorTruncationDetector

func normalizeHAProtocolVersion(version uint16) uint16 {
	if version == 0 {
		return LegacyHAProtocolVersion
	}
	return version
}

// MarshalHeartbeat encodes a heartbeat packet to wire format.
// The output is capped at maxHeartbeatSize. RG group entries are always
// included (they are critical for election). When SoftwareVersion is present,
// space for it is reserved first so monitor truncation never drops version
// metadata. If monitors would cause the packet to exceed the limit, the monitor
// section is truncated and the version field is preserved.
func MarshalHeartbeat(pkt *HeartbeatPacket) []byte {
	return marshalHeartbeatBody(pkt, 0)
}

// marshalHeartbeatBody encodes the heartbeat wire body, keeping tailReserve
// bytes free at the tail of the frame for fixed-tail trailers (epoch and auth).
// Packets without echo fields retain the legacy body encoding; the optional
// `XPFE` section is included only when a sender session and sequence are set.
// The election-critical header + RG groups are always written and the SOFTWARE
// version and echo section are reserved before best-effort monitors are
// truncated to fit. Because the reserve is honored WHILE building the body, a
// keyed frame ALWAYS has room for its HMAC — a heartbeat is never silently
// downgraded to unsigned (the #4107 invariant; see MarshalHeartbeatAuth).
func marshalHeartbeatBody(pkt *HeartbeatPacket, tailReserve int) []byte {
	buf := make([]byte, maxHeartbeatSize)
	copy(buf[0:4], heartbeatMagic)
	buf[4] = heartbeatVersion
	buf[5] = pkt.NodeID
	binary.LittleEndian.PutUint16(buf[6:8], pkt.ClusterID)
	// #4434: bound the group section to the heartbeat wire limit. The count
	// byte and each per-group id byte are uint8 and the frame is a fixed
	// buffer, so an over-size redundancy-group set would overflow the count
	// (256 -> 0, desyncing it from the records actually written) or index
	// past the buffer and panic. The commit gate rejects such a config; this
	// defensive cap keeps a leniently-loaded / peer-synced config panic-safe
	// and the count byte consistent with the body.
	groups := pkt.Groups
	if len(groups) > maxHeartbeatGroups {
		oversizeHeartbeatGroupsWarn.Do(func() {
			slog.Warn("cluster: redundancy-group count exceeds heartbeat wire "+
				"limit; advertising only the first groups",
				"groups", len(pkt.Groups), "wire_limit", maxHeartbeatGroups)
		})
		groups = groups[:maxHeartbeatGroups]
	}
	buf[8] = uint8(len(groups))

	off := heartbeatHeaderSize
	for _, g := range groups {
		buf[off] = g.GroupID
		binary.LittleEndian.PutUint16(buf[off+1:off+3], g.Priority)
		buf[off+3] = g.Weight
		buf[off+4] = g.State
		off += heartbeatGroupSize
	}

	var version []byte
	const heartbeatVersionTrailerSize = 1 + 2 // version length byte + HA protocol version
	echoTrailerSize := 0
	if normalizeHAProtocolVersion(pkt.HAProtocolVersion) >= heartbeatEchoProtocolVersion &&
		pkt.HeartbeatSession != 0 && pkt.HeartbeatSequence != 0 {
		echoTrailerSize = heartbeatEchoTrailerSize
	}
	versionReserve := heartbeatVersionTrailerSize + echoTrailerSize
	if pkt.SoftwareVersion != "" {
		version = []byte(pkt.SoftwareVersion)
		if len(version) > maxHeartbeatSoftwareVersionSize {
			version = version[:maxHeartbeatSoftwareVersionSize]
		}
		if off+heartbeatVersionTrailerSize+len(version)+echoTrailerSize <= maxHeartbeatSize-tailReserve {
			versionReserve = heartbeatVersionTrailerSize + len(version) + echoTrailerSize
		} else {
			version = nil
		}
	}

	// Append monitor section, fitting as many monitors as possible.
	monCountOff := off // remember offset of NumMonitors byte
	buf[off] = 0       // NumMonitors — updated below
	off++
	numMon := 0
	for _, mon := range pkt.Monitors {
		// #14704: a name that cannot fit the uint8 NameLen byte must be
		// skipped whole, never written with a wrapped length — the payload
		// bytes would be parsed as the following monitors / version trailer.
		// Skip rather than break so one oversize entry (e.g. from a
		// peer-synced config) does not starve the monitors after it.
		if len(mon.Interface) > maxHeartbeatMonitorNameSize {
			continue
		}
		// #14704: the uint8 NumMonitors byte caps the section at 255;
		// writing a 256th entry would wrap the count (256 -> 0) and desync
		// it from the records actually written.
		if numMon >= maxHeartbeatMonitors {
			break
		}
		nameBytes := []byte(mon.Interface)
		entrySize := 4 + len(nameBytes) // RGID + Flags + Weight + NameLen + name
		if off+entrySize > maxHeartbeatSize-versionReserve-tailReserve {
			break
		}
		buf[off] = mon.RGID
		flags := uint8(0)
		if mon.Up {
			flags |= 1
		}
		buf[off+1] = flags
		buf[off+2] = mon.Weight
		buf[off+3] = uint8(len(nameBytes))
		off += 4
		copy(buf[off:off+len(nameBytes)], nameBytes)
		off += len(nameBytes)
		numMon++
	}
	heartbeatMonitorTruncations.observe(len(pkt.Monitors), numMon)
	buf[monCountOff] = uint8(numMon)
	if off+versionReserve+tailReserve <= maxHeartbeatSize {
		buf[off] = uint8(len(version))
		off++
		if len(version) > 0 {
			copy(buf[off:off+len(version)], version)
			off += len(version)
		}
		binary.LittleEndian.PutUint16(buf[off:off+2], normalizeHAProtocolVersion(pkt.HAProtocolVersion))
		off += 2
		if echoTrailerSize != 0 {
			copy(buf[off:off+len(heartbeatEchoMagic)], heartbeatEchoMagic)
			off += len(heartbeatEchoMagic)
			binary.LittleEndian.PutUint64(buf[off:off+8], pkt.HeartbeatSession)
			off += 8
			binary.LittleEndian.PutUint64(buf[off:off+8], pkt.HeartbeatSequence)
			off += 8
			binary.LittleEndian.PutUint64(buf[off:off+8], pkt.PeerHeartbeatSession)
			off += 8
			binary.LittleEndian.PutUint64(buf[off:off+8], pkt.PeerHeartbeatSequence)
			off += 8
		}
	}
	return buf[:off]
}

// UnmarshalHeartbeat decodes a heartbeat packet from wire format.
func UnmarshalHeartbeat(data []byte) (*HeartbeatPacket, error) {
	if len(data) < heartbeatHeaderSize {
		return nil, fmt.Errorf("heartbeat too short: %d bytes", len(data))
	}
	if string(data[0:4]) != heartbeatMagic {
		return nil, fmt.Errorf("invalid heartbeat magic: %q", string(data[0:4]))
	}
	if data[4] != heartbeatVersion {
		return nil, fmt.Errorf("unsupported heartbeat version: %d", data[4])
	}

	pkt := &HeartbeatPacket{
		NodeID:            data[5],
		ClusterID:         binary.LittleEndian.Uint16(data[6:8]),
		HAProtocolVersion: LegacyHAProtocolVersion,
	}

	numGroups := int(data[8])
	need := heartbeatHeaderSize + numGroups*heartbeatGroupSize
	if len(data) < need {
		return nil, fmt.Errorf("heartbeat truncated: have %d, need %d", len(data), need)
	}

	pkt.Groups = make([]HeartbeatGroup, numGroups)
	off := heartbeatHeaderSize
	for i := 0; i < numGroups; i++ {
		pkt.Groups[i] = HeartbeatGroup{
			GroupID:  data[off],
			Priority: binary.LittleEndian.Uint16(data[off+1 : off+3]),
			Weight:   data[off+3],
			State:    data[off+4],
		}
		off += heartbeatGroupSize
	}

	// Parse monitor section if present (backwards compatible — old packets
	// without monitors just have no remaining data). If the monitor section
	// is truncated (sender capped at maxHeartbeatSize), return whatever
	// monitors were successfully parsed rather than erroring — RG state
	// (already parsed above) is the critical data.
	monitorSectionComplete := true
	if off < len(data) {
		numMonitors := int(data[off])
		off++
		for i := 0; i < numMonitors; i++ {
			if off+4 > len(data) {
				monitorSectionComplete = false
				break // truncated — return what we have
			}
			rgID := data[off]
			up := data[off+1]&1 != 0
			weight := data[off+2]
			nameLen := int(data[off+3])
			off += 4
			if off+nameLen > len(data) {
				monitorSectionComplete = false
				break // truncated name — return what we have
			}
			name := string(data[off : off+nameLen])
			off += nameLen
			pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
				RGID:      rgID,
				Weight:    weight,
				Up:        up,
				Interface: name,
			})
		}
	}
	versionSectionComplete := false
	if monitorSectionComplete && off < len(data) {
		versionLen := int(data[off])
		off++
		if off+versionLen <= len(data) {
			pkt.SoftwareVersion = string(data[off : off+versionLen])
			off += versionLen
			versionSectionComplete = true
		} else {
			return pkt, nil
		}
	}
	if monitorSectionComplete && versionSectionComplete && off+2 <= len(data) {
		pkt.HAProtocolVersion = normalizeHAProtocolVersion(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2
		if pkt.HAProtocolVersion >= heartbeatEchoProtocolVersion &&
			off+heartbeatEchoTrailerSize <= len(data) &&
			string(data[off:off+len(heartbeatEchoMagic)]) == heartbeatEchoMagic {
			off += len(heartbeatEchoMagic)
			pkt.HeartbeatSession = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
			pkt.HeartbeatSequence = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
			pkt.PeerHeartbeatSession = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
			pkt.PeerHeartbeatSequence = binary.LittleEndian.Uint64(data[off : off+8])
		}
	}

	return pkt, nil
}

// --- #4107 control-channel authentication (heartbeat/election) -------------
//
// The cluster heartbeat drives election: handlePeerHeartbeat rebuilds peer RG
// state directly from the packet and runs runElection(), so a forged cleartext
// heartbeat can force the local node PRIMARY or demote the peer. When a shared
// PSK (chassis cluster authentication-key) is configured, the sender appends an
// HMAC-SHA256 trailer over the whole frame plus an anti-replay nonce, and the
// receiver rejects a heartbeat that fails (or, once both nodes are keyed, lacks)
// authentication BEFORE it can refresh peer liveness or drive election.
//
// Dual-accept (rolling upgrade): a node without a key emits and accepts legacy
// frames; a keyed node accepts an unauthenticated frame until it has observed
// the peer authenticate (proving both nodes hold the key), after which an
// unauthenticated frame is a downgrade attack and is rejected. This mirrors the
// #4126 VRRP-checksum dual-accept migration: accept both wire forms during the
// upgrade window, enforce once both sides speak the new form.

// MarshalHeartbeatAuth encodes a heartbeat and, when authKey is non-empty,
// appends the PSK/HMAC auth trailer so the receiver can reject a forged or
// tampered heartbeat. session is a per-sender-process random value and counter
// is a per-session monotonic send counter; together they are the anti-replay
// nonce (a new session re-anchors the receiver after a restart/reboot; a
// strictly increasing counter rejects intra-session replays). When authKey is
// empty the output is byte-identical to MarshalHeartbeat — it omits the auth
// trailer. The key is never logged.
//
// INVARIANT: once a key is configured, the returned frame is ALWAYS signed. The
// trailer space is reserved WHILE building the body (marshalHeartbeatBody drops
// best-effort monitor entries to make room), so a heartbeat is never silently
// downgraded to unsigned — a silent downgrade would make an ENFORCING peer
// reject every frame and split the cluster (dual-primary). At realistic RG +
// monitor counts the reserve never even bites; the belt-and-suspenders guard
// below is unreachable and fails LOUD rather than emitting cleartext.
func MarshalHeartbeatAuth(pkt *HeartbeatPacket, authKey []byte, session, counter uint64) []byte {
	return marshalHeartbeatAuthEpoch(pkt, authKey, session, counter, 0)
}

// marshalHeartbeatAuthEpoch is MarshalHeartbeatAuth plus the optional #6169
// boot-epoch section. A non-zero epoch inserts
//
//	[ marker(8) = HMAC(key, bootEpochLabel)[:8] ][ epoch(8, little-endian) ]
//
// BETWEEN the body and the auth trailer. epoch == 0 emits a byte-identical
// legacy frame — the MarshalHeartbeatAuth path, i.e. a caller that has no epoch
// to advertise at all.
//
// A KEYED PRODUCTION SENDER NEVER REACHES THAT PATH, and the distinction is
// load-bearing for the receiver's downgrade latch: Manager.heartbeatBootEpoch
// publishes a non-zero wall-clock value SYNCHRONOUSLY, before any file is
// touched, so a persistence failure degrades MONOTONICITY, never EMISSION. That
// is what makes "a keyed heartbeat carries no epoch <=> the peer runs a
// pre-#6169 build" true, and a storage fault therefore cannot make a latched
// peer see a healthy node as epoch-less (and so dead).
//
// The section placement is what makes this a NON-BREAKING wire change, and it
// is not interchangeable with appending after the trailer (which is what failed
// review in #6370 — a v1 receiver looking for "XPFA" at len-52 found body bytes,
// read the frame as unsigned, and an enforcing v1 peer rejected every frame,
// splitting a keyed cluster mid-upgrade). With the section BEFORE the trailer:
//
//   - the 52-byte auth trailer stays at the fixed tail, so heartbeatAuthTrailer
//     still locates it at len-52 on a v1 receiver;
//   - the signed span is still everything but the trailing digest, so a v1
//     receiver's verifyHeartbeatMAC recomputes over exactly the bytes a v2
//     sender signed and the HMAC verifies — the epoch is INSIDE the signed
//     region and therefore unforgeable; and
//   - UnmarshalHeartbeat stops after the version section and ignores the rest,
//     so a v1 receiver simply never sees the epoch.
//
// Bidirectional compatibility with no HAProtocolVersion bump.
func marshalHeartbeatAuthEpoch(pkt *HeartbeatPacket, authKey []byte, session, counter, epoch uint64) []byte {
	if len(authKey) == 0 {
		return marshalHeartbeatBody(pkt, 0)
	}
	epochSection := 0
	if epoch != 0 {
		epochSection = heartbeatEpochSectionSize
	}
	// Reserve the epoch section AND the trailer up front so the signed frame is
	// guaranteed to fit. Reserving only the trailer would let a maximal frame
	// reach maxHeartbeatSize+16 bytes, which the receiver's maxHeartbeatSize
	// read buffer silently TRUNCATES — destroying the HMAC and making an
	// enforcing peer reject every frame.
	tailReserve := epochSection + heartbeatAuthTrailerSize
	body := marshalHeartbeatBody(pkt, tailReserve)
	if len(body)+tailReserve > maxHeartbeatSize {
		// Unreachable: the RG group count is uint8-bounded and monitors were
		// already truncated to leave the reserve. Guard so a future change can
		// never SILENTLY downgrade a keyed heartbeat to unsigned (which an
		// enforcing peer rejects → split-brain). Fail loud and still sign
		// rather than emit an unsigned frame.
		slog.Error("cluster: keyed heartbeat exceeds frame cap after monitor truncation; signing anyway to preserve the auth invariant",
			"body_bytes", len(body), "cap", maxHeartbeatSize)
	}
	trailer := make([]byte, heartbeatAuthTrailerSize)
	copy(trailer[0:4], heartbeatAuthMagic)
	binary.LittleEndian.PutUint64(trailer[4:12], session)
	binary.LittleEndian.PutUint64(trailer[12:20], counter)

	out := make([]byte, 0, len(body)+tailReserve)
	out = append(out, body...)
	if epochSection > 0 {
		out = append(out, heartbeatEpochMarker(authKey)...)
		out = binary.LittleEndian.AppendUint64(out, epoch)
	}
	// Sign the body PLUS the epoch section PLUS magic+session+counter
	// (everything but the digest), so the epoch, the nonce and the whole packet
	// are all bound by the MAC.
	mac := hmac.New(sha256.New, authKey)
	mac.Write(out)
	mac.Write(trailer[:20])
	copy(trailer[20:], mac.Sum(nil))

	return append(out, trailer...)
}

// heartbeatAuthTrailer locates the auth trailer at the tail of a raw heartbeat
// frame and returns its nonce. present is false when the frame carries no
// trailer (a legacy / not-yet-keyed peer).
func heartbeatAuthTrailer(data []byte) (session, counter uint64, present bool) {
	if len(data) < heartbeatAuthTrailerSize {
		return 0, 0, false
	}
	start := len(data) - heartbeatAuthTrailerSize
	if !bytes.Equal(data[start:start+4], []byte(heartbeatAuthMagic)) {
		return 0, 0, false
	}
	session = binary.LittleEndian.Uint64(data[start+4 : start+12])
	counter = binary.LittleEndian.Uint64(data[start+12 : start+20])
	return session, counter, true
}

// verifyHeartbeatMAC recomputes the HMAC over the signed span (everything but
// the trailing 32-byte digest) and compares it in constant time. It presumes a
// trailer is present (heartbeatAuthTrailer returned present) and authKey is
// non-empty; it returns false otherwise.
func verifyHeartbeatMAC(data, authKey []byte) bool {
	if len(authKey) == 0 || len(data) < heartbeatAuthTrailerSize {
		return false
	}
	signed := data[:len(data)-heartbeatAuthMACSize]
	got := data[len(data)-heartbeatAuthMACSize:]
	mac := hmac.New(sha256.New, authKey)
	mac.Write(signed)
	return hmac.Equal(got, mac.Sum(nil))
}
