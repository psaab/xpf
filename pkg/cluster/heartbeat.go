package cluster

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// HeartbeatPort is the UDP port used for cluster heartbeat.
	HeartbeatPort = 4784

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

	// maxHeartbeatSize is the max packet size we'll read/write.
	// 1472 = 1500 MTU - 20 IP header - 8 UDP header.
	maxHeartbeatSize = 1472

	// DefaultHeartbeatInterval is the default heartbeat send interval.
	DefaultHeartbeatInterval = 100 * time.Millisecond

	// DefaultHeartbeatThreshold is the default missed heartbeat count before peer is lost.
	DefaultHeartbeatThreshold = 5

	// heartbeatStartupGrace is the cold-boot config-apply grace window. For
	// this long after a receiver starts, the local config apply phase (VRF
	// binding, FRR reload, fabric creation, RETH MAC down/up) can disrupt the
	// control-link UDP receive path for 10-15+ seconds. BOTH peer-liveness
	// decisions hold behind this floor so a simultaneous cold boot cannot
	// split-brain:
	//   - seen-then-lost: suppress peer-lost entirely — a recovering node must
	//     not declare a live peer dead on the first dropped heartbeat.
	//   - never-seen-at-boot: suppress single-node promotion (#4386). Deciding
	//     a peer NEVER EXISTED is different from a peer that WAS seen then went
	//     silent: on a simultaneous boot the first heartbeats from a live peer
	//     are dropped and lastSeen stays 0 on BOTH nodes, so promoting at
	//     threshold*interval (~500ms) makes BOTH claim the RETH virtual MAC.
	//     The floor lets a slow-to-appear peer be heard first while a
	//     genuinely-absent peer (single-node deployment) still promotes once it
	//     elapses.
	heartbeatStartupGrace = 30 * time.Second

	// heartbeatRestartGrace bounds the seen-then-lost suppression of a receiver
	// that REPLACED one which had already seen the peer (RestartHeartbeat,
	// #9722). Such a restart happens on a node that is already up: every config
	// apply that rebinds the management VRF rebuilds the heartbeat sockets.
	// Arming the 30s cold-boot grace there meant a peer that died within 30s
	// after a commit was declared lost up to 30s late. The restart's own
	// disruption is the socket rebind, which RestartHeartbeat already retries
	// for up to 5s, so the grace matches that window. A live peer whose
	// heartbeats are briefly lost past it is still covered by the sync-recency
	// guard handlePeerTimeout consults (the daemon's
	// shouldSuppressPeerHeartbeatTimeout, #1792). The never-seen arm keeps the
	// cold-boot floor: a replacement for a receiver that never saw the peer is
	// not armed, so it IS a cold start.
	heartbeatRestartGrace = 5 * time.Second

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
//
// The trailing version trailer is optional; packets may end after the monitor
// section. When present, the trailer always starts with a length byte, even if
// the software version string is empty, so newer readers can unambiguously find
// the HA protocol version. Older readers ignore any bytes after the optional
// software-version field, and newer readers treat a missing trailer as the
// legacy protocol version.
type HeartbeatPacket struct {
	NodeID            uint8
	ClusterID         uint16
	Groups            []HeartbeatGroup
	Monitors          []HeartbeatMonitor
	SoftwareVersion   string
	HAProtocolVersion uint16
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
// bytes free at the tail of the frame for a trailer the caller appends (the
// #4107 auth trailer). tailReserve==0 is the plain legacy encoding, byte-for-
// byte what MarshalHeartbeat always produced. The election-critical header +
// RG groups are always written and the SOFTWARE version is reserved next; only
// the best-effort monitor section is truncated to fit within
// maxHeartbeatSize-tailReserve. Because the reserve is honored WHILE building
// the body, a keyed frame ALWAYS has room for its HMAC — a heartbeat is never
// silently downgraded to unsigned (the #4107 invariant; see
// MarshalHeartbeatAuth).
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
	versionReserve := heartbeatVersionTrailerSize
	if pkt.SoftwareVersion != "" {
		version = []byte(pkt.SoftwareVersion)
		if len(version) > maxHeartbeatSoftwareVersionSize {
			version = version[:maxHeartbeatSoftwareVersionSize]
		}
		if off+heartbeatVersionTrailerSize+len(version) <= maxHeartbeatSize-tailReserve {
			versionReserve = heartbeatVersionTrailerSize + len(version)
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
// empty the output is byte-identical to MarshalHeartbeat — a node without a key
// emits legacy frames (dual-accept). The key is never logged.
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

// heartbeatReplaySessions bounds how many distinct sender sessions the
// anti-replay tracker remembers a counter watermark for. Each genuine peer
// reboot picks a fresh random session (randomSessionID) and consumes one slot;
// the oldest watermark is evicted FIFO once the ring is full.
//
// #5477 security bound — and its honest limit. The retired-session watermarks
// must be bounded (a peer that reboots forever cannot grow the ring without
// limit). This map RAISES the on-link REPLAY attacker's cost — from the
// pre-#5477 single-watermark A->B->A loop (only 2 recorded incarnations) to
// heartbeatReplaySessions+1 distinct recorded incarnations — but it is NOT an
// absolute bar:
//
//   - HMAC-SHA256 over the nonce blocks fabricating a valid frame for any NEW
//     session id, and blocks fabricating a counter beyond the highest the
//     genuine peer ever signed for a session. So the attacker can only REPLAY
//     the session incarnations they captured off the wire.
//   - With FEWER than heartbeatReplaySessions+1 recorded incarnations, every
//     replay of a retired session is at/below its remembered watermark and is
//     rejected — the sustained A->B->A loop #5477 targets is fully closed.
//   - With heartbeatReplaySessions+1 OR MORE recorded incarnations the bound is
//     defeatable by REPLAY ALONE (no reboot, no minting): a replayed frame
//     whose session is not currently in the ring is "never-seen" from the
//     ring's view, so admit() re-records it and evicts the oldest FIFO entry.
//     FIFO always leaves exactly one just-evicted session to replay back in as
//     never-seen, so an attacker holding >= heartbeatReplaySessions+1
//     incarnations can churn the ring and SUSTAIN the replay indefinitely.
//     (Confirmed empirically: M == heartbeatReplaySessions recordings -> all
//     replays rejected; M == heartbeatReplaySessions+1 -> sustained admits.)
//
// This receiver-only map cannot close that residual by itself — it needs an
// order over peer incarnations, which random session ids cannot provide. That
// order SHIPPED in #6169 as the signed boot epoch (heartbeat_epoch.go):
// admitAuthed consults the epoch floor BEFORE this ring, so a frame the
// floor REJECTS never reaches admit() and therefore cannot churn it. That is an
// ORDERING property, not a claim that every retired incarnation is rejected —
// see the #6711 paragraph below, where the opposite happens.
//
// It is a TOTAL order only while the sender's clock advances monotonically
// across incarnations. A backward step larger than bootEpochMaxSkew sorts a
// later incarnation below an earlier one — the #6711 residual.
//
// THAT DIRECTION DOES NOT FAIL CLOSED. An earlier revision of this comment said
// it did ("a genuine peer is refused, never a retired one admitted"), and that
// is false in both halves. Once the sender regresses, the highest epoch on the
// wire belongs to a RETIRED incarnation, so an archived frame from it is at or
// above the floor and is ADMITTED — raising the floor, refreshing peer liveness
// and applying its stale election state — while the genuine current incarnation
// sits below and is refused. Measured in
// TestArchivedEpochPoisonsAFreshFloor_6711. So the cost is availability AND one
// admitted retired incarnation, not availability alone.
//
// What survives is narrower and is what the paragraph above actually needs:
// SUSTAINED churn still requires heartbeatReplaySessions+1 captured sessions the
// floor ADMITS, and the floor admits at most heartbeatEpochSessionsPerEpoch of
// them PER EPOCH VALUE — a constant far below the ring's 64 slots. So
// epoch-BEARING captures buy a finite ascending pass rather than an indefinite
// one — measured on 65 captured epoch-bearing incarnations against a fresh
// receiver: 325/325 admitted on the ascending pass, then 0/1625 across five
// further rounds. It is the epoch-LESS captures that stay indefinitely
// churnable, which is what the downgrade latch exists for.
//
// THE PER-VALUE BOUND IS NOT A COROLLARY OF "ONE SESSION PER INCARNATION", and
// an earlier revision of this comment derived it as one. The derivation was: one
// incarnation emits exactly one session (#6169 Stage 0), so distinct sessions
// are distinct incarnations, so their epochs differ and all but the newest are
// below the floor. The last step is the false one — nothing stops two
// incarnations publishing the SAME epoch, and `epoch == highEpoch` fell through
// to the ring for every session, so 65 captures sharing one valid epoch churned
// it exactly as epochless frames do (measured 1625/1625). Reachable whenever the
// sender's epoch does not move between incarnations, which takes neither a dead
// clock nor a dead store: refineBootEpoch chains to prev+1, a pure function of
// the state FILE, so a store that reads but cannot WRITE republishes one value
// across every incarnation on a healthy advancing clock. (bootEpochSeed also
// returns the literal 1 under a clock at or before the Unix epoch, which is the
// degenerate case where nothing orders anything.) The floor therefore binds a
// BOUNDED SET of sessions per value — see the highEpochSessions field for why
// the bound is neither one nor unbounded.
//
// The ring is retained and still owns within-incarnation replay. It does NOT
// cause a genuine-peer lockout (an evicted live-peer watermark just makes the
// peer's next frame never-seen -> admitted) and cannot grow memory (fixed
// 64-slot array).
//
// 64 slots (64*16 = 1 KiB) bounds memory while forcing an attacker to have
// captured 65+ distinct peer SESSIONS before any replay is sustainable.
//
// THE UNIT IS A DAEMON INCARNATION, and only since #6169 Stage 0. A session id
// used to be minted per heartbeatSender, so every peer heartbeat RESTART — a
// DHCP-triggered VRF rebind, an HA comms restart — minted a new one with no
// reboot involved: routine peer restarts permanently consumed slots (the ring
// reached eviction pressure from legitimate traffic alone), and the attacker's
// capture cost for the churn above was 65 sessions, cheaper to harvest than 65
// daemon boots. Worse, those extra sessions all shared ONE boot epoch, which
// the floor cannot separate — so the ring stayed churnable WITHIN an
// incarnation, under the epoch gate.
//
// Manager.heartbeatNonce now draws the session once per Manager
// (hbNonceOnce) and only advances the counter, so a restart no longer
// re-anchors. See TestHeartbeatNonceIsIncarnationScoped_6169.
const heartbeatReplaySessions = 64

// heartbeatEpochSessionsPerEpoch is how many DISTINCT peer sessions may be
// admitted at one boot-epoch VALUE (heartbeatAuthState.highEpochSessions).
//
// It is the whole knob in the equal-epoch trade-off, and both ends of its range
// are wrong for reasons that have been measured, not argued:
//
//   - 1 (round 10 of #6669 shipped this) refuses every successor incarnation
//     that publishes its predecessor's epoch, and that is REACHABLE on a
//     healthy, advancing clock: refineBootEpoch chains to exactly prev+1, which
//     is a pure function of the file, so a store that reads but cannot WRITE
//     hands every successive incarnation the identical value — PROVIDED the file
//     sits at or above the wall-clock seed, since the chain engages only on
//     `prev+1 > epoch`. An unwritable store holding a value BEHIND `now` gives
//     each incarnation its own higher seed and no collision at all; the reachable
//     shape is the unwritable store plus an RTC that ran fast and was corrected
//     back, which is what epochUnwritableStore builds. Measured through
//     initHeartbeatEpochState over such a directory: 0/40 heartbeats from the
//     second incarnation admitted, which declares a healthy node dead in 1s at
//     the shipped 200ms interval and threshold 5.
//   - unbounded (pre-round-10) is the #6169 replay hole itself: 65 captured
//     incarnations sharing one epoch churned the ring 1625/1625.
//
// A bound that satisfies the k <= heartbeatReplaySessions invariant below keeps
// the security property, because the floor is monotone: at most this many
// sessions are ever admitted at a given value, so an attacker's capture set buys
// a finite ascending pass and NOTHING sustained. The bound must not be refilled
// by anything an attacker can produce — in particular not by the bound session
// going quiet, which is free (wait out the dead-peer interval between captures)
// and restores unbounded admissions.
//
// "ANY FINITE k" IS FALSE, and an earlier revision of this comment asserted it
// twice. Finiteness is not the property; the invariant is. At k = 65 against a
// 64-slot ring the sessions admissible at ONE value overflow the ring by
// themselves: the 65th mark evicts the 1st, whose session is STILL BOUND, so
// replaying it clears the epoch gate, reads as never-seen to the ring, and is
// admitted — evicting the 2nd, and so on around. That is sustained churn at a
// single epoch value, which is the #6169 hole this bound exists to close,
// reintroduced by a bound that is perfectly finite.
//
// 2 admits a legitimate successor at an unchanged epoch ONLY when nothing else
// has spent a slot, and it is far below heartbeatReplaySessions so the sessions
// bound at one value can never evict each other from the ring.
//
// AN ATTACKER SPENDS SLOTS AS CHEAPLY AS THE PEER DOES, and an earlier revision
// of this comment claimed 2 was "the smallest value that admits a legitimate
// successor" without that qualifier. In the equal-epoch regime EVERY prior
// incarnation's frames carry the current floor value under a distinct session,
// so an on-link recorder holds them for free: one replayed archived frame fills
// the second slot, and the first genuine successor is then refused. Measured —
// A1 admitted (slots {A1}), one archived frame from an earlier incarnation at
// the same epoch admitted (slots FULL), A1 exits, successor A2 REFUSED with
// EpochSessionCollision=1.
//
// So the headroom is AT MOST k-1 restarts and can be none. An earlier revision
// of this comment wrote it as exactly "k-1-j restarts, where j is the number of
// distinct captured sessions an attacker can present", and that arithmetic
// over-counts what a capture set consumes: presenting a session is not the same
// as spending a slot. admitAuthed binds only AFTER s.replay.admit
// succeeds, so a replay the ring refuses — a session already at or above its
// remembered watermark, which is every re-presentation of one already used —
// costs the attacker a frame and the budget nothing
// (TestEqualEpochSuccessorIsAdmitted_6669/a_ring_refused_frame_does_not_spend_
// a_slot). The subtraction also has no meaning once j reaches k. What is true
// is the direction: one archived frame from a distinct earlier session at the
// live epoch value is free in exactly the regime that produces equal epochs, so
// against a no-attacker fault the bound buys one restart and against an on-link
// replay attacker it can buy none. Raising k does not fix that — k-1 slots are
// as cheap to spend as one — which is why this is stated rather than tuned.
//
// THE INVARIANT THE CONSTANT IS CHOSEN AGAINST is k <= heartbeatReplaySessions,
// and it is what keeps the two bounds from interfering: the sessions admissible
// at one epoch value must never be numerous enough to evict each other from the
// ring, which would let a bound session's own watermark be forgotten and
// re-admitted. 2 against 64 satisfies it with room to spare. The lower end is
// an availability floor, not a security one — k >= 2 is what admits a
// legitimate successor at an unchanged epoch when nothing else has spent a slot.
//
// The SECURITY property is unaffected by the choice WITHIN that invariant: for
// any k <= heartbeatReplaySessions the floor stays monotone and the budget stays
// finite and non-refilling. It is NOT a consequence of finiteness alone — see
// the k = 65 counterexample above, where a finite bound larger than the ring
// restores exactly the sustained churn this constant closes.
// See heartbeatAuthState.highEpochSessions for the rest of the cost.
const heartbeatEpochSessionsPerEpoch = 2

// heartbeatAuthState is the per-PEER control-channel authentication state:
// the anti-replay watermarks and the sticky "peer has authenticated" flag.
//
// #5086: this state lives on the Manager (process lifetime), NOT on the
// heartbeatReceiver (heartbeat lifetime). Every StartHeartbeat builds a brand
// new heartbeatReceiver, and StartHeartbeat runs on far more than a daemon
// boot — RestartHeartbeat on a DHCP-triggered VRF rebind
// (daemon_apply_dataplane.go), and the HA comms (re)start
// (daemon_ha_sync.go). While the tracker was a receiver field, each of those
// routine events discarded every retired-session watermark, so the #5477
// A->B->A rollback re-opened in full: an attacker holding captured
// authenticated frames from retired peer incarnations replays them into the
// empty tracker and each one is "never-seen" -> admitted, refreshing peer
// liveness and applying stale election state for the whole captured run. A
// heartbeat restart is exactly the moment the local node is least able to
// afford a peer it wrongly believes is alive.
//
// Anchoring the state to the Manager makes the retired-session memory span the
// process instead of the socket. The bound is unchanged and does not grow with
// restart count, uptime, or the number of peer incarnations observed: one
// fixed heartbeatAuthReplay ring (heartbeatReplaySessions * 16 B = 1 KiB) plus
// a mutex and an atomic, allocated once per Manager.
//
// The mutex is required now that the ring outlives a single readLoop: the
// StartHeartbeat stop-then-start sequence joins the previous readLoop before
// the next one runs, but the tracker is no longer confined to one goroutine's
// lifetime and must not depend on that ordering to stay race-free.
type heartbeatAuthState struct {
	mu     sync.Mutex
	replay heartbeatAuthReplay

	// rejectWarn bounds the per-frame rejection warning (#6669 r18, finding 8).
	// Its own mutex, so it is not serialized behind the admission path.
	rejectWarn heartbeatRejectWarnLimiter

	// highEpoch is the #6169 across-reboot floor: the highest boot epoch ever
	// accepted from the peer. It is O(1) state (one uint64) that gives the
	// receiver an ORDER over peer incarnations, which the session ring cannot
	// provide — session ids are random and unordered, so the ring can only
	// remember a bounded set of them and is churnable by replay once the
	// attacker holds more captured sessions than it has slots.
	//
	// It is a total order over the VALUES, but it tracks incarnation RECENCY
	// only while the sender is monotonic. A backward clock step larger than
	// bootEpochMaxSkew regresses the sender's epoch (#6711), and from then on a
	// captured OLDER frame carries the HIGHER value — so the floor can be raised
	// above the live peer and lock it out. Do not read "total order" as a safety
	// property; see TestArchivedEpochPoisonsAFreshFloor_6711.
	//
	// Anchored here (Manager lifetime, #5086/#6642) rather than on the
	// heartbeatReceiver on purpose: a receiver-scoped floor is zeroed by every
	// StartHeartbeat — including RestartHeartbeat on a routine DHCP-triggered
	// VRF rebind and the HA comms restart — and a zero floor re-admits and
	// re-latches a replayed retired epoch, defeating the gate entirely.
	//
	// 0 means "no epoch accepted yet" and is also the sender's "advertise no
	// epoch" sentinel, so it can never be a real floor.
	highEpoch uint64

	// highEpochSessions are the peer SESSION ids admitted at exactly highEpoch,
	// and highEpochSessionCount is how many slots are in use. BOUNDING that set
	// is what makes the floor bound the ring rather than merely order it. Both
	// are reset by a raise, so they describe the CURRENT floor value only, and
	// both are meaningless while highEpoch is 0.
	//
	// The floor's whole security value is the step "sustained ring churn needs
	// heartbeatReplaySessions+1 sessions the floor admits, and one incarnation
	// emits exactly one session (Manager.heartbeatNonce, #6169 Stage 0)". That
	// step needs DISTINCT SESSIONS TO IMPLY DISTINCT EPOCHS, and the comparison
	// against highEpoch alone does not give it: `epoch == highEpoch` fell
	// through to the ring for every session, so any number of them sharing ONE
	// valid epoch were admitted at the floor and churned the ring exactly as
	// epochless frames do. Measured before this bound existed: 65 captured
	// incarnations sharing one epoch -> 325/325 admitted on the first pass and
	// 1625/1625 across five further rounds, against 0/1625 for the same 65 with
	// strictly increasing epochs.
	//
	// So a frame at exactly highEpoch is admitted only from a session already
	// bound here, or from a new one while a slot is free; any other is refused
	// BEFORE the ring (the same ordering the floor itself needs — see
	// admitAuthed) and counted as epochSessionCollision. A raise rebinds to the
	// raising session alone.
	//
	// WHY THE SET IS NOT A SINGLETON — this is the part round 10 got wrong, and
	// its cost was larger than the hole it closed. Equal epochs across
	// incarnations were said to need "a dead clock AND a dead store", the regime
	// in which the sender publishes no order at all. That is false. The reachable
	// regime needs neither:
	//
	//   - the state file holds a value AHEAD of now but inside bootEpochMaxSkew
	//     — an RTC that ran fast and was corrected back by NTP. Beyond an hour
	//     refineBootEpoch declines to chain; inside it, chaining is mandatory,
	//     and it is the case persistence exists for;
	//   - the store READS but cannot WRITE (ENOSPC/EDQUOT/EACCES on /var — an
	//     ordinary appliance fault, and one that tends to CAUSE restarts). The
	//     .lock already exists so withEpochFileLock takes it and os.ReadFile
	//     succeeds; only WriteFileDurable's temp file fails;
	//   - a restart inside that window.
	//
	// refineBootEpoch then chains with `if next := prev + 1; next > epoch`,
	// which is a pure function of the FILE. With the persist half unable to
	// advance it, every successive incarnation reads the same prev and publishes
	// exactly prev+1 — on a healthy advancing clock, with visibly different
	// seeds and sessions. REFINEMENT, which the round-10 text offered as the
	// escape ("one successful pass, which persists prev+1"), is the equal-epoch
	// GENERATOR whenever persist fails. Measured through the production entry
	// point (Manager.initHeartbeatEpochState) over a write-failing directory,
	// two Managers, real signed frames through the real readLoop gate: identical
	// epochs, and 0/40 heartbeats from the second incarnation admitted at a
	// singleton bound, against 40/40 with no bound at all. That refusal returns
	// false here, so readLoop continues BEFORE r.lastSeen.Store — the peer
	// declares a healthy node dead in 1s at the shipped 200ms interval and
	// threshold 5 and takes over its RGs while it still holds them.
	//
	// WHAT IT STILL COSTS, stated as the bound actually is. A successor beyond
	// the heartbeatEpochSessionsPerEpoch-th at one unchanged epoch value IS
	// refused, and refused for its whole process lifetime: bootEpoch is set once
	// under bootEpochOnce, and re-refinement lands on the same prev+1 every pass
	// (prev+1 > prev+1 is false), so nothing recovers it in-process. Recovery
	// needs the wall clock to climb past prev+1 AND another restart, i.e. up to
	// however far the file leads the clock — at most bootEpochMaxSkew, one hour.
	// So the honest statement is NOT "only under a dead clock and a dead store":
	// it is DURABLE ACROSS EVERY RESTART IN A WINDOW UP TO bootEpochMaxSkew
	// WHENEVER THE PERSIST HALF CANNOT ADVANCE THE FILE, and the bound buys
	// heartbeatEpochSessionsPerEpoch-1 restarts inside it rather than removing
	// it. epochSessionCollision is what makes that regime visible; a
	// non-writable /var is the first thing to check when it climbs.
	//
	// TWO ALTERNATIVES WERE PRICED AND DECLINED.
	//
	// Rebinding when the bound session goes QUIET would cover every successor.
	// It also hands the attack back: waiting out the dead-peer interval between
	// captures is free, so 65 captures sharing one epoch become 65 rebinds and
	// then 65 more, and the finite-admissions property — the only thing the
	// floor buys against a shared epoch — is gone. A budget refilled by silence
	// is refilled by the attacker.
	//
	// Fixing the GENERATOR so it stops emitting equal epochs cannot replace this
	// bound, only narrow it — but not for the reason an earlier revision of this
	// comment gave. It claimed there is "nothing to jitter" when the clock is at
	// or before the Unix epoch and no chainable file exists. That is false:
	// randomSessionID() draws from crypto/rand in that same process, so entropy
	// is available.
	//
	// The sound reason is that a randomised epoch stops being an ORDER, which is
	// the only thing the epoch exists to provide. Jitter can only be added in low
	// bits, and every bit spent on distinctness is a bit of ordering resolution
	// given up; a jittered chain then collides at 2^-j rather than never, so the
	// receiver still needs a bound for the collision it does not prevent.
	//
	// AND NOT BECAUSE THE ATTACKER DECLINES TO JITTER, which is what a further
	// revision of this comment said ("the attacker controls the frames it replays
	// and will not jitter them"). It does not control them in that sense: the
	// epoch sits INSIDE the signed span (marshalHeartbeatAuthEpoch writes it
	// before the trailer and the HMAC covers it), so a replayed frame carries the
	// ORIGINAL sender's value verbatim, jitter included. An attacker chooses
	// WHICH captured frames to present, never what is in them.
	//
	// What actually leaves the receiver needing its own bound is that it cannot
	// depend on a property of the SENDER's generator. The frames it must judge
	// come from whatever build and whatever storage state the peer is in — a
	// pre-jitter build, a partial upgrade, or the same write-failing store that
	// produces equal epochs in the first place — and in every one of those the
	// generator is not jittering. A receiver-side bound is needed in every
	// regime; a sender-side jitter in none of them on its own. It is therefore
	// left out rather than stacked on top, and the residual above is stated
	// instead.
	//
	// A peer session id of 0 is possible (crypto/rand) at ~2^-64 and needs no
	// special case: it binds and compares like any other value, because
	// membership is decided against highEpochSessionCount and never against a
	// zero sentinel.
	highEpochSessions     [heartbeatEpochSessionsPerEpoch]uint64
	highEpochSessionCount int

	// epochSeen is the DOWNGRADE LATCH: an epoch-bearing frame has been accepted
	// from this peer, and admitAuthed refuses an epochless one from now
	// on. Two qualifications, both stated in full elsewhere: an accepted frame
	// is normally proof the peer runs a build that emits epochs, but a REPLAYED
	// archived one arms the latch identically (see the arming site in
	// admitAuthed); and admitAuthed is not the outermost gate, so
	// "armed" is not the same as "epochless frames are being refused right now"
	// (see peerEpochLatched).
	//
	// Without this the epoch closes almost nothing. An attacker's captured
	// incarnations are, by construction, mostly from BEFORE the upgrade and so
	// carry no epoch; if epochless frames are accepted forever the floor is
	// never even consulted. Measured on the first cut of this change: with the
	// floor latched at a live peer's epoch, 975/975 epochless replays were
	// still admitted.
	//
	// DURABILITY — deliberately PROCESS-SCOPED, not on disk.
	//
	// A durable latch would additionally cover "the survivor's daemon restarts
	// while the genuine peer is silent". It was priced and declined — but the
	// pricing has to be done against the design actually on the table, and an
	// earlier revision of this comment did not: it charged a durable LATCH for
	// the costs of a durable FLOOR. Those are different objects.
	//
	// A durable FLOOR persists highEpoch. It turns a deliberate rollback into
	// "delete the right file on the right node and restart" (a procedure run
	// under incident pressure) and makes an in-range-but-wrong epoch — the
	// bounded lockout of README residual 2 — outlive reboots, converting a
	// self-clearing hour into an operator ticket. Those two costs are real and
	// they are why there is no peer-floor file.
	//
	// A durable LATCH need not be a floor. The narrowest form is a PSK-SCOPED
	// BOOLEAN — {key fingerprint, epochSeen} — which persists no epoch at all,
	// so an in-range wrong floor still dies at the next restart, and which
	// resets by construction when the control-link PSK is rotated. Neither
	// floor cost above applies to it. What it does cost:
	//
	//   - A DURABLE WRITE ON THE ACCEPT PATH, with no good failure policy. The
	//     write must land BEFORE the frame is accepted, or a crash in between
	//     leaves the latch clear across the reboot — precisely the state a
	//     replay wants, so the window it was bought to close is still open. And
	//     a write that must complete before an accept puts storage back on the
	//     control-channel receive path, which is the hazard the sender half of
	//     #6169 spent real effort removing (see the HANGING-store case below):
	//     fail-open on a wedged fsync buys nothing over today, fail-closed lets
	//     a disk fault refuse a healthy peer.
	//   - CROSS-PROCESS LOCKING on that path, for the same concurrent-incarnation
	//     reason withEpochFileLock exists. (Not SO_REUSEPORT: that was this
	//     comment's stated reason until #8233 and it was false for the primary
	//     listener. The conclusion is unaffected — overlapping incarnations are
	//     still reachable.)
	//   - It STRICTLY WORSENS the legitimate rollback, which is the common case
	//     and the one with no attacker in it. Today a restart clears the latch
	//     and the downgraded peer is accepted. With the latch durable, a
	//     restart no longer clears it, so every deliberate downgrade requires a
	//     PSK rotation across both nodes — the heavier procedure — even when
	//     nothing is being replayed.
	//
	// WHAT IT BUYS IS NOT "ALREADY BOUGHT BY THE ROTATION". An earlier revision
	// of this comment said it was, and that is false. The mandatory post-upgrade
	// PSK rotation retires every capture made BEFORE it; it cannot retire one
	// made AFTER it under the CURRENT key. Measured sequence: rotate K1->K2,
	// let the epoch-capable peer arm the latch under K2, roll that peer back
	// under K2 to a build that signs but emits no epoch, record the frames this
	// receiver then refuses, let the peer go silent and restart this daemon —
	// 5/5 of those POST-rotation K2 captures are admitted against the empty
	// state (TestRotationDoesNotRetirePostRotationCaptures_6669). A durable
	// K2-scoped latch would have refused them. So the design has to be declined
	// on its own merits, and it still is:
	//
	//   - IN THE STATE WHERE IT MATTERS MOST, ITS BENEFIT AND ITS WORST COST
	//     ARE THE SAME CONFIGURATION. A signed epoch-less frame under the
	//     current key can only exist if the peer held that key while running a
	//     pre-#6169 build (the ALWAYS-EMIT invariant means a #6169+ build always
	//     carries one, even under storage failure) — rollback, replacement under
	//     the same identity and key, or a partial upgrade. While the peer is
	//     still on that build, a durable latch refuses the attacker's captures
	//     AND the LIVE peer, which is the "strictly worsens the no-attacker
	//     rollback" cost above, not a separate one. It does not convert
	//     protected into exposed; it makes an already-refused, already-alarmed
	//     peer's liveness unforgeable while it is silent.
	//
	// WHAT IT BUYS IS NOT BOUGHT BY THE EPOCH-BEARING DOOR EITHER, and an
	// earlier revision of this comment argued that it was: the latch can only
	// have armed under this key because an epoch-BEARING frame was accepted
	// under it, so an attacker on-link then holds one of those too, and against
	// empty post-restart state an archived epoch-bearing frame is admitted
	// whatever the latch says (TestArchivedEpochReplayReArmsLatchAfterRestart_
	// 6169) — therefore, the argument went, a durable latch adds nothing outside
	// a capture window strictly inside the rollback.
	//
	// THE TWO DOORS ARE NOT EQUIVALENT, because what they cost the attacker in
	// SUSTAINED liveness differs. Measured against a restarted receiver:
	//
	//   - 65 captured epoch-BEARING incarnations admit 325/325 on one ascending
	//     pass and then 0/1625 across five further rounds. The floor climbs with
	//     them and the per-session watermark closes the rest, so the capture set
	//     is spent — one finite pass per receiver restart.
	//   - 65 captured epoch-LESS incarnations under the CURRENT key admit
	//     1625/1625 and keep going: nothing orders them, and FIFO eviction hands
	//     the attacker a fresh never-seen session every round. That is forged
	//     peer liveness sustained indefinitely against a silent peer — the exact
	//     #6169 threat, in the one configuration #6169's floor cannot see.
	//
	// A durable PSK-scoped latch refuses all 1625. So the benefit is a real one
	// and larger than "captures taken strictly inside a rollback": it is every
	// epoch-less capture taken under the current key, which is what a peer that
	// spent any time on a pre-#6169 build under this key hands an on-link
	// attacker.
	//
	// IT IS STILL DECLINED, on the costs above and not on redundancy: a durable
	// write on the accept path with no good failure policy, cross-process
	// locking there, and a strictly heavier procedure (a PSK rotation across
	// both nodes) for every no-attacker rollback. The exposure that buys is
	// bounded by the rollback itself — no rollback under the current key, no
	// epoch-less captures to replay — and is metered, not silent
	// (EpochlessAdmitted, and the epoch-downgrade warning names the rotation).
	// Reconsider the trade if a rollback under the current key ever becomes
	// routine rather than an incident action.
	//
	// What process scope costs is otherwise narrow, because this state already
	// lives on the Manager (#5086/#6642): a heartbeat restart, a DHCP-triggered
	// VRF rebind and an HA comms restart all PRESERVE it. Only a full daemon
	// restart clears it, and a live peer re-arms it with its next heartbeat —
	// one DefaultHeartbeatInterval, ~100ms. So the uncovered case needs a daemon
	// restart AND a genuinely absent peer AND an attacker holding usable
	// captures. Rotating the control-link PSK retires everything captured before
	// the rotation, which is what makes it the recovery step; it is not a
	// prophylactic against captures taken after it.
	//
	// It also makes rollback recovery a restart, an operation operators already
	// perform, instead of a documented rm.
	//
	// What process scope does NOT buy is a restart that recovers
	// UNCONDITIONALLY. A replayed archived epoch frame re-arms this latch
	// against the empty post-restart state, so PSK rotation has to come FIRST.
	// Stated in full at the arming site in admitAuthed, where the
	// property lives.
	epochSeen bool

	// epochlessAdmitted counts authenticated heartbeats ADMITTED without a boot
	// epoch, and epochDowngradeRejected counts those refused because the peer
	// had already proved it emits them. Atomics, not mu-guarded, because
	// HeartbeatStats reads them from another goroutine.
	//
	// These exist so the #6169 residual is OBSERVABLE. Without a counter an
	// operator who has upgraded both nodes has no way to tell whether the
	// cluster is still accepting pre-upgrade-shaped frames — the exposure would
	// be invisible and the documentation would be the only defence. A non-zero
	// epochlessAdmitted after a completed rollout means either a node is still
	// on an old build or someone is replaying captures; a non-zero
	// epochDowngradeRejected means the latch is actively refusing something.
	epochlessAdmitted      atomic.Uint64
	epochDowngradeRejected atomic.Uint64

	// epochSessionCollision counts frames refused because they claimed the
	// floor epoch beyond the bound on sessions at that value (see
	// highEpochSessions). A non-zero value means either a sender emitting one
	// constant epoch across its own incarnations — most often a store that
	// cannot WRITE, so refinement republishes prev+1 unchanged — or an on-link
	// attacker replaying a captured set that shares one epoch. Both are things
	// an operator must see, and neither is
	// visible in the other two counters: such a frame carries an epoch, so it
	// is not epochlessAdmitted, and it is not a downgrade, so it is not
	// epochDowngradeRejected.
	epochSessionCollision atomic.Uint64

	// epochOutOfBandRejected and epochRaiseDeclinedAheadOfClock count the two epoch
	// refusals that are NOT replays, and that is the whole reason they are
	// separate counters rather than folded into a general "epoch rejected"
	// total. Both arms used to be silent AND mislabelled: they returned a bare
	// false, so heartbeatAuthDecision reported them as "stale nonce (replay)",
	// and an operator reading that goes looking for an on-link attacker.
	//
	//   - epochOutOfBandRejected: the epoch is 0 or past the year-2200 horizon
	//     (epochUsableAsFloor). A conforming #6169 sender cannot emit one —
	//     refineBootEpoch refuses to chain to such a value, clock-independently
	//     — so a non-zero count means a corrupt state file on the peer or a peer
	//     running something that is not this build. Check the PEER.
	//   - epochRaiseDeclinedAheadOfClock: the epoch is more than bootEpochMaxSkew
	//     ahead of OUR clock (epochWithinForwardBound). This is the one that is
	//     routinely a healthy peer: either its clock runs fast or ours runs
	//     slow. It is a CLOCK fault and the action is NTP on both nodes, not an
	//     incident response. It gates only the raise path, so a peer already at
	//     the floor keeps being accepted while this climbs — which is why it can
	//     climb with liveness perfectly healthy.
	//     #6969 F5: the two arms this counts are no longer the same event. From
	//     an ESTABLISHED receiver (highEpoch != 0) the frame is ADMITTED and only
	//     the raise is declined, so the floor is held and liveness is preserved;
	//     from a FRESH one (highEpoch == 0) it is still refused outright, because
	//     there is no established peer to strand. Both increment this, because
	//     both mean the same thing to an operator: the peer's epoch is ahead of
	//     this node's clock.
	//
	// The third silent arm, `epoch < s.highEpoch`, deliberately has neither a
	// counter nor a distinct reason: a frame below the floor IS a replay of a
	// retired incarnation, so "stale nonce (replay)" is already the true
	// statement, and the lockout case it can also mean (#6711) is metered by the
	// floor itself rather than by a rejection count.
	epochOutOfBandRejected         atomic.Uint64
	epochRaiseDeclinedAheadOfClock atomic.Uint64

	// peerAuthSeen is sticky and READ cross-goroutine
	// (Manager.HeartbeatPeerAuthSeen, consumed by the gRPC fabric listener to
	// arm its downgrade-guard off the fast-arming heartbeat instead of the
	// lazily-arming on-demand fabric RPCs), so it is an atomic rather than
	// mu-guarded.
	peerAuthSeen atomic.Bool
}

// peerEpochFloor reports the highest peer boot epoch accepted so far (0 when
// none). Diagnostics and tests only.
func (s *heartbeatAuthState) peerEpochFloor() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.highEpoch
}

// peerEpochLatched reports whether the peer has proved it emits boot epochs.
// Diagnostics and tests only.
//
// IT IS A FACT ABOUT THIS STATE, NOT ABOUT CURRENT ENFORCEMENT, and callers
// that render it must not promote it into one. admitAuthed does refuse an
// epochless frame while this is true — but it is not the outermost gate:
// heartbeatAuthDecision short-circuits to dual-accept whenever no local key is
// configured, and UpdateConfig clears the live key WITHOUT resetting hbAuth. So
// "latched" and "epochless frames are being refused right now" come apart
// whenever the PSK is removed from a running daemon. See epochlessExposureNote.
func (s *heartbeatAuthState) peerEpochLatched() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epochSeen
}

// peerBootEpoch reports the across-reboot floor AND whether the peer has proved
// it emits epochs, read under ONE acquisition of s.mu (#7762).
//
// The pairing is the point. `peerEpochFloor` and `peerEpochLatched` each take
// s.mu separately, and admitAuthed sets `epochSeen = true` and raises
// `highEpoch` inside a SINGLE critical section — so a caller taking the two
// locks in sequence can interleave between them and observe (floor=0,
// latched=true). That pair is incoherent: it says "the peer emits epochs" and
// "the highest epoch ever accepted is none" at once, and a classifier acting on
// it would read a reboot where there is none. One lock, one snapshot.
//
// Returns (floor, latched). A caller must treat `latched == false` as its own
// case rather than as floor 0: they are different states, and only the second
// says the floor means anything.
func (s *heartbeatAuthState) peerBootEpoch() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.highEpoch, s.epochSeen
}

// peerAuthenticated reports whether the peer has ever sent a valid
// HMAC-authenticated heartbeat (sticky for the life of the process).
func (s *heartbeatAuthState) peerAuthenticated() bool {
	return s.peerAuthSeen.Load()
}

// notePeerAuthenticated records that the peer proved it holds the PSK. From
// then on an unauthenticated frame from it is a downgrade attack.
func (s *heartbeatAuthState) notePeerAuthenticated() {
	s.peerAuthSeen.Store(true)
}

// heartbeatAuthState returns the Manager's process-lifetime control-channel
// auth state — the state a new heartbeatReceiver binds to so a restart does
// not reset anti-replay (#5086). A nil Manager (unit tests constructing a
// standalone receiver) gets a fresh private state rather than a nil deref, so
// a test receiver behaves exactly like a never-restarted production one.
func (m *Manager) heartbeatAuthState() *heartbeatAuthState {
	if m == nil {
		return &heartbeatAuthState{}
	}
	return &m.hbAuth
}

// heartbeatAuthDecision applies the #4107 dual-accept policy for one received
// heartbeat and returns whether to accept it (and, when rejected, a short
// reason for logging — never the key or packet bytes).
//
//	keyConfigured — the local ControlLinkAuthKey is set (we can verify).
//	present       — the frame carried an auth trailer.
//	macOK         — the trailer's HMAC verified (only meaningful when present).
//	nonceFresh    — the nonce passed anti-replay (only meaningful when macOK).
//	peerAuthSeen  — we have previously accepted an authenticated heartbeat from
//	                the peer (sticky: proves the peer holds the key, so both
//	                nodes are keyed and an unauthenticated frame is now forged).
//
// Policy:
//   - No local key: dual-accept everything — this node cannot verify and may be
//     the not-yet-upgraded / not-yet-keyed side of a rolling upgrade.
//   - Local key + auth trailer: enforce — reject a bad HMAC or a replayed nonce.
//   - Local key + no trailer + peer never authenticated: dual-accept — the peer
//     has not started signing yet (rolling upgrade / key not yet synced).
//   - Local key + no trailer + peer HAS authenticated: reject — a downgrade to
//     cleartext once both nodes are keyed is an attack.
func heartbeatAuthDecision(keyConfigured, present, macOK, nonceFresh, peerAuthSeen bool) (bool, string) {
	if !keyConfigured {
		return true, ""
	}
	if present {
		if !macOK {
			return false, "hmac verification failed"
		}
		if !nonceFresh {
			return false, "stale nonce (replay)"
		}
		return true, ""
	}
	if peerAuthSeen {
		return false, "missing auth trailer (enforced: peer previously authenticated)"
	}
	return true, ""
}

// heartbeatNonce returns the next control-channel anti-replay nonce for a
// heartbeat send: this daemon incarnation's session id (drawn once, lazily) and
// a strictly increasing per-incarnation counter.
//
// #6169: Manager-scoped, NOT per-heartbeatSender — see the hbNonceOnce field
// comment for why a per-sender session made the receiver's bounded ring
// churnable within a single peer boot epoch.
func (m *Manager) heartbeatNonce() (session, counter uint64) {
	m.hbNonceOnce.Do(func() { m.hbSession = randomSessionID() })
	return m.hbSession, m.hbCounter.Add(1)
}

// randomSessionID returns a random 64-bit anti-replay session id. On the
// (practically impossible) crypto/rand failure it falls back to the monotonic
// clock, which is still process-unique for the receiver's re-anchor logic.
func randomSessionID() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(MonotonicNanos())
	}
	return binary.LittleEndian.Uint64(b[:])
}

// PeerGroupState holds the last-known state of a peer's redundancy group.
type PeerGroupState struct {
	GroupID  int
	Priority int
	Weight   int
	State    NodeState
	// StateOverriddenLocally records that `State` above is NOT what the peer
	// reported — this node substituted it (#7367).
	//
	// applyTransferCommitOverridesOnPeerStateLocked rewrites `State` to
	// StateSecondaryHold for an armed transfer-out override or an unexpired
	// transfer-commit grace window, in the SAME map that feeds both the
	// election and `show chassis cluster status`. So one write corrupts the
	// operator's view of the peer at the same time as the election input, and
	// the rendered `secondary-hold` is indistinguishable from one the peer
	// actually sent.
	//
	// That is how the #6656 incident could show node0 printing node1 as
	// secondary-hold while node1 printed itself primary, with neither node
	// displaying anything anomalous. This flag does not change `State` or any
	// election behaviour; it only lets the render say which of the two it is.
	StateOverriddenLocally bool
	// OverrideReason names WHICH mechanism substituted the state, because the
	// two have different operator responses: a transfer-out override is armed
	// until explicitly cleared, whereas a commit-grace window expires on its
	// own. Empty when StateOverriddenLocally is false.
	OverrideReason string
}

// heartbeatSender sends periodic heartbeat packets.
type heartbeatSender struct {
	mgr        *Manager
	conn       *net.UDPConn
	peerAddr   *net.UDPAddr
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
	sent       atomic.Uint64
	sendErrors atomic.Uint64
}

// heartbeatReceiver listens for peer heartbeat packets.
type heartbeatReceiver struct {
	mgr        *Manager
	conn       *net.UDPConn
	threshold  int
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
	lastSeen   atomic.Int64 // CLOCK_MONOTONIC nanos of last heartbeat (MonotonicNanos)
	received   atomic.Uint64
	recvErrors atomic.Uint64
	startedAt  time.Time // when receiver started (for initial peer-lost detection)
	// seenGrace is the seen-then-lost suppression window measured from
	// startedAt. Zero means the cold-boot heartbeatStartupGrace. armRestart sets
	// it to heartbeatRestartGrace for a receiver that replaced one which had seen
	// the peer (#9722). Written only before start(), so the timeout goroutine
	// reads it without a lock.
	seenGrace time.Duration

	// peerAddr is the configured control-link peer, used to drop datagrams
	// from any other source before they cost a MAC verification (#6888).
	//
	// NIL MEANS UNSET, AND UNSET FAILS OPEN. A receiver with no configured
	// peer accepts every source exactly as it did before #6888. That is
	// deliberate and is the branch most likely to be got wrong: a pin that
	// rejects when it does not know what to accept takes the cluster down,
	// which is far worse than the defence-in-depth gap it closes.
	peerAddr *net.UDPAddr

	// foreignSrc counts datagrams dropped by the peer pin.
	//
	// It is counted rather than silently dropped because the issue's strongest
	// argument is that a misconfigured third node pointed at this control link
	// is currently INVISIBLE — its frames are read, MAC-checked and discarded
	// with no signal anywhere. A rejection that is not counted reproduces
	// exactly that, one layer down.
	foreignSrc atomic.Uint64

	// lastForeignWarn rate-limits the foreign-source log. Owned by readLoop,
	// which is the only goroutine that touches it, so it needs no lock.
	lastForeignWarn time.Time

	// auth is the #4107 control-channel auth state (anti-replay watermarks +
	// the sticky peer-authenticated flag). It is a POINTER to state owned by
	// the Manager, not an embedded value: the tracker must outlive this
	// receiver so a heartbeat restart cannot discard the retired-session
	// memory and re-open the #5086 replay. newHeartbeatReceiver always sets
	// it; it is never nil.
	auth *heartbeatAuthState
}

// peerAuthenticated reports whether the peer has ever sent a valid
// HMAC-authenticated heartbeat (sticky). It proves the peer holds the
// control-link PSK and is signing — the arming signal the gRPC fabric
// listener reuses so its downgrade-guard engages within ~one heartbeat
// interval of the peer coming up, not on the next on-demand fabric RPC.
func (r *heartbeatReceiver) peerAuthenticated() bool {
	return r.auth.peerAuthenticated()
}

func newHeartbeatSender(mgr *Manager, conn *net.UDPConn, peerAddr *net.UDPAddr, interval time.Duration) *heartbeatSender {
	return &heartbeatSender{
		mgr:      mgr,
		conn:     conn,
		peerAddr: peerAddr,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (s *heartbeatSender) start() {
	s.wg.Add(1)
	go s.run()
}

func (s *heartbeatSender) run() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// #6724: the boot-epoch persist-retry trigger rides this loop rather than
	// owning a goroutine. This package's start/stop discipline is where its
	// hazards live (superseded starts, leaked loops whose stopCh is never
	// closed), so a retry that needs no new lifecycle is the cheaper thing to
	// get right. The per-tick cost when nothing is owed is one atomic load —
	// and it is only paid once every retryEvery ticks, so the 200ms send path
	// is untouched in the ordinary case.
	retryEvery := bootEpochPersistRetryTicks(s.interval)
	ticks := 0

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.send()
			ticks++
			if ticks >= retryEvery {
				ticks = 0
				s.mgr.retryOwedBootEpochPersist()
			}
		}
	}
}

func (s *heartbeatSender) send() {
	pkt := s.mgr.buildHeartbeat()
	// #4107: sign the frame when a control-channel PSK is configured. The key
	// is fetched fresh each tick so a commit that sets/clears it takes effect
	// without a heartbeat restart. Never logged.
	var data []byte
	if key := s.mgr.controlLinkAuthKey(); len(key) > 0 {
		session, counter := s.mgr.heartbeatNonce()
		// #6169: ALWAYS carry a boot epoch. heartbeatBootEpoch publishes a
		// wall-clock value before any I/O and never returns 0 once called, so
		// this cannot silently degrade to a legacy frame under a storage fault —
		// which a latched peer would read as a rollback and refuse.
		data = marshalHeartbeatAuthEpoch(pkt, key, session, counter, s.mgr.heartbeatBootEpoch())
	} else {
		data = MarshalHeartbeat(pkt)
	}
	if _, err := s.conn.WriteToUDP(data, s.peerAddr); err != nil {
		s.sendErrors.Add(1)
		slog.Debug("cluster: heartbeat send failed", "err", err)
	} else {
		s.sent.Add(1)
	}
}

func (s *heartbeatSender) stop() {
	close(s.stopCh)
	s.wg.Wait()
	// Close the send socket after the run loop has exited (wg.Wait above) so
	// there is no write-after-close race. Without this the sender FD leaks on
	// every heartbeat stop/restart (#4033); the receiver already closes its
	// conn in stop().
	s.conn.Close()
}

// srcIsConfiguredPeer reports whether a datagram's source may be processed
// (#6888). It compares the IP ONLY, never the port.
//
// THE PORT IS DELIBERATELY EXCLUDED, and this is measured, not assumed. The
// peer's SENDER socket is bound with port 0 — `net.JoinHostPort(localAddr,
// "0")` in startHeartbeatLocked — so it sources from an EPHEMERAL port that is
// unrelated to the port it listens on and changes on every daemon restart.
// Observed on the live loss cluster: fw0 listens on 10.99.12.1:4784 and sends
// from :40745; fw1 listens on 10.99.12.2:4784 and sends from :50923. A pin on
// the full UDPAddr would therefore reject 100% of legitimate heartbeats and
// take down every cluster on upgrade — strictly worse than no pin at all.
//
// Two fail-open cases, both returning true:
//
//   - peerAddr nil: no configured peer, so there is nothing to pin against.
//   - src nil: the read gave no source, so the pin has no input. Refusing here
//     would turn an unexpected-but-harmless read into a comms outage.
//
// The zone (%iface on a link-local address) is not compared either. net.IP.Equal
// ignores it, and that is the tolerant direction: a peer legitimately sourcing
// from a link-local address on the control interface must not be rejected
// because a zone string differs. This is defence in depth — the frame still
// faces MAC verification either way — so tolerance costs little and strictness
// costs availability.
func (r *heartbeatReceiver) srcIsConfiguredPeer(src *net.UDPAddr) bool {
	if r == nil || r.peerAddr == nil || r.peerAddr.IP == nil {
		return true
	}
	if src == nil || src.IP == nil {
		return true
	}
	return r.peerAddr.IP.Equal(src.IP)
}

// noteForeignSource counts and (rate-limited) reports a datagram dropped by the
// peer pin. Called only from readLoop, which owns lastForeignWarn.
func (r *heartbeatReceiver) noteForeignSource(src *net.UDPAddr) {
	r.foreignSrc.Add(1)
	now := time.Now()
	if !r.lastForeignWarn.IsZero() && now.Sub(r.lastForeignWarn) < 30*time.Second {
		return
	}
	r.lastForeignWarn = now
	slog.Warn("cluster: heartbeat datagram from an unexpected source dropped before "+
		"authentication — something other than the configured control-link peer is "+
		"sending to this port. Check for a third node misconfigured onto this "+
		"cluster's control link.",
		"src", src.String(), "configured_peer", r.peerAddr.IP.String(),
		"dropped_total", r.foreignSrc.Load(), "issue", "#6888")
}

// newHeartbeatReceiver builds the heartbeat read side.
//
// peerAddr is the configured control-link peer (#6888). It is a REQUIRED
// parameter rather than a setter so the compiler proves every construction
// site decided what to pass: a pin that silently never gets its address is
// indistinguishable from no pin at all, and would be discovered only by an
// attacker or a misconfiguration. Pass nil to accept any source (see the
// peerAddr field comment — unset fails OPEN).
func newHeartbeatReceiver(mgr *Manager, conn *net.UDPConn, threshold int, interval time.Duration, peerAddr *net.UDPAddr) *heartbeatReceiver {
	r := &heartbeatReceiver{
		mgr:       mgr,
		conn:      conn,
		threshold: threshold,
		interval:  interval,
		peerAddr:  peerAddr,
		stopCh:    make(chan struct{}),
		// #5086: bind to the Manager's process-lifetime auth state so a
		// heartbeat restart (VRF rebind, comms restart) keeps every retired
		// peer-session watermark instead of starting from an empty tracker
		// that re-admits captured frames. mgr is nil only in unit tests that
		// exercise a standalone receiver; those get their own state, which is
		// exactly the pre-#5086 per-receiver scope and is safe because such a
		// receiver is never restarted.
		auth: mgr.heartbeatAuthState(),
	}
	return r
}

// armRestart installs the pre-restart peer liveness on a replacement receiver
// BEFORE start(): the last heartbeat the replaced receiver saw, and the short
// restart grace (#9722). Only a receiver that replaced one which had seen the
// peer is armed; lastSeen == 0 leaves the cold-boot semantics in place.
func (r *heartbeatReceiver) armRestart(lastSeen int64) {
	if lastSeen == 0 {
		return
	}
	r.lastSeen.Store(lastSeen)
	r.seenGrace = heartbeatRestartGrace
}

// seenThenLostGrace is how long after startedAt checkTimeout suppresses
// peer-lost for a peer it has seen: the restart grace when armRestart set one,
// the cold-boot grace otherwise.
func (r *heartbeatReceiver) seenThenLostGrace() time.Duration {
	if r.seenGrace > 0 {
		return r.seenGrace
	}
	return heartbeatStartupGrace
}

func (r *heartbeatReceiver) start() {
	r.startedAt = time.Now()
	r.wg.Add(2)
	go r.readLoop()
	go r.timeoutLoop()
}

func (r *heartbeatReceiver) readLoop() {
	defer r.wg.Done()
	buf := make([]byte, maxHeartbeatSize)

	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		r.conn.SetReadDeadline(time.Now().Add(r.interval))
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-r.stopCh:
				return
			default:
				slog.Debug("cluster: heartbeat read error", "err", err)
				continue
			}
		}

		// #6888: drop anything not from the configured peer at the CHEAPEST
		// point — before unmarshal, before cluster-id validation, before MAC
		// verification. Placed first because that is the whole benefit: an
		// off-path sender that can reach this port otherwise makes the node do
		// HMAC work on every forged frame, on a path that runs at a 200ms
		// interval with a threshold of 5.
		//
		// It cannot skip replay-state updates for genuine frames: a frame from
		// the peer passes this and reaches admitFrame exactly as before, and a
		// frame from anywhere else has no legitimate replay state to update.
		//
		// This is NOT an authentication boundary and must not be read as one —
		// frames are HMAC-verified in admitFrame, and an attacker without the
		// control-link PSK could never get one admitted whatever source it
		// carried. What this adds is cheapest-point filtering, visibility of a
		// misconfiguration that was previously silent, and a constraint on
		// where forged frames can originate if the PSK ever leaks.
		if !r.srcIsConfiguredPeer(src) {
			r.noteForeignSource(src)
			continue
		}

		pkt, err := UnmarshalHeartbeat(buf[:n])
		if err != nil {
			r.recvErrors.Add(1)
			slog.Warn("cluster: invalid heartbeat", "err", err)
			continue
		}

		// Validate cluster ID.
		if int(pkt.ClusterID) != r.mgr.ClusterID() {
			r.recvErrors.Add(1)
			slog.Warn("cluster: heartbeat from wrong cluster",
				"got", pkt.ClusterID, "want", r.mgr.ClusterID())
			continue
		}

		// A same-cluster heartbeat carrying OUR node-id is not a loopback on a
		// unicast point-to-point control link (a node never receives its own
		// frame) — it is a peer misconfigured with a duplicate node-id, an
		// INVALID cluster (#4549 F11). Surface it (rate-limited) so the
		// operator fixes /etc/xpf/node-id, then discard it: it cannot be told
		// apart from a stray loopback and a duplicate-node-id cluster is
		// unresolvable at runtime, so it must never drive election.
		if int(pkt.NodeID) == r.mgr.NodeID() {
			r.mgr.NoteDuplicateNodeIDHeartbeat()
			continue
		}

		if !r.admitFrame(buf[:n], pkt) {
			continue
		}
	}
}

// admitFrame runs the #4107/#6169 authentication gate over one raw heartbeat
// datagram and, on accept, applies the consequences an accepted frame has:
// refresh peer liveness (lastSeen) and drive election (handlePeerHeartbeat).
// It reports whether the frame was accepted.
//
// IT IS THE ONLY IMPLEMENTATION OF THAT GATE — the point of it being a method
// rather than inline in readLoop. Two epoch fixtures used to RESTATE the gate
// line-for-line and assert equivalence in a prose comment, so severing
// `if macOK { epoch, hasEpoch = ... }` here — every frame read as epochless, the
// floor never consulted, the latch never armed — left the whole package green.
// Two human-written artifacts restating each other catch typos, not wrong
// beliefs. Those helpers now DELEGATE here, so divergence is impossible rather
// than asserted. Do not reintroduce a second copy for a test's convenience.
//
// pkt must be the already-unmarshalled view of frame; readLoop needs it for the
// cluster-id and duplicate-node-id checks that run first.
func (r *heartbeatReceiver) admitFrame(frame []byte, pkt *HeartbeatPacket) bool {
	// #4107 control-channel authentication. When a PSK is configured the
	// heartbeat/election channel is HMAC-authenticated; a forged or
	// replayed heartbeat is rejected HERE, before it can refresh peer
	// liveness (lastSeen) or drive election (handlePeerHeartbeat).
	// Dual-accept keeps a mixed-version / not-yet-keyed cluster from
	// splitting — see heartbeatAuthDecision. The key is never logged.
	// #6630: verify against EVERY accepted key, not just the signing key. A
	// rotation is otherwise a planned outage: while the two nodes hold
	// different keys each receives a present-but-invalid HMAC from the other,
	// this gate rejects it WITHOUT refreshing lastSeen, and after
	// heartbeat-interval x threshold (~1s at shipped settings) BOTH nodes
	// declare the peer dead and BOTH take over their redundancy groups —
	// dual-master with duplicate VIPs for the whole window between the two
	// commits. Accepting the other key of the rotation for an
	// operator-bounded window is what makes the rollout node-by-node, and
	// with no in-band coordination channel it is the only mechanism that can:
	// there is nothing for the two nodes to agree a cutover instant with.
	//
	// verifiedKey, not a bool: the epoch read below re-derives from the signed
	// body and MUST use the key that actually verified. Using the signing key
	// there while a frame verified under the additional one would read the
	// epoch as garbage, drop it below the floor, and reject the frame the gate
	// just accepted — reintroducing the outage inside the fix for it.
	keys := r.mgr.controlLinkAcceptedKeys()
	session, counter, present := heartbeatAuthTrailer(frame)
	var verifiedKey []byte
	if present {
		for _, k := range keys {
			if verifyHeartbeatMAC(frame, k) {
				verifiedKey = k
				break
			}
		}
	}
	key := verifiedKey
	macOK := verifiedKey != nil
	// #6169: the boot epoch is read ONLY from a MAC-verified frame — only a
	// verified frame authorises treating len-52 as the end of the signed
	// body — and the epoch floor is applied BEFORE the session ring, so a
	// frame the floor REJECTS never churns it. That is an ordering property
	// of admitAuthed, not a claim that every replayed retired frame is
	// rejected: after a sender regression (#6711) an archived frame can sit
	// at or above the floor and reach the ring like any other.
	var (
		epoch    uint64
		hasEpoch bool
	)
	if macOK {
		epoch, hasEpoch = heartbeatFrameEpoch(frame, key)
	}
	var (
		nonceFresh  bool
		epochReason string
	)
	if macOK {
		nonceFresh, epochReason = r.auth.admitAuthed(hasEpoch, epoch, session, counter)
	}
	// keyConfigured asks "can this node verify at all", so it is the ACCEPTED
	// SET being non-empty — not `len(key) > 0`, which since #6630 is nil
	// whenever verification failed and would collapse a keyed node's rejection
	// into the unkeyed dual-accept arm.
	accept, reason := heartbeatAuthDecision(len(keys) > 0, present, macOK, nonceFresh, r.peerAuthenticated())
	if !accept {
		r.recvErrors.Add(1)
		// #6669: prefer the epoch gate's own reason when it has one.
		// heartbeatAuthDecision sees only `nonceFresh == false` and calls every
		// epoch refusal "stale nonce (replay)" — true for the ring and for a
		// below-floor frame, and WRONG for an out-of-band epoch (a corrupt or
		// non-conforming peer) and for one past the forward bound (a clock
		// fault). Those two send an operator hunting an attacker instead of
		// checking the peer's build or NTP, which is the whole cost of the
		// collapsed label.
		if epochReason != "" {
			reason = epochReason
		}
		// #6169: an authenticated frame that lost its epoch after the peer
		// had proved it signs one is operator-actionable (a deliberate
		// rollback stays refused until the floor is cleared), so surface it
		// distinctly instead of burying it in the generic replay reason.
		if macOK && !hasEpoch && r.auth.peerEpochLatched() {
			r.mgr.NoteEpochDowngradeHeartbeat()
		}
		// #6669 r18 (finding 8): rate-limited, and it reports what it
		// suppressed so the bound does not conceal the rate.
		if emit, suppressed := r.auth.rejectWarn.admit(); emit {
			slog.Warn("cluster: heartbeat auth rejected",
				"reason", reason, "peer_node", pkt.NodeID,
				"suppressed_since_last", suppressed)
		}
		return false
	}
	if macOK {
		// The peer proved it holds the key — from now on an
		// unauthenticated frame from it is a downgrade attack. This also
		// arms the gRPC fabric listener's downgrade-guard (via
		// Manager.HeartbeatPeerAuthSeen).
		r.auth.notePeerAuthenticated()
		// #6630: record WHICH accepted key the peer is signing with, so
		// `show chassis cluster statistics` can answer the one question a
		// rotation raises and nothing else could — "has the peer moved to the
		// new key, i.e. is it safe to finalize?". The stored value is a short
		// derived IDENTIFIER, never the key; see controlLinkKeyID.
		r.mgr.notePeerControlKeyID(controlLinkKeyID(verifiedKey))
	}

	r.received.Add(1)
	// Store CLOCK_MONOTONIC, not wall clock: the timeout comparison
	// must be immune to wall-clock steps (#1792).
	r.lastSeen.Store(MonotonicNanos())
	r.mgr.handlePeerHeartbeat(pkt)
	return true
}

func (r *heartbeatReceiver) timeoutLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.checkTimeout()
		}
	}
}

// checkTimeout runs one peer-liveness evaluation tick. Split out of
// timeoutLoop so the cold-boot never-seen floor and the steady-state
// staleness decision are unit testable without driving the ticker goroutine.
func (r *heartbeatReceiver) checkTimeout() {
	timeout := time.Duration(r.threshold) * r.interval
	lastNano := r.lastSeen.Load()
	if lastNano == 0 {
		// No heartbeat ever received. Deciding a peer NEVER EXISTED at boot
		// is not the same as a peer that WAS seen then went silent: on a
		// simultaneous cold boot the local config apply phase disrupts the
		// control-link RX for 10-15+ seconds, so the first heartbeats from a
		// live peer are dropped and lastSeen stays 0 on BOTH nodes. Promoting
		// at threshold*interval (~500ms) would then make BOTH claim primary
		// and the RETH virtual MAC — split-brain (#4386). Hold the never-seen
		// promotion behind the SAME cold-boot grace the seen-then-lost path
		// uses below. A genuinely-absent peer (single-node deployment, or a
		// peer that will never come up) still promotes once the grace elapses,
		// so this delays the decision, it never blocks it.
		// (r.startedAt is a direct time.Time, so time.Since uses its embedded
		// monotonic reading — already step-safe.)
		if neverSeenConfirmed(time.Since(r.startedAt), heartbeatStartupGrace) {
			r.mgr.handlePeerNeverSeen()
		}
		return
	}
	// During the cold-boot grace, suppress peer-lost entirely. The config
	// apply phase (VRF binding, FRR reload, fabric creation, RETH MAC) can
	// disrupt the UDP receive path on the control link for 10-15+ seconds.
	// Without this grace, the recovering node sees one peer heartbeat then
	// declares peer lost — creating split-brain. (r.startedAt is a direct
	// time.Time, so time.Since uses its embedded monotonic reading — already
	// step-safe.)
	//
	// #9722: a receiver that replaced one which had already seen the peer is
	// not booting, so it holds only for heartbeatRestartGrace
	// (seenThenLostGrace). Holding 30s there hid a peer that died just after a
	// commit for up to 30s.
	if time.Since(r.startedAt) < r.seenThenLostGrace() {
		return
	}
	// Compare in the CLOCK_MONOTONIC domain. The previous
	// time.Unix(0, lastNano) round-trip produced a Time with no monotonic
	// reading, making time.Since pure wall-clock — a forward step > timeout
	// fired a false peer-lost on a healthy cluster (#1792).
	if heartbeatStale(lastNano, MonotonicNanos(), timeout) {
		r.mgr.handlePeerTimeout()
	}
}

// neverSeenConfirmed reports whether a receiver that has never seen a peer
// heartbeat (lastSeen == 0) has waited out the cold-boot config-apply grace
// and may now confirm the peer absent to drive single-node election. It is a
// startup FLOOR, not a steady-state timeout: threshold*interval (~500ms) is
// correct for a peer that WAS seen then went silent, but far too aggressive
// for deciding a peer never existed at boot, where the first heartbeats are
// commonly dropped by the local config apply disruption (#4386). Returning
// true once sinceStart >= grace guarantees a genuinely-absent peer still
// promotes — the floor delays the never-seen decision, it never blocks it.
func neverSeenConfirmed(sinceStart, grace time.Duration) bool {
	return sinceStart >= grace
}

// heartbeatStale reports whether the last peer heartbeat is older than
// timeout. Both timestamps are CLOCK_MONOTONIC nanoseconds (MonotonicNanos),
// so the decision is immune to wall-clock steps. A nowMono earlier than
// lastSeenMono (cannot happen on a correct monotonic clock, but cheap to
// tolerate) yields a negative age and reports not-stale.
func heartbeatStale(lastSeenMono, nowMono int64, timeout time.Duration) bool {
	return time.Duration(nowMono-lastSeenMono) > timeout
}

// peerHeartbeatFresh reports whether a peer heartbeat has been received and is
// currently within the timeout window — i.e. NOT stale. It re-reads lastSeen
// against the live monotonic clock, so a heartbeat that landed since the
// timeout was first declared is observed. A receiver that has never seen a
// heartbeat (lastSeen == 0) is not "fresh".
//
// This is the truth source for handlePeerTimeout's post-guard re-check: after a
// slow guard window, the only correct question is "is the heartbeat fresh
// again?", not "is peerAlive still set?" (peerAlive is essentially always true
// at that point — a fresh heartbeat only keeps it true).
func (r *heartbeatReceiver) peerHeartbeatFresh() bool {
	lastNano := r.lastSeen.Load()
	if lastNano == 0 {
		return false
	}
	timeout := time.Duration(r.threshold) * r.interval
	return !heartbeatStale(lastNano, MonotonicNanos(), timeout)
}

func (r *heartbeatReceiver) stop() {
	close(r.stopCh)
	r.conn.Close()
	r.wg.Wait()
}
