package cluster

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #8121: the idle persistent-NAT lease channel.
//
// #7360 rebuilds a persistent lease on the standby from the synced sessions
// that hold it, which reaches every lease with live flows — every lease session
// sync can observe, since a lease is learned FROM a session. An IDLE lease has
// none, yet on the active node it is still live and still reusable, so a client
// whose flows all closed within the persistence timeout keeps its translated
// port there and loses it across a failover. This carries that population.
//
// The generation-bearing type 41 and its replay semantics remain unchanged.
// #14638 gives deterministic leases a separate type-43 record layout; mixed
// batches split type-41 and type-43 records under one generation.
// #16877 adds provenance successors 50/51, carrying mint_from_zone after the
// corresponding legacy/deterministic layout. New senders use 50/51 only for a
// peer that advertises provenance support; otherwise they fall back to 41/43
// with provenance omitted. New receivers still decode 41/43 as no provenance,
// and old receivers ignore the additive successor types. Unknown types are
// additive under the existing #2239/#6650 precedent.
const (
	// The config schema permits persistent NAT inactivity timeouts up to 24h.
	// Refuse larger peer lifetimes before handing the record to the dataplane.
	maxPersistentNatLeaseLifetimeNS  uint64 = 86_400_000_000_000
	minPersistentNatLeaseTimeoutNS   uint64 = 1_000_000_000
	maxPersistentNatLeaseRemoteCount        = userspace.MaxPersistentNatLeaseRemotes
	// syncMsgPersistentNatLease is the RETIRED pre-#10018 lease set. It stays
	// reserved so a new receiver can explicitly ignore an old sender's
	// unscoped records rather than decoding them as domain 0.
	syncMsgPersistentNatLease = 38
	// syncMsgPersistentNatLeaseScoped is the retired additive v25 form. It has
	// no durable revocation generation and is therefore ignored by receivers.
	syncMsgPersistentNatLeaseScoped = 39
	// syncMsgPersistentNatLeaseGeneration carries an origin and durable clear
	// generation ahead of the v25 lease payload. A pre-feature peer ignores the
	// unknown type; a new peer can reject delayed pre-clear records indefinitely.
	syncMsgPersistentNatLeaseGeneration = 41
	// syncMsgPersistentNatLeaseDeterministic is the #14638 record-layout
	// successor to syncMsgPersistentNatLeaseGeneration: same origin/generation
	// envelope and lease-count framing, but each record carries the seven
	// Deterministic* fields after TimeoutNs. Value 43 remains the deterministic
	// layout; type 51 carries the same records plus mint_from_zone (#16877).
	// Mixed batches split dynamic and deterministic records.
	syncMsgPersistentNatLeaseDeterministic = 43
	// #16877: successor layouts append mint_from_zone after all existing
	// fields. Old peers ignore these additive message types; new peers continue
	// decoding 41/43 with no provenance during rolling upgrades.
	syncMsgPersistentNatLeaseProvenance              = 50
	syncMsgPersistentNatLeaseDeterministicProvenance = 51
	// #17099: successor layouts append the typed pool identity
	// (pool_kind byte + nat64_prefix string) after all existing fields
	// (after provenance when both apply). Types 52/53 are the
	// typed-pool counterparts of 50/51 and are sent only to a peer that
	// advertises capFlag2PersistentNatLeaseTypedPool; otherwise the
	// sender falls back to 41/43/50/51 with PoolKind stripped to 0, so
	// an old receiver's helper decode-fallback still applies. New
	// receivers decode 41/43/50/51 as legacy (PoolKind 0).
	syncMsgPersistentNatLeaseTypedPool              = 52
	syncMsgPersistentNatLeaseDeterministicTypedPool = 53
)

// encodePersistentNatLeasePayload serializes the scoped idle-lease set inside
// the generation-bearing envelope. Records are additive within one generation;
// advancing the envelope generation clears the receiver before import.
//
// Records are encoded FIRST so an unencodable one drops individually while the
// count prefix stays consistent with what was actually emitted — the #4892
// shape, and the reason the string helper returns an error rather than
// narrowing a uint16 length. Dropping one lease costs that client its port on
// takeover; misframing the peer's decode corrupts the lease's identity.
func encodePersistentNatLeasePayload(leases []userspace.IdleLeaseWire) []byte {
	return encodePersistentNatLeasePayloadLayout(leases, false)
}

func encodePersistentNatLeasePayloadDeterministic(leases []userspace.IdleLeaseWire) []byte {
	return encodePersistentNatLeasePayloadLayout(leases, true)
}

func encodePersistentNatLeasePayloadLayout(leases []userspace.IdleLeaseWire, deterministic bool) []byte {
	return encodePersistentNatLeasePayloadLayoutWithProvenance(leases, deterministic, false)
}

func encodePersistentNatLeasePayloadLayoutWithProvenance(
	leases []userspace.IdleLeaseWire, deterministic, provenance bool,
) []byte {
	return encodePersistentNatLeasePayloadLayoutTyped(leases, deterministic, provenance, false)
}

func encodePersistentNatLeasePayloadLayoutTyped(
	leases []userspace.IdleLeaseWire, deterministic, provenance, typedPool bool,
) []byte {
	recs := make([][]byte, 0, len(leases))
	for _, l := range leases {
		rec, err := encodeOnePersistentNatLeaseLayoutTyped(l, deterministic, provenance, typedPool)
		if err != nil {
			slog.Warn("cluster sync: dropping unencodable persistent-NAT lease from sync push",
				"pool", l.Pool, "src", l.SrcIP, "err", err)
			continue
		}
		recs = append(recs, rec)
	}
	b := make([]byte, 0, 8+len(recs)*100)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(recs)))
	for _, rec := range recs {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
		b = append(b, rec...)
	}
	return b
}

func encodeOnePersistentNatLease(l userspace.IdleLeaseWire) ([]byte, error) {
	return encodeOnePersistentNatLeaseLayout(l, false)
}

func encodeOnePersistentNatLeaseLayout(l userspace.IdleLeaseWire, deterministicLayout bool) ([]byte, error) {
	return encodeOnePersistentNatLeaseLayoutWithProvenance(l, deterministicLayout, false)
}

func encodeOnePersistentNatLeaseLayoutWithProvenance(
	l userspace.IdleLeaseWire, deterministicLayout, provenanceLayout bool,
) ([]byte, error) {
	return encodeOnePersistentNatLeaseLayoutTyped(l, deterministicLayout, provenanceLayout, false)
}

func encodeOnePersistentNatLeaseLayoutTyped(
	l userspace.IdleLeaseWire, deterministicLayout, provenanceLayout, typedPoolLayout bool,
) ([]byte, error) {
	if !deterministicLayout && persistentNatLeaseIsDeterministic(l) {
		return nil, errors.New("encode idle lease: deterministic identity requires the deterministic record layout (#14638)")
	}
	if len(l.PermittedRemotes) > maxPersistentNatLeaseRemoteCount {
		return nil, fmt.Errorf("encode idle lease permissions: %d remotes exceeds maximum %d",
			len(l.PermittedRemotes), maxPersistentNatLeaseRemoteCount)
	}
	b := make([]byte, 0, 100+len(l.PermittedRemotes)*19)
	var err error
	if b, err = putLeaseString(b, l.Pool); err != nil {
		return nil, fmt.Errorf("encode idle lease Pool: %w", err)
	}
	b = append(b, l.Protocol)
	if l.RoutingScope == nil {
		return nil, errors.New("encode idle lease RoutingScope: missing v25 scope")
	}
	b = binary.LittleEndian.AppendUint32(b, *l.RoutingScope)
	if l.EgressScope == nil {
		return nil, errors.New("encode idle lease EgressScope: missing v50 scope")
	}
	b = binary.LittleEndian.AppendUint32(b, *l.EgressScope)
	if b, err = putLeaseString(b, l.SrcIP); err != nil {
		return nil, fmt.Errorf("encode idle lease SrcIP: %w", err)
	}
	b = binary.LittleEndian.AppendUint16(b, l.SrcPort)
	if b, err = putLeaseString(b, l.RemoteIP); err != nil {
		return nil, fmt.Errorf("encode idle lease RemoteIP: %w", err)
	}
	b = binary.LittleEndian.AppendUint16(b, l.RemotePort)
	var permitAnyRemote byte
	if l.PermitAnyRemote {
		permitAnyRemote = 1
	}
	b = append(b, permitAnyRemote)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(l.PermittedRemotes)))
	for i := range l.PermittedRemotes {
		remote := l.PermittedRemotes[i]
		addr, err := netip.ParseAddr(remote.IP)
		if err != nil || addr.Zone() != "" {
			return nil, fmt.Errorf("encode idle lease permission %d IP: invalid address %q", i, remote.IP)
		}
		if addr.Is4() {
			b = append(b, 4)
			v := addr.As4()
			b = append(b, v[:]...)
		} else {
			b = append(b, 6)
			v := addr.As16()
			b = append(b, v[:]...)
		}
		b = binary.LittleEndian.AppendUint16(b, remote.Port)
	}
	if b, err = putLeaseString(b, l.TranslatedIP); err != nil {
		return nil, fmt.Errorf("encode idle lease TranslatedIP: %w", err)
	}
	b = binary.LittleEndian.AppendUint16(b, l.TranslatedPort)
	var addressOnly byte
	if l.AddressOnly {
		addressOnly = 1
	}
	b = append(b, addressOnly)
	b = binary.LittleEndian.AppendUint64(b, l.RemainingNs)
	b = binary.LittleEndian.AppendUint64(b, l.TimeoutNs)
	if deterministicLayout {
		var deterministic byte
		if l.Deterministic {
			deterministic = 1
		}
		b = append(b, deterministic)
		b = append(b, l.DeterministicMode)
		b = binary.LittleEndian.AppendUint16(b, l.DeterministicBlockSize)
		b = binary.LittleEndian.AppendUint16(b, l.DeterministicBlocksPerIP)
		b = append(b, l.DeterministicHostPrefixLen)
		if b, err = putLeaseString(b, l.DeterministicHostBase); err != nil {
			return nil, fmt.Errorf("encode idle lease DeterministicHostBase: %w", err)
		}
		b = binary.LittleEndian.AppendUint32(b, l.DeterministicHostCount)
	}
	if provenanceLayout {
		if l.MintFromZone == nil {
			b = append(b, 0)
		} else {
			b = append(b, 1)
			if b, err = putLeaseString(b, *l.MintFromZone); err != nil {
				return nil, fmt.Errorf("encode idle lease MintFromZone: %w", err)
			}
		}
	}
	if typedPoolLayout {
		b = append(b, l.PoolKind)
		if b, err = putLeaseString(b, l.Nat64Prefix); err != nil {
			return nil, fmt.Errorf("encode idle lease Nat64Prefix: %w", err)
		}
		if b, err = putLeaseString(b, l.Nat64Scope); err != nil {
			return nil, fmt.Errorf("encode idle lease Nat64Scope: %w", err)
		}
	}
	return b, nil
}

// decodePersistentNatLeasePayload parses one lease advertisement batch. The
// bool reports whether the payload decoded COMPLETELY: callers reject a
// malformed batch rather than installing a prefix; absent records never
// retract state already installed on the peer.
func decodePersistentNatLeasePayload(buf []byte) ([]userspace.IdleLeaseWire, bool) {
	return decodePersistentNatLeasePayloadLayout(buf, false)
}

func decodePersistentNatLeasePayloadDeterministic(buf []byte) ([]userspace.IdleLeaseWire, bool) {
	return decodePersistentNatLeasePayloadLayout(buf, true)
}

func decodePersistentNatLeasePayloadLayout(buf []byte, deterministicLayout bool) ([]userspace.IdleLeaseWire, bool) {
	return decodePersistentNatLeasePayloadLayoutWithProvenance(buf, deterministicLayout, false)
}

func decodePersistentNatLeasePayloadLayoutWithProvenance(
	buf []byte, deterministicLayout, provenanceLayout bool,
) ([]userspace.IdleLeaseWire, bool) {
	return decodePersistentNatLeasePayloadLayoutTyped(buf, deterministicLayout, provenanceLayout, false)
}

func decodePersistentNatLeasePayloadLayoutTyped(
	buf []byte, deterministicLayout, provenanceLayout, typedPoolLayout bool,
) ([]userspace.IdleLeaseWire, bool) {
	if len(buf) < 4 {
		return nil, false
	}
	count := int(binary.LittleEndian.Uint32(buf))
	off := 4
	// #8792: SIZE THE ALLOCATION FROM THE BUFFER, NOT FROM THE WIRE.
	//
	// `count` is untrusted on-wire data and the make() below sizes its
	// preallocation from it, so the loop's bounds check — one line further down
	// — fires only AFTER the allocation it was meant to protect. A four-byte
	// frame of `ff ff ff ff` asks for 2^32-1 records of 112 bytes each, roughly
	// 448 GiB, before a single length prefix has been read.
	//
	// Every record costs at least its own 4-byte length prefix, so the body
	// after the count can hold at most (len(buf)-4)/4 of them. A count above
	// that cannot describe THIS frame under any encoding, so it is refused
	// rather than clamped. The decoder's bool means "decoded COMPLETELY", and
	// installing a partial batch would admit an incomplete message rather than
	// the sender's intended advertisement.
	//
	// The DHCP sibling in sync_protocol.go CLAMPS and continues on the same
	// input, and that divergence is deliberate: #7175 fixed it under a contract
	// that separates a wrong COUNT from lost DATA, and
	// TestDHCPFullSetStillToleratesAnOverDeclaredCount7175 pins the tolerance.
	// This decoder has no such separation to make.
	//
	// What this is NOT: a claim about crashing. Whether the oversized make()
	// is fatal depends on the host — 112 * (2^32-1) stays under the runtime's
	// maxAlloc, so no makeslice panic is inherent, and under
	// overcommit_memory=1 the mapping can succeed unbacked and the process
	// survives to discard the frame. The invariant repaired here holds in every
	// environment: a count the body cannot physically hold is rejected BEFORE
	// the allocation. Note also that the receive loop's defer only disconnects;
	// it is not a recovery boundary, so wrapping the decoder in recover() would
	// not be a fix where the allocation IS fatal — a Go runtime OOM is a fatal
	// error, not a panic.
	if maxRecords := (len(buf) - 4) / 4; count < 0 || count > maxRecords {
		return nil, false
	}
	out := make([]userspace.IdleLeaseWire, 0, count)
	for range count {
		// Checked SUBTRACTION rather than `off+4 > len(buf)`. NOT LOAD-BEARING,
		// and said so rather than left to look like part of the fix: with the
		// count now bounded above, `off` and `n` are both bounded and the
		// additive form cannot overflow on any reachable input — mutating this
		// back to `off+n > len(buf)` does NOT red the #8792 cell. It is kept as
		// shape hygiene, because the additive form is what overflows when one
		// operand comes off the wire, and a future change that loosens the
		// bound above would silently re-arm it.
		if len(buf)-off < 4 {
			return out, false
		}
		n := int(binary.LittleEndian.Uint32(buf[off:]))
		off += 4
		if n < 0 || n > len(buf)-off {
			return out, false
		}
		rec, ok := decodeOnePersistentNatLeaseLayoutTyped(
			buf[off:off+n], deterministicLayout, provenanceLayout, typedPoolLayout)
		if !ok {
			return out, false
		}
		out = append(out, rec)
		off += n
	}
	return out, true
}

// persistentNatLeaseIsDeterministic reports whether a lease carries any
// deterministic identity and therefore needs the #14638 record layout.
func persistentNatLeaseIsDeterministic(l userspace.IdleLeaseWire) bool {
	return l.Deterministic || l.DeterministicMode != 0 || l.DeterministicBlockSize != 0 ||
		l.DeterministicBlocksPerIP != 0 || l.DeterministicHostPrefixLen != 0 ||
		l.DeterministicHostBase != "" || l.DeterministicHostCount != 0
}

// persistentNatLeaseBatchLayouts detects optional record layouts in one pass.
func persistentNatLeaseBatchLayouts(batch userspace.PersistentNatLeaseBatch) (deterministic, provenance bool) {
	for _, l := range batch.Leases {
		deterministic = deterministic || persistentNatLeaseIsDeterministic(l)
		provenance = provenance || l.MintFromZone != nil
		if deterministic && provenance {
			return true, true
		}
	}
	return deterministic, provenance
}

func persistentNatLeaseBatchIsDeterministic(batch userspace.PersistentNatLeaseBatch) bool {
	deterministic, _ := persistentNatLeaseBatchLayouts(batch)
	return deterministic
}

// encodePersistentNatLeaseBatchPayload wraps the scoped lease rows with the
// sender's stable origin and durable clear generation. Empty lease sets are
// meaningful: they still carry the generation barrier after a clear.
func encodePersistentNatLeaseBatchPayload(batch userspace.PersistentNatLeaseBatch) ([]byte, error) {
	return encodePersistentNatLeaseBatchPayloadLayout(batch, persistentNatLeaseBatchIsDeterministic(batch))
}

func encodePersistentNatLeaseBatchPayloadLayout(batch userspace.PersistentNatLeaseBatch, deterministic bool) ([]byte, error) {
	if len(batch.OriginID) != 32 {
		return nil, errors.New("persistent-NAT batch origin must be 16-byte hex")
	}
	if _, err := hex.DecodeString(batch.OriginID); err != nil {
		return nil, fmt.Errorf("persistent-NAT batch origin: %w", err)
	}
	b, err := putLeaseString(nil, batch.OriginID)
	if err != nil {
		return nil, fmt.Errorf("encode persistent-NAT batch origin: %w", err)
	}
	b = binary.LittleEndian.AppendUint64(b, batch.Generation)
	if deterministic {
		return append(b, encodePersistentNatLeasePayloadDeterministic(batch.Leases)...), nil
	}
	return append(b, encodePersistentNatLeasePayload(batch.Leases)...), nil
}

// persistentNatLeaseFrameBudget is the per-frame byte budget for one
// chunked lease frame (#14607): the shared receive cap minus the
// origin/generation envelope, the lease count prefix, and the full-set
// sequence trailer the sender appends. Every frame produced by
// encodePersistentNatLeaseBatchFrames — envelope + records + trailer —
// stays at or below maxSyncPayload.
const persistentNatLeaseFrameBudget = maxSyncPayload - 64

type persistentNatLeaseFrame struct {
	payload       []byte
	deterministic bool
	provenance    bool
	typedPool     bool
}

// encodePersistentNatLeaseBatchFrames encodes one origin/generation batch
// as one or more complete batch payloads (WITHOUT the full-set trailer),
// each within persistentNatLeaseFrameBudget. Records are additive within
// one generation and advancing the generation clears the receiver before
// import, so delivering chunks of the same generation in order rebuilds
// exactly the sender's set: the first frame carries the generation barrier,
// and later chunks add to it. Empty batches and batches with no encodable
// records yield exactly one barrier frame. A lease whose single record cannot
// fit any frame is dropped and counted by the caller via the returned dropped
// count — it is never emitted over-cap.
func encodePersistentNatLeaseBatchFrames(batch userspace.PersistentNatLeaseBatch) ([][]byte, error) {
	frames, _, err := encodePersistentNatLeaseBatchFramesCountedLayout(batch)
	if err != nil {
		return nil, err
	}
	payloads := make([][]byte, 0, len(frames))
	for _, frame := range frames {
		payloads = append(payloads, frame.payload)
	}
	return payloads, nil
}

func encodePersistentNatLeaseBatchFramesCounted(batch userspace.PersistentNatLeaseBatch) ([][]byte, int, error) {
	frames, dropped, err := encodePersistentNatLeaseBatchFramesCountedLayout(batch)
	if err != nil {
		return nil, 0, err
	}
	payloads := make([][]byte, 0, len(frames))
	for _, frame := range frames {
		payloads = append(payloads, frame.payload)
	}
	return payloads, dropped, nil
}

// encodePersistentNatLeaseBatchFramesCountedLayout splits mixed batches by
// record layout. Legacy-layout frames are emitted first; deterministic records
// follow under the same origin/generation. Provenance is optional and selected
// by the sender only for a peer that advertised support.
func encodePersistentNatLeaseBatchFramesCountedLayout(batch userspace.PersistentNatLeaseBatch) ([]persistentNatLeaseFrame, int, error) {
	deterministic, _ := persistentNatLeaseBatchLayouts(batch)
	return encodePersistentNatLeaseBatchFramesCountedLayoutCore(batch, deterministic, false)
}

func encodePersistentNatLeaseBatchFramesCountedLayoutWithProvenance(
	batch userspace.PersistentNatLeaseBatch, provenance bool,
) ([]persistentNatLeaseFrame, int, error) {
	deterministic, _ := persistentNatLeaseBatchLayouts(batch)
	return encodePersistentNatLeaseBatchFramesCountedLayoutCore(batch, deterministic, provenance)
}

func encodePersistentNatLeaseBatchFramesCountedLayoutCore(
	batch userspace.PersistentNatLeaseBatch, deterministic, provenance bool,
) ([]persistentNatLeaseFrame, int, error) {
	return encodePersistentNatLeaseBatchFramesCountedLayoutCoreTyped(batch, deterministic, provenance, false)
}

func encodePersistentNatLeaseBatchFramesCountedLayoutCoreTyped(
	batch userspace.PersistentNatLeaseBatch, deterministic, provenance, typedPool bool,
) ([]persistentNatLeaseFrame, int, error) {
	if len(batch.OriginID) != 32 {
		return nil, 0, errors.New("persistent-NAT batch origin must be 16-byte hex")
	}
	if _, err := hex.DecodeString(batch.OriginID); err != nil {
		return nil, 0, fmt.Errorf("persistent-NAT batch origin: %w", err)
	}
	envelope, err := putLeaseString(nil, batch.OriginID)
	if err != nil {
		return nil, 0, fmt.Errorf("encode persistent-NAT batch origin: %w", err)
	}
	envelope = binary.LittleEndian.AppendUint64(envelope, batch.Generation)

	var frames []persistentNatLeaseFrame
	dropped := 0
	for _, deterministicLayout := range []bool{false, true} {
		groupFrames, groupDropped := encodePersistentNatLeaseLayoutFrames(
			batch.Leases, envelope, deterministicLayout, provenance, typedPool, false,
		)
		frames = append(frames, groupFrames...)
		dropped += groupDropped
	}
	if len(frames) == 0 {
		emptyFrames, _ := encodePersistentNatLeaseLayoutFrames(
			nil, envelope, deterministic, provenance, typedPool, true,
		)
		frames = append(frames, emptyFrames...)
	}
	return frames, dropped, nil
}

func encodePersistentNatLeaseLayoutFrames(
	leases []userspace.IdleLeaseWire, envelope []byte, deterministic, provenance, typedPool, emitEmpty bool,
) ([]persistentNatLeaseFrame, int) {
	overhead := len(envelope) + 4
	var frames []persistentNatLeaseFrame
	var cur [][]byte
	curBytes := overhead
	flush := func() {
		b := make([]byte, 0, curBytes)
		b = append(b, envelope...)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(cur)))
		for _, rec := range cur {
			b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
			b = append(b, rec...)
		}
		frames = append(frames, persistentNatLeaseFrame{
			payload: b, deterministic: deterministic, provenance: provenance, typedPool: typedPool,
		})
		cur = nil
		curBytes = overhead
	}
	dropped := 0
	for _, l := range leases {
		if persistentNatLeaseIsDeterministic(l) != deterministic {
			continue
		}
		if !typedPool {
			// Legacy peer: strip the typed identity so the record falls
			// back to the in-band string exactly as a pre-#17099 sender's
			// would (#17099 one-release decode fallback).
			l.PoolKind = 0
			l.Nat64Prefix = ""
			l.Nat64Scope = ""
		}
		rec, err := encodeOnePersistentNatLeaseLayoutTyped(l, deterministic, provenance, typedPool)
		if err != nil {
			slog.Warn("cluster sync: dropping unencodable persistent-NAT lease from sync push",
				"pool", l.Pool, "src", l.SrcIP, "err", err)
			dropped++
			continue
		}
		need := 4 + len(rec)
		if overhead+need > persistentNatLeaseFrameBudget {
			slog.Warn("cluster sync: dropping persistent-NAT lease exceeding sync frame budget",
				"pool", l.Pool, "src", l.SrcIP, "record_bytes", len(rec), "budget", persistentNatLeaseFrameBudget)
			dropped++
			continue
		}
		if len(cur) > 0 && curBytes+need > persistentNatLeaseFrameBudget {
			flush()
		}
		cur = append(cur, rec)
		curBytes += need
	}
	if len(cur) > 0 || emitEmpty {
		flush()
	}
	return frames, dropped
}

func decodePersistentNatLeaseBatchPayload(buf []byte) (userspace.PersistentNatLeaseBatch, bool) {
	return decodePersistentNatLeaseBatchPayloadLayout(buf, false)
}

func decodePersistentNatLeaseBatchPayloadDeterministic(buf []byte) (userspace.PersistentNatLeaseBatch, bool) {
	return decodePersistentNatLeaseBatchPayloadLayout(buf, true)
}
func decodePersistentNatLeaseBatchPayloadProvenance(
	buf []byte, deterministic bool,
) (userspace.PersistentNatLeaseBatch, bool) {
	return decodePersistentNatLeaseBatchPayloadLayoutWithProvenance(buf, deterministic, true)
}

func decodePersistentNatLeaseBatchPayloadTypedPool(
	buf []byte, deterministic bool,
) (userspace.PersistentNatLeaseBatch, bool) {
	return decodePersistentNatLeaseBatchPayloadLayoutTyped(buf, deterministic, true, true)
}

func decodePersistentNatLeaseBatchPayloadLayout(buf []byte, deterministic bool) (userspace.PersistentNatLeaseBatch, bool) {
	return decodePersistentNatLeaseBatchPayloadLayoutWithProvenance(buf, deterministic, false)
}

func decodePersistentNatLeaseBatchPayloadLayoutWithProvenance(
	buf []byte, deterministic, provenance bool,
) (userspace.PersistentNatLeaseBatch, bool) {
	return decodePersistentNatLeaseBatchPayloadLayoutTyped(buf, deterministic, provenance, false)
}

func decodePersistentNatLeaseBatchPayloadLayoutTyped(
	buf []byte, deterministic, provenance, typedPool bool,
) (userspace.PersistentNatLeaseBatch, bool) {
	var batch userspace.PersistentNatLeaseBatch
	origin, off, ok := getLeaseString(buf, 0)
	if !ok || len(origin) != 32 {
		return batch, false
	}
	if _, err := hex.DecodeString(origin); err != nil {
		return batch, false
	}
	if len(buf)-off < 8 {
		return batch, false
	}
	batch.OriginID = origin
	batch.Generation = binary.LittleEndian.Uint64(buf[off:])
	batch.Leases, ok = decodePersistentNatLeasePayloadLayoutTyped(
		buf[off+8:], deterministic, provenance, typedPool)
	if !ok {
		return userspace.PersistentNatLeaseBatch{}, false
	}
	return batch, true
}

func decodeOnePersistentNatLeaseLayout(buf []byte, deterministicLayout bool) (userspace.IdleLeaseWire, bool) {
	return decodeOnePersistentNatLeaseLayoutWithProvenance(buf, deterministicLayout, false)
}

func decodeOnePersistentNatLeaseLayoutWithProvenance(
	buf []byte, deterministicLayout, provenanceLayout bool,
) (userspace.IdleLeaseWire, bool) {
	return decodeOnePersistentNatLeaseLayoutTyped(buf, deterministicLayout, provenanceLayout, false)
}

func decodeOnePersistentNatLeaseLayoutTyped(
	buf []byte, deterministicLayout, provenanceLayout, typedPoolLayout bool,
) (userspace.IdleLeaseWire, bool) {
	var l userspace.IdleLeaseWire
	off := 0
	var ok bool
	if l.Pool, off, ok = getLeaseString(buf, off); !ok {
		return l, false
	}
	if off >= len(buf) {
		return l, false
	}
	l.Protocol = buf[off]
	off++
	if off+4 > len(buf) {
		return l, false
	}
	scope := binary.LittleEndian.Uint32(buf[off:])
	l.RoutingScope = &scope
	off += 4
	if off+4 > len(buf) {
		return l, false
	}
	egressScope := binary.LittleEndian.Uint32(buf[off:])
	l.EgressScope = &egressScope
	off += 4
	if l.SrcIP, off, ok = getLeaseString(buf, off); !ok {
		return l, false
	}
	if off+2 > len(buf) {
		return l, false
	}
	l.SrcPort = binary.LittleEndian.Uint16(buf[off:])
	off += 2
	if l.RemoteIP, off, ok = getLeaseString(buf, off); !ok {
		return l, false
	}
	if off+2 > len(buf) {
		return l, false
	}
	l.RemotePort = binary.LittleEndian.Uint16(buf[off:])
	off += 2
	if off >= len(buf) || buf[off] > 1 {
		return l, false
	}
	l.PermitAnyRemote = buf[off] == 1
	off++
	if len(buf)-off < 2 {
		return l, false
	}
	remoteCount := int(binary.LittleEndian.Uint16(buf[off:]))
	off += 2
	if remoteCount > maxPersistentNatLeaseRemoteCount {
		return l, false
	}
	l.PermittedRemotes = make([]userspace.PersistentNatRemote, 0, remoteCount)
	for range remoteCount {
		if off >= len(buf) {
			return l, false
		}
		family := buf[off]
		off++
		addressBytes := 4
		if family == 6 {
			addressBytes = 16
		} else if family != 4 {
			return l, false
		}
		if len(buf)-off < addressBytes+2 {
			return l, false
		}
		var addr netip.Addr
		if family == 4 {
			var raw [4]byte
			copy(raw[:], buf[off:off+4])
			addr = netip.AddrFrom4(raw)
		} else {
			var raw [16]byte
			copy(raw[:], buf[off:off+16])
			addr = netip.AddrFrom16(raw)
		}
		off += addressBytes
		port := binary.LittleEndian.Uint16(buf[off:])
		off += 2
		l.PermittedRemotes = append(l.PermittedRemotes,
			userspace.PersistentNatRemote{IP: addr.String(), Port: port})
	}

	if l.TranslatedIP, off, ok = getLeaseString(buf, off); !ok {
		return l, false
	}
	if off+2 > len(buf) {
		return l, false
	}
	l.TranslatedPort = binary.LittleEndian.Uint16(buf[off:])
	off += 2
	if off >= len(buf) {
		return l, false
	}
	l.AddressOnly = buf[off] == 1
	off++
	if off+16 > len(buf) {
		return l, false
	}
	l.RemainingNs = binary.LittleEndian.Uint64(buf[off:])
	l.TimeoutNs = binary.LittleEndian.Uint64(buf[off+8:])
	off += 16
	// Clamp peer lifetimes to the schema maximum and advertised timeout.
	// Export samples its clock before taking the allocator lock, so a release
	// can legitimately re-arm expiry between the remaining/timeout snapshots.
	if l.RemainingNs == 0 || l.TimeoutNs < minPersistentNatLeaseTimeoutNS {
		return l, false
	}
	if l.TimeoutNs > maxPersistentNatLeaseLifetimeNS {
		l.TimeoutNs = maxPersistentNatLeaseLifetimeNS
	}
	if l.RemainingNs > l.TimeoutNs {
		l.RemainingNs = l.TimeoutNs
	}
	if deterministicLayout {
		if off >= len(buf) || buf[off] > 1 {
			return l, false
		}
		l.Deterministic = buf[off] == 1
		off++
		if off >= len(buf) {
			return l, false
		}
		l.DeterministicMode = buf[off]
		off++
		if l.Deterministic && l.DeterministicMode != 1 && l.DeterministicMode != 2 {
			return l, false
		}
		if !l.Deterministic && l.DeterministicMode != 0 {
			return l, false
		}
		if len(buf)-off < 5 {
			return l, false
		}
		l.DeterministicBlockSize = binary.LittleEndian.Uint16(buf[off:])
		l.DeterministicBlocksPerIP = binary.LittleEndian.Uint16(buf[off+2:])
		l.DeterministicHostPrefixLen = buf[off+4]
		off += 5
		if l.DeterministicHostBase, off, ok = getLeaseString(buf, off); !ok {
			return l, false
		}
		if len(buf)-off < 4 {
			return l, false
		}
		l.DeterministicHostCount = binary.LittleEndian.Uint32(buf[off:])
		off += 4
		if l.Deterministic {
			if l.DeterministicBlockSize == 0 || l.DeterministicBlocksPerIP == 0 || l.DeterministicHostCount == 0 {
				return l, false
			}
			addr, err := netip.ParseAddr(l.DeterministicHostBase)
			if err != nil || addr.Zone() != "" {
				return l, false
			}
			if l.DeterministicMode == 1 && !addr.Is4() {
				return l, false
			}
			if l.DeterministicMode == 2 && !addr.Is6() {
				return l, false
			}
		} else if l.DeterministicBlockSize != 0 || l.DeterministicBlocksPerIP != 0 ||
			l.DeterministicHostPrefixLen != 0 || l.DeterministicHostBase != "" ||
			l.DeterministicHostCount != 0 {
			return l, false
		}
	}
	if provenanceLayout {
		if off >= len(buf) || buf[off] > 1 {
			return l, false
		}
		hasMintFromZone := buf[off] == 1
		off++
		if hasMintFromZone {
			mintFromZone, next, ok := getLeaseString(buf, off)
			if !ok {
				return l, false
			}
			l.MintFromZone = &mintFromZone
			off = next
		}
	}

	if typedPoolLayout {
		if off >= len(buf) {
			return l, false
		}
		l.PoolKind = buf[off]
		off++
		if l.PoolKind > 3 {
			return l, false
		}
		if l.Nat64Prefix, off, ok = getLeaseString(buf, off); !ok {
			return l, false
		}
		if l.Nat64Scope, off, ok = getLeaseString(buf, off); !ok {
			return l, false
		}
		if (l.PoolKind == 2 || l.PoolKind == 3) && (l.Nat64Prefix == "" || l.Nat64Scope == "") {
			return l, false
		}
		if l.PoolKind < 2 && (l.Nat64Prefix != "" || l.Nat64Scope != "") {
			return l, false
		}
	}

	// Each message type has one exact layout; only successor types parse
	// their trailing fields. Any remaining bytes are a layout mismatch.
	return l, off == len(buf)
}

func decodeOnePersistentNatLease(buf []byte) (userspace.IdleLeaseWire, bool) {
	return decodeOnePersistentNatLeaseLayout(buf, false)
}

func decodeOnePersistentNatLeaseDeterministic(buf []byte) (userspace.IdleLeaseWire, bool) {
	return decodeOnePersistentNatLeaseLayout(buf, true)
}

// QueuePersistentNatLeaseBatch sends one sender-origin/generation snapshot
// as one or more sub-cap frames (#14607). Provenance-bearing types 50/51 are
// selected only after the peer advertises support; an unlearned or older peer
// receives the compatible 41/43 layout so ordinary lease refreshes continue.
// Empty batches still send the legacy generation barrier. All chunks share the
// batch origin/generation and are written in order under writeMu, each with its
// own increasing full-set sequence, so the peer applies the barrier first.
func (s *SessionSync) QueuePersistentNatLeaseBatch(batch userspace.PersistentNatLeaseBatch) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	deterministic, hasProvenance := persistentNatLeaseBatchLayouts(batch)
	provenance := hasProvenance && s.peerCapabilitiesLearned() && s.PersistentNatLeaseProvenanceCapable()
	typedPool := s.peerCapabilitiesLearned() && s.PersistentNatLeaseTypedPoolCapable()
	if typedPool {
		// Typed frames always carry the provenance section (possibly a
		// bare absent marker) so the layout stays fixed per type.
		provenance = true
	}
	frames, dropped, err := encodePersistentNatLeaseBatchFramesCountedLayoutCoreTyped(
		batch, deterministic, provenance, typedPool)
	if err != nil {
		slog.Warn("cluster sync: refusing invalid persistent-NAT lease batch", "err", err)
		s.stats.MalformedRecordsDropped.Add(1)
		return
	}
	if dropped > 0 {
		s.stats.MalformedRecordsDropped.Add(uint64(dropped))
	}
	for _, frame := range frames {
		if len(frame.payload)+fullSetSeqTrailerLen > maxSyncPayload {
			slog.Warn("cluster sync: refusing oversize persistent-NAT lease frame",
				"bytes", len(frame.payload)+fullSetSeqTrailerLen, "cap", maxSyncPayload)
			s.stats.MalformedRecordsDropped.Add(1)
			return
		}
		seq := s.persistentNatLeaseSeqCounter.Add(1)
		payload := appendFullSetSeq(frame.payload, s.syncEpoch, seq)
		msgType := uint8(syncMsgPersistentNatLeaseGeneration)
		if frame.provenance {
			msgType = syncMsgPersistentNatLeaseProvenance
		}
		if frame.deterministic {
			msgType = syncMsgPersistentNatLeaseDeterministic
			if frame.provenance {
				msgType = syncMsgPersistentNatLeaseDeterministicProvenance
			}
		}
		if frame.typedPool {
			msgType = syncMsgPersistentNatLeaseTypedPool
			if frame.deterministic {
				msgType = syncMsgPersistentNatLeaseDeterministicTypedPool
			}
		}
		s.writeMu.Lock()
		err = writeMsg(conn, msgType, payload)
		s.writeMu.Unlock()
		if err != nil {
			slog.Warn("cluster sync: persistent-NAT lease send error", "err", err)
			s.stats.Errors.Add(1)
			s.handleDisconnect(conn)
			return
		}
	}
	slog.Debug("cluster sync: persistent-NAT lease generation batch sent",
		"count", len(batch.Leases), "generation", batch.Generation, "frames", len(frames))
}
