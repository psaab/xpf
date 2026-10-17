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
// The generation-bearing message type and replay semantics remain unchanged;
// only its self-contained lease record gains permission fields. Do not bump
// SessionSyncWireVersion / CurrentHAProtocolVersion: the message is length
// framed, and a receiver with the old record layout rejects the mismatched
// record instead of installing a permission-less lease. During version skew
// the safe degradation is loss of the idle lease until a compatible push.
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
	recs := make([][]byte, 0, len(leases))
	for _, l := range leases {
		rec, err := encodeOnePersistentNatLease(l)
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
	return b, nil
}

// decodePersistentNatLeasePayload parses one lease advertisement batch. The
// bool reports whether the payload decoded COMPLETELY: callers reject a
// malformed batch rather than installing a prefix; absent records never
// retract state already installed on the peer.
func decodePersistentNatLeasePayload(buf []byte) ([]userspace.IdleLeaseWire, bool) {
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
	for i := 0; i < count; i++ {
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
		rec, ok := decodeOnePersistentNatLease(buf[off : off+n])
		if !ok {
			return out, false
		}
		out = append(out, rec)
		off += n
	}
	return out, true
}

// encodePersistentNatLeaseBatchPayload wraps the scoped lease rows with the
// sender's stable origin and durable clear generation. Empty lease sets are
// meaningful: they still carry the generation barrier after a clear.
func encodePersistentNatLeaseBatchPayload(batch userspace.PersistentNatLeaseBatch) ([]byte, error) {
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
	return append(b, encodePersistentNatLeasePayload(batch.Leases)...), nil
}

// persistentNatLeaseFrameBudget is the per-frame byte budget for one
// chunked lease frame (#14607): the shared receive cap minus the
// origin/generation envelope, the lease count prefix, and the full-set
// sequence trailer the sender appends. Every frame produced by
// encodePersistentNatLeaseBatchFrames — envelope + records + trailer —
// stays at or below maxSyncPayload.
const persistentNatLeaseFrameBudget = maxSyncPayload - 64

// encodePersistentNatLeaseBatchFrames encodes one origin/generation batch
// as one or more complete batch payloads (WITHOUT the full-set trailer),
// each within persistentNatLeaseFrameBudget. Records are additive within
// one generation and advancing the generation clears the receiver before
// import, so delivering chunks of the same generation in order rebuilds
// exactly the sender's set: the first chunk carries the generation barrier
// (clearing stale state) and later chunks add to it. An empty batch yields
// exactly one frame so the barrier still reaches the peer. A lease whose
// single record cannot fit any frame is dropped and counted by the caller
// via the returned dropped count — it is never emitted over-cap.
func encodePersistentNatLeaseBatchFrames(batch userspace.PersistentNatLeaseBatch) ([][]byte, error) {
	frames, _, err := encodePersistentNatLeaseBatchFramesCounted(batch)
	return frames, err
}

func encodePersistentNatLeaseBatchFramesCounted(batch userspace.PersistentNatLeaseBatch) ([][]byte, int, error) {
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
	// Per-frame overhead: envelope + 4-byte count + 4-byte per-record prefix.
	overhead := len(envelope) + 4

	var frames [][]byte
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
		frames = append(frames, b)
		cur = nil
		curBytes = overhead
	}
	dropped := 0
	for _, l := range batch.Leases {
		rec, err := encodeOnePersistentNatLease(l)
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
	// Always emit a final frame: for an empty (or all-dropped) batch this is
	// the sole generation-barrier frame; otherwise it carries the tail chunk.
	flush()
	return frames, dropped, nil
}

func decodePersistentNatLeaseBatchPayload(buf []byte) (userspace.PersistentNatLeaseBatch, bool) {
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
	batch.Leases, ok = decodePersistentNatLeasePayload(buf[off+8:])
	if !ok {
		return userspace.PersistentNatLeaseBatch{}, false
	}
	return batch, true
}

func decodeOnePersistentNatLease(buf []byte) (userspace.IdleLeaseWire, bool) {
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
	// The permission-bearing record is self-contained: trailing bytes are not
	// an append-only extension because they could hide a layout mismatch.
	return l, off == len(buf)
}

// QueuePersistentNatLeaseBatch sends one sender-origin/generation snapshot
// as one or more sub-cap frames (#14607). Empty batches are sent too so a
// clear generation reaches the peer even when no idle leases remain. All
// chunks share the batch origin/generation and are written in order under
// writeMu, each with its own increasing full-set sequence, so the peer
// applies the generation barrier on the first chunk and adds the rest.
func (s *SessionSync) QueuePersistentNatLeaseBatch(batch userspace.PersistentNatLeaseBatch) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	frames, dropped, err := encodePersistentNatLeaseBatchFramesCounted(batch)
	if err != nil {
		slog.Warn("cluster sync: refusing invalid persistent-NAT lease batch", "err", err)
		s.stats.MalformedRecordsDropped.Add(1)
		return
	}
	if dropped > 0 {
		s.stats.MalformedRecordsDropped.Add(uint64(dropped))
	}
	for _, frame := range frames {
		if len(frame)+fullSetSeqTrailerLen > maxSyncPayload {
			slog.Warn("cluster sync: refusing oversize persistent-NAT lease frame",
				"bytes", len(frame)+fullSetSeqTrailerLen, "cap", maxSyncPayload)
			s.stats.MalformedRecordsDropped.Add(1)
			return
		}
		seq := s.persistentNatLeaseSeqCounter.Add(1)
		payload := appendFullSetSeq(frame, s.syncEpoch, seq)
		s.writeMu.Lock()
		err = writeMsg(conn, syncMsgPersistentNatLeaseGeneration, payload)
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
