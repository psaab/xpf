package cluster

import (
	"encoding/binary"
	"log/slog"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #15160 (B03-01): chunked DHCP lease full-sets.
//
// A family's Kea lease set has no count cap in pkg/dhcpserver and the Kea
// read bound is 64 MiB, but the session-sync receiveLoop refuses any frame
// over maxSyncPayload (16 MiB) by RETURNING — tearing down the connection
// that also carries sessions, IPsec SAs and config — and the forced
// re-push on reconnect repeats the cycle. queueDHCPLeaseSnapshot used to
// encode the whole set as one frame regardless of size.
//
// The fix mirrors #14607 (persistent-NAT batches): when the encoded set
// (metadata + full-set trailer included) exceeds the cap, the sender
// splits the lease RECORDS across sub-cap chunk frames of new additive
// message types (syncMsgDHCPLeaseV4Chunk/V6Chunk). Each chunk payload is:
//
//	{ generation u64 | index u32 | total u32 | totalLeases u32 | body }
//
// where generation is the set's first full-set sequence number (its
// identity), and body is a standard count-prefixed DHCP lease chunk
// (encodeDHCPLeasePayload of the chunk's leases). The #10170 authority
// trailer rides the LAST chunk only, ahead of the full-set sequence
// trailer every frame carries. Chunk frames each carry their own
// increasing full-set seq; the receiver admits chunks in seq order and
// assembles by (incarnation, generation), committing the concatenated
// set atomically — held-set store + high-water advance + callback under
// dhcpApplyMu, exactly like a legacy frame — only when every chunk has
// arrived. An unclosed generation never commits (the #7175 posture: the
// prior set is retained), and a newer legacy or chunked set supersedes a
// pending assembly, which is discarded.
//
// Budget: each chunk's wire payload (chunk header + body + optional
// authority trailer + full-set trailer) must stay <= maxSyncPayload. The
// sender budgets the lease body at dhcpChunkFrameBudget, reserving the
// header, trailer and a generous authority-trailer allowance; the final
// per-frame size check in queueDHCPLeaseSnapshot is defense in depth.
// A single lease whose record cannot fit any frame is dropped and
// counted by the caller — never emitted over-cap.

// dhcpChunkHeaderLen is the fixed chunk envelope: generation(8) +
// index(4) + total(4) + totalLeases(4).
const dhcpChunkHeaderLen = 20

// dhcpChunkFrameBudget is the per-chunk lease-body budget. It reserves the
// chunk header, the full-set sequence trailer, and 4096 bytes for the
// #10170 authority trailer (scope records are ~20 bytes each; a snapshot
// with more scopes than that allowance keeps the legacy single-frame path
// below the cap or, if the set itself is over-cap, the authority trailer
// still rides the last chunk and the sender's final size check refuses —
// fail-closed with a count — rather than emitting an over-cap frame).
const dhcpChunkFrameBudget = maxSyncPayload - dhcpChunkHeaderLen - fullSetSeqTrailerLen - 4096

// dhcpChunkGeneration is the assembly identity of one chunked set.
type dhcpChunkGeneration struct {
	incarnation uint64
	generation  uint64
}

// dhcpChunkAssembly is one in-progress chunked set on the receiver.
type dhcpChunkAssembly struct {
	total       uint32
	totalLeases uint32
	parts       map[uint32][]dhcpserver.SyncLease
	received    uint32 // leases accumulated so far
	have        int    // distinct chunks present
}

// dhcpChunkState is the receiver's per-family assembly table. Only
// dhcpApplyMu holders touch it (the chunk commit path and the legacy
// commit's supersede), so it needs no lock of its own; the zero value
// (nil map) is valid.
type dhcpChunkState struct {
	pending map[dhcpChunkGeneration]*dhcpChunkAssembly
}

// encodeDHCPLeaseChunkPayload builds one chunk payload (WITHOUT the
// full-set trailer): the fixed header followed by the chunk body (a
// standard count-prefixed lease body, possibly with the #10170 authority
// trailer already appended by the caller on the last chunk — no: the
// trailer is appended by queueDHCPLeaseSnapshot AFTER this envelope, so
// stripDHCPLeaseSnapshotMeta sees it at the very end of the base).
func encodeDHCPLeaseChunkPayload(leaseBody []byte, generation uint64, index, total, totalLeases uint32) []byte {
	out := make([]byte, 0, dhcpChunkHeaderLen+len(leaseBody))
	out = binary.LittleEndian.AppendUint64(out, generation)
	out = binary.LittleEndian.AppendUint32(out, index)
	out = binary.LittleEndian.AppendUint32(out, total)
	out = binary.LittleEndian.AppendUint32(out, totalLeases)
	return append(out, leaseBody...)
}

// decodeDHCPLeaseChunkHeader parses and validates the fixed chunk header.
// ok is false for any truncated or internally inconsistent header: index
// must be < total, total must be in [1, 1<<20] (a real set needs a handful
// of 16 MiB chunks; the bound keeps a forged total from preallocating
// assembly state), and totalLeases must be nonzero for a chunked set (an
// empty set always fits the legacy frame and is never chunked).
func decodeDHCPLeaseChunkHeader(payload []byte) (generation uint64, index, total, totalLeases uint32, body []byte, ok bool) {
	if len(payload) < dhcpChunkHeaderLen {
		return 0, 0, 0, 0, nil, false
	}
	generation = binary.LittleEndian.Uint64(payload[0:8])
	index = binary.LittleEndian.Uint32(payload[8:12])
	total = binary.LittleEndian.Uint32(payload[12:16])
	totalLeases = binary.LittleEndian.Uint32(payload[16:20])
	if generation == 0 || total == 0 || total > 1<<20 || index >= total || totalLeases == 0 {
		return 0, 0, 0, 0, nil, false
	}
	return generation, index, total, totalLeases, payload[dhcpChunkHeaderLen:], true
}

// encodeDHCPLeaseChunkFrames splits leases into chunk bodies (each a
// standard count-prefixed encodeDHCPLeasePayload) whose chunk payload
// stays within dhcpChunkFrameBudget. It returns the bodies, the number of
// leases kept, and the number dropped (unencodable, or a single record too
// large for any frame). Mirrors encodePersistentNatLeaseBatchFrames.
func encodeDHCPLeaseChunkFrames(leases []dhcpserver.SyncLease) (bodies [][]byte, kept, dropped int) {
	var cur [][]byte // encoded records of the current chunk
	curBytes := 4    // count prefix
	flush := func() {
		b := make([]byte, 0, curBytes)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(cur)))
		for _, rec := range cur {
			b = binary.LittleEndian.AppendUint32(b, uint32(len(rec)))
			b = append(b, rec...)
		}
		bodies = append(bodies, b)
		cur = nil
		curBytes = 4
	}
	for _, l := range leases {
		rec, err := encodeOneLease(l)
		if err != nil {
			slog.Warn("cluster sync: dropping unencodable DHCP lease from chunked sync push",
				"family", l.Family, "address", l.Address, "err", err)
			dropped++
			continue
		}
		need := 4 + len(rec)
		if 4+need > dhcpChunkFrameBudget {
			slog.Warn("cluster sync: dropping DHCP lease exceeding sync chunk budget",
				"family", l.Family, "address", l.Address, "record_bytes", len(rec), "budget", dhcpChunkFrameBudget)
			dropped++
			continue
		}
		if len(cur) > 0 && curBytes+need > dhcpChunkFrameBudget {
			flush()
		}
		cur = append(cur, rec)
		curBytes += need
		kept++
	}
	if len(cur) > 0 || len(bodies) == 0 {
		flush()
	}
	return bodies, kept, dropped
}

// addChunk records one decoded chunk in the pending assembly for key and
// reports the completed lease set when every chunk has arrived (the
// assembly is then consumed). A chunk that disagrees with the pending
// assembly on total/totalLeases, or a duplicate index, invalidates the
// whole generation (dropped, never committed) — a torn or forged stream
// must not assemble. Caller holds dhcpApplyMu.
func (st *dhcpChunkState) addChunk(key dhcpChunkGeneration, index, total, totalLeases uint32, leases []dhcpserver.SyncLease) (complete []dhcpserver.SyncLease, closed bool) {
	if st.pending == nil {
		st.pending = make(map[dhcpChunkGeneration]*dhcpChunkAssembly)
	}
	// A new set supersedes any older pending assembly for other
	// generations is NOT done here: generations are keyed exactly, and a
	// stale generation is refused by the caller before admission. Only
	// bound the table: at most a few generations can be in flight (the
	// sender writes one set at a time under writeMu), so evict
	// everything if a forged stream inflates it.
	if len(st.pending) > 4 {
		st.pending = make(map[dhcpChunkGeneration]*dhcpChunkAssembly)
	}
	a, ok := st.pending[key]
	if !ok {
		a = &dhcpChunkAssembly{total: total, totalLeases: totalLeases, parts: make(map[uint32][]dhcpserver.SyncLease)}
		st.pending[key] = a
	}
	if a.total != total || a.totalLeases != totalLeases {
		delete(st.pending, key)
		return nil, false
	}
	if _, dup := a.parts[index]; dup {
		delete(st.pending, key)
		return nil, false
	}
	a.parts[index] = leases
	a.have++
	a.received += uint32(len(leases))
	if a.have < int(a.total) {
		return nil, false
	}
	// Complete: concatenate in index order and verify the announced total.
	complete = make([]dhcpserver.SyncLease, 0, a.totalLeases)
	for i := uint32(0); i < a.total; i++ {
		part, ok := a.parts[i]
		if !ok {
			delete(st.pending, key)
			return nil, false
		}
		complete = append(complete, part...)
	}
	delete(st.pending, key)
	if uint32(len(complete)) != a.totalLeases {
		return nil, false
	}
	return complete, true
}

// discard removes any pending assembly (a newer committed set supersedes
// in-flight chunks). Caller holds dhcpApplyMu.
func (st *dhcpChunkState) discard(key dhcpChunkGeneration) {
	delete(st.pending, key)
}

// discardAll drops every pending assembly (legacy commit supersedes all
// chunk generations older than it). Caller holds dhcpApplyMu.
func (st *dhcpChunkState) discardAll() {
	st.pending = nil
}
