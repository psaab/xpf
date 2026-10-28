package cluster

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// #16758: chunked IPsec SA full-sets.
//
// decodeIPsecSAPayload refuses any legacy frame with more than
// maxIPsecSANames names (#9061), and QueueIPsecSA emitted the sender's
// whole live set as one such frame with no count check. A primary with
// more than 4096 active child SAs therefore had every advertise refused
// whole on the standby, which kept its frozen prior set and would
// re-initiate that stale set on takeover — silently on the primary.
//
// The fix mirrors #15160 (DHCP lease chunking): when the name count
// exceeds maxIPsecSANames, the sender splits the names across additive
// syncMsgIPsecSAChunk frames. Each chunk payload is:
//
//	{ generation u64 | index u32 | total u32 | totalNames u32 | body }
//
// where generation is the set's first full-set sequence number (its
// identity), and body is encodeIPsecSAPayload of that chunk's names
// (newline-joined, no count prefix — the same codec as the legacy frame).
// Chunk frames each carry their own increasing full-set seq; the receiver
// admits chunks in seq order and assembles by (incarnation, generation),
// committing the concatenated set atomically — held-set store + high-water
// advance + callback under ipsecApplyMu, exactly like a legacy frame —
// only when every chunk has arrived. An unclosed generation never commits
// (the prior set is retained); a newer legacy set supersedes pending
// assemblies, and at the pending cap only the oldest assembly is evicted.
//
// Budget: each chunk holds at most maxIPsecSANames names, so its body is
// at most maxIPsecSANames*(maxIPsecSANameLen+1) bytes (~1 MiB), far below
// maxSyncPayload. The sender refuses (counted, warned) a set containing a
// name over maxIPsecSANameLen rather than chunking a set no receiver can
// install, and refuses a total over ipsecChunkMaxTotalNames before any
// frame is written, so a conforming sender never announces a total a new
// receiver must refuse.

const (
	// ipsecChunkHeaderLen is the fixed chunk envelope: generation(8) +
	// index(4) + total(4) + totalNames(4).
	ipsecChunkHeaderLen = 20
	// ipsecChunkMaxTotal is the bound on chunk count per set; a real set
	// needs a handful of <=4096-name chunks.
	ipsecChunkMaxTotal = 1 << 20
	// ipsecChunkMaxTotalNames is the sender+receiver cap on chunked-set
	// name count: decodeIPsecSAChunkHeader refuses totalNames outside
	// [1, ipsecChunkMaxTotalNames] and QueueIPsecSA refuses to chunk a
	// larger set, so a forged total cannot size the completion allocation.
	ipsecChunkMaxTotalNames = 1 << 20
	// ipsecChunkNamesPerChunk is the per-chunk name bound: the receiver's
	// existing per-frame element bound, reused so each chunk body decodes
	// through decodeIPsecSAPayloadChunk unchanged in spirit.
	ipsecChunkNamesPerChunk = maxIPsecSANames
	// ipsecChunkMaxPending bounds simultaneously pending assemblies.
	// Opening a generation past it evicts only the oldest pending
	// assembly (#17846), never the whole table.
	ipsecChunkMaxPending = 5
)

// ipsecSAChunkGeneration is the assembly identity of one chunked set.
type ipsecSAChunkGeneration struct {
	incarnation uint64
	generation  uint64
}

// ipsecSAChunkAssembly is one in-progress chunked set on the receiver.
type ipsecSAChunkAssembly struct {
	total      uint32
	totalNames uint32
	parts      map[uint32][]string
	have       int
	received   uint32
}

// ipsecSAChunkState is the receiver's pending-assembly table. Only
// ipsecApplyMu holders touch it (the chunk commit path and the legacy
// commit's supersede), so it needs no lock of its own; the zero value
// (nil map) is valid.
type ipsecSAChunkState struct {
	pending map[ipsecSAChunkGeneration]*ipsecSAChunkAssembly
	// order stores pending keys oldest first so bounded admission evicts
	// by insertion order, not map iteration order.
	order []ipsecSAChunkGeneration
}

// encodeIPsecSAChunkPayload builds one chunk payload (WITHOUT the full-set
// trailer): the fixed header followed by the chunk body.
func encodeIPsecSAChunkPayload(body []byte, generation uint64, index, total, totalNames uint32) []byte {
	out := make([]byte, 0, ipsecChunkHeaderLen+len(body))
	out = binary.LittleEndian.AppendUint64(out, generation)
	out = binary.LittleEndian.AppendUint32(out, index)
	out = binary.LittleEndian.AppendUint32(out, total)
	out = binary.LittleEndian.AppendUint32(out, totalNames)
	return append(out, body...)
}

// decodeIPsecSAChunkHeader parses and validates the fixed chunk header.
// ok is false for any truncated or internally inconsistent header: index
// must be < total, total must be in [1, ipsecChunkMaxTotal], and
// totalNames must be in [1, ipsecChunkMaxTotalNames] (an empty set always
// fits the legacy frame and is never chunked).
func decodeIPsecSAChunkHeader(payload []byte) (generation uint64, index, total, totalNames uint32, body []byte, ok bool) {
	if len(payload) < ipsecChunkHeaderLen {
		return 0, 0, 0, 0, nil, false
	}
	generation = binary.LittleEndian.Uint64(payload[0:8])
	index = binary.LittleEndian.Uint32(payload[8:12])
	total = binary.LittleEndian.Uint32(payload[12:16])
	totalNames = binary.LittleEndian.Uint32(payload[16:20])
	if generation == 0 || total == 0 || total > ipsecChunkMaxTotal || index >= total || totalNames == 0 || totalNames > ipsecChunkMaxTotalNames {
		return 0, 0, 0, 0, nil, false
	}
	return generation, index, total, totalNames, payload[ipsecChunkHeaderLen:], true
}

// encodeIPsecSAChunkBodies splits names into chunk bodies (each an
// encodeIPsecSAPayload of at most ipsecChunkNamesPerChunk names). It
// returns the bodies and the total name count. Names are assumed already
// validated by the caller (each <= maxIPsecSANameLen); an empty input
// yields one empty body so the caller never chunks an empty set in
// production (QueueIPsecSA only chunks over-bound sets).
func encodeIPsecSAChunkBodies(names []string) (bodies [][]byte, total int) {
	for start := 0; start < len(names); start += ipsecChunkNamesPerChunk {
		end := start + ipsecChunkNamesPerChunk
		if end > len(names) {
			end = len(names)
		}
		bodies = append(bodies, encodeIPsecSAPayload(names[start:end]))
	}
	if len(bodies) == 0 {
		bodies = append(bodies, encodeIPsecSAPayload(nil))
	}
	return bodies, len(names)
}

var (
	errIPsecSAChunkNameTooLong  = errors.New("cluster sync: IPsec SA chunk name exceeds byte limit")
	errIPsecSAChunkTooManyNames = errors.New("cluster sync: IPsec SA chunk exceeds per-chunk name limit")
)

// decodeIPsecSAChunkBody decodes one chunk body with the same per-name and
// per-frame element bounds as the legacy decoder. Names are copied, never
// aliased to the frame. The per-frame bound is enforced before materializing
// each name so a peer cannot make the decoder build an over-bound slice only
// for the receiver to reject it.
func decodeIPsecSAChunkBody(payload []byte) ([]string, error) {
	if len(payload) == 0 {
		return nil, nil
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
			return nil, errIPsecSAChunkNameTooLong
		}
		if len(names) >= ipsecChunkNamesPerChunk {
			return nil, errIPsecSAChunkTooManyNames
		}
		names = append(names, string(line))
	}
	return names, nil
}

// addChunk records one decoded chunk in the pending assembly for key and
// reports the completed name set when every chunk has arrived (the
// assembly is then consumed). A chunk that disagrees with the pending
// assembly on total/totalNames, pushes the accumulated name count past
// totalNames, or duplicates an index invalidates the whole generation
// (dropped, never committed). The received>totalNames refusal sits BEFORE
// the completion allocation so an over-total stream is dropped without
// ever sizing a slice from the announced total. Caller holds ipsecApplyMu.
func (st *ipsecSAChunkState) addChunk(key ipsecSAChunkGeneration, index, total, totalNames uint32, names []string) (complete []string, closed bool, accepted bool) {
	if st.pending == nil {
		st.pending = make(map[ipsecSAChunkGeneration]*ipsecSAChunkAssembly)
	}
	a, ok := st.pending[key]
	if !ok {
		// Opening a new generation past the cap evicts only the oldest
		// assembly. The incoming key is not in pending yet, so it cannot
		// evict its own just-arrived chunk.
		if len(st.pending) >= ipsecChunkMaxPending {
			st.removePending(st.order[0])
		}
		a = &ipsecSAChunkAssembly{total: total, totalNames: totalNames, parts: make(map[uint32][]string)}
		st.pending[key] = a
		st.order = append(st.order, key)
	}
	if a.total != total || a.totalNames != totalNames {
		st.removePending(key)
		return nil, false, false
	}
	if _, dup := a.parts[index]; dup {
		st.removePending(key)
		return nil, false, false
	}
	a.parts[index] = names
	a.have++
	a.received += uint32(len(names))
	if a.received > a.totalNames {
		st.removePending(key)
		return nil, false, false
	}
	if a.have < int(a.total) {
		return nil, false, true
	}
	complete = make([]string, 0, a.received)
	for i := uint32(0); i < a.total; i++ {
		part, ok := a.parts[i]
		if !ok {
			st.removePending(key)
			return nil, false, false
		}
		complete = append(complete, part...)
	}
	st.removePending(key)
	if uint32(len(complete)) != a.totalNames {
		return nil, false, false
	}
	return complete, true, true
}

// removePending removes one assembly and its insertion-order entry.
func (st *ipsecSAChunkState) removePending(key ipsecSAChunkGeneration) {
	if _, ok := st.pending[key]; !ok {
		return
	}
	delete(st.pending, key)
	for i, pendingKey := range st.order {
		if pendingKey == key {
			copy(st.order[i:], st.order[i+1:])
			st.order[len(st.order)-1] = ipsecSAChunkGeneration{}
			st.order = st.order[:len(st.order)-1]
			return
		}
	}
}

// discardAll drops every pending assembly (a legacy commit supersedes all
// chunk generations older than it). Caller holds ipsecApplyMu.
func (st *ipsecSAChunkState) discardAll() {
	st.pending = nil
	st.order = nil
}
