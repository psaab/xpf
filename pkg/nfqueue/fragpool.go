package nfqueue

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// FragmentKey identifies one inner datagram. Tunnel, VRF and generation are
// intentionally part of the key: fragment state must never cross a tunnel,
// routing instance or queue generation boundary.
type FragmentKey struct {
	Version    uint8
	Tunnel     uint32
	VRF        uint32
	Generation uint64
	ID         uint32
	Src        [16]byte
	Dst        [16]byte
}

// Fragment is one L3 fragment payload. Offset is in bytes. More indicates that
// another fragment follows this one; a fragment with More=false supplies the
// datagram end. The pool is transport-measurement code, not the final policy
// reassembly implementation from the r4 plan.
type Fragment struct {
	Offset uint32
	More   bool
	Data   []byte
}

// CompletedDatagram is emitted when the retained fragment set covers [0,end).
// Fragments is the number of retained pieces, not the number of input copies.
type CompletedDatagram struct {
	Key       FragmentKey
	Payload   []byte
	Fragments int
}

var (
	// ErrFragmentCapacity means the flow was dropped because a configured
	// per-flow or global bound was reached.
	ErrFragmentCapacity = errors.New("nfqueue: fragment pool capacity exceeded")
	// ErrFragmentOverlap means an IPv6 overlap (or an invalid fragment) caused
	// the entire datagram's retained state to be dropped.
	ErrFragmentOverlap = errors.New("nfqueue: overlapping IPv6 fragments")
	// ErrFragmentMalformed means the fragment cannot be represented safely.
	ErrFragmentMalformed = errors.New("nfqueue: malformed fragment")
)

// FragStats is a snapshot of fragment-pool accounting.
type FragStats struct {
	Flows          int
	Fragments      int
	Completed      uint64
	CapacityDrops  uint64
	OverlapDrops   uint64
	DuplicateDrops uint64
	Expired        uint64
}

type fragmentPiece struct {
	offset uint32
	data   []byte
	more   bool
}

type fragmentSet struct {
	pieces    []fragmentPiece
	bytes     int
	lastEnd   uint32
	haveLast  bool
	createdAt time.Time
}

// FragPool is a bounded, mutex-protected fragment reassembly pool. A flow
// consumes at most perFlowCap pieces and the pool holds at most maxDatagrams
// flow sets. Completion is queued separately from input insertion and is also
// bounded, so a stalled consumer cannot make memory grow without limit.
type FragPool struct {
	mu               sync.Mutex
	perFlowCap       int
	maxDatagrams     int
	maxDatagramBytes int
	flows            map[FragmentKey]*fragmentSet
	completed        []CompletedDatagram
	completedBytes   int
	fragments        int
	completedN       atomic.Uint64
	capacityDrops    atomic.Uint64
	overlapDrops     atomic.Uint64
	duplicates       atomic.Uint64
	expired          atomic.Uint64
}

const maxDatagramBytes = 64 * 1024

// NewFragPool constructs a pool with explicit positive bounds.
func NewFragPool(perFlowCap, maxDatagrams int) (*FragPool, error) {
	if perFlowCap <= 0 || maxDatagrams <= 0 {
		return nil, errors.New("nfqueue: fragment pool bounds must be positive")
	}
	return &FragPool{
		perFlowCap:       perFlowCap,
		maxDatagrams:     maxDatagrams,
		maxDatagramBytes: maxDatagramBytes,
		flows:            make(map[FragmentKey]*fragmentSet),
	}, nil
}

// Insert retains one fragment. On completion it queues the assembled payload
// and returns complete=true. Capacity and overlap errors are fail-closed: the
// whole flow set is removed and the caller must drop that datagram.
func (p *FragPool) Insert(key FragmentKey, frag Fragment) (complete bool, err error) {
	return p.insertAt(key, frag, time.Time{})
}

// insertAt uses the caller's first-seen time when the flow is new, keeping
// expiry aligned with pipeline-held frames.
func (p *FragPool) insertAt(key FragmentKey, frag Fragment, createdAt time.Time) (complete bool, err error) {
	if len(frag.Data) == 0 {
		return false, ErrFragmentMalformed
	}
	end := uint64(frag.Offset) + uint64(len(frag.Data))
	if end > uint64(^uint32(0)) || end > maxDatagramBytes {
		return false, ErrFragmentMalformed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	set := p.flows[key]
	if set == nil {
		if len(p.flows) >= p.maxDatagrams {
			p.capacityDrops.Add(1)
			return false, ErrFragmentCapacity
		}
		if createdAt.IsZero() {
			createdAt = time.Now()
		}
		set = &fragmentSet{createdAt: createdAt}
		p.flows[key] = set
	}
	if len(set.pieces) >= p.perFlowCap {
		p.dropSetLocked(key, set)
		p.capacityDrops.Add(1)
		return false, ErrFragmentCapacity
	}
	before := len(set.pieces)
	if key.Version == 6 {
		if err := p.insertIPv6Locked(set, frag); err != nil {
			p.dropSetLocked(key, set)
			p.overlapDrops.Add(1)
			return false, err
		}
	} else {
		p.insertIPv4FirstWinsLocked(set, frag)
	}
	p.fragments += len(set.pieces) - before
	if len(set.pieces) > p.perFlowCap || set.bytes > p.maxDatagramBytes {
		p.dropSetLocked(key, set)
		p.capacityDrops.Add(1)
		return false, ErrFragmentCapacity
	}
	if !set.haveLast || !p.isCompleteLocked(set) {
		return false, nil
	}
	payload := assembleLocked(set)
	if payload == nil {
		p.dropSetLocked(key, set)
		p.overlapDrops.Add(1)
		return false, ErrFragmentOverlap
	}
	if len(p.completed) >= p.maxDatagrams ||
		p.completedBytes+len(payload) > p.maxDatagrams*maxDatagramBytes {
		p.dropSetLocked(key, set)
		p.capacityDrops.Add(1)
		return false, ErrFragmentCapacity
	}
	out := CompletedDatagram{Key: key, Payload: payload, Fragments: len(set.pieces)}
	p.dropSetLocked(key, set)
	p.completed = append(p.completed, out)
	p.completedBytes += len(payload)
	p.completedN.Add(1)
	return true, nil
}

func (p *FragPool) insertIPv6Locked(set *fragmentSet, frag Fragment) error {
	start := frag.Offset
	end := start + uint32(len(frag.Data))
	for _, old := range set.pieces {
		oldEnd := old.offset + uint32(len(old.data))
		if end <= old.offset || start >= oldEnd {
			continue
		}
		if start == old.offset && end == oldEnd && string(frag.Data) == string(old.data) && frag.More == old.more {
			p.duplicates.Add(1)
			return nil
		}
		return ErrFragmentOverlap
	}
	if !frag.More && set.haveLast && set.lastEnd != end {
		return ErrFragmentOverlap
	}
	set.pieces = append(set.pieces, fragmentPiece{offset: start, data: append([]byte(nil), frag.Data...), more: frag.More})
	set.bytes += len(frag.Data)
	if !frag.More {
		set.haveLast = true
		set.lastEnd = end
	}
	return nil
}

// insertIPv4FirstWinsLocked keeps the first bytes received for an overlap and
// only stores uncovered portions of a later fragment. This makes completion
// depend on the releasable/forwarded set, rather than bytes copied from a
// discarded overlap.
func (p *FragPool) insertIPv4FirstWinsLocked(set *fragmentSet, frag Fragment) {
	start := frag.Offset
	end := start + uint32(len(frag.Data))
	covered := make([]bool, len(frag.Data))
	for _, old := range set.pieces {
		oldStart := old.offset
		oldEnd := oldStart + uint32(len(old.data))
		lo, hi := start, end
		if lo < oldStart {
			lo = oldStart
		}
		if hi > oldEnd {
			hi = oldEnd
		}
		for x := lo; x < hi; x++ {
			covered[x-start] = true
		}
	}
	for i := 0; i < len(frag.Data); {
		for i < len(frag.Data) && covered[i] {
			i++
		}
		if i == len(frag.Data) {
			p.duplicates.Add(1)
			return
		}
		begin := i
		for i < len(frag.Data) && !covered[i] {
			i++
		}
		piece := fragmentPiece{
			offset: start + uint32(begin),
			data:   append([]byte(nil), frag.Data[begin:i]...),
			more:   frag.More,
		}
		set.pieces = append(set.pieces, piece)
		set.bytes += len(piece.data)
	}
	if !frag.More {
		if set.haveLast && set.lastEnd != end {
			// Retain the first terminal boundary; the completion check will
			// fail closed if the retained bytes do not cover it.
			return
		}
		set.haveLast = true
		set.lastEnd = end
	}
}

func (p *FragPool) isCompleteLocked(set *fragmentSet) bool {
	if !set.haveLast || set.lastEnd == 0 {
		return false
	}
	pieces := append([]fragmentPiece(nil), set.pieces...)
	sort.Slice(pieces, func(i, j int) bool { return pieces[i].offset < pieces[j].offset })
	var cursor uint32
	for _, piece := range pieces {
		if piece.offset > cursor {
			return false
		}
		end := piece.offset + uint32(len(piece.data))
		if end > cursor {
			cursor = end
		}
		if cursor >= set.lastEnd {
			return cursor == set.lastEnd
		}
	}
	return cursor == set.lastEnd
}

func assembleLocked(set *fragmentSet) []byte {
	if set.lastEnd == 0 {
		return nil
	}
	pieces := append([]fragmentPiece(nil), set.pieces...)
	sort.Slice(pieces, func(i, j int) bool { return pieces[i].offset < pieces[j].offset })
	out := make([]byte, int(set.lastEnd))
	var cursor uint32
	for _, piece := range pieces {
		if piece.offset > cursor {
			return nil
		}
		end := piece.offset + uint32(len(piece.data))
		if end > set.lastEnd {
			end = set.lastEnd
		}
		if end > cursor {
			copy(out[int(cursor):int(end)], piece.data[:int(end-piece.offset)])
			cursor = end
		}
	}
	if cursor != set.lastEnd {
		return nil
	}
	return out
}

func (p *FragPool) dropSetLocked(key FragmentKey, set *fragmentSet) {
	delete(p.flows, key)
	p.fragments -= len(set.pieces)
	if p.fragments < 0 {
		p.fragments = 0
	}
}

// PopCompleted removes and returns the oldest completed datagram, if any.
func (p *FragPool) PopCompleted() (CompletedDatagram, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.completed) == 0 {
		return CompletedDatagram{}, false
	}
	out := p.completed[0]
	p.completed[0] = CompletedDatagram{}
	p.completed = p.completed[1:]
	p.completedBytes -= len(out.Payload)
	if p.completedBytes < 0 {
		p.completedBytes = 0
	}
	return out, true
}

// Expire drops flow sets first seen before cutoff and returns the number of
// sets removed. It shares the absolute deadline used for held pipeline frames.
func (p *FragPool) Expire(cutoff time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	removed := 0
	for key, set := range p.flows {
		if set.createdAt.Before(cutoff) {
			p.dropSetLocked(key, set)
			removed++
		}
	}
	p.expired.Add(uint64(removed))
	return removed
}

// Stats snapshots pool occupancy and counters.
func (p *FragPool) Stats() FragStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return FragStats{
		Flows:          len(p.flows),
		Fragments:      p.fragments,
		Completed:      p.completedN.Load(),
		CapacityDrops:  p.capacityDrops.Load(),
		OverlapDrops:   p.overlapDrops.Load(),
		DuplicateDrops: p.duplicates.Load(),
		Expired:        p.expired.Load(),
	}
}
