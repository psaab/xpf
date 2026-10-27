package nfqueue

// Test-only fragment reassembly measurement apparatus (#17045). FragPool,
// CompletedDatagram, FragStats and the ErrFragment* sentinels are retained
// solely so the Measure*/FragPool measurement tests keep running; no
// production file in this package references them. The pool is
// transport-measurement code, not the final policy reassembly implementation.

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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

func testFragmentKey(version uint8, id uint32) FragmentKey {
	return FragmentKey{Version: version, Tunnel: 7, VRF: 3, Generation: 11, ID: id}
}

func TestFragPoolIPv4FirstWinsCompletesRetainedSet(t *testing.T) {
	pool, err := NewFragPool(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	key := testFragmentKey(4, 1)
	if complete, err := pool.Insert(key, Fragment{Offset: 0, More: true, Data: []byte("abcd")}); complete || err != nil {
		t.Fatalf("first fragment: complete=%t err=%v", complete, err)
	}
	// The later fragment overlaps bytes 2..3. First-wins keeps "ab" and
	// retains only the new bytes at offsets 4..5, so the releasable set is
	// "abcdZZ", not bytes copied from a discarded overlap.
	if complete, err := pool.Insert(key, Fragment{Offset: 2, More: false, Data: []byte("ZZZZ")}); !complete || err != nil {
		t.Fatalf("overlapping terminal fragment: complete=%t err=%v", complete, err)
	}
	got, ok := pool.PopCompleted()
	if !ok {
		t.Fatal("completed datagram missing")
	}
	if string(got.Payload) != "abcdZZ" {
		t.Fatalf("first-wins payload = %q, want %q", got.Payload, "abcdZZ")
	}
	if got.Fragments != 2 {
		t.Fatalf("retained fragment count = %d, want 2", got.Fragments)
	}
}

func TestFragPoolIPv6OverlapDropsWholeDatagram(t *testing.T) {
	pool, err := NewFragPool(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	key := testFragmentKey(6, 2)
	_, _ = pool.Insert(key, Fragment{Offset: 0, More: true, Data: []byte("abcd")})
	complete, err := pool.Insert(key, Fragment{Offset: 2, More: false, Data: []byte("WXYZ")})
	if complete || !errors.Is(err, ErrFragmentOverlap) {
		t.Fatalf("IPv6 overlap: complete=%t err=%v", complete, err)
	}
	if got := pool.Stats(); got.Flows != 0 || got.OverlapDrops != 1 {
		t.Fatalf("overlap stats = %+v, want no flow and one drop", got)
	}
}

func TestFragPoolExactIPv6DuplicateDoesNotConsumePieceCap(t *testing.T) {
	pool, err := NewFragPool(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	key := testFragmentKey(6, 3)
	first := Fragment{Offset: 0, More: true, Data: []byte("ab")}
	if _, err := pool.Insert(key, first); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Insert(key, first); err != nil {
		t.Fatalf("exact duplicate: %v", err)
	}
	if complete, err := pool.Insert(key, Fragment{Offset: 2, More: false, Data: []byte("cd")}); !complete || err != nil {
		t.Fatalf("terminal after duplicate: complete=%t err=%v", complete, err)
	}
	if got := pool.Stats(); got.DuplicateDrops != 1 || got.Completed != 1 {
		t.Fatalf("duplicate stats = %+v", got)
	}
}

func TestFragPoolCapacityDropsFlowAndBoundsCompletionQueue(t *testing.T) {
	pool, err := NewFragPool(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	stalled := testFragmentKey(4, 10)
	for i := uint32(0); i < 2; i++ {
		if complete, err := pool.Insert(stalled, Fragment{Offset: i * 2, More: true, Data: []byte("ab")}); complete || err != nil {
			t.Fatalf("stalled fragment %d: complete=%t err=%v", i, complete, err)
		}
	}
	if complete, err := pool.Insert(stalled, Fragment{Offset: 4, More: true, Data: []byte("cd")}); complete || !errors.Is(err, ErrFragmentCapacity) {
		t.Fatalf("per-flow cap: complete=%t err=%v", complete, err)
	}
	if got := pool.Stats(); got.Flows != 0 || got.CapacityDrops != 1 {
		t.Fatalf("capacity stats = %+v", got)
	}
	first := testFragmentKey(4, 11)
	if complete, err := pool.Insert(first, Fragment{More: false, Data: []byte("one")}); !complete || err != nil {
		t.Fatalf("first completion: complete=%t err=%v", complete, err)
	}
	second := testFragmentKey(4, 12)
	if complete, err := pool.Insert(second, Fragment{More: false, Data: []byte("two")}); complete || !errors.Is(err, ErrFragmentCapacity) {
		t.Fatalf("completion queue bound: complete=%t err=%v", complete, err)
	}
	if _, ok := pool.PopCompleted(); !ok {
		t.Fatal("first completion missing")
	}
	if complete, err := pool.Insert(second, Fragment{More: false, Data: []byte("two")}); !complete || err != nil {
		t.Fatalf("completion after drain: complete=%t err=%v", complete, err)
	}
}

func TestFragPoolExpireReclaimsStalledFlows(t *testing.T) {
	pool, err := NewFragPool(8, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Insert(testFragmentKey(4, 20), Fragment{More: true, Data: []byte("stalled")}); err != nil {
		t.Fatal(err)
	}
	if removed := pool.Expire(time.Now().Add(time.Second)); removed != 1 {
		t.Fatalf("expired sets = %d, want 1", removed)
	}
	if got := pool.Stats(); got.Flows != 0 || got.Expired != 1 {
		t.Fatalf("expiry stats = %+v", got)
	}
}
func TestFragPoolConflictingTerminalPreservesOtherFragmentCounts(t *testing.T) {
	pool, err := NewFragPool(8, 4)
	if err != nil {
		t.Fatal(err)
	}
	survivor := testFragmentKey(6, 30)
	if _, err := pool.Insert(survivor, Fragment{Offset: 0, More: true, Data: []byte("ab")}); err != nil {
		t.Fatal(err)
	}
	conflict := testFragmentKey(6, 31)
	for _, frag := range []Fragment{
		{Offset: 0, More: true, Data: []byte("ab")},
		{Offset: 4, More: false, Data: []byte("ef")},
	} {
		if _, err := pool.Insert(conflict, frag); err != nil {
			t.Fatal(err)
		}
	}
	if complete, err := pool.Insert(conflict, Fragment{Offset: 6, More: false, Data: []byte("gh")}); complete || !errors.Is(err, ErrFragmentOverlap) {
		t.Fatalf("conflicting terminal: complete=%t err=%v, want overlap error", complete, err)
	}
	if got := pool.Stats(); got.Flows != 1 || got.Fragments != 1 {
		t.Fatalf("stats after dropping one of two sets = %+v, want one surviving flow and fragment", got)
	}
}
