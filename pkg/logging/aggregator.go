package logging

import (
	"container/heap"
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// defaultMaxAggKeys bounds the number of distinct source/destination keys
// retained per flush window in each map. It exists to defend against a
// control-plane resource-exhaustion amplifier (#2936): an attacker driving
// high source/destination cardinality (spoofed-source or scan traffic — the
// exact pattern a security appliance observes during an incident) would
// otherwise force the daemon to retain two unbounded maps for the full flush
// window, then allocate and sort O(N) entries twice per flush. Bounding the
// monitored key set bounds both the resident memory and the per-flush
// allocate+sort cost by configuration rather than by traffic cardinality.
//
// This value is now the K of a Space-Saving (Metwally et al.) top-K counter
// set (#3099). Memory is still bounded by K exactly as the old cardinality cap
// bounded it (one counter per monitored key, K counters per map), but the
// reported top-N is no longer arrival-order dependent: a genuine heavy hitter
// whose first session of the window arrives after the counter set is full now
// evicts the current minimum counter instead of being silently dropped.
//
// 10000 monitored keys per map per window keeps the aggregator well within a
// few MB of transient memory while remaining far above any plausible
// legitimate top-N working set (the report only emits top-10).
const defaultMaxAggKeys = 10000

// SessionAggregator tracks session statistics and periodically flushes
// top-N source and destination reports.
//
// Each direction (source IP, destination IP) is accounted with an independent
// Space-Saving counter set (streamSummary). Space-Saving gives bounded memory
// (K counters) AND arrival-order-independent top-K accuracy: the heaviest
// hitters of the window are retained regardless of when in the window they
// first appear, which the previous capped-exact-map approach could not do
// (keys offered after the cap filled were dropped, #3099).
type SessionAggregator struct {
	mu   sync.Mutex
	srcs *streamSummary // srcIP top-K
	dsts *streamSummary // dstIP top-K

	// maxKeys is K: the number of counters in each Space-Saving set, i.e. the
	// maximum number of distinct keys monitored per map per window. <= 0 means
	// unbounded (no eviction). Production uses defaultMaxAggKeys.
	maxKeys int

	flushInterval time.Duration
	topN          int
	logFn         func(severity int, msg string) // where to send aggregate reports
}

// AggregateEntry is a single top-N entry returned by Flush.
type AggregateEntry struct {
	IP       string
	Sessions uint64
	Bytes    uint64
}

// ssCounter is one Space-Saving counter. bytes is the (over-)estimated total
// session bytes for the currently monitored key and is the ranking key; err is
// the maximum over-estimate (the count the slot held when this key took it
// over). The Space-Saving guarantee is bytes-err <= true_bytes <= bytes. The
// session count is tracked with the same bookkeeping so the displayed session
// total is also a bounded over-estimate.
type ssCounter struct {
	ip       string
	bytes    uint64
	bytesErr uint64
	sessions uint64
	sessErr  uint64
	idx      int // index within the min-heap (maintained by heap.Interface)
}

// ssHeap is a min-heap of *ssCounter keyed on bytes. heap[0] is therefore the
// minimum-bytes counter — the Space-Saving eviction victim when the set is
// full. O(log K) Fix/Push/Pop keeps Add cheap on the SESSION_CLOSE path.
type ssHeap []*ssCounter

func (h ssHeap) Len() int            { return len(h) }
func (h ssHeap) Less(i, j int) bool  { return h[i].bytes < h[j].bytes }
func (h ssHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i]; h[i].idx = i; h[j].idx = j }
func (h *ssHeap) Push(x interface{}) { c := x.(*ssCounter); c.idx = len(*h); *h = append(*h, c) }
func (h *ssHeap) Pop() interface{} {
	old := *h
	n := len(old)
	c := old[n-1]
	old[n-1] = nil
	c.idx = -1
	*h = old[:n-1]
	return c
}

// streamSummary is a Space-Saving (Metwally, Agrawal & El Abbadi 2005) top-K
// counter set. monitored maps a key to its counter; minHeap orders counters by
// bytes so the minimum is found in O(1) and updated in O(log K). overflow
// counts evictions this window — a non-zero value means cardinality exceeded K
// so the reported top-K is approximate (the #2936 incident indicator).
type streamSummary struct {
	monitored map[string]*ssCounter
	minHeap   ssHeap
	overflow  uint64
}

func newStreamSummary() *streamSummary {
	return &streamSummary{monitored: make(map[string]*ssCounter)}
}

// add records one session of bytesWeight for key. k is the counter-set size K
// (<= 0 means unbounded). The three Space-Saving cases:
//
//  1. key already monitored        -> accumulate (exact for this key).
//  2. set below K                   -> admit a new exact counter.
//  3. set full                      -> evict the minimum counter: the new key
//     inherits the victim's count as its error floor, so the new estimate
//     over-estimates by at most the previous minimum (the algorithm's
//     guarantee). This is what makes a LATE heavy hitter rankable.
func (s *streamSummary) add(key string, bytesWeight uint64, k int) {
	if c, ok := s.monitored[key]; ok {
		c.bytes = addBytesSaturating(c.bytes, bytesWeight)
		c.sessions++
		heap.Fix(&s.minHeap, c.idx) // bytes only grows -> sift down
		return
	}
	if k <= 0 || len(s.minHeap) < k {
		c := &ssCounter{ip: key, bytes: bytesWeight, sessions: 1}
		s.monitored[key] = c
		heap.Push(&s.minHeap, c)
		return
	}
	// Set full: take over the minimum-bytes counter for the new key.
	min := s.minHeap[0]
	delete(s.monitored, min.ip)
	min.ip = key
	min.bytesErr = min.bytes
	min.bytes = addBytesSaturating(min.bytes, bytesWeight)
	min.sessErr = min.sessions
	min.sessions++
	s.monitored[key] = min
	heap.Fix(&s.minHeap, 0) // bytes grew -> sift down from the root
	s.overflow++
}

// topAndReset returns the top-n counters by bytes (descending) plus the
// per-window overflow (eviction) count, then clears the summary for the next
// window. Allocation is bounded by K, matching the old capped-map cost.
func (s *streamSummary) topAndReset(n int) ([]AggregateEntry, uint64) {
	var entries []AggregateEntry
	if len(s.minHeap) > 0 {
		entries = make([]AggregateEntry, 0, len(s.minHeap))
		for _, c := range s.minHeap {
			entries = append(entries, AggregateEntry{IP: c.ip, Sessions: c.sessions, Bytes: c.bytes})
		}
	}
	overflow := s.overflow

	s.monitored = make(map[string]*ssCounter)
	s.minHeap = nil
	s.overflow = 0

	sort.Slice(entries, func(i, j int) bool { return entries[i].Bytes > entries[j].Bytes })
	if n >= 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries, overflow
}

// NewSessionAggregator creates a new aggregator.
// flushInterval controls how often top-N stats are emitted (default 5min).
// topN controls how many entries per category (default 10).
func NewSessionAggregator(flushInterval time.Duration, topN int) *SessionAggregator {
	if flushInterval <= 0 {
		flushInterval = 5 * time.Minute
	}
	if topN <= 0 {
		topN = 10
	}
	return &SessionAggregator{
		srcs:          newStreamSummary(),
		dsts:          newStreamSummary(),
		maxKeys:       defaultMaxAggKeys,
		flushInterval: flushInterval,
		topN:          topN,
	}
}

// SetLogFunc sets the function used to emit aggregate log lines.
func (sa *SessionAggregator) SetLogFunc(fn func(severity int, msg string)) {
	sa.mu.Lock()
	sa.logFn = fn
	sa.mu.Unlock()
}

// addBytesSaturating adds byte counts without allowing uint64 wraparound.
func addBytesSaturating(a, b uint64) uint64 {
	const maxUint64 = ^uint64(0)
	if a > maxUint64-b {
		return maxUint64
	}
	return a + b
}

// totalSessionBytes returns both directions without allowing uint64 wraparound.
func totalSessionBytes(forward, reverse uint64) uint64 {
	return addBytesSaturating(forward, reverse)
}

// Add records a session event. Only SESSION_CLOSE events update counters.
func (sa *SessionAggregator) Add(rec EventRecord) {
	if rec.Type != "SESSION_CLOSE" {
		return
	}

	srcIP, _ := splitAddrPort(rec.SrcAddr)
	dstIP, _ := splitAddrPort(rec.DstAddr)

	sa.mu.Lock()
	defer sa.mu.Unlock()

	// Space-Saving accounting: a key already in the set always accumulates; a
	// new key is admitted while the set is below K, otherwise it evicts the
	// current minimum counter (instead of being dropped). Memory stays bounded
	// by K and the top-K is arrival-order independent (#3099).
	bytes := totalSessionBytes(rec.SessionBytes, rec.RevSessionBytes)
	sa.srcs.add(srcIP, bytes, sa.maxKeys)
	sa.dsts.add(dstIP, bytes, sa.maxKeys)
}

// Flush returns top-N sources and destinations by total (forward+reverse) bytes,
// then resets counters.
func (sa *SessionAggregator) Flush() (topSrc, topDst []AggregateEntry) {
	topSrc, topDst, _, _ = sa.flushWithDropped()
	return
}

// flushWithDropped is Flush plus the per-window overflow (eviction) counts. The
// two Space-Saving sets and their overflow counters are swapped out atomically
// under the lock so the snapshot is internally consistent and the next window
// starts clean.
func (sa *SessionAggregator) flushWithDropped() (topSrc, topDst []AggregateEntry, droppedSrc, droppedDst uint64) {
	sa.mu.Lock()
	n := sa.topN
	topSrc, droppedSrc = sa.srcs.topAndReset(n)
	topDst, droppedDst = sa.dsts.topAndReset(n)
	sa.mu.Unlock()
	return
}

// Run starts the periodic flush loop. Blocks until ctx is cancelled.
//
// On ctx cancellation Run performs a FINAL flush before returning (#5313).
// Without it, cancelling the context — which happens on daemon shutdown AND on
// every config-churn teardown/replace in applyAggregator — silently discarded
// up to a full flush interval (~5 min) of accumulated SESSION_CLOSE counters:
// the pending window was only ever emitted on ticker.C. The final flush emits
// that window as its own (partial) report so no counters are lost. flushAndLog
// is a no-op when there are no pending counters (empty window), so a cancel
// that races just after a ticker flush neither double-counts nor emits an empty
// report.
func (sa *SessionAggregator) Run(ctx context.Context) {
	ticker := time.NewTicker(sa.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Graceful final flush of the pending window before teardown.
			sa.flushAndLog()
			return
		case <-ticker.C:
			sa.flushAndLog()
		}
	}
}

// HandleEvent is an EventCallback adapter for use with EventReader.AddCallback.
func (sa *SessionAggregator) HandleEvent(rec EventRecord, _ []byte) {
	sa.Add(rec)
}

func (sa *SessionAggregator) flushAndLog() {
	topSrc, topDst, droppedSrc, droppedDst := sa.flushWithDropped()

	if len(topSrc) == 0 && len(topDst) == 0 && droppedSrc == 0 && droppedDst == 0 {
		return
	}

	sa.mu.Lock()
	logFn := sa.logFn
	maxKeys := sa.maxKeys
	sa.mu.Unlock()

	// Surface the counter set overflowing. A non-zero count means new
	// source/destination keys evicted an existing counter this window because
	// the Space-Saving set was full (K = maxKeys) — i.e. observed cardinality
	// exceeded K, so the reported top-N is approximate rather than exact. This
	// is the same incident-grade high-cardinality signal operators relied on
	// from the old capped-map "dropped-keys" counter; the field name is kept
	// for continuity. Emit at warning severity so it is visible.
	if droppedSrc > 0 || droppedDst > 0 {
		msg := fmt.Sprintf("RT_FLOW_SESSION_AGGREGATE dropped-keys source=%d destination=%d cap=%d "+
			"(source/destination cardinality exceeded the top-K counter set; top-N is approximate, heavy hitters retained)",
			droppedSrc, droppedDst, maxKeys)
		if logFn != nil {
			logFn(SyslogWarning, msg)
		}
		slog.Warn(msg)
	}

	for _, e := range topSrc {
		msg := fmt.Sprintf("RT_FLOW_SESSION_AGGREGATE top-source=%q sessions=%d bytes=%d",
			e.IP, e.Sessions, e.Bytes)
		if logFn != nil {
			logFn(SyslogInfo, msg)
		}
		slog.Info(msg)
	}
	for _, e := range topDst {
		msg := fmt.Sprintf("RT_FLOW_SESSION_AGGREGATE top-destination=%q sessions=%d bytes=%d",
			e.IP, e.Sessions, e.Bytes)
		if logFn != nil {
			logFn(SyslogInfo, msg)
		}
		slog.Info(msg)
	}
}
