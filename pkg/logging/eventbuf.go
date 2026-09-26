package logging

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EventRecord is a formatted event stored in the event buffer.
type EventRecord struct {
	Time            time.Time
	Type            string // "SESSION_OPEN", "POLICY_DENY", etc.
	SrcAddr         string // "10.0.1.5:443"
	DstAddr         string
	Protocol        string // "TCP", "UDP" (rendered name; numeric for unnamed)
	ProtocolNum     uint8  // raw IP protocol number the record carries (#3382). The matcher compares this directly rather than re-parsing the rendered name: numeric comparison stays total for named, numeric-only, and any future render-only protocols (the ProtocolName↔ProtocolNumber round-trip is closed since #3393, but the raw number is the robust key regardless).
	Action          string // "permit", "deny"
	PolicyID        uint32
	RuleID          uint32
	TermID          uint32
	Reason          string
	OwnerRGID       int16
	InZone          uint16
	OutZone         uint16
	ScreenCheck     string // for SCREEN_DROP
	SessionPkts     uint64 // for SESSION_CLOSE (client→server)
	SessionBytes    uint64
	NATSrcAddr      string // "172.16.1.1:12345" (post-NAT source)
	NATDstAddr      string // "10.0.2.1:80" (post-NAT destination)
	InZoneName      string // resolved zone name
	OutZoneName     string // resolved zone name
	ElapsedTime     uint32 // seconds since session creation (for CLOSE)
	Created         uint32 // #2465: absolute session-creation Unix seconds (for CLOSE); 0 = unknown (exporter falls back to the packet-count estimate)
	CreatedNanos    uint32 // #2853: sub-second nanosecond remainder (0..=999_999_999) of the session-creation instant (SESSION_CLOSE only; rides the close-unused [44:48] wire slot). Combined with Created so the flow StartTime keeps millisecond resolution.
	PolicyName      string // resolved policy name (e.g. "allow-everything")
	RevSessionPkts  uint64 // packets from server (for SESSION_CLOSE)
	RevSessionBytes uint64 // bytes from server (for SESSION_CLOSE)
	AppName         string // resolved application name (e.g. "junos-http")
	IngressIface    string // resolved interface name (e.g. "trust0")
	// IngressIfindex is the raw numeric ingress ifindex carried on the
	// SESSION_CLOSE wire frame ([128:132], #2615). IngressIface is the
	// name resolution of this value; the numeric form is retained so the
	// NetFlow v9 / IPFIX exporters can populate ingressInterface
	// (IE 10 / IN_SNMP), which is an SNMP ifIndex, not a name (#2749).
	// 0 means the dataplane could not attribute an ingress interface.
	IngressIfindex uint32
	// #2749: class-of-service / interface-attribution fields carried on the
	// SESSION_CLOSE wire frame's additive [144:152] block. TOS is the IP ToS
	// byte (DSCP<<2, ECN cleared) observed on the forward direction;
	// TCPControlBits is the OR of every TCP flag byte seen over the flow;
	// EgressIfindex is the SNMP ifIndex of the session's resolved output
	// interface. They drive the re-introduced NetFlow v9 srcTos (IE 5) /
	// tcpFlags (IE 6) / OutputSNMP (IE 14) and the IPFIX ipClassOfService /
	// tcpControlBits / egressInterface close-record fields. 0 keeps the
	// collector's "unknown" sentinel for a frame that did not carry them
	// (a short legacy frame, or a non-close event).
	TOS            uint8
	TCPControlBits uint8
	EgressIfindex  uint32
	CloseReason    string // "idle Timeout", "TCP FIN", "TCP RST", etc.
	// SessionID is the dataplane's STABLE per-session identity (#4915). On a
	// SESSION_CREATE / SESSION_CLOSE frame it is decoded from the [152:160] wire
	// slot — the SAME uint64 the userspace-dp session table assigns and that
	// `show security flow session` will surface — so a session's open and close
	// records correlate and a reused 5-tuple is disambiguated. 0 means "unknown":
	// a non-session event (deny/screen/filter), or a short legacy frame that did
	// not carry the slot. Before #4915 this field held a per-EVENT monotonic
	// ordinal that could never match across a session's create and close; that
	// ordinal now lives in EventSeq.
	SessionID uint64
	// EventSeq is a per-EVENT monotonic ordinal stamped by the live event reader
	// (#4915). Unlike SessionID it increments on EVERY event (including
	// deny/screen/filter), so it orders events within a reader session and
	// exposes gaps; it is NOT a session identity and does not correlate a
	// session's create with its close. It is 0 on records produced by
	// DecodeRawEventRecord (which has no reader-scoped counter).
	EventSeq uint64
	// BufSeq is the EventBuffer's own publish sequence (#5064). Unlike
	// EventSeq (reader-scoped, and 0 for the direct Add callers — health
	// probes, HA event replay), BufSeq is stamped by EventBuffer.Add on
	// EVERY record that transits the ring, from 1 and strictly monotonic per
	// buffer. It is the same value stored in the ring, so a live subscriber
	// and a Latest() snapshot agree. A subscriber detects lost records by a
	// discontinuity: two consecutively delivered records whose BufSeq differs
	// by more than 1 means the intervening records were dropped because the
	// subscriber's channel was full. 0 means the record never went through
	// Add (a bare EventRecord literal or DecodeRawEventRecord).
	BufSeq uint64
	// Overrun is set on the FIRST record delivered to a subscriber after that
	// subscriber missed one or more records to a full channel (#5064). It
	// gives a consumer that is not tracking BufSeq an explicit "you lost
	// records" signal in-band; the exact count is the per-subscription
	// Dropped() counter. It is per-delivery (subscriber-scoped): the same
	// underlying event is delivered with Overrun=true only to the subscriber
	// that gapped, and the flag is cleared once that subscriber receives it.
	// It is always false on records returned by Latest()/LatestFiltered()
	// (the ring copy is never overrun-flagged).
	Overrun bool
}

// EventBuffer is a thread-safe circular buffer for recent events.
type EventBuffer struct {
	mu    sync.RWMutex
	buf   []EventRecord
	size  int
	head  int    // next write position
	count int    // number of events stored
	seq   uint64 // monotonically increasing sequence number

	subMu   sync.RWMutex
	subs    map[*Subscription]struct{}
	maxSubs int // cap on concurrent subscribers (0 = unbounded)

	// droppedTotal counts records lost across ALL subscribers because a
	// subscriber's channel was full when Add fanned out (#5064). It is the
	// aggregate drop metric the intentionally-lossy fan-out must expose so a
	// slow REST-SSE / gRPC / CLI-monitor consumer silently shedding security
	// records is visible (surfaced as xpf_event_stream_subscriber_dropped_total).
	droppedTotal atomic.Uint64

	// refused counts TrySubscribe calls rejected at the maxSubs cap (#10910).
	// The daemon's REST SSE handlers and the gRPC MonitorPacketDrop RPC share
	// ONE EventBuffer (daemon_run_servers.go wires the same instance to both
	// servers), so this single counter is the admission-denial accounting for
	// BOTH surfaces — an SSE 503 and a gRPC ResourceExhausted increment the
	// same number (surfaced as xpf_event_stream_subscriber_refusals_total).
	// Monotonic; never reset.
	refused atomic.Uint64
}

// Subscription receives new events from an EventBuffer.
type Subscription struct {
	C    chan EventRecord
	eb   *EventBuffer
	once sync.Once

	// dropped counts records this specific subscriber lost because its
	// channel C was full when Add tried to deliver (#5064). Exposed via
	// Dropped() so the consumer (or a test) can observe its own loss; a
	// nonzero value means the stream this subscriber saw is gapped.
	dropped atomic.Uint64
	// overrun is armed when a delivery to this subscriber is dropped and
	// disarmed once the next record is delivered carrying EventRecord.Overrun
	// (#5064). It is the per-subscriber state behind the in-band overrun flag.
	overrun atomic.Bool
}

// Close unsubscribes and closes the channel (#3384). It honors the documented
// contract so a consumer ranging over sub.C until it closes terminates instead
// of blocking forever. The unsubscribe runs first under eb.subMu (write lock),
// which removes this subscription from the fan-out map and waits out any
// in-flight Add send — so close(s.C) afterwards can never race a send-on-closed
// in Add. sync.Once makes a double Close safe (the in-tree consumers Close via
// defer; some also Close explicitly).
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.eb.unsubscribe(s)
		close(s.C)
	})
}

// defaultEventBufferSize is the fallback ring capacity used when a caller
// requests a non-positive size. A zero-capacity ring is a footgun: Add
// indexes buf[head] and computes head % size, so size==0 panics with an
// index-out-of-range / divide-by-zero on the first event (#3342).
const defaultEventBufferSize = 1000

// defaultMaxSubscribers bounds the number of concurrent event-stream
// subscribers (#4484 L-2). Every Add fans out O(N) over the subscriber set
// and each subscriber holds a buffered channel, so an unbounded set is a
// memory + per-event-CPU DoS vector — chiefly via the untrusted REST SSE
// surface (/events/stream, /logs/stream), which can open many connections.
// This mirrors metricsMaxInFlight (#4162), which bounds concurrent /metrics
// scrapes. The cap counts ALL subscribers uniformly; the trusted internal
// consumers (gRPC event stream, CLI monitor) use Subscribe (never rejected)
// and are few, so the untrusted REST path is what the cap actually gates via
// TrySubscribe.
const defaultMaxSubscribers = 64

// NewEventBuffer creates a new event buffer with the given capacity. A
// non-positive size is clamped to defaultEventBufferSize so the ring is
// always usable; Add must never index an empty buffer or divide by zero.
func NewEventBuffer(size int) *EventBuffer {
	if size < 1 {
		size = defaultEventBufferSize
	}
	return &EventBuffer{
		buf:     make([]EventRecord, size),
		size:    size,
		subs:    make(map[*Subscription]struct{}),
		maxSubs: defaultMaxSubscribers,
	}
}

// Add appends an event to the buffer, overwriting the oldest if full.
// Subscribers are notified non-blocking.
//
// Every record is stamped with the buffer's monotonic BufSeq before it is
// stored and fanned out (#5064), so both the ring copy and every delivered
// copy carry the same sequence. The fan-out is intentionally lossy — a
// subscriber whose channel is full is skipped rather than blocking Add — but
// the loss is now observable: the record is counted (per-subscriber Dropped()
// and the aggregate DroppedTotal()), the next delivery to that subscriber
// carries Overrun=true, and the BufSeq discontinuity marks exactly which
// records were shed. A forensic consumer can no longer mistake a gapped
// stream for a complete one.
func (eb *EventBuffer) Add(rec EventRecord) {
	eb.mu.Lock()
	eb.seq++
	rec.BufSeq = eb.seq
	eb.buf[eb.head] = rec
	eb.head = (eb.head + 1) % eb.size
	if eb.count < eb.size {
		eb.count++
	}
	eb.mu.Unlock()

	eb.subMu.RLock()
	for sub := range eb.subs {
		// Per-subscriber copy: the Overrun flag is subscriber-scoped (only
		// the subscriber that gapped sees it), and the record must not be
		// mutated in place while other subscribers still receive it.
		out := rec
		if sub.overrun.Load() {
			out.Overrun = true
		}
		select {
		case sub.C <- out:
			// Delivered. If this record carried the overrun flag, disarm it
			// so the next delivery is clean — the consumer has now been told
			// it missed records.
			if out.Overrun {
				sub.overrun.Store(false)
			}
		default:
			// Channel full: the record is lost for THIS subscriber. Count it
			// (per-subscriber + aggregate) and arm the overrun flag so the
			// next successful delivery signals the gap in-band. The BufSeq
			// discontinuity marks the loss regardless. #5064.
			sub.dropped.Add(1)
			eb.droppedTotal.Add(1)
			sub.overrun.Store(true)
		}
	}
	eb.subMu.RUnlock()
}

// DroppedTotal returns the aggregate number of records dropped across all
// subscribers because a subscriber's channel was full when Add fanned out
// (#5064). It is monotonic for the life of the buffer and is the aggregate
// drop metric exported to Prometheus.
func (eb *EventBuffer) DroppedTotal() uint64 { return eb.droppedTotal.Load() }

// SubscriberRefusals reports how many TrySubscribe calls this buffer rejected
// because the live subscriber cap was reached. It includes every control
// surface sharing the buffer (REST SSE, gRPC, and internal callers).
func (eb *EventBuffer) SubscriberRefusals() uint64 { return eb.refused.Load() }

// Dropped returns the number of records THIS subscriber lost because its
// channel was full when Add tried to deliver (#5064). A nonzero value means
// the stream this subscriber observed is gapped; the gaps are locatable via
// the BufSeq discontinuities on the records it did receive.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// OverrunLine formats the in-band gap marker a consumer emits when it observes
// the #5064 loss signal. Consumers pass the increment in Dropped() since the
// last marker, so consecutive overruns preserve exact loss accounting.
func OverrunLine(dropped uint64) string {
	return fmt.Sprintf("** %d records lost (overrun) **", dropped)
}

// EventGapTracker reports each newly observed subscriber loss exactly once.
// Dropped() can advance before the consumer reaches the first Overrun-flagged
// record already queued, so it remembers that marker and does not report the
// same gap a second time when the flagged record arrives.
type EventGapTracker struct {
	dropped        uint64
	overrunPending bool
}

// Observe returns the newly lost record count and whether the current record
// reveals a gap. Call it before applying consumer filters so a dropped event
// outside the selected filter still marks the stream as incomplete.
func (g *EventGapTracker) Observe(sub *Subscription, rec EventRecord) (uint64, bool) {
	dropped := sub.Dropped()
	if dropped > g.dropped {
		lost := dropped - g.dropped
		g.dropped = dropped
		if rec.Overrun {
			g.overrunPending = false
		} else {
			g.overrunPending = true
		}
		return lost, true
	}
	if rec.Overrun {
		if g.overrunPending {
			g.overrunPending = false
			return 0, false
		}
		return 0, true
	}
	return 0, false
}

// Finish returns drops that were not followed by a delivered record before
// the consumer stopped, allowing terminal consumers to report trailing loss.
func (g *EventGapTracker) Finish(sub *Subscription) uint64 {
	dropped := sub.Dropped()
	if dropped <= g.dropped {
		return 0
	}
	lost := dropped - g.dropped
	g.dropped = dropped
	return lost
}

// Subscribe returns a Subscription that receives new events.
// Call Close() on the subscription when done.
//
// Subscribe never fails: it is the entry point for the TRUSTED, inherently
// bounded internal consumers (gRPC event stream, CLI monitor). The untrusted
// REST SSE surface must use TrySubscribe, which enforces the concurrency cap.
func (eb *EventBuffer) Subscribe(bufSize int) *Subscription {
	if bufSize < 1 {
		bufSize = 64
	}
	sub := &Subscription{
		C:  make(chan EventRecord, bufSize),
		eb: eb,
	}
	eb.subMu.Lock()
	eb.subs[sub] = struct{}{}
	eb.subMu.Unlock()
	return sub
}

// TrySubscribe is Subscribe with a concurrency cap (#4484 L-2): it returns nil
// when the live subscriber count has reached maxSubs, so the untrusted REST
// SSE surface (/events/stream, /logs/stream) cannot grow the fan-out set — and
// its per-event O(N) cost — without bound. Callers MUST handle a nil return
// (the REST handlers respond 503). Trusted internal callers use Subscribe,
// which never fails but still counts toward the cap here.
func (eb *EventBuffer) TrySubscribe(bufSize int) *Subscription {
	if bufSize < 1 {
		bufSize = 64
	}
	sub := &Subscription{
		C:  make(chan EventRecord, bufSize),
		eb: eb,
	}
	eb.subMu.Lock()
	if eb.maxSubs > 0 && len(eb.subs) >= eb.maxSubs {
		eb.refused.Add(1)
		eb.subMu.Unlock()
		return nil
	}
	eb.subs[sub] = struct{}{}
	eb.subMu.Unlock()
	return sub
}

func (eb *EventBuffer) unsubscribe(sub *Subscription) {
	eb.subMu.Lock()
	delete(eb.subs, sub)
	eb.subMu.Unlock()
}

// EventFilter specifies criteria for filtering events.
//
// Zone-filter presence is tracked by HasZone, NOT by overloading Zone==0 as
// "no filter" (#3338). Zone IDs are 1-based (the pkg/dataplane compiler
// assigns 1..N; see compiler.go phase 1), so zone 0 is the "unknown" /
// unassigned zone — the pre-classification drops, host-inbound, and
// emitted-before-zone-resolution events. Those are exactly the records an
// operator needs to isolate during an incident, so zone 0 MUST be a
// selectable filter value. With the old `Zone==0 means no filter` sentinel
// they were silently invisible to any zone-filtered query.
type EventFilter struct {
	Zone     uint16 // zone ID to match against InZone/OutZone; gated by HasZone
	HasZone  bool   // true if Zone is an active filter (0 = the unknown zone)
	Protocol string // exact case-insensitive match on Protocol ("" = no filter)
	Action   string // exact case-insensitive match on Action ("" = no filter)
}

// IsEmpty returns true if no filter criteria are set.
func (f EventFilter) IsEmpty() bool {
	return !f.HasZone && f.Protocol == "" && f.Action == ""
}

func (f EventFilter) matches(rec *EventRecord) bool {
	if f.HasZone && rec.InZone != f.Zone && rec.OutZone != f.Zone {
		return false
	}
	// Exact (case-insensitive) match, NOT substring: substring matching
	// over-matches for forensic queries — protocol=C would match TCP,
	// ICMP, and ICMPv6 simultaneously, and action substrings are equally
	// ambiguous (#2939). This aligns the event filter with the exact
	// matching the other operator surfaces use.
	if f.Protocol != "" && !strings.EqualFold(rec.Protocol, f.Protocol) {
		return false
	}
	if f.Action != "" && !strings.EqualFold(rec.Action, f.Action) {
		return false
	}
	return true
}

// LatestFiltered returns the most recent n events matching the filter, newest first.
func (eb *EventBuffer) LatestFiltered(n int, f EventFilter) []EventRecord {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if n <= 0 {
		return nil
	}

	var result []EventRecord
	for i := 0; i < eb.count && len(result) < n; i++ {
		idx := (eb.head - 1 - i + eb.size) % eb.size
		if f.matches(&eb.buf[idx]) {
			result = append(result, eb.buf[idx])
		}
	}
	return result
}

// Latest returns the most recent n events, newest first.
func (eb *EventBuffer) Latest(n int) []EventRecord {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	// Guard non-positive n first: a negative count must not reach
	// make([]EventRecord, n), which panics ("makeslice: len out of
	// range"). This mirrors LatestFiltered's `n <= 0` contract so a
	// count argument behaves identically on both surfaces (#3342).
	if n <= 0 {
		return nil
	}
	if n > eb.count {
		n = eb.count
	}
	if n == 0 {
		return nil
	}

	result := make([]EventRecord, n)
	for i := 0; i < n; i++ {
		// Walk backwards from the most recent entry
		idx := (eb.head - 1 - i + eb.size) % eb.size
		result[i] = eb.buf[idx]
	}
	return result
}
