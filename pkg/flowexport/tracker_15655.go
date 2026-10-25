package flowexport

import (
	"net"
	"sync"
	"time"
)

// #15655 V17-02: active/inactive timeout enforcement.
//
// ExportConfig.FlowActiveTimeout / FlowInactiveTimeout were compiled and
// rendered as live but had no consumer: records were exported only on
// session close. FlowTracker is the missing consumer. The daemon feeds it
// session-open events and periodic session snapshots (from `show security
// flow session` polling / SESSION_OPEN+tick), and each exporter's Run loop
// drains due records via CollectDueExports:
//
//   - Active: a flow whose time since its last export (or start) reaches
//     FlowActiveTimeout emits an interim record covering [windowStart, now]
//     with delta counters, and its window resets.
//   - Inactive: a flow with no counter progress for FlowInactiveTimeout
//     emits a final record and is forgotten. A real SESSION_CLOSE for the
//     same flow afterwards finds no tracker entry, so no duplicate final
//     record is produced (ExportSessionClose on tracked flows should be
//     routed through Tracker.Close which suppresses the duplicate).
//
// Counter snapshots are cumulative; interim/final records carry deltas
// since the last export so collector totals sum to the session total.

// FlowKey identifies a tracked flow (the pre-NAT 5-tuple).
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	IsIPv6   bool
}

// FlowKeyFromClose builds a FlowKey from close data.
func FlowKeyFromClose(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8, isV6 bool) FlowKey {
	return FlowKey{SrcIP: srcIP.String(), DstIP: dstIP.String(), SrcPort: srcPort, DstPort: dstPort, Protocol: proto, IsIPv6: isV6}
}

type trackedFlow struct {
	key            FlowKey
	start          time.Time
	lastExport     time.Time
	lastActivity   time.Time
	lastPackets    uint64
	lastBytes      uint64
	lastRevPackets uint64
	lastRevBytes   uint64
	// template fields copied onto emitted records
	record FlowRecord
}

// FlowTracker tracks live flows for active/inactive export. Zero value is
// not usable; construct with NewFlowTracker. A nil tracker is safe: all
// methods are no-ops (exporters without timeouts keep close-only behaviour).
type FlowTracker struct {
	mu       sync.Mutex
	active   time.Duration
	inactive time.Duration
	flows    map[FlowKey]*trackedFlow
}

// NewFlowTracker returns a tracker, or nil when both timeouts are <= 0
// (close-only export, the pre-#15655 behaviour).
func NewFlowTracker(active, inactive time.Duration) *FlowTracker {
	if active <= 0 && inactive <= 0 {
		return nil
	}
	return &FlowTracker{active: active, inactive: inactive, flows: make(map[FlowKey]*trackedFlow)}
}

func (t *FlowTracker) enabled() bool { return t != nil }

// TrackFlowOpen registers a newly opened flow. template supplies the
// tuple/NAT/interface fields copied onto interim records; counters start
// at zero. Re-opening an existing key resets its window.
func (t *FlowTracker) TrackFlowOpen(key FlowKey, start time.Time, template FlowRecord) {
	if !t.enabled() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	template.StartTime = start
	t.flows[key] = &trackedFlow{key: key, start: start, lastExport: start, lastActivity: start, record: template}
}

// TrackFlowOpenSimple registers a flow from its key/start only (used by
// tests and by daemon paths that only have the tuple at open time).
func (t *FlowTracker) TrackFlowOpenSimple(key FlowKey, start time.Time) {
	t.TrackFlowOpen(key, start, FlowRecord{
		SrcIP: net.ParseIP(key.SrcIP), DstIP: net.ParseIP(key.DstIP),
		SrcPort: key.SrcPort, DstPort: key.DstPort, Protocol: key.Protocol, IsIPv6: key.IsIPv6,
		StartTime: start,
	})
}

// Touch records cumulative counters for a flow at `now`; progress counts
// as activity for the inactive timer. The daemon feeds this from live
// session snapshots (#16303 F5), not only at close: without a live feed
// the active timer exported zero counters and the inactive timer
// removed continuously-active flows as if idle.
func (t *FlowTracker) Touch(key FlowKey, now time.Time, packets, bytes uint64) {
	if !t.enabled() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		return
	}
	// #16750: cumulative counters are monotonic per field. A snapshot
	// that raced backwards (helper restart, mirror-row alternation
	// between workers) must not lower the stored cumulative: the next
	// delta would otherwise under-report, and deltaRecord/baseline
	// arithmetic could be driven below its last-export baseline.
	progress := false
	if packets > f.record.Packets {
		f.record.Packets = packets
		progress = true
	}
	if bytes > f.record.Bytes {
		f.record.Bytes = bytes
		progress = true
	}
	if progress {
		// #15946: progress vs cumulative record, not last-export baseline
		// (which CollectDueExports advances, masking activity).
		f.lastActivity = now
	}
}

// TouchBidirectional is Touch with the reverse-direction cumulative
// counters the live session snapshot carries; IPFIX biflow records and
// the close-time totals use the same forward+reverse sum the daemon's
// close path feeds.
func (t *FlowTracker) TouchBidirectional(key FlowKey, now time.Time, fwdPackets, fwdBytes, revPackets, revBytes uint64) {
	if !t.enabled() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		return
	}
	// #16750: monotonic per field (see Touch), and activity is any
	// single field advancing — not the forward+reverse sum, which a
	// backward-moving mirror field can hold flat while another field
	// genuinely progresses.
	progress := false
	if fwdPackets > f.record.Packets {
		f.record.Packets = fwdPackets
		progress = true
	}
	if fwdBytes > f.record.Bytes {
		f.record.Bytes = fwdBytes
		progress = true
	}
	if revPackets > f.record.RevPackets {
		f.record.RevPackets = revPackets
		progress = true
	}
	if revBytes > f.record.RevBytes {
		f.record.RevBytes = revBytes
		progress = true
	}
	if progress {
		f.lastActivity = now
	}
}

// CollectDueExports returns interim (active-timeout) and final
// (inactive-timeout) records due at `now`, advancing each flow's export
// window. Interim records remain tracked; inactive flows are removed.
func (t *FlowTracker) CollectDueExports(now time.Time) []FlowRecord {
	if !t.enabled() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []FlowRecord
	for key, f := range t.flows {
		// Inactive first: an idle flow gets one final record, not an
		// interim plus a final.
		if t.inactive > 0 && now.Sub(f.lastActivity) >= t.inactive {
			out = append(out, f.deltaRecord(now))
			delete(t.flows, key)
			continue
		}
		if t.active > 0 && now.Sub(f.lastExport) >= t.active {
			out = append(out, f.deltaRecord(now))
			f.lastExport = now
			f.lastPackets = f.record.Packets
			f.lastBytes = f.record.Bytes
			f.lastRevPackets = f.record.RevPackets
			f.lastRevBytes = f.record.RevBytes
			// Window start for the next record is this export instant.
			f.start = now
		}
	}
	return out
}

// deltaRecord builds a record covering [windowStart, now] with counters
// since the last export.
func (f *trackedFlow) deltaRecord(now time.Time) FlowRecord {
	r := f.record
	r.StartTime = f.lastExport
	if r.StartTime.IsZero() {
		r.StartTime = f.start
	}
	r.EndTime = now
	// #16750: saturate like the close remainder (exporter_core.go
	// satSub): a record that raced below its last-export baseline
	// yields a zero delta, never a ~2^64 wrap that poisons collector
	// aggregates.
	r.Packets = satSub(f.record.Packets, f.lastPackets)
	r.Bytes = satSub(f.record.Bytes, f.lastBytes)
	r.RevPackets = satSub(f.record.RevPackets, f.lastRevPackets)
	r.RevBytes = satSub(f.record.RevBytes, f.lastRevBytes)
	return r
}

// Close removes a flow on real session close and reports whether it was
// tracked.
func (t *FlowTracker) Close(key FlowKey) bool {
	_, _, _, _, tracked := t.CloseWithBaseline(key)
	return tracked
}

// CloseWithBaseline atomically forgets a tracked flow AND returns its
// last-export counter baselines (#16303 fold 2). The real-close export
// must subtract these from the close event's lifetime counters: an
// active interim already emitted [0, baseline], so queueing the full
// lifetime at close would count that span twice. Returning the
// baseline with the removal keeps the extraction atomic — no window
// where a concurrent collect could emit the same span again.
func (t *FlowTracker) CloseWithBaseline(key FlowKey) (lastPackets, lastBytes, lastRevPackets, lastRevBytes uint64, tracked bool) {
	if !t.enabled() {
		return 0, 0, 0, 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		return 0, 0, 0, 0, false
	}
	delete(t.flows, key)
	return f.lastPackets, f.lastBytes, f.lastRevPackets, f.lastRevBytes, true
}

// Keys returns a snapshot of the currently tracked flow keys, so the
// daemon's live-counter poll can address session lookups to exactly the
// flows this tracker cares about instead of enumerating every session.
func (t *FlowTracker) Keys() []FlowKey {
	if !t.enabled() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	keys := make([]FlowKey, 0, len(t.flows))
	for k := range t.flows {
		keys = append(keys, k)
	}
	return keys
}

// Len reports tracked flow count (tests/metrics).
func (t *FlowTracker) Len() int {
	if !t.enabled() {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// Has reports whether key is tracked (#15946 close-cleanup).
func (t *FlowTracker) Has(key FlowKey) bool {
	if !t.enabled() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.flows[key]
	return ok
}

// CloseFlow / TrackFlowOpen / TouchFlow / CollectDueExports adapters
// live on exporterCore (exporter_core.go, #16126): one definition
// promoted to both exporters, so the daemon drives either family the
// same way. Only the batch-draining CollectDueExports wrapper differs
// per exporter in name only -- it is exporterCore.collectDueExports
// behind these thin promoted wrappers.

// CollectDueExports drains due interim/final records into the v9 batch.
func (e *Exporter) CollectDueExports(now time.Time) []FlowRecord {
	return e.collectDueExports(now)
}

// CollectDueExports drains due interim/final records into the IPFIX batch.
func (e *IPFIXExporter) CollectDueExports(now time.Time) []FlowRecord {
	return e.collectDueExports(now)
}
