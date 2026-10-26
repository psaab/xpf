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
//     emits a final record and leaves the live tracker. A bounded
//     sampled-idle marker (#16747) retains the final-record baselines and
//     the record template so later packets of the same session are still
//     polled: progress re-arms a live entry, and the real SESSION_CLOSE
//     exports only the post-expiry remainder (lifetime minus the final
//     baselines) exactly once instead of reporting not-sampled. A real
//     SESSION_CLOSE with no post-expiry progress finds the marker, so no
//     duplicate final record is produced (ExportSessionClose on tracked
//     flows should be routed through Tracker.Close which suppresses the
//     duplicate).
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

// idleMarkerMax bounds the sampled-idle markers retained after inactive
// expiry (#16747). A marker is small (four baselines + a template copy),
// and the cap matches the route-mask cache ceiling: far above any
// realistic idle-then-resumed working set, yet a hard ceiling so a
// flood of distinct idle-expired flows cannot grow tracker state
// without bound. At the cap the whole marker set is cleared (see
// storeIdleMarkerLocked); affected closes fall back to #16742's close-time
// sampling decision and may re-export inactive-final counters if selected.
const idleMarkerMax = 8192

// idleMarker remembers a flow whose inactive expiry already emitted its
// final record (#16747). It carries everything needed to re-admit the
// session: the final record's cumulative baselines (what the collector
// has already seen), the last cumulative counters observed at expiry
// (the progress comparison for a re-arming Touch), and the record
// template copied onto later interim records.
type idleMarker struct {
	basePackets    uint64
	baseBytes      uint64
	baseRevPackets uint64
	baseRevBytes   uint64
	lastPackets    uint64
	lastBytes      uint64
	lastRevPackets uint64
	lastRevBytes   uint64
	record         FlowRecord
}

// FlowTracker tracks live flows for active/inactive export. Zero value is
// not usable; construct with NewFlowTracker. A nil tracker is safe: all
// methods are no-ops (exporters without timeouts keep close-only behaviour).
type FlowTracker struct {
	mu       sync.Mutex
	active   time.Duration
	inactive time.Duration
	flows    map[FlowKey]*trackedFlow
	idle     map[FlowKey]idleMarker
}

// NewFlowTracker returns a tracker, or nil when both timeouts are <= 0
// (close-only export, the pre-#15655 behaviour).
func NewFlowTracker(active, inactive time.Duration) *FlowTracker {
	if active <= 0 && inactive <= 0 {
		return nil
	}
	return &FlowTracker{active: active, inactive: inactive, flows: make(map[FlowKey]*trackedFlow), idle: make(map[FlowKey]idleMarker)}
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
	delete(t.idle, key)
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
		// #16747: an idle-expired flow re-enters on progress. The new
		// entry's baselines are the marker's (the inactive final already
		// emitted that span), so later deltas and the close remainder
		// never recount it. No progress leaves the marker untouched.
		m, idle := t.idle[key]
		if !idle {
			return
		}
		if packets <= m.lastPackets && bytes <= m.lastBytes {
			return
		}
		delete(t.idle, key)
		nf := &trackedFlow{key: key, start: now, lastExport: now, lastActivity: now,
			lastPackets: m.basePackets, lastBytes: m.baseBytes,
			lastRevPackets: m.baseRevPackets, lastRevBytes: m.baseRevBytes,
			record: m.record}
		// #17851: keep the per-field maxima (#16750), exactly as the
		// live-flow branch below does. Assigning the incoming snapshot
		// directly let a backwards-racing snapshot lower the stored
		// cumulative below the inactive final's coverage, so the next
		// export re-counted already-exported traffic.
		if packets > nf.record.Packets {
			nf.record.Packets = packets
		}
		if bytes > nf.record.Bytes {
			nf.record.Bytes = bytes
		}
		t.flows[key] = nf
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
		// #16747: re-arm on bidirectional progress (see Touch).
		m, idle := t.idle[key]
		if !idle {
			return
		}
		if fwdPackets+revPackets <= m.lastPackets+m.lastRevPackets && fwdBytes+revBytes <= m.lastBytes+m.lastRevBytes {
			return
		}
		delete(t.idle, key)
		nf := &trackedFlow{key: key, start: now, lastExport: now, lastActivity: now,
			lastPackets: m.basePackets, lastBytes: m.baseBytes,
			lastRevPackets: m.baseRevPackets, lastRevBytes: m.baseRevBytes,
			record: m.record}
		// #17851: per-field maxima, as in Touch above and the live
		// branch below.
		if fwdPackets > nf.record.Packets {
			nf.record.Packets = fwdPackets
		}
		if fwdBytes > nf.record.Bytes {
			nf.record.Bytes = fwdBytes
		}
		if revPackets > nf.record.RevPackets {
			nf.record.RevPackets = revPackets
		}
		if revBytes > nf.record.RevBytes {
			nf.record.RevBytes = revBytes
		}
		t.flows[key] = nf
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
			// #16747: the final record's cumulative coverage becomes
			// the baseline (lastExport baselines advanced by this
			// delta == the cumulative counters at expiry). Retain it
			// as a bounded marker so resumed traffic is re-polled and
			// the real close can export the post-expiry remainder.
			t.storeIdleMarkerLocked(key, idleMarker{
				basePackets: f.record.Packets, baseBytes: f.record.Bytes,
				baseRevPackets: f.record.RevPackets, baseRevBytes: f.record.RevBytes,
				lastPackets: f.record.Packets, lastBytes: f.record.Bytes,
				lastRevPackets: f.record.RevPackets, lastRevBytes: f.record.RevBytes,
				record: f.record,
			})
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
	if ok {
		delete(t.flows, key)
		delete(t.idle, key)
		return f.lastPackets, f.lastBytes, f.lastRevPackets, f.lastRevBytes, true
	}
	// #16747: the flow idle-expired earlier; its marker proves the open
	// was sampled and carries the final-record baselines, so the close
	// exports lifetime-minus-baseline (the post-expiry remainder, zero
	// when nothing resumed) exactly once. Consuming the marker here
	// keeps a duplicate close reporting not-sampled.
	if m, idle := t.idle[key]; idle {
		delete(t.idle, key)
		return m.basePackets, m.baseBytes, m.baseRevPackets, m.baseRevBytes, true
	}
	return 0, 0, 0, 0, false
}

// Clone returns an independent copy of the tracked flow, or nil.
// Used to carry live state to a replacement exporter (#16742).
func (t *FlowTracker) Clone(key FlowKey) *trackedFlow {
	if !t.enabled() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		return nil
	}
	cp := *f
	return &cp
}

// Adopt installs a previously cloned tracked flow unless one exists.
func (t *FlowTracker) Adopt(f *trackedFlow) bool {
	if !t.enabled() || f == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.flows[f.key]; ok {
		return false
	}
	cp := *f
	t.flows[f.key] = &cp
	return true
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
	// #16747: live keys plus idle-marker keys, deduplicated — the
	// daemon polls marker keys too so resumed traffic is observed.
	keys := make([]FlowKey, 0, len(t.flows)+len(t.idle))
	for k := range t.flows {
		keys = append(keys, k)
	}
	for k := range t.idle {
		if _, live := t.flows[k]; !live {
			keys = append(keys, k)
		}
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
	if ok {
		return true
	}
	_, idle := t.idle[key]
	return idle
}

// IdleLen reports the sampled-idle marker count (tests/metrics, #16747).
func (t *FlowTracker) IdleLen() int {
	if !t.enabled() {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.idle)
}

// storeIdleMarkerLocked retains m under key, bounding the marker set at
// idleMarkerMax (#16747). At the cap the whole set is cleared (the
// routemask.go hard-ceiling idiom): the evicted flows lose their
// re-admission chance and fall back to the pre-fix close-dropped
// behaviour, but tracker memory stays bounded. Caller holds t.mu.
func (t *FlowTracker) storeIdleMarkerLocked(key FlowKey, m idleMarker) {
	if t.idle == nil {
		t.idle = make(map[FlowKey]idleMarker)
	}
	if _, exists := t.idle[key]; !exists && len(t.idle) >= idleMarkerMax {
		clear(t.idle)
	}
	t.idle[key] = m
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
