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
	key          FlowKey
	start        time.Time
	lastExport   time.Time
	lastActivity time.Time
	lastPackets  uint64
	lastBytes    uint64
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
// as activity for the inactive timer.
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
	if packets > f.lastPackets || bytes > f.lastBytes {
		// Activity is measured against exported baseline: progress since
		// last export means the flow is not idle.
		f.lastActivity = now
	}
	f.record.Packets = packets
	f.record.Bytes = bytes
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
	r.Packets = f.record.Packets - f.lastPackets
	r.Bytes = f.record.Bytes - f.lastBytes
	return r
}

// Close removes a flow on real session close and reports whether it was
// tracked.
func (t *FlowTracker) Close(key FlowKey) bool {
	if !t.enabled() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.flows[key]
	delete(t.flows, key)
	return ok
}

// CloseFlow forgets a tracked flow on real session close (v9).
func (e *Exporter) CloseFlow(key FlowKey) {
	if e.tracker != nil {
		e.tracker.Close(key)
	}
}

// CloseFlow forgets a tracked flow on real session close (IPFIX).
func (e *IPFIXExporter) CloseFlow(key FlowKey) {
	if e.tracker != nil {
		e.tracker.Close(key)
	}
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

// --- Exporter / IPFIXExporter adapters -------------------------------------
// Both exporters share the tracker logic; these methods keep the exported
// API identical so the daemon can drive either family the same way.

// TrackFlowOpen registers a flow on the v9 exporter (no-op without timeouts).
func (e *Exporter) TrackFlowOpen(key FlowKey, start time.Time) {
	if e.tracker != nil {
		e.tracker.TrackFlowOpenSimple(key, start)
	}
}

// TouchFlow updates cumulative counters on the v9 exporter.
func (e *Exporter) TouchFlow(key FlowKey, now time.Time, packets, bytes uint64) {
	if e.tracker != nil {
		e.tracker.Touch(key, now, packets, bytes)
	}
}

// CollectDueExports drains due interim/final records into the v9 batch.
func (e *Exporter) CollectDueExports(now time.Time) []FlowRecord {
	if e.tracker == nil {
		return nil
	}
	due := e.tracker.CollectDueExports(now)
	for _, r := range due {
		e.batch.add(r)
	}
	return due
}

// TrackFlowOpen registers a flow on the IPFIX exporter.
func (e *IPFIXExporter) TrackFlowOpen(key FlowKey, start time.Time) {
	if e.tracker != nil {
		e.tracker.TrackFlowOpenSimple(key, start)
	}
}

// TouchFlow updates cumulative counters on the IPFIX exporter.
func (e *IPFIXExporter) TouchFlow(key FlowKey, now time.Time, packets, bytes uint64) {
	if e.tracker != nil {
		e.tracker.Touch(key, now, packets, bytes)
	}
}

// CollectDueExports drains due interim/final records into the IPFIX batch.
func (e *IPFIXExporter) CollectDueExports(now time.Time) []FlowRecord {
	if e.tracker == nil {
		return nil
	}
	due := e.tracker.CollectDueExports(now)
	for _, r := range due {
		e.batch.add(r)
	}
	return due
}
