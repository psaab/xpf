package flowexport

// #16126: shared FlowRecord enrichment core + exporterCore.
//
// Before #16126 the NetFlow v9 and IPFIX ExportSessionClose bodies were
// byte-for-byte twins (flowStartTime fallback counting, post-NAT
// resolution, route-mask resolution + unresolved counting, FlowRecord
// assembly) and every per-exporter accessor (Stats, batch depth/drop,
// retire/handoff, collector health, close) was duplicated across the two
// structs. A fix applied to one twin and missed on the other silently
// diverged the protocols' view of the same flow.
//
// The narrowed survivor form (validated Codex + Opus + Wonder) shares
// ONLY this enrichment and lifecycle core. The encoders stay separate
// and stateful: NetFlow v9 increments its sequence per MESSAGE while
// IPFIX carries/increments the cumulative data-record count, so a
// unified field table (rejected step 5) or a pure Encode(records, seq)
// (unsound) was deliberately NOT built. Wire identity of both encoders
// is pinned by testdata/golden_16126.txt, captured before this refactor.
//
// exporterCore is embedded by value in both exporters. Embedding (not a
// type alias -- alias types were rejected as unsound) keeps each
// exporter's own state (sequence counter, template bytes, tracker) on
// the outer struct while the shared fields and methods have exactly one
// definition. Methods on the unexported core are promoted, so existing
// call sites (e.batch, e.tracker, e.conns, e.MaskResolver, accessors)
// compile unchanged.
//
// Allocation invariant: buildFlowRecord performs no allocation beyond
// what the two pre-refactor twins performed -- it copies net.IP slice
// headers and values into a FlowRecord by value, exactly as the inline
// struct literals did. BenchmarkBuildFlowRecordAllocation pins the
// per-call allocation count so a future enrichment change cannot add a
// copy per flow unnoticed.

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// enrichmentStats are the data-quality counters buildFlowRecord reports
// back to each exporter's core. One struct returned by value -- no
// per-flow allocation, no callbacks into the exporter.
type enrichmentStats struct {
	estimatedDurations  uint64 // close records with no creation stamp
	clockSkewClamped    uint64 // creation stamps clamped to close time
	routeMaskUnresolved uint64 // route-mask halves exported as unresolved 0
}

// exporterCore holds the protocol-independent exporter state and the
// shared enrichment pipeline. Both Exporter (NetFlow v9) and
// IPFIXExporter embed it; protocol-specific state (sequence semantics,
// template sets, v9 boot-time anchor, IPFIX sampler options) stays on
// the outer structs because it MUST NOT be unified (#16126).
type exporterCore struct {
	// MaskResolver resolves the per-flow src/dst route prefix length
	// (NetFlow IE 9/13, IPv6 IE 29/30 / IPFIX IE 9/13/29/30) from the FIB
	// at export time. Nil on a zero-value exporter (masks stay 0, the
	// pre-#2866 behaviour); the daemon reconcile path sets it via
	// NewRouteMaskResolver so production records carry the real
	// matching-route prefix length (#2866).
	MaskResolver MaskResolver
	// tracker enforces active/inactive timeouts (#15655); nil means
	// close-only export.
	tracker *FlowTracker
	// sampledFlows remembers flows selected at SESSION_OPEN when this
	// exporter has no active/inactive tracker (tracker == nil). Without
	// it, a close-only exporter could not distinguish "open was sampled"
	// from "open was not sampled" without consuming a second 1-in-N slot
	// at close. Keys are deleted on close, so the set is bounded by live
	// sampled sessions for this exporter.
	sampledMu    sync.Mutex
	sampledFlows map[FlowKey]struct{}

	batch flowBatch
	conns *collectorConns

	exportedFlows atomic.Uint64
	exportedPkts  atomic.Uint64
	// #2465/#11699: close records without a creation timestamp, emitted
	// with zero duration at close time rather than a packet-count estimate.
	estimatedDurations atomic.Uint64
	// #3744: route-mask halves that did not resolve to a FIB route and
	// were exported as an unresolved 0 rather than a real matched-route
	// prefix length.
	routeMaskUnresolved atomic.Uint64
	// #13305: close records whose Created stamp is later than close time,
	// clamped to zero duration.
	clockSkewClamped atomic.Uint64
}

// buildFlowRecord converts one session-close event into the shared
// FlowRecord both encoders consume. It is the single definition of the
// enrichment the two ExportSessionClose twins used to duplicate:
//
//   - flow start: flowStartTime resolves rec.Created (+CreatedNanos);
//     a missing stamp yields StartTime == close time (counted in
//     stats.estimatedDurations), a future stamp clamps to close time
//     (stats.clockSkewClamped) (#2465/#11699/#13305).
//   - post-NAT: resolvePostNAT with pre-NAT fallback so every record
//     carries the RFC 5103/8158 post-NAT fields (post == pre when the
//     flow was not translated) (#2526).
//   - route masks: resolveMasks scoped to the ingress VRF (evt.InIf,
//     evt.OutIf fallback); unresolved halves are counted in
//     stats.routeMaskUnresolved (#2866/#3744).
//   - protocol: rec.ProtocolNum, the raw number the dataplane stamped,
//     NOT evt.Protocol's name-table value (#3939).
//
// includeReverse is the ONLY protocol divergence in enrichment: IPFIX
// exports the RFC 5103 biflow reverse counters (rec.RevSessionPkts /
// RevSessionBytes, PEN 29305) while NetFlow v9 has no standard reverse
// element and leaves RevPackets/RevBytes zero (v9 exports the
// initiator-direction volume only, #3746). Passing it explicitly keeps
// that divergence visible at both call sites instead of hiding it in a
// protocol switch inside the core.
//
// The record is returned by value; no allocation is added over the
// pre-refactor inline literals (IP slice headers are copied, the
// backing arrays are shared with the event, as before).
func (c *exporterCore) buildFlowRecord(rec logging.EventRecord, evt SessionCloseData, includeReverse bool) (FlowRecord, enrichmentStats) {
	startTime, missingCreated, skewClamped := flowStartTime(rec)
	var stats enrichmentStats
	if missingCreated {
		stats.estimatedDurations = 1
	}
	if skewClamped {
		stats.clockSkewClamped = 1
	}
	natSrcIP, natDstIP, natSrcPort, natDstPort := resolvePostNAT(
		evt.SrcIP, evt.DstIP, evt.SrcPort, evt.DstPort,
		evt.NATSrcIP, evt.NATDstIP, evt.NATSrcPort, evt.NATDstPort)
	srcMask, dstMask, maskMisses := resolveMasks(c.MaskResolver, evt.SrcIP, evt.DstIP, evt.InIf, evt.OutIf)
	stats.routeMaskUnresolved = maskMisses

	fr := FlowRecord{
		SrcIP:      evt.SrcIP,
		DstIP:      evt.DstIP,
		SrcPort:    evt.SrcPort,
		DstPort:    evt.DstPort,
		Protocol:   rec.ProtocolNum,
		Packets:    rec.SessionPkts,
		Bytes:      rec.SessionBytes,
		StartTime:  startTime,
		EndTime:    rec.Time,
		IsIPv6:     evt.IsIPv6,
		SrcMask:    srcMask,
		DstMask:    dstMask,
		InIf:       evt.InIf,
		TOS:        evt.TOS,
		TCPFlags:   evt.TCPFlags,
		OutIf:      evt.OutIf,
		Direction:  evt.Direction,
		NATSrcIP:   natSrcIP,
		NATDstIP:   natDstIP,
		NATSrcPort: natSrcPort,
		NATDstPort: natDstPort,
	}
	if includeReverse {
		fr.RevPackets = rec.RevSessionPkts
		fr.RevBytes = rec.RevSessionBytes
	}
	return fr, stats
}

// exportSessionClose is the shared ExportSessionClose body: enrich one
// close event, fold the enrichment counters into this exporter's core,
// and queue the record. includeReverse selects the IPFIX-only biflow
// counters (see buildFlowRecord).
func (c *exporterCore) exportSessionClose(rec logging.EventRecord, evt SessionCloseData, includeReverse bool) {
	fr, stats := c.buildFlowRecord(rec, evt, includeReverse)
	if stats.estimatedDurations > 0 {
		c.estimatedDurations.Add(stats.estimatedDurations)
	}
	if stats.clockSkewClamped > 0 {
		c.clockSkewClamped.Add(stats.clockSkewClamped)
	}
	if stats.routeMaskUnresolved > 0 {
		c.routeMaskUnresolved.Add(stats.routeMaskUnresolved)
	}
	c.batch.add(fr)
}

// collectDueExports drains due interim/final tracker records into the
// batch (#15655). Shared by both exporters' CollectDueExports wrappers.
func (c *exporterCore) collectDueExports(now time.Time) []FlowRecord {
	if c.tracker == nil {
		return nil
	}
	due := c.tracker.CollectDueExports(now)
	for _, r := range due {
		c.batch.add(r)
	}
	return due
}

// --- Shared lifecycle / stats accessors (one definition, both exporters) ---

// Stats returns export statistics: flow records and data packets
// successfully written to at least one collector. Template-refresh
// packets are not counted.
func (c *exporterCore) Stats() (flows, packets uint64) {
	return c.exportedFlows.Load(), c.exportedPkts.Load()
}

// EstimatedDurations returns the count of exported close records missing
// a creation timestamp (#2465/#11699). Those records use
// StartTime=EndTime rather than a packet-count estimate.
func (c *exporterCore) EstimatedDurations() uint64 {
	return c.estimatedDurations.Load()
}

// RouteMaskUnresolved returns the count of exported route-mask halves
// (#3744) that did not resolve to a FIB route and were exported as an
// unresolved 0 rather than a real matched-route prefix length.
func (c *exporterCore) RouteMaskUnresolved() uint64 {
	return c.routeMaskUnresolved.Load()
}

// ClockSkewClamped returns the number of exported close records whose
// future creation timestamp was clamped to the close time (#13305).
func (c *exporterCore) ClockSkewClamped() uint64 { return c.clockSkewClamped.Load() }

// BatchDepth returns the current number of flow records pending in the
// export batch (both families combined). Normally near 0 -- the Run
// goroutine drains every 100ms (#3747).
func (c *exporterCore) BatchDepth() uint64 { return c.batch.depth() }

// BatchMaxDepth returns the high-water mark of the pending batch depth (#3747).
func (c *exporterCore) BatchMaxDepth() uint64 { return c.batch.MaxDepth() }

// BatchDropped returns the cumulative count of flow records dropped
// because the export batch was at capacity (#3747).
func (c *exporterCore) BatchDropped() uint64 { return c.batch.Dropped() }

// Retire quiesces the exporter's batch admission lease ahead of the
// final flush that Run performs on ctx cancel (#4963). See flowBatch.retire.
func (c *exporterCore) Retire() { c.batch.retire() }

// HandoffDropped returns the count of session-close records this
// exporter rejected because they arrived after it was retired (#4963).
func (c *exporterCore) HandoffDropped() uint64 { return c.batch.HandoffDropped() }

// SetHandoffCounter injects the fixed-cardinality family-level counter
// the batch also increments on a handoff reject (#4963). Called once at
// construction before Run starts.
func (c *exporterCore) SetHandoffCounter(counter *atomic.Uint64) {
	c.batch.setSharedHandoff(counter)
}

// CollectorHealth returns a per-collector write-health snapshot (#2464):
// write attempts/failures, last error, and last success/failure
// timestamps for every collector this exporter writes to.
func (c *exporterCore) CollectorHealth() []CollectorHealth {
	return c.conns.health()
}

// Close shuts down all collector connections.
func (c *exporterCore) Close() { c.conns.close() }

// CloseFlow forgets a flow on real session close (#15655) and reports
// whether it had been selected at open. The boolean is the close-side
// sampling decision: callers must not consume another 1-in-N slot for a
// flow whose open already made the instance's one decision.
func (c *exporterCore) CloseFlow(key FlowKey) bool {
	tracked := false
	if c.tracker != nil {
		tracked = c.tracker.Close(key)
	}
	c.sampledMu.Lock()
	_, sampled := c.sampledFlows[key]
	if sampled {
		delete(c.sampledFlows, key)
	}
	c.sampledMu.Unlock()
	return tracked || sampled
}

// MarkFlowSampledAtOpen records that the instance's single sampling
// decision selected this flow at SESSION_OPEN. Tracked flows already
// carry that fact in the tracker; close-only exporters use this set.
func (c *exporterCore) MarkFlowSampledAtOpen(key FlowKey) {
	if c.tracker != nil {
		return
	}
	c.sampledMu.Lock()
	if c.sampledFlows == nil {
		c.sampledFlows = make(map[FlowKey]struct{})
	}
	c.sampledFlows[key] = struct{}{}
	c.sampledMu.Unlock()
}

// ForgetFlowSampledAtOpen drops an open-side selection without treating
// it as a close export decision (used when an exporter is retired).
func (c *exporterCore) ForgetFlowSampledAtOpen(key FlowKey) {
	c.sampledMu.Lock()
	delete(c.sampledFlows, key)
	c.sampledMu.Unlock()
}

// TrackFlowOpen registers a flow for active/inactive tracking (#15655);
// no-op without timeouts.
func (c *exporterCore) TrackFlowOpen(key FlowKey, start time.Time) {
	if c.tracker != nil {
		c.tracker.TrackFlowOpenSimple(key, start)
	}
}

// TrackFlowOpenRecord registers with a full template (#15946: NAT/ifindex/masks).
func (c *exporterCore) TrackFlowOpenRecord(key FlowKey, start time.Time, template FlowRecord) {
	if c.tracker != nil {
		c.tracker.TrackFlowOpen(key, start, template)
	}
}

// TouchFlow updates cumulative counters for a tracked flow (#15655).
func (c *exporterCore) TouchFlow(key FlowKey, now time.Time, packets, bytes uint64) {
	if c.tracker != nil {
		c.tracker.Touch(key, now, packets, bytes)
	}
}

// TouchFlowBidirectional feeds one live session snapshot's cumulative
// forward+reverse counters (#16303 F5).
func (c *exporterCore) TouchFlowBidirectional(key FlowKey, now time.Time, fwdPackets, fwdBytes, revPackets, revBytes uint64) {
	if c.tracker != nil {
		c.tracker.TouchBidirectional(key, now, fwdPackets, fwdBytes, revPackets, revBytes)
	}
}

// TrackedKeys snapshots this exporter's tracked flow keys for the
// daemon live-counter poll; nil when close-only.
func (c *exporterCore) TrackedKeys() []FlowKey {
	if c.tracker == nil {
		return nil
	}
	return c.tracker.Keys()
}

// Tracked reports whether key is currently tracked or was selected at
// open by a close-only exporter.
func (c *exporterCore) Tracked(key FlowKey) bool {
	if c.tracker != nil && c.tracker.Has(key) {
		return true
	}
	c.sampledMu.Lock()
	_, ok := c.sampledFlows[key]
	c.sampledMu.Unlock()
	return ok
}
