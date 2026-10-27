package flowexport

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #17834: a flowexport config rebuild replaces exporter groups and
// carries open state via AbsorbSampledInto/TransferFlowStateTo
// (#16742). That transfer cloned only live tracker entries, so a flow
// inside its idle window (marker set, no live entry) was silently
// dropped: the replacement never polled the key (resumed traffic went
// invisible again — the #16747 defect), and the real close hit the
// #16742 close-time fallback, which either consumed a second sampling
// slot and re-exported the FULL lifetime the inactive final had already
// emitted (double-count) or, deciding out, dropped the remainder.

// Drive one flow through open, progress, and inactive expiry: the final
// record is emitted and exactly one sampled-idle marker remains.
func expireIdleFlow17834(t *testing.T, e trackerFamily17834, start time.Time, key FlowKey, fwdPkts, fwdBytes, revPkts, revBytes uint64) {
	t.Helper()
	e.TrackFlowOpen(key, start)
	e.TouchFlowBidirectional(key, start.Add(5*time.Second), fwdPkts, fwdBytes, revPkts, revBytes)
	if due := e.CollectDueExports(start.Add(21 * time.Second)); len(due) != 1 {
		t.Fatalf("inactive final = %+v, want 1 record", due)
	}
}

// trackerFamily17834 is the promoted surface both exporter families
// share for this cell (identical signatures, so one helper drives both).
type trackerFamily17834 interface {
	TrackFlowOpen(key FlowKey, start time.Time)
	TouchFlowBidirectional(key FlowKey, now time.Time, fwdPackets, fwdBytes, revPackets, revBytes uint64)
	CollectDueExports(now time.Time) []FlowRecord
	TrackedKeys() []FlowKey
	Tracked(key FlowKey) bool
	CloseFlow(key FlowKey) (bool, uint64, uint64, uint64, uint64)
	CloseFlowOrSample(key FlowKey, decide func() bool) (bool, uint64, uint64, uint64, uint64)
	ExportSessionCloseRemainder(rec logging.EventRecord, evt SessionCloseData, basePkts, baseBytes, baseRevPkts, baseRevBytes uint64)
}

// The full rebuild-then-resume path on the replacement exporter: the
// transferred marker keeps the key polled, resumed traffic re-arms a
// live entry, and the close exports only the post-expiry remainder with
// no second sampling decision.
func TestIdleMarkerTransfersToReplacement17834(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	sd := SessionCloseData{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 12345, DstPort: 80, Protocol: 6}

	oldE, err := NewIPFIXExporter(cfg)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	expireIdleFlow17834(t, oldE, start, key, 100, 10000, 40, 4000)
	if got := oldE.tracker.IdleLen(); got != 1 {
		t.Fatalf("pre-absorb marker count = %d, want 1", got)
	}
	if v4, _ := oldE.batch.drain(); len(v4) != 1 {
		t.Fatalf("inactive final batch = %d records, want 1", len(v4))
	}

	newE, err := NewIPFIXExporter(cfg)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	oldE.AbsorbSampledInto(newE)
	if got := newE.tracker.IdleLen(); got != 1 {
		t.Fatalf("replacement must hold the transferred idle marker, markers=%d", got)
	}
	// The daemon feed polls the replacement's TrackedKeys: the marker
	// key must still be there or resumed traffic is never observed.
	if keys := newE.TrackedKeys(); len(keys) != 1 || keys[0] != key {
		t.Fatalf("replacement TrackedKeys = %v, want [%v]", keys, key)
	}
	// The source keeps its copy; the caller retires it and its flush
	// never re-emits tracker state, so exactly one side exports.
	if got := oldE.tracker.IdleLen(); got != 1 {
		t.Fatalf("source marker count after absorb = %d, want 1 (kept)", got)
	}

	// Resumed traffic re-arms a live entry on the replacement with the
	// marker's baselines, so nothing already emitted recounts.
	newE.TouchFlowBidirectional(key, start.Add(30*time.Second), 107, 10700, 43, 4300)
	if got := newE.tracker.Len(); got != 1 {
		t.Fatalf("resumed flow must re-arm on the replacement, live=%d", got)
	}

	calls := 0
	sampled, bp, bb, brp, brb := newE.CloseFlowOrSample(key, func() bool { calls++; return true })
	if !sampled || calls != 0 {
		t.Fatalf("close = sampled=%v fallback calls=%d, want true/0 (transferred marker is the open state)", sampled, calls)
	}
	if bp != 100 || bb != 10000 || brp != 40 || brb != 4000 {
		t.Fatalf("close baselines = %d/%d/%d/%d, want final-record 100/10000/40/4000", bp, bb, brp, brb)
	}
	newE.ExportSessionCloseRemainder(logging.EventRecord{
		Type: "SESSION_CLOSE", ProtocolNum: 6, Time: start.Add(40 * time.Second),
		SessionPkts: 107, SessionBytes: 10700, RevSessionPkts: 43, RevSessionBytes: 4300,
	}, sd, bp, bb, brp, brb)
	v4, _ := newE.batch.drain()
	if len(v4) != 1 || v4[0].Packets != 7 || v4[0].Bytes != 700 || v4[0].RevPackets != 3 || v4[0].RevBytes != 300 {
		t.Fatalf("close remainder = %+v, want exactly the post-expiry 7/700 fwd + 3/300 rev", v4)
	}
	if newE.Tracked(key) {
		t.Fatal("flow must be fully forgotten after close")
	}
}

// The exact double-count shape from the issue: rebuild lands inside the
// idle window and no resumed poll is observed before the close. The
// replacement must consume the marker (sampled, final-record baselines,
// no fallback slot) and export only the post-expiry remainder — not the
// full lifetime the inactive final already emitted.
func TestIdleMarkerRebuildCloseWithoutPoll17834(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}

	oldE, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	expireIdleFlow17834(t, oldE, start, key, 50, 5000, 0, 0)
	if v4, _ := oldE.batch.drain(); len(v4) != 1 || v4[0].Packets != 50 {
		t.Fatalf("inactive final = %v, want 1 record of 50 packets", v4)
	}

	newE, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	oldE.AbsorbSampledInto(newE)
	if !newE.Tracked(key) {
		t.Fatal("replacement must hold the transferred idle marker")
	}

	calls := 0
	sampled, bp, bb, _, _ := newE.CloseFlowOrSample(key, func() bool { calls++; return true })
	if !sampled || calls != 0 {
		t.Fatalf("close = sampled=%v fallback calls=%d, want true/0 (no second sampling slot)", sampled, calls)
	}
	if bp != 50 || bb != 5000 {
		t.Fatalf("close baselines = %d/%d, want final-record 50/5000", bp, bb)
	}
	// Lifetime 59 = 50 already emitted by the inactive final + 9 quiet
	// post-expiry packets. Only the 9 may be exported at close.
	newE.ExportSessionCloseRemainder(logging.EventRecord{
		Type: "SESSION_CLOSE", ProtocolNum: 6, Time: start.Add(40 * time.Second),
		SessionPkts: 59, SessionBytes: 5900,
	}, SessionCloseData{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 12345, DstPort: 80, Protocol: 6}, bp, bb, 0, 0)
	v4, _ := newE.batch.drain()
	if len(v4) != 1 || v4[0].Packets != 9 || v4[0].Bytes != 900 {
		t.Fatalf("close remainder = %+v, want exactly the post-expiry 9/900 (no lifetime double-count)", v4)
	}
	if newE.Tracked(key) {
		t.Fatal("marker must be consumed by the close")
	}
}

// Controls for the transfer precedence, mirroring Adopt's
// "state already present in dst wins" rule: a live entry or an existing
// marker in the replacement is never overwritten by an absorbed marker.
func TestIdleMarkerTransferDestinationWins17834(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}

	// Source holds only the idle marker (100/10000/40/4000 emitted).
	oldE, _ := NewIPFIXExporter(cfg)
	expireIdleFlow17834(t, oldE, start, key, 100, 10000, 40, 4000)
	oldE.batch.drain()

	// Destination already tracks the flow live: its entry wins and no
	// marker may be installed alongside it.
	newE, _ := NewIPFIXExporter(cfg)
	newE.TrackFlowOpen(key, start)
	newE.TouchFlowBidirectional(key, start.Add(10*time.Second), 10, 1000, 0, 0)
	oldE.AbsorbSampledInto(newE)
	if got := newE.tracker.Len(); got != 1 {
		t.Fatalf("destination live entries = %d, want 1", got)
	}
	if got := newE.tracker.IdleLen(); got != 0 {
		t.Fatalf("marker must not shadow the destination's live entry, markers=%d", got)
	}
	if _, bp, _, _, _ := newE.CloseFlow(key); bp != 0 {
		t.Fatalf("destination live entry must win (close baselines %d, want its own 0)", bp)
	}

	// Destination already holds its own marker with different
	// baselines: the absorbed marker must not replace it.
	oldE2, _ := NewIPFIXExporter(cfg)
	expireIdleFlow17834(t, oldE2, start, key, 100, 10000, 40, 4000)
	oldE2.batch.drain()
	newE2, _ := NewIPFIXExporter(cfg)
	expireIdleFlow17834(t, newE2, start, key, 20, 2000, 0, 0)
	newE2.batch.drain()
	oldE2.AbsorbSampledInto(newE2)
	if got := newE2.tracker.IdleLen(); got != 1 {
		t.Fatalf("destination markers = %d, want 1", got)
	}
	if _, bp, bb, _, _ := newE2.CloseFlow(key); bp != 20 || bb != 2000 {
		t.Fatalf("destination marker must win (close baselines %d/%d, want its own 20/2000)", bp, bb)
	}
}
