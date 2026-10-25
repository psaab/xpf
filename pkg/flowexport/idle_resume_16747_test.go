package flowexport

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #16747: a flow that idles past FlowInactiveTimeout is forgotten by the
// tracker, so the daemon live feed (which polls only TrackedKeys) never
// sees its resumed traffic and the real close reports not-sampled. The
// tracker must keep a bounded sampled-idle marker carrying the
// inactive-final baselines + template; a Touch showing progress or the
// close re-arms it so the post-expiry remainder exports exactly once.

func TestIdleResumeExportsRemainderAtClose16747(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	e, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	sd := SessionCloseData{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 12345, DstPort: 80, Protocol: 6}

	e.TrackFlowOpen(key, start)
	e.TouchFlowBidirectional(key, start.Add(5*time.Second), 100, 10000, 40, 4000)

	// Idle past the 15s inactive timeout: the final record carries the
	// 100/40 span and the flow leaves the live tracker.
	due := e.CollectDueExports(start.Add(21 * time.Second))
	if len(due) != 1 || due[0].Packets != 100 || due[0].RevPackets != 40 {
		t.Fatalf("inactive final = %+v, want 1 record fwd=100 rev=40", due)
	}
	if e.tracker.Len() != 0 {
		t.Fatalf("expired flow must leave live tracker, len=%d", e.tracker.Len())
	}
	// The idle marker keeps the key pollable and close-sampled.
	if !e.Tracked(key) {
		t.Fatal("idle-expired sampled flow must remain Tracked via marker")
	}
	keys := e.TrackedKeys()
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("TrackedKeys after expiry = %v, want [%v]", keys, key)
	}

	// The daemon feed polls the marker key and observes resumed traffic
	// (cumulative 100+N). Progress re-arms a live entry whose baseline
	// is the inactive-final span, so nothing already emitted recounts.
	const nPkts, nBytes, nRevPkts, nRevBytes = 7, 700, 3, 300
	e.TouchFlowBidirectional(key, start.Add(30*time.Second), 100+nPkts, 10000+nBytes, 40+nRevPkts, 4000+nRevBytes)
	if e.tracker.Len() != 1 {
		t.Fatalf("resumed flow must be re-tracked, len=%d", e.tracker.Len())
	}

	// Real close at the same cumulative counters: CloseFlow must report
	// sampled with the final-record baselines, and the remainder must be
	// exactly the post-expiry N packets, exported once.
	sampled, bp, bb, brp, brb := e.CloseFlow(key)
	if !sampled {
		t.Fatal("close after idle+resume must report sampled")
	}
	if bp != 100 || bb != 10000 || brp != 40 || brb != 4000 {
		t.Fatalf("CloseFlow baselines = %d/%d/%d/%d, want final-record 100/10000/40/4000", bp, bb, brp, brb)
	}
	e.ExportSessionCloseRemainder(logging.EventRecord{
		Type: "SESSION_CLOSE", ProtocolNum: 6, Time: start.Add(40 * time.Second),
		SessionPkts: 100 + nPkts, SessionBytes: 10000 + nBytes,
		RevSessionPkts: 40 + nRevPkts, RevSessionBytes: 4000 + nRevBytes,
	}, sd, bp, bb, brp, brb)
	v4, _ := e.batch.drain()
	// The batch holds the inactive final (100 fwd) plus the close
	// remainder. NetFlow v9 enrichment leaves reverse counters zero on
	// close records, so assert the forward remainder exactly here; the
	// reverse remainder is asserted on the IPFIX cell below.
	var sumPkts uint64
	for _, r := range v4 {
		sumPkts += r.Packets
	}
	if len(v4) != 2 || sumPkts != 100+nPkts {
		t.Fatalf("records=%d sum fwd=%d, want 2 records summing 107 (final + remainder)", len(v4), sumPkts)
	}
	var remainder *FlowRecord
	for i := range v4 {
		if v4[i].Packets == nPkts {
			remainder = &v4[i]
		}
	}
	if remainder == nil || remainder.Bytes != nBytes {
		t.Fatalf("close remainder record = %+v, want exactly N=%d packets / %d bytes", remainder, nPkts, nBytes)
	}
	// Exactly once: the marker/entry is consumed.
	if got, _, _, _, _ := e.CloseFlow(key); got {
		t.Fatal("second CloseFlow must report not-sampled (remainder exported once)")
	}
	if e.Tracked(key) {
		t.Fatal("flow must be fully forgotten after close")
	}
}

// The close itself re-arms when no resumed Touch was polled first: a
// close whose lifetime counters exceed the final-record baseline proves
// post-expiry traffic, so the close must still export the remainder.
func TestIdleCloseWithoutResumePollExportsRemainder16747(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	ie, err := NewIPFIXExporter(cfg)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	sd := SessionCloseData{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 12345, DstPort: 80, Protocol: 6}

	ie.TrackFlowOpen(key, start)
	ie.TouchFlowBidirectional(key, start.Add(5*time.Second), 50, 5000, 20, 2000)
	due := ie.CollectDueExports(start.Add(21 * time.Second))
	if len(due) != 1 {
		t.Fatalf("inactive final = %+v, want 1", due)
	}
	v4, _ := ie.batch.drain()
	if len(v4) != 1 || v4[0].Packets != 50 {
		t.Fatalf("drained final = %+v, want 50", v4)
	}
	// No feed poll after expiry; the close arrives with 59 lifetime
	// packets (9 post-expiry). It must export those 9, not drop.
	sampled, bp, bb, brp, brb := ie.CloseFlow(key)
	if !sampled || bp != 50 || bb != 5000 || brp != 20 || brb != 2000 {
		t.Fatalf("CloseFlow = sampled=%v %d/%d/%d/%d, want true 50/5000/20/2000", sampled, bp, bb, brp, brb)
	}
	ie.ExportSessionCloseRemainder(logging.EventRecord{
		Type: "SESSION_CLOSE", ProtocolNum: 6, Time: start.Add(40 * time.Second),
		SessionPkts: 59, SessionBytes: 5900, RevSessionPkts: 24, RevSessionBytes: 2400,
	}, sd, bp, bb, brp, brb)
	v4, _ = ie.batch.drain()
	if len(v4) != 1 || v4[0].Packets != 9 || v4[0].Bytes != 900 || v4[0].RevPackets != 4 || v4[0].RevBytes != 400 {
		t.Fatalf("close remainder = %+v, want exactly 9/900 fwd + 4/400 rev", v4)
	}
}

// Control: a close with NO post-expiry progress (lifetime == baseline)
// must not emit a phantom remainder, and a never-opened flow must stay
// not-sampled. This cell is unchanged by the fix — it guards against
// fail-open re-admission of unsampled flows.
func TestIdleCloseNoProgressNoRemainder16747(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	e, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}

	// Never opened: not tracked, not sampled.
	if e.Tracked(key) {
		t.Fatal("never-opened flow must not be tracked")
	}
	if got, _, _, _, _ := e.CloseFlow(key); got {
		t.Fatal("never-opened close must report not-sampled")
	}

	e.TrackFlowOpen(key, start)
	e.TouchFlowBidirectional(key, start.Add(5*time.Second), 50, 5000, 20, 2000)
	if due := e.CollectDueExports(start.Add(21 * time.Second)); len(due) != 1 {
		t.Fatalf("inactive final = %+v, want 1", due)
	}
	e.batch.drain()
	// A resumed Touch at the SAME cumulative counters is not progress:
	// it must not re-arm a live entry (poll-loop revival of a dead flow).
	e.TouchFlowBidirectional(key, start.Add(30*time.Second), 50, 5000, 20, 2000)
	if e.tracker.Len() != 0 {
		t.Fatalf("no-progress Touch must not re-arm, len=%d", e.tracker.Len())
	}
	if !e.Tracked(key) {
		t.Fatal("marker must survive a no-progress poll touch")
	}
	// Close at the baseline: sampled (so the daemon calls the remainder
	// export) but the remainder saturates to zero — no phantom volume.
	sampled, bp, bb, brp, brb := e.CloseFlow(key)
	if !sampled || bp != 50 || bb != 5000 || brp != 20 || brb != 2000 {
		t.Fatalf("CloseFlow = sampled=%v %d/%d/%d/%d, want true 50/5000/20/2000", sampled, bp, bb, brp, brb)
	}
	sd := SessionCloseData{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 12345, DstPort: 80, Protocol: 6}
	e.ExportSessionCloseRemainder(logging.EventRecord{
		Type: "SESSION_CLOSE", ProtocolNum: 6, Time: start.Add(40 * time.Second),
		SessionPkts: 50, SessionBytes: 5000, RevSessionPkts: 20, RevSessionBytes: 2000,
	}, sd, bp, bb, brp, brb)
	v4, _ := e.batch.drain()
	if len(v4) != 1 || v4[0].Packets != 0 || v4[0].Bytes != 0 {
		t.Fatalf("no-progress close record = %+v, want one zero remainder", v4)
	}
}

// The marker set is bounded: flooding distinct idle-expired flows cannot
// grow it past the cap (a leak here would reintroduce unbounded state).
func TestIdleMarkerBounded16747(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	e, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	start := time.Unix(1_700_000_000, 0)
	total := idleMarkerMax + 512
	for i := range total {
		key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: uint16(1000 + i), DstPort: 80, Protocol: 6}
		e.TrackFlowOpen(key, start)
		e.TouchFlowBidirectional(key, start.Add(time.Second), 1, 100, 0, 0)
		e.CollectDueExports(start.Add(20 * time.Second))
		if got := e.tracker.IdleLen(); got > idleMarkerMax {
			t.Fatalf("idle markers = %d after %d expiries, want <= %d (unbounded leak)", got, i+1, idleMarkerMax)
		}
	}
	if got := len(e.TrackedKeys()); got > idleMarkerMax {
		t.Fatalf("TrackedKeys = %d, want <= %d", got, idleMarkerMax)
	}
}
