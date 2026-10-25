package flowexport

import (
	"testing"
	"time"
)

// #16742: a close with no recorded open anywhere makes one close-time
// 1-in-N decision; a close with recorded state consumes no second slot.

func TestCloseWithoutOpenAtRateOneExports16742(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}

	// v9 close-only, rate 1 (export all): fallback decides in.
	e, err := NewExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	calls := 0
	sampled, bp, bb, rp, rb := e.CloseFlowOrSample(key, func() bool { calls++; return true })
	if !sampled || bp != 0 || bb != 0 || rp != 0 || rb != 0 {
		t.Fatalf("v9 fallback close = %v baselines %d/%d/%d/%d, want true zeros", sampled, bp, bb, rp, rb)
	}
	if calls != 1 {
		t.Fatalf("decide calls = %d, want 1", calls)
	}
	// Exporting the decided-in close queues exactly one record.
	e.ExportSessionCloseRemainder(closeEventFor16303(10, 1000, 4, 400), SessionCloseData{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 12345, DstPort: 80, Protocol: 6}, bp, bb, rp, rb)
	v4, _ := e.batch.drain()
	if len(v4) != 1 || v4[0].Packets != 10 {
		t.Fatalf("v9 fallback records = %+v, want 1 record pkts=10", v4)
	}

	// IPFIX twin.
	ie, err := NewIPFIXExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	calls = 0
	sampled, _, _, _, _ = ie.CloseFlowOrSample(key, func() bool { calls++; return true })
	if !sampled || calls != 1 {
		t.Fatalf("ipfix fallback = %v calls=%d, want true/1", sampled, calls)
	}

	// Fallback decides out: no export.
	e2, _ := NewExporter(&ExportConfig{})
	if s, _, _, _, _ := e2.CloseFlowOrSample(key, func() bool { return false }); s {
		t.Fatal("fallback decided-out close must not export")
	}
}

func TestCloseWithRecordedOpenConsumesNoSecondSlot16742(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	start := time.Unix(1_700_000_000, 0)

	// Tracked exporter: recorded open, fallback must not run.
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	e, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.TrackFlowOpen(key, start)
	e.TouchFlowBidirectional(key, start.Add(50*time.Second), 200, 20000, 90, 9000)
	if due := e.CollectDueExports(start.Add(61 * time.Second)); len(due) != 1 {
		t.Fatalf("interim = %+v, want 1", due)
	}
	calls := 0
	sampled, bp, bb, _, _ := e.CloseFlowOrSample(key, func() bool { calls++; return false })
	if !sampled || bp != 200 || bb != 20000 {
		t.Fatalf("tracked close = %v baselines %d/%d, want true 200/20000", sampled, bp, bb)
	}
	if calls != 0 {
		t.Fatalf("tracked close consumed fallback decision (%d calls), want 0", calls)
	}

	// Close-only exporter with sampled mark: same rule.
	plain, _ := NewExporter(&ExportConfig{})
	plain.MarkFlowSampledAtOpen(key)
	calls = 0
	if s, _, _, _, _ := plain.CloseFlowOrSample(key, func() bool { calls++; return false }); !s || calls != 0 {
		t.Fatalf("sampled-mark close = %v calls=%d, want true/0", s, calls)
	}
}

func TestTransferFlowStateToReplacement16742(t *testing.T) {
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	start := time.Unix(1_700_000_000, 0)
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}

	// Tracker -> tracker: baselines survive the swap.
	oldE, _ := NewExporter(cfg)
	oldE.TrackFlowOpen(key, start)
	oldE.TouchFlowBidirectional(key, start.Add(50*time.Second), 200, 20000, 90, 9000)
	if due := oldE.CollectDueExports(start.Add(61 * time.Second)); len(due) != 1 {
		t.Fatalf("interim = %+v, want 1", due)
	}
	newE, _ := NewExporter(cfg)
	oldE.AbsorbSampledInto(newE)
	if !newE.Tracked(key) {
		t.Fatal("replacement must hold transferred tracked flow")
	}
	sampled, bp, bb, _, _ := newE.CloseFlow(key)
	if !sampled || bp != 200 || bb != 20000 {
		t.Fatalf("transferred close = %v baselines %d/%d, want true 200/20000", sampled, bp, bb)
	}

	// Close-only sampled mark -> close-only replacement.
	oldP, _ := NewExporter(&ExportConfig{})
	oldP.MarkFlowSampledAtOpen(key)
	newP, _ := NewExporter(&ExportConfig{})
	oldP.AbsorbSampledInto(newP)
	if !newP.Tracked(key) {
		t.Fatal("replacement must hold transferred sampled mark")
	}
	if s, _, _, _, _ := newP.CloseFlow(key); !s {
		t.Fatal("transferred sampled close must export")
	}

	// HasFlowState is non-consuming.
	e, _ := NewExporter(&ExportConfig{})
	e.MarkFlowSampledAtOpen(key)
	if !e.HasFlowState(key) || !e.HasFlowState(key) {
		t.Fatal("HasFlowState must be repeatable/non-consuming")
	}
	if s, _, _, _, _ := e.CloseFlow(key); !s {
		t.Fatal("close after HasFlowState must still export")
	}
}
