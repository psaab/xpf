package flowexport

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #16303 fold 2: an active interim already emitted [0, baseline]; the
// real close must queue only the unexported remainder. Before the fix
// CloseFlow deleted the baselines and ExportSessionClose queued the
// full lifetime counters, double-counting the interim span.

func closeEventFor16303(pkts, bytes, revPkts, revBytes uint64) logging.EventRecord {
	return logging.EventRecord{
		Type: "SESSION_CLOSE", ProtocolNum: 6, Time: time.Unix(1_700_000_100, 0),
		SrcAddr: "10.0.0.1:12345", DstAddr: "10.0.0.2:80",
		SessionPkts: pkts, SessionBytes: bytes,
		RevSessionPkts: revPkts, RevSessionBytes: revBytes,
	}
}

func TestCloseExportsOnlyRemainderAfterInterim16303(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	sd := SessionCloseData{SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}, SrcPort: 12345, DstPort: 80, Protocol: 6}

	// v9 path.
	e, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.TrackFlowOpen(key, start)
	e.TouchFlowBidirectional(key, start.Add(50*time.Second), 200, 20000, 90, 9000)
	interim := e.CollectDueExports(start.Add(61 * time.Second))
	if len(interim) != 1 || interim[0].Packets != 200 {
		t.Fatalf("v9 interim = %+v, want 1 record fwd=200", interim)
	}
	sampled, bp, bb, brp, brb := e.CloseFlow(key)
	if !sampled || bp != 200 || bb != 20000 || brp != 90 || brb != 9000 {
		t.Fatalf("v9 CloseFlow = sampled=%v baselines %d/%d/%d/%d, want true 200/20000/90/9000", sampled, bp, bb, brp, brb)
	}
	e.ExportSessionCloseRemainder(closeEventFor16303(280, 28000, 130, 13000), sd, bp, bb, brp, brb)
	v4, _ := e.batch.drain()
	// Batch holds interim (200) + remainder (80): collector sum 280.
	var sumPkts, sumBytes uint64
	for _, r := range v4 {
		sumPkts += r.Packets
		sumBytes += r.Bytes
	}
	if len(v4) != 2 || sumPkts != 280 || sumBytes != 28000 {
		t.Fatalf("v9 records=%d sum=%d/%d, want 2 records summing 280/28000 (no overlap)", len(v4), sumPkts, sumBytes)
	}

	// IPFIX path, reverse counters included.
	ie, err := NewIPFIXExporter(cfg)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	ie.TrackFlowOpen(key, start)
	ie.TouchFlowBidirectional(key, start.Add(50*time.Second), 200, 20000, 90, 9000)
	if due := ie.CollectDueExports(start.Add(61 * time.Second)); len(due) != 1 {
		t.Fatalf("ipfix interim = %+v, want 1", due)
	}
	sampled, bp, bb, brp, brb = ie.CloseFlow(key)
	if !sampled {
		t.Fatal("ipfix close must be sampled")
	}
	ie.ExportSessionCloseRemainder(closeEventFor16303(280, 28000, 130, 13000), sd, bp, bb, brp, brb)
	v4, _ = ie.batch.drain()
	var sumRev uint64
	sumPkts = 0
	for _, r := range v4 {
		sumPkts += r.Packets
		sumRev += r.RevPackets
	}
	if sumPkts != 280 || sumRev != 130 {
		t.Fatalf("ipfix sums fwd=%d rev=%d, want 280/130 (no overlap)", sumPkts, sumRev)
	}

	// Close-only exporter (no tracker): zero baselines keep lifetime.
	plain, err := NewExporter(&ExportConfig{})
	if err != nil {
		t.Fatalf("NewExporter plain: %v", err)
	}
	plain.ExportSessionCloseRemainder(closeEventFor16303(50, 5000, 0, 0), sd, 0, 0, 0, 0)
	v4, _ = plain.batch.drain()
	if len(v4) != 1 || v4[0].Packets != 50 {
		t.Fatalf("close-only remainder = %+v, want full lifetime 50", v4)
	}
}
