package flowexport

import (
	"testing"
	"time"
)

// #16303 F5: live cumulative snapshots (fed by the daemon poll, here
// driven directly as Touch calls with advancing counters) must (a)
// produce an active-timeout interim with the cumulative delta, (b) keep
// the flow alive past the inactive window while counters advance, and
// (c) not double-count at close: close after interim+final exports only
// the remaining delta, and the interim deltas sum to the session total.

func TestLiveFeedActiveInactiveNoDoubleCount16303(t *testing.T) {
	cfg := &ExportConfig{FlowActiveTimeout: 60 * time.Second, FlowInactiveTimeout: 15 * time.Second}
	e, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	e.TrackFlowOpen(key, start)

	// Live traffic advancing through the active window (this is what
	// the daemon poll feeds from the session snapshot; before F5 these
	// touches only ever happened inside the close callback).
	e.TouchFlowBidirectional(key, start.Add(30*time.Second), 100, 10000, 40, 4000)
	e.TouchFlowBidirectional(key, start.Add(61*time.Second), 200, 20000, 90, 9000)

	due := e.CollectDueExports(start.Add(61 * time.Second))
	if len(due) != 1 {
		t.Fatalf("active: want 1 interim, got %d (%v)", len(due), due)
	}
	if due[0].Packets != 200 || due[0].Bytes != 20000 || due[0].RevPackets != 90 || due[0].RevBytes != 9000 {
		t.Fatalf("interim must carry cumulative deltas, got %+v", due[0])
	}

	// Traffic keeps advancing: touches at +100s and +115s keep the
	// 15s inactive timer from firing at the +122s collect (61s after
	// the first interim), which must emit the second window's delta.
	e.TouchFlowBidirectional(key, start.Add(100*time.Second), 260, 26000, 120, 12000)
	e.TouchFlowBidirectional(key, start.Add(115*time.Second), 270, 27000, 125, 12500)
	due = e.CollectDueExports(start.Add(122 * time.Second))
	if len(due) != 1 {
		t.Fatalf("second active window: want 1 interim, got %d (%v)", len(due), due)
	}
	if due[0].Packets != 70 || due[0].RevPackets != 35 {
		t.Fatalf("second interim must be the window delta only, got %+v", due[0])
	}
	if !e.Tracked(key) {
		t.Fatal("continuously-active flow must remain tracked (not idle-removed)")
	}

	// Counters stop advancing after +130s: inactive expiry fires once
	// with only the unexported remainder.
	e.TouchFlowBidirectional(key, start.Add(130*time.Second), 280, 28000, 130, 13000)
	due = e.CollectDueExports(start.Add(130*time.Second + 16*time.Second))
	if len(due) != 1 {
		t.Fatalf("inactive: want 1 final, got %d (%v)", len(due), due)
	}
	if due[0].Packets != 10 || due[0].RevPackets != 5 {
		t.Fatalf("final must carry only the unexported remainder, got %+v", due[0])
	}
	if e.Tracked(key) {
		t.Fatal("inactive-expired flow must be forgotten")
	}
	// Deltas sum to the session totals (200+70+10, 90+35+5): no
	// double count across interim + final records.
	if got, _, _, _, _ := e.CloseFlow(key); got {
		t.Fatal("close after inactive expiry must report not-tracked (no duplicate final)")
	}
}
