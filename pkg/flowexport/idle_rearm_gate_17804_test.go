package flowexport

import (
	"math"
	"testing"
	"time"
)

// #17804: TouchBidirectional's idle-rearm gate compared forward+reverse
// SUMs against the marker baselines. A backwards-racing mirror field (the
// #16750 snapshot reality the #17851 carry already clamps) can hold both
// sums exactly flat while another field genuinely progresses, and summed
// uint64s wrap near 2^64 flipping the comparison either way — so the gate
// read "no progress", the marker never re-armed, and the resumed traffic
// stayed outside the live tracker (no interim exports, activity
// invisible): the #16747 defect shape again. The live-flow path in the
// same function uses per-field monotonic checks for exactly this reason;
// the gate must match it.

// Net-flat arm (issue counterexample): inactive final covers
// 100/1000 fwd + 50/500 rev; a resumed snapshot reports 110/1100 fwd
// (genuine progress) and 40/400 rev (raced backwards). Both sums are
// exactly flat (150 pkts / 1500 bytes), so the pre-fix sum gate refused
// the re-arm. Per-field, forward advanced: the marker must re-arm with
// the progressed forward taken, the regressed reverse clamped at its
// maximum, and the following export must carry only the genuine
// forward delta — never a reverse recount.
func TestIdleRearmGatePerFieldNetFlat17804(t *testing.T) {
	tr := NewFlowTracker(60*time.Second, 15*time.Second)
	if tr == nil {
		t.Fatal("tracker must be enabled")
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	tr.TrackFlowOpenSimple(key, start)

	tr.TouchBidirectional(key, start.Add(10*time.Second), 100, 1000, 50, 500)
	due := tr.CollectDueExports(start.Add(26 * time.Second))
	if len(due) != 1 || due[0].Packets != 100 || due[0].Bytes != 1000 || due[0].RevPackets != 50 || due[0].RevBytes != 500 {
		t.Fatalf("inactive final = %+v, want 1 record 100/1000/50/500", due)
	}
	if tr.Len() != 0 || tr.IdleLen() != 1 {
		t.Fatalf("after expiry len=%d idle=%d, want 0/1 (marker retained)", tr.Len(), tr.IdleLen())
	}

	// Sum-flat resume: fwd +10/+100, rev -10/-100.
	tr.TouchBidirectional(key, start.Add(30*time.Second), 110, 1100, 40, 400)
	if tr.Len() != 1 {
		t.Fatalf("net-flat rearm: len=%d, want 1 (fwd field genuinely progressed; sums must not mask it)", tr.Len())
	}
	if tr.IdleLen() != 0 {
		t.Fatalf("net-flat rearm: idle=%d, want 0 (marker consumed)", tr.IdleLen())
	}
	f := tr.flows[key]
	if f == nil {
		t.Fatal("net-flat rearm: flow not tracked")
	}
	// Per-field carry (#17851): progress taken forward, reverse clamped.
	if f.record.Packets != 110 || f.record.Bytes != 1100 {
		t.Fatalf("rearmed forward cumulative = %d/%d, want progressed 110/1100", f.record.Packets, f.record.Bytes)
	}
	if f.record.RevPackets != 50 || f.record.RevBytes != 500 {
		t.Fatalf("rearmed reverse cumulative = %d/%d, want clamped maxima 50/500 (not regressed 40/400)", f.record.RevPackets, f.record.RevBytes)
	}
	if f.lastPackets != 100 || f.lastBytes != 1000 || f.lastRevPackets != 50 || f.lastRevBytes != 500 {
		t.Fatalf("rearmed baselines = %d/%d/%d/%d, want final-record 100/1000/50/500", f.lastPackets, f.lastBytes, f.lastRevPackets, f.lastRevBytes)
	}

	// Next due export: exactly the genuine forward progress, zero
	// reverse. Pre-fix this record never existed — the flow was never
	// re-admitted, so the post-expiry forward traffic had no interim
	// export and the tracker saw no activity.
	due = tr.CollectDueExports(start.Add(91 * time.Second))
	if len(due) != 1 || due[0].Packets != 10 || due[0].Bytes != 100 || due[0].RevPackets != 0 || due[0].RevBytes != 0 {
		t.Fatalf("post-rearm export = %+v, want 1 record 10/100/0/0 (genuine fwd progress only)", due)
	}

	// Exactly-once accounting: a close at the lifetime maxima finds the
	// advanced baselines and exports a zero remainder.
	bp, bb, brp, brb, tracked := tr.CloseWithBaseline(key)
	if !tracked || bp != 110 || bb != 1100 || brp != 50 || brb != 500 {
		t.Fatalf("CloseWithBaseline = %v %d/%d/%d/%d, want true 110/1100/50/500", tracked, bp, bb, brp, brb)
	}
}

// Wrap arm: near-2^64 forward counters plus genuine reverse progress.
// fwd+rev sums wrap modulo 2^64 to tiny values, so the pre-fix summed
// comparison read "no progress" and refused the re-arm. Per-field
// comparison has no addition and cannot wrap.
func TestIdleRearmGatePerFieldWrap17804(t *testing.T) {
	tr := NewFlowTracker(60*time.Second, 15*time.Second)
	if tr == nil {
		t.Fatal("tracker must be enabled")
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	tr.TrackFlowOpenSimple(key, start)

	tr.TouchBidirectional(key, start.Add(10*time.Second), math.MaxUint64, math.MaxUint64, 0, 0)
	if due := tr.CollectDueExports(start.Add(26 * time.Second)); len(due) != 1 {
		t.Fatalf("inactive final = %+v, want 1", due)
	}

	// Forward pinned at the maximum (flat), reverse genuinely advanced:
	// the packet sum MaxUint64+10 wraps to 9, the byte sum to 999.
	tr.TouchBidirectional(key, start.Add(30*time.Second), math.MaxUint64, math.MaxUint64, 10, 1000)
	if tr.Len() != 1 {
		t.Fatalf("wrap rearm: len=%d, want 1 (reverse genuinely progressed; wrapped sums must not mask it)", tr.Len())
	}
	f := tr.flows[key]
	if f == nil {
		t.Fatal("wrap rearm: flow not tracked")
	}
	if f.record.Packets != math.MaxUint64 || f.record.Bytes != math.MaxUint64 {
		t.Fatalf("rearmed forward cumulative = %d/%d, want MaxUint64/MaxUint64", f.record.Packets, f.record.Bytes)
	}
	if f.record.RevPackets != 10 || f.record.RevBytes != 1000 {
		t.Fatalf("rearmed reverse cumulative = %d/%d, want 10/1000", f.record.RevPackets, f.record.RevBytes)
	}

	due := tr.CollectDueExports(start.Add(91 * time.Second))
	if len(due) != 1 || due[0].Packets != 0 || due[0].Bytes != 0 || due[0].RevPackets != 10 || due[0].RevBytes != 1000 {
		t.Fatalf("post-rearm export = %+v, want 1 record 0/0/10/1000 (reverse progress, no wrap)", due)
	}
	bp, bb, brp, brb, tracked := tr.CloseWithBaseline(key)
	if !tracked || brp != 10 || brb != 1000 {
		t.Fatalf("CloseWithBaseline = %v %d/%d/%d/%d, want reverse baselines 10/1000", tracked, bp, bb, brp, brb)
	}
}

// Control arms: the per-field gate must not over-trigger. With no field
// advancing — flat, uniformly regressed, or forward-flat with a regressed
// reverse — the marker must stay put (poll-loop revival of a dead flow
// stays suppressed). A single genuinely advancing counter (reverse bytes
// only) must re-arm.
func TestIdleRearmGateControlsNoProgress17804(t *testing.T) {
	tr := NewFlowTracker(60*time.Second, 15*time.Second)
	if tr == nil {
		t.Fatal("tracker must be enabled")
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	tr.TrackFlowOpenSimple(key, start)

	tr.TouchBidirectional(key, start.Add(10*time.Second), 100, 1000, 50, 500)
	if due := tr.CollectDueExports(start.Add(26 * time.Second)); len(due) != 1 {
		t.Fatalf("inactive final = %+v, want 1", due)
	}

	for name, snap := range map[string][4]uint64{
		"flat":              {100, 1000, 50, 500},
		"uniformly-regress": {90, 900, 40, 400},
		"fwd-flat-rev-reg":  {100, 1000, 40, 400},
	} {
		tr.TouchBidirectional(key, start.Add(30*time.Second), snap[0], snap[1], snap[2], snap[3])
		if tr.Len() != 0 || tr.IdleLen() != 1 {
			t.Fatalf("%s: len=%d idle=%d, want 0/1 (no advancing field must not re-arm)", name, tr.Len(), tr.IdleLen())
		}
	}

	// Single-field progress (reverse bytes only) re-arms.
	tr.TouchBidirectional(key, start.Add(35*time.Second), 100, 1000, 50, 600)
	if tr.Len() != 1 {
		t.Fatalf("single-field progress: len=%d, want 1 (any one counter advancing re-arms)", tr.Len())
	}
	f := tr.flows[key]
	if f == nil || f.record.RevBytes != 600 || f.record.Packets != 100 || f.record.RevPackets != 50 {
		t.Fatalf("single-field rearm state = %+v, want fwd 100 packets, reverse bytes 600, others unchanged", f)
	}
}
