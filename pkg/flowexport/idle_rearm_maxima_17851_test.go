package flowexport

import (
	"testing"
	"time"
)

// #17851: PR #17543's idle-rearm branches assigned the incoming
// counters directly (nf.record.Packets = fwdPackets, ...) instead of
// keeping the per-field maxima the live-flow branch keeps (#16750).
// A re-arming snapshot that races backwards in one direction therefore
// lowered the stored cumulative below what the inactive final already
// exported; the next due export then saved that smaller value as its
// baseline, so a later snapshot at the original level re-counted the
// same traffic a second time. Collector totals could exceed the
// maximum lifetime total ever observed.

// Bidirectional acceptance probe (issue counterexample, in bytes and
// packets): inactive final covers (100 pkts/1000 bytes fwd, 0 rev); a
// backward/mirrored rearm snapshot (50/500 fwd, 900/90000 rev) must
// report 0 forward / genuine reverse on the next export and keep the
// forward cumulative at 100/1000, so a subsequent (100, 900) snapshot
// exports 0 forward — never a second 50.
func TestIdleRearmBidirectionalKeepsMaxima17851(t *testing.T) {
	tr := NewFlowTracker(60*time.Second, 15*time.Second)
	if tr == nil {
		t.Fatal("tracker must be enabled")
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	tr.TrackFlowOpenSimple(key, start)

	// Live phase: 100 fwd packets, no reverse. Idles out at +15s
	// idle -> inactive final exports the full span and stores a marker.
	tr.TouchBidirectional(key, start.Add(10*time.Second), 100, 1000, 0, 0)
	due := tr.CollectDueExports(start.Add(26 * time.Second))
	if len(due) != 1 || due[0].Packets != 100 || due[0].Bytes != 1000 || due[0].RevPackets != 0 || due[0].RevBytes != 0 {
		t.Fatalf("inactive final = %+v, want 1 record 100/1000/0/0", due)
	}
	if tr.Len() != 0 || tr.IdleLen() != 1 {
		t.Fatalf("after expiry len=%d idle=%d, want 0/1 (marker retained)", tr.Len(), tr.IdleLen())
	}

	// Rearm: forward races backwards (50/500), reverse genuinely
	// advances (900/90000). Sum-based gate passes (950 > 100).
	tr.TouchBidirectional(key, start.Add(30*time.Second), 50, 500, 900, 90000)
	if tr.Len() != 1 {
		t.Fatalf("rearm: len=%d, want 1 (flow re-admitted)", tr.Len())
	}
	f := tr.flows[key]
	if f == nil {
		t.Fatal("rearm: flow not tracked")
	}
	if f.record.Packets != 100 || f.record.Bytes != 1000 {
		t.Fatalf("rearmed forward cumulative = %d/%d, want per-field maxima 100/1000 (not regressed 50/500)", f.record.Packets, f.record.Bytes)
	}
	if f.record.RevPackets != 900 || f.record.RevBytes != 90000 {
		t.Fatalf("rearmed reverse cumulative = %d/%d, want 900/90000", f.record.RevPackets, f.record.RevBytes)
	}
	// Export baselines must stay at the inactive final's coverage.
	if f.lastPackets != 100 || f.lastBytes != 1000 || f.lastRevPackets != 0 || f.lastRevBytes != 0 {
		t.Fatalf("rearmed baselines = %d/%d/%d/%d, want 100/1000/0/0", f.lastPackets, f.lastBytes, f.lastRevPackets, f.lastRevBytes)
	}

	// Next due (active) export: only the genuine reverse progress,
	// zero forward — and it must not lower the saved forward baseline.
	due = tr.CollectDueExports(start.Add(91 * time.Second))
	if len(due) != 1 {
		t.Fatalf("post-rearm export: want 1 record, got %v", due)
	}
	if due[0].Packets != 0 || due[0].Bytes != 0 {
		t.Fatalf("post-rearm forward delta = %d/%d, want 0/0", due[0].Packets, due[0].Bytes)
	}
	if due[0].RevPackets != 900 || due[0].RevBytes != 90000 {
		t.Fatalf("post-rearm reverse delta = %d/%d, want 900/90000", due[0].RevPackets, due[0].RevBytes)
	}

	// Snapshot back at the original forward level: nothing new forward
	// may be exported. Pre-fix this emitted another 50/500 because the
	// interim above had lowered the forward baseline to 50/500, so the
	// collector total (150/1500) exceeded the lifetime max (100/1000).
	tr.TouchBidirectional(key, start.Add(100*time.Second), 100, 1000, 900, 90000)
	// The inactive expiry emits a zero-delta final (or, if the interim
	// above already covered it, nothing); what must never appear is a
	// positive delta past the lifetime maxima.
	due = tr.CollectDueExports(start.Add(116 * time.Second))
	if len(due) > 1 || (len(due) == 1 && (due[0].Packets != 0 || due[0].Bytes != 0 || due[0].RevPackets != 0 || due[0].RevBytes != 0)) {
		t.Fatalf("second post-rearm export = %+v, want no positive delta (no double count past lifetime max 100/1000/900/90000)", due)
	}
}

// Unidirectional rearm (Touch): same invariant on the two forward
// fields. Inactive final covers 100/1000; a rearm snapshot whose bytes
// advance but packets race backwards (50/2000) must keep packets at
// 100 while taking bytes to 2000, and the following export must report
// only the genuine byte progress.
func TestIdleRearmTouchKeepsMaxima17851(t *testing.T) {
	tr := NewFlowTracker(60*time.Second, 15*time.Second)
	if tr == nil {
		t.Fatal("tracker must be enabled")
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	tr.TrackFlowOpenSimple(key, start)

	tr.Touch(key, start.Add(10*time.Second), 100, 1000)
	due := tr.CollectDueExports(start.Add(26 * time.Second))
	if len(due) != 1 || due[0].Packets != 100 || due[0].Bytes != 1000 {
		t.Fatalf("inactive final = %+v, want 1 record 100/1000", due)
	}

	tr.Touch(key, start.Add(30*time.Second), 50, 2000)
	if tr.Len() != 1 {
		t.Fatalf("rearm: len=%d, want 1 (flow re-admitted)", tr.Len())
	}
	f := tr.flows[key]
	if f.record.Packets != 100 || f.record.Bytes != 2000 {
		t.Fatalf("rearmed cumulative = %d/%d, want per-field maxima 100/2000 (not regressed 50/2000)", f.record.Packets, f.record.Bytes)
	}
	if f.lastPackets != 100 || f.lastBytes != 1000 {
		t.Fatalf("rearmed baselines = %d/%d, want 100/1000", f.lastPackets, f.lastBytes)
	}

	due = tr.CollectDueExports(start.Add(91 * time.Second))
	if len(due) != 1 || due[0].Packets != 0 || due[0].Bytes != 1000 {
		t.Fatalf("post-rearm export = %+v, want 1 record 0/1000 (only genuine byte progress)", due)
	}

	// Back at the packet level already exported: no re-count. The
	// inactive expiry at +161s emits the (zero-delta) final or nothing;
	// either way no positive forward delta may appear.
	tr.Touch(key, start.Add(100*time.Second), 100, 2000)
	due = tr.CollectDueExports(start.Add(161 * time.Second))
	if len(due) > 1 || (len(due) == 1 && (due[0].Packets != 0 || due[0].Bytes != 0)) {
		t.Fatalf("second post-rearm export = %+v, want no positive delta (no double count)", due)
	}
}
