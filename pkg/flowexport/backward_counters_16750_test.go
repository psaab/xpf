package flowexport

import (
	"testing"
	"time"
)

// #16750 R3-A46-04: cumulative snapshots can race backwards (helper
// restart, mirror-row alternation between workers). Touch must keep
// the per-field maximum and deltaRecord must saturate at its
// last-export baseline, mirroring the close remainder's satSub
// contract in exporter_core.go. One wrapped ~2^64 delta poisons
// collector top-talker / billing aggregates.

// Acceptance probe: after a first interim at 100 forward packets, a
// backward forward snapshot (50) paired with genuine reverse progress
// (900) must report 0 forward and 900 reverse on the second interim —
// never a wrap, never more than the lifetime total.
func TestBackwardTouchSecondInterim16750(t *testing.T) {
	tr := NewFlowTracker(60*time.Second, 10*time.Minute)
	if tr == nil {
		t.Fatal("tracker must be enabled")
	}
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	tr.TrackFlowOpenSimple(key, start)

	tr.TouchBidirectional(key, start.Add(30*time.Second), 100, 10000, 0, 0)
	due := tr.CollectDueExports(start.Add(61 * time.Second))
	if len(due) != 1 || due[0].Packets != 100 || due[0].Bytes != 10000 || due[0].RevPackets != 0 {
		t.Fatalf("first interim = %+v, want 1 record 100/10000/0", due)
	}

	// Forward races backwards, reverse genuinely advances.
	tr.TouchBidirectional(key, start.Add(90*time.Second), 50, 5000, 900, 90000)
	due = tr.CollectDueExports(start.Add(122 * time.Second))
	if len(due) != 1 {
		t.Fatalf("second interim: want 1 record, got %v", due)
	}
	if due[0].Packets != 0 || due[0].Bytes != 0 {
		t.Fatalf("second interim forward = %d/%d, want 0/0 (no wrap past lifetime 100/10000)", due[0].Packets, due[0].Bytes)
	}
	if due[0].RevPackets != 900 || due[0].RevBytes != 90000 {
		t.Fatalf("second interim reverse = %d/%d, want 900/90000", due[0].RevPackets, due[0].RevBytes)
	}
}

// Per-field monotonicity: one field racing backwards must not drag
// down a sibling field that advanced in the same snapshot (Touch and
// TouchBidirectional).
func TestTouchMonotonicPerField16750(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}

	tr := NewFlowTracker(60*time.Second, 10*time.Minute)
	tr.TrackFlowOpenSimple(key, start)
	tr.Touch(key, start.Add(30*time.Second), 100, 10000)
	// Packets race backwards, bytes advance.
	tr.Touch(key, start.Add(40*time.Second), 10, 20000)
	due := tr.CollectDueExports(start.Add(61 * time.Second))
	if len(due) != 1 || due[0].Packets != 100 || due[0].Bytes != 20000 {
		t.Fatalf("Touch interim = %+v, want 100/20000 (per-field max)", due)
	}

	tr2 := NewFlowTracker(60*time.Second, 10*time.Minute)
	tr2.TrackFlowOpenSimple(key, start)
	tr2.TouchBidirectional(key, start.Add(30*time.Second), 100, 10000, 40, 4000)
	// RevPackets races backwards, the other three advance.
	tr2.TouchBidirectional(key, start.Add(40*time.Second), 110, 11000, 5, 4500)
	due = tr2.CollectDueExports(start.Add(61 * time.Second))
	if len(due) != 1 || due[0].Packets != 110 || due[0].Bytes != 11000 || due[0].RevPackets != 40 || due[0].RevBytes != 4500 {
		t.Fatalf("TouchBidirectional interim = %+v, want 110/11000/40/4500 (per-field max)", due)
	}
}

// deltaRecord saturation, exercised directly: even if a stored record
// somehow sits below its last-export baseline (the state Touch
// monotonicity now prevents via the public API), the delta is zero,
// never a ~2^64 wrap. Positive control: above-baseline fields still
// subtract normally.
func TestDeltaRecordSaturates16750(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	f := &trackedFlow{
		record: FlowRecord{Packets: 10, Bytes: 2000, RevPackets: 5, RevBytes: 50},
		// Bytes (2000) sits above its baseline (1000): control field.
		lastPackets: 100, lastBytes: 1000, lastRevPackets: 50, lastRevBytes: 500,
		start: start, lastExport: start,
	}
	r := f.deltaRecord(start.Add(60 * time.Second))
	if r.Packets != 0 || r.RevPackets != 0 || r.RevBytes != 0 {
		t.Fatalf("deltaRecord below baseline = %+v, want saturating 0s", r)
	}
	if r.Bytes != 1000 {
		t.Fatalf("deltaRecord control bytes = %d, want 2000-1000=1000", r.Bytes)
	}
}

// Activity is per-field progress: a snapshot whose forward+reverse
// SUM is flat but one field genuinely advanced counts as activity,
// while a fully backward snapshot does not revive an idle flow.
func TestBackwardTouchActivity16750(t *testing.T) {
	tr := NewFlowTracker(60*time.Second, 15*time.Second)
	start := time.Unix(1_700_000_000, 0)
	key := FlowKey{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80, Protocol: 6}
	tr.TrackFlowOpenSimple(key, start)
	tr.TouchBidirectional(key, start.Add(10*time.Second), 100, 10000, 100, 10000)
	// Sum flat (200 pkts / 20000 bytes both times); forward advances,
	// reverse races backwards.
	tr.TouchBidirectional(key, start.Add(20*time.Second), 150, 10000, 50, 10000)
	if due := tr.CollectDueExports(start.Add(34 * time.Second)); len(due) != 0 || tr.Len() != 1 {
		t.Fatalf("per-field progress must count as activity: due=%v len=%d, want none/1", due, tr.Len())
	}
	// Backward-only snapshot must not count as activity: inactive
	// expiry (lastActivity=+20s, +15s) fires at +36s.
	tr.TouchBidirectional(key, start.Add(30*time.Second), 10, 10, 10, 10)
	due := tr.CollectDueExports(start.Add(36 * time.Second))
	if len(due) != 1 || tr.Len() != 0 {
		t.Fatalf("backward snapshot must not revive idle flow: due=%v len=%d, want 1 final/0", due, tr.Len())
	}
	// Final carries the monotonic maxima since open, not the
	// backward snapshot's lower values.
	if due[0].Packets != 150 || due[0].RevPackets != 100 {
		t.Fatalf("final = %+v, want monotonic 150 fwd / 100 rev", due[0])
	}
}
