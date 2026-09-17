package conntrack

import (
	"math"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// STEP-0 RED cell for psaab/xpf#9915 F-118 (GC half): a wrapped deadline must
// never expire a live session. Fails on base, kept as regression coverage.
func TestGCDeadlineNeverWrapsToExpired_9915(t *testing.T) {
	fwdKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 9, 1}, DstIP: [4]byte{10, 0, 9, 2},
		Protocol: 6, SrcPort: 1000, DstPort: 80,
	}
	fwdKey6 := dataplane.SessionKeyV6{
		SrcIP: [16]byte{15: 1}, DstIP: [16]byte{15: 2},
		Protocol: 6, SrcPort: 1000, DstPort: 80,
	}
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			fwdKey: {LastSeen: math.MaxUint64 - 10, Timeout: 100},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			fwdKey6: {LastSeen: math.MaxUint64 - 10, Timeout: 100},
		},
	}
	gc := NewGC(dp, 10*time.Second)
	gc.sweep()
	if len(dp.deleted) != 0 {
		t.Fatalf("v4 wrapped deadline expired a live session: deleted=%v (F-118)", dp.deleted)
	}
	if len(dp.deletedV6) != 0 {
		t.Fatalf("v6 wrapped deadline expired a live session: deleted=%v (F-118)", dp.deletedV6)
	}

	// Control: a genuinely expired session is still reaped at a fixed clock.
	const now uint64 = 5000
	oldKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 9, 3}, DstIP: [4]byte{10, 0, 9, 4},
		Protocol: 6, SrcPort: 2000, DstPort: 80,
	}
	dp2 := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			oldKey: {LastSeen: now - 1000, Timeout: 10},
		},
	}
	gc2 := NewGC(dp2, 10*time.Second)
	gc2.testNow = func() uint64 { return now }
	gc2.sweep()
	if len(dp2.deleted) != 1 {
		t.Fatalf("CONTROL: expired session reaped %d keys, want 1", len(dp2.deleted))
	}
}

// F-118 (stat half): with session limiting enabled (count checks active), one
// wrapped v4 row + one wrapped v6 row count exactly 2 saturations, not 4 —
// the expiry check counts each row once; the count-active check must not
// double-count. GREEN-only: statistic is new API.
func TestGCDeadlinesSaturatedCountedOnce_9915(t *testing.T) {
	fwdKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 9, 1}, DstIP: [4]byte{10, 0, 9, 2},
		Protocol: 6, SrcPort: 1000, DstPort: 80,
	}
	fwdKey6 := dataplane.SessionKeyV6{
		SrcIP: [16]byte{15: 1}, DstIP: [16]byte{15: 2},
		Protocol: 6, SrcPort: 1000, DstPort: 80,
	}
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			fwdKey: {LastSeen: math.MaxUint64 - 10, Timeout: 100},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			fwdKey6: {LastSeen: math.MaxUint64 - 10, Timeout: 100},
		},
	}
	gc := NewGC(dp, 10*time.Second)
	gc.SetSessionLimitEnabled(true)
	if gc.sessionCount == nil {
		t.Fatal("FIXTURE: session-count publisher not retained; count path would not run")
	}
	gc.sweep()
	if got := gc.Stats().DeadlinesSaturated; got != 2 {
		t.Fatalf("DeadlinesSaturated = %d, want exactly 2 (one per wrapped row, not 4)", got)
	}
	if len(dp.deleted) != 0 || len(dp.deletedV6) != 0 {
		t.Fatalf("wrapped sessions reaped: v4=%v v6=%v", dp.deleted, dp.deletedV6)
	}
}

// F-118 review (spark-MAJOR-6): the cluster install path lands exactly
// MaxUint64 (not MaxUint64-10) — the exact saturated value must survive a
// real GC sweep, counted once.
func TestGCDeadlineExactMaxUint64SurvivesSweep_9915(t *testing.T) {
	fwdKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 9, 11}, DstIP: [4]byte{10, 0, 9, 12},
		Protocol: 6, SrcPort: 3000, DstPort: 80,
	}
	fwdKey6 := dataplane.SessionKeyV6{
		SrcIP: [16]byte{15: 11}, DstIP: [16]byte{15: 12},
		Protocol: 6, SrcPort: 3000, DstPort: 80,
	}
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			fwdKey: {LastSeen: math.MaxUint64, Timeout: 100},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			fwdKey6: {LastSeen: math.MaxUint64, Timeout: 100},
		},
	}
	gc := NewGC(dp, 10*time.Second)
	gc.SetSessionLimitEnabled(true)
	if gc.sessionCount == nil {
		t.Fatal("FIXTURE: session-count publisher not retained; count path would not run")
	}
	gc.sweep()
	if len(dp.deleted) != 0 || len(dp.deletedV6) != 0 {
		t.Fatalf("exact-MaxUint64 rows reaped: v4=%v v6=%v (F-118 review)", dp.deleted, dp.deletedV6)
	}
	if got := gc.Stats().DeadlinesSaturated; got != 2 {
		t.Fatalf("DeadlinesSaturated = %d, want exactly 2 (one per saturated row)", got)
	}
}
