package conntrack

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// TestGCSweepPostDeletionCounts13236 pins D5-06 (#13236): sweep must report
// post-deletion surviving counts, not pre-deletion counts inflated by the
// entries it just expired. 9/9 expired established pairs => surviving 0.
// FAIL-ON-REVERT: reverting (git diff -R on gc.go) restores pre-deletion
// accounting and this test fails with TotalEntries=18 etc.
func TestGCSweepPostDeletionCounts13236(t *testing.T) {
	dp := &mockGCDP{
		v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue),
		v6sessions: make(map[dataplane.SessionKeyV6]dataplane.SessionValueV6),
	}
	for i := byte(1); i <= 9; i++ {
		fk := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, i}, DstIP: [4]byte{10, 0, 1, 1}, SrcPort: 1000, DstPort: 80, Protocol: 6}
		rk := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 0, i}, SrcPort: 80, DstPort: 1000, Protocol: 6}
		dp.v4sessions[fk] = dataplane.SessionValue{State: dataplane.SessStateEstablished, LastSeen: 1, Timeout: 1, ReverseKey: rk}
		dp.v4sessions[rk] = dataplane.SessionValue{State: dataplane.SessStateEstablished, IsReverse: 1, LastSeen: 1, Timeout: 1, ReverseKey: fk}
	}
	gc := NewGC(dp, time.Second)
	gc.highWatermark = 80
	gc.lowWatermark = 60
	gc.earlyAgeout = 30
	gc.testNow = func() uint64 { return 100 }

	delay := gc.sweep()
	stats := gc.Stats()
	if len(dp.v4sessions) != 0 {
		t.Fatalf("expected 0 remaining, got %d", len(dp.v4sessions))
	}
	if stats.ExpiredDeleted != 9 {
		t.Fatalf("ExpiredDeleted=%d want 9", stats.ExpiredDeleted)
	}
	if stats.TotalEntries != 0 || stats.EstablishedSessions != 0 {
		t.Fatalf("post-deletion stats inflated: Total=%d Established=%d want 0/0", stats.TotalEntries, stats.EstablishedSessions)
	}
	if gc.lastTotal != 0 {
		t.Fatalf("lastTotal=%d want 0", gc.lastTotal)
	}
	if gc.agingActive {
		t.Fatal("aggressive aging activated on drained table")
	}
	if delay != time.Second {
		t.Fatalf("next delay=%v want %v for empty table", delay, time.Second)
	}
}
