package conntrack

import (
	"errors"
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
func TestGCSweepPostDeletionCountsMixedAndMissingCompanion13236(t *testing.T) {
	now := uint64(100)
	expired := dataplane.SessionKey{Protocol: 6, SrcPort: 1000}
	survivor := dataplane.SessionKey{Protocol: 6, SrcPort: 1001}
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			expired:  {State: dataplane.SessStateEstablished, LastSeen: 1, Timeout: 1, ReverseKey: dataplane.SessionKey{Protocol: 6, SrcPort: 2000}},
			survivor: {State: dataplane.SessStateEstablished, LastSeen: now, Timeout: 100},
		},
		v6sessions: make(map[dataplane.SessionKeyV6]dataplane.SessionValueV6),
	}
	gc := NewGC(dp, time.Second)
	gc.testNow = func() uint64 { return now }

	gc.sweep()
	stats := gc.Stats()
	if stats.TotalEntries != 1 || stats.EstablishedSessions != 1 || gc.lastTotal != 1 {
		t.Fatalf("mixed sweep counts = total:%d established:%d lastTotal:%d; want 1/1/1",
			stats.TotalEntries, stats.EstablishedSessions, gc.lastTotal)
	}
}

type reverseOnlyDeleteFailureStore struct {
	*mockGCDP
}

func (s *reverseOnlyDeleteFailureStore) DeleteBatchKnownExactV4(entries []dataplane.SessionEntryV4, _ dataplane.DeleteReason, _ bool) ([]dataplane.SessionKey, error) {
	for _, entry := range entries {
		if entry.Value.ReverseKey.Protocol != 0 {
			if err := s.DeleteSession(entry.Value.ReverseKey); err != nil {
				return nil, err
			}
		}
	}
	return nil, errors.New("forward delete failed after reverse delete")
}
func (s *reverseOnlyDeleteFailureStore) DeleteBatchKnownExactV6(entries []dataplane.SessionEntryV6, _ dataplane.DeleteReason, _ bool) ([]dataplane.SessionKeyV6, error) {
	for _, entry := range entries {
		if entry.Value.ReverseKey.Protocol != 0 {
			if err := s.DeleteSessionV6(entry.Value.ReverseKey); err != nil {
				return nil, err
			}
		}
	}
	return nil, errors.New("forward delete failed after reverse delete")
}

func TestGCSweepCountsReverseRemovedBeforeForwardErrorV613236(t *testing.T) {
	now := uint64(100)
	forward := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1000}
	reverse := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 2000}
	dp := &mockGCDP{
		v4sessions: make(map[dataplane.SessionKey]dataplane.SessionValue),
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			forward: {State: dataplane.SessStateEstablished, LastSeen: 1, Timeout: 1, ReverseKey: reverse},
			reverse: {State: dataplane.SessStateEstablished, IsReverse: 1, LastSeen: 1, Timeout: 1, ReverseKey: forward},
		},
	}
	store := &reverseOnlyDeleteFailureStore{mockGCDP: dp}
	gc := NewGCWithDomains(store, mockGCTelemetry{}, nil, nil, time.Second)
	gc.testNow = func() uint64 { return now }

	gc.sweep()
	stats := gc.Stats()
	if len(dp.v6sessions) != 1 {
		t.Fatalf("remaining v6 entries=%d want 1 after reverse-only delete", len(dp.v6sessions))
	}
	if stats.TotalEntries != 1 || stats.EstablishedSessions != 1 || gc.lastTotal != 1 {
		t.Fatalf("partial v6-delete counts = total:%d established:%d lastTotal:%d; want 1/1/1",
			stats.TotalEntries, stats.EstablishedSessions, gc.lastTotal)
	}
}

func TestGCSweepCountsReverseRemovedBeforeForwardError13236(t *testing.T) {
	now := uint64(100)
	forward := dataplane.SessionKey{Protocol: 6, SrcPort: 1000}
	reverse := dataplane.SessionKey{Protocol: 6, SrcPort: 2000}
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			forward: {State: dataplane.SessStateEstablished, LastSeen: 1, Timeout: 1, ReverseKey: reverse},
			reverse: {State: dataplane.SessStateEstablished, IsReverse: 1, LastSeen: 1, Timeout: 1, ReverseKey: forward},
		},
		v6sessions: make(map[dataplane.SessionKeyV6]dataplane.SessionValueV6),
	}
	store := &reverseOnlyDeleteFailureStore{mockGCDP: dp}
	gc := NewGCWithDomains(store, mockGCTelemetry{}, nil, nil, time.Second)
	gc.testNow = func() uint64 { return now }

	gc.sweep()
	stats := gc.Stats()
	if len(dp.v4sessions) != 1 {
		t.Fatalf("remaining entries=%d want 1 after reverse-only delete", len(dp.v4sessions))
	}
	if stats.TotalEntries != 1 || stats.EstablishedSessions != 1 || gc.lastTotal != 1 {
		t.Fatalf("partial-delete counts = total:%d established:%d lastTotal:%d; want 1/1/1",
			stats.TotalEntries, stats.EstablishedSessions, gc.lastTotal)
	}
}
