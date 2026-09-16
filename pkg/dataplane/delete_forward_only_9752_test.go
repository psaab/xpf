package dataplane

// #9752: a forward-only delete retires exactly the named keys through the
// peer-marked helper path too — no companion deletes for a purge close.
import (
	"testing"
)

func TestForwardOnlySkipsPeerCompanionDeletes9752(t *testing.T) {
	forward := SessionKey{Protocol: 6, SrcPort: 47912, DstPort: 5203}
	reverse := SessionKey{Protocol: 6, SrcPort: 5203, DstPort: 47912}
	entries := []SessionEntryV4{{
		Key:   forward,
		Value: SessionValue{RoutingDomain: 100007, ReverseKey: reverse},
	}}
	dp := &peerRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	if _, err := store.DeleteBatchKnownV4(entries, DeleteReasonClusterStale, true); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp.peerBatchV4) != 1 || dp.peerBatchV4[0].Key != forward {
		t.Fatalf("#9752: forward-only delete sent %d peer deletes, want exactly the forward",
			len(dp.peerBatchV4))
	}

	// Control: an ordinary delete still retracts the stored companion.
	dp2 := &peerRecorderDP{}
	store2 := dataPlaneSessionStore{dp: dp2}
	if _, err := store2.DeleteBatchKnownV4(entries, DeleteReasonClusterStale, false); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp2.peerBatchV4) != 2 {
		t.Fatalf("ordinary delete sent %d peer deletes, want forward + companion", len(dp2.peerBatchV4))
	}
}

// #9752 round 3 item 4: the forward-only mark reaches the HELPER request —
// batch and miss-path single — so the helper retires exactly the named key
// instead of deriving/removing/queueing the reverse it cannot see was
// deliberately preserved.
func TestForwardOnlyMarkReachesTheHelper9752(t *testing.T) {
	forward := SessionKey{Protocol: 6, SrcPort: 47912, DstPort: 5203}
	reverse := SessionKey{Protocol: 6, SrcPort: 5203, DstPort: 47912}
	entries := []SessionEntryV4{{
		Key:   forward,
		Value: SessionValue{RoutingDomain: 100007, ReverseKey: reverse},
	}}
	dp := &peerRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	if _, err := store.DeleteBatchKnownV4(entries, DeleteReasonClusterStale, true); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp.peerBatchMarks) != 1 || !dp.peerBatchMarks[0] {
		t.Fatalf("#9752 round 3: forward-only batch reached the helper with marks %v, want [true]",
			dp.peerBatchMarks)
	}
	// Control: ordinary batch is unmarked.
	dp2 := &peerRecorderDP{}
	store2 := dataPlaneSessionStore{dp: dp2}
	if _, err := store2.DeleteBatchKnownV4(entries, DeleteReasonClusterStale, false); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	for _, m := range dp2.peerBatchMarks {
		if m {
			t.Fatalf("#9752 round 3: ordinary batch carried the forward-only mark: %v", dp2.peerBatchMarks)
		}
	}
	// Miss path: the mirror holds nothing (the recorder always misses), so a
	// forward-only companions delete falls to the helper single — marked.
	dp3 := &peerRecorderDP{}
	store3 := dataPlaneSessionStore{dp: dp3}
	if err := store3.DeleteWithCompanionsV4(forward, DeleteReasonClusterStale, true); err != nil {
		t.Fatalf("DeleteWithCompanionsV4: %v", err)
	}
	if len(dp3.peerSingleMarks) != 1 || !dp3.peerSingleMarks[0] {
		t.Fatalf("#9752 round 3: forward-only miss-path single reached the helper with marks %v, want [true]",
			dp3.peerSingleMarks)
	}
}
