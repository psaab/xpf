package dataplane

import (
	"errors"
	"testing"
)

// sentinelReader17193 models the userspace LegacyDataPlaneAdapter contract
// (#13274): the four known-unsourced indexes return ErrCounterNotPopulated,
// every other index returns idx+1.
type sentinelReader17193 struct{}

func (sentinelReader17193) ReadGlobalCounter(idx uint32) (uint64, error) {
	switch idx {
	case GlobalCtrFlowCacheFlush, GlobalCtrFlowCacheInvalidate,
		GlobalCtrTCEgressPackets, GlobalCtrFabricRedirect:
		return 0, ErrCounterNotPopulated
	default:
		return uint64(idx) + 1, nil
	}
}

// TestReadGlobalCountersClassifiesUnavailable17193 pins the shared
// classification (#17193): ErrCounterNotPopulated is unavailable, never a
// value and never an error; healthy counters keep their values.
//
// FAIL-ON-REVERT: routing ErrCounterNotPopulated into Err (the pre-fix
// per-surface behaviour) makes snap.Err non-nil and drops the four indexes
// from Unavailable; recording them in Values fabricates the 0 the text
// surfaces printed.
func TestReadGlobalCountersClassifiesUnavailable17193(t *testing.T) {
	snap := ReadGlobalCounters(sentinelReader17193{},
		GlobalCtrRxPackets, GlobalCtrTCEgressPackets, GlobalCtrFlowCacheFlush,
		GlobalCtrFlowCacheInvalidate, GlobalCtrFabricRedirect, GlobalCtrFlowCacheHit)
	if snap.Err != nil {
		t.Fatalf("Err = %v, want nil (unavailable is not a read failure)", snap.Err)
	}
	wantUnavailable := []uint32{GlobalCtrTCEgressPackets, GlobalCtrFlowCacheFlush,
		GlobalCtrFlowCacheInvalidate, GlobalCtrFabricRedirect}
	if len(snap.Unavailable) != len(wantUnavailable) {
		t.Fatalf("Unavailable = %v, want %v", snap.Unavailable, wantUnavailable)
	}
	for i, want := range wantUnavailable {
		if snap.Unavailable[i] != want {
			t.Errorf("Unavailable[%d] = %d, want %d", i, snap.Unavailable[i], want)
		}
		if _, ok := snap.Values[want]; ok {
			t.Errorf("unavailable counter %d recorded in Values (fabricated value)", want)
		}
	}
	if v, ok := snap.Value(GlobalCtrRxPackets); !ok || v != uint64(GlobalCtrRxPackets)+1 {
		t.Errorf("Value(RxPackets) = %d,%v, want %d,true", v, ok, uint64(GlobalCtrRxPackets)+1)
	}
	wantNames := []string{"tc_egress_packets", "flow_cache_flushes", "flow_cache_invalidations", "fabric_redirects"}
	gotNames := snap.UnavailableNames()
	if len(gotNames) != len(wantNames) {
		t.Fatalf("UnavailableNames = %v, want %v", gotNames, wantNames)
	}
	for i := range wantNames {
		if gotNames[i] != wantNames[i] {
			t.Errorf("UnavailableNames[%d] = %q, want %q", i, gotNames[i], wantNames[i])
		}
	}
}

// TestReadGlobalCountersPreservesGenuineError17193 pins the other half of
// the #3345 contract: a genuine failure is Err (first one wins), is not
// reclassified as unavailable, and does not poison healthy reads.
func TestReadGlobalCountersPreservesGenuineError17193(t *testing.T) {
	boom := errors.New("counter bridge degraded")
	r := globalCounterFunc17193(func(idx uint32) (uint64, error) {
		switch idx {
		case GlobalCtrTCEgressPackets:
			return 0, ErrCounterNotPopulated
		case GlobalCtrRxPackets, GlobalCtrTxPackets:
			return 0, boom
		default:
			return 7, nil
		}
	})
	snap := ReadGlobalCounters(r, GlobalCtrRxPackets, GlobalCtrTCEgressPackets,
		GlobalCtrTxPackets, GlobalCtrDrops)
	if !errors.Is(snap.Err, boom) {
		t.Fatalf("Err = %v, want the genuine failure %v", snap.Err, boom)
	}
	if !snap.IsUnavailable(GlobalCtrTCEgressPackets) {
		t.Errorf("sentinel counter not classified unavailable: %+v", snap)
	}
	if _, ok := snap.Values[GlobalCtrRxPackets]; ok {
		t.Errorf("failed counter recorded in Values")
	}
	if v, ok := snap.Value(GlobalCtrDrops); !ok || v != 7 {
		t.Errorf("healthy counter Value = %d,%v, want 7,true", v, ok)
	}
}

// TestReadGlobalCountersDedupes17193 pins read-once for duplicate indexes:
// the helper must not add a control-socket request per duplicate.
func TestReadGlobalCountersDedupes17193(t *testing.T) {
	reads := 0
	r := globalCounterFunc17193(func(idx uint32) (uint64, error) {
		reads++
		return 3, nil
	})
	snap := ReadGlobalCounters(r, GlobalCtrDrops, GlobalCtrDrops, GlobalCtrDrops)
	if reads != 1 {
		t.Errorf("underlying reads = %d, want 1 for a duplicated index", reads)
	}
	if v, ok := snap.Value(GlobalCtrDrops); !ok || v != 3 {
		t.Errorf("Value(Drops) = %d,%v, want 3,true", v, ok)
	}
}

type globalCounterFunc17193 func(uint32) (uint64, error)

func (f globalCounterFunc17193) ReadGlobalCounter(idx uint32) (uint64, error) { return f(idx) }
