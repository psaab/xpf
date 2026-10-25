package dataplane

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3643 HIDE read-side pin. Zone ids are stable name-hashes in [1,65533]
// (#3075), but the legacy zone_counters / flood_counters BPF arrays are dense
// MaxZones*2 / MaxZones-entry per-CPU arrays. Before this fix ReadZoneCounters
// indexed the dense array by the stable-hash id, so an id >= MaxZones OOB'd the
// bounded Lookup (ErrKeyNotExist / "map not found") and the read surfaces
// mis-reported it as a hard failure (REST 500, false Prometheus read-error
// alerts, CLI/gRPC error rows). The reads now key a Go-side sparse offset map
// (#2255 nat_rule_counters treatment) and NEVER index the dense array, so an id
// >= MaxZones reports the DISTINCT ErrCounterNotPopulated sentinel instead.
//
// FAIL-ON-REVERT: restoring the dense-array Lookup makes these reads return an
// OOB / map-not-found error (NOT ErrCounterNotPopulated) for a stable-hash id
// >= MaxZones, so the errors.Is(..., ErrCounterNotPopulated) assertions go RED.
func TestReadZoneCountersHideForStableHashID(t *testing.T) {
	m := New()

	// A representative stable-hash id well past MaxZones (64). This is the
	// common case: a real config essentially always has a zone whose
	// name-hash lands >= MaxZones.
	bigID := config.StableZoneID("untrust")
	if bigID < MaxZones {
		// Extremely unlikely, but pick a fixed large id if this name happens
		// to hash low, so the test still exercises the >= MaxZones path.
		bigID = 40000
	}

	for _, dir := range []int{0, 1} {
		v, err := m.ReadZoneCounters(bigID, dir)
		if !errors.Is(err, ErrCounterNotPopulated) {
			t.Fatalf("ReadZoneCounters(%d, %d) err = %v, want ErrCounterNotPopulated "+
				"(a stable-hash id >= MaxZones must not OOB the dense array)", bigID, dir, err)
		}
		if v != (CounterValue{}) {
			t.Fatalf("ReadZoneCounters(%d, %d) = %+v, want zero value", bigID, dir, v)
		}
	}

	fs, err := m.ReadFloodCounters(bigID)
	if !errors.Is(err, ErrCounterNotPopulated) {
		t.Fatalf("ReadFloodCounters(%d) err = %v, want ErrCounterNotPopulated", bigID, err)
	}
	if fs != (FloodState{}) {
		t.Fatalf("ReadFloodCounters(%d) = %+v, want zero value", bigID, fs)
	}
}

// The sparse offset map is the deferred POPULATE hook (#3643 plan §5A): once a
// setter records a value, the read returns it with a nil error (not the
// sentinel), so a future populate path lights the same surfaces up without a
// second read-side change. This also guards that a genuinely-zero populated
// counter is reported as available (nil error), NOT as ErrCounterNotPopulated.
func TestZoneFloodCounterOffsetsPopulateAndClear(t *testing.T) {
	m := New()
	const id uint32 = 40000

	m.SetZoneCounterOffset(id, CounterValue{Packets: 5, Bytes: 600}, CounterValue{Packets: 3, Bytes: 400})
	if v, err := m.ReadZoneCounters(id, 0); err != nil || v.Packets != 5 || v.Bytes != 600 {
		t.Fatalf("ReadZoneCounters ingress = %+v, err = %v; want {5,600}, nil", v, err)
	}
	if v, err := m.ReadZoneCounters(id, 1); err != nil || v.Packets != 3 || v.Bytes != 400 {
		t.Fatalf("ReadZoneCounters egress = %+v, err = %v; want {3,400}, nil", v, err)
	}

	// A populated-but-zero value is still "available" (nil error), distinct
	// from "not populated".
	m.SetFloodCounterOffset(id, FloodState{})
	if _, err := m.ReadFloodCounters(id); err != nil {
		t.Fatalf("ReadFloodCounters after populate err = %v, want nil (a real zero is available)", err)
	}

	m.ClearZoneCounterOffsets()
	m.ClearFloodCounterOffsets()
	if _, err := m.ReadZoneCounters(id, 0); !errors.Is(err, ErrCounterNotPopulated) {
		t.Fatalf("ReadZoneCounters after clear err = %v, want ErrCounterNotPopulated", err)
	}
	if _, err := m.ReadFloodCounters(id); !errors.Is(err, ErrCounterNotPopulated) {
		t.Fatalf("ReadFloodCounters after clear err = %v, want ErrCounterNotPopulated", err)
	}
}
