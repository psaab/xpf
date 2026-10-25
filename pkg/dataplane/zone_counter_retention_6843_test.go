package dataplane

import (
	"errors"
	"testing"
)

// #6843: the per-zone offset map must be REPLACED from each helper status
// snapshot, never merged into.
//
// The helper publishes a complete sparse set every poll. A row that stops being
// published means the helper is no longer reporting that zone, and the correct
// Go-side answer is ErrCounterNotPopulated. A merge-only update (per-row
// SetZoneCounterOffset with no removal) instead strands the last value: every
// read surface keeps serving a FROZEN total that can never advance, which is
// worse than reporting nothing because it looks alive.
//
// This is reachable in normal operation, not just on teardown — a zone pushed
// past the helper's hot-path slot capacity by a later config keeps its retained
// totals but stops being counted, so its row drops out while the zone stays
// configured.

// TestReplaceZoneCounterOffsetsDropsAbsentZones is the core retention pin: a
// zone present in poll N and absent in poll N+1 must go back to unpopulated.
//
// FAIL-ON-REVERT: implement ReplaceZoneCounterOffsets as a loop of
// SetZoneCounterOffset (merge, no removal) and the "gone" assertion goes RED
// with the stale value still readable.
func TestReplaceZoneCounterOffsetsDropsAbsentZones(t *testing.T) {
	m := New()
	const kept uint32 = 101 // synthetic slotted zone id (#16557: StableZoneID now exceeds dense slot space)
	const gone uint32 = 102 // synthetic slotted zone id

	// Poll N: both zones reporting.
	m.ReplaceZoneCounterOffsets(map[uint32][2]CounterValue{
		kept: {{Packets: 1, Bytes: 100}, {Packets: 2, Bytes: 200}},
		gone: {{Packets: 9, Bytes: 900}, {Packets: 8, Bytes: 800}},
	})
	if v, err := m.ReadZoneCounters(gone, 0); err != nil || v.Packets != 9 {
		t.Fatalf("poll N: ReadZoneCounters(gone) = %+v, err = %v; want {9,900}, nil", v, err)
	}

	// Poll N+1: `gone` is no longer published (lost its slot / removed /
	// helper restarted). `kept` advances.
	m.ReplaceZoneCounterOffsets(map[uint32][2]CounterValue{
		kept: {{Packets: 5, Bytes: 500}, {Packets: 6, Bytes: 600}},
	})

	if _, err := m.ReadZoneCounters(gone, 0); !errors.Is(err, ErrCounterNotPopulated) {
		v, _ := m.ReadZoneCounters(gone, 0)
		t.Errorf("a zone absent from the new snapshot still reads as populated (%+v, err=%v); "+
			"want ErrCounterNotPopulated — a retained value here is a FROZEN counter "+
			"that under-reports every subsequent packet while looking alive", v, err)
	}
	if v, err := m.ReadZoneCounters(kept, 0); err != nil || v.Packets != 5 || v.Bytes != 500 {
		t.Errorf("kept zone = %+v, err = %v; want {5,500}, nil — replacing must not "+
			"disturb zones that are still reporting", v, err)
	}
	if v, err := m.ReadZoneCounters(kept, 1); err != nil || v.Packets != 6 {
		t.Errorf("kept zone egress = %+v, err = %v; want {6,600}, nil", v, err)
	}
}

// TestReplaceZoneCounterOffsetsEmptyClearsAll covers the helper-restart and
// helper-downgrade cases: an empty published set means nothing is populated.
func TestReplaceZoneCounterOffsetsEmptyClearsAll(t *testing.T) {
	m := New()
	const id uint32 = 101
	m.ReplaceZoneCounterOffsets(map[uint32][2]CounterValue{
		id: {{Packets: 3, Bytes: 300}, {Packets: 4, Bytes: 400}},
	})
	if _, err := m.ReadZoneCounters(id, 0); err != nil {
		t.Fatalf("setup read failed: %v", err)
	}

	m.ReplaceZoneCounterOffsets(nil)
	if _, err := m.ReadZoneCounters(id, 0); !errors.Is(err, ErrCounterNotPopulated) {
		t.Errorf("empty snapshot must clear the map; got err = %v, want ErrCounterNotPopulated", err)
	}
	m.ReplaceZoneCounterOffsets(map[uint32][2]CounterValue{})
	if _, err := m.ReadZoneCounters(id, 0); !errors.Is(err, ErrCounterNotPopulated) {
		t.Errorf("empty (non-nil) snapshot must clear the map; got err = %v", err)
	}

	// This leg guards a STICKY clear: an implementation that clears correctly
	// but never repopulates (e.g. clearing to an empty non-nil map and then
	// dropping later writes). Measured at both trees: an ALWAYS-clear
	// implementation is already caught upstream by the setup precondition at
	// the top of this test, which t.Fatalf's before reaching here — so this leg
	// does NOT bind always-clear, and an earlier version of this comment which
	// claimed it did was wrong.
	m.ReplaceZoneCounterOffsets(map[uint32][2]CounterValue{
		id: {{Packets: 7, Bytes: 700}, {Packets: 8, Bytes: 800}},
	})
	if v, err := m.ReadZoneCounters(id, 0); err != nil || v.Packets != 7 || v.Bytes != 700 {
		t.Errorf("after re-populating = %+v err=%v, want {7,700} nil — a STICKY "+
			"clear (clears correctly but never repopulates) must not pass. "+
			"Always-clear is caught upstream by this test's setup precondition, "+
			"not here", v, err)
	}
}

// TestReplaceZoneCounterOffsetsRemoveThenReadd covers the second retention
// hazard the gate named: a zone removed and later re-added must report the NEW
// totals, never a resurrected pre-removal value.
func TestReplaceZoneCounterOffsetsRemoveThenReadd(t *testing.T) {
	m := New()
	const id uint32 = 103 // synthetic slotted zone id

	m.ReplaceZoneCounterOffsets(map[uint32][2]CounterValue{
		id: {{Packets: 100, Bytes: 10000}, {Packets: 200, Bytes: 20000}},
	})
	m.ReplaceZoneCounterOffsets(nil) // removed from config
	if _, err := m.ReadZoneCounters(id, 0); !errors.Is(err, ErrCounterNotPopulated) {
		t.Fatalf("after removal: err = %v, want ErrCounterNotPopulated", err)
	}

	// Re-added; the helper's store was reconciled away, so it counts from zero.
	// The caller's map is MUTATED after the call below, so an implementation
	// that stored it by reference (rather than copying) would be caught here as
	// well as by TestReplaceZoneCounterOffsetsCopiesInput.
	readd := map[uint32][2]CounterValue{
		id: {{Packets: 1, Bytes: 64}, {Packets: 0, Bytes: 0}},
	}
	m.ReplaceZoneCounterOffsets(readd)
	readd[id] = [2]CounterValue{{Packets: 4242, Bytes: 4242}, {}}
	v, err := m.ReadZoneCounters(id, 0)
	if err != nil {
		t.Fatalf("after re-add: err = %v, want nil", err)
	}
	if v.Packets != 1 || v.Bytes != 64 {
		t.Errorf("after re-add ingress = %+v, want {1,64} — a pre-removal total "+
			"resurfacing here would over-report the zone's lifetime traffic", v)
	}
	// A genuinely-zero published value stays AVAILABLE (nil error): "the helper
	// reports zero" and "the helper reports nothing" are different states.
	if ev, err := m.ReadZoneCounters(id, 1); err != nil || ev.Packets != 0 {
		t.Errorf("after re-add egress = %+v, err = %v; want {0,0}, nil", ev, err)
	}
}

// TestReplaceZoneCounterOffsetsCopiesInput guards against the caller's map
// being retained by reference: syncBPFCountersLocked builds a fresh map each
// poll, but a future caller reusing one buffer must not be able to mutate
// stored offsets behind the manager's lock.
func TestReplaceZoneCounterOffsetsCopiesInput(t *testing.T) {
	m := New()
	const id uint32 = 101
	rows := map[uint32][2]CounterValue{
		id: {{Packets: 7, Bytes: 700}, {Packets: 8, Bytes: 800}},
	}
	m.ReplaceZoneCounterOffsets(rows)

	rows[id] = [2]CounterValue{{Packets: 999}, {Packets: 999}}
	delete(rows, id)

	v, err := m.ReadZoneCounters(id, 0)
	if err != nil || v.Packets != 7 || v.Bytes != 700 {
		t.Errorf("stored offsets follow the caller's map after it was mutated: "+
			"got %+v err=%v, want {7,700} nil", v, err)
	}

	// A SECOND snapshot that omits id. Without this leg a merge-only
	// implementation passes everything above — one populated snapshot cannot
	// distinguish replace from merge, and replace-not-merge is the whole point
	// of this method.
	const other uint32 = 102
	m.ReplaceZoneCounterOffsets(map[uint32][2]CounterValue{
		other: {{Packets: 1, Bytes: 10}, {Packets: 2, Bytes: 20}},
	})
	if _, err := m.ReadZoneCounters(id, 0); !errors.Is(err, ErrCounterNotPopulated) {
		t.Errorf("a zone omitted from the second snapshot survived: replace "+
			"degenerated to merge; err=%v", err)
	}
	if v, err := m.ReadZoneCounters(other, 0); err != nil || v.Packets != 1 {
		t.Errorf("second snapshot zone = %+v err=%v, want {1,10} nil", v, err)
	}
}
