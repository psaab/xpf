package dataplane

import (
	"errors"
	"testing"
)

// #3651: the per-zone FLOOD offset map must be REPLACED from each helper
// snapshot, never merged into.
//
// TestReplaceFloodCounterOffsetsDropsAbsentZones is the core retention pin: a
// zone present in poll N and absent in poll N+1 must stop being served.
//
// FAIL-ON-REVERT: implement ReplaceFloodCounterOffsets as a loop of
// SetFloodCounterOffset (add-or-overwrite only) and `gone` keeps its poll-N
// counts forever — a FROZEN flood count that under-reports every subsequent
// attack while looking alive.
func TestReplaceFloodCounterOffsetsDropsAbsentZones(t *testing.T) {
	m := &Manager{}
	const kept uint32 = 101 // synthetic slotted zone id (#16557: StableZoneID now exceeds dense slot space)
	const gone uint32 = 102 // synthetic slotted zone id

	m.ReplaceFloodCounterOffsets(map[uint32]FloodState{
		kept: {SynCount: 1, ICMPCount: 2, UDPCount: 3},
		gone: {SynCount: 90, ICMPCount: 91, UDPCount: 92},
	})
	if fs, err := m.ReadFloodCounters(gone); err != nil || fs.SynCount != 90 {
		t.Fatalf("poll N: gone zone = %+v err=%v; want SynCount 90, nil", fs, err)
	}

	// Poll N+1: `gone` is no longer published — it lost its hot-path slot, was
	// removed from the config, or the helper restarted/was cleared.
	m.ReplaceFloodCounterOffsets(map[uint32]FloodState{
		kept: {SynCount: 5, ICMPCount: 6, UDPCount: 7},
	})

	if _, err := m.ReadFloodCounters(gone); !errors.Is(err, ErrCounterNotPopulated) {
		fs, _ := m.ReadFloodCounters(gone)
		t.Errorf("a zone the helper stopped publishing kept a stale flood offset "+
			"(%+v, err=%v); want ErrCounterNotPopulated — a retained value here is a "+
			"FROZEN counter that under-reports every subsequent flood", fs, err)
	}
	// The still-published zone must ADVANCE, not merely survive: an
	// implementation that cleared everything and re-added nothing would pass the
	// assertion above.
	fs, err := m.ReadFloodCounters(kept)
	if err != nil {
		t.Fatalf("kept zone err = %v; want nil", err)
	}
	if fs.SynCount != 5 || fs.ICMPCount != 6 || fs.UDPCount != 7 {
		t.Errorf("kept zone = %+v; want {5,6,7} — the replacement must carry the "+
			"NEW values, not merely preserve the old ones", fs)
	}
}

// TestReplaceFloodCounterOffsetsEmptyClearsAll covers the helper-restart /
// downgrade / just-cleared case: an empty published block means "the helper
// reports no per-zone flood counts", which is exactly ErrCounterNotPopulated.
//
// Paired with a POPULATED first poll so an implementation that always clears
// cannot pass — the assertion is a transition, not a state.
func TestReplaceFloodCounterOffsetsEmptyClearsAll(t *testing.T) {
	m := &Manager{}
	const id uint32 = 103 // synthetic slotted zone id

	m.ReplaceFloodCounterOffsets(map[uint32]FloodState{id: {SynCount: 3}})
	if fs, err := m.ReadFloodCounters(id); err != nil || fs.SynCount != 3 {
		t.Fatalf("populated poll must be readable first: %+v err=%v", fs, err)
	}
	m.ReplaceFloodCounterOffsets(nil)
	if _, err := m.ReadFloodCounters(id); !errors.Is(err, ErrCounterNotPopulated) {
		t.Errorf("a nil published block must clear the offsets; err=%v", err)
	}

	m.ReplaceFloodCounterOffsets(map[uint32]FloodState{id: {SynCount: 4}})
	if fs, err := m.ReadFloodCounters(id); err != nil || fs.SynCount != 4 {
		t.Fatalf("re-populate after nil must work: %+v err=%v", fs, err)
	}
	m.ReplaceFloodCounterOffsets(map[uint32]FloodState{})
	if _, err := m.ReadFloodCounters(id); !errors.Is(err, ErrCounterNotPopulated) {
		t.Errorf("an EMPTY (non-nil) published block must clear the offsets too; err=%v", err)
	}
}

// TestReplaceFloodCounterOffsetsCopiesInput guards against the caller's map
// aliasing the stored one. syncBPFCountersLocked builds a fresh map each poll
// today, but a stored alias would let a later caller-side mutation silently
// rewrite live counters.
func TestReplaceFloodCounterOffsetsCopiesInput(t *testing.T) {
	m := &Manager{}
	const id uint32 = 101
	rows := map[uint32]FloodState{id: {SynCount: 1}}
	m.ReplaceFloodCounterOffsets(rows)

	rows[id] = FloodState{SynCount: 999}
	delete(rows, id)
	rows[77] = FloodState{SynCount: 5}

	fs, err := m.ReadFloodCounters(id)
	if err != nil || fs.SynCount != 1 {
		t.Errorf("stored offsets aliased the caller's map: %+v err=%v; want SynCount 1", fs, err)
	}
	if _, err := m.ReadFloodCounters(77); !errors.Is(err, ErrCounterNotPopulated) {
		t.Errorf("a zone added to the caller's map after the call leaked into the "+
			"stored offsets; err=%v", err)
	}
}

// TestReplaceFloodCounterOffsetsDoesNotTouchZoneTrafficOffsets is the
// over-reach guard: the two per-zone counter families are independent maps, and
// replacing one must not disturb the other. It stays GREEN under the
// replace-vs-set revert above — it is about scope, not about the fix.
func TestReplaceFloodCounterOffsetsDoesNotTouchZoneTrafficOffsets(t *testing.T) {
	m := &Manager{}
	const id uint32 = 101

	m.ReplaceZoneCounterOffsets(map[uint32][2]CounterValue{
		id: {{Packets: 7, Bytes: 700}, {Packets: 8, Bytes: 800}},
	})
	// A flood replacement that publishes NOTHING — the most destructive shape.
	m.ReplaceFloodCounterOffsets(nil)

	v, err := m.ReadZoneCounters(id, 0)
	if err != nil || v.Packets != 7 || v.Bytes != 700 {
		t.Errorf("replacing the flood offsets disturbed the per-zone TRAFFIC "+
			"offsets: %+v err=%v; want {7,700} nil", v, err)
	}
	v, err = m.ReadZoneCounters(id, 1)
	if err != nil || v.Packets != 8 {
		t.Errorf("egress traffic offset = %+v err=%v; want {8,800} nil", v, err)
	}

	// And the reverse direction.
	m.ReplaceFloodCounterOffsets(map[uint32]FloodState{id: {SynCount: 4}})
	m.ReplaceZoneCounterOffsets(nil)
	fs, err := m.ReadFloodCounters(id)
	if err != nil || fs.SynCount != 4 {
		t.Errorf("replacing the traffic offsets disturbed the FLOOD offsets: "+
			"%+v err=%v; want SynCount 4, nil", fs, err)
	}
}
