package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #6843 (Codex gate): bind the PRODUCTION status-loop call site.
//
// The pkg/dataplane retention tests drive Manager.ReplaceZoneCounterOffsets
// directly. That proves the replacement primitive and NOT that
// syncBPFCountersLocked uses it — reverting the status loop to per-row
// SetZoneCounterOffset, while leaving the primitive correct, left every one of
// those tests green. This drives two successive ProcessStatus polls through the
// real loop.
func TestSyncBPFCountersReplacesZoneOffsetsAcrossPolls6843(t *testing.T) {
	m := New()
	const kept uint32 = 101 // synthetic slotted zone id (#16557: StableZoneID now exceeds dense slot space)
	const gone uint32 = 102 // synthetic slotted zone id

	// Poll N: the helper publishes both zones.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		ZoneCounterLayoutVersion: 1,
		ZoneTrafficCounters: []ZoneTrafficCounterStatus{
			{ZoneID: kept, IngressPackets: 1, IngressBytes: 100, EgressPackets: 2, EgressBytes: 200},
			{ZoneID: gone, IngressPackets: 9, IngressBytes: 900, EgressPackets: 8, EgressBytes: 800},
		},
	})
	m.mu.Unlock()

	if v, err := m.bpfShim.ReadZoneCounters(gone, 0); err != nil || v.Packets != 9 {
		t.Fatalf("poll N: gone zone = %+v err=%v; want {9,900} nil", v, err)
	}

	// Poll N+1: `gone` is no longer published — it lost its hot-path slot, was
	// removed from the config, or the helper restarted. `kept` advances.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		ZoneCounterLayoutVersion: 1,
		ZoneTrafficCounters: []ZoneTrafficCounterStatus{
			{ZoneID: kept, IngressPackets: 5, IngressBytes: 500, EgressPackets: 6, EgressBytes: 600},
		},
	})
	m.mu.Unlock()

	if _, err := m.bpfShim.ReadZoneCounters(gone, 0); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		v, _ := m.bpfShim.ReadZoneCounters(gone, 0)
		t.Errorf("the status loop left a stale offset for a zone the helper stopped "+
			"publishing (%+v, err=%v); want ErrCounterNotPopulated — a retained value "+
			"here is a FROZEN counter that under-reports every subsequent packet", v, err)
	}
	// The still-published zone must ADVANCE, not merely survive: a loop that
	// cleared everything and re-added nothing would pass the assertion above.
	if v, err := m.bpfShim.ReadZoneCounters(kept, 0); err != nil || v.Packets != 5 || v.Bytes != 500 {
		t.Errorf("kept zone = %+v err=%v; want {5,500} nil", v, err)
	}
	if v, err := m.bpfShim.ReadZoneCounters(kept, 1); err != nil || v.Packets != 6 {
		t.Errorf("kept zone egress = %+v err=%v; want {6,600} nil", v, err)
	}
}

// TestSyncBPFCountersClearsZoneOffsetsWhenHelperStopsPublishing6843 covers the
// helper-restart / downgrade case through the real loop: an empty block clears.
//
// Paired with a POPULATED first poll in the same fixture so an implementation
// that always clears cannot pass — the assertion is a transition, not a state.
func TestSyncBPFCountersClearsZoneOffsetsWhenHelperStopsPublishing6843(t *testing.T) {
	m := New()
	const id uint32 = 103 // synthetic slotted zone id

	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		ZoneCounterLayoutVersion: 1,
		ZoneTrafficCounters: []ZoneTrafficCounterStatus{
			{ZoneID: id, IngressPackets: 3, IngressBytes: 300},
		},
	})
	m.mu.Unlock()
	if v, err := m.bpfShim.ReadZoneCounters(id, 0); err != nil || v.Packets != 3 {
		t.Fatalf("populated poll must be readable first: %+v err=%v", v, err)
	}

	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{ZoneCounterLayoutVersion: 1})
	m.mu.Unlock()
	if _, err := m.bpfShim.ReadZoneCounters(id, 0); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		t.Errorf("an empty published block must clear the offsets; err=%v", err)
	}
}

// TestSyncBPFCountersClearsZoneOffsetsOnLayoutVersionZero6843 covers the
// HELPER-DOWNGRADE case, which layout version 0 is precisely how the wire
// signals (protocol_status.go: "0/absent = pre-#3651 helper, no per-zone data").
//
// #6843 gate F2: both other tests in this file hard-code
// ZoneCounterLayoutVersion 1, so a `if status.ZoneCounterLayoutVersion == 0 {
// return }` guard added before the zone block escapes them AND the whole Go
// suite. That guard reads as a natural optimisation — the field's own doc
// invites it — but ReplaceZoneCounterOffsets names "the helper restarted, or
// was downgraded to a build with no per-zone block" as one of the three
// disappearance cases that MUST clear. Under such a guard a downgrade strands
// the last offsets forever: the frozen-counter failure this PR exists to
// prevent, reintroduced through the version field.
//
// Version 0 must therefore be handled like any other empty block: clear.
func TestSyncBPFCountersClearsZoneOffsetsOnLayoutVersionZero6843(t *testing.T) {
	m := New()
	const id uint32 = 101

	// A populated poll from a current helper.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		ZoneCounterLayoutVersion: 1,
		ZoneTrafficCounters: []ZoneTrafficCounterStatus{
			{ZoneID: id, IngressPackets: 11, IngressBytes: 1100},
		},
	})
	m.mu.Unlock()
	if v, err := m.bpfShim.ReadZoneCounters(id, 0); err != nil || v.Packets != 11 {
		t.Fatalf("populated poll must be readable first: %+v err=%v", v, err)
	}

	// The helper restarts into an OLDER build: layout version 0, no per-zone
	// block. The offsets must not survive.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{ZoneCounterLayoutVersion: 0})
	m.mu.Unlock()
	if _, err := m.bpfShim.ReadZoneCounters(id, 0); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		v, _ := m.bpfShim.ReadZoneCounters(id, 0)
		t.Errorf("a layout-version-0 (downgraded/restarted) helper left the previous "+
			"offsets in place (%+v, err=%v); want ErrCounterNotPopulated — the old "+
			"values can never advance again, which is the frozen counter this "+
			"change exists to prevent", v, err)
	}
}
