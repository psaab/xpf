package dataplane

import (
	"errors"
	"strings"
	"testing"
)

// TestClearAllCountersClearsNATZoneAndFloodOffsets_13297 is the #13297
// (D5-03) fail-on-revert guard: ClearAllCounters must clear every
// userspace-reported offset map (NAT rule, zone traffic, zone flood) even
// when the legacy interface_counters BPF map is absent — the mapless /
// userspace-only manager shape, where the pre-fix composition returned at
// clearInterfaceCountersRaw before reaching the zone/flood legs and never
// called ClearNATRuleCounters at all.
//
// FAIL-ON-REVERT: drop ClearNATRuleCounters from ClearAllCounters and the
// NAT assertion fails (offset survives); drop the unconditional offset
// clears (or move them back below the interface leg) and the zone/flood
// assertions fail on the mapless manager.
func TestClearAllCountersClearsNATZoneAndFloodOffsets_13297(t *testing.T) {
	m2 := &Manager{}
	// m2 has no maps at all: interface_counters absent -> pre-fix early return.

	m2.SetNATRuleCounterOffset(3, CounterValue{Packets: 99, Bytes: 4096})
	m2.SetZoneCounterOffset(1, CounterValue{Packets: 50}, CounterValue{Packets: 20})
	m2.SetFloodCounterOffset(1, FloodState{SynCount: 7})

	// Pre-clear: all three families readable.
	if got, err := m2.ReadNATRuleCounter(3); err != nil || got != (CounterValue{Packets: 99, Bytes: 4096}) {
		t.Fatalf("seeded NAT counter = %+v, %v", got, err)
	}
	if got, err := m2.ReadZoneCounters(1, 0); err != nil || got.Packets != 50 {
		t.Fatalf("seeded zone counter = %+v, %v", got, err)
	}
	if got, err := m2.ReadFloodCounters(1); err != nil || got.SynCount != 7 {
		t.Fatalf("seeded flood counter = %+v, %v", got, err)
	}

	err := m2.ClearAllCounters()
	// The pinned legacy outcome for a mapless manager is preserved: the
	// composition still surfaces the interface_counters text (armed-gate
	// tests pin this byte-for-byte), it just must not abort the clears.
	if err == nil || !strings.Contains(err.Error(), "interface_counters map not found") {
		t.Fatalf("ClearAllCounters on mapless manager = %v, want pinned interface_counters text", err)
	}

	// Post-clear: NAT reads zero (offset dropped -> zero value, no error);
	// zone/flood read ErrCounterNotPopulated (offset row gone).
	if got, err := m2.ReadNATRuleCounter(3); err != nil || got != (CounterValue{}) {
		t.Errorf("NAT counter after ClearAllCounters = %+v, %v; want zero (ClearNATRuleCounters not wired into ClearAllCounters?)", got, err)
	}
	if _, err := m2.ReadZoneCounters(1, 0); !errors.Is(err, ErrCounterNotPopulated) {
		t.Errorf("zone counter after ClearAllCounters err = %v, want ErrCounterNotPopulated (offsets stranded by early interface abort?)", err)
	}
	if _, err := m2.ReadFloodCounters(1); !errors.Is(err, ErrCounterNotPopulated) {
		t.Errorf("flood counter after ClearAllCounters err = %v, want ErrCounterNotPopulated (offsets stranded by early interface abort?)", err)
	}
}
