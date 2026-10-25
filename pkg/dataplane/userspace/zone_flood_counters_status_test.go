package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #3651: the ZoneFloodCounters block survives JSON round-trip both directions
// (Go-encode -> JSON -> Go-decode, and Go-decode of a Rust-style payload). The
// Rust-side mirror is protocol/tests.rs::
// zone_flood_counters_wire_roundtrip_and_default_omits.
//
// FAIL-ON-REVERT: change any of the three per-row json tags (or the two
// ProcessStatus-level ones) away from the Rust serde rename and the Rust-style
// decode leg below reports the field as zero.
func TestZoneFloodCounterStatusWireRoundTrip(t *testing.T) {
	// A default ProcessStatus omits the layout-version / overflow keys
	// (omitempty), matching the Rust skip_serializing_if behaviour.
	def, err := json.Marshal(&ProcessStatus{})
	if err != nil {
		t.Fatalf("marshal default ProcessStatus: %v", err)
	}
	for _, k := range []string{"flood_counter_layout_version", "flood_counter_overflow_active"} {
		if strings.Contains(string(def), k) {
			t.Fatalf("default ProcessStatus must omit %q: %s", k, def)
		}
	}

	orig := ProcessStatus{
		FloodCounterLayoutVersion:  1,
		FloodCounterOverflowActive: true,
		ZoneFloodCounters: []ZoneFloodCounterStatus{
			// Three DISTINCT values so a mapping that crossed two families (or
			// read one field into all three) cannot pass.
			{ZoneID: 40000, SynFloodEvents: 11, ICMPFloodEvents: 22, UDPFloodEvents: 33},
		},
	}
	payload, err := json.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal populated ProcessStatus: %v", err)
	}
	if !strings.Contains(string(payload), `"zone_flood_counters"`) {
		t.Fatalf("the populated flood block must be on the wire under its "+
			"Rust-facing key: %s", payload)
	}
	var back ProcessStatus
	if err := json.Unmarshal(payload, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.FloodCounterLayoutVersion != 1 || !back.FloodCounterOverflowActive {
		t.Fatalf("layout/overflow not preserved: %+v", back)
	}
	if len(back.ZoneFloodCounters) != 1 {
		t.Fatalf("zone_flood_counters len = %d, want 1", len(back.ZoneFloodCounters))
	}
	z := back.ZoneFloodCounters[0]
	if z.ZoneID != 40000 || z.SynFloodEvents != 11 || z.ICMPFloodEvents != 22 ||
		z.UDPFloodEvents != 33 {
		t.Fatalf("flood row not preserved: %+v", z)
	}

	// Decode a Rust-style helper payload (json tags emitted by control.rs).
	const rustJSON = `{
		"pid": 1,
		"flood_counter_layout_version": 1,
		"flood_counter_overflow_active": true,
		"zone_flood_counters": [
			{"zone_id": 7, "syn_flood_events": 2, "icmp_flood_events": 3,
			 "udp_flood_events": 4}
		]
	}`
	var decoded ProcessStatus
	if err := json.Unmarshal([]byte(rustJSON), &decoded); err != nil {
		t.Fatalf("decode Rust-style payload: %v", err)
	}
	if decoded.FloodCounterLayoutVersion != 1 || !decoded.FloodCounterOverflowActive {
		t.Fatalf("Rust payload layout/overflow not decoded: %+v", decoded)
	}
	if len(decoded.ZoneFloodCounters) != 1 {
		t.Fatalf("Rust payload flood block not decoded: %+v", decoded)
	}
	r := decoded.ZoneFloodCounters[0]
	if r.ZoneID != 7 || r.SynFloodEvents != 2 || r.ICMPFloodEvents != 3 || r.UDPFloodEvents != 4 {
		t.Fatalf("Rust flood row mismatch: %+v", r)
	}

	// Cross-version safety: a pre-#3651 helper's status carries no flood keys at
	// all and must still decode, reporting "no per-zone flood data" rather than
	// failing the whole status decode.
	var old ProcessStatus
	if err := json.Unmarshal([]byte(`{"pid": 1}`), &old); err != nil {
		t.Fatalf("a status with no flood keys must still decode: %v", err)
	}
	if old.FloodCounterLayoutVersion != 0 || len(old.ZoneFloodCounters) != 0 {
		t.Fatalf("absent flood keys must decode to the empty state: %+v", old)
	}
}

// #3651: the status loop maps each wire field onto the RIGHT FloodState field.
// The wire names three flood families and dataplane.FloodState names them
// differently (SynCount/ICMPCount/UDPCount), so the mapping is a real place to
// cross two of them. Three distinct values make any crossing observable.
func TestSyncBPFCountersMapsFloodFamiliesToTheRightFloodStateFields3651(t *testing.T) {
	m := New()
	const id uint32 = 101

	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		FloodCounterLayoutVersion: 1,
		ZoneFloodCounters: []ZoneFloodCounterStatus{
			{ZoneID: id, SynFloodEvents: 11, ICMPFloodEvents: 22, UDPFloodEvents: 33},
		},
	})
	m.mu.Unlock()

	fs, err := m.bpfShim.ReadFloodCounters(id)
	if err != nil {
		t.Fatalf("ReadFloodCounters: %v", err)
	}
	want := dataplane.FloodState{SynCount: 11, ICMPCount: 22, UDPCount: 33}
	if fs != want {
		t.Fatalf("FloodState = %+v, want %+v — the legacy WindowStart/"+
			"SynproxyActive fields belonged to the deleted eBPF rate-limiter "+
			"state and must stay zero", fs, want)
	}
}
