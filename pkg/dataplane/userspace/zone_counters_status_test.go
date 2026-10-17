package userspace

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #3651: syncBPFCountersLocked must mirror the helper's pre-summed per-zone
// traffic block into the bpfShim zone-counter offset map so Manager.
// ReadZoneCounters reports live volume instead of ErrCounterNotPopulated.
//
// RED-on-revert: delete the ZoneTrafficCounters loop in syncBPFCountersLocked
// (the Go decode half of #3651) and the reads below revert to
// ErrCounterNotPopulated ("not available"), failing this test.
func TestSyncBPFCountersPopulatesZoneCounters(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}

	// A stable-hash zone id reads "not available" before any populate.
	if _, err := m.bpfShim.ReadZoneCounters(40000, 0); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		t.Fatalf("pre-populate ReadZoneCounters(40000,ingress) err = %v, want ErrCounterNotPopulated", err)
	}

	status := &ProcessStatus{
		ZoneCounterLayoutVersion: 1,
		ZoneTrafficCounters: []ZoneTrafficCounterStatus{
			{ZoneID: 40000, IngressPackets: 10, IngressBytes: 1500, EgressPackets: 4, EgressBytes: 600},
			{ZoneID: 7, IngressPackets: 3, IngressBytes: 180, EgressPackets: 9, EgressBytes: 540},
		},
	}
	m.syncBPFCountersLocked(status)

	// Ingress (direction 0) and egress (direction 1) both surface, no error.
	ing, err := m.bpfShim.ReadZoneCounters(40000, 0)
	if err != nil {
		t.Fatalf("ReadZoneCounters(40000,ingress) err = %v, want nil", err)
	}
	if ing.Packets != 10 || ing.Bytes != 1500 {
		t.Fatalf("zone 40000 ingress = %+v, want {Packets:10 Bytes:1500}", ing)
	}
	eg, err := m.bpfShim.ReadZoneCounters(40000, 1)
	if err != nil {
		t.Fatalf("ReadZoneCounters(40000,egress) err = %v, want nil", err)
	}
	if eg.Packets != 4 || eg.Bytes != 600 {
		t.Fatalf("zone 40000 egress = %+v, want {Packets:4 Bytes:600}", eg)
	}
	ing7, err := m.bpfShim.ReadZoneCounters(7, 0)
	if err != nil {
		t.Fatalf("ReadZoneCounters(7,ingress) err = %v, want nil", err)
	}
	if ing7.Packets != 3 || ing7.Bytes != 180 {
		t.Fatalf("zone 7 ingress = %+v, want {Packets:3 Bytes:180}", ing7)
	}

	// A zone the helper never reported still reads "not available".
	if _, err := m.bpfShim.ReadZoneCounters(999, 0); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		t.Fatalf("unreported zone ReadZoneCounters(999) err = %v, want ErrCounterNotPopulated", err)
	}

	// Absolute overwrite: a fresh status snaps to the new cumulative totals.
	m.syncBPFCountersLocked(&ProcessStatus{
		ZoneCounterLayoutVersion: 1,
		ZoneTrafficCounters: []ZoneTrafficCounterStatus{
			{ZoneID: 40000, IngressPackets: 25, IngressBytes: 4000, EgressPackets: 11, EgressBytes: 1600},
		},
	})
	ing2, err := m.bpfShim.ReadZoneCounters(40000, 0)
	if err != nil {
		t.Fatalf("post-overwrite ReadZoneCounters(40000,ingress) err = %v", err)
	}
	if ing2.Packets != 25 || ing2.Bytes != 4000 {
		t.Fatalf("zone 40000 ingress after overwrite = %+v, want {Packets:25 Bytes:4000}", ing2)
	}
}

// #3651: the ZoneTrafficCounters block survives JSON round-trip both directions
// (Go-encode -> JSON -> Go-decode, and Go-decode of a Rust-style payload). The
// Rust-side mirror is protocol/tests.rs::
// zone_traffic_counters_wire_roundtrip_and_default_omits.
func TestZoneTrafficCounterStatusWireRoundTrip(t *testing.T) {
	// A default ProcessStatus omits the layout-version / overflow keys
	// (omitempty), matching the Rust skip_serializing_if behaviour.
	def, err := json.Marshal(&ProcessStatus{})
	if err != nil {
		t.Fatalf("marshal default ProcessStatus: %v", err)
	}
	for _, k := range []string{"zone_counter_layout_version", "zone_counter_overflow_active"} {
		if strings.Contains(string(def), k) {
			t.Fatalf("default ProcessStatus must omit %q: %s", k, def)
		}
	}

	orig := ProcessStatus{
		ZoneCounterLayoutVersion:  1,
		ZoneCounterOverflowActive: true,
		ZoneTrafficCounters: []ZoneTrafficCounterStatus{
			{ZoneID: 40000, IngressPackets: 10, IngressBytes: 1500, EgressPackets: 4, EgressBytes: 600},
		},
	}
	payload, err := json.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal populated ProcessStatus: %v", err)
	}
	var back ProcessStatus
	if err := json.Unmarshal(payload, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.ZoneCounterLayoutVersion != 1 || !back.ZoneCounterOverflowActive {
		t.Fatalf("layout/overflow not preserved: %+v", back)
	}
	if len(back.ZoneTrafficCounters) != 1 {
		t.Fatalf("zone_traffic_counters len = %d, want 1", len(back.ZoneTrafficCounters))
	}
	z := back.ZoneTrafficCounters[0]
	if z.ZoneID != 40000 || z.IngressPackets != 10 || z.IngressBytes != 1500 ||
		z.EgressPackets != 4 || z.EgressBytes != 600 {
		t.Fatalf("zone row not preserved: %+v", z)
	}

	// Decode a Rust-style helper payload (json tags emitted by control.rs).
	const rustJSON = `{
		"pid": 1,
		"zone_counter_layout_version": 1,
		"zone_traffic_counters": [
			{"zone_id": 7, "ingress_packets": 2, "ingress_bytes": 200,
			 "egress_packets": 1, "egress_bytes": 100}
		]
	}`
	var decoded ProcessStatus
	if err := json.Unmarshal([]byte(rustJSON), &decoded); err != nil {
		t.Fatalf("decode Rust-style payload: %v", err)
	}
	if decoded.ZoneCounterLayoutVersion != 1 || len(decoded.ZoneTrafficCounters) != 1 {
		t.Fatalf("Rust payload not decoded: %+v", decoded)
	}
	if decoded.ZoneTrafficCounters[0].ZoneID != 7 || decoded.ZoneTrafficCounters[0].EgressBytes != 100 {
		t.Fatalf("Rust zone row mismatch: %+v", decoded.ZoneTrafficCounters[0])
	}
}

// #14619: the slotted set must decode from the Rust wire name and
// round-trip; without lockstep it silently stays empty and every
// slotted-idle zone under overflow renders as uncounted.
func TestZoneCounterSlottedZoneIDsWire_14619(t *testing.T) {
	const rustJSON = `{
		"pid": 1,
		"zone_counter_layout_version": 1,
		"zone_counter_overflow_active": true,
		"zone_counter_slotted_zone_ids": [7, 40000]
	}`
	var decoded ProcessStatus
	if err := json.Unmarshal([]byte(rustJSON), &decoded); err != nil {
		t.Fatalf("decode Rust-style payload: %v", err)
	}
	if len(decoded.ZoneCounterSlottedZoneIDs) != 2 ||
		decoded.ZoneCounterSlottedZoneIDs[0] != 7 ||
		decoded.ZoneCounterSlottedZoneIDs[1] != 40000 {
		t.Fatalf("slotted ids not decoded: %+v", decoded.ZoneCounterSlottedZoneIDs)
	}
	payload, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(payload), `"zone_counter_slotted_zone_ids":[7,40000]`) {
		t.Fatalf("slotted ids not re-encoded under the Rust name: %s", payload)
	}
	// Empty set is omitted (matching Rust Vec::is_empty).
	def, _ := json.Marshal(&ProcessStatus{})
	if strings.Contains(string(def), "zone_counter_slotted_zone_ids") {
		t.Fatalf("default must omit slotted ids: %s", def)
	}
}
