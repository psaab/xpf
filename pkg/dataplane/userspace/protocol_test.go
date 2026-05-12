// #825 plan §3.9 test #5 / §3.8 Go mirror: round-trip pin for the
// four TX kick-latency fields added to BindingStatus and
// BindingCountersSnapshot. The JSON tag contract between Rust and
// Go is wire-critical — a rename on either side silently breaks
// the P3 capture consumer.

package userspace

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The wire JSON keys the Rust helper emits (serde rename strings
// verified in userspace-dp/src/protocol.rs). A rename on the Rust
// side without a matching Go update lands in the field as zero
// rather than erroring, so a static pin at CI time is the only
// line of defense.
var tx_kick_latency_wire_keys = []string{
	"tx_kick_latency_hist",
	"tx_kick_latency_count",
	"tx_kick_latency_sum_ns",
	"tx_kick_retry_count",
}

func TestBindingStatusTxKickLatencyRoundTrip(t *testing.T) {
	// Encode a Go BindingStatus with non-trivial values on the
	// four kick-latency fields; decode the JSON back; assert
	// field equality across the boundary.
	in := BindingStatus{
		WorkerID:           3,
		Slot:               7,
		Ifindex:            11,
		QueueID:            2,
		TxKickLatencyHist:  []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		TxKickLatencyCount: 136,
		TxKickLatencySumNs: 1_234_567,
		TxKickRetryCount:   42,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Wire-key presence: the Rust helper's consumer rejects a
	// BindingStatus that renamed one of the four keys. Pin the
	// names so a Go rename is caught here, not in the field.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range tx_kick_latency_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingStatus JSON: %s", key, string(raw))
		}
	}

	var back BindingStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingStatus: %v", err)
	}
	if !reflect.DeepEqual(back.TxKickLatencyHist, in.TxKickLatencyHist) {
		t.Fatalf("TxKickLatencyHist: got %v, want %v",
			back.TxKickLatencyHist, in.TxKickLatencyHist)
	}
	if back.TxKickLatencyCount != in.TxKickLatencyCount {
		t.Fatalf("TxKickLatencyCount: got %d, want %d",
			back.TxKickLatencyCount, in.TxKickLatencyCount)
	}
	if back.TxKickLatencySumNs != in.TxKickLatencySumNs {
		t.Fatalf("TxKickLatencySumNs: got %d, want %d",
			back.TxKickLatencySumNs, in.TxKickLatencySumNs)
	}
	if back.TxKickRetryCount != in.TxKickRetryCount {
		t.Fatalf("TxKickRetryCount: got %d, want %d",
			back.TxKickRetryCount, in.TxKickRetryCount)
	}
}

func TestBindingCountersSnapshotTxKickLatencyRoundTrip(t *testing.T) {
	in := BindingCountersSnapshot{
		WorkerID:           5,
		QueueID:            3,
		TxKickLatencyHist:  []uint64{100, 200, 300},
		TxKickLatencyCount: 600,
		TxKickLatencySumNs: 987_654,
		TxKickRetryCount:   7,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range tx_kick_latency_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingCountersSnapshot JSON: %s",
				key, string(raw))
		}
	}

	var back BindingCountersSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingCountersSnapshot: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}
}

// Pre-#825 payload — four kick-latency keys absent. omitempty on
// the Go side means empty/zero values on the producing side are
// also absent on the wire, so backward-compat is symmetric: a
// pre-#825 Rust helper decodes into empty slice / zero uint64
// without failing.
func TestBindingCountersSnapshotTxKickLatencyBackwardCompat(t *testing.T) {
	legacyJSON := []byte(`{
		"worker_id": 5,
		"ifindex": 7,
		"queue_id": 2,
		"dbg_tx_ring_full": 0,
		"dbg_sendto_enobufs": 0,
		"dbg_bound_pending_overflow": 0,
		"dbg_cos_queue_overflow": 0,
		"rx_fill_ring_empty_descs": 0,
		"outstanding_tx": 0,
		"tx_errors": 0,
		"tx_submit_error_drops": 0,
		"pending_tx_local_overflow_drops": 0
	}`)
	var back BindingCountersSnapshot
	if err := json.Unmarshal(legacyJSON, &back); err != nil {
		t.Fatalf("pre-#825 payload must decode: %v", err)
	}
	if len(back.TxKickLatencyHist) != 0 {
		t.Fatalf("pre-#825 TxKickLatencyHist must decode as empty, got %v",
			back.TxKickLatencyHist)
	}
	if back.TxKickLatencyCount != 0 {
		t.Fatalf("pre-#825 TxKickLatencyCount must be 0, got %d",
			back.TxKickLatencyCount)
	}
	if back.TxKickLatencySumNs != 0 {
		t.Fatalf("pre-#825 TxKickLatencySumNs must be 0, got %d",
			back.TxKickLatencySumNs)
	}
	if back.TxKickRetryCount != 0 {
		t.Fatalf("pre-#825 TxKickRetryCount must be 0, got %d",
			back.TxKickRetryCount)
	}
}

// #943: round-trip the V_min telemetry fields on both BindingStatus
// and the lean BindingCountersSnapshot mirror. Without this test, a
// future tag drift (e.g. someone renames `v_min_throttles` to
// `v_min_throttle_count` on one side) would silently zero the
// counter on the wire and the daemon would report no throttling.
func TestBindingStatusVMinThrottleRoundTrip(t *testing.T) {
	in := BindingStatus{
		WorkerID:                     3,
		Slot:                         7,
		Ifindex:                      11,
		QueueID:                      2,
		FlowCacheCollisionEvictions:  53,
		VMinThrottleHardCapOverrides: 59,
		VMinThrottles:                67,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range []string{"flow_cache_collision_evictions", "v_min_throttle_hard_cap_overrides", "v_min_throttles"} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingStatus JSON: %s", key, string(raw))
		}
	}

	var back BindingStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingStatus: %v", err)
	}
	if back.FlowCacheCollisionEvictions != 53 {
		t.Fatalf("FlowCacheCollisionEvictions: got %d, want 53", back.FlowCacheCollisionEvictions)
	}
	if back.VMinThrottleHardCapOverrides != 59 {
		t.Fatalf("VMinThrottleHardCapOverrides: got %d, want 59", back.VMinThrottleHardCapOverrides)
	}
	if back.VMinThrottles != 67 {
		t.Fatalf("VMinThrottles: got %d, want 67", back.VMinThrottles)
	}
}

func TestBindingCountersSnapshotVMinThrottleRoundTrip(t *testing.T) {
	in := BindingCountersSnapshot{
		WorkerID:                     3,
		Ifindex:                      11,
		QueueID:                      2,
		FlowCacheCollisionEvictions:  53,
		VMinThrottleHardCapOverrides: 59,
		VMinThrottles:                67,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range []string{"flow_cache_collision_evictions", "v_min_throttle_hard_cap_overrides", "v_min_throttles"} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingCountersSnapshot JSON: %s", key, string(raw))
		}
	}

	var back BindingCountersSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingCountersSnapshot: %v", err)
	}
	if back.FlowCacheCollisionEvictions != 53 {
		t.Fatalf("FlowCacheCollisionEvictions: got %d, want 53", back.FlowCacheCollisionEvictions)
	}
	if back.VMinThrottleHardCapOverrides != 59 {
		t.Fatalf("VMinThrottleHardCapOverrides: got %d, want 59", back.VMinThrottleHardCapOverrides)
	}
	if back.VMinThrottles != 67 {
		t.Fatalf("VMinThrottles: got %d, want 67", back.VMinThrottles)
	}
}

func TestProcessStatusFlowWorkerMapRoundTrip(t *testing.T) {
	cosQueueID := uint8(4)
	in := ProcessStatus{
		FlowWorkerMapTruncated:       true,
		CoSActiveFlowCountsTruncated: true,
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{{
			Ifindex:         80,
			QueueID:         4,
			WorkerID:        1,
			ActiveFlowCount: 7,
		}},
		FlowWorkerMap: []FlowWorkerStatus{{
			Slot:           2,
			QueueID:        1,
			WorkerID:       1,
			Interface:      "ge-0-0-1.0",
			Ifindex:        17,
			IngressIfindex: 17,
			EgressIfindex:  80,
			TxIfindex:      80,
			SessionKey: FlowTupleStatus{
				AddrFamily: 2,
				Protocol:   6,
				SrcIP:      "10.0.61.100",
				DstIP:      "172.16.80.200",
				SrcPort:    5201,
				DstPort:    49152,
			},
			ForwardWireKey: FlowTupleStatus{
				AddrFamily: 2,
				Protocol:   6,
				SrcIP:      "10.0.61.100",
				DstIP:      "172.16.80.200",
				SrcPort:    5201,
				DstPort:    49152,
			},
			ReverseCanonicalKey: FlowTupleStatus{
				AddrFamily: 2,
				Protocol:   6,
				SrcIP:      "172.16.80.200",
				DstIP:      "10.0.61.100",
				SrcPort:    49152,
				DstPort:    5201,
			},
			CoSQueueID:    &cosQueueID,
			AgeEpochs:     3,
			ObservedBytes: 123456,
		}},
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range []string{
		"flow_worker_map",
		"flow_worker_map_truncated",
		"cos_active_flow_counts",
		"cos_active_flow_counts_truncated",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from ProcessStatus JSON: %s", key, string(raw))
		}
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if !reflect.DeepEqual(back.FlowWorkerMap, in.FlowWorkerMap) {
		t.Fatalf("FlowWorkerMap mismatch: got %+v, want %+v", back.FlowWorkerMap, in.FlowWorkerMap)
	}
	if !back.FlowWorkerMapTruncated {
		t.Fatal("FlowWorkerMapTruncated must round-trip true")
	}
	if !reflect.DeepEqual(back.CoSActiveFlowCounts, in.CoSActiveFlowCounts) {
		t.Fatalf("CoSActiveFlowCounts mismatch: got %+v, want %+v", back.CoSActiveFlowCounts, in.CoSActiveFlowCounts)
	}
	if !back.CoSActiveFlowCountsTruncated {
		t.Fatal("CoSActiveFlowCountsTruncated must round-trip true")
	}
}
