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

const testFlowCacheCapacity = 4096

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

var tx_completion_ring_wire_keys = []string{
	"tx_completion_ring_available",
	"tx_completion_ring_available_max",
}

var mirror_counter_wire_keys = []string{
	"mirrored_packets",
	"mirrored_bytes",
	"mirror_drops_no_frame",
	"mirror_drops_tx_frame_reserve",
	"mirror_drops_no_binding",
	"mirror_drops_queue_full",
	"mirror_drops_queue_full_same_worker",
	"mirror_drops_queue_full_cross_worker",
}

var syn_cookie_counter_wire_keys = []string{
	"syn_cookie_challenges",
	"syn_cookie_secret_unavailable",
	"syn_cookie_syn_ack_sent",
	"syn_cookie_ack_rst_sent",
	"syn_cookie_reply_budget_drops",
	"syn_cookie_ack_valid",
	"syn_cookie_ack_invalid",
	"syn_cookie_bypass",
}

func TestBindingStatusTXSharedRecycleUnknownSlotDropsRoundTrip(t *testing.T) {
	in := BindingStatus{
		WorkerID:                          3,
		Slot:                              7,
		Ifindex:                           11,
		QueueID:                           2,
		TXErrors:                          9,
		TXSharedRecycleUnknownSlotDrops:   4,
		TXSharedRecycleUnknownSlotRescued: 8,
		RedirectInboxOverflowDrops:        5,
		PendingTXLocalOverflowDrops:       6,
		TxSubmitErrorDrops:                7,
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
		"tx_shared_recycle_unknown_slot_drops",
		"tx_shared_recycle_unknown_slot_rescued",
		"redirect_inbox_overflow_drops",
		"pending_tx_local_overflow_drops",
		"tx_submit_error_drops",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingStatus JSON: %s", key, string(raw))
		}
	}

	var back BindingStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingStatus: %v", err)
	}
	if back.TXSharedRecycleUnknownSlotDrops != in.TXSharedRecycleUnknownSlotDrops {
		t.Fatalf("TXSharedRecycleUnknownSlotDrops: got %d, want %d",
			back.TXSharedRecycleUnknownSlotDrops, in.TXSharedRecycleUnknownSlotDrops)
	}
	if back.TXSharedRecycleUnknownSlotRescued != in.TXSharedRecycleUnknownSlotRescued {
		t.Fatalf("TXSharedRecycleUnknownSlotRescued: got %d, want %d",
			back.TXSharedRecycleUnknownSlotRescued, in.TXSharedRecycleUnknownSlotRescued)
	}
	if back.RedirectInboxOverflowDrops != in.RedirectInboxOverflowDrops {
		t.Fatalf("RedirectInboxOverflowDrops: got %d, want %d",
			back.RedirectInboxOverflowDrops, in.RedirectInboxOverflowDrops)
	}
	if back.PendingTXLocalOverflowDrops != in.PendingTXLocalOverflowDrops {
		t.Fatalf("PendingTXLocalOverflowDrops: got %d, want %d",
			back.PendingTXLocalOverflowDrops, in.PendingTXLocalOverflowDrops)
	}
	if back.TxSubmitErrorDrops != in.TxSubmitErrorDrops {
		t.Fatalf("TxSubmitErrorDrops: got %d, want %d",
			back.TxSubmitErrorDrops, in.TxSubmitErrorDrops)
	}
}

func TestBindingStatusSYNCookieCountersRoundTrip(t *testing.T) {
	in := BindingStatus{
		WorkerID:                   7,
		Slot:                       1,
		Ifindex:                    11,
		QueueID:                    2,
		SYNCookieChallenges:        3,
		SYNCookieSecretUnavailable: 5,
		SYNCookieSynAckSent:        7,
		SYNCookieAckRstSent:        11,
		SYNCookieReplyBudgetDrops:  13,
		SYNCookieAckValid:          17,
		SYNCookieAckInvalid:        19,
		SYNCookieBypass:            23,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range syn_cookie_counter_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingStatus JSON: %s", key, string(raw))
		}
	}

	var back BindingStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingStatus: %v", err)
	}
	if back.SYNCookieChallenges != in.SYNCookieChallenges {
		t.Fatalf("SYNCookieChallenges: got %d, want %d", back.SYNCookieChallenges, in.SYNCookieChallenges)
	}
	if back.SYNCookieSecretUnavailable != in.SYNCookieSecretUnavailable {
		t.Fatalf("SYNCookieSecretUnavailable: got %d, want %d",
			back.SYNCookieSecretUnavailable, in.SYNCookieSecretUnavailable)
	}
	if back.SYNCookieSynAckSent != in.SYNCookieSynAckSent {
		t.Fatalf("SYNCookieSynAckSent: got %d, want %d",
			back.SYNCookieSynAckSent, in.SYNCookieSynAckSent)
	}
	if back.SYNCookieAckRstSent != in.SYNCookieAckRstSent {
		t.Fatalf("SYNCookieAckRstSent: got %d, want %d",
			back.SYNCookieAckRstSent, in.SYNCookieAckRstSent)
	}
	if back.SYNCookieReplyBudgetDrops != in.SYNCookieReplyBudgetDrops {
		t.Fatalf("SYNCookieReplyBudgetDrops: got %d, want %d",
			back.SYNCookieReplyBudgetDrops, in.SYNCookieReplyBudgetDrops)
	}
	if back.SYNCookieAckValid != in.SYNCookieAckValid {
		t.Fatalf("SYNCookieAckValid: got %d, want %d", back.SYNCookieAckValid, in.SYNCookieAckValid)
	}
	if back.SYNCookieAckInvalid != in.SYNCookieAckInvalid {
		t.Fatalf("SYNCookieAckInvalid: got %d, want %d", back.SYNCookieAckInvalid, in.SYNCookieAckInvalid)
	}
	if back.SYNCookieBypass != in.SYNCookieBypass {
		t.Fatalf("SYNCookieBypass: got %d, want %d", back.SYNCookieBypass, in.SYNCookieBypass)
	}
}

func TestConfigSnapshotMirrorConfigsRoundTrip(t *testing.T) {
	in := ConfigSnapshot{
		Version: ProtocolVersion,
		MirrorConfigs: []MirrorConfigSnapshot{
			{IngressIfindex: 11, OutputIfindex: 22, Rate: 100},
			{IngressIfindex: 12, OutputIfindex: 22},
		},
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["mirror_configs"]; !ok {
		t.Fatalf("wire key missing from ConfigSnapshot JSON: %s", string(raw))
	}
	var mirrorObjects []map[string]json.RawMessage
	if err := json.Unmarshal(obj["mirror_configs"], &mirrorObjects); err != nil {
		t.Fatalf("unmarshal mirror_configs: %v", err)
	}
	for i, mirror := range mirrorObjects {
		for _, key := range []string{"ingress_ifindex", "output_ifindex", "rate"} {
			if _, ok := mirror[key]; !ok {
				t.Fatalf("mirror_configs[%d] missing wire key %q: %s", i, key, string(raw))
			}
		}
	}

	var back ConfigSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ConfigSnapshot: %v", err)
	}
	if !reflect.DeepEqual(back.MirrorConfigs, in.MirrorConfigs) {
		t.Fatalf("mirror config round-trip mismatch: got %+v, want %+v", back.MirrorConfigs, in.MirrorConfigs)
	}
}

func TestBindingStatusMirrorCountersRoundTrip(t *testing.T) {
	in := BindingStatus{
		WorkerID:                        3,
		Ifindex:                         11,
		QueueID:                         2,
		MirroredPackets:                 5,
		MirroredBytes:                   640,
		MirrorDropsNoFrame:              1,
		MirrorDropsTXFrameReserve:       2,
		MirrorDropsNoBinding:            3,
		MirrorDropsQueueFull:            4,
		MirrorDropsQueueFullSameWorker:  5,
		MirrorDropsQueueFullCrossWorker: 6,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range mirror_counter_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingStatus JSON: %s", key, string(raw))
		}
	}

	var back BindingStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingStatus: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("mirror counters round-trip mismatch: got %+v, want %+v", back, in)
	}
}

func TestBindingCountersSnapshotMirrorCountersRoundTrip(t *testing.T) {
	in := BindingCountersSnapshot{
		WorkerID:                        3,
		Ifindex:                         11,
		QueueID:                         2,
		MirroredPackets:                 5,
		MirroredBytes:                   640,
		MirrorDropsNoFrame:              1,
		MirrorDropsTXFrameReserve:       2,
		MirrorDropsNoBinding:            3,
		MirrorDropsQueueFull:            4,
		MirrorDropsQueueFullSameWorker:  5,
		MirrorDropsQueueFullCrossWorker: 6,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range mirror_counter_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingCountersSnapshot JSON: %s", key, string(raw))
		}
	}

	var back BindingCountersSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingCountersSnapshot: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("mirror counters round-trip mismatch: got %+v, want %+v", back, in)
	}
}

func TestCoSSchedulerSnapshotBufferSizePercentRoundTrip(t *testing.T) {
	in := CoSSchedulerSnapshot{
		Name:              "percent-sched",
		TransmitRateBytes: 1_250_000,
		BufferSizePercent: 10,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["buffer_size_percent"]; !ok {
		t.Fatalf("wire key missing from CoSSchedulerSnapshot JSON: %s", string(raw))
	}
	if _, ok := obj["buffer_size_bytes"]; ok {
		t.Fatalf("legacy byte key should be omitted for percent-only scheduler: %s", string(raw))
	}

	var back CoSSchedulerSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal CoSSchedulerSnapshot: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}
}

func TestCoSSchedulerSnapshotLegacyBufferSizePercentDefault(t *testing.T) {
	raw := []byte(`{"name":"legacy","buffer_size_bytes":65536}`)
	var back CoSSchedulerSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal legacy CoSSchedulerSnapshot: %v", err)
	}
	if got := back.BufferSizeBytes; got != 65536 {
		t.Fatalf("BufferSizeBytes = %d, want 65536", got)
	}
	if got := back.BufferSizePercent; got != 0 {
		t.Fatalf("BufferSizePercent = %v, want 0 for legacy JSON", got)
	}
}

func TestBindingCountersSnapshotTXSharedRecycleUnknownSlotDropsRoundTrip(t *testing.T) {
	in := BindingCountersSnapshot{
		WorkerID:                          3,
		Ifindex:                           11,
		QueueID:                           2,
		TXErrors:                          9,
		TXSharedRecycleUnknownSlotDrops:   4,
		TXSharedRecycleUnknownSlotRescued: 8,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["tx_shared_recycle_unknown_slot_drops"]; !ok {
		t.Fatalf("wire key missing from BindingCountersSnapshot JSON: %s", string(raw))
	}
	if _, ok := obj["tx_shared_recycle_unknown_slot_rescued"]; !ok {
		t.Fatalf("wire key missing from BindingCountersSnapshot JSON: %s", string(raw))
	}

	var back BindingCountersSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingCountersSnapshot: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}
}

func TestConfigSnapshotThreeColorPolicersRoundTrip(t *testing.T) {
	in := ConfigSnapshot{
		Version: 1,
		ThreeColorPolicers: []ThreeColorPolicerSnapshot{
			{
				Name:                   "tr",
				Mode:                   "two-rate",
				ColorBlind:             true,
				CommittedRateBytes:     125000,
				CommittedBurstBytes:    50000,
				PeakOrExcessRateBytes:  250000,
				PeakOrExcessBurstBytes: 100000,
				ThenAction:             "discard",
			},
		},
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["three_color_policers"]; !ok {
		t.Fatalf("wire key missing from ConfigSnapshot JSON: %s", string(raw))
	}
	var back ConfigSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ConfigSnapshot: %v", err)
	}
	if !reflect.DeepEqual(back.ThreeColorPolicers, in.ThreeColorPolicers) {
		t.Fatalf("ThreeColorPolicers = %+v, want %+v", back.ThreeColorPolicers, in.ThreeColorPolicers)
	}
}

func TestSourceNATRuleSnapshotPersistentNATRoundTrip(t *testing.T) {
	in := SourceNATRuleSnapshot{
		Name:                             "snat",
		FromZone:                         "lan",
		ToZone:                           "wan",
		PoolName:                         "pool1",
		PoolAddresses:                    []string{"203.0.113.10"},
		PortLow:                          40000,
		PortHigh:                         40010,
		PersistentNAT:                    true,
		PersistentNATPermitAnyRemoteHost: true,
		PersistentNATInactivityTimeout:   600,
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
		"persistent_nat",
		"persistent_nat_permit_any_remote_host",
		"persistent_nat_inactivity_timeout",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from SourceNATRuleSnapshot JSON: %s", key, string(raw))
		}
	}
	var back SourceNATRuleSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal SourceNATRuleSnapshot: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}
}

func TestProcessStatusSourceNATPoolStatusRoundTrip(t *testing.T) {
	in := ProcessStatus{
		SourceNATPools: []SourceNATPoolStatus{{
			RuleName:                         "snat",
			PoolName:                         "pool1",
			AddressCount:                     1,
			PortLow:                          40000,
			PortHigh:                         40010,
			PersistentNAT:                    true,
			PersistentNATPermitAnyRemoteHost: true,
			PersistentNATInactivityTimeout:   600,
			LiveFlows:                        2,
			UsedPorts:                        1,
			PersistentLeases:                 1,
			MaxTrackedFlows:                  11,
			AllocationsTotal:                 1,
			ReusesTotal:                      3,
			ExhaustionTotal:                  5,
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
	if _, ok := obj["source_nat_pools"]; !ok {
		t.Fatalf("source_nat_pools missing from ProcessStatus JSON: %s", string(raw))
	}
	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if !reflect.DeepEqual(back.SourceNATPools, in.SourceNATPools) {
		t.Fatalf("SourceNATPools = %+v, want %+v", back.SourceNATPools, in.SourceNATPools)
	}
}

func TestProcessStatusThreeColorPolicerCountersRoundTrip(t *testing.T) {
	in := ProcessStatus{
		ThreeColorPolicerCounters: []ThreeColorPolicerStatus{
			{
				ID:            1,
				Name:          "wan-egress",
				Mode:          "single-rate",
				ColorBlind:    true,
				GreenPackets:  10,
				GreenBytes:    1000,
				YellowPackets: 3,
				YellowBytes:   300,
				RedPackets:    2,
				RedBytes:      200,
				DropPackets:   2,
				DropBytes:     200,
			},
		},
	}

	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["three_color_policer_counters"]; !ok {
		t.Fatalf("wire key missing from ProcessStatus JSON: %s", string(raw))
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if !reflect.DeepEqual(back.ThreeColorPolicerCounters, in.ThreeColorPolicerCounters) {
		t.Fatalf("ThreeColorPolicerCounters = %+v, want %+v",
			back.ThreeColorPolicerCounters, in.ThreeColorPolicerCounters)
	}
}

func TestProcessStatusDegradedPathCountersJSON(t *testing.T) {
	in := ProcessStatus{
		DegradedPathCounters: map[string]uint64{
			"ctrl_disabled":  1,
			"pass_to_kernel": 2,
			"redirect_err":   3,
			"strict_drop":    4,
			"transit_drop":   5,
		},
	}

	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["degraded_path_counters"]; !ok {
		t.Fatalf("degraded_path_counters missing from ProcessStatus JSON: %s", string(raw))
	}
	if _, ok := obj["fallback_counters"]; !ok {
		t.Fatalf("legacy fallback_counters alias missing from ProcessStatus JSON: %s", string(raw))
	}
	var legacyAlias map[string]uint64
	if err := json.Unmarshal(obj["fallback_counters"], &legacyAlias); err != nil {
		t.Fatalf("unmarshal legacy fallback_counters alias: %v", err)
	}
	if !reflect.DeepEqual(legacyAlias, in.DegradedPathCounters) {
		t.Fatalf("fallback_counters alias = %+v, want %+v",
			legacyAlias, in.DegradedPathCounters)
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if !reflect.DeepEqual(back.DegradedPathCounters, in.DegradedPathCounters) {
		t.Fatalf("DegradedPathCounters = %+v, want %+v",
			back.DegradedPathCounters, in.DegradedPathCounters)
	}

	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{"fallback_counters":{"transit_drop":9}}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy ProcessStatus: %v", err)
	}
	if got := legacy.DegradedPathCounters["transit_drop"]; got != 9 {
		t.Fatalf("legacy fallback_counters decode transit_drop = %d, want 9", got)
	}

	var both ProcessStatus
	if err := json.Unmarshal([]byte(
		`{"degraded_path_counters":{},"fallback_counters":{"transit_drop":9}}`,
	), &both); err != nil {
		t.Fatalf("unmarshal mixed ProcessStatus: %v", err)
	}
	if got := both.DegradedPathCounters["transit_drop"]; got != 0 {
		t.Fatalf("new empty degraded_path_counters should not be overridden, got transit_drop=%d", got)
	}
}

func TestProcessStatusInjectPacketTupleVersionRoundTrip(t *testing.T) {
	in := ProcessStatus{
		InjectPacketTupleProtocolVersion: InjectPacketTupleProtocolVersion,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["inject_packet_tuple_protocol_version"]; !ok {
		t.Fatalf("wire key missing from ProcessStatus JSON: %s", string(raw))
	}
	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.InjectPacketTupleProtocolVersion != InjectPacketTupleProtocolVersion {
		t.Fatalf("InjectPacketTupleProtocolVersion = %d, want %d",
			back.InjectPacketTupleProtocolVersion, InjectPacketTupleProtocolVersion)
	}
}

func TestInjectPacketRequestTupleMetadataRoundTrip(t *testing.T) {
	sourcePort := uint16(4660)
	destinationPort := uint16(0)
	in := InjectPacketRequest{
		Slot:                 7,
		PacketLength:         128,
		AddrFamily:           2,
		Protocol:             1,
		ConfigGeneration:     11,
		FIBGeneration:        12,
		MetadataValid:        true,
		DestinationIP:        "172.16.80.200",
		EmitOnWire:           true,
		TupleMetadataVersion: InjectPacketTupleProtocolVersion,
		SourceIP:             "172.16.80.8",
		SourcePort:           &sourcePort,
		DestinationPort:      &destinationPort,
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
		"tuple_metadata_version",
		"source_ip",
		"source_port",
		"destination_port",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from InjectPacketRequest JSON: %s", key, string(raw))
		}
	}
	var back InjectPacketRequest
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal InjectPacketRequest: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}
}

func TestCoSQueueStatusDrainPhaseCountersRoundTrip(t *testing.T) {
	in := CoSQueueStatus{
		QueueID:                 0,
		DrainSentBytes:          4096,
		DrainGuaranteeSentBytes: 1024,
		DrainSurplusSentBytes:   3072,
		DrainNonExactSentBytesWhileExactBacklogged: 2048,
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
		"drain_guarantee_sent_bytes",
		"drain_surplus_sent_bytes",
		"drain_nonexact_sent_bytes_while_exact_backlogged",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from CoSQueueStatus JSON: %s", key, string(raw))
		}
	}

	var back CoSQueueStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal CoSQueueStatus: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}
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

func TestBindingStatusTXCompletionRingRoundTrip(t *testing.T) {
	in := BindingStatus{
		WorkerID:                     3,
		Slot:                         7,
		Ifindex:                      11,
		QueueID:                      2,
		TXCompletionRingAvailable:    17,
		TXCompletionRingAvailableMax: 29,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range tx_completion_ring_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingStatus JSON: %s", key, string(raw))
		}
	}

	var back BindingStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingStatus: %v", err)
	}
	if back.TXCompletionRingAvailable != 17 {
		t.Fatalf("TXCompletionRingAvailable: got %d, want 17", back.TXCompletionRingAvailable)
	}
	if back.TXCompletionRingAvailableMax != 29 {
		t.Fatalf("TXCompletionRingAvailableMax: got %d, want 29", back.TXCompletionRingAvailableMax)
	}
}

func TestBindingCountersSnapshotTXCompletionRingRoundTrip(t *testing.T) {
	in := BindingCountersSnapshot{
		WorkerID:                     3,
		Ifindex:                      11,
		QueueID:                      2,
		TXCompletionRingAvailable:    31,
		TXCompletionRingAvailableMax: 47,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range tx_completion_ring_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingCountersSnapshot JSON: %s", key, string(raw))
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

func TestBindingFlowCacheCapacityRoundTrip(t *testing.T) {
	in := BindingStatus{
		WorkerID:          3,
		Slot:              7,
		Ifindex:           11,
		QueueID:           2,
		ActiveFlowCount:   53,
		FlowCacheCapacity: testFlowCacheCapacity,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["flow_cache_capacity"]; !ok {
		t.Fatalf("flow_cache_capacity missing from BindingStatus JSON: %s", string(raw))
	}

	var back BindingStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingStatus: %v", err)
	}
	if back.FlowCacheCapacity != in.FlowCacheCapacity {
		t.Fatalf("FlowCacheCapacity: got %d, want %d", back.FlowCacheCapacity, in.FlowCacheCapacity)
	}

	snap := BindingCountersSnapshot{
		WorkerID:          3,
		Ifindex:           11,
		QueueID:           2,
		ActiveFlowCount:   53,
		FlowCacheCapacity: testFlowCacheCapacity,
	}
	raw, err = json.Marshal(&snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal snapshot obj: %v", err)
	}
	if _, ok := obj["flow_cache_capacity"]; !ok {
		t.Fatalf("flow_cache_capacity missing from BindingCountersSnapshot JSON: %s", string(raw))
	}
	var snapBack BindingCountersSnapshot
	if err := json.Unmarshal(raw, &snapBack); err != nil {
		t.Fatalf("unmarshal BindingCountersSnapshot: %v", err)
	}
	if !reflect.DeepEqual(snapBack, snap) {
		t.Fatalf("snapshot round-trip mismatch: got %+v, want %+v", snapBack, snap)
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

func TestProcessStatusBufferCapacityRoundTrip(t *testing.T) {
	in := ProcessStatus{
		SessionTableEntries:   77,
		MaxSessions:           100,
		FlowCacheCapacity:     4096,
		NeighborEntries:       9,
		NeighborCacheCapacity: 64,
		WorkerRuntime: []WorkerRuntimeStatus{{
			WorkerID:            2,
			SessionTableEntries: 77,
			MaxSessions:         100,
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
		"session_table_entries",
		"max_sessions",
		"flow_cache_capacity",
		"neighbor_cache_capacity",
		"worker_runtime",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from ProcessStatus JSON: %s", key, string(raw))
		}
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}
}

func TestProcessStatusPolicyRuleCountersRoundTrip(t *testing.T) {
	in := ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{{
			RuleID:  "lan->wan/allow-web",
			Packets: 12,
			Bytes:   1536,
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
	if _, ok := obj["policy_rule_counters"]; !ok {
		t.Fatalf("policy_rule_counters missing from ProcessStatus JSON: %s", string(raw))
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if !reflect.DeepEqual(back.PolicyRuleCounters, in.PolicyRuleCounters) {
		t.Fatalf("PolicyRuleCounters mismatch: got %+v, want %+v", back.PolicyRuleCounters, in.PolicyRuleCounters)
	}
}

// #1642: the Rust helper serialized several status fields the Go side had
// no matching json: tag for, so json.Unmarshal silently dropped them and
// the operator-facing telemetry stayed zero. These tests decode the exact
// wire JSON the Rust structs emit (serde rename strings verified against
// userspace-dp/src/protocol/{binding,cos,control}.rs at the same revision)
// and assert the Go side now observes every field. A Rust rename without a
// matching Go update will land in the field as zero rather than erroring,
// so feeding the Rust-shaped JSON literal is the real regression gate — a
// pure Go marshal round-trip would not have caught the dropped fields,
// since the Go struct lacked them entirely.

func TestHAGroupStatusLeaseFieldsParity1642(t *testing.T) {
	// Wire JSON exactly as Rust HAGroupStatus (protocol/binding.rs) emits.
	const rustJSON = `{
		"rg_id": 1,
		"active": true,
		"watchdog_timestamp": 1234567890,
		"forwarding_active": true,
		"lease_state": "owner",
		"lease_until": 9876543210
	}`
	var got HAGroupStatus
	if err := json.Unmarshal([]byte(rustJSON), &got); err != nil {
		t.Fatalf("unmarshal Rust HAGroupStatus JSON: %v", err)
	}
	if !got.ForwardingActive {
		t.Errorf("forwarding_active dropped: got false")
	}
	if got.LeaseState != "owner" {
		t.Errorf("lease_state dropped: got %q, want %q", got.LeaseState, "owner")
	}
	if got.LeaseUntil != 9876543210 {
		t.Errorf("lease_until dropped: got %d, want %d", got.LeaseUntil, uint64(9876543210))
	}

	// Wire-key presence on the Go marshal side (the contract is symmetric).
	raw, err := json.Marshal(&HAGroupStatus{ForwardingActive: true, LeaseState: "owner", LeaseUntil: 1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range []string{"forwarding_active", "lease_state", "lease_until"} {
		if _, ok := obj[key]; !ok {
			t.Errorf("wire key %q missing from HAGroupStatus JSON: %s", key, string(raw))
		}
	}
}

func TestCoSQueueStatusStarvationCountersParity1642(t *testing.T) {
	// Wire JSON exactly as Rust CoSQueueStatus (protocol/cos.rs) emits for
	// the shaper-starvation / ring-pressure diagnostics.
	const rustJSON = `{
		"queue_id": 3,
		"root_token_starvation_parks": 11,
		"queue_token_starvation_parks": 22,
		"tx_ring_full_submit_stalls": 33
	}`
	var got CoSQueueStatus
	if err := json.Unmarshal([]byte(rustJSON), &got); err != nil {
		t.Fatalf("unmarshal Rust CoSQueueStatus JSON: %v", err)
	}
	if got.RootTokenStarvationParks != 11 {
		t.Errorf("root_token_starvation_parks dropped: got %d, want 11", got.RootTokenStarvationParks)
	}
	if got.QueueTokenStarvationParks != 22 {
		t.Errorf("queue_token_starvation_parks dropped: got %d, want 22", got.QueueTokenStarvationParks)
	}
	if got.TxRingFullSubmitStalls != 33 {
		t.Errorf("tx_ring_full_submit_stalls dropped: got %d, want 33", got.TxRingFullSubmitStalls)
	}

	raw, _ := json.Marshal(&CoSQueueStatus{
		RootTokenStarvationParks:  1,
		QueueTokenStarvationParks: 1,
		TxRingFullSubmitStalls:    1,
	})
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range []string{
		"root_token_starvation_parks",
		"queue_token_starvation_parks",
		"tx_ring_full_submit_stalls",
	} {
		if _, ok := obj[key]; !ok {
			t.Errorf("wire key %q missing from CoSQueueStatus JSON: %s", key, string(raw))
		}
	}
}

func TestCoSWaterfillCountersParity1628(t *testing.T) {
	// Decode wire JSON exactly as Rust CoSQueueStatus / CoSInterfaceStatus
	// (protocol/cos.rs) emit the #1628 waterfill trace counters; assert the
	// Go mirror reads each field (JSON tags match byte-for-byte).
	const rustQueueJSON = `{
		"queue_id": 5,
		"waterfill_phase1_admissions": 12,
		"waterfill_phase2_admissions": 34,
		"waterfill_eligible_visits": 56
	}`
	var gotQueue CoSQueueStatus
	if err := json.Unmarshal([]byte(rustQueueJSON), &gotQueue); err != nil {
		t.Fatalf("unmarshal Rust CoSQueueStatus JSON: %v", err)
	}
	if gotQueue.WaterfillPhase1Admissions != 12 {
		t.Errorf("waterfill_phase1_admissions dropped: got %d, want 12", gotQueue.WaterfillPhase1Admissions)
	}
	if gotQueue.WaterfillPhase2Admissions != 34 {
		t.Errorf("waterfill_phase2_admissions dropped: got %d, want 34", gotQueue.WaterfillPhase2Admissions)
	}
	if gotQueue.WaterfillEligibleVisits != 56 {
		t.Errorf("waterfill_eligible_visits dropped: got %d, want 56", gotQueue.WaterfillEligibleVisits)
	}

	const rustIfaceJSON = `{
		"ifindex": 80,
		"waterfill_epochs": 1000,
		"waterfill_phase1_budget_breaks": 7,
		"waterfill_min_epochs_per_worker": 3
	}`
	var gotIface CoSInterfaceStatus
	if err := json.Unmarshal([]byte(rustIfaceJSON), &gotIface); err != nil {
		t.Fatalf("unmarshal Rust CoSInterfaceStatus JSON: %v", err)
	}
	if gotIface.WaterfillEpochs != 1000 {
		t.Errorf("waterfill_epochs dropped: got %d, want 1000", gotIface.WaterfillEpochs)
	}
	if gotIface.WaterfillPhase1BudgetBreaks != 7 {
		t.Errorf("waterfill_phase1_budget_breaks dropped: got %d, want 7", gotIface.WaterfillPhase1BudgetBreaks)
	}
	if gotIface.WaterfillMinEpochsPerWorker != 3 {
		t.Errorf("waterfill_min_epochs_per_worker dropped: got %d, want 3", gotIface.WaterfillMinEpochsPerWorker)
	}

	// Forward direction: Go-marshaled JSON must carry the exact wire keys
	// (so a Rust deserializer with #[serde(rename)] reads them).
	rawQ, _ := json.Marshal(&CoSQueueStatus{
		WaterfillPhase1Admissions: 1,
		WaterfillPhase2Admissions: 1,
		WaterfillEligibleVisits:   1,
	})
	rawI, _ := json.Marshal(&CoSInterfaceStatus{
		WaterfillEpochs:             1,
		WaterfillPhase1BudgetBreaks: 1,
		WaterfillMinEpochsPerWorker: 1,
	})
	for raw, keys := range map[string][]string{
		string(rawQ): {"waterfill_phase1_admissions", "waterfill_phase2_admissions", "waterfill_eligible_visits"},
		string(rawI): {"waterfill_epochs", "waterfill_phase1_budget_breaks", "waterfill_min_epochs_per_worker"},
	} {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			t.Fatalf("unmarshal obj: %v", err)
		}
		for _, key := range keys {
			if _, ok := obj[key]; !ok {
				t.Errorf("wire key %q missing from JSON: %s", key, raw)
			}
		}
	}
}

func TestBindingStatusPostDrainBackupCosDropsParity1642(t *testing.T) {
	// Rust serializes post_drain_backup_cos_drops / _cos_drop_bytes on
	// BindingStatus (protocol/binding.rs), NOT on CoSQueueStatus. Feed
	// binding-level wire JSON and assert the Go BindingStatus now reads it.
	const rustJSON = `{
		"slot": 4,
		"queue_id": 0,
		"worker_id": 2,
		"registered": true,
		"armed": true,
		"ready": true,
		"bound": true,
		"xsk_registered": true,
		"post_drain_backup_cos_drops": 7,
		"post_drain_backup_cos_drop_bytes": 4096
	}`
	var got BindingStatus
	if err := json.Unmarshal([]byte(rustJSON), &got); err != nil {
		t.Fatalf("unmarshal Rust BindingStatus JSON: %v", err)
	}
	if got.PostDrainBackupCosDrops != 7 {
		t.Errorf("post_drain_backup_cos_drops dropped: got %d, want 7", got.PostDrainBackupCosDrops)
	}
	if got.PostDrainBackupCosDropBytes != 4096 {
		t.Errorf("post_drain_backup_cos_drop_bytes dropped: got %d, want 4096", got.PostDrainBackupCosDropBytes)
	}

	// Guard against re-introducing the wrong-level bug: CoSQueueStatus must
	// NOT declare these keys (post_drain_backup_bytes is the only legitimate
	// post_drain key on CoSQueueStatus).
	cosRaw, _ := json.Marshal(&CoSQueueStatus{PostDrainBackupBytes: 1})
	var cosObj map[string]json.RawMessage
	if err := json.Unmarshal(cosRaw, &cosObj); err != nil {
		t.Fatalf("unmarshal cos obj: %v", err)
	}
	for _, key := range []string{"post_drain_backup_cos_drops", "post_drain_backup_cos_drop_bytes"} {
		if _, ok := cosObj[key]; ok {
			t.Errorf("CoSQueueStatus must not carry binding-scoped key %q: %s", key, string(cosRaw))
		}
	}
	if _, ok := cosObj["post_drain_backup_bytes"]; !ok {
		t.Errorf("post_drain_backup_bytes must remain on CoSQueueStatus: %s", string(cosRaw))
	}
}

func TestProcessStatusEventStreamFieldsParity1642(t *testing.T) {
	// Rust ProcessStatus (protocol/control.rs) emits flat event_stream_*
	// fields. _sent / _dropped already matched; connected / seq / acked
	// were dropped on the Go side.
	const rustJSON = `{
		"event_stream_connected": true,
		"event_stream_seq": 4242,
		"event_stream_acked": 4200,
		"event_stream_sent": 5000,
		"event_stream_dropped": 3,
		"event_stream_write_stalls": 17,
		"event_stream_replay_evictions": 9,
		"event_stream_invalid_acks": 11
	}`
	var got ProcessStatus
	if err := json.Unmarshal([]byte(rustJSON), &got); err != nil {
		t.Fatalf("unmarshal Rust ProcessStatus JSON: %v", err)
	}
	if !got.EventStreamConnected {
		t.Errorf("event_stream_connected dropped: got false")
	}
	if got.EventStreamSeq != 4242 {
		t.Errorf("event_stream_seq dropped: got %d, want 4242", got.EventStreamSeq)
	}
	if got.EventStreamAcked != 4200 {
		t.Errorf("event_stream_acked dropped: got %d, want 4200", got.EventStreamAcked)
	}
	// Sanity: the previously-matching fields still decode.
	if got.EventStreamSent != 5000 || got.EventStreamDropped != 3 {
		t.Errorf("event_stream_sent/dropped regressed: sent=%d dropped=%d", got.EventStreamSent, got.EventStreamDropped)
	}
	// #2381: the stalled-consumer backlog counter must decode under its exact
	// wire key so a wedged daemon reader is observable in status/metrics.
	if got.EventStreamWriteStalls != 17 {
		t.Errorf("event_stream_write_stalls dropped: got %d, want 17", got.EventStreamWriteStalls)
	}
	// #2382: the replay-buffer eviction telemetry-loss counter must decode
	// under its exact wire key so a daemon that let the replay window wrap
	// (dropping accepted RT_FLOW frames) is observable in status/metrics.
	if got.EventStreamReplayEvictions != 9 {
		t.Errorf("event_stream_replay_evictions dropped: got %d, want 9", got.EventStreamReplayEvictions)
	}
	// #2959: the invalid-ACK counter must decode under its exact wire key so a
	// daemon-side listener emitting impossible ACK watermarks (rejected by the
	// helper's fail-closed validation) is observable in status/metrics.
	if got.EventStreamInvalidAcks != 11 {
		t.Errorf("event_stream_invalid_acks dropped: got %d, want 11", got.EventStreamInvalidAcks)
	}
	// #2382: a legacy helper that omits the key must decode to 0, not error
	// (omitempty + Go zero-value default).
	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{"event_stream_sent": 1}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy ProcessStatus (no replay key): %v", err)
	}
	if legacy.EventStreamReplayEvictions != 0 {
		t.Errorf("missing event_stream_replay_evictions must default to 0, got %d", legacy.EventStreamReplayEvictions)
	}
	// #2959: a legacy helper that omits the invalid-acks key must decode to 0,
	// not error (omitempty + Go zero-value default).
	if legacy.EventStreamInvalidAcks != 0 {
		t.Errorf("missing event_stream_invalid_acks must default to 0, got %d", legacy.EventStreamInvalidAcks)
	}

	raw, _ := json.Marshal(&ProcessStatus{EventStreamConnected: true, EventStreamSeq: 1, EventStreamAcked: 1})
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range []string{"event_stream_connected", "event_stream_seq", "event_stream_acked"} {
		if _, ok := obj[key]; !ok {
			t.Errorf("wire key %q missing from ProcessStatus JSON: %s", key, string(raw))
		}
	}
}

// #1807: wire pin for the worker-command-queue poison-recovery counter.
// The Rust helper serializes ProcessStatus.worker_command_queue_poison_recoveries
// (serde rename in userspace-dp/src/protocol/control.rs); a key rename on
// either side silently decodes as zero, so pin the tag here and verify
// the pre-#1807 (key absent) payload defaults to zero.
func TestProcessStatusWorkerCommandQueuePoisonRecoveriesRoundTrip(t *testing.T) {
	in := ProcessStatus{
		WorkerCommandQueuePoisonRecoveries: 3,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["worker_command_queue_poison_recoveries"]; !ok {
		t.Fatalf("wire key %q missing from ProcessStatus JSON: %s",
			"worker_command_queue_poison_recoveries", string(raw))
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.WorkerCommandQueuePoisonRecoveries != in.WorkerCommandQueuePoisonRecoveries {
		t.Fatalf("WorkerCommandQueuePoisonRecoveries: got %d, want %d",
			back.WorkerCommandQueuePoisonRecoveries, in.WorkerCommandQueuePoisonRecoveries)
	}

	// Pre-#1807 helper payload (key absent) must decode to zero.
	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy ProcessStatus: %v", err)
	}
	if legacy.WorkerCommandQueuePoisonRecoveries != 0 {
		t.Fatalf("legacy WorkerCommandQueuePoisonRecoveries: got %d, want 0",
			legacy.WorkerCommandQueuePoisonRecoveries)
	}
}

// #1771 §2.6: wire pin for the resolver backoff-retry counter, the §2.5
// ENOBUFS/re-dump counters, and the pending-keys / negative-keys gauges.
// The Rust helper serializes these via serde renames in
// userspace-dp/src/protocol/control.rs; a key rename on either side
// silently decodes as zero, so pin every tag here and verify the
// pre-Phase-3 (keys absent) payload defaults to zero.
// #2402/#6641: wire pin for the shared-session poison-recovery counter.
// A key rename on either side decodes silently as zero -- and for THIS
// counter zero reads as "no worker panic ever touched HA session state",
// which is exactly the reassuring value the missing-metric defect already
// produced. Pin the tag and the absent-key default on both sides.
func TestProcessStatusSharedSessionPoisonRecoveriesRoundTrip(t *testing.T) {
	in := ProcessStatus{
		SharedSessionPoisonRecoveries: 7,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	if _, ok := obj["shared_session_poison_recoveries"]; !ok {
		t.Fatalf("wire key %q missing from ProcessStatus JSON: %s",
			"shared_session_poison_recoveries", string(raw))
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.SharedSessionPoisonRecoveries != in.SharedSessionPoisonRecoveries {
		t.Fatalf("SharedSessionPoisonRecoveries: got %d, want %d",
			back.SharedSessionPoisonRecoveries, in.SharedSessionPoisonRecoveries)
	}

	// Pre-#6641 helper payload (key absent) must decode to zero.
	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy ProcessStatus: %v", err)
	}
	if legacy.SharedSessionPoisonRecoveries != 0 {
		t.Fatalf("legacy SharedSessionPoisonRecoveries: got %d, want 0",
			legacy.SharedSessionPoisonRecoveries)
	}
}

func TestProcessStatusNeighborPhase3CountersRoundTrip(t *testing.T) {
	in := ProcessStatus{
		NeighborResolverGetBackoffAttemptsTotal: 7,
		NeighborNetlinkEnobufsTotal:             3,
		NeighborNetlinkRedumpsTotal:             2,
		NeighborNetlinkRedumpUpsertsTotal:       11,
		NeighborPendingKeys:                     4,
		NegNeighKeys:                            5,
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
		"neighbor_resolver_get_backoff_attempts_total",
		"neighbor_netlink_enobufs_total",
		"neighbor_netlink_redumps_total",
		"neighbor_netlink_redump_upserts_total",
		"neighbor_pending_keys",
		"neg_neigh_keys",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from ProcessStatus JSON: %s", key, string(raw))
		}
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.NeighborResolverGetBackoffAttemptsTotal != in.NeighborResolverGetBackoffAttemptsTotal ||
		back.NeighborNetlinkEnobufsTotal != in.NeighborNetlinkEnobufsTotal ||
		back.NeighborNetlinkRedumpsTotal != in.NeighborNetlinkRedumpsTotal ||
		back.NeighborNetlinkRedumpUpsertsTotal != in.NeighborNetlinkRedumpUpsertsTotal ||
		back.NeighborPendingKeys != in.NeighborPendingKeys ||
		back.NegNeighKeys != in.NegNeighKeys {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}

	// Pre-Phase-3 helper payload (keys absent) must decode to zero.
	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy ProcessStatus: %v", err)
	}
	if legacy.NeighborResolverGetBackoffAttemptsTotal != 0 ||
		legacy.NeighborNetlinkEnobufsTotal != 0 ||
		legacy.NeighborNetlinkRedumpsTotal != 0 ||
		legacy.NeighborNetlinkRedumpUpsertsTotal != 0 ||
		legacy.NeighborPendingKeys != 0 ||
		legacy.NegNeighKeys != 0 {
		t.Fatalf("legacy decode must zero-default Phase-3 fields: %+v", legacy)
	}
}

// #3773 (M13): wire pin for the fabric-link skip diagnostic counters. The Rust
// helper serializes these via serde renames in
// userspace-dp/src/protocol/control.rs; a key rename on either side silently
// decodes as zero, so pin both tags here and verify the pre-#3773 (keys
// absent) payload defaults to zero.
func TestProcessStatusFabricSkipCountersRoundTrip(t *testing.T) {
	in := ProcessStatus{
		FabricLinkSkippedMalformedTotal: 4,
		FabricLinkUnresolvedPeerTotal:   9,
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
		"fabric_link_skipped_malformed_total",
		"fabric_link_unresolved_peer_total",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from ProcessStatus JSON: %s", key, string(raw))
		}
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.FabricLinkSkippedMalformedTotal != in.FabricLinkSkippedMalformedTotal ||
		back.FabricLinkUnresolvedPeerTotal != in.FabricLinkUnresolvedPeerTotal {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}

	// Pre-#3773 helper payload (keys absent) must decode to zero.
	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy ProcessStatus: %v", err)
	}
	if legacy.FabricLinkSkippedMalformedTotal != 0 || legacy.FabricLinkUnresolvedPeerTotal != 0 {
		t.Fatalf("legacy decode must zero-default fabric-skip fields: %+v", legacy)
	}
}

// #2375: wire pin for the pending_neigh distinct-hop capacity-drop
// counter. Mirrors the Rust
// process_status_pending_neigh_capacity_drops_roundtrip test — a rename
// or a one-sided add fails a test instead of silently decoding zero
// (#1961 one-sided-field risk). The duplicate counter must stay a
// SEPARATE wire key (the #1782/#2375 split).
func TestProcessStatusPendingNeighCapacityDropsRoundTrip(t *testing.T) {
	in := ProcessStatus{
		PendingNeighCapacityDropsTotal:  9,
		PendingNeighDuplicateDropsTotal: 4,
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
		"pending_neigh_capacity_drops_total",
		"pending_neigh_duplicate_drops_total",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from ProcessStatus JSON: %s", key, string(raw))
		}
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.PendingNeighCapacityDropsTotal != in.PendingNeighCapacityDropsTotal {
		t.Fatalf("capacity round-trip mismatch: got %d, want %d",
			back.PendingNeighCapacityDropsTotal, in.PendingNeighCapacityDropsTotal)
	}
	if back.PendingNeighDuplicateDropsTotal != in.PendingNeighDuplicateDropsTotal {
		t.Fatalf("duplicate round-trip mismatch: got %d, want %d",
			back.PendingNeighDuplicateDropsTotal, in.PendingNeighDuplicateDropsTotal)
	}

	// Pre-#2375 helper payload (key absent) must decode to zero.
	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{"pending_neigh_duplicate_drops_total":7}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy ProcessStatus: %v", err)
	}
	if legacy.PendingNeighCapacityDropsTotal != 0 {
		t.Fatalf("legacy decode must zero-default capacity field: %d",
			legacy.PendingNeighCapacityDropsTotal)
	}
	if legacy.PendingNeighDuplicateDropsTotal != 7 {
		t.Fatalf("legacy duplicate field decode = %d, want 7",
			legacy.PendingNeighDuplicateDropsTotal)
	}
}

// #1829 Phase 1: wire pin for the sojourn telemetry trio on
// CoSQueueStatus. Mirrors the Rust cos_queue_status_sojourn_roundtrip_1829
// test — a rename on either side fails a test instead of silently
// decoding zero. SojournWindowedMinNS is the #1829 Phase-2 gate metric.
func TestCoSQueueStatusSojournRoundTrip(t *testing.T) {
	in := CoSQueueStatus{
		SojournEwmaNS:        2500000,
		SojournPeakNS:        9000000,
		SojournWindowedMinNS: 1750000,
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
		"sojourn_ewma_ns",
		"sojourn_peak_ns",
		"sojourn_windowed_min_ns",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from CoSQueueStatus JSON: %s", key, string(raw))
		}
	}

	var back CoSQueueStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal CoSQueueStatus: %v", err)
	}
	if back.SojournEwmaNS != 2500000 || back.SojournPeakNS != 9000000 || back.SojournWindowedMinNS != 1750000 {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}

	// Pre-#1829 helper payload (keys absent) must decode to zero.
	var legacy CoSQueueStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy CoSQueueStatus: %v", err)
	}
	if legacy.SojournEwmaNS != 0 || legacy.SojournPeakNS != 0 || legacy.SojournWindowedMinNS != 0 {
		t.Fatalf("legacy decode must zero-default #1829 fields: %+v", legacy)
	}
}

// #1830 (g): wire pin for the bucket-vs-flow occupancy fields on
// CoSQueueStatus. Mirrors the Rust
// cos_queue_status_flow_fair_occupancy_roundtrip_1830 test — a rename
// on either side fails a test instead of silently decoding zero.
func TestCoSQueueStatusFlowFairOccupancyRoundTrip(t *testing.T) {
	in := CoSQueueStatus{
		FlowFairBucketsOccupied: 9,
		FlowFairFlowsActive:     12,
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
		"flow_fair_buckets_occupied",
		"flow_fair_flows_active",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from CoSQueueStatus JSON: %s", key, string(raw))
		}
	}

	var back CoSQueueStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal CoSQueueStatus: %v", err)
	}
	if back.FlowFairBucketsOccupied != 9 || back.FlowFairFlowsActive != 12 {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}

	// Pre-#1830 helper payload (keys absent) must decode to zero.
	var legacy CoSQueueStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy CoSQueueStatus: %v", err)
	}
	if legacy.FlowFairBucketsOccupied != 0 || legacy.FlowFairFlowsActive != 0 {
		t.Fatalf("legacy decode must zero-default #1830 fields: %+v", legacy)
	}
}

// TestCoSQueueStatusLeaseClaimFlowWire pins the #1863 Step-0 per-worker
// v8 lease claim-flow wire contract on the Go side: tag byte-equality
// with the Rust serde renames in protocol/cos.rs, slice round-trip,
// and omitempty for legacy/non-v8 rows (empty slices encode to absent
// keys — byte-identical pre-#1863 wire).
func TestCoSQueueStatusLeaseClaimFlowWire(t *testing.T) {
	in := CoSQueueStatus{
		QueueID:                     4,
		LeaseV8WorkerRequestedBytes: []uint64{100, 0, 250},
		LeaseV8WorkerGrantedBytes:   []uint64{90, 0, 200},
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
		"lease_v8_worker_requested_bytes",
		"lease_v8_worker_granted_bytes",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from CoSQueueStatus JSON: %s", key, string(raw))
		}
	}
	var back CoSQueueStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal CoSQueueStatus: %v", err)
	}
	if len(back.LeaseV8WorkerRequestedBytes) != 3 || back.LeaseV8WorkerRequestedBytes[2] != 250 {
		t.Fatalf("LeaseV8WorkerRequestedBytes round-trip: got %v", back.LeaseV8WorkerRequestedBytes)
	}
	if len(back.LeaseV8WorkerGrantedBytes) != 3 || back.LeaseV8WorkerGrantedBytes[0] != 90 {
		t.Fatalf("LeaseV8WorkerGrantedBytes round-trip: got %v", back.LeaseV8WorkerGrantedBytes)
	}

	// Legacy row: empty slices must be omitted entirely.
	legacyRaw, err := json.Marshal(&CoSQueueStatus{QueueID: 4})
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	var legacyObj map[string]json.RawMessage
	if err := json.Unmarshal(legacyRaw, &legacyObj); err != nil {
		t.Fatalf("unmarshal legacy obj: %v", err)
	}
	for _, key := range []string{
		"lease_v8_worker_requested_bytes",
		"lease_v8_worker_granted_bytes",
	} {
		if _, ok := legacyObj[key]; ok {
			t.Fatalf("wire key %q must be omitted for legacy rows: %s", key, string(legacyRaw))
		}
	}
}

// #1861: wire pin for the install-refusal trio (transactional session
// install). The Rust helper serializes ProcessStatus.session_create_drops /
// session_install_admission_refused / session_install_partial plus the
// per-worker WorkerRuntimeStatus copies (serde renames in
// userspace-dp/src/protocol/control.rs and protocol/binding.rs); a key
// rename on either side silently decodes as zero, so pin the tags here
// and verify the pre-#1861 (key absent) payloads default to zero.
func TestProcessStatusInstallRefusalTrioRoundTrip(t *testing.T) {
	in := ProcessStatus{
		SessionCreateDrops:             7,
		SessionInstallAdmissionRefused: 5,
		SessionInstallPartial:          1,
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
		"session_create_drops",
		"session_install_admission_refused",
		"session_install_partial",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from ProcessStatus JSON: %s", key, string(raw))
		}
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.SessionCreateDrops != in.SessionCreateDrops ||
		back.SessionInstallAdmissionRefused != in.SessionInstallAdmissionRefused ||
		back.SessionInstallPartial != in.SessionInstallPartial {
		t.Fatalf("round trip mismatch: got (%d,%d,%d), want (%d,%d,%d)",
			back.SessionCreateDrops, back.SessionInstallAdmissionRefused,
			back.SessionInstallPartial, in.SessionCreateDrops,
			in.SessionInstallAdmissionRefused, in.SessionInstallPartial)
	}

	// Pre-#1861 helper payload (keys absent) must decode to zero.
	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy ProcessStatus: %v", err)
	}
	if legacy.SessionCreateDrops != 0 ||
		legacy.SessionInstallAdmissionRefused != 0 ||
		legacy.SessionInstallPartial != 0 {
		t.Fatalf("legacy trio: got (%d,%d,%d), want zeros",
			legacy.SessionCreateDrops, legacy.SessionInstallAdmissionRefused,
			legacy.SessionInstallPartial)
	}
}

// #1861: same pin for the per-worker WorkerRuntimeStatus copies.
func TestWorkerRuntimeStatusInstallRefusalTrioRoundTrip(t *testing.T) {
	in := WorkerRuntimeStatus{
		SessionCreateDrops:             3,
		SessionInstallAdmissionRefused: 2,
		SessionInstallPartial:          1,
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
		"session_create_drops",
		"session_install_admission_refused",
		"session_install_partial",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from WorkerRuntimeStatus JSON: %s", key, string(raw))
		}
	}
	var back WorkerRuntimeStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal WorkerRuntimeStatus: %v", err)
	}
	if back.SessionCreateDrops != 3 || back.SessionInstallAdmissionRefused != 2 ||
		back.SessionInstallPartial != 1 {
		t.Fatalf("round trip mismatch: got (%d,%d,%d)",
			back.SessionCreateDrops, back.SessionInstallAdmissionRefused,
			back.SessionInstallPartial)
	}
	var legacy WorkerRuntimeStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy WorkerRuntimeStatus: %v", err)
	}
	if legacy.SessionCreateDrops != 0 || legacy.SessionInstallAdmissionRefused != 0 ||
		legacy.SessionInstallPartial != 0 {
		t.Fatalf("legacy WorkerRuntimeStatus trio nonzero")
	}
}

// TestProcessStatusUnsurfacedCounterTrioRoundTrip7398 covers the three
// counters #7398 wired out of the status-wiring allowlist. Each is asserted
// with a DISTINCT value, so a field wired to the wrong wire key cannot pass by
// reading its neighbour — the three sit adjacent in the struct and carry
// near-identical names, which is exactly the shape that makes a copy-paste
// error survive a "the key is present" check.
func TestProcessStatusUnsurfacedCounterTrioRoundTrip7398(t *testing.T) {
	in := ProcessStatus{
		SessionInstallStaleIgnored: 31,
		SessionDeleteStaleIgnored:  32,
		SyncedImportReserveRefused: 33,
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
		"session_install_stale_ignored",
		"session_delete_stale_ignored",
		"synced_import_reserve_refused",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from ProcessStatus JSON: %s", key, string(raw))
		}
	}

	var back ProcessStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal ProcessStatus: %v", err)
	}
	if back.SessionInstallStaleIgnored != 31 {
		t.Errorf("SessionInstallStaleIgnored: got %d, want 31 — a value of 32 or 33 means "+
			"this field decodes another counter's wire key", back.SessionInstallStaleIgnored)
	}
	if back.SessionDeleteStaleIgnored != 32 {
		t.Errorf("SessionDeleteStaleIgnored: got %d, want 32 — a value of 31 or 33 means "+
			"this field decodes another counter's wire key", back.SessionDeleteStaleIgnored)
	}
	if back.SyncedImportReserveRefused != 33 {
		t.Errorf("SyncedImportReserveRefused: got %d, want 33 — a value of 31 or 32 means "+
			"this field decodes another counter's wire key", back.SyncedImportReserveRefused)
	}

	// A helper that predates #7398 omits all three keys; they must decode to 0
	// rather than failing the parse, which is what makes the wiring additive
	// and keeps a mixed-version cluster readable.
	var legacy ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if legacy.SessionInstallStaleIgnored != 0 ||
		legacy.SessionDeleteStaleIgnored != 0 ||
		legacy.SyncedImportReserveRefused != 0 {
		t.Fatalf("pre-#7398 payload must decode the trio to 0, got %d/%d/%d",
			legacy.SessionInstallStaleIgnored,
			legacy.SessionDeleteStaleIgnored,
			legacy.SyncedImportReserveRefused)
	}
}
