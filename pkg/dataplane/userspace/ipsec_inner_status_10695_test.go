package userspace

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestIPsecInnerStatusWireCensus10695(t *testing.T) {
	const payload = `{"zone_gate_unzoned_total":11,"zone_gate_ambiguous_total":12,"zone_gate_stale_total":13,"zone_gate_no_generation_total":14,"ipsec_inner_parse_drops_total":15,"ipsec_inner_ecn_illegal_drops":16,"ipsec_inner_worker_queue_full_total":17,"ipsec_inner_verdict_queue_full_total":18,"ipsec_inner_slab_exhausted_total":19,"ipsec_inner_worker_retired_total":20,"ipsec_inner_worker_orphan_reaped_total":21,"ipsec_inner_orphan_provisional_total":22}`
	var status ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode current helper status: %v", err)
	}

	fields := []struct {
		name  string
		key   string
		value uint64
	}{
		{"ZoneGateUnzonedTotal", "zone_gate_unzoned_total", 11},
		{"ZoneGateAmbiguousTotal", "zone_gate_ambiguous_total", 12},
		{"ZoneGateStaleTotal", "zone_gate_stale_total", 13},
		{"ZoneGateNoGenerationTotal", "zone_gate_no_generation_total", 14},
		{"IpsecInnerParseDropsTotal", "ipsec_inner_parse_drops_total", 15},
		{"IpsecInnerEcnIllegalDrops", "ipsec_inner_ecn_illegal_drops", 16},
		{"IpsecInnerWorkerQueueFullTotal", "ipsec_inner_worker_queue_full_total", 17},
		{"IpsecInnerVerdictQueueFullTotal", "ipsec_inner_verdict_queue_full_total", 18},
		{"IpsecInnerSlabExhaustedTotal", "ipsec_inner_slab_exhausted_total", 19},
		{"IpsecInnerWorkerRetiredTotal", "ipsec_inner_worker_retired_total", 20},
		{"IpsecInnerWorkerOrphanReapedTotal", "ipsec_inner_worker_orphan_reaped_total", 21},
		{"IpsecInnerOrphanProvisionalTotal", "ipsec_inner_orphan_provisional_total", 22},
	}
	typeOfStatus := reflect.TypeOf(status)
	valueOfStatus := reflect.ValueOf(status)
	for _, tc := range fields {
		t.Run(tc.key, func(t *testing.T) {
			field, ok := typeOfStatus.FieldByName(tc.name)
			if !ok {
				t.Fatalf("ProcessStatus is missing field %s", tc.name)
			}
			if got := field.Tag.Get("json"); got != tc.key+",omitempty" {
				t.Errorf("%s json tag = %q, want %q", tc.name, got, tc.key+",omitempty")
			}
			if got := valueOfStatus.FieldByName(tc.name).Uint(); got != tc.value {
				t.Errorf("%s decoded as %d, want %d from %q", tc.name, got, tc.value, tc.key)
			}
		})
	}

	// Older helpers omit every new field; the additive status extension must
	// continue to decode and preserve the established zero default.
	var old ProcessStatus
	if err := json.Unmarshal([]byte(`{}`), &old); err != nil {
		t.Fatalf("decode status without IPsec-inner counters: %v", err)
	}
	oldValue := reflect.ValueOf(old)
	for _, tc := range fields {
		if got := oldValue.FieldByName(tc.name).Uint(); got != 0 {
			t.Errorf("absent %s decoded as %d, want 0", tc.key, got)
		}
	}
}
