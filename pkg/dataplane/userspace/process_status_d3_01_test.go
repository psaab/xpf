package userspace

import (
	"encoding/json"
	"reflect"
	"testing"
)

// #13280: Rust's ProcessStatus fields must survive Go's JSON decode. Unknown
// JSON object keys are silently discarded by encoding/json, so check both the
// exact tags and the decoded values with distinct counters.
func TestProcessStatusD301OperationalCountersDecode(t *testing.T) {
	const payload = `{"cos_no_owner_binding_drops_total":11,"io_uring_write_refused_total":12,"io_uring_write_refused_bytes_total":13,"route_change_unrejudged_sessions_total":14,"owner_rg_filings_declined_total":15,"ha_transition_demote_dropped":16,"ha_transition_refresh_dropped":17,"ha_transition_vacate_dropped":18,"ha_transition_demote_stale_skipped":19,"ha_transition_refresh_stale_skipped":20,"session_delete_refused_identity":21,"session_delete_dropped_released":22,"tunnel_purge_reservations_released":23,"synced_reverse_rederived":24,"s5_reinject":{"permit_epoch":25,"completed_written":26,"completed_permitted":27,"completed_fenced":28,"completed_denied":29,"completed_refused":30,"provenance":[{"request_id":31,"frame_digest":[1,2,255]}]}}`
	var status ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode Rust ProcessStatus payload: %v", err)
	}

	want := map[string]uint64{
		"CosNoOwnerBindingDropsTotal":        11,
		"IoUringWriteRefusedTotal":           12,
		"IoUringWriteRefusedBytesTotal":      13,
		"RouteChangeUnrejudgedSessionsTotal": 14,
		"OwnerRGFilingsDeclinedTotal":        15,
		"HATransitionDemoteDropped":          16,
		"HATransitionRefreshDropped":         17,
		"HATransitionVacateDropped":          18,
		"HATransitionDemoteStaleSkipped":     19,
		"HATransitionRefreshStaleSkipped":    20,
		"SessionDeleteRefusedIdentity":       21,
		"SessionDeleteDroppedReleased":       22,
		"TunnelPurgeReservationsReleased":    23,
		"SyncedReverseRederived":             24,
	}
	value := reflect.ValueOf(status)
	for name, expected := range want {
		field := value.FieldByName(name)
		if !field.IsValid() {
			t.Errorf("ProcessStatus is missing Rust counter field %s", name)
			continue
		}
		if got := field.Uint(); got != expected {
			t.Errorf("%s = %d, want %d", name, got, expected)
		}
		structField, _ := reflect.TypeOf(status).FieldByName(name)
		if got, wantTag := structField.Tag.Get("json"), rustStatusJSONTag(name); got != wantTag {
			t.Errorf("%s JSON tag = %q, want %q", name, got, wantTag)
		}
	}
	s5 := value.FieldByName("S5Reinject")
	if !s5.IsValid() {
		t.Fatal("ProcessStatus is missing Rust s5_reinject field")
	}
	if s5.IsNil() {
		t.Fatal("s5_reinject object was discarded")
	}
	permitEpoch := s5.Elem().FieldByName("PermitEpoch")
	completedWritten := s5.Elem().FieldByName("CompletedWritten")
	if !permitEpoch.IsValid() || permitEpoch.Uint() != 25 ||
		!completedWritten.IsValid() || completedWritten.Uint() != 26 {
		t.Errorf("s5_reinject decoded as %v, want permit_epoch=25 completed_written=26", s5.Interface())
	}
	for name, expected := range map[string]uint64{
		"CompletedPermitted": 27, "CompletedFenced": 28,
		"CompletedDenied": 29, "CompletedRefused": 30,
	} {
		field := s5.Elem().FieldByName(name)
		if !field.IsValid() || field.Uint() != expected {
			t.Errorf("s5_reinject.%s = %v, want %d", name, field, expected)
		}
	}
	provenance := s5.Elem().FieldByName("Provenance")
	if !provenance.IsValid() || provenance.Len() != 1 {
		t.Fatalf("s5_reinject provenance = %v, want one Rust array-valued row", provenance)
	}
	digest := provenance.Index(0).FieldByName("FrameDigest")
	if !digest.IsValid() || digest.Len() != 3 ||
		digest.Index(0).Uint() != 1 || digest.Index(1).Uint() != 2 ||
		digest.Index(2).Uint() != 255 {
		t.Errorf("s5_reinject frame_digest = %v, want [1 2 255]", digest)
	}
	s5Field, ok := reflect.TypeOf(status).FieldByName("S5Reinject")
	if !ok || s5Field.Tag.Get("json") != "s5_reinject,omitempty" {
		t.Errorf("S5Reinject JSON tag = %q, want %q", s5Field.Tag.Get("json"), "s5_reinject,omitempty")
	}
}

func rustStatusJSONTag(field string) string {
	tags := map[string]string{
		"CosNoOwnerBindingDropsTotal":        "cos_no_owner_binding_drops_total,omitempty",
		"IoUringWriteRefusedTotal":           "io_uring_write_refused_total,omitempty",
		"IoUringWriteRefusedBytesTotal":      "io_uring_write_refused_bytes_total,omitempty",
		"RouteChangeUnrejudgedSessionsTotal": "route_change_unrejudged_sessions_total,omitempty",
		"OwnerRGFilingsDeclinedTotal":        "owner_rg_filings_declined_total,omitempty",
		"HATransitionDemoteDropped":          "ha_transition_demote_dropped,omitempty",
		"HATransitionRefreshDropped":         "ha_transition_refresh_dropped,omitempty",
		"HATransitionVacateDropped":          "ha_transition_vacate_dropped,omitempty",
		"HATransitionDemoteStaleSkipped":     "ha_transition_demote_stale_skipped,omitempty",
		"HATransitionRefreshStaleSkipped":    "ha_transition_refresh_stale_skipped,omitempty",
		"SessionDeleteRefusedIdentity":       "session_delete_refused_identity,omitempty",
		"SessionDeleteDroppedReleased":       "session_delete_dropped_released,omitempty",
		"TunnelPurgeReservationsReleased":    "tunnel_purge_reservations_released,omitempty",
		"SyncedReverseRederived":             "synced_reverse_rederived,omitempty",
	}
	return tags[field]
}
