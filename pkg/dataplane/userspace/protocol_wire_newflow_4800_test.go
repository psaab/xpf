package userspace

import (
	"encoding/json"
	"testing"
)

// #4800: the Rust->Go wire seam for the new-flow contention counters.
//
// WHY THIS SHAPE, AND WHY A ROUND TRIP WOULD NOT DO IT. The Go JSON tags here
// must match the Rust `serde(rename = ...)` names in `protocol/control.rs`,
// `protocol/binding.rs` and `protocol/nat.rs`. Nothing enforced that: the Rust
// fixture test checks Rust serialization against Rust deserialization, and the
// Go tests hand-BUILD their status structs instead of decoding a helper
// payload. So a rename on either side left both suites green while the field
// silently decoded as zero on the other — every ratio the analyzer computes
// would read 0 with no error anywhere. The sibling PR #6938 shipped exactly
// this: a serde key rename stayed green because the only assertion was a
// same-struct Rust->Rust round trip, which is symmetric under rename BY
// CONSTRUCTION and therefore cannot see one.
//
// The payload below is therefore JSON TEXT, written out by hand as the helper
// emits it — NOT the result of marshalling a Go struct. Marshal-then-unmarshal
// is symmetric under a tag rename for the same reason, so it proves only that
// Go agrees with itself.
//
// Every value is DISTINCT. A fixture that reuses a number across fields cannot
// detect a cross-wiring, which is precisely the failure mode a JSON-tag seam
// has: swap two tags and a same-valued fixture stays green.
//
// RED on revert: rename any tag in `protocol_status.go` /
// `protocol_counters.go` away from the Rust name and that field decodes as 0,
// failing here on its own name. Distinct primes make the report unambiguous
// about WHICH field lost its tag.
func TestNewFlowContentionWireDecodesFromHelperJSON_4800(t *testing.T) {
	// Keys exactly as the Rust helper emits them. Do not regenerate this from
	// a Go struct — that would defeat the whole test.
	const helperJSON = `{
	  "shared_session_publishes_total": 1009,
	  "shared_session_publish_lock_acquisitions_total": 1013,
	  "shared_session_publish_lock_contended_total": 1019,
	  "session_replication_upserts_total": 1021,
	  "session_replication_enqueued_total": 1031,
	  "session_replication_lock_contended_total": 1033,
	  "session_replication_queue_depth_sum": 1039,
	  "session_replication_queue_depth_max": 1049,
	  "worker_runtime": [
	    { "worker_id": 0, "new_flow_installs": 1051 },
	    { "worker_id": 1, "new_flow_installs": 1061 }
	  ],
	  "source_nat_pools": [
	    {
	      "flow_shard_lock_acquisitions_total": 1073,
	      "flow_shard_lock_contended_total": 1079,
	      "live_write_lock_acquisitions_total": 1087,
	      "live_write_lock_contended_total": 1091,
	      "live_lock_acquisitions_total": 1063,
	      "live_lock_contended_total": 1069
	    }
	  ]
	}`

	var got ProcessStatus
	if err := json.Unmarshal([]byte(helperJSON), &got); err != nil {
		t.Fatalf("decode helper payload: %v", err)
	}

	for _, tc := range []struct {
		field string
		got   uint64
		want  uint64
	}{
		{"shared_session_publishes_total", got.SharedSessionPublishesTotal, 1009},
		{"shared_session_publish_lock_acquisitions_total", got.SharedSessionPublishLockAcquisitionsTotal, 1013},
		{"shared_session_publish_lock_contended_total", got.SharedSessionPublishLockContendedTotal, 1019},
		{"session_replication_upserts_total", got.SessionReplicationUpsertsTotal, 1021},
		{"session_replication_enqueued_total", got.SessionReplicationEnqueuedTotal, 1031},
		{"session_replication_lock_contended_total", got.SessionReplicationLockContendedTotal, 1033},
		{"session_replication_queue_depth_sum", got.SessionReplicationQueueDepthSum, 1039},
		{"session_replication_queue_depth_max", got.SessionReplicationQueueDepthMax, 1049},
	} {
		if tc.got != tc.want {
			t.Errorf("%s decoded as %d, want %d — the Go json tag no longer "+
				"matches the name the Rust helper emits, so this counter "+
				"silently reads zero in production", tc.field, tc.got, tc.want)
		}
	}

	// Per-worker installs: the sole input to both cross-worker analyzer gates.
	if len(got.WorkerRuntime) != 2 {
		t.Fatalf("worker_runtime decoded %d entries, want 2", len(got.WorkerRuntime))
	}
	for i, want := range []uint64{1051, 1061} {
		if got.WorkerRuntime[i].NewFlowInstalls != want {
			t.Errorf("worker_runtime[%d].new_flow_installs decoded as %d, want %d",
				i, got.WorkerRuntime[i].NewFlowInstalls, want)
		}
	}

	// Per-pool allocator lock pairs (#17036 split + legacy sum).
	if len(got.SourceNATPools) != 1 {
		t.Fatalf("source_nat_pools decoded %d entries, want 1", len(got.SourceNATPools))
	}
	if v := got.SourceNATPools[0].FlowShardLockAcquisitionsTotal; v != 1073 {
		t.Errorf("flow_shard_lock_acquisitions_total decoded as %d, want 1073", v)
	}
	if v := got.SourceNATPools[0].FlowShardLockContendedTotal; v != 1079 {
		t.Errorf("flow_shard_lock_contended_total decoded as %d, want 1079", v)
	}
	if v := got.SourceNATPools[0].LiveWriteLockAcquisitionsTotal; v != 1087 {
		t.Errorf("live_write_lock_acquisitions_total decoded as %d, want 1087", v)
	}
	if v := got.SourceNATPools[0].LiveWriteLockContendedTotal; v != 1091 {
		t.Errorf("live_write_lock_contended_total decoded as %d, want 1091", v)
	}
	if v := got.SourceNATPools[0].LiveLockAcquisitionsTotal; v != 1063 {
		t.Errorf("live_lock_acquisitions_total decoded as %d, want 1063", v)
	}
	if v := got.SourceNATPools[0].LiveLockContendedTotal; v != 1069 {
		t.Errorf("live_lock_contended_total decoded as %d, want 1069", v)
	}
}
