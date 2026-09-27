package userspace

import (
	"encoding/json"
	"testing"
)

// #7919: the Go half of the session-volume high-water wire contract.
//
// The whole value of this field is that it distinguishes "this worker has never
// held a session carrying traffic" from "this helper cannot tell me". An older
// helper omits the key, and if that decoded to 0 the reader would attribute a
// measurement to a binary that never made one — manufacturing exactly the
// evidence the field exists to gather. So it decodes to a POINTER and absence
// stays nil.
func TestSessionVolumeHighWaterAbsentDecodesToNil7919(t *testing.T) {
	// An OLD helper's per-worker status: no such key.
	var old WorkerRuntimeStatus
	if err := json.Unmarshal([]byte(`{"worker_id":3,"work_loops":7}`), &old); err != nil {
		t.Fatalf("decode old payload: %v", err)
	}
	// POSITIVE CONTROL: the payload really did decode, so the nil below is
	// about the missing key and not about a failed unmarshal.
	if old.WorkerID != 3 || old.WorkLoops != 7 {
		t.Fatalf("control: old payload did not decode (worker_id=%d work_loops=%d); "+
			"the nil assertion below would prove nothing", old.WorkerID, old.WorkLoops)
	}
	if old.SessionVolumeHighWater != nil {
		t.Errorf("an absent session_volume_high_water must decode to nil (unknown), "+
			"got %d — a helper that cannot answer must not be recorded as having "+
			"measured zero", *old.SessionVolumeHighWater)
	}

	// A NEW helper that reports it.
	var cur WorkerRuntimeStatus
	if err := json.Unmarshal(
		[]byte(`{"worker_id":2,"session_volume_high_water":117280}`), &cur); err != nil {
		t.Fatalf("decode current payload: %v", err)
	}
	if cur.SessionVolumeHighWater == nil {
		t.Fatalf("a reported session_volume_high_water must decode non-nil")
	}
	if *cur.SessionVolumeHighWater != 117280 {
		t.Errorf("session_volume_high_water = %d, want 117280",
			*cur.SessionVolumeHighWater)
	}
}

func TestEventStreamProducerCountersWire10979(t *testing.T) {
	const payload = `{"event_stream_policy_deny_sent":101,"event_stream_policy_deny_dropped":102,"event_stream_policy_deny_rate_limited":103,"event_stream_policy_deny_queue_full":104,"event_stream_policy_deny_disconnected":105,"event_stream_screen_drop_sent":106,"event_stream_screen_drop_dropped":107,"event_stream_screen_drop_rate_limited":108,"event_stream_screen_drop_queue_full":109,"event_stream_screen_drop_disconnected":110,"event_stream_filter_log_sent":111,"event_stream_filter_log_dropped":112,"event_stream_filter_log_rate_limited":113,"event_stream_filter_log_queue_full":114,"event_stream_filter_log_disconnected":115,"event_stream_session_close_sent":116,"event_stream_session_close_dropped":117,"event_stream_session_close_rate_limited":118,"event_stream_session_close_queue_full":119,"event_stream_session_close_disconnected":120,"event_stream_session_create_sent":121,"event_stream_session_create_dropped":122,"event_stream_session_create_rate_limited":123,"event_stream_session_create_queue_full":124,"event_stream_session_create_disconnected":125}`
	var status ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode producer counters: %v", err)
	}

	for _, item := range []struct {
		key  string
		got  uint64
		want uint64
	}{
		{"event_stream_policy_deny_sent", status.EventStreamPolicyDenySent, 101},
		{"event_stream_policy_deny_dropped", status.EventStreamPolicyDenyDropped, 102},
		{"event_stream_policy_deny_rate_limited", status.EventStreamPolicyDenyRateLimited, 103},
		{"event_stream_policy_deny_queue_full", status.EventStreamPolicyDenyQueueFull, 104},
		{"event_stream_policy_deny_disconnected", status.EventStreamPolicyDenyDisconnected, 105},
		{"event_stream_screen_drop_sent", status.EventStreamScreenDropSent, 106},
		{"event_stream_screen_drop_dropped", status.EventStreamScreenDropDropped, 107},
		{"event_stream_screen_drop_rate_limited", status.EventStreamScreenDropRateLimited, 108},
		{"event_stream_screen_drop_queue_full", status.EventStreamScreenDropQueueFull, 109},
		{"event_stream_screen_drop_disconnected", status.EventStreamScreenDropDisconnected, 110},
		{"event_stream_filter_log_sent", status.EventStreamFilterLogSent, 111},
		{"event_stream_filter_log_dropped", status.EventStreamFilterLogDropped, 112},
		{"event_stream_filter_log_rate_limited", status.EventStreamFilterLogRateLimited, 113},
		{"event_stream_filter_log_queue_full", status.EventStreamFilterLogQueueFull, 114},
		{"event_stream_filter_log_disconnected", status.EventStreamFilterLogDisconnected, 115},
		{"event_stream_session_close_sent", status.EventStreamSessionCloseSent, 116},
		{"event_stream_session_close_dropped", status.EventStreamSessionCloseDropped, 117},
		{"event_stream_session_close_rate_limited", status.EventStreamSessionCloseRateLimited, 118},
		{"event_stream_session_close_queue_full", status.EventStreamSessionCloseQueueFull, 119},
		{"event_stream_session_close_disconnected", status.EventStreamSessionCloseDisconnected, 120},
		{"event_stream_session_create_sent", status.EventStreamSessionCreateSent, 121},
		{"event_stream_session_create_dropped", status.EventStreamSessionCreateDropped, 122},
		{"event_stream_session_create_rate_limited", status.EventStreamSessionCreateRateLimited, 123},
		{"event_stream_session_create_queue_full", status.EventStreamSessionCreateQueueFull, 124},
		{"event_stream_session_create_disconnected", status.EventStreamSessionCreateDisconnected, 125},
	} {
		if item.got != item.want {
			t.Errorf("%s = %d, want %d", item.key, item.got, item.want)
		}
	}
}
