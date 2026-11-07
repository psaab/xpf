package userspace

import (
	"context"
	"encoding/json"
	"testing"
	"time"
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

// #18635: per-kind HA event-stream loss survives the helper JSON boundary.
func TestEventStreamSessionDeltaLossWire18635(t *testing.T) {
	const payload = `{"event_stream_session_delta_lost_open":11,"event_stream_session_delta_lost_close":22,"event_stream_session_delta_lost_update":33}`
	var status ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("decode HA session-delta loss counters: %v", err)
	}
	if status.EventStreamSessionDeltaLostOpen == nil ||
		*status.EventStreamSessionDeltaLostOpen != 11 ||
		status.EventStreamSessionDeltaLostClose == nil ||
		*status.EventStreamSessionDeltaLostClose != 22 ||
		status.EventStreamSessionDeltaLostUpdate == nil ||
		*status.EventStreamSessionDeltaLostUpdate != 33 {
		t.Fatalf("HA session-delta loss counters = open=%v close=%v update=%v, want 11/22/33",
			status.EventStreamSessionDeltaLostOpen,
			status.EventStreamSessionDeltaLostClose,
			status.EventStreamSessionDeltaLostUpdate)
	}
}

func TestEventStreamSessionDeltaLossMissingKeysStayUnknown18635(t *testing.T) {
	var status ProcessStatus
	if err := json.Unmarshal([]byte(`{"pid":1234}`), &status); err != nil {
		t.Fatalf("decode pre-#18635 helper status: %v", err)
	}
	if status.EventStreamSessionDeltaLostOpen != nil ||
		status.EventStreamSessionDeltaLostClose != nil ||
		status.EventStreamSessionDeltaLostUpdate != nil {
		t.Fatalf("missing pre-#18635 loss keys decoded as known values: open=%v close=%v update=%v",
			status.EventStreamSessionDeltaLostOpen,
			status.EventStreamSessionDeltaLostClose,
			status.EventStreamSessionDeltaLostUpdate)
	}
}

func TestHelperStatusObservationSequenceAdvancesOnPublication18635(t *testing.T) {
	m := New()
	for want := uint64(1); want <= 2; want++ {
		m.mu.Lock()
		status := ProcessStatus{PID: 1234}
		m.recordHelperStatusLocked(&status)
		m.mu.Unlock()
		if status.HelperStatusObservationSequence != want {
			t.Fatalf("published helper status sequence = %d, want %d",
				status.HelperStatusObservationSequence, want)
		}
		published, err := m.Status()
		if err != nil {
			t.Fatalf("read published helper status: %v", err)
		}
		if published.HelperStatusObservationSequence != want {
			t.Fatalf("cached helper status sequence = %d, want %d",
				published.HelperStatusObservationSequence, want)
		}
		cachedAgain, err := m.Status()
		if err != nil {
			t.Fatalf("read cached helper status again: %v", err)
		}
		if cachedAgain.HelperStatusObservationSequence != want {
			t.Fatalf("ordinary cached status read advanced observation sequence to %d, want %d",
				cachedAgain.HelperStatusObservationSequence, want)
		}
	}
}

func TestEventStreamLossSecondReadRejectsStaleProjection18635(t *testing.T) {
	m := New()
	projected := make(chan struct{})
	release := make(chan struct{})
	type statusResult struct {
		status ProcessStatus
		err    error
	}
	firstResult := make(chan statusResult, 1)
	var loss uint64
	var calls int
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type != "status" {
			t.Errorf("request type = %q, want status", req.Type)
		}
		calls++
		open, zero := loss, uint64(0)
		*status = ProcessStatus{
			PID:                              4242,
			EventStreamSessionDeltaLostOpen:   &open,
			EventStreamSessionDeltaLostClose:  &zero,
			EventStreamSessionDeltaLostUpdate: &zero,
		}
		if calls == 1 {
			close(projected) // the helper has projected loss=0 into this response
			<-release        // hold it while the worker records loss
		}
		return nil
	}

	go func() {
		status, err := m.requestHelperStatusAtSocket("", m.controlRequestHook)
		firstResult <- statusResult{status: status, err: err}
	}()
	<-projected
	loss = 1
	close(release)
	first := <-firstResult
	if first.err != nil {
		t.Fatalf("first helper status read: %v", first.err)
	}
	if first.status.EventStreamSessionDeltaLostOpen == nil ||
		*first.status.EventStreamSessionDeltaLostOpen != 0 {
		t.Fatalf("held pre-loss projection = %v, want zero", first.status.EventStreamSessionDeltaLostOpen)
	}

	published, err := m.refreshEventStreamSessionDeltaLossStatusAtSocket(
		first.status, "", m.controlRequestHook)
	if err != nil {
		t.Fatalf("second status read: %v", err)
	}
	if published.EventStreamSessionDeltaLostOpen == nil ||
		*published.EventStreamSessionDeltaLostOpen != 1 {
		t.Fatalf("status selected for publication = %v, want second-read loss=1",
			published.EventStreamSessionDeltaLostOpen)
	}
	if calls != 2 {
		t.Fatalf("helper status reads = %d, want first projection plus one confirmation read", calls)
	}
}

func TestEventStreamLossRefreshErrorIsNotPublishable18635(t *testing.T) {
	m := New()
	zero := uint64(0)
	projected := ProcessStatus{
		PID:                              4242,
		EventStreamSessionDeltaLostOpen:   &zero,
		EventStreamSessionDeltaLostClose:  &zero,
		EventStreamSessionDeltaLostUpdate: &zero,
	}
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
		return errStatusDecode
	}
	if _, err := m.refreshEventStreamSessionDeltaLossStatusAtSocket(projected, "", m.controlRequestHook); err == nil {
		t.Fatal("a failed confirmation read returned a publishable status")
	}
}

func TestStatusLoopPublishesPostProjectionLossRead18635(t *testing.T) {
	oldInterval := statusLoopInterval
	statusLoopInterval = 5 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	m, _ := stalePollManager16653(t)
	projected := make(chan struct{})
	release := make(chan struct{})
	var loss uint64
	var calls int
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type != "status" {
			t.Errorf("request type = %q, want status", req.Type)
		}
		calls++
		currentLoss, zero := loss, uint64(0)
		snapshot := *readyHelperStatus()
		snapshot.PID = 4242
		snapshot.EventStreamSessionDeltaLostOpen = &currentLoss
		snapshot.EventStreamSessionDeltaLostClose = &zero
		snapshot.EventStreamSessionDeltaLostUpdate = &zero
		*status = snapshot
		if calls == 1 {
			close(projected) // Rust projected zero before the RPC response was held.
			<-release        // The worker records loss before Go can publish it.
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.statusLoop(ctx, false)
	}()
	select {
	case <-projected:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("status loop did not reach the held pre-loss projection")
	}
	loss = 1
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		sequence := m.lastStatus.HelperStatusObservationSequence
		publishedLoss := m.lastStatus.EventStreamSessionDeltaLostOpen
		var got uint64
		if publishedLoss != nil {
			got = *publishedLoss
		}
		m.mu.Unlock()
		if sequence != 0 {
			cancel()
			<-done
			if publishedLoss == nil || got != 1 {
				t.Fatalf("published status sequence=%d loss=%v, want second-read loss=1",
					sequence, publishedLoss)
			}
			if calls < 2 {
				t.Fatalf("status requests = %d, want a confirmation read before publication", calls)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("status loop never published the confirmed helper response")
}
