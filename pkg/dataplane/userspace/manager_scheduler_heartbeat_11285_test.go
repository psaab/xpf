package userspace

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestScheduledSnapshotSeedsBestEffortHeartbeat11285(t *testing.T) {
	m := New()
	var requests []ControlRequest
	m.controlRequestHook = func(request ControlRequest, _ *ProcessStatus) error {
		requests = append(requests, request)
		if request.Type == "scheduler_heartbeat" {
			return errors.New("old helper does not recognize scheduler_heartbeat")
		}
		return nil
	}

	snapshot := &ConfigSnapshot{
		Policies: []PolicyRuleSnapshot{{SchedulerName: "workhours"}},
	}
	m.mu.Lock()
	err := m.requestApplySnapshotLocked(snapshot, nil)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("successful snapshot must not fail when its best-effort heartbeat is refused: %v", err)
	}
	if len(requests) != 2 || requests[0].Type != "apply_snapshot" || requests[1].Type != "scheduler_heartbeat" {
		t.Fatalf("requests = %#v, want apply_snapshot followed by scheduler_heartbeat", requests)
	}
	if requests[1].Version != 1 || !requests[1].SuppressStatus || m.policySchedulerVersion != 1 || !m.hasScheduledPolicySnapshot {
		t.Fatalf("heartbeat request/state = version %d suppress_status %v, manager version %d, scheduled %v; want 1, true, 1, true",
			requests[1].Version, requests[1].SuppressStatus, m.policySchedulerVersion, m.hasScheduledPolicySnapshot)
	}
	if !m.lastSchedulerHeartbeatAt.IsZero() {
		t.Fatalf("refused heartbeat advanced successful-send timestamp: %v", m.lastSchedulerHeartbeatAt)
	}
}

func TestSchedulerHeartbeatThrottleRetriesUntilSuccessful11285(t *testing.T) {
	m := New()
	m.hasScheduledPolicySnapshot = true
	m.policySchedulerVersion = 7
	base := time.Unix(1_700_000_000, 0)
	m.lastSchedulerHeartbeatAt = base
	var requests []ControlRequest
	fail := true
	m.controlRequestHook = func(request ControlRequest, _ *ProcessStatus) error {
		requests = append(requests, request)
		if fail {
			return errors.New("control request failed")
		}
		return nil
	}

	m.heartbeatPolicySchedulerAt(context.Background(), base.Add(time.Minute-time.Nanosecond))
	if len(requests) != 0 {
		t.Fatalf("heartbeat sent before 60-second lease refresh interval: %#v", requests)
	}

	refreshAt := base.Add(time.Minute)
	m.heartbeatPolicySchedulerAt(context.Background(), refreshAt)
	if len(requests) != 1 || requests[0].Type != "scheduler_heartbeat" || requests[0].Version != 7 || !requests[0].SuppressStatus {
		t.Fatalf("first due heartbeat = %#v, want scheduler_heartbeat version 7 with suppress_status", requests)
	}
	if !m.lastSchedulerHeartbeatAt.Equal(base) {
		t.Fatalf("failed heartbeat advanced timestamp to %v, want %v", m.lastSchedulerHeartbeatAt, base)
	}
	fail = false
	m.heartbeatPolicySchedulerAt(context.Background(), refreshAt)
	if len(requests) != 2 || !m.lastSchedulerHeartbeatAt.Equal(refreshAt) {
		t.Fatalf("retry after failure = requests %#v, timestamp %v; want second request and %v",
			requests, m.lastSchedulerHeartbeatAt, refreshAt)
	}
	m.heartbeatPolicySchedulerAt(context.Background(), refreshAt)
	if len(requests) != 2 {
		t.Fatalf("successful heartbeat was not throttled: %#v", requests)
	}
}

func TestSchedulerHeartbeatWireFields11285(t *testing.T) {
	request := ControlRequest{
		Type:           "scheduler_heartbeat",
		Version:        7,
		SuppressStatus: true,
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal scheduler heartbeat: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatalf("decode scheduler heartbeat: %v", err)
	}
	var version uint64
	if err := json.Unmarshal(fields["version"], &version); err != nil || version != 7 {
		t.Fatalf("wire version = %q (decoded %d, err %v), want 7", fields["version"], version, err)
	}
	var suppressStatus bool
	if err := json.Unmarshal(fields["suppress_status"], &suppressStatus); err != nil || !suppressStatus {
		t.Fatalf("wire suppress_status = %q (decoded %v, err %v), want true",
			fields["suppress_status"], suppressStatus, err)
	}
}
