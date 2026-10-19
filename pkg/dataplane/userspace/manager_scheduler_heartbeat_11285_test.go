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

// #15093: a snapshot that re-introduces scheduled policy after a
// no-schedule era that had heartbeats must send its heartbeat BEFORE the
// apply, so the helper never publishes the new snapshot against a stale
// lease. Controls: a first-ever scheduled snapshot does not pre-send (no
// stale stamp exists; the version-zero lease never expires), a continuous
// scheduled era does not pre-send, and a no-schedule snapshot never sends.
func TestScheduledReintroductionSendsHeartbeatBeforeApply15093(t *testing.T) {
	scheduled := &ConfigSnapshot{Policies: []PolicyRuleSnapshot{{SchedulerName: "workhours"}}}
	plain := &ConfigSnapshot{Policies: []PolicyRuleSnapshot{{Name: "plain"}}}

	run := func(t *testing.T, snaps ...*ConfigSnapshot) []ControlRequest {
		t.Helper()
		m := New()
		var requests []ControlRequest
		m.controlRequestHook = func(request ControlRequest, _ *ProcessStatus) error {
			requests = append(requests, request)
			return nil
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, snap := range snaps[:len(snaps)-1] {
			if err := m.requestApplySnapshotLocked(snap, nil); err != nil {
				t.Fatalf("setup apply: %v", err)
			}
		}
		requests = nil
		if err := m.requestApplySnapshotLocked(snaps[len(snaps)-1], nil); err != nil {
			t.Fatalf("final apply: %v", err)
		}
		return requests
	}

	types := func(reqs []ControlRequest) []string {
		out := make([]string, len(reqs))
		for i, r := range reqs {
			out[i] = r.Type
		}
		return out
	}
	equal := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	// scheduled -> plain -> scheduled: the last apply re-introduces.
	if got := types(run(t, scheduled, plain, scheduled)); !equal(got, []string{"scheduler_heartbeat", "apply_snapshot", "scheduler_heartbeat"}) {
		t.Fatalf("re-introduction order = %v, want heartbeat, apply_snapshot, heartbeat", got)
	}
	if got := types(run(t, scheduled, scheduled)); !equal(got, []string{"apply_snapshot", "scheduler_heartbeat"}) {
		t.Fatalf("continuous scheduled era order = %v, want apply_snapshot, heartbeat (no pre-send)", got)
	}
	if got := types(run(t, plain, scheduled)); !equal(got, []string{"apply_snapshot", "scheduler_heartbeat"}) {
		t.Fatalf("first-ever scheduled order = %v, want apply_snapshot, heartbeat (no pre-send)", got)
	}
	if got := types(run(t, scheduled, plain)); !equal(got, []string{"apply_snapshot"}) {
		t.Fatalf("no-schedule snapshot order = %v, want apply_snapshot only", got)
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
