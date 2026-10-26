package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17837: the applied accessor and its latch must advance together only after
// a snapshot is accepted; simulator consumers must never read staged desired
// state after apply_snapshot fails.
func TestPolicySchedulerAppliedStateAndFailClosed17837(t *testing.T) {
	var zero Manager
	if got, failClosed := zero.PolicySchedulerAppliedStateAndFailClosed(); got != nil || failClosed {
		t.Fatalf("zero manager applied = (%v,%t), want nil/false", got, failClosed)
	}
	cfg := schedCfg10005()
	m := New()
	controlSock := shortSockDir10005(t)
	seedOpenBaseline10005(t, m, cfg, controlSock, 7)

	// Stage an inactive window and fail the real scheduler snapshot publish.
	// The manager must retain the previously applied OPEN permit and unlatch.
	m.SetPolicySchedulerActiveStateWithLatch(map[string]bool{"workhours": false}, true)
	err := m.UpdatePolicyScheduleStateWithLatch(cfg, map[string]bool{"workhours": false}, true)
	if err == nil || !strings.Contains(err.Error(), "publish policy scheduler snapshot") {
		t.Fatalf("failed apply error = %v, want apply_snapshot publication failure", err)
	}
	got, failClosed := m.PolicySchedulerAppliedStateAndFailClosed()
	if !got["workhours"] || failClosed {
		t.Fatalf("applied state after failed publish = (%v,%t), want active/unlatched", got, failClosed)
	}

	// The CLI/gRPC action-aware predicate must use that applied pair, so it
	// does not skip the old scheduled permit the helper continues enforcing.
	if m.lastSnapshot == nil || len(m.lastSnapshot.Policies) != 1 || m.lastSnapshot.Policies[0].Inactive {
		t.Fatalf("failed publish changed enforced permit snapshot: %+v", m.lastSnapshot)
	}
	policy := cfg.Security.Policies[0].Policies[0]
	if PolicyInactiveFnWithLatch(cfg, got, failClosed)(policy) {
		t.Fatal("simulator predicate marked the previously applied permit inactive")
	}

	// The state/latch pair changes only when an accepted snapshot is committed.
	snap, err := buildSnapshotWithSchedulerStateAndNATCountersAndFailClosed(
		cfg, config.UserspaceConfig{}, 8, 0,
		map[string]bool{"workhours": false}, nil, nil, nil, true)
	if err != nil {
		t.Fatalf("build accepted snapshot: %v", err)
	}
	m.mu.Lock()
	m.commitPolicySchedulerActiveStateFromSnapshotLocked(snap)
	m.mu.Unlock()
	got, failClosed = m.PolicySchedulerAppliedStateAndFailClosed()
	if !failClosed || got["workhours"] {
		t.Fatalf("applied state after commit = (%v,%t), want workhours=false with latch", got, failClosed)
	}
	// Direct compiles without a staged pair must preserve the accepted latch.
	m.mu.Lock()
	m.policySchedulerDesiredSet = false
	m.mu.Unlock()
	fallback, fallbackLatch := m.policySchedulerDesiredStateAndFailClosedSnapshot()
	if !fallbackLatch || fallback["workhours"] {
		t.Fatalf("desired fallback = (%v,%t), want accepted inactive/latch pair", fallback, fallbackLatch)
	}
	if _, ok := fallback["workhours"]; !ok {
		t.Fatalf("desired fallback missing workhours key: %v", fallback)
	}
	// Returned maps must not alias manager state.
	if _, ok := got["workhours"]; !ok {
		t.Fatalf("applied after commit missing workhours key: %v", got)
	}
	got["workhours"] = true
	if again, _ := m.PolicySchedulerAppliedStateAndFailClosed(); again["workhours"] {
		t.Fatal("applied accessor aliases manager map")
	}
}

func TestBuildSnapshotRetainsUserspaceConfig17837(t *testing.T) {
	ucfg := config.UserspaceConfig{Binary: "userspace-helper", Workers: 6}
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{name: "nil config"},
		{name: "configured", cfg: schedCfg10005()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap, err := buildSnapshotWithSchedulerStateAndNATCountersAndFailClosed(
				tc.cfg, ucfg, 1, 0, nil, nil, nil, nil, false)
			if err != nil {
				t.Fatalf("build snapshot: %v", err)
			}
			if snap.Userspace.Binary != ucfg.Binary || snap.Userspace.Workers != ucfg.Workers {
				t.Fatalf("snapshot Userspace = %+v, want Binary=%q Workers=%d", snap.Userspace, ucfg.Binary, ucfg.Workers)
			}
		})
	}
}
