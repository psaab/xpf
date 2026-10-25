package userspace

import (
	"os"
	"os/exec"
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16643: a scheduler transition or ip-monitoring overlay published while
// the helper is down must be folded into m.lastSnapshot, because the
// supervisor restart replays exactly that snapshot (syncSnapshotLocked)
// and nothing else re-sends the transition. Before the fix both partial
// publishers returned "converged" without touching the retained snapshot,
// so the restarted helper re-enforced the stale inactive bits / old
// routes and later converged ticks only heartbeated.
//
// These cells model the restart as the issue's probe does: proc restored
// with publishedSnapshot=0, then a real syncSnapshotLocked publish over a
// recording control hook, asserting the content the restarted helper
// receives.

// seedHelperDownManager16643 builds a manager whose generation-7 snapshot
// was published with the workhours window OPEN (permit active), then drops
// the helper (proc=nil, publishedSnapshot=0) exactly as
// resetAfterHelperGoneLocked leaves it.
func seedHelperDownManager16643(t *testing.T, cfg *config.Config) *Manager {
	t.Helper()
	snap := mustBuildSnapshotWithSchedulerState(t, cfg, config.UserspaceConfig{}, 7, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if schedPolicyInactive5328(t, snap.Policies, "scheduled-allow") {
		t.Fatal("premise: the seeded snapshot must carry the window OPEN (permit active)")
	}
	m := New()
	m.generation = 7
	m.lastSnapshot = snap
	m.publishedSnapshot = 7
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.helperStatusObserved = true
	// The helper is gone.
	m.proc = nil
	m.publishedSnapshot = 0
	m.publishedPlanKey = ""
	return m
}

// simulateRestart16643 restores a (modelled) helper process and drives the
// real status-loop republish, returning the snapshots it sent.
func simulateRestart16643(t *testing.T, m *Manager) []ConfigSnapshot {
	t.Helper()
	rec := &applyRecorder9520{}
	rec.ctrl = &fakeCtrlMap{}
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.helperStatusCtrlMapHook = rec.ctrl
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.controlRequestHook = rec.hook
	// The modelled helper reports nothing applied yet.
	m.lastStatus.LastSnapshotGeneration = 0
	m.mu.Lock()
	err := m.syncSnapshotLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("restart republish (syncSnapshotLocked): %v", err)
	}
	return rec.sent
}

func TestSchedulerTransitionWhileHelperDownSurvivesRestart16643(t *testing.T) {
	stubRuleListHermetic(t)
	cfg := scheduledPolicyConfig9520()
	m := seedHelperDownManager16643(t, cfg)

	// The window closes while the helper is down.
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("UpdatePolicyScheduleState while helper down: %v", err)
	}
	// The transition must already live in the retained snapshot, and the
	// retained snapshot must NOT claim to be published/applied.
	if m.lastSnapshot == nil || !schedPolicyInactive5328(t, m.lastSnapshot.Policies, "scheduled-allow") {
		t.Fatal("the closing transition was not folded into m.lastSnapshot; the restart replay would re-enforce the permit")
	}
	if m.publishedSnapshot != 0 {
		t.Fatalf("publishedSnapshot = %d, want 0: the helper accepted nothing while down", m.publishedSnapshot)
	}
	if m.appliedSnapshot.Generation != 0 {
		t.Fatalf("appliedSnapshot.Generation = %d, want 0: a retained-only fold is not an applied snapshot", m.appliedSnapshot.Generation)
	}
	if got := m.PolicySchedulerActiveState(); got["workhours"] {
		t.Fatalf("applied/show scheduler state = %v, want still-open until the restart publish lands", got)
	}

	sent := simulateRestart16643(t, m)
	if len(sent) != 1 {
		t.Fatalf("restart republish sent %d snapshots, want 1", len(sent))
	}
	if !schedPolicyInactive5328(t, sent[0].Policies, "scheduled-allow") {
		t.Fatal("restart republish carries inactive=false: the permit would stay enforced past its window (#16643)")
	}
	if got := m.PolicySchedulerActiveState(); len(got) != 1 || got["workhours"] {
		t.Fatalf("after restart publish, applied scheduler state = %v, want workhours=false committed", got)
	}
}

// Helper-up control: the same closing transition with the helper running
// publishes immediately and the retained snapshot agrees.
func TestSchedulerTransitionHelperUpControl16643(t *testing.T) {
	stubRuleListHermetic(t)
	cfg := scheduledPolicyConfig9520()
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(mustBuildSnapshotWithSchedulerState(t, cfg, config.UserspaceConfig{}, 7, 0,
		map[string]bool{"workhours": true}, nil, nil), rec)

	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("UpdatePolicyScheduleState helper-up: %v", err)
	}
	if len(rec.sent) != 1 || !schedPolicyInactive5328(t, rec.sent[0].Policies, "scheduled-allow") {
		t.Fatalf("helper-up control: sent=%d, want one publish carrying inactive=true", len(rec.sent))
	}
	if got := rec.generations(); !slices.Equal(got, []uint64{8}) {
		t.Fatalf("helper-up generations = %v, want [8]", got)
	}
}

func TestOverlayWhileHelperDownSurvivesRestart16643(t *testing.T) {
	stubRuleListHermetic(t)
	cfg := overlayTestConfig()
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	m := New()
	m.generation = 7
	m.lastSnapshot = snap
	m.publishedSnapshot = 7
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.helperStatusObserved = true
	m.proc = nil
	m.publishedSnapshot = 0
	m.publishedPlanKey = ""

	overlay := []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"}}
	published, err := m.PublishRouteOverlaySnapshot(cfg, overlay, nil)
	if err != nil || published {
		t.Fatalf("PublishRouteOverlaySnapshot while helper down: published=%v err=%v, want (false, nil)", published, err)
	}
	// The failover route must already be in the retained snapshot.
	found := false
	for _, r := range m.lastSnapshot.Routes {
		if r.Destination == "0.0.0.0/0" && len(r.NextHops) == 1 && r.NextHops[0] == "172.16.80.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("overlay route not folded into m.lastSnapshot; retained routes = %+v", m.lastSnapshot.Routes)
	}
	if m.publishedSnapshot != 0 {
		t.Fatalf("publishedSnapshot = %d, want 0", m.publishedSnapshot)
	}
	if got := m.routeOverlaySnapshot(); len(got) != 1 || got[0].NextHop != "172.16.80.1" {
		t.Fatalf("routeOverlay cache = %+v, want the committed overlay", got)
	}

	sent := simulateRestart16643(t, m)
	if len(sent) != 1 {
		t.Fatalf("restart republish sent %d snapshots, want 1", len(sent))
	}
	found = false
	for _, r := range sent[0].Routes {
		if r.Destination == "0.0.0.0/0" && len(r.NextHops) == 1 && r.NextHops[0] == "172.16.80.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("restart republish routes = %+v, want the overlay default via 172.16.80.1 (#16643)", sent[0].Routes)
	}
}

// Helper-up control for the overlay: publishes immediately.
func TestOverlayHelperUpControl16643(t *testing.T) {
	stubRuleListHermetic(t)
	cfg := overlayTestConfig()
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0), rec)

	overlay := []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"}}
	published, err := m.PublishRouteOverlaySnapshot(cfg, overlay, nil)
	if err != nil || !published {
		t.Fatalf("helper-up overlay: published=%v err=%v, want (true, nil)", published, err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("helper-up overlay sent %d snapshots, want 1", len(rec.sent))
	}
}

// The #3780 nil arm is preserved: with no snapshot ever published, both
// publishers still report converged and stage only the desired state.
func TestHelperDownNoSnapshotEverPublishedStaysConverged16643(t *testing.T) {
	m := New()
	if err := m.UpdatePolicyScheduleStateWithLatch(nil, map[string]bool{"workhours": false}, true); err != nil {
		t.Fatalf("no-snapshot scheduler update must stay converged (#3780): %v", err)
	}
	if m.lastSnapshot != nil {
		t.Fatal("no-snapshot arm must not fabricate a retained snapshot")
	}
	published, err := m.PublishRouteOverlaySnapshotWithLatch(nil, nil, map[string]bool{"workhours": false}, true)
	if err != nil || published {
		t.Fatalf("no-snapshot overlay: published=%v err=%v, want (false, nil) (#3780)", published, err)
	}
	if m.lastSnapshot != nil {
		t.Fatal("no-snapshot overlay arm must not fabricate a retained snapshot")
	}
}
