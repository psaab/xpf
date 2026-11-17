package userspace

import (
	"errors"
	"github.com/psaab/xpf/pkg/config"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"
)

// #19167: BeginTransferPreActivation used to make the RG helper-facing Active
// at once (effectiveHAGroupLocked). The periodic status poll runs outside the
// daemon's applySem and publishes the effective inventory
// (syncHAWatchdogOnlyLocked -> syncHAStateLocked -> update_ha_state), so in
// the window between Begin and the daemon's route republish it could tell the
// helper the RG was active. The helper's activation refresh then ran against
// the pre-activation FIB during a planned failover, and the daemon's later
// explicit publish brought no second refresh, because the RG was already
// active. Now a pre-active RG is routes-pending until
// PublishTransferPreActivation marks it ready, after the republish.

// pollPublish19167 runs the status poll's HA publish under m.mu, as
// process_status.go does once the effective signature changed.
func pollPublish19167(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	err := m.syncHAWatchdogOnlyLocked()
	m.mu.Unlock()
	if err != nil && err.Error() != "userspace_ctrl map not loaded" {
		t.Fatalf("poll publish: %v", err)
	}
}

// TestPollCannotPublishPreActiveRGBeforeRoutes19167 is the deterministic
// interleaving: Begin, then the status poll's publish, then the route
// publish. The poll must neither publish RG1 active nor see an effective
// signature change for it; once the daemon's publish marks the routes ready,
// RG1 is active.
func TestPollCannotPublishPreActiveRGBeforeRoutes19167(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.mu.Lock()
	sigBefore := activeHAGroupSignature(m.effectiveHAGroupMapLocked())
	m.mu.Unlock()

	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))

	m.mu.Lock()
	sigPending := activeHAGroupSignature(m.effectiveHAGroupMapLocked())
	m.mu.Unlock()
	if sigPending != sigBefore {
		t.Fatalf("effective active signature moved from %q to %q on Begin alone; the status poll would publish the RG before its routes", sigBefore, sigPending)
	}
	pollPublish19167(t, m)
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v: the status poll published the pre-active RG1 before its route republish", got)
	}
	if !rec.last(t)[2] {
		t.Fatal("the poll publish dropped the unrelated active RG2")
	}

	if err := m.PublishTransferPreActivation([]int{1}, preActivateEpoch19167(m)); err != nil && err.Error() != "userspace_ctrl map not loaded" {
		t.Fatalf("PublishTransferPreActivation: %v", err)
	}
	if got := rec.last(t); !got[1] {
		t.Fatalf("helper inventory %v: after the route publish the pre-active RG1 must be active", got)
	}
	// The poll after the publish keeps it active.
	pollPublish19167(t, m)
	if got := rec.last(t); !got[1] {
		t.Fatalf("helper inventory %v: the status poll closed a routes-ready pre-activation", got)
	}
}

// TestRoutesPendingRGIsLocalForTheRouteBuilder19167: the republish that makes
// the RG ready must carry its connected prefixes, so the route builder sees a
// routes-pending RG as locally primary.
func TestRoutesPendingRGIsLocalForTheRouteBuilder19167(t *testing.T) {
	m, _ := newPreActivateManager18559(t)
	m.rgPrimaryProvider = func(int) (bool, bool) { return false, true }
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	m.mu.Lock()
	routes := m.routeRGPrimaryLocked()
	m.mu.Unlock()
	if p, k := routes(1); !p || !k {
		t.Fatalf("route provider(1) = (%v, %v) for a routes-pending RG, want (true, true)", p, k)
	}
}

// TestPublishMarksOnlyItsOwnRGs19167: a concurrent transfer's Begin for RG3
// must stay routes-pending when RG1's publish runs.
func TestPublishMarksOnlyItsOwnRGs19167(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.mu.Lock()
	m.haGroups[3] = HAGroupStatus{RGID: 3, Active: false}
	m.mu.Unlock()
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	m.BeginTransferPreActivation([]int{3}, time.Now().Add(time.Minute))
	_ = m.PublishTransferPreActivation([]int{1}, preActivateEpoch19167(m))
	got := rec.last(t)
	if !got[1] {
		t.Fatalf("helper inventory %v: RG1 was published and must be active", got)
	}
	if got[3] {
		t.Fatalf("helper inventory %v: RG3's routes were never republished, so it must stay closed", got)
	}
}

// TestReBeginKeepsAReadyPreActivationOpen19167: Begin on an RG that is live
// and routes-ready only extends the deadline. Dropping it back to pending
// would make the next helper publish close forwarding mid-window.
func TestReBeginKeepsAReadyPreActivationOpen19167(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	_ = m.PublishTransferPreActivation([]int{1}, preActivateEpoch19167(m))
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(2*time.Minute))
	pollPublish19167(t, m)
	if got := rec.last(t); !got[1] {
		t.Fatalf("helper inventory %v: re-beginning a routes-ready RG closed its forwarding", got)
	}
}

// TestPendingPreActivationNotOpenedBySecondaryWrite19167: the reconcile's
// rg_active=false write for a still-secondary RG publishes the effective
// inventory too. A routes-pending RG must not ride it.
func TestPendingPreActivationNotOpenedBySecondaryWrite19167(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	_ = m.UpdateRGActive(1, false)
	if rec.count() == 0 {
		t.Fatal("setup: the rg_active=false write published nothing, so this cell would observe nothing")
	}
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v: an rg_active=false write published a routes-pending RG active", got)
	}
}

// preActivateEpoch19167 is the helper epoch, for cells that call Publish
// without a helper reset after their Begin (#19167 fold 1).
func preActivateEpoch19167(m *Manager) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.helperEpoch
}

// Fold 1 (codex-d P2-1): routes-ready is bound to the helper that received the
// routes. The helper is replaced between the route republish and the Publish:
// the Publish is refused, and every HA publication afterwards keeps the RG
// inactive (the snapshot replay to the new helper has not happened).
func TestPreActivationRefusedAfterHelperReplaced19167(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	epoch := m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	// The helper exits and a replacement spawns before the daemon's Publish.
	m.mu.Lock()
	m.resetAfterHelperGoneLocked()
	m.helperEpoch++ // what startHelperSupervisorLocked does at the spawn
	m.mu.Unlock()
	if err := m.PublishTransferPreActivation([]int{1}, epoch); !errors.Is(err, errPreActivationHelperChanged) {
		t.Fatalf("Publish across a helper replacement = %v, want errPreActivationHelperChanged", err)
	}
	pollPublish19167(t, m)
	if rec.count() == 0 {
		t.Fatal("setup: no HA publication after the replacement, so this cell would observe nothing")
	}
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v: the replacement helper was told the pre-active RG1 is active", got)
	}
	m.mu.Lock()
	ready := m.transferPreActive[1].routesReady
	m.mu.Unlock()
	if ready {
		t.Fatal("the refused Publish still marked RG1 routes-ready")
	}
}

// Fold 1: a helper reset drops the readiness of an ALREADY-OPEN pre-activation:
// its routes went to the helper that is gone.
func TestHelperResetDropsPreActivationReadiness19167(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	epoch := m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	if err := m.PublishTransferPreActivation([]int{1}, epoch); err != nil && err.Error() != "userspace_ctrl map not loaded" {
		t.Fatalf("Publish: %v", err)
	}
	if got := rec.last(t); !got[1] {
		t.Fatalf("setup: helper inventory %v, want RG1 open", got)
	}
	m.mu.Lock()
	m.resetAfterHelperGoneLocked()
	m.mu.Unlock()
	pollPublish19167(t, m)
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v after a helper reset: the pre-active RG1 stayed open on routes the new helper never got", got)
	}
}

// snapshotPublished19167 records that the live helper acknowledged a snapshot,
// which fold 2's helper-facing predicate requires.
func snapshotPublished19167(m *Manager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.publishedSnapshot == 0 {
		m.publishedSnapshot = 1
	}
}

// Fold 2: the helper-facing predicate itself. Readiness counts only at the
// current epoch, with a live helper process that holds a published snapshot.
// The two process conditions sit behind the epoch check on every ordering the
// API allows, so they are pinned here against constructed state.
func TestReadinessRequiresALiveHelperWithAPublishedSnapshot19167(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(m *Manager)
		want  bool
	}{
		{"control: current epoch, live helper, published snapshot", func(*Manager) {}, true},
		{"helper process gone", func(m *Manager) { m.proc = nil }, false},
		{"no published snapshot", func(m *Manager) { m.publishedSnapshot = 0 }, false},
		{"older epoch", func(m *Manager) { m.helperEpoch++ }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newPreActivateManager18559(t)
			m.mu.Lock()
			defer m.mu.Unlock()
			m.transferPreActive = map[int]transferPreActivation{
				1: {until: time.Now().Add(time.Minute), routesReady: true, readyEpoch: m.helperEpoch},
			}
			tc.setup(m)
			if got := m.transferPreActiveForHelperLocked(1, time.Now()); got != tc.want {
				t.Fatalf("helper-facing pre-activation = %v, want %v", got, tc.want)
			}
		})
	}
}

// Fold 2 (codex-d P2-2): a helper reset clears the route dedup hash, which
// describes what the GONE helper acknowledged.
func TestHelperResetClearsTheRouteDedupHash19167(t *testing.T) {
	m, _ := newPreActivateManager18559(t)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSnapshotHash = [32]byte{1}
	m.resetAfterHelperGoneLocked()
	if m.lastSnapshotHash != ([32]byte{}) {
		t.Fatal("the route dedup hash survived the helper reset: a replacement helper could be reported \"unchanged\" for content it never received")
	}
}

// Fold 2 (codex-d P2-2): the route publisher's duplicate skip reports
// Unchanged only for the LIVE helper's acknowledged snapshot. The control: a
// second identical publish on the live helper is Unchanged. The constructed
// state: the old helper's hash is still in place and no snapshot is published
// (a replacement helper before its replay, the pre-fold-2 state). That is
// Retained, not Unchanged.
func TestRouteDedupIsUnchangedOnlyOnTheLiveHelper19167(t *testing.T) {
	stubRuleListHermetic(t)
	cfg := overlayTestConfig()
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0), rec)
	overlay := []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"}}
	if outcome, err := m.PublishRouteOverlaySnapshotOutcome(cfg, overlay, nil, false); err != nil || outcome != RouteOverlayPublished {
		t.Fatalf("setup: first publish = (%v, %v), want (RouteOverlayPublished, nil)", outcome, err)
	}
	if outcome, err := m.PublishRouteOverlaySnapshotOutcome(cfg, overlay, nil, false); err != nil || outcome != RouteOverlayUnchanged {
		t.Fatalf("control: identical publish on the live helper = (%v, %v), want (RouteOverlayUnchanged, nil)", outcome, err)
	}
	m.mu.Lock()
	m.publishedSnapshot = 0
	m.mu.Unlock()
	if outcome, err := m.PublishRouteOverlaySnapshotOutcome(cfg, overlay, nil, false); err != nil || outcome != RouteOverlayRetained {
		t.Fatalf("dedup with no published snapshot = (%v, %v), want (RouteOverlayRetained, nil): a hash no live helper acknowledged is not evidence", outcome, err)
	}
}

// replayFixture19167 is a manager with a REAL retained snapshot (the #9520
// republish fixture), the #18559 HA inventory, and one control hook that
// records the ORDER of apply_snapshot and update_ha_state requests (codex-d's
// fold-2 P3: the replay must be driven, not simulated).
type replayFixture19167 struct {
	m       *Manager
	cfg     *config.Config
	overlay []config.RouteOverlayEntry
	apply   *applyRecorder9520
	ha      *haSendRecorder18559
	mu      sync.Mutex
	order   []string
}

func newReplayFixture19167(t *testing.T) *replayFixture19167 {
	t.Helper()
	stubRuleListHermetic(t)
	f := &replayFixture19167{
		cfg:     overlayTestConfig(),
		overlay: []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"}},
		apply:   &applyRecorder9520{},
		ha:      &haSendRecorder18559{},
	}
	m := newRepublishManager9520(mustBuildSnapshot(t, f.cfg, config.UserspaceConfig{}, 7, 0), f.apply)
	m.clusterHA = true
	m.haGroups = map[int]HAGroupStatus{0: {RGID: 0}, 1: {RGID: 1}, 2: {RGID: 2}}
	m.haRGActiveMapWrite = func(int, bool) error { return nil }
	m.restartTimerFn = func(time.Duration, func()) {}
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		f.mu.Lock()
		f.order = append(f.order, req.Type)
		f.mu.Unlock()
		if req.Type == "update_ha_state" && req.HAState != nil {
			f.ha.mu.Lock()
			f.ha.sends = append(f.ha.sends, append([]HAGroupStatus(nil), req.HAState.Groups...))
			f.ha.mu.Unlock()
			return nil
		}
		return f.apply.hook(req, status)
	}
	f.m = m
	return f
}

// helperGone runs the real reset and drops the process (H1 exited).
func (f *replayFixture19167) helperGone() {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.m.resetAfterHelperGoneLocked()
	f.m.proc = nil
}

// spawnAndReplay starts a REAL child through startHelperSupervisorLocked (the
// spawn path), then drives the REAL restart replay (syncSnapshotLocked).
func (f *replayFixture19167) spawnAndReplay(t *testing.T) {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.m.proc = cmd
	f.m.startHelperSupervisorLocked(cmd)
	f.m.lastStatus.LastSnapshotGeneration = 0 // the new helper holds nothing yet
	if err := f.m.syncSnapshotLocked(); err != nil {
		t.Fatalf("restart replay (syncSnapshotLocked): %v", err)
	}
	if f.m.publishedSnapshot == 0 || len(f.apply.sent) == 0 {
		t.Fatalf("setup: the replay sent %d snapshots and left publishedSnapshot %d", len(f.apply.sent), f.m.publishedSnapshot)
	}
}

func (f *replayFixture19167) orderSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.order...)
}

// Fold 2 (codex-d P2-1, ordering 1), every step REAL:
//   - H1 exits and the real reset runs;
//   - Begin runs with no helper, and the route publish is the real
//     helper-down fold into the retained snapshot (#16643), reported
//     Retained;
//   - a caller publishes the pre-activation anyway;
//   - H2 spawns through startHelperSupervisorLocked, and the real restart
//     replay sends apply_snapshot.
//
// The HA publish AFTER the replay keeps RG1 inactive: readiness reached while
// no helper ran never opens the RG on the next one.
func TestReadinessReachedWithNoHelperDoesNotSurviveTheSpawn19167(t *testing.T) {
	f := newReplayFixture19167(t)
	f.helperGone()
	epoch := f.m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	outcome, err := f.m.PublishRouteOverlaySnapshotOutcome(f.cfg, f.overlay, nil, false)
	if err != nil || outcome != RouteOverlayRetained {
		t.Fatalf("route publish with the helper down = (%v, %v), want (RouteOverlayRetained, nil): the helper-down fold reached no helper", outcome, err)
	}
	_ = f.m.PublishTransferPreActivation([]int{1}, epoch) // a caller that publishes anyway
	f.spawnAndReplay(t)
	pollPublish19167(t, f.m)
	order := f.orderSnapshot()
	replay, haAfter := slices.Index(order, "apply_snapshot"), -1
	for i := replay + 1; replay >= 0 && i < len(order); i++ {
		if order[i] == "update_ha_state" {
			haAfter = i
		}
	}
	if replay < 0 || haAfter < 0 {
		t.Fatalf("requests %v: want the replay's apply_snapshot, then an HA publish", order)
	}
	if got := f.ha.last(t); got[1] {
		t.Fatalf("helper inventory %v after the real replay: H2 was told RG1 is active from readiness reached while no helper ran", got)
	}
}

// Fold 2 positive control, at a non-zero epoch, on the same REAL path. After
// the real reset, spawn and replay, a fresh Begin plus a fresh route
// publication on the live helper (published, or unchanged against the
// snapshot H2 just acknowledged), then Publish, opens RG1. A re-Begin (a
// deadline extension) keeps it open.
func TestFreshPublishOnTheNewHelperOpens19167(t *testing.T) {
	f := newReplayFixture19167(t)
	f.helperGone()
	f.spawnAndReplay(t)
	f.m.mu.Lock()
	epochNow := f.m.helperEpoch
	f.m.mu.Unlock()
	if epochNow == 0 {
		t.Fatal("setup: the epoch did not move, so this control would run at epoch 0")
	}
	epoch := f.m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	outcome, err := f.m.PublishRouteOverlaySnapshotOutcome(f.cfg, f.overlay, nil, false)
	if err != nil || (outcome != RouteOverlayPublished && outcome != RouteOverlayUnchanged) {
		t.Fatalf("fresh route publication on the live helper = (%v, %v), want published or unchanged", outcome, err)
	}
	if err := f.m.PublishTransferPreActivation([]int{1}, epoch); err != nil && err.Error() != "userspace_ctrl map not loaded" {
		t.Fatalf("Publish on the new helper: %v", err)
	}
	if got := f.ha.last(t); !got[1] {
		t.Fatalf("helper inventory %v: a pre-activation published on the new helper did not open RG1", got)
	}
	f.m.BeginTransferPreActivation([]int{1}, time.Now().Add(2*time.Minute)) // extend
	pollPublish19167(t, f.m)
	if got := f.ha.last(t); !got[1] {
		t.Fatalf("helper inventory %v: a re-Begin closed a pre-activation open on the new helper", got)
	}
}
