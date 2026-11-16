package userspace

import (
	"errors"
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
