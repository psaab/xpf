package vrrp

import (
	"net"
	"testing"
	"time"
)

// #17145 (R4-Q36-02): the RFC 5798 effective-priority rule and the
// Master_Down_Interval / Skew_Time formula must have ONE source of truth
// (effectivePriority / skewFor / masterDownFor in instance_timing.go).
// Before the fix every lock-held arm, preempt helper and staleness check
// re-typed the arithmetic, so a drift in any copy other than
// prioritySnapshot survived the suite. These cells pin the pure helpers
// directly and assert every former copy site agrees with them, so a
// cost+1 drift inside effectivePriority is killed here and by
// TestGetPriority_TrackMatrix.

func TestEffectivePriority_17145_Matrix(t *testing.T) {
	cases := []struct {
		name      string
		prio      int
		cost      int
		trackDown bool
		iface     string
		want      int
	}{
		{"resign-0-passthrough", 0, 50, true, "eth1", 0},
		{"owner-255-passthrough", 255, 50, true, "eth1", 255},
		{"tracked-down-subtract", 200, 50, true, "eth1", 150},
		{"clamp-low", 100, 250, true, "eth1", 1},
		{"clamp-high-negative-cost", 250, -10, true, "eth1", 254},
		{"tracked-up-unchanged", 200, 50, false, "eth1", 200},
		{"no-track-iface-unchanged", 200, 50, true, "", 200},
		{"zero-cost-unchanged", 200, 0, true, "eth1", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectivePriority(tc.prio, tc.cost, tc.trackDown, tc.iface); got != tc.want {
				t.Errorf("effectivePriority(%d,%d,%v,%q) = %d, want %d", tc.prio, tc.cost, tc.trackDown, tc.iface, got, tc.want)
			}
		})
	}
}

func TestMasterDownFor_17145_ExactValues(t *testing.T) {
	advert := 1000 * time.Millisecond
	cases := []struct {
		name    string
		effPrio int
		want    time.Duration
	}{
		{"p0-max-skew", 0, 3*advert + time.Duration(256-0)*advert/256},
		{"p1", 1, 3*advert + time.Duration(256-1)*advert/256},
		{"p100", 100, 3*advert + time.Duration(256-100)*advert/256},
		{"p255-owner", 255, 3*advert + time.Duration(256-255)*advert/256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := masterDownFor(advert, tc.effPrio); got != tc.want {
				t.Errorf("masterDownFor(%v,%d) = %v, want %v", advert, tc.effPrio, got, tc.want)
			}
			if got, want := skewFor(advert, tc.effPrio), tc.want-3*advert; got != want {
				t.Errorf("skewFor(%v,%d) = %v, want %v", advert, tc.effPrio, got, want)
			}
		})
	}
}

// TestFormulaAgreement_17145 pins every former copy site to the pure
// helpers for one track-demoted fixture: configured 200, cost 150 while
// down -> effective 50, local advert 10s (no learned interval).
func TestFormulaAgreement_17145(t *testing.T) {
	vi := newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		TrackInterface:    "eth1",
		TrackPriorityCost: 150,
		AdvertiseInterval: 10000,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 16), nil)
	vi.mu.Lock()
	vi.trackDown = true
	vi.mu.Unlock()

	const wantEff = 50
	advert := 10 * time.Second
	wantMasterDown := masterDownFor(advert, wantEff)
	wantSkew := skewFor(advert, wantEff)

	if got := vi.getPriority(); got != wantEff {
		t.Errorf("getPriority() = %d, want %d", got, wantEff)
	}
	if _, eff, down := vi.prioritySnapshot(); eff != wantEff || !down {
		t.Errorf("prioritySnapshot() effective=%d trackDown=%v, want %d/true", eff, down, wantEff)
	}
	// Pending-resign branch of getPriority must agree too (#18045 detour
	// reports the pre-resign cfg priority through the same rule).
	vi.resignMu.Lock()
	vi.resignPending = true
	vi.resignMu.Unlock()
	if got := vi.getPriority(); got != wantEff {
		t.Errorf("getPriority() pending-resign = %d, want %d", got, wantEff)
	}
	vi.resignMu.Lock()
	vi.resignPending = false
	vi.resignMu.Unlock()

	vi.mu.RLock()
	if got := vi.effectivePriorityLocked(); got != wantEff {
		t.Errorf("effectivePriorityLocked() = %d, want %d", got, wantEff)
	}
	if got := vi.masterDownLocked(); got != wantMasterDown {
		t.Errorf("masterDownLocked() = %v, want %v", got, wantMasterDown)
	}
	if got := vi.skewTimeLocked(); got != wantSkew {
		t.Errorf("skewTimeLocked() = %v, want %v", got, wantSkew)
	}
	vi.mu.RUnlock()

	if got := vi.masterDownInterval(); got != wantMasterDown {
		t.Errorf("masterDownInterval() = %v, want %v", got, wantMasterDown)
	}

	// Staleness sites: lastMasterSeen just inside the horizon is live,
	// just outside is stale. Margins are seconds against a ~38s horizon.
	now := time.Now()
	vi.mu.Lock()
	vi.lastMasterSeen = now.Add(-(wantMasterDown - 2*time.Second))
	insideStale := vi.observedMasterStaleLocked(now)
	vi.lastMasterSeen = now.Add(-(wantMasterDown + 2*time.Second))
	outsideStale := vi.observedMasterStaleLocked(now)
	vi.mu.Unlock()
	if insideStale {
		t.Error("observedMasterStaleLocked() = true inside masterDownFor horizon, want false")
	}
	if !outsideStale {
		t.Error("observedMasterStaleLocked() = false outside masterDownFor horizon, want true")
	}

	vi.mu.Lock()
	vi.lastMasterSeen = time.Now().Add(-(wantMasterDown - 2*time.Second))
	vi.mu.Unlock()
	if vi.heldMasterIsStale() {
		t.Error("heldMasterIsStale() = true inside masterDownFor horizon, want false")
	}
	vi.mu.Lock()
	vi.lastMasterSeen = time.Now().Add(-(wantMasterDown + 2*time.Second))
	vi.mu.Unlock()
	if !vi.heldMasterIsStale() {
		t.Error("heldMasterIsStale() = false outside masterDownFor horizon, want true")
	}

	// Preempt comparison sites use the same effective priority: demoted
	// 50 must not preempt a live 100 master, and the same staleness
	// horizon governs preemptingLiveLowerMaster.
	vi.mu.Lock()
	vi.lastMasterPriority = 100
	vi.lastMasterSeen = time.Now()
	vi.mu.Unlock()
	if vi.shouldPreemptObservedMaster() {
		t.Error("shouldPreemptObservedMaster() = true for demoted 50 vs live 100, want false")
	}
	if vi.preemptingLiveLowerMaster() {
		t.Error("preemptingLiveLowerMaster() = true for demoted 50 vs live 100, want false")
	}
}

// TestArmTimersUseMasterDownFor_17145 arms the three timer sites whose
// open-coded copies the issue cites and checks their fire horizons
// against masterDownFor for the demoted fixture (advert 30ms,
// effective 50 -> master-down ~114ms; safety = max(3x, 500ms)).
func TestArmTimersUseMasterDownFor_17145(t *testing.T) {
	newDemoted := func() *vrrpInstance {
		vi := newInstance(Instance{
			Interface:         "eth0",
			GroupID:           101,
			Priority:          200,
			Preempt:           true,
			TrackInterface:    "eth1",
			TrackPriorityCost: 150,
			AdvertiseInterval: 30,
		}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 16), nil)
		vi.mu.Lock()
		vi.trackDown = true
		vi.mu.Unlock()
		return vi
	}
	masterDown := masterDownFor(30*time.Millisecond, 50)

	armTimer := time.NewTimer(time.Hour)
	armTimer.Stop()
	newDemoted().armMasterDownTimer(armTimer)
	select {
	case <-armTimer.C:
		t.Fatalf("armMasterDownTimer fired within 20ms, want ~%v", masterDown)
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-armTimer.C:
	case <-time.After(2 * time.Second):
		t.Fatalf("armMasterDownTimer did not fire within 2s, want ~%v", masterDown)
	}

	holdMasterDown := time.NewTimer(time.Hour)
	holdTimer := time.NewTimer(time.Hour)
	vi := newDemoted()
	vi.armPreemptHold(holdMasterDown, holdTimer, time.Hour)
	holdTimer.Stop()
	select {
	case <-holdMasterDown.C:
	case <-time.After(2 * time.Second):
		t.Fatalf("armPreemptHold watchdog did not fire within 2s, want ~%v", masterDown)
	}

	safetyTimer := time.NewTimer(time.Hour)
	safetyTimer.Stop()
	newDemoted().armMasterDownSafetyTimer(safetyTimer)
	select {
	case <-safetyTimer.C:
		t.Fatal("armMasterDownSafetyTimer fired within 200ms, want 500ms floor over 3x master-down")
	case <-time.After(200 * time.Millisecond):
	}
	select {
	case <-safetyTimer.C:
	case <-time.After(2 * time.Second):
		t.Fatal("armMasterDownSafetyTimer did not fire within 2s, want 500ms floor")
	}
}
