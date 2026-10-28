package cluster

import (
	"testing"
)

func newSyncArmCompositionManager17814(t *testing.T, controlInterface string) *Manager {
	t.Helper()
	cfg := makeConfig(makeRG(1, true, map[int]int{0: 200, 1: 100}))
	cfg.ControlInterface = controlInterface
	m := NewManager(0, 1)
	t.Cleanup(m.Stop)
	m.UpdateConfig(cfg)
	return m
}

func installArmAndSyncHold17814(t *testing.T, m *Manager) {
	t.Helper()
	m.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	m.SetMonitorWeight(1, startupSyncHoldMonitorIface, true, startupSyncHoldMonitorCost)
}

func TestSyncAndArmHoldsComposeAtWeightOne17814(t *testing.T) {
	for _, tt := range []struct {
		name        string
		configure   func(*Manager)
		wantWeight  int
		wantPrimary bool
	}{
		{
			name:         "lone control-interface node keeps primary",
			configure:    func(m *Manager) {
				m.SetRGReady(1, true, nil)
				if !m.IsLocalPrimary(1) {
					t.Fatal("precondition: lone node is primary before overlapping holds")
				}
				installArmAndSyncHold17814(t, m)
			},
			wantWeight:   1,
			wantPrimary:  true,
		},
		{
			name:         "config reapply preserves shared floor",
			configure:    func(m *Manager) {
				m.SetRGReady(1, true, nil)
				if !m.IsLocalPrimary(1) {
					t.Fatal("precondition: lone node is primary before overlapping holds")
				}
				installArmAndSyncHold17814(t, m)
				// A zero-debt failed monitor is removed by config reconciliation,
				// forcing that independent weight recompute to use the shared hold floor.
				m.SetMonitorWeight(1, "ge-0/0/1", true, 0)
				cfg := makeConfig(makeRG(1, true, map[int]int{0: 200, 1: 100}))
				cfg.ControlInterface = "em0"
				m.UpdateConfig(cfg)
			},
			wantWeight:   1,
			wantPrimary:  true,
		},
		{
			name:         "retained helper failure still resigns",
			configure:    func(m *Manager) {
				installArmAndSyncHold17814(t, m)
				m.SetMonitorWeight(1, HelperCrashLoopMonitorIface, true, HelperCrashLoopMonitorCost)
			},
			wantWeight:   0,
			wantPrimary:  false,
		},
		{
			name:         "genuine monitor failure still resigns",
			configure:    func(m *Manager) {
				installArmAndSyncHold17814(t, m)
				m.SetMonitorWeight(1, "ge-0/0/1", true, 255)
			},
			wantWeight:   0,
			wantPrimary:  false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := newSyncArmCompositionManager17814(t, "em0")
			tt.configure(m)

			if got := m.GroupState(1).Weight; got != tt.wantWeight {
				t.Fatalf("composed arm+sync weight = %d, want %d", got, tt.wantWeight)
			}
			if got := m.IsLocalPrimary(1); got != tt.wantPrimary {
				t.Fatalf("lone node primary = %v, want %v at weight %d", got, tt.wantPrimary, tt.wantWeight)
			}
		})
	}
}

func TestSyncAndArmHoldsRecompute17814(t *testing.T) {
	syncOnly := newSyncArmCompositionManager17814(t, "")
	syncOnly.SetMonitorWeight(1, startupSyncHoldMonitorIface, true, startupSyncHoldMonitorCost)
	if got := syncOnly.GroupState(1).Weight; got != 1 {
		t.Fatalf("sync-only weight = %d, want 1", got)
	}

	m := newSyncArmCompositionManager17814(t, "")
	m.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	if got := m.GroupState(1).Weight; got != 1 {
		t.Fatalf("arm-only weight = %d, want 1", got)
	}

	m.SetMonitorWeight(1, startupSyncHoldMonitorIface, true, startupSyncHoldMonitorCost)
	if got := m.GroupState(1).Weight; got != 1 {
		t.Fatalf("arm+sync weight = %d, want shared floor 1", got)
	}

	m.mu.Lock()
	recomputed := m.debtDerivedWeightLocked(m.groups[1])
	isDebt := m.localWeightIsMonitorDebtLocked(m.groups[1])
	m.mu.Unlock()
	if recomputed != 1 {
		t.Fatalf("debt-derived weight = %d, want shared floor 1", recomputed)
	}
	if !isDebt {
		t.Fatal("overlapping hold weight must still read as monitor-debt-derived")
	}
}

func TestSyncHoldFloorRecoversWhenIndependentDebtDecays17814(t *testing.T) {
	m := newSyncArmCompositionManager17814(t, "")
	m.SetMonitorWeight(1, startupSyncHoldMonitorIface, true, startupSyncHoldMonitorCost)
	if got := m.GroupState(1).Weight; got != 1 {
		t.Fatalf("sync-only weight = %d, want 1", got)
	}

	m.SetMonitorWeight(1, "ge-0/0/1", true, 1)
	if got := m.GroupState(1).Weight; got != 0 {
		t.Fatalf("sync hold plus independent debt weight = %d, want 0", got)
	}

	// Decay the independent debt to zero, then clear it, without changing the hold.
	m.SetMonitorWeight(1, "ge-0/0/1", true, 0)
	if got := m.GroupState(1).Weight; got != 1 {
		t.Fatalf("weight after independent debt decays to zero = %d, want 1", got)
	}
	m.SetMonitorWeight(1, "ge-0/0/1", false, 0)
	if got := m.GroupState(1).Weight; got != 1 {
		t.Fatalf("weight after independent debt clears = %d, want 1", got)
	}
	fails := m.GroupState(1).MonitorFails
	if len(fails) != 1 || fails[0] != startupSyncHoldMonitorIface {
		t.Fatalf("monitor failures after independent debt clears = %v, want only the unchanged sync hold", fails)
	}
}

func TestReservedHoldKeyExplicit255Resigns17814(t *testing.T) {
	for _, key := range []string{DataplaneArmMonitorIface, startupSyncHoldMonitorIface} {
		t.Run(key, func(t *testing.T) {
			m := newSyncArmCompositionManager17814(t, "")
			m.SetMonitorWeight(1, key, true, maxRedundancyGroupWeight)
			if got := m.GroupState(1).Weight; got != 0 {
				t.Fatalf("explicit 255 debt on reserved key %q: weight = %d, want 0", key, got)
			}
			if m.IsLocalPrimary(1) {
				t.Fatalf("explicit 255 debt on reserved key %q: lone node still primary at weight 0", key)
			}
		})
	}
}
