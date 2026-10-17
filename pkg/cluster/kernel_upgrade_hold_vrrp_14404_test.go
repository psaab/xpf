package cluster

import "testing"

// #14404: LocalPriorities must suppress every RG while the kernel-upgrade
// election hold is armed. A held secondary advertises 100 today, so its RETH
// VRRP instances can win / dead-master-promote on an unverified kernel.
func TestLocalPriorities_KernelUpgradeHeldSuppressesAll14404(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)
	// RG1 demoted to secondary; RG0 primary.
	if _, err := m.ManualFailover(1); err != nil {
		t.Fatal(err)
	}
	drainEvents(m, 1)

	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	prios := m.LocalPriorities()
	for id, want := range map[int]int{0: 0, 1: 0} {
		if prios[id] != want {
			t.Errorf("held RG %d priority = %d, want %d", id, prios[id], want)
		}
	}

	m.ClearKernelUpgradeHold()
	prios = m.LocalPriorities()
	if prios[1] == 0 {
		t.Errorf("cleared RG1 priority = 0, want restored non-zero")
	}
}
