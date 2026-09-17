package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8338: a reserved monitor debt must SURVIVE an unrelated config commit.
//
// THE DEFECT. `reconcileMonitorDebtsLocked` builds its desired set solely from
// `rg.InterfaceMonitors`, so a reserved key is never in it, and the delete loop
// exempted only `isIPMonitorName`. Every commit therefore deleted the
// `__dataplane-arm__` debt. `applyDataplaneReadyTrack` is edge-triggered from
// the three ready-transition helpers, so a commit taken while the node was
// ALREADY unready reinstalled nothing — the node forwarded nothing and carried
// no penalty saying so, and could win an election and hold the RG as a blackhole.
//
// THE FIXTURE MUST ENTER THE UNREADY STATE BEFORE COMMITTING. A cell that
// commits while READY passes against the broken code, because in that state the
// debt is absent anyway and there is nothing to delete. That is not a likely
// mistake here, it is a guaranteed one, so the debt is installed first and its
// presence asserted before the commit.
//
// Driven over the reserved list rather than one name: `reservedMonitorNames` is
// the same slice `isReservedMonitorName` consumes, so a third reserved debt
// added to the category is covered here automatically and one added WITHOUT
// being registered fails the ownership it needs.
func TestReservedMonitorDebtSurvivesConfigCommit8338(t *testing.T) {
	for _, iface := range reservedMonitorNames {
		t.Run(iface, func(t *testing.T) {
			m := NewManager(0, 1)
			cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
			m.UpdateConfig(cfg)
			drainEvents(m, 8)

			// Enter the state the debt represents — for the arm debt this is
			// exactly what `applyDataplaneReadyTrack(false)` does.
			m.SetMonitorWeight(0, iface, true, DataplaneArmMonitorCost)
			before := m.GroupStates()
			if len(before) == 0 || before[0].Weight == 255 {
				t.Fatalf("precondition: the debt must be INSTALLED before the commit "+
					"(weight %v). A fixture that commits without it, or while armed, "+
					"passes on the broken code by having nothing to delete",
					before[0].Weight)
			}
			penalised := before[0].Weight

			// An unrelated commit — no monitor configuration is touched.
			m.UpdateConfig(cfg)
			drainEvents(m, 8)

			after := m.GroupStates()
			if after[0].Weight != penalised {
				t.Fatalf("reserved monitor debt %q was wiped by an unrelated config "+
					"commit: weight %d -> %d. The node still carries the condition the "+
					"debt represents, so it now wins elections it should lose and holds "+
					"the RG while unable to forward (#8338)",
					iface, penalised, after[0].Weight)
			}
		})
	}
}

// #8338 OVER-CORRECTION CONTROL, and it is the one that matters most: getting
// the exemption wrong in the other direction pins a node penalised forever
// after a single arm failure, which is worse than the bug.
//
// The arm transition that legitimately CLEARS the debt must still clear it.
func TestReservedMonitorDebtIsStillClearedByItsOwner8338(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100}))
	m.UpdateConfig(cfg)
	drainEvents(m, 8)

	m.SetMonitorWeight(0, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	if w := m.GroupStates()[0].Weight; w == 255 {
		t.Fatalf("precondition: the debt must be installed, weight = %d", w)
	}

	// The ready-to-serve transition — `applyDataplaneReadyTrack(true)`.
	m.SetMonitorWeight(0, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("the arm-recovered transition must clear the debt: weight = %d, want 255. "+
			"An exemption that also blocks the legitimate clear leaves a node penalised "+
			"forever after one arm failure (#8338)", w)
	}
}

// #8338: an ORDINARY interface-monitor debt must still be reconciled away when
// its monitor leaves the config. This is what the exemption must NOT break —
// the reconciler still owns its own class.
func TestOrdinaryInterfaceMonitorDebtIsStillReconciledAway8338(t *testing.T) {
	m := NewManager(0, 1)
	withMon := makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100},
		&config.InterfaceMonitor{Interface: "ge-0/0/9", Weight: 100}))
	m.UpdateConfig(withMon)
	drainEvents(m, 8)

	m.SetMonitorWeight(0, "ge-0/0/9", true, 100)
	if w := m.GroupStates()[0].Weight; w == 255 {
		t.Fatalf("precondition: the interface-monitor debt must be installed, weight = %d", w)
	}

	// Remove the monitor from the config — the reconciler owns this key.
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	drainEvents(m, 8)

	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("an interface-monitor debt whose monitor was removed must be "+
			"reconciled away: weight = %d, want 255. Over-broad reservation would "+
			"strand real monitor debt and reintroduce #5080", w)
	}
}
