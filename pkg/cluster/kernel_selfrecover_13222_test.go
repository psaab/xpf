package cluster

import "testing"

// #13222 (D4-04): SetKernelUpgradeHold demotes primary RGs in random map
// order without the demotion accounting every other Primary->Secondary
// transition performs (FailoverCount++, transferCommitRolePinned cleared —
// see ManualFailover and ForceSecondary in failover.go), and
// ResetAllFailover ran a wasted election (ClearKernelUpgradeHold) while
// every RG was still manually drained, then reset RGs in random map
// order so a data RG could re-elect before RG 0.

// TestSetKernelUpgradeHoldDemotionCountsFailover13222 pins the demotion
// accounting: a hold-armed demotion is a real failover of the RG.
func TestSetKernelUpgradeHoldDemotionCountsFailover13222(t *testing.T) {
	m := NewManager(0, 1)
	for _, id := range []int{0, 1, 2} {
		m.groups[id] = &RedundancyGroupState{
			GroupID: id, State: StatePrimary, Weight: 255,
			transferCommitRolePinned: true,
		}
	}
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	for id, rg := range m.groups {
		if rg.State != StateSecondary {
			t.Errorf("RG %d: state = %v, want secondary after hold armed", id, rg.State)
		}
		if rg.FailoverCount != 1 {
			t.Errorf("RG %d: FailoverCount = %d, want 1 (demotion must be counted)", id, rg.FailoverCount)
		}
		if rg.transferCommitRolePinned {
			t.Errorf("RG %d: transferCommitRolePinned still set after demotion", id)
		}
	}
	var got []int
	for len(m.eventCh) > 0 {
		event := <-m.eventCh
		if event.OldState == StatePrimary && event.NewState == StateSecondary {
			got = append(got, event.GroupID)
		}
	}
	if len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
		t.Errorf("hold demotion events = %v, want deterministic RG order [0 1 2]", got)
	}
}

// TestResetAllFailoverRejoinsAllDrainedRGs13222 pins the rejoin end state:
// every drained RG is un-drained, the hold is cleared, and (single-node)
// the RGs are election-eligible again instead of stranded secondary by
// the hold-first ordering.
func TestResetAllFailoverRejoinsAllDrainedRGs13222(t *testing.T) {
	m := NewManager(0, 1)
	for _, id := range []int{0, 1} {
		m.groups[id] = &RedundancyGroupState{
			GroupID: id, State: StateSecondary, Weight: 0,
			ManualFailover: true, Preempt: true,
			transferCommitRolePinned: true,
		}
	}
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	if !m.KernelUpgradeHeld() {
		t.Fatal("setup: hold not armed")
	}
	if err := m.ResetAllFailover(); err != nil {
		t.Fatalf("ResetAllFailover: %v", err)
	}
	if m.KernelUpgradeHeld() {
		t.Error("hold still set after ResetAllFailover")
	}
	for id, rg := range m.groups {
		if rg.ManualFailover {
			t.Errorf("RG %d: ManualFailover still set after ResetAllFailover", id)
		}
		if rg.transferCommitRolePinned {
			t.Errorf("RG %d: transferCommitRolePinned still set after ResetAllFailover", id)
		}
		if rg.Weight == 0 {
			t.Errorf("RG %d: weight not restored after ResetAllFailover", id)
		}
		if rg.State != StatePrimary {
			t.Errorf("RG %d: state = %v, want primary (single-node rejoin must re-elect)", id, rg.State)
		}
	}
	var promoted []int
	for len(m.eventCh) > 0 {
		event := <-m.eventCh
		if event.NewState == StatePrimary {
			promoted = append(promoted, event.GroupID)
		}
	}
	if len(promoted) != 2 || promoted[0] != 0 || promoted[1] != 1 {
		t.Errorf("rejoin promotion events = %v, want RG0 before RG1", promoted)
	}
}

