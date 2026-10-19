package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15036 (A15-01): a redundancy group carrying TWO compiled monitors for
// the same interface — [{ge-0/0/1,100} {ge-0/0/1,255}], what a re-weighted
// `set` produced before the compiler folded by interface — made the two
// runtime consumers disagree about the live weight:
//
//   - pollInterfaceMonitors shares one dampening key per (rg,iface); the
//     first down-transition applies the FIRST entry's weight (100).
//   - reconcileMonitorDebtsLocked builds a last-wins desired map, so an
//     unrelated later commit reapplies the LAST entry's weight (255).
//
// So the group stayed primary behind a dead monitored link (weight
// 255-100=155) until a no-op commit flipped it to 0. The #15036 fix folds
// the duplicate to one monitor at compile time (last-wins) and rejects it
// at strict commit, so a compiled config can no longer carry the pair.
// These tests pin the runtime half of the acceptance: fed the FOLDED
// single monitor {ge-0/0/1,255}, the poll path gives weight 0 with the
// link down, and a re-commit of the same config changes nothing.
//
// FAIL-ON-REVERT: hand these tests the pre-fix duplicate pair (two
// monitors for ge-0/0/1) and the pre-commit weight is 155, not 0 — the
// first-wins poll applies 100 while reconcile would later apply 255.

// TestDuplicateMonitorFold_PollAndRecommitAgree_15036 drives the real
// poll path (mock netlink -> pollInterfaceMonitors -> SetMonitorWeight)
// with the folded monitor and then re-applies the identical config,
// requiring the weight to be 0 both before and after the re-commit.
func TestDuplicateMonitorFold_PollAndRecommitAgree_15036(t *testing.T) {
	m := NewManager(0, 1) // node 0
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200},
		&config.InterfaceMonitor{Interface: "ge-0/0/1", Weight: 255},
	))
	m.UpdateConfig(cfg)
	drainEvents(m, 4)

	// "ge-0/0/1" is a Junos-style name; the poll translates it to the
	// Linux name ge-0-0-1 before LinkByName.
	nlh := newMockNlHandle()
	nlh.setLink("ge-0-0-1", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("weight with monitored link up = %d, want 255", w)
	}
	if sts := mon.LocalInterfaceStatuses(); len(sts) != 1 {
		t.Fatalf("local statuses = %d entries, want exactly 1 folded monitor", len(sts))
	} else if sts[0].Weight != 255 {
		t.Fatalf("advertised monitor weight = %d, want 255 (the folded last-wins weight)", sts[0].Weight)
	}

	// The monitored link dies: the single folded weight 255 must resign
	// the group immediately — no second entry may shadow it first-wins.
	nlh.setLink("ge-0-0-1", false)
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight with monitored link down = %d, want 0 — the folded "+
			"weight 255 must apply on the first poll, not an earlier 100", w)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node must not stay primary with its only monitored link down")
	}

	// An unrelated re-commit of the SAME config must change nothing:
	// reconcileMonitorDebtsLocked reads the same single weight the poll
	// already applied.
	m.UpdateConfig(cfg)
	drainEvents(m, 4)
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight after re-commit = %d, want 0 — poll and reconcile disagree", w)
	}
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight after post-commit poll = %d, want 0", w)
	}
}
