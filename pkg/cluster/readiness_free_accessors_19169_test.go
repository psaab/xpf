package cluster

import (
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #19169: the callback-free accessors return every configured group (RG0
// included for GroupIDs and MonitorFailuresByGroup) without invoking the
// transfer-readiness callback.
func TestReadinessFreeAccessors19169(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 2, NodePriorities: map[int]int{0: 200}},
		{ID: 0, NodePriorities: map[int]int{0: 200}},
		{ID: 1, NodePriorities: map[int]int{0: 200}},
	}})
	var calls atomic.Int32
	m.SetTransferReadinessFunc(func(int) (bool, []string) { calls.Add(1); return true, nil })

	if got := m.GroupIDs(); !reflect.DeepEqual(got, []int{0, 1, 2}) {
		t.Fatalf("GroupIDs = %v, want [0 1 2]", got)
	}
	var ids []int
	for _, g := range m.MonitorFailuresByGroup() {
		ids = append(ids, g.GroupID)
	}
	if !reflect.DeepEqual(ids, []int{0, 1, 2}) {
		t.Fatalf("MonitorFailuresByGroup ids = %v, want [0 1 2]", ids)
	}
	m.SetGroupStateForTesting(1, StatePrimary)
	if st, known := m.LocalGroupState(1); !known || st != StatePrimary {
		t.Fatalf("LocalGroupState(1) = (%s, %v), want (primary, true)", st, known)
	}
	if _, known := m.LocalGroupState(9); known {
		t.Fatal("LocalGroupState reported an unconfigured group as known")
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("the accessors ran the transfer-readiness callback %d times", n)
	}
	// The control: GroupStates does run it, once per group.
	_ = m.GroupStates()
	if n := calls.Load(); n != 3 {
		t.Fatalf("control: GroupStates ran the callback %d times, want 3", n)
	}
}

// #19169 (codex-e P3): MonitorFailuresByGroup returns a SNAPSHOT. Returning
// rg.MonitorFails itself would expose the backing array SetMonitorWeight
// sorts and edits in place. Several failures are installed; a mutation on
// either side must not show up on the other.
func TestMonitorFailuresByGroupIsASnapshot19169(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 1, NodePriorities: map[int]int{0: 200}},
	}})
	for _, iface := range []string{"ge-0-0-3", "ge-0-0-1", "ge-0-0-2"} {
		m.SetMonitorWeight(1, iface, true, 10)
	}
	failsOf := func(gs []GroupMonitorFailures) []string {
		for _, g := range gs {
			if g.GroupID == 1 {
				return g.MonitorFails
			}
		}
		return nil
	}
	snap := failsOf(m.MonitorFailuresByGroup())
	want := []string{"ge-0-0-1", "ge-0-0-2", "ge-0-0-3"}
	if !reflect.DeepEqual(snap, want) {
		t.Fatalf("setup: RG1 failures %v, want %v", snap, want)
	}
	// The caller's side: writing into the snapshot must not reach the group.
	snap[0] = "caller-wrote-this"
	if got := failsOf(m.MonitorFailuresByGroup()); !reflect.DeepEqual(got, want) {
		t.Fatalf("a write into the returned slice changed the group's failures: %v", got)
	}
	// The manager's side: recovering one monitor (an in-place edit of the
	// group's slice) must not change a snapshot taken before it.
	before := failsOf(m.MonitorFailuresByGroup())
	m.SetMonitorWeight(1, "ge-0-0-1", false, 10)
	if !reflect.DeepEqual(before, want) {
		t.Fatalf("a monitor recovery rewrote an earlier snapshot: %v, want %v", before, want)
	}
}
