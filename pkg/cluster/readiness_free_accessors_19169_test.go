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
