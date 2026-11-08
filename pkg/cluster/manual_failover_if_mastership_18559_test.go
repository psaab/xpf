package cluster

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18559: ManualFailoverIfMastership resigns only while this node is still
// primary at the ownership epoch the caller observed. A demotion and
// re-promotion in between (a newer, completed move) must fail the fence and
// leave the newer owner untouched.
func TestManualFailoverIfMastership18559(t *testing.T) {
	newMgr := func() *Manager {
		m := NewManager(0, 22)
		m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
		}})
		m.SetGroupStateForTesting(1, StatePrimary)
		return m
	}
	t.Run("same epoch resigns", func(t *testing.T) {
		m := newMgr()
		primary, gen := m.LocalMastershipSnapshot(1)
		if !primary {
			t.Fatal("setup: not primary")
		}
		if _, err := m.ManualFailoverIfMastership(1, gen); err != nil {
			t.Fatalf("fenced resign at the observed epoch: %v", err)
		}
		if m.IsLocalPrimary(1) {
			t.Fatal("the fenced resign did not demote")
		}
	})
	t.Run("moved epoch refuses", func(t *testing.T) {
		m := newMgr()
		_, gen := m.LocalMastershipSnapshot(1)
		m.SetGroupStateForTesting(1, StateSecondary)
		m.SetGroupStateForTesting(1, StatePrimary)
		_, err := m.ManualFailoverIfMastership(1, gen)
		if !errors.Is(err, ErrMastershipChanged) {
			t.Fatalf("err = %v, want ErrMastershipChanged", err)
		}
		if !m.IsLocalPrimary(1) {
			t.Fatal("a moved epoch still resigned the newer owner")
		}
	})
	t.Run("no longer primary refuses", func(t *testing.T) {
		m := newMgr()
		_, gen := m.LocalMastershipSnapshot(1)
		m.SetGroupStateForTesting(1, StateSecondary)
		if _, err := m.ManualFailoverIfMastership(1, gen); !errors.Is(err, ErrMastershipChanged) {
			t.Fatalf("err = %v, want ErrMastershipChanged", err)
		}
	})
}
