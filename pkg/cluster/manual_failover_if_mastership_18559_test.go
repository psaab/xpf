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
		if !errors.Is(err, ErrMastershipChanged) || errors.Is(err, ErrNoLongerPrimary) {
			t.Fatalf("err = %v, want ErrMastershipChanged (primary again), not ErrNoLongerPrimary", err)
		}
		if !m.IsLocalPrimary(1) {
			t.Fatal("a moved epoch still resigned the newer owner")
		}
	})
	t.Run("no longer primary refuses", func(t *testing.T) {
		m := newMgr()
		_, gen := m.LocalMastershipSnapshot(1)
		m.SetGroupStateForTesting(1, StateSecondary)
		if _, err := m.ManualFailoverIfMastership(1, gen); !errors.Is(err, ErrNoLongerPrimary) {
			t.Fatalf("err = %v, want ErrNoLongerPrimary", err)
		}
		if m.groups[1].ManualFailover {
			t.Fatal("a refused resign still set the manual-failover hold")
		}
	})
	// The pre-hook (the dataplane barrier) runs UNLOCKED. An election that
	// demotes and re-promotes this node while it runs is a newer ownership
	// incarnation; only the admission re-check after the hook, in the
	// critical section that installs the hold, can see it. The early check
	// above it passes here (the epoch is still the observed one), so these
	// rows fail if the post-hook check is removed (review T2).
	t.Run("ABA during the unlocked pre-hook refuses", func(t *testing.T) {
		m := newMgr()
		_, gen := m.LocalMastershipSnapshot(1)
		m.SetPreManualFailoverHook(func(rgID int) error {
			m.SetGroupStateForTesting(rgID, StateSecondary)
			m.SetGroupStateForTesting(rgID, StatePrimary)
			return nil
		})
		_, err := m.ManualFailoverIfMastership(1, gen)
		if !errors.Is(err, ErrMastershipChanged) || errors.Is(err, ErrNoLongerPrimary) {
			t.Fatalf("err = %v, want ErrMastershipChanged from the post-hook check", err)
		}
		if !m.IsLocalPrimary(1) || m.groups[1].ManualFailover {
			t.Fatal("an ownership round trip during the barrier still resigned the newer owner")
		}
	})
	t.Run("demotion during the unlocked pre-hook refuses", func(t *testing.T) {
		m := newMgr()
		_, gen := m.LocalMastershipSnapshot(1)
		m.SetPreManualFailoverHook(func(rgID int) error {
			m.SetGroupStateForTesting(rgID, StateSecondary)
			return nil
		})
		if _, err := m.ManualFailoverIfMastership(1, gen); !errors.Is(err, ErrNoLongerPrimary) {
			t.Fatalf("err = %v, want ErrNoLongerPrimary from the post-hook check", err)
		}
		if m.groups[1].ManualFailover || m.groups[1].State != StateSecondary {
			t.Fatalf("a demotion during the barrier was turned into a hold: state=%v manual=%v",
				m.groups[1].State, m.groups[1].ManualFailover)
		}
	})
}
