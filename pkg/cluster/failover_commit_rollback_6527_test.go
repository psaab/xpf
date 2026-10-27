package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #6527: commitRequestedPeerFailover arms the transfer override BEFORE it
// runs the election, so an election that declines to promote this node must
// roll the override back. The BATCH request path already did
// (abortRequestedPeerFailoverBatch); the single-RG path returned the error bare
// and leaked the override.
//
// The property under test is the AGREEMENT between the two request paths, not
// either copy: both must leave the override map empty, the peer's advertised
// state restored, and this node out of primary — and must keep it that way
// once the transient that failed the election clears. Binding only the
// single-RG path would let a future edit break the batch half silently.
//
// The election is failed the way production fails it: a monitored interface
// goes down while the failover REQUEST is in flight on the fabric.
// RequestPeerFailover releases m.mu around peerFailoverFn, and
// commitRequestedPeerFailover's re-check is IsReadyForTakeover, which reads
// Ready/ReadySince only — it does not look at weight. So a monitor debt that
// lands in that window passes the readiness gate and then loses the election
// on electRG's "Local weight 0" arm.
func TestRequestPeerFailoverCommitFailureRollsBackOverrideOnBothPaths(t *testing.T) {
	const (
		reqID    = 4242
		monIface = "ge-0/0/9"
	)

	cases := []struct {
		name    string
		rgIDs   []int
		arm     func(m *Manager, t *testing.T, onRequest func())
		request func(m *Manager, rgIDs []int) error
	}{
		{
			name:  "single-RG",
			rgIDs: []int{0},
			arm: func(m *Manager, t *testing.T, onRequest func()) {
				m.SetPeerFailoverFunc(func(int) (uint64, error) {
					onRequest()
					return reqID, nil
				})
				m.SetPeerFailoverCommitFunc(func(int, uint64) error {
					t.Error("peer transfer-commit must not be sent after the local commit lost the election")
					return nil
				})
			},
			request: func(m *Manager, rgIDs []int) error { return m.RequestPeerFailover(rgIDs[0]) },
		},
		{
			// RequestPeerFailoverBatch delegates a single ID back to
			// RequestPeerFailover, so the batch leg needs two RGs to reach
			// commitRequestedPeerFailoverBatch at all.
			name:  "batch",
			rgIDs: []int{0, 1},
			arm: func(m *Manager, t *testing.T, onRequest func()) {
				m.SetPeerFailoverBatchFunc(func([]int) (uint64, error) {
					onRequest()
					return reqID, nil
				})
				m.SetPeerFailoverCommitBatchFunc(func([]int, uint64) error {
					t.Error("peer transfer-commit must not be sent after the local commit lost the election")
					return nil
				})
			},
			request: func(m *Manager, rgIDs []int) error { return m.RequestPeerFailoverBatch(rgIDs) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(0, 1)

			groups := make([]*config.RedundancyGroup, 0, len(tc.rgIDs))
			hbGroups := make([]HeartbeatGroup, 0, len(tc.rgIDs))
			for _, rgID := range tc.rgIDs {
				groups = append(groups, makeRG(rgID, true, map[int]int{0: 100, 1: 200},
					&config.InterfaceMonitor{Interface: monIface, Weight: 255}))
				hbGroups = append(hbGroups, HeartbeatGroup{
					GroupID: uint8(rgID), Priority: 200, Weight: 255, State: uint8(StatePrimary),
				})
			}
			m.UpdateConfig(makeConfig(groups...))
			drainClusterEvents6527(m)

			peerPrimary := &HeartbeatPacket{NodeID: 1, ClusterID: 1, Groups: hbGroups}
			m.handlePeerHeartbeat(peerPrimary)

			m.mu.Lock()
			for _, rgID := range tc.rgIDs {
				m.groups[rgID].Ready = true
				m.groups[rgID].ReadySince = time.Now().Add(-m.takeoverHoldTime - time.Second)
				m.groups[rgID].ReadinessReasons = nil
			}
			m.mu.Unlock()
			drainClusterEvents6527(m)

			m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
			m.SetLocalTransferCommitReadyHook(func([]int) error {
				t.Error("local transfer-commit-ready hook must not run after the commit lost the election")
				return nil
			})
			tc.arm(m, t, func() {
				// The monitored link drops while the request is on the wire.
				// SetMonitorWeight is the production entry point
				// (pkg/routing/monitor.go and the interface-monitor poll both
				// call it); it takes m.mu itself, which RequestPeerFailover
				// has released for exactly this window.
				for _, rgID := range tc.rgIDs {
					m.SetMonitorWeight(rgID, monIface, true, 255)
				}
			})

			if err := tc.request(m, tc.rgIDs); err == nil {
				t.Fatal("expected the transfer commit to fail the election with local weight 0")
			}

			m.mu.Lock()
			leakedOverride := len(m.transferOverrides)
			m.mu.Unlock()
			if leakedOverride != 0 {
				t.Errorf("transferOverrides has %d leaked entries after a failed commit, want 0",
					leakedOverride)
			}

			peers := m.PeerGroupStates()
			for _, rgID := range tc.rgIDs {
				if got := peers[rgID].State; got != StatePrimary {
					t.Errorf("rg %d peer state = %s after rollback, want primary (the snapshot taken before the override)",
						rgID, got)
				}
				if m.IsLocalPrimary(rgID) {
					t.Errorf("rg %d is locally primary while the peer is still primary — dual-primary", rgID)
				}
			}

			// The monitored link recovers. A leaked override survives every
			// heartbeat (applyTransferCommitOverridesOnPeerStateLocked has no
			// expiry for it), so this is where the leak turns into a
			// PERSISTENT dual-primary rather than a transient one: electRG
			// takes the "Peer transfer out" arm before it ever reaches the
			// preempt comparison the peer would win.
			for _, rgID := range tc.rgIDs {
				m.SetMonitorWeight(rgID, monIface, false, 0)
			}
			m.handlePeerHeartbeat(peerPrimary)

			peers = m.PeerGroupStates()
			for _, rgID := range tc.rgIDs {
				if m.IsLocalPrimary(rgID) {
					t.Errorf("rg %d self-promoted to primary after weight recovery — the leaked override made the dual-primary persistent",
						rgID)
				}
				if got := peers[rgID].State; got != StatePrimary {
					t.Errorf("rg %d peer state = %s after weight recovery, want primary (a live heartbeat must not be overridden)",
						rgID, got)
				}
			}
		})
	}
}

// drainClusterEvents6527 empties the manager event channel without blocking. UpdateConfig
// emits one event per created RG and the election emits more, and the count is
// not what this test is about.
func drainClusterEvents6527(m *Manager) {
	for {
		select {
		case <-m.Events():
		default:
			return
		}
	}
}
