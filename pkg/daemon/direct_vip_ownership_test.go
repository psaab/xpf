package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// TestDirectVIPOwnershipDesired pins the direct-VIP ownership predicate
// through shouldOwnDirectVIPs itself: only a locally PRIMARY group owns its
// VIPs. (#19169 moved the read from GroupState to LocalGroupPrimary, which
// runs no transfer-readiness callback; the predicate is unchanged.)
func TestDirectVIPOwnershipDesired(t *testing.T) {
	tests := []struct {
		name       string
		localState cluster.NodeState
		want       bool
	}{
		{"local secondary never owns VIPs", cluster.StateSecondary, false},
		{"local primary owns VIPs (peer lost or dual-active resolution)", cluster.StatePrimary, true},
		{"local secondary hold does not own VIPs", cluster.StateSecondaryHold, false},
		{"local lost does not own VIPs", cluster.StateLost, false},
		{"local disabled does not own VIPs", cluster.StateDisabled, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := cluster.NewManager(0, 1)
			cm.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
				{ID: 1, NodePriorities: map[int]int{0: 200}},
			}})
			cm.SetGroupStateForTesting(1, tt.localState)
			d := &Daemon{cluster: cm}
			if got := d.shouldOwnDirectVIPs(1); got != tt.want {
				t.Fatalf("shouldOwnDirectVIPs with local state %s = %v, want %v",
					tt.localState, got, tt.want)
			}
		})
	}
	t.Run("an unknown group owns nothing", func(t *testing.T) {
		cm := cluster.NewManager(0, 1)
		cm.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 200}},
		}})
		cm.SetGroupStateForTesting(1, cluster.StatePrimary)
		if (&Daemon{cluster: cm}).shouldOwnDirectVIPs(7) {
			t.Fatal("shouldOwnDirectVIPs(7) = true for a group the cluster does not know")
		}
	})
}

func TestApplyDirectVIPOwnershipRemovesStaleVIPsWithoutEdge(t *testing.T) {
	var removeCalls int
	d := &Daemon{
		directVIPOwned: make(map[int]bool),
		directRemoveVIPsFn: func(rgID int) int {
			if rgID != 1 {
				t.Fatalf("unexpected rgID %d", rgID)
			}
			removeCalls++
			return 1
		},
		directRemoveStableLLFn: func(rgID int) {
			if rgID != 1 {
				t.Fatalf("unexpected stable-LL rgID %d", rgID)
			}
		},
	}

	d.applyDirectVIPOwnership(1, false, "test")

	if removeCalls != 1 {
		t.Fatalf("expected one VIP removal attempt, got %d", removeCalls)
	}
	if d.directVIPOwnershipApplied(1) {
		t.Fatal("expected direct VIP ownership to remain false")
	}
}
