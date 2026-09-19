package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// TestHandleClusterEventPreemptDualActiveWinSchedulesDirectAnnounce is the
// daemon-side half of #10426. The election winner event has no state change,
// so only the DualActiveWin branch can schedule the direct-VIP GARP/NA burst.
// Keep the direct sender as a seam and use a zero-delay schedule so this
// verifies the complete event-to-announce path without raw-socket I/O.
func TestHandleClusterEventPreemptDualActiveWinSchedulesDirectAnnounce(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key test-10426-psk",
		"chassis cluster no-reth-vrrp",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit direct-mode cluster config: %v", err)
	}

	state := newRGStateMachine()
	state.SetCluster(true)
	announces := make(chan int, 1)
	d := &Daemon{
		store:                 store,
		rgStates:              map[int]*rgStateMachine{0: state},
		directAnnounceSchedule: []time.Duration{0},
		directSendGARPsFn: func(rgID int) {
			announces <- rgID
		},
	}

	d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID:       0,
		OldState:      cluster.StatePrimary,
		NewState:      cluster.StatePrimary,
		DualActiveWin: true,
	}, nil)

	select {
	case rgID := <-announces:
		if rgID != 0 {
			t.Fatalf("DualActiveWin scheduled announce for RG %d, want RG 0", rgID)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("DualActiveWin did not schedule the direct-VIP GARP/NA burst")
	}
}
