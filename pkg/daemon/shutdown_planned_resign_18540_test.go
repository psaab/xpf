package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #18540: an HA stop resigns every redundancy group to the peer, and does it
// at a specific point in the sequence:
//
//   - AFTER the Kea units stop (#6787): the resign promotes the peer, which
//     starts its own Kea, so a resign before the stop reopens the
//     two-DHCP-servers window #6787 closed;
//   - BEFORE d.cluster.Stop: the heartbeat sender carries the resign, and a
//     resign after Stop is refused (nothing would hear it).
//
// The witness reads the cluster manager's debt AT the Kea stop call, which is
// the ordering proof; an end-state check alone cannot see a resign that ran
// first.
func hasPlannedShutdownDebt18540(m *cluster.Manager) (all, any bool) {
	groups := m.GroupStates()
	all = len(groups) > 0
	for _, rg := range groups {
		found := false
		for _, f := range rg.MonitorFails {
			if f == cluster.PlannedShutdownMonitorIface {
				found = true
			}
		}
		if found {
			any = true
		} else {
			all = false
		}
		if found && rg.Weight != 0 {
			all = false
		}
	}
	return all, any
}

func TestHAShutdownResignsAfterKeaStopAndBeforeClusterStop18540(t *testing.T) {
	for _, tc := range []struct {
		name    string
		hitless bool
	}{
		{name: "fail-closed HA stop"},
		{name: "hitless-restart HA stop", hitless: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6, fake := seamTransitClose9686(t)
			hitless := ""
			if tc.hitless {
				hitless = "hitless-restart;"
			}
			store := commitShutdownFixture9686(t, `
chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "cyaLE6jUXcHqZBB6xSJP7CVc5S9dHRBAtF5vTBqFEss=";
        `+hitless+`
    }
}
`)
			mgr := cluster.NewManager(0, 1)
			mgr.UpdateConfig(&config.ClusterConfig{
				ControlInterface: "em0",
				RedundancyGroups: []*config.RedundancyGroup{
					{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
					{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
				},
			})
			t.Cleanup(mgr.Stop)
			// The resign needs a live peer (a lone node keeps ownership
			// through its stop; see the lone-node cell below).
			alivePeer18540(mgr)

			var (
				mu         sync.Mutex
				stopSeen   bool
				debtAtStop bool
			)
			r := newKeaRecorder6787()
			dir := t.TempDir()
			kea := dhcpserver.NewManagerForTesting(
				filepath.Join(dir, "kea-dhcp4.conf"),
				filepath.Join(dir, "kea-dhcp6.conf"),
				func(args ...string) error {
					if len(args) >= 1 && args[0] == "stop" {
						_, any := hasPlannedShutdownDebt18540(mgr)
						mu.Lock()
						stopSeen = true
						debtAtStop = debtAtStop || any
						mu.Unlock()
					}
					return r.run(args...)
				},
				r.isActive,
			)
			if err := kea.Apply(servingDHCPConfig6787()); err != nil {
				t.Fatalf("precondition Apply: %v", err)
			}

			daemonCtx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			dp := &transitWitnessDP{v4: v4, v6: v6, nft: fake}
			d := &Daemon{
				store:      store,
				applySem:   semaphore.NewWeighted(1),
				daemonCtx:  daemonCtx,
				dhcpServer: kea,
				cluster:    mgr,
			}
			d.setDataplane(dp)
			d.dataplaneArmed.Store(true)

			runShutdownFor6787(t, d)

			mu.Lock()
			defer mu.Unlock()
			if !stopSeen {
				t.Fatalf("fixture: Kea was never stopped, so the ordering witness saw nothing; calls=%v",
					strings.Join(r.snapshot(), " | "))
			}
			if debtAtStop {
				t.Error("the planned-shutdown resign ran BEFORE the Kea units stopped: the peer is " +
					"promoted (and starts its Kea) while this node still serves DHCP (#6787)")
			}
			if all, _ := hasPlannedShutdownDebt18540(mgr); !all {
				t.Error("the HA stop did not resign every redundancy group (weight 0, " +
					"__planned-shutdown__ debt) before the cluster manager stopped; the peer " +
					"waits for heartbeat loss instead (#18540)")
			}
		})
	}
}

// alivePeer18540 admits one heartbeat from node1 so the manager has a live
// peer, through the real admission handler.
func alivePeer18540(mgr *cluster.Manager) {
	mgr.HandlePeerHeartbeatForTesting(&cluster.HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []cluster.HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(cluster.StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(cluster.StateSecondary)},
		},
	})
}

// drainClusterEvents18540 pushes every queued cluster event through the
// daemon's REAL per-event handler (dispatchClusterEvent, the body of
// watchClusterEvents) synchronously, so the cell observes the handler's
// effect deterministically rather than racing the watcher goroutine.
func drainClusterEvents18540(t *testing.T, d *Daemon) int {
	t.Helper()
	n := 0
	var timer *time.Timer
	for {
		select {
		case ev := <-d.cluster.Events():
			timer = d.dispatchClusterEvent(d.daemonCtx, ev, timer)
			n++
		default:
			if timer != nil {
				timer.Stop()
			}
			return n
		}
	}
}

// #18540 review (MAJOR): on a LONE node the resign must not run. The
// cluster-event watcher binds to the never-cancelled daemon context, so it is
// live during runShutdownSequence, and an RG0 primary->secondary event reaches
// applyRG0OwnershipTransition -> ConfirmPendingOnDemotion (#4378). An operator
// who ran `commit confirmed` on a cluster whose peer is down, lost access, and
// restarted xpfd to get the rollback would instead find the commit made
// permanent (#12171's intent defeated).
//
// The positive control demotes RG0 through ordinary monitor debt and drives
// the same handler: the pending window IS confirmed there, which proves the
// instrument can see the confirm the resign must not cause.
func TestLoneNodeShutdownResignKeepsPendingCommitConfirmed18540(t *testing.T) {
	store, _ := newDemoteTestStore(t)
	mgr := cluster.NewManager(0, 1)
	t.Cleanup(mgr.Stop)
	// No control interface and no peer ever seen: the lone-node election
	// takes RG0 primary, as a cluster whose peer is down for maintenance.
	mgr.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
			{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	})
	daemonCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// The same daemon shape the #12171 RG0-demotion cells drive the real
	// handler with.
	d := &Daemon{
		applySem:                   semaphore.NewWeighted(1),
		daemonCtx:                  daemonCtx,
		cluster:                    mgr,
		vrrpMgr:                    vrrp.NewManager(),
		rgStates:                   make(map[int]*rgStateMachine),
		blackholeRoutes:            make(map[int][]netlink.Route),
		store:                      store,
		opts:                       Options{NoDataplane: true},
		failoverActuations:         failoverActuationRegistry{timeout: 2 * time.Second},
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
	drainClusterEvents18540(t, d) // the lone-node promotion events
	if !mgr.IsLocalPrimary(0) {
		t.Fatal("fixture: a lone node must own RG0")
	}
	if !store.IsConfirmPending() {
		t.Fatal("fixture: the commit-confirmed window must still be pending")
	}

	if got := mgr.ResignForPlannedShutdown(); got != 0 {
		t.Errorf("lone-node resign installed %d debts, want 0 (no peer to hand over to)", got)
	}
	handled := drainClusterEvents18540(t, d)
	if !mgr.IsLocalPrimary(0) {
		t.Error("a lone node's planned-shutdown resign demoted RG0")
	}
	if !store.IsConfirmPending() {
		t.Fatalf("a lone node's planned-shutdown resign confirmed the pending commit-confirmed "+
			"(%d cluster event(s) handled): the commit an operator is rebooting to roll back "+
			"became permanent", handled)
	}

	// Positive control: an ordinary RG0 demotion through the same handler
	// does confirm, so the "still pending" above is a measurement.
	mgr.SetMonitorWeight(0, "ge-0/0/9", true, 255)
	if drainClusterEvents18540(t, d) == 0 || mgr.IsLocalPrimary(0) {
		t.Fatal("control: a full monitor debt must demote RG0 and emit its event")
	}
	if store.IsConfirmPending() {
		t.Fatal("control: an RG0 demotion through dispatchClusterEvent must confirm the pending " +
			"window (#4378); without that the lone-node row above proves nothing")
	}
}

// Standalone has no peer and no cluster manager; the resign must not be
// attempted (and must not panic on the nil manager).
func TestStandaloneShutdownDoesNotResign18540(t *testing.T) {
	seamTransitClose9686(t)
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	daemonCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), daemonCtx: daemonCtx}
	runShutdownFor6787(t, d)
}
