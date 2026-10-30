package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcpserver"
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
