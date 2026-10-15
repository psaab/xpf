package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
)

// TestReconcileStartupGoodbyeDoneEmptyAndActive13224 proves the cold-boot
// one-shot goodbye is marked done for an inactive RG with no RA interfaces
// and for an RG that boots Active (#13224/D4-06).
func TestReconcileStartupGoodbyeDoneEmptyAndActive13224(t *testing.T) {
	for _, tc := range []struct {
		name     string
		priority string
		hold     bool
	}{
		{name: "inactive empty RA", priority: "100", hold: true},
		{name: "boots active", priority: "200"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := testStoreWithSetConfig(t, []string{
				"set system dataplane-type userspace",
				"set chassis cluster cluster-id 1",
				"set chassis cluster node 0",
				"set chassis cluster authentication-key test-cluster-psk",
				"set chassis cluster redundancy-group 1 node 0 priority " + tc.priority,
				"set interfaces reth1 redundant-ether-options redundancy-group 1",
				"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
			})
			cm := cluster.NewManager(0, 1)
			cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
			if tc.hold {
				cm.SetKernelUpgradeHold("force secondary for test")
			}
			d := &Daemon{
				rgStates:        make(map[int]*rgStateMachine),
				blackholeRoutes: make(map[int][]netlink.Route),
				cluster:         cm,
				store:           store,
				vrrpMgr:         vrrp.NewManager(),
				ra:              &ra.Manager{},
				raApplyFn:       func([]*config.RAInterfaceConfig) error { return nil },
			}

			if tc.hold && cm.IsLocalPrimary(1) {
				t.Fatal("fixture: expected RG1 to be inactive")
			}
			if !tc.hold && !cm.IsLocalPrimary(1) {
				t.Fatal("fixture: expected RG1 to boot Active")
			}
			d.reconcileRGState()
			if !d.startupGoodbyeRA[1] {
				t.Fatalf("startupGoodbyeRA[1] remains false after first reconcile; startupGoodbyeNeeded=%v", d.startupGoodbyeNeeded(1))
			}
		})
	}
}
