package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
)

// snmpVRFRecreateFixture16626 wires a daemon whose SNMP agent is pinned to
// vrf-mgmt (index 77) and whose fake kernel can delete + re-create that
// device at a new ifindex, exactly as `ip link del vrf-mgmt` followed by
// the #15223 reassert re-create does.
type snmpVRFRecreateFixture16626 struct {
	d   *Daemon
	ops *mgmtVRFBindRecorder11448
	rec *snmpServeRecorder

	mu sync.Mutex
	// liveIndex is the ifindex fabricLinkByName reports for vrf-mgmt;
	// 0 means the device is absent.
	liveIndex int
}

func newSNMPVRFRecreateFixture16626(t *testing.T) *snmpVRFRecreateFixture16626 {
	t.Helper()
	f := &snmpVRFRecreateFixture16626{liveIndex: 77}
	f.ops = &mgmtVRFBindRecorder11448{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	f.ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{
		Name: config.ManagementVRFDeviceName, Index: 77,
	}}
	// Management member already correctly enslaved to the original VRF.
	f.ops.links["fxp0"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name: "fxp0", Index: 10, MasterIndex: 77,
	}}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	sets := "set snmp community public authorization read-only\n" +
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24\n"
	if _, err := store.LoadSet(sets); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !snmpEnabled(cfg) {
		t.Fatal("fixture: committed config must enable SNMP")
	}
	if got := snmpVRFDeviceForConfig(cfg); got != config.ManagementVRFDeviceName {
		t.Fatalf("fixture: SNMP VRF device = %q, want %q", got, config.ManagementVRFDeviceName)
	}

	f.rec = &snmpServeRecorder{}
	installFakeNetworkctl(t)
	f.d = &Daemon{
		applySem:         semaphore.NewWeighted(1),
		vrrpMgr:          vrrp.NewManager(),
		store:            store,
		opts:             Options{NoDataplane: true},
		daemonCtx:        context.Background(),
		snmpBootReady:    true,
		snmpServe:        f.rec.serve,
		snmpBootsPath:    filepath.Join(t.TempDir(), "engineboots"),
		snmpEngineIDPath: filepath.Join(t.TempDir(), "snmp-engine-id"),
		routing:          routing.NewManagerWithLinkOpsForTest(f.ops),
		linkStateSubscribe: func(_ chan<- netlink.LinkUpdate, done <-chan struct{}, _ func(error)) error {
			go func() { <-done }()
			return nil
		},
		linkStateList: func() ([]netlink.Link, error) { return nil, nil },
	}
	f.d.setDataplane(&runtimeOnlyApplyTestDP{})
	f.d.linkByNameFn = func(name string) (netlink.Link, error) {
		if name == config.ManagementVRFDeviceName {
			// After the routing fake re-creates the device its map entry
			// exists (index 0); report the kernel-assigned live index.
			if _, ok := f.ops.links[name]; ok {
				f.mu.Lock()
				idx := f.liveIndex
				f.mu.Unlock()
				if idx == 0 {
					idx = 77
				}
				return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: name, Index: idx}}, nil
			}
			return nil, netlink.LinkNotFoundError{}
		}
		return f.ops.LinkByName(name)
	}
	f.d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	t.Cleanup(f.d.teardownSNMP)

	// Start the agent through the real reconcile path (pinned to vrf-mgmt).
	if !f.d.reconcileSNMP(cfg) {
		t.Fatal("fixture: initial reconcileSNMP did not start the agent")
	}
	if got := f.rec.count(); got != 1 {
		t.Fatalf("fixture: SNMP starts = %d, want 1", got)
	}
	if f.d.snmpVRFIndex != 77 {
		t.Fatalf("fixture: recorded SNMP VRF ifindex = %d, want 77", f.d.snmpVRFIndex)
	}
	return f
}

// deleteAndRecreateVRF simulates `ip link del vrf-mgmt` and lets the
// routing fake re-create it: LinkAdd in the fake stores the link object
// (index 0, as netlink leaves a freshly added link), while the daemon's
// link seam reports the kernel-assigned new index 99.
func (f *snmpVRFRecreateFixture16626) deleteVRF() {
	f.mu.Lock()
	f.liveIndex = 0
	f.mu.Unlock()
	delete(f.ops.links, config.ManagementVRFDeviceName)
}

func (f *snmpVRFRecreateFixture16626) recreateAt(index int) {
	f.mu.Lock()
	f.liveIndex = index
	f.mu.Unlock()
}

// TestReassertRecreatedMgmtVRFRestartsSNMP16626 is the #16626 RED-on-revert
// cell: after vrf-mgmt is deleted and re-created by one reassert tick
// (new ifindex, same name), the running SNMP listener — bound by
// SO_BINDTODEVICE to the dead ifindex — must be restarted in that tick.
//
// Mutation check: remove the restartSNMPForVRFRecreate call (or the
// snmpVRFIndex comparison in reconcileSNMP) and this test fails — the
// serve count stays 1 and the agent pointer is unchanged, i.e. the
// listener stays deaf until a commit or daemon restart.
func TestReassertRecreatedMgmtVRFRestartsSNMP16626(t *testing.T) {
	f := newSNMPVRFRecreateFixture16626(t)
	first := f.d.snmpAgent

	// Out-of-band deletion, then the routing fake re-creates the device
	// during the tick; the kernel assigns ifindex 99.
	f.deleteVRF()
	f.recreateAt(99)
	// Keep the member enslaved to the new index so the tick needs no
	// member re-bind: this isolates the SNMP defect from the #11448
	// re-bind path (control: no drift, yet SNMP must still restart).
	f.ops.links["fxp0"].Attrs().MasterIndex = 99

	prevRoute := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return nil }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = prevRoute })

	f.d.reassertMgmtVRFOnce(context.Background())

	if _, ok := f.ops.links[config.ManagementVRFDeviceName]; !ok {
		t.Fatal("reassert tick did not re-create vrf-mgmt (premise broken)")
	}
	if got := f.rec.count(); got != 2 {
		t.Fatalf("SNMP listener starts after VRF re-create = %d, want 2 (restart in the same tick)", got)
	}
	if f.d.snmpAgent == first || f.d.snmpAgent == nil {
		t.Fatal("re-created VRF kept the old SNMP agent bound to the dead ifindex")
	}
	if f.d.snmpVRFIndex != 99 {
		t.Fatalf("recorded SNMP VRF ifindex after restart = %d, want 99", f.d.snmpVRFIndex)
	}

	// Control: a second tick with the device healthy must NOT bounce again.
	f.d.reassertMgmtVRFOnce(context.Background())
	if got := f.rec.count(); got != 2 {
		t.Fatalf("healthy second tick restarted SNMP: starts = %d, want 2", got)
	}
}

// TestReconcileSNMPRecreatedVRFIndexRestarts16626 pins the second acceptance
// arm: even without a reassert tick, the next commit's reconcileSNMP must
// detect the ifindex change under an unchanged name/hash and restart,
// while an unchanged ifindex stays an idempotent no-op (positive control).
func TestReconcileSNMPRecreatedVRFIndexRestarts16626(t *testing.T) {
	f := newSNMPVRFRecreateFixture16626(t)
	cfg := f.d.store.ActiveConfig()
	first := f.d.snmpAgent

	// Positive control: same name, same ifindex, same hash ⇒ no bounce.
	if f.d.reconcileSNMP(cfg) {
		t.Fatal("unchanged reconcile reported a change (control broken)")
	}
	if got := f.rec.count(); got != 1 || f.d.snmpAgent != first {
		t.Fatalf("unchanged reconcile bounced SNMP: starts=%d sameAgent=%v, want 1/true",
			got, f.d.snmpAgent == first)
	}

	// Device re-created at a new ifindex under the same name.
	f.recreateAt(99)
	if !f.d.reconcileSNMP(cfg) {
		t.Fatal("reconcile after VRF re-create did not restart the SNMP listener")
	}
	if got := f.rec.count(); got != 2 {
		t.Fatalf("SNMP starts after ifindex change = %d, want 2", got)
	}
	if f.d.snmpAgent == first {
		t.Fatal("ifindex change kept the old SNMP agent")
	}
	if f.d.snmpVRFIndex != 99 {
		t.Fatalf("recorded SNMP VRF ifindex = %d, want 99", f.d.snmpVRFIndex)
	}

	// And it settles: the following identical reconcile is a no-op again.
	second := f.d.snmpAgent
	if f.d.reconcileSNMP(cfg) {
		t.Fatal("post-restart identical reconcile reported a change")
	}
	if got := f.rec.count(); got != 2 || f.d.snmpAgent != second {
		t.Fatalf("post-restart reconcile bounced SNMP: starts=%d sameAgent=%v, want 2/true",
			got, f.d.snmpAgent == second)
	}
}

// TestReassertRecreatedMgmtVRFLeavesMainTableSNMPAlone16626 is the
// scope control: when SNMP runs on the main table (no management VRF
// bind), a vrf-mgmt re-create must not bounce the listener.
func TestReassertRecreatedMgmtVRFLeavesMainTableSNMPAlone16626(t *testing.T) {
	f := newSNMPVRFRecreateFixture16626(t)
	// Simulate a main-table listener: device/index cleared as
	// startSNMPLocked records them for the empty-device case.
	f.d.snmpReconMu.Lock()
	f.d.snmpVRFDevice = ""
	f.d.snmpVRFIndex = 0
	f.d.snmpReconMu.Unlock()

	f.deleteVRF()
	f.recreateAt(99)
	f.ops.links["fxp0"].Attrs().MasterIndex = 99
	prevRoute := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return nil }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = prevRoute })

	f.d.reassertMgmtVRFOnce(context.Background())

	if got := f.rec.count(); got != 1 {
		t.Fatalf("main-table SNMP listener bounced on VRF re-create: starts = %d, want 1", got)
	}
}
