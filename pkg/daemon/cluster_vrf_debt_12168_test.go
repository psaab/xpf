package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

// D1: #7901 restart debt across a bootstrap rollback. The first commit
// confirmed times out with no compiled rollback target (store promotes the
// empty tree, daemon relinquishes the cluster and owes one comms restart).
// A #11448 reassert tick then repairs a drifted management interface before
// the operator commits the corrected config with an identical transport key.
func bootstrapDebt12168(t *testing.T, reassert bool) int {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	lines := []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key bootstrap-debt-12168",
		"chassis cluster control-interface em0",
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, line := range lines {
		if err := store.SetFromInput(line); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	store.ExitConfigure()

	ops := &mgmtVRFBindRecorder11448{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{
		Name: config.ManagementVRFDeviceName, Index: 77}}
	ops.links["fxp0"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0", Index: 10, MasterIndex: 77}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := &Daemon{
		store:        store,
		networkd:     networkd.NewInDir(t.TempDir()),
		vrrpMgr:      vrrp.NewManager(),
		cluster:      cluster.NewManager(0, 1),
		daemonCtx:    ctx,
		opts:         Options{NoDataplane: true},
		applySem:     semaphore.NewWeighted(1),
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
		rgStates:     make(map[int]*rgStateMachine),
	}
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }
	t.Cleanup(func() {
		d.stopClusterComms()
		d.cluster.Stop()
	})
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	prevRoute := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return nil }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = prevRoute })

	d.startClusterComms(ctx)
	started := d.activeTransport()
	if started == (clusterTransportKey{}) {
		t.Fatal("premise: comms must publish a non-zero transport")
	}

	prev, ok := store.PromoteRollback(store.ConfirmGenForTesting())
	if !ok || prev != nil {
		t.Fatalf("premise: first-commit rollback must promote the empty tree (prev=%v ok=%v)", prev != nil, ok)
	}
	d.applyBodyForTest = func(*config.Config) {}
	d.bootstrapTeardownForTest = func() []bootstrapTeardownStep { return nil }
	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("enterBootstrapMode: %v", err)
	}
	t.Logf("bootstrap: active-config-nil=%v gen=%d active=%+v", store.ActiveConfig() == nil, warmVRFCommsGeneration12168(d), d.activeTransport())

	if reassert {
		ops.links["fxp0"].Attrs().MasterIndex = 0 // networkd reload / driver reset drift
		d.reassertMgmtVRFOnce(context.Background())
		t.Logf("reassert: binds=%v gen=%d active=%+v", ops.binds, warmVRFCommsGeneration12168(d), d.activeTransport())
	}

	restarts := 0
	d.startClusterCommsFn = func(context.Context) { restarts++ }
	d.routing = nil
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, line := range append(lines, "chassis cluster heartbeat-interval 250") {
		if err := store.SetFromInput(line); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("corrected commit: %v", err)
	}
	store.ExitConfigure()
	corrected := store.ActiveConfig()
	if got := clusterTransportFromConfig(corrected); got != started {
		t.Fatalf("premise: corrected transport must be identical: started=%+v corrected=%+v", started, got)
	}
	_ = d.applyTailReconciles(corrected, applyPhaseErrors{})
	return restarts
}

func TestBootstrapDebtControl12168(t *testing.T) {
	if got := bootstrapDebt12168(t, false); got != 1 {
		t.Errorf("control (no reassert): corrected commit restarts=%d, want 1", got)
	}
}

func TestBootstrapDebtSurvivesReassert12168(t *testing.T) {
	if got := bootstrapDebt12168(t, true); got != 1 {
		t.Errorf("#7901 debt consumed by the reassert: corrected commit restarts=%d, want 1 (comms stay DOWN)", got)
	}
}

func c2DebtStore12168(t *testing.T, clustered bool) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	lines := []string{"system host-name c2-debt-12168-16ch"}
	if clustered {
		lines = append(lines,
			"chassis cluster cluster-id 1",
			"chassis cluster node 0",
			"chassis cluster authentication-key c2-debt-12168-16ch",
			"chassis cluster control-interface fxp0",
			"chassis cluster peer-address 192.0.2.2")
	}
	for _, line := range lines {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	return store
}

func clusterCommsRestartOwed12168(d *Daemon) bool {
	d.clusterCommsMu.Lock()
	defer d.clusterCommsMu.Unlock()
	return d.clusterCommsRestartNeeded
}

// newClusterVRFDebtFixture12168 publishes the starting key through the same
// epoch-gated path as startClusterComms before optionally inducing kernel drift.
func newClusterVRFDebtFixture12168(t *testing.T, storeMode string, bootstrap, staleActive, drift bool) (*Daemon, *mgmtVRFBindRecorder11448, *config.Config, uint64) {
	t.Helper()
	var store *configstore.Store
	switch storeMode {
	case "nil":
	case "no-cluster":
		store = c2DebtStore12168(t, false)
	case "cluster":
		store = c2DebtStore12168(t, true)
	default:
		t.Fatalf("unknown store mode %q", storeMode)
	}
	seedStore := store
	if seedStore == nil || seedStore.ActiveConfig().Chassis.Cluster == nil {
		seedStore = c2DebtStore12168(t, true)
	}
	seedConfig := seedStore.ActiveConfig()
	activeConfig := seedConfig
	if staleActive {
		stale := *seedConfig
		chassis := stale.Chassis
		clusterConfig := *seedConfig.Chassis.Cluster
		clusterConfig.PeerAddress = "192.0.2.99"
		chassis.Cluster = &clusterConfig
		stale.Chassis = chassis
		activeConfig = &stale
	}

	ops := &mgmtVRFBindRecorder11448{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{
		Name: config.ManagementVRFDeviceName, Index: 77}}
	ops.links["fxp0"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name: "fxp0", Index: 10, MasterIndex: 77}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := &Daemon{
		store:        store,
		networkd:     networkd.NewInDir(t.TempDir()),
		vrrpMgr:      vrrp.NewManager(),
		cluster:      cluster.NewManager(0, 1),
		daemonCtx:    ctx,
		opts:         Options{NoDataplane: true},
		applySem:     semaphore.NewWeighted(1),
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
		rgStates:     make(map[int]*rgStateMachine),
	}
	t.Cleanup(func() {
		d.stopClusterComms()
		d.cluster.Stop()
	})
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	activeKey := d.clusterTransportForConfig(activeConfig)
	if activeKey == (clusterTransportKey{}) {
		t.Fatal("fixture must publish a non-zero transport key")
	}
	_, gen, _ := d.beginClusterCommsEpoch(ctx)
	if !d.setActiveTransportIfCurrent(gen, activeKey) {
		t.Fatal("fixture could not publish the initial transport key")
	}
	if drift {
		ops.links["fxp0"].Attrs().MasterIndex = 0
	}
	if bootstrap {
		d.bootstrapMode.Store(true)
	}
	return d, ops, seedConfig, gen
}

func TestReassertBackgroundTransportGuards12168(t *testing.T) {
	for _, tc := range []struct {
		name        string
		storeMode   string
		bootstrap   bool
		staleActive bool
	}{
		{name: "nil config", storeMode: "nil"},
		{name: "no cluster", storeMode: "no-cluster"},
		{name: "bootstrap", storeMode: "cluster", bootstrap: true, staleActive: true},
		{name: "valid config preserves debt", storeMode: "cluster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, ops, _, _ := newClusterVRFDebtFixture12168(t, tc.storeMode, tc.bootstrap, tc.staleActive, true)
			d.markClusterCommsRestartNeeded()
			starts := 0
			d.startClusterCommsFn = func(context.Context) { starts++ }
			routes := 0
			prevRoute := mgmtVRFRouteReconcileFn
			mgmtVRFRouteReconcileFn = func(*Daemon) error {
				routes++
				return nil
			}
			t.Cleanup(func() { mgmtVRFRouteReconcileFn = prevRoute })

			d.reassertMgmtVRFOnce(context.Background())

			if len(ops.binds) != 1 || ops.binds[0] != "fxp0->vrf-mgmt" {
				t.Fatalf("reassert did not repair fxp0 in %q: binds=%v", tc.name, ops.binds)
			}
			if got := ops.links["fxp0"].Attrs().MasterIndex; got != 77 {
				t.Fatalf("fxp0 master after reassert = %d, want 77", got)
			}
			if routes != 1 {
				t.Fatalf("management routes refreshed %d times, want once", routes)
			}
			if starts != 0 {
				t.Fatalf("background transport reconcile started comms %d times, want none", starts)
			}
			if !clusterCommsRestartOwed12168(d) {
				t.Fatal("reassert consumed #7901 restart debt")
			}
		})
	}
}

func TestReassertWiresStickyClusterTransportRetry12168(t *testing.T) {
	d, _, cfg, gen := newClusterVRFDebtFixture12168(t, "cluster", false, false, false)
	d.noteClusterTransportBinding(gen, "")
	if !d.activeTransport().BindingChanged {
		t.Fatal("fixture failed to mark the current transport binding sticky")
	}

	starts := 0
	// startClusterComms publishes a fresh key for each replacement epoch;
	// doing the same keeps a second reassert pass stable.
	d.startClusterCommsFn = func(ctx context.Context) {
		starts++
		_, nextGen, _ := d.beginClusterCommsEpoch(ctx)
		if !d.setActiveTransportIfCurrent(nextGen, d.clusterTransportForConfig(cfg)) {
			t.Errorf("replacement comms epoch %d failed to publish its transport", nextGen)
		}
	}
	routes := 0
	prevRoute := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error {
		routes++
		return nil
	}
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = prevRoute })

	beforeGeneration := warmVRFCommsGeneration12168(d)
	d.reassertMgmtVRFOnce(context.Background())
	if starts != 1 {
		t.Fatalf("sticky transport binding triggered %d comms restarts, want exactly one", starts)
	}
	if d.activeTransport().BindingChanged {
		t.Fatal("replacement comms epoch retained the previous epoch's binding-change flag")
	}
	if routes != 0 {
		t.Fatalf("binding-only reassert refreshed routes %d times, want no route work", routes)
	}
	generation := warmVRFCommsGeneration12168(d)
	if generation == beforeGeneration {
		t.Fatalf("sticky binding reassert did not advance the comms epoch: %d", generation)
	}
	active := d.activeTransport()

	d.reassertMgmtVRFOnce(context.Background())
	if starts != 1 || warmVRFCommsGeneration12168(d) != generation || d.activeTransport() != active {
		t.Fatalf("stable reassert restarted or rewrote the replacement epoch: starts=%d gen=%d->%d key=%+v->%+v",
			starts, generation, warmVRFCommsGeneration12168(d), active, d.activeTransport())
	}
	if routes != 0 {
		t.Fatalf("stable binding-only reassert refreshed routes %d times, want none", routes)
	}
}
