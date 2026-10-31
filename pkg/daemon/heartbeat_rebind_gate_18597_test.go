package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/vishvananda/netlink"
)

// #18597: every commit restarted the cluster heartbeat after the management-VRF
// rebind, because networkd detached em0 from vrf-mgmt on every reconfigure and
// the rebind had to move it back. networkd now renders KeepMaster=yes, so the
// rebind is a no-op for a link that stayed bound, and the restart is gated on
// the control link actually having been moved.
//
// FAIL-ON-REVERT: restore the unconditional restart (call
// restartHeartbeatAfterRebindForCurrentCommsEpoch directly, or make
// controlLinkMovedSinceLastCheck return true) and the steady-state half reds
// with three restarts for three commits; drop the restart on a real move and
// the drift half reds with zero.

func controlLinkCfg18597(control string) *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: control}
	return cfg
}

func newHeartbeatGateDaemon18597(t *testing.T) (*Daemon, *mgmtVRFBindRecorder11448, *atomic.Int32) {
	t.Helper()
	// em0 and fxp0 are already vrf-mgmt members (index 77), as they are on a
	// running cluster before every commit.
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 77, "fxp0": 77})
	mgr := cluster.NewManager(0, 1)
	d.cluster = mgr
	// A current comms epoch: the restart wrapper is epoch-fenced and does
	// nothing without one, which would make the zero-restart cells vacuous.
	// TestControlLinkMovedBackIntoVRFRestartsHeartbeatOnce18597 is the
	// positive control that this fixture CAN restart.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d.clusterCommsCtx, d.clusterCommsGen = ctx, 1
	t.Cleanup(mgr.Stop)
	if err := mgr.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("start heartbeat: %v", err)
	}
	var restarts atomic.Int32
	// RestartHeartbeat calls this once before it tears the sockets down.
	mgr.SetHeartbeatRestartNotifyFunc(func() { restarts.Add(1) })
	return d, ops, &restarts
}

// commitBindPasses18597 runs the two management-VRF bind passes one apply
// runs, each followed by the gate exactly as the apply path calls it: the
// pre-networkd pass (applyVRFReconcile, retryOwed=false) and the
// authoritative post-networkd rebind (retryOwed=true).
func commitBindPasses18597(t *testing.T, d *Daemon, cfg *config.Config) {
	t.Helper()
	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		t.Fatalf("pre-networkd bind: %v", err)
	}
	if err := d.restartHeartbeatIfControlLinkMoved(cfg, false); err != nil {
		t.Fatalf("pre-networkd gate: %v", err)
	}
	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		t.Fatalf("post-networkd rebind: %v", err)
	}
	if err := d.restartHeartbeatIfControlLinkMoved(cfg, true); err != nil {
		t.Fatalf("post-networkd gate: %v", err)
	}
}

func TestCommitThatLeavesControlLinkInVRFKeepsHeartbeat18597(t *testing.T) {
	d, ops, restarts := newHeartbeatGateDaemon18597(t)
	cfg := controlLinkCfg18597("em0")

	for i := 0; i < 3; i++ {
		commitBindPasses18597(t, d, cfg)
	}
	if len(ops.binds) != 0 {
		t.Fatalf("precondition: rebind moved already-bound links: %v", ops.binds)
	}
	if got := restarts.Load(); got != 0 {
		t.Fatalf("three commits that left em0 in vrf-mgmt restarted the heartbeat %d times, want 0 "+
			"(every restart rebuilds the heartbeat sockets and arms a 5s restart grace; #18597)", got)
	}
}

func TestControlLinkMovedBackIntoVRFRestartsHeartbeatOnce18597(t *testing.T) {
	d, ops, restarts := newHeartbeatGateDaemon18597(t)
	cfg := controlLinkCfg18597("em0")
	commitBindPasses18597(t, d, cfg)

	// em0 leaves vrf-mgmt (vrf-mgmt recreated, or an out-of-band nomaster):
	// the sockets bound through it are stale and the next bind pass moves it.
	link, err := ops.LinkByName("em0")
	if err != nil {
		t.Fatalf("lookup em0: %v", err)
	}
	link.Attrs().MasterIndex = 0
	commitBindPasses18597(t, d, cfg)
	if len(ops.binds) != 1 || ops.binds[0] != "em0->"+config.ManagementVRFDeviceName {
		t.Fatalf("precondition: binds = %v, want exactly em0 moved back", ops.binds)
	}
	if got := restarts.Load(); got != 1 {
		t.Fatalf("moving em0 back into vrf-mgmt restarted the heartbeat %d times, want exactly 1 "+
			"(the pre-networkd pass restarts right after the move; the post-networkd pass sees no new move)", got)
	}

	// A later unrelated commit moves nothing and restarts nothing.
	commitBindPasses18597(t, d, cfg)
	if got := restarts.Load(); got != 1 {
		t.Fatalf("an unrelated commit after the move restarted the heartbeat again: %d restarts, want 1", got)
	}
}

// A move of some OTHER management link (fab0 recreated after XSK bind, fxp0
// drifting) does not touch the sockets bound through the control link.
func TestNonControlLinkMoveKeepsHeartbeat18597(t *testing.T) {
	d, ops, restarts := newHeartbeatGateDaemon18597(t)
	cfg := controlLinkCfg18597("em0")
	link, err := ops.LinkByName("fxp0")
	if err != nil {
		t.Fatalf("lookup fxp0: %v", err)
	}
	link.Attrs().MasterIndex = 0
	commitBindPasses18597(t, d, cfg)
	if len(ops.binds) != 1 || ops.binds[0] != "fxp0->"+config.ManagementVRFDeviceName {
		t.Fatalf("precondition: binds = %v, want exactly fxp0 moved", ops.binds)
	}
	if got := restarts.Load(); got != 0 {
		t.Fatalf("an fxp0 move restarted the heartbeat %d times, want 0", got)
	}
}

// The restart follows the move inside the pre-networkd pass itself, not at the
// end of the apply: drive the real applyVRFReconcile (ReconcileVRFs, the
// step-0b bind loop, publish) with em0 detached and observe the restart before
// any post-networkd step runs. A restart deferred to step 2.7 would leave the
// sockets stale for the whole networkd + dataplane apply, the window in which
// neither RestartHeartbeat's peer keepalive nor its grace covers anything.
func TestPreNetworkdBindRestartsHeartbeatRightAfterTheMove18597(t *testing.T) {
	d, ops, restarts := newHeartbeatGateDaemon18597(t)
	vrf, err := ops.LinkByName(config.ManagementVRFDeviceName)
	if err != nil {
		t.Fatalf("lookup vrf-mgmt: %v", err)
	}
	// Match the desired table so ReconcileVRFs adopts the device as-is.
	vrf.(*netlink.Vrf).Table = config.ManagementVRFTableID
	cfg := controlLinkCfg18597("em0")
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"em0":  {Name: "em0"},
		"fxp0": {Name: "fxp0"},
	}

	if ctxErr, vrfErr := d.applyVRFReconcile(context.Background(), cfg); ctxErr != nil || vrfErr != nil {
		t.Fatalf("precondition: steady-state applyVRFReconcile = %v, %v", ctxErr, vrfErr)
	}
	if got := restarts.Load(); got != 0 || len(ops.binds) != 0 {
		t.Fatalf("precondition: steady-state pass restarted %d times, binds %v; want none", got, ops.binds)
	}

	em0, err := ops.LinkByName("em0")
	if err != nil {
		t.Fatalf("lookup em0: %v", err)
	}
	em0.Attrs().MasterIndex = 0
	if ctxErr, vrfErr := d.applyVRFReconcile(context.Background(), cfg); ctxErr != nil || vrfErr != nil {
		t.Fatalf("applyVRFReconcile after the detach = %v, %v", ctxErr, vrfErr)
	}
	if len(ops.binds) != 1 || ops.binds[0] != "em0->"+config.ManagementVRFDeviceName {
		t.Fatalf("precondition: binds = %v, want exactly em0 moved back", ops.binds)
	}
	if got := restarts.Load(); got != 1 {
		t.Fatalf("the pre-networkd pass moved em0 and restarted the heartbeat %d times, want 1 "+
			"right after the move", got)
	}
}

// The background management-VRF reassert loop is the third owner that can
// move the control link back into vrf-mgmt (an out-of-band nomaster between
// commits). It used to rebind em0 and leave the heartbeat sockets stale until
// the next commit; it now runs the same gate. An fxp0-only drift restarts
// nothing.
func TestMgmtVRFReassertRestartsHeartbeatOnlyForAControlLinkMove18597(t *testing.T) {
	d, ops, restarts := newHeartbeatGateDaemon18597(t)
	d.store = clusterStore18597(t)

	fxp0, err := ops.LinkByName("fxp0")
	if err != nil {
		t.Fatalf("lookup fxp0: %v", err)
	}
	fxp0.Attrs().MasterIndex = 0
	d.reassertMgmtVRFOnce(context.Background())
	if len(ops.binds) != 1 || ops.binds[0] != "fxp0->"+config.ManagementVRFDeviceName {
		t.Fatalf("precondition: binds = %v, want fxp0 moved back", ops.binds)
	}
	if got := restarts.Load(); got != 0 {
		t.Fatalf("an fxp0-only reassert restarted the heartbeat %d times, want 0", got)
	}

	em0, err := ops.LinkByName("em0")
	if err != nil {
		t.Fatalf("lookup em0: %v", err)
	}
	em0.Attrs().MasterIndex = 0
	d.reassertMgmtVRFOnce(context.Background())
	if len(ops.binds) != 2 || ops.binds[1] != "em0->"+config.ManagementVRFDeviceName {
		t.Fatalf("precondition: binds = %v, want em0 moved back second", ops.binds)
	}
	if got := restarts.Load(); got != 1 {
		t.Fatalf("reasserting a drifted em0 restarted the heartbeat %d times, want 1", got)
	}
}

// TestHeartbeatRestartGateRetryOwedPerCallSite18597 pins retryOwed at each call
// site. Behaviour cells drive the gate directly, so they cannot see a call
// site passing the wrong value — and the wrong value is silent: with false at
// step 2.7 an owed restart (#9751, heartbeat STOPPED) is retried by no apply,
// and the whole ./pkg/daemon suite stayed green under that mutant. The
// pre-networkd pass must pass false (its failure is retried and reported by
// 2.7 of the same apply); 2.7 and the reassert tick must pass true.
func TestHeartbeatRestartGateRetryOwedPerCallSite18597(t *testing.T) {
	want := map[string]string{
		"daemon_apply_interfaces.go": "false",
		"daemon_apply_dataplane.go":  "true",
		"mgmt_vrf_reassert_11448.go": "true",
	}
	for file, arg := range want {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		var got []string
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "restartHeartbeatIfControlLinkMoved" || len(call.Args) != 2 {
				return true
			}
			if id, ok := call.Args[1].(*ast.Ident); ok {
				got = append(got, id.Name)
			} else {
				got = append(got, "<non-literal>")
			}
			return true
		})
		if len(got) != 1 || got[0] != arg {
			t.Errorf("%s: restartHeartbeatIfControlLinkMoved retryOwed args = %v, want exactly [%s]", file, got, arg)
		}
	}
}

// A restart the pre-networkd pass starts and that fails every bind is owed,
// is NOT a commit failure by itself, and the post-networkd pass of the same
// apply retries it; when that retry succeeds the apply reports nothing. The
// first revision joined the 0b failure into vrfErr, failing a commit whose
// heartbeat 2.7 had already restored.
func TestPreNetworkdRestartFailureIsRetriedNotReported18597(t *testing.T) {
	defer cluster.SetHeartbeatRestartRetryDelayForTesting(time.Millisecond)()
	d, ops, _ := newHeartbeatGateDaemon18597(t)
	vrf, err := ops.LinkByName(config.ManagementVRFDeviceName)
	if err != nil {
		t.Fatalf("lookup vrf-mgmt: %v", err)
	}
	vrf.(*netlink.Vrf).Table = config.ManagementVRFTableID
	cfg := controlLinkCfg18597("em0")
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{"em0": {Name: "em0"}, "fxp0": {Name: "fxp0"}}
	var failing atomic.Bool
	failing.Store(true)
	d.cluster.SetHeartbeatVRFDeviceFunc(func(string) string {
		if failing.Load() {
			return "r18597-novrf" // SO_BINDTODEVICE fails: no such device
		}
		return ""
	})

	em0, err := ops.LinkByName("em0")
	if err != nil {
		t.Fatalf("lookup em0: %v", err)
	}
	em0.Attrs().MasterIndex = 0
	if ctxErr, vrfErr := d.applyVRFReconcile(context.Background(), cfg); ctxErr != nil || vrfErr != nil {
		t.Fatalf("applyVRFReconcile with a failing restart = %v, %v; want nil: the owed restart is the "+
			"post-networkd pass's to retry and report", ctxErr, vrfErr)
	}
	if !d.cluster.HeartbeatRestartOwed() {
		t.Fatal("precondition: the failed pre-networkd restart did not leave a debt")
	}

	failing.Store(false)
	if err := d.restartHeartbeatIfControlLinkMoved(cfg, true); err != nil {
		t.Fatalf("post-networkd retry of the owed restart = %v, want nil", err)
	}
	if d.cluster.HeartbeatRestartOwed() || !d.cluster.HeartbeatRunning() {
		t.Fatalf("after the post-networkd retry: owed=%v running=%v, want false/true",
			d.cluster.HeartbeatRestartOwed(), d.cluster.HeartbeatRunning())
	}
}

// The reassert tick retries an owed restart even when nothing drifted: before,
// its quick gate ignored HeartbeatRestartOwed and its call passed
// retryOwed=false, so a restart that failed there left the heartbeat stopped
// until the next apply, with no bound.
func TestMgmtVRFReassertRetriesAnOwedHeartbeatRestart18597(t *testing.T) {
	defer cluster.SetHeartbeatRestartRetryDelayForTesting(time.Millisecond)()
	d, ops, _ := newHeartbeatGateDaemon18597(t)
	d.store = clusterStore18597(t)
	var failing atomic.Bool
	failing.Store(true)
	d.cluster.SetHeartbeatVRFDeviceFunc(func(string) string {
		if failing.Load() {
			return "r18597-novrf"
		}
		return ""
	})
	em0, err := ops.LinkByName("em0")
	if err != nil {
		t.Fatalf("lookup em0: %v", err)
	}
	em0.Attrs().MasterIndex = 0
	d.reassertMgmtVRFOnce(context.Background())
	if !d.cluster.HeartbeatRestartOwed() || d.cluster.HeartbeatRunning() {
		t.Fatalf("precondition: owed=%v running=%v after a tick whose restart failed every bind; want true/false",
			d.cluster.HeartbeatRestartOwed(), d.cluster.HeartbeatRunning())
	}

	// Nothing drifts any more; only the debt is outstanding.
	failing.Store(false)
	d.reassertMgmtVRFOnce(context.Background())
	if d.cluster.HeartbeatRestartOwed() || !d.cluster.HeartbeatRunning() {
		t.Fatalf("a tick with only an owed restart outstanding left owed=%v running=%v, want false/true: "+
			"the heartbeat stayed stopped until the next apply", d.cluster.HeartbeatRestartOwed(), d.cluster.HeartbeatRunning())
	}
}

// clusterStore18597 is a committed store whose active config names em0 as the
// cluster control link (reassertMgmtVRFOnce reads the active config).
func clusterStore18597(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key reassert-gate-18597",
		"chassis cluster control-interface em0",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	store.ExitConfigure()
	return store
}

// The gate reads the move count under the control link's KERNEL name. The
// routing manager records moves by kernel name, so a gate that used the raw
// config name (ge-0/0/5) would read 0 forever for kernel link ge-0-0-5 and
// never restart the heartbeat after a real move.
func TestGateResolvesControlLinkKernelName18597(t *testing.T) {
	d, ops, restarts := newHeartbeatGateDaemon18597(t)
	ops.links["ge-0-0-5"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-5", Index: 30}}
	cfg := controlLinkCfg18597("ge-0/0/5")
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{"ge-0/0/5": {Name: "ge-0/0/5"}}
	if got := clusterControlLinkName(cfg); got != "ge-0-0-5" {
		t.Fatalf("precondition: control link kernel name = %q, want ge-0-0-5", got)
	}
	if err := d.restartHeartbeatIfControlLinkMoved(cfg, true); err != nil || restarts.Load() != 0 {
		t.Fatalf("precondition: unmoved link restarted=%d err=%v", restarts.Load(), err)
	}
	if err := d.routing.BindInterfaceToVRF("ge-0-0-5", config.ManagementVRFInstanceName); err != nil {
		t.Fatalf("bind ge-0-0-5: %v", err)
	}
	if err := d.restartHeartbeatIfControlLinkMoved(cfg, true); err != nil {
		t.Fatalf("gate after the move: %v", err)
	}
	if got := restarts.Load(); got != 1 {
		t.Fatalf("a move of the control link's kernel device restarted the heartbeat %d times, want 1", got)
	}
}
