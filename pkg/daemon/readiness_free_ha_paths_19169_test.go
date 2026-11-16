package daemon

import (
	"context"
	"fmt"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #19169: GroupStates and GroupState run the cluster's transfer-readiness
// callback for every group they return. In production that is
// userspaceTransferReadiness, which can reach routing discovery and FRR
// queries bounded at 2 s per group. The helper-down direct-VIP release
// (#18701/#18715), the ownership read inside every direct VIP reconcile, the
// reconcile pass's RG set, and the transit gate's election-debt tick need only
// IDs, ownership or monitor failures, and must not wait on those probes.

// readinessDaemon19169 is a direct-mode (default) daemon with RG0..2 primary,
// an unresponsive helper, and a transfer-readiness callback that logs
// "readiness:<rg>" and blocks for block.
func readinessDaemon19169(t *testing.T, block time.Duration) (*Daemon, *order18701) {
	t.Helper()
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })

	log := &order18701{}
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 0, NodePriorities: map[int]int{0: 200}},
		{ID: 1, NodePriorities: map[int]int{0: 200}},
		{ID: 2, NodePriorities: map[int]int{0: 200}},
	}})
	d := &Daemon{
		store:                      fenceTestStore(t, fenceStartupClusterSet),
		cluster:                    cm,
		vrrpMgr:                    vrrp.NewManager(),
		rgStates:                   make(map[int]*rgStateMachine),
		failoverActuations:         failoverActuationRegistry{timeout: 2 * time.Second},
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
	dp := &readinessDP18701{ha: &slowHA18701{log: log, hold: 5 * time.Second}}
	dp.notReady.Store(true)
	d.setDataplane(dp)
	if !d.isNoRethVRRP() {
		t.Fatal("setup: the fixture must be direct (no-RETH-VRRP) mode, the default")
	}
	d.directRemoveVIPsFn = func(rg int) int { log.add(fmt.Sprintf("vips-removed:%d", rg)); return 1 }
	d.directAddVIPsFn = func(int) int { return 0 }
	d.directVIPsConfirmAbsentFn = func(int) error { return nil }
	d.directVIPMu.Lock()
	d.directVIPOwned = map[int]bool{1: true, 2: true}
	d.directVIPMu.Unlock()
	for drained := true; drained; {
		select {
		case <-cm.Events():
		default:
			drained = false
		}
	}
	for _, rg := range []int{1, 2} {
		if !cm.IsLocalPrimary(rg) {
			t.Fatalf("setup: RG%d must be primary", rg)
		}
		d.getOrCreateRGState(rg).SetCluster(true)
	}
	cm.SetTransferReadinessFunc(func(rg int) (bool, []string) {
		log.add(fmt.Sprintf("readiness:%d", rg))
		time.Sleep(block)
		return true, nil
	})
	return d, log
}

// firstReadiness19169 is the index of the first readiness callback, or -1.
func firstReadiness19169(ev []string) int {
	return slices.IndexFunc(ev, func(e string) bool { return strings.HasPrefix(e, "readiness:") })
}

// TestHelperDownReleaseRunsNoReadinessCallback19169: RG1 and RG2 are lost in
// one election and RG1's event is handled. Both RGs' VIPs must be released
// with no transfer-readiness callback before them, and quickly.
func TestHelperDownReleaseRunsNoReadinessCallback19169(t *testing.T) {
	d, log := readinessDaemon19169(t, time.Second)
	for _, rg := range []int{1, 2} {
		if _, err := d.cluster.ManualFailover(rg); err != nil {
			t.Fatalf("ManualFailover(%d): %v", rg, err)
		}
	}
	var ev1 cluster.ClusterEvent
	for found := false; !found; {
		select {
		case ev := <-d.cluster.Events():
			if ev.GroupID == 1 && ev.OldState == cluster.StatePrimary {
				ev1, found = ev, true
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no RG1 demotion event")
		}
	}
	start := time.Now()
	var releasedAfter atomic.Int64
	d.directRemoveVIPsFn = func(rg int) int {
		log.add(fmt.Sprintf("vips-removed:%d", rg))
		if rg == 2 {
			releasedAfter.CompareAndSwap(0, int64(time.Since(start)))
		}
		return 1
	}
	if timer := d.handleClusterEvent(context.Background(), ev1, nil); timer != nil {
		timer.Stop()
	}
	ev := log.snapshot()
	first := firstReadiness19169(ev)
	for _, want := range []string{"vips-removed:1", "vips-removed:2"} {
		at := slices.Index(ev, want)
		if at < 0 || (first >= 0 && first < at) {
			t.Fatalf("events %v: %s must come before any transfer-readiness callback", ev, want)
		}
	}
	if after := time.Duration(releasedAfter.Load()); after > 500*time.Millisecond {
		t.Fatalf("both RGs' VIPs were released only %s after the handler started", after)
	}
}

// TestReconcileReleasesBeforeAnyReadinessCallback19169: the 2 s reconcile pass
// applies a demotion whose event was dropped. Its helper-down release must run
// before any transfer-readiness callback (its RG enumeration included).
func TestReconcileReleasesBeforeAnyReadinessCallback19169(t *testing.T) {
	d, log := readinessDaemon19169(t, 100*time.Millisecond)
	if _, err := d.cluster.ManualFailover(1); err != nil {
		t.Fatalf("ManualFailover(1): %v", err)
	}
	for drained := true; drained; {
		select {
		case <-d.cluster.Events():
		default:
			drained = false
		}
	}
	d.reconcileRGState()
	ev := log.snapshot()
	at, first := slices.Index(ev, "vips-removed:1"), firstReadiness19169(ev)
	if at < 0 || (first >= 0 && first < at) {
		t.Fatalf("events %v: the reconcile pass must release RG1's VIPs before any transfer-readiness callback", ev)
	}
}

// TestTransitElectionDebtRunsNoReadinessCallback19169: the transit gate's debt
// tick installs the arm debt on every data RG without any transfer-readiness
// callback. That debt is what moves the RGs off a sick helper.
func TestTransitElectionDebtRunsNoReadinessCallback19169(t *testing.T) {
	d, log := readinessDaemon19169(t, time.Second)
	start := time.Now()
	d.applyTransitElectionDebt(false, false)
	took := time.Since(start)
	if first := firstReadiness19169(log.snapshot()); first >= 0 {
		t.Fatalf("events %v: the election-debt tick ran a transfer-readiness callback", log.snapshot())
	}
	if took > 500*time.Millisecond {
		t.Fatalf("the election-debt tick took %s", took)
	}
	for _, rg := range d.cluster.MonitorFailuresByGroup() {
		if !slices.Contains(rg.MonitorFails, cluster.DataplaneArmMonitorIface) {
			t.Fatalf("RG%d has no arm debt after the tick: %v", rg.GroupID, rg.MonitorFails)
		}
	}
}

// TestNoFailoverPathRunsTheReadinessCallback19169 is the census as a test, not
// a judgment: the cluster's transfer-readiness callback FAILS the test if any
// failover-path entry point invokes it. It drives:
//   - a helper-down demotion (the event handler's VIP release and its
//     ownership reads);
//   - the reconcile pass (RG0 config ownership, the RG set, the helper-down
//     release, the demotion write);
//   - a direct-VIP reconcile on its own;
//   - the transit gate's election-debt tick.
//
// The first validation run of #19169 found reconcileRG0ConfigOwnership's
// GroupState(0) this way, a caller the hand census had marked off-path.
func TestNoFailoverPathRunsTheReadinessCallback19169(t *testing.T) {
	d, log := readinessDaemon19169(t, 0)
	var calls atomic.Int32
	d.cluster.SetTransferReadinessFunc(func(rg int) (bool, []string) {
		calls.Add(1)
		t.Errorf("a failover-path entry point ran the transfer-readiness callback for RG%d:\n%s", rg, debug.Stack())
		return true, nil
	})
	step := func(name string, fn func()) {
		t.Helper()
		before := calls.Load()
		fn()
		if n := calls.Load() - before; n != 0 {
			t.Errorf("%s ran the transfer-readiness callback %d times", name, n)
		}
	}
	step("the helper-down demotion of RG1", func() {
		if _, err := d.cluster.ManualFailover(1); err != nil {
			t.Fatalf("ManualFailover(1): %v", err)
		}
		for {
			select {
			case ev := <-d.cluster.Events():
				if ev.GroupID != 1 || ev.OldState != cluster.StatePrimary {
					continue
				}
				if timer := d.handleClusterEvent(context.Background(), ev, nil); timer != nil {
					timer.Stop()
				}
				return
			case <-time.After(2 * time.Second):
				t.Fatal("no RG1 demotion event")
				return
			}
		}
	})
	step("the reconcile pass", d.reconcileRGState)
	step("a direct-VIP reconcile", func() { d.reconcileDirectVIPOwnership(2, "test") })
	step("the helper-down release", func() { d.releaseDirectVIPsHelperDown("test") })
	step("the election-debt tick", func() { d.applyTransitElectionDebt(false, false) })
	if !slices.Contains(log.snapshot(), "vips-removed:1") {
		t.Fatalf("events %v: the drive never reached the VIP release, so this census proved nothing", log.snapshot())
	}
}
