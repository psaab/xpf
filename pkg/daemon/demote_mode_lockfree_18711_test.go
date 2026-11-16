package daemon

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #18711: on a demotion with an unresponsive helper, nothing before the
// bounded rg_active write may wait on the userspace Manager's mu, whose
// holders (an abandoned UpdateRGActive) sit in 3 s round trips against the
// wedged helper.

// realModeDP18711 is the #18701 fixture's runtime with Mode() answered by a
// REAL userspace Manager, so a cell can hold that Manager's mu the way an
// abandoned UpdateRGActive does.
type realModeDP18711 struct {
	*readinessDP18701
	mgr   *dpuserspace.Manager
	calls atomic.Int32
}

func (d *realModeDP18711) Mode() dpuserspace.DataplaneMode {
	d.calls.Add(1)
	return d.mgr.Mode()
}

// The event path: injectBlackholeRoutes reads Mode() before the bounded
// write. With the Manager's mu held, the demotion must still reach its
// bounded write and return, without waiting for the holder.
func TestDemotionDoesNotWaitOnManagerMutex18711(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, true, 5*time.Second)
	base := d.dataplane().(*readinessDP18701)
	mgr := dpuserspace.NewModeManagerForTest(dpuserspace.ModeUserspaceCompat)
	dp := &realModeDP18711{readinessDP18701: base, mgr: mgr}
	d.setDataplane(dp)
	primeRG1Primary(t, d)
	if _, err := d.cluster.ManualFailover(1); err != nil {
		t.Fatalf("ManualFailover(1): %v", err)
	}
	var ev cluster.ClusterEvent
	select {
	case ev = <-d.cluster.Events():
	case <-time.After(2 * time.Second):
		t.Fatal("cluster manager emitted no demotion event")
	}
	release := mgr.HoldMuForTest() // an abandoned UpdateRGActive
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		if timer := d.handleClusterEvent(context.Background(), ev, nil); timer != nil {
			timer.Stop()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		release()
		released = true
		<-done
		t.Fatal("the demotion waited on the userspace Manager's mu; it must reach its bounded write without it (#18711)")
	}
	took := time.Since(start)
	if dp.calls.Load() == 0 {
		t.Fatal("setup: the demotion never read Mode(); the cell exercised nothing")
	}
	ev2 := log.snapshot()
	if slices.Index(ev2, "vips-removed") < 0 || slices.Index(ev2, "rg_active=false sent") < 0 {
		t.Fatalf("events %v: want the VIP release and the bounded write", ev2)
	}
	if took > 2*time.Second {
		t.Fatalf("the demotion took %s with the Manager's mu held", took)
	}
}

// slowReadinessDP18711 makes the per-RG takeover readiness wait, the way
// TakeoverReadyForPeer waits on the Manager's mu behind an abandoned write.
type slowReadinessDP18711 struct {
	*readinessDP18701
	log  *order18701
	hold time.Duration
}

func (d *slowReadinessDP18711) TakeoverReadyForPeer(bool) (bool, []string) {
	d.log.add("readiness")
	time.Sleep(d.hold)
	return true, nil
}

// The reconcile pass releases the direct VIPs of a helper-down demotion
// BEFORE its per-RG takeover readiness, which can wait on the Manager's mu.
func TestReconcileReleasesVIPsBeforeReadiness18711(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	log := &order18701{}
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
			{ID: 1, NodePriorities: map[int]int{0: 200}},
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm.Start(ctx) // the readiness loop runs only with a monitor
	d := &Daemon{
		// RG1 owns a RETH, so its readiness asks the userspace dataplane.
		store: fenceTestStore(t, fenceStartupClusterSet+
			"set interfaces reth0 redundant-ether-options redundancy-group 1\n"+
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n"+
			"set interfaces reth0 unit 0 family inet address 10.0.61.1/24\n"),
		cluster:                    cm,
		vrrpMgr:                    vrrp.NewManager(),
		rgStates:                   make(map[int]*rgStateMachine),
		failoverActuations:         failoverActuationRegistry{timeout: 2 * time.Second},
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
	base := &readinessDP18701{ha: &slowHA18701{log: log, hold: 5 * time.Second}}
	base.notReady.Store(true)
	d.setDataplane(&slowReadinessDP18711{readinessDP18701: base, log: log, hold: 300 * time.Millisecond})
	d.directRemoveVIPsFn = func(int) int { log.add("vips-removed"); return 1 }
	d.directAddVIPsFn = func(int) int { return 0 }
	d.directVIPsConfirmAbsentFn = func(int) error { log.add("vips-confirmed"); return nil }
	d.directVIPMu.Lock()
	if d.directVIPOwned == nil {
		d.directVIPOwned = make(map[int]bool)
	}
	d.directVIPOwned[1] = true
	d.directVIPMu.Unlock()
	if !d.isNoRethVRRP() {
		t.Fatalf("setup: the fixture must use direct (no-RETH-VRRP) mode")
	}
	primeRG1Primary(t, d)
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
	vips, ready := slices.Index(ev, "vips-removed"), slices.Index(ev, "readiness")
	if ready < 0 {
		t.Fatalf("events %v: setup: the reconcile pass never asked the takeover readiness; the cell exercised nothing", ev)
	}
	if vips < 0 || vips > ready {
		t.Fatalf("events %v: the reconcile pass must release the VIPs before its per-RG readiness, which can wait on the Manager's mu (#18711)", ev)
	}
}
