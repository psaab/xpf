package daemon

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #18701: on a demotion edge, an UNRESPONSIVE local helper must not hold the
// VIPs hostage. On tcp the old primary kept the LAN VIP ~26 s after the peer
// took it, because the VIP release came after helper round trips that each
// burned their deadline, and the next ARP re-resolve landed on the dead node.

// The demotion WARN reads the verdict reason through the RUNTIME dataplane,
// which in production is the adapter (the #18704 lesson).
var _ helperElectionReasonSource = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

type order18701 struct {
	mu     sync.Mutex
	events []string
}

func (o *order18701) add(ev string) {
	o.mu.Lock()
	o.events = append(o.events, ev)
	o.mu.Unlock()
}

func (o *order18701) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.events...)
}

// slowHA18701 records the rg_active=false write and then blocks for hold,
// the way UpdateRGActive does against a helper that does not answer.
type slowHA18701 struct {
	log  *order18701
	hold time.Duration
}

func (h *slowHA18701) SetRGActive(_ context.Context, _ int, active bool) error {
	if !active {
		h.log.add("rg_active=false sent")
		time.Sleep(h.hold)
	}
	return nil
}

func (h *slowHA18701) SetHAWatchdog(context.Context, int, uint64) error { return nil }
func (h *slowHA18701) SyncFabricState(context.Context) error            { return nil }

// readinessDP18701 is the runtime the transit gate and the demotion read the
// #18697/#18685 verdict from.
type readinessDP18701 struct {
	dataplane.RuntimeDataPlane
	ha       *slowHA18701
	notReady atomic.Bool
}

func (d *readinessDP18701) HA() dataplane.HAController { return d.ha }
func (d *readinessDP18701) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceStrict
}
func (d *readinessDP18701) HelperElectionNotReady() bool { return d.notReady.Load() }

func newDemotion18701(t *testing.T, notReady bool, hold time.Duration) (*Daemon, *order18701) {
	t.Helper()
	log := &order18701{}
	d := newActuationDaemon(t, &actuationHA{})
	dp := &readinessDP18701{ha: &slowHA18701{log: log, hold: hold}}
	dp.notReady.Store(notReady)
	d.setDataplane(dp)
	d.directRemoveVIPsFn = func(int) int { log.add("vips-removed"); return 1 }
	d.directAddVIPsFn = func(int) int { return 0 }
	d.directVIPMu.Lock()
	if d.directVIPOwned == nil {
		d.directVIPOwned = make(map[int]bool)
	}
	d.directVIPOwned[1] = true
	d.directVIPMu.Unlock()
	return d, log
}

// TestUnresponsiveHelperDemotionReleasesVIPsFirst18701: with the helper not
// answering, the VIPs go BEFORE the rg_active write, and the handler does not
// wait out a helper that never acknowledges.
func TestUnresponsiveHelperDemotionReleasesVIPsFirst18701(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, true, 5*time.Second)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	primeRG1Primary(t, d)
	start := time.Now()
	demoteRG1(t, d)
	took := time.Since(start)
	ev := log.snapshot()
	vips, write := slices.Index(ev, "vips-removed"), slices.Index(ev, "rg_active=false sent")
	if vips < 0 || write < 0 || vips > write {
		t.Fatalf("events %v: with an unresponsive helper the VIPs must be released before the rg_active write", ev)
	}
	if took > 2*time.Second {
		t.Fatalf("the demotion waited %s on a helper that never acknowledges; the helper-side write must be bounded", took)
	}
}

// TestHealthyDemotionKeepsTheOrder18701: with a healthy helper the existing
// order stands (#18563/#18620): the rg_active write comes first and the VIPs
// after it, and the handler waits for the acknowledgement.
func TestHealthyDemotionKeepsTheOrder18701(t *testing.T) {
	d, log := newDemotion18701(t, false, 300*time.Millisecond)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	primeRG1Primary(t, d)
	start := time.Now()
	demoteRG1(t, d)
	took := time.Since(start)
	ev := log.snapshot()
	vips, write := slices.Index(ev, "vips-removed"), slices.Index(ev, "rg_active=false sent")
	if vips < 0 || write < 0 || write > vips {
		t.Fatalf("events %v: a healthy demotion must write rg_active before releasing the VIPs", ev)
	}
	if took < 300*time.Millisecond {
		t.Fatalf("a healthy demotion returned after %s, before the helper acknowledged", took)
	}
}

// TestUnresponsiveHelperReleasesEveryRGsVIPsFirst18701 (#18715 review,
// BLOCKING): cluster events are handled one at a time, so the early release
// must cover every RG this node lost, not just the event's. Both RG1 and RG2
// are demoted in one election; RG1's handler runs first and its helper write
// stalls. Both RGs' VIPs must be gone before ANY helper round trip.
func runTwoRGDemotion18701(t *testing.T, demote []int) []string {
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
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	d.directRemoveVIPsFn = func(rg int) int { log.add(fmt.Sprintf("vips-removed:%d", rg)); return 1 }
	d.directAddVIPsFn = func(int) int { return 0 }
	d.directVIPMu.Lock()
	d.directVIPOwned = map[int]bool{1: true, 2: true}
	d.directVIPMu.Unlock()
	for drained := true; drained; {
		select {
		case <-d.cluster.Events():
		default:
			drained = false
		}
	}
	for _, rg := range []int{1, 2} {
		if !d.cluster.IsLocalPrimary(rg) {
			t.Fatalf("setup: RG%d must be primary", rg)
		}
		d.getOrCreateRGState(rg).SetCluster(true)
	}
	// One election demotes both; the manager emits both events before either
	// is handled.
	var evs []cluster.ClusterEvent
	for _, rg := range demote {
		if _, err := d.cluster.ManualFailover(rg); err != nil {
			t.Fatalf("ManualFailover(%d): %v", rg, err)
		}
	}
	for len(evs) < len(demote) {
		select {
		case ev := <-d.cluster.Events():
			if ev.OldState == cluster.StatePrimary && ev.NewState != cluster.StatePrimary {
				evs = append(evs, ev)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("got %d demotion events, want %d", len(evs), len(demote))
		}
	}
	// Handle RG1's event first, as the serial event loop would.
	slices.SortFunc(evs, func(a, b cluster.ClusterEvent) int { return a.GroupID - b.GroupID })
	if timer := d.handleClusterEvent(context.Background(), evs[0], nil); timer != nil {
		timer.Stop()
	}
	return log.snapshot()
}

func TestUnresponsiveHelperReleasesEveryRGsVIPsFirst18701(t *testing.T) {
	ev := runTwoRGDemotion18701(t, []int{1, 2})
	first := slices.Index(ev, "rg_active=false sent")
	for _, want := range []string{"vips-removed:1", "vips-removed:2"} {
		at := slices.Index(ev, want)
		if at < 0 || (first >= 0 && at > first) {
			t.Fatalf("events %v: %s must happen before the first helper round trip (RG1's handler)", ev, want)
		}
	}
}

// TestUnresponsiveHelperKeepsOwnedRGsVIPs18701: the all-RG release removes only
// the VIPs of RGs this node lost; an RG it still owns keeps its VIPs.
func TestUnresponsiveHelperKeepsOwnedRGsVIPs18701(t *testing.T) {
	ev := runTwoRGDemotion18701(t, []int{1})
	if slices.Index(ev, "vips-removed:1") < 0 {
		t.Fatalf("events %v: the demoted RG1's VIPs were not released", ev)
	}
	if slices.Index(ev, "vips-removed:2") >= 0 {
		t.Fatalf("events %v: RG2, still owned by this node, lost its VIPs", ev)
	}
}

// TestReconcileLoopReleasesVIPsFirstWithUnresponsiveHelper18701 (#18715
// review): the 2 s reconcile loop retries a demotion whose rg_active write has
// not been applied. With an unresponsive helper it must release the VIPs
// before the retry's helper round trip, skip the prep, and bound the write.
func TestReconcileLoopReleasesVIPsFirstWithUnresponsiveHelper18701(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, true, 5*time.Second)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	primeRG1Primary(t, d)
	// The election demoted RG1, but its event was never handled: the
	// reconcile pass is what applies the demotion.
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
	start := time.Now()
	d.reconcileRGState()
	took := time.Since(start)
	ev := log.snapshot()
	vips, write := slices.Index(ev, "vips-removed"), slices.Index(ev, "rg_active=false sent")
	if vips < 0 || (write >= 0 && vips > write) {
		t.Fatalf("events %v: the reconcile pass must release the VIPs before its helper round trip", ev)
	}
	if took > 2*time.Second {
		t.Fatalf("the reconcile pass waited %s on a helper that never acknowledges", took)
	}
}

// TestDirectVIPOwnershipReadUnderTheLock18715 (review hardening): ownership is
// read under directVIPMu, so a reconcile that waited for the lock while the RG
// was promoted acts on the CURRENT owner and does not remove the VIPs the
// promotion added.
func TestDirectVIPOwnershipReadUnderTheLock18715(t *testing.T) {
	d, log := newDemotion18701(t, false, 0)
	primeRG1Primary(t, d)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.directVIPMu.Lock()
	done := make(chan struct{})
	go func() {
		d.reconcileDirectVIPOwnership(1, "test")
		close(done)
	}()
	time.Sleep(100 * time.Millisecond) // the reconcile is now waiting for the lock
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.directVIPMu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile never finished")
	}
	if ev := log.snapshot(); slices.Index(ev, "vips-removed") >= 0 {
		t.Fatalf("events %v: a reconcile that waited out a promotion removed the new owner's VIPs", ev)
	}
}
