package daemon

import (
	"context"
	"errors"
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
var _ helperControlSource = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

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
	err  error // returned by the rg_active=false write (an explicit refusal)
}

func (h *slowHA18701) SetRGActive(_ context.Context, _ int, active bool) error {
	if !active {
		h.log.add("rg_active=false sent")
		time.Sleep(h.hold)
		return h.err
	}
	return nil
}

func (h *slowHA18701) SetHAWatchdog(context.Context, int, uint64) error { return nil }
func (h *slowHA18701) SyncFabricState(context.Context) error            { return nil }

// readinessDP18701 is the runtime the transit gate and the demotion read the
// #18697/#18685 verdict from.
type readinessDP18701 struct {
	dataplane.RuntimeDataPlane
	ha             *slowHA18701
	notReady       atomic.Bool
	controlAnswers atomic.Bool
}

func (d *readinessDP18701) HA() dataplane.HAController { return d.ha }
func (d *readinessDP18701) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceStrict
}
func (d *readinessDP18701) HelperElectionNotReady() bool { return d.notReady.Load() }

// HelperControlUnresponsive: true unless the test says the control thread
// still answers (the frozen-worker verdict).
func (d *readinessDP18701) HelperControlUnresponsive() bool { return !d.controlAnswers.Load() }

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

// TestLegacyVRRPModeNeverTouchesDirectVIPs18715 (review, NL1): the helper-down
// release is direct-mode only. In legacy VRRP mode VRRP owns the same RETH
// addresses, so a not-ready helper must cause no direct-VIP add or remove on
// either the event path or the reconcile pass; converging them to cluster
// state there could add a VIP behind a VRRP BACKUP or strip a VRRP master's.
func TestLegacyVRRPModeNeverTouchesDirectVIPs18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, true, 300*time.Millisecond)
	d.store = fenceTestStore(t, rethFenceClusterSet)
	d.resignRethRGFn = func(int) vipReleaseBarrier { return nil }
	if d.isNoRethVRRP() {
		t.Fatal("setup: the daemon is still in direct mode")
	}
	touched := 0
	d.directRemoveVIPsFn = func(int) int { touched++; return 1 }
	d.directAddVIPsFn = func(int) int { touched++; return 1 }
	primeRG1Primary(t, d)
	demoteRG1(t, d)
	d.reconcileRGState()
	if touched != 0 {
		t.Fatalf("legacy VRRP mode: a not-ready helper made %d direct-VIP add/remove calls; events %v", touched, log.snapshot())
	}
}

// TestRemoteFailoverOfAWedgedNodeCompletes18715 (review): a peer-requested
// evacuation of the sick node must complete. The bounded write times out by
// design against an unresponsive helper; with the VIPs released, the fence is
// reported actuated so the requester's failover is not aborted and this node
// is not restored as owner.
func TestRemoteFailoverOfAWedgedNodeCompletes18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, true, 5*time.Second)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	primeRG1Primary(t, d)
	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)
	if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
		t.Fatalf("remote failover of a wedged node did not complete: %v (events %v)", err, log.snapshot())
	}
	if !slices.Contains(log.snapshot(), "vips-removed") {
		t.Fatal("the fence was acked without the VIPs released")
	}
}

// TestDemotionPrepRunsWhenControlStillAnswers18715 (review LOW 4): the prep is
// skipped only when the helper's control socket is silent. With a frozen worker
// (control answering) it still runs, AFTER the VIP release, so flows reaching
// this node are redirected via the fabric instead of dropped.
func TestDemotionPrepRunsWhenControlStillAnswers18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	for _, tc := range []struct {
		name     string
		answers  bool
		wantPrep bool
	}{{"control-silent", false, false}, {"frozen-worker-control-answers", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			d, log := newDemotion18701(t, true, 300*time.Millisecond)
			if !d.isNoRethVRRP() {
				t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
			}
			d.dataplane().(*readinessDP18701).controlAnswers.Store(tc.answers)
			d.tryPrepareDemotionFn = func(int) { log.add("prep") }
			primeRG1Primary(t, d)
			demoteRG1(t, d)
			ev := log.snapshot()
			prep, vips := slices.Index(ev, "prep"), slices.Index(ev, "vips-removed")
			if tc.wantPrep && (prep < 0 || vips < 0 || prep < vips) {
				t.Fatalf("events %v: with the control thread answering the prep must run, after the VIP release", ev)
			}
			if !tc.wantPrep && prep >= 0 {
				t.Fatalf("events %v: with the control socket silent the prep must be skipped", ev)
			}
		})
	}
}

// TestSlowButAnsweringHelperFenceIsNotAcked18715 (review, demonstrated by L):
// the twin of TestRemoteFailoverOfAWedgedNodeCompletes18715 with the control
// thread STILL ANSWERING (a frozen worker, or a not-yet-armed helper). The
// other workers may still forward until the write lands, so a write that misses
// the bound must NOT be acked actuated: the #6371 abort runs instead.
func TestSlowButAnsweringHelperFenceIsNotAcked18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, _ := newDemotion18701(t, true, 2*time.Second)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	d.dataplane().(*readinessDP18701).controlAnswers.Store(true)
	d.tryPrepareDemotionFn = func(int) {}
	primeRG1Primary(t, d)
	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)
	if err := d.waitFailoverActuated(1, actuationReqID); err == nil {
		t.Fatal("the fence was acked actuated while an answering helper's rg_active write was still pending: a two-owner window (#5640/#16592)")
	}
}

// TestReconcileLoopPrepRunsWhenControlStillAnswers18715 (review): the reconcile
// loop's twin of TestDemotionPrepRunsWhenControlStillAnswers18715. With the
// helper not ready, the retry skips the prep only when the control socket is
// silent; with the control thread answering it runs the prep, after the VIP
// release.
func TestReconcileLoopPrepRunsWhenControlStillAnswers18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	for _, tc := range []struct {
		name     string
		answers  bool
		wantPrep bool
	}{{"control-silent", false, false}, {"frozen-worker-control-answers", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			d, log := newDemotion18701(t, true, 300*time.Millisecond)
			if !d.isNoRethVRRP() {
				t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
			}
			d.dataplane().(*readinessDP18701).controlAnswers.Store(tc.answers)
			d.tryPrepareDemotionFn = func(int) { log.add("prep") }
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
			prep, vips := slices.Index(ev, "prep"), slices.Index(ev, "vips-removed")
			if tc.wantPrep && (prep < 0 || vips < 0 || prep < vips) {
				t.Fatalf("events %v: with the control thread answering the reconcile prep must run, after the VIP release", ev)
			}
			if !tc.wantPrep && prep >= 0 {
				t.Fatalf("events %v: with the control socket silent the reconcile prep must be skipped", ev)
			}
		})
	}
}

// TestAnsweringHelperRefusalIsNotAcked18715 (review, AH): an answering helper
// that explicitly REFUSES the rg_active=false write keeps the #6371 rule: the
// fence is not acked, whatever the readiness verdict says.
func TestAnsweringHelperRefusalIsNotAcked18715(t *testing.T) {
	d, _ := newDemotion18701(t, true, 0)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	dp := d.dataplane().(*readinessDP18701)
	dp.controlAnswers.Store(true)
	dp.ha.err = errors.New("rg_active refused by the helper")
	d.tryPrepareDemotionFn = func(int) {}
	primeRG1Primary(t, d)
	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)
	if err := d.waitFailoverActuated(1, actuationReqID); err == nil {
		t.Fatal("an answering helper's explicit rg_active refusal was acked actuated (#6371)")
	}
}
