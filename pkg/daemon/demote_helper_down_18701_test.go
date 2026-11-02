package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
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
	d.directVIPsConfirmAbsentFn = func(int) error { log.add("vips-confirmed"); return nil }
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
	d.directVIPsConfirmAbsentFn = func(int) error { return nil }
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

// TestSlowButAnsweringHelperFenceAckedAfterTheWrite18715 (fold 3, L fix 1):
// with the helper's control thread STILL ANSWERING (a frozen worker, or a
// not-yet-armed helper) nothing is bounded. The demotion waits for the real
// rg_active=false result, here 1.5 s, past the 1 s helper-down bound, and acks
// the fence only once that write has succeeded. Before fold 3 the write was
// bounded at 1 s and the late success was thrown away as an abort, which left
// the RG with no primary (L, BLOCKING).
func TestSlowButAnsweringHelperFenceAckedAfterTheWrite18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	const hold = 1500 * time.Millisecond
	d, _ := newDemotion18701(t, true, hold)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	d.dataplane().(*readinessDP18701).controlAnswers.Store(true)
	d.tryPrepareDemotionFn = func(int) {}
	primeRG1Primary(t, d)
	d.armFailoverActuation(1, actuationReqID)
	start := time.Now()
	demoteRG1(t, d)
	took := time.Since(start)
	if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
		t.Fatalf("an answering helper's rg_active=false write succeeded after %s and the fence was still not acked: %v", hold, err)
	}
	if took < hold {
		t.Fatalf("the fence resolved after %s, before the %s write completed: a two-owner window (#5640)", took, hold)
	}
}

// TestHelperAnsweringMidWriteUsesTheRealResult18715 (fold 3, U item 3): the
// control socket is silent when the demotion starts (so the prep is skipped and
// the write is bounded) and starts answering mid-write. The fence decision then
// samples the socket FRESH, finds it answering, and waits for the real result:
// a failed write aborts, a successful one acks. The prep decision keeps the
// entry sample: it is not re-run.
func TestHelperAnsweringMidWriteUsesTheRealResult18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	for _, tc := range []struct {
		name    string
		err     error
		wantAck bool
	}{
		{"write-times-out", errors.New("control request timed out"), false},
		{"write-succeeds", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, log := newDemotion18701(t, true, 600*time.Millisecond)
			if !d.isNoRethVRRP() {
				t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
			}
			dp := d.dataplane().(*readinessDP18701)
			dp.ha.err = tc.err
			d.tryPrepareDemotionFn = func(int) { log.add("prep") }
			primeRG1Primary(t, d)
			d.armFailoverActuation(1, actuationReqID)
			go func() {
				time.Sleep(100 * time.Millisecond)
				dp.controlAnswers.Store(true)
			}()
			demoteRG1(t, d)
			err := d.waitFailoverActuated(1, actuationReqID)
			if tc.wantAck && err != nil {
				t.Fatalf("the helper answered and the write succeeded, but the fence was not acked: %v", err)
			}
			if !tc.wantAck && err == nil {
				t.Fatal("the helper answered mid-write and the write then failed: that is a refusal, and the fence was acked anyway (#6371)")
			}
			if slices.Contains(log.snapshot(), "prep") {
				t.Fatal("the prep ran although the control socket was silent at entry: the prep decision must use the entry sample")
			}
		})
	}
}

// TestAnsweringAtEntryIsNeverBounded18715 (fold 3, L fix 1): a control socket
// that answers when the demotion starts means the write is not bounded at all.
// If the socket then goes silent mid-write, the demotion still waits for the
// real result and acks a write that lands; a bounded write would have given up
// at the bound and, with the entry sample "answering", could only abort.
func TestAnsweringAtEntryIsNeverBounded18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, _ := newDemotion18701(t, true, 600*time.Millisecond)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	dp := d.dataplane().(*readinessDP18701)
	dp.controlAnswers.Store(true)
	d.tryPrepareDemotionFn = func(int) {}
	primeRG1Primary(t, d)
	d.armFailoverActuation(1, actuationReqID)
	go func() {
		time.Sleep(100 * time.Millisecond)
		dp.controlAnswers.Store(false)
	}()
	demoteRG1(t, d)
	if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
		t.Fatalf("the write landed after the socket went silent mid-write, and the fence was not acked: %v", err)
	}
}

// TestPrepKeepsTheEntrySampleAcrossTheVIPRelease18715 (L, fold 5): the VIP
// release runs between the entry sample and the prep decision, and it is not
// instant (every RG's removal and service clear under directVIPMu), while the
// silence verdict is a time threshold that can flip inside it. The prep must
// follow the ENTRY sample, the same one that bounded the write: here the
// socket is silent at entry and starts answering during the release, and the
// prep must stay skipped. Re-sampling for the prep would run it, so the prep
// and the bound would disagree about one demotion.
func TestPrepKeepsTheEntrySampleAcrossTheVIPRelease18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, true, 50*time.Millisecond)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	dp := d.dataplane().(*readinessDP18701)
	dp.controlAnswers.Store(false)
	d.directRemoveVIPsFn = func(int) int {
		log.add("vips-removed")
		dp.controlAnswers.Store(true) // the verdict flips during the release
		return 1
	}
	d.tryPrepareDemotionFn = func(int) { log.add("prep") }
	primeRG1Primary(t, d)
	demoteRG1(t, d)
	ev := log.snapshot()
	if !slices.Contains(ev, "vips-removed") {
		t.Fatalf("events %v: setup: the release did not run", ev)
	}
	if slices.Contains(ev, "prep") {
		t.Fatalf("events %v: the prep re-read the control socket after the VIP release instead of using the entry sample", ev)
	}
}

// TestSilentAckNeedsEveryVIPConfirmedGone18715 (fold 3, U item 2): a failed
// write is acked as a fence only when every direct VIP of the RG is confirmed
// off the interfaces. The release skips failed deletes and clears the
// ownership flag regardless, so "released" is not proof.
func TestSilentAckNeedsEveryVIPConfirmedGone18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, _ := newDemotion18701(t, true, 5*time.Second)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	d.directVIPsConfirmAbsentFn = func(int) error { return errors.New("VIP 10.0.61.1/24 is still on ge-0-0-1") }
	primeRG1Primary(t, d)
	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)
	if err := d.waitFailoverActuated(1, actuationReqID); err == nil {
		t.Fatal("the fence was acked on a silent helper while a VIP of the RG was still on the interface")
	}
}

// noSurfaceDP18715 is a runtime WITHOUT the helperControlSource surface.
type noSurfaceDP18715 struct {
	dataplane.RuntimeDataPlane
	ha *slowHA18701
}

func (d *noSurfaceDP18715) HA() dataplane.HAController { return d.ha }
func (d *noSurfaceDP18715) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceStrict
}
func (d *noSurfaceDP18715) HelperElectionNotReady() bool { return true }

// TestNoControlSurfaceSplitsTheFallback18715 (fold 3, U item 4): without the
// control-socket surface the prep is skipped (conservative) but a failed write
// is NOT acked (fail closed).
func TestNoControlSurfaceSplitsTheFallback18715(t *testing.T) {
	d, log := newDemotion18701(t, true, 0)
	if !d.isNoRethVRRP() {
		t.Skip("fixture config is not direct (no-RETH-VRRP) mode")
	}
	ha := &slowHA18701{log: log, err: errors.New("no helper")}
	d.setDataplane(&noSurfaceDP18715{ha: ha})
	if _, ok := d.dataplane().(helperControlSource); ok {
		t.Fatal("setup: the fixture runtime must not carry the control surface")
	}
	d.tryPrepareDemotionFn = func(int) { log.add("prep") }
	primeRG1Primary(t, d)
	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)
	if slices.Contains(log.snapshot(), "prep") {
		t.Fatal("without the surface the prep must be skipped")
	}
	if err := d.waitFailoverActuated(1, actuationReqID); err == nil {
		t.Fatal("without the surface a failed write was acked as a fence: the ack fallback must fail closed")
	}
}

// countingHA18715 blocks every rg_active write until release is closed.
type countingHA18715 struct {
	calls   atomic.Int32
	release chan struct{}
	err     error
}

func (h *countingHA18715) SetRGActive(context.Context, int, bool) error {
	h.calls.Add(1)
	<-h.release
	return h.err
}
func (h *countingHA18715) SetHAWatchdog(context.Context, int, uint64) error { return nil }
func (h *countingHA18715) SyncFabricState(context.Context) error            { return nil }

// TestHelperDownWritesAreSingleFlight18715 (fold 3, U item 5): an abandoned
// write keeps running, and a later demotion or reconcile pass for the same RG
// joins it instead of stacking another write behind a wedged helper.
func TestHelperDownWritesAreSingleFlight18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 50 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, _ := newDemotion18701(t, true, 0)
	ha := &countingHA18715{release: make(chan struct{})}
	for range 3 {
		if err := d.helperDownRGActiveWrite(context.Background(), ha, 1, false, true); err == nil {
			t.Fatal("a write against a blocked, silent helper returned success")
		}
	}
	if got := ha.calls.Load(); got != 1 {
		t.Fatalf("%d rg_active writes in flight for one RG, want 1", got)
	}
	close(ha.release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.rgActiveWriteMu.Lock()
		n := len(d.rgActiveWrites)
		d.rgActiveWriteMu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the released write never left the in-flight set")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := d.helperDownRGActiveWrite(context.Background(), ha, 1, false, true); err != nil {
		t.Fatalf("a fresh write after the old one finished: %v", err)
	}
	if got := ha.calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2 (one per write once the first finished)", got)
	}
}

// TestAbandonedWriteLogsItsLateOutcome18715 (fold 3, U item 1): the outcome
// of a write the demotion stopped waiting for is logged when it arrives: a
// success at Info, the first failure of a streak at Warn, repeats at Debug.
func TestAbandonedWriteLogsItsLateOutcome18715(t *testing.T) {
	old := helperDownDemotionBound
	helperDownDemotionBound = 20 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	var buf syncBuffer18715
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	d, _ := newDemotion18701(t, true, 0)
	abandon := func(err error) {
		ha := &countingHA18715{release: make(chan struct{}), err: err}
		_ = d.helperDownRGActiveWrite(context.Background(), ha, 1, false, true)
		close(ha.release)
		deadline := time.Now().Add(2 * time.Second)
		for {
			d.rgActiveWriteMu.Lock()
			n := len(d.rgActiveWrites)
			d.rgActiveWriteMu.Unlock()
			if n == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the abandoned write never finished")
			}
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond) // the log runs after the set is cleared
	}
	abandon(errors.New("refused"))
	abandon(errors.New("refused again"))
	abandon(nil)
	out := buf.String()
	for _, want := range []string{
		"level=WARN msg=\"cluster: an rg_active write the demotion had stopped waiting for failed",
		"level=DEBUG msg=\"cluster: abandoned rg_active write failed again\"",
		"level=INFO msg=\"cluster: the helper acknowledged an rg_active write the demotion had stopped waiting for",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

type syncBuffer18715 struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer18715) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer18715) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
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
