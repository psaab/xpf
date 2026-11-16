package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #18716: in legacy VRRP mode (no-private-rg-election) the RETH VIPs follow
// the VRRP resign, and that resign used to run only after the 5 s demotion
// prep, followed by an unbounded rg_active write. Meanwhile the new primary
// forces MASTER at priority 200 while this node is still MASTER at 200, and
// the IPv4 tie-break decides (pkg/vrrp/legacy_equal_priority_18716_test.go):
// no window, the VIP stuck on this wedged node, or both MASTER. With the
// helper down, the resign must now come FIRST.

// legacyDemotion18716 is newDemotion18701 in legacy VRRP mode, with the RETH
// resign recorded per RG. Each resign returns a released barrier unless the
// test supplies its own.
func legacyDemotion18716(t *testing.T, notReady bool, hold time.Duration) (*Daemon, *order18701) {
	t.Helper()
	old := helperDownDemotionBound
	helperDownDemotionBound = 200 * time.Millisecond
	t.Cleanup(func() { helperDownDemotionBound = old })
	d, log := newDemotion18701(t, notReady, hold)
	d.store = fenceTestStore(t, rethFenceClusterSet)
	if d.isNoRethVRRP() {
		t.Fatal("setup: the daemon is still in direct (no-RETH-VRRP) mode")
	}
	d.resignRethRGFn = func(rg int) vipReleaseBarrier {
		log.add(fmt.Sprintf("resign:%d", rg))
		b := newFakeVIPRelease()
		b.release(nil)
		return b
	}
	d.tryPrepareDemotionFn = func(int) { log.add("prep") }
	return d, log
}

func index18716(t *testing.T, ev []string, name string) int {
	t.Helper()
	at := slices.Index(ev, name)
	if at < 0 {
		t.Fatalf("events %v: %q never happened", ev, name)
	}
	return at
}

// TestLegacyHelperDownResignsBeforeHelperRoundTrips18716: with the helper down
// and its control socket silent, the priority-0 resign comes before the
// rg_active write, the 5 s prep is skipped, and the handler does not wait out
// a helper that never acknowledges.
func TestLegacyHelperDownResignsBeforeHelperRoundTrips18716(t *testing.T) {
	d, log := legacyDemotion18716(t, true, 5*time.Second)
	d.tryPrepareDemotionFn = func(int) { log.add("prep"); time.Sleep(2 * time.Second) }
	primeRG1Primary(t, d)
	start := time.Now()
	demoteRG1(t, d)
	took := time.Since(start)
	ev := log.snapshot()
	if index18716(t, ev, "resign:1") > index18716(t, ev, "rg_active=false sent") {
		t.Fatalf("events %v: the RETH VRRP resign must come before the rg_active write", ev)
	}
	if slices.Contains(ev, "prep") {
		t.Fatalf("events %v: the prep ran although the helper's control socket is silent", ev)
	}
	if took > 1500*time.Millisecond {
		t.Fatalf("the demotion took %s against a helper that never acknowledges; the write must be bounded", took)
	}
}

// TestLegacyHelperDownResignsBeforePrepWhenControlAnswers18716: a frozen worker
// whose control thread still answers keeps the prep (it moves flows to fabric
// redirect), but AFTER the resign: prep no longer delays the VIP handover.
func TestLegacyHelperDownResignsBeforePrepWhenControlAnswers18716(t *testing.T) {
	d, log := legacyDemotion18716(t, true, 300*time.Millisecond)
	d.dataplane().(*readinessDP18701).controlAnswers.Store(true)
	primeRG1Primary(t, d)
	demoteRG1(t, d)
	ev := log.snapshot()
	resign, prep, write := index18716(t, ev, "resign:1"), index18716(t, ev, "prep"), index18716(t, ev, "rg_active=false sent")
	if resign > prep || prep > write {
		t.Fatalf("events %v: want resign, then prep, then the rg_active write", ev)
	}
}

// TestLegacyHealthyDemotionKeepsTheOrder18716 (negative control): a healthy
// helper keeps the #485 order, prep then resign then write, and the handler
// waits for the acknowledgement.
func TestLegacyHealthyDemotionKeepsTheOrder18716(t *testing.T) {
	d, log := legacyDemotion18716(t, false, 300*time.Millisecond)
	primeRG1Primary(t, d)
	start := time.Now()
	demoteRG1(t, d)
	took := time.Since(start)
	ev := log.snapshot()
	prep, resign, write := index18716(t, ev, "prep"), index18716(t, ev, "resign:1"), index18716(t, ev, "rg_active=false sent")
	if prep > resign || resign > write {
		t.Fatalf("events %v: a healthy demotion must keep prep, resign, write", ev)
	}
	if took < 300*time.Millisecond {
		t.Fatalf("a healthy demotion returned after %s, before the helper acknowledged", took)
	}
}

// TestLegacyHelperDownNonSecondaryEdgeDoesNotResign18716: the early resign keys
// on the same edge as the resign it moves (primary to secondary or
// secondary-hold). A primary to disabled edge resigned nothing before and
// resigns nothing now.
func TestLegacyHelperDownNonSecondaryEdgeDoesNotResign18716(t *testing.T) {
	d, log := legacyDemotion18716(t, true, 300*time.Millisecond)
	primeRG1Primary(t, d)
	ev := cluster.ClusterEvent{GroupID: 1, OldState: cluster.StatePrimary, NewState: cluster.StateDisabled}
	if timer := d.handleClusterEvent(context.Background(), ev, nil); timer != nil {
		timer.Stop()
	}
	if got := log.snapshot(); slices.Contains(got, "resign:1") {
		t.Fatalf("events %v: a primary to disabled edge resigned the RETH VRRP", got)
	}
}

// runTwoRGLegacy18716 demotes the RGs in demote in one election and handles
// RG1's event only, as the serial event loop would first. RG2's VRRP is MASTER
// unless rg2Backup. RG1's helper write stalls for 5 s against a silent helper.
// syncHold puts VRRP in its startup sync hold.
func runTwoRGLegacy18716(t *testing.T, demote []int, rg2Backup, syncHold bool) []string {
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
		store:                      fenceTestStore(t, rethFenceClusterSet),
		cluster:                    cm,
		vrrpMgr:                    vrrp.NewManager(),
		rgStates:                   make(map[int]*rgStateMachine),
		failoverActuations:         failoverActuationRegistry{timeout: 2 * time.Second},
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
	dp := &readinessDP18701{ha: &slowHA18701{log: log, hold: 5 * time.Second}}
	dp.notReady.Store(true)
	d.setDataplane(dp)
	if d.isNoRethVRRP() {
		t.Fatal("setup: the daemon is still in direct (no-RETH-VRRP) mode")
	}
	d.resignRethRGFn = func(rg int) vipReleaseBarrier {
		log.add(fmt.Sprintf("resign:%d", rg))
		b := newFakeVIPRelease()
		b.release(nil)
		return b
	}
	d.tryPrepareDemotionFn = func(int) { log.add("prep") }
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
	// RG2's VRRP posture, read by RG1's handler for the sibling resign.
	d.getOrCreateRGState(2).SetVRRP("reth2", !rg2Backup)
	if syncHold {
		d.vrrpMgr.SetSyncHold(time.Minute)
		t.Cleanup(d.vrrpMgr.ReleaseSyncHold)
	}
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
	slices.SortFunc(evs, func(a, b cluster.ClusterEvent) int { return a.GroupID - b.GroupID })
	if timer := d.handleClusterEvent(context.Background(), evs[0], nil); timer != nil {
		timer.Stop()
	}
	return log.snapshot()
}

// TestLegacyHelperDownResignsEveryLostRGFirst18716: RG1 and RG2 are lost in one
// election. RG2's VIPs must not wait behind RG1's helper round trips: RG2 is
// resigned before RG1's write.
func TestLegacyHelperDownResignsEveryLostRGFirst18716(t *testing.T) {
	ev := runTwoRGLegacy18716(t, []int{1, 2}, false, false)
	write := index18716(t, ev, "rg_active=false sent")
	for _, want := range []string{"resign:1", "resign:2"} {
		if index18716(t, ev, want) > write {
			t.Fatalf("events %v: %s must come before RG1's rg_active write", ev, want)
		}
	}
}

// TestLegacyHelperDownKeepsOwnedRG18716: an RG this node still owns is not
// resigned, even though its VRRP is MASTER.
func TestLegacyHelperDownKeepsOwnedRG18716(t *testing.T) {
	ev := runTwoRGLegacy18716(t, []int{1}, false, false)
	index18716(t, ev, "resign:1")
	if slices.Contains(ev, "resign:2") {
		t.Fatalf("events %v: RG2, still owned by this node, was resigned", ev)
	}
}

// TestLegacyHelperDownLeavesNonMasterSibling18716: a lost sibling whose VRRP is
// not MASTER holds no VIP; the safety-net predicate leaves it to its own event.
func TestLegacyHelperDownLeavesNonMasterSibling18716(t *testing.T) {
	ev := runTwoRGLegacy18716(t, []int{1, 2}, true, false)
	index18716(t, ev, "resign:1")
	if at := slices.Index(ev, "resign:2"); at >= 0 && at < index18716(t, ev, "rg_active=false sent") {
		t.Fatalf("events %v: RG2's VRRP is BACKUP, so RG1's handler must not resign it early", ev)
	}
}

// TestLegacyHelperDownNoSiblingResignInSyncHold18716: like the reconcile safety
// net, the sibling resign does nothing while VRRP is in its startup sync hold.
// The event RG itself is still resigned on its own edge.
func TestLegacyHelperDownNoSiblingResignInSyncHold18716(t *testing.T) {
	ev := runTwoRGLegacy18716(t, []int{1, 2}, false, true)
	index18716(t, ev, "resign:1")
	if at := slices.Index(ev, "resign:2"); at >= 0 && at < index18716(t, ev, "rg_active=false sent") {
		t.Fatalf("events %v: RG2 was resigned early during VRRP sync hold", ev)
	}
}

// TestLegacyHelperDownFenceFollowsTheVIPRelease18716 is the no-dual-VIP cell
// for the peer-requested failover (an evacuation of this sick node). The peer
// promotes only on this node's applied-ack, so the ack must not come before
// the RETH VIPs are actually off this node. And it must come once they are:
// the bounded write fails by design against a silent helper, and before
// #18716 that failure aborted the evacuation, leaving the RG on the wedged
// node (#16592).
func TestLegacyHelperDownFenceFollowsTheVIPRelease18716(t *testing.T) {
	for _, tc := range []struct {
		name       string
		answers    bool
		releaseErr error
		wantErr    bool
	}{
		{"silent-clean-release", false, nil, false},
		{"silent-failed-release", false, errors.New("VIP removal failed"), true},
		{"control-answers", true, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, log := legacyDemotion18716(t, true, 5*time.Second)
			d.rethVIPReleaseTimeout = 5 * time.Second
			dp := d.dataplane().(*readinessDP18701)
			dp.controlAnswers.Store(tc.answers)
			// A wedged helper's write fails after its round trip, as
			// UpdateRGActive does; an answering one refuses it at once.
			dp.ha.err = errors.New("helper did not acknowledge rg_active=false")
			if tc.answers {
				dp.ha.hold = 0
			}
			barrier := newFakeVIPRelease()
			d.resignRethRGFn = func(rg int) vipReleaseBarrier {
				log.add(fmt.Sprintf("resign:%d", rg))
				return barrier
			}
			primeRG1Primary(t, d)
			d.armFailoverActuation(1, actuationReqID)
			demoteRG1(t, d)
			waited := make(chan error, 1)
			go func() { waited <- d.waitFailoverActuated(1, actuationReqID) }()
			if !tc.answers {
				select {
				case err := <-waited:
					t.Fatalf("applied-ack resolved (err=%v) while the RETH VIPs were still on this node; events %v",
						err, log.snapshot())
				case <-time.After(150 * time.Millisecond):
				}
			}
			barrier.release(tc.releaseErr)
			select {
			case err := <-waited:
				if (err != nil) != tc.wantErr {
					t.Fatalf("applied-ack verdict = %v, want error %v; events %v", err, tc.wantErr, log.snapshot())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("applied-ack never resolved")
			}
		})
	}
}

// TestLegacyReconcileHelperDownBoundsTheWrite18716: the reconcile pass retries
// a demotion whose event was dropped. In legacy mode too it skips the prep and
// bounds the write when the helper's control socket is silent, so the VRRP
// posture safety net behind it is not held for the 5 s prep and a 5 s write.
func TestLegacyReconcileHelperDownBoundsTheWrite18716(t *testing.T) {
	d, log := legacyDemotion18716(t, true, 5*time.Second)
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
	start := time.Now()
	d.reconcileRGState()
	took := time.Since(start)
	ev := log.snapshot()
	index18716(t, ev, "rg_active=false sent")
	if slices.Contains(ev, "prep") {
		t.Fatalf("events %v: the reconcile prep ran although the helper's control socket is silent", ev)
	}
	if took > 2*time.Second {
		t.Fatalf("the reconcile pass waited %s on a helper that never acknowledges", took)
	}
}
