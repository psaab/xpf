package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
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
// helper down, this RG's resign must now come FIRST.

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
	d.removeStableRethLLFn = func(rg int) { log.add(fmt.Sprintf("ll-removed:%d", rg)) }
	d.clearRethServicesFn = func(rg int) { log.add(fmt.Sprintf("services-cleared:%d", rg)) }
	d.stableLLConfirmAbsentFn = func(int) error { return nil }
	return d, log
}

// primeRG1PrimaryVRRPMaster18716 primes the shape #18716 is about (review
// P2-1): RG1 is cluster primary AND its RETH VRRP instance is MASTER at the
// demotion edge. Legacy desired is cluster || all-MASTER, so it stays true
// across the cluster edge: the cluster handler writes nothing, and the
// rg_active write happens on the VRRP BACKUP event the resign produces.
func primeRG1PrimaryVRRPMaster18716(t *testing.T, d *Daemon) {
	t.Helper()
	primeRG1Primary(t, d)
	d.getOrCreateRGState(1).SetVRRP("reth1", true)
}

// vrrpBackupRG1_18716 delivers the VRRP BACKUP event for RG1's RETH instance,
// as watchVRRPEvents does after the resign. It returns how long the arm took
// and the events the arm itself logged.
func vrrpBackupRG1_18716(d *Daemon, log *order18701) (time.Duration, []string) {
	before := len(log.snapshot())
	start := time.Now()
	d.handleVRRPEvent(context.Background(),
		vrrp.VRRPEvent{Interface: "reth1", GroupID: rethVRIDBase + 1, State: vrrp.StateBackup}, rgTransition{})
	took := time.Since(start)
	return took, log.snapshot()[before:]
}

// demotionEdges18716 are the two primary-to-non-primary edges the resign keys
// on: an operator or peer-requested move (ManualFailover, which yields
// secondary-hold) and an election loss (a plain primary to secondary edge,
// e.g. on local weight 0).
var demotionEdges18716 = []string{"manual-secondary-hold", "election-secondary"}

// demoteRG1Edge18716 drives one RG1 demotion along edge through
// handleClusterEvent.
func demoteRG1Edge18716(t *testing.T, d *Daemon, edge string) {
	t.Helper()
	switch edge {
	case "manual-secondary-hold":
		demoteRG1(t, d)
	case "election-secondary":
		d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
		ev := cluster.ClusterEvent{GroupID: 1, OldState: cluster.StatePrimary, NewState: cluster.StateSecondary}
		if timer := d.handleClusterEvent(context.Background(), ev, nil); timer != nil {
			timer.Stop()
		}
	default:
		t.Fatalf("unknown edge %q", edge)
	}
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
// a helper that never acknowledges. On both demotion edges.
func TestLegacyHelperDownResignsBeforeHelperRoundTrips18716(t *testing.T) {
	for _, edge := range demotionEdges18716 {
		t.Run(edge, func(t *testing.T) {
			d, log := legacyDemotion18716(t, true, 5*time.Second)
			d.tryPrepareDemotionFn = func(int) { log.add("prep"); time.Sleep(2 * time.Second) }
			primeRG1Primary(t, d)
			start := time.Now()
			demoteRG1Edge18716(t, d, edge)
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
		})
	}
}

// TestLegacyHelperDownResignsBeforePrepWhenControlAnswers18716: a frozen worker
// whose control thread still answers keeps the prep (it moves flows to fabric
// redirect), but AFTER the resign: prep no longer delays the VIP handover.
func TestLegacyHelperDownResignsBeforePrepWhenControlAnswers18716(t *testing.T) {
	for _, edge := range demotionEdges18716 {
		t.Run(edge, func(t *testing.T) {
			d, log := legacyDemotion18716(t, true, 300*time.Millisecond)
			d.dataplane().(*readinessDP18701).controlAnswers.Store(true)
			primeRG1Primary(t, d)
			demoteRG1Edge18716(t, d, edge)
			ev := log.snapshot()
			resign, prep, write := index18716(t, ev, "resign:1"), index18716(t, ev, "prep"), index18716(t, ev, "rg_active=false sent")
			if resign > prep || prep > write {
				t.Fatalf("events %v: want resign, then prep, then the rg_active write", ev)
			}
		})
	}
}

// TestLegacyHealthyDemotionKeepsTheOrder18716 (negative control): a healthy
// helper keeps the #485 order, prep then resign then write, and the handler
// waits for the acknowledgement.
func TestLegacyHealthyDemotionKeepsTheOrder18716(t *testing.T) {
	for _, edge := range demotionEdges18716 {
		t.Run(edge, func(t *testing.T) {
			d, log := legacyDemotion18716(t, false, 300*time.Millisecond)
			primeRG1Primary(t, d)
			start := time.Now()
			demoteRG1Edge18716(t, d, edge)
			took := time.Since(start)
			ev := log.snapshot()
			prep, resign, write := index18716(t, ev, "prep"), index18716(t, ev, "resign:1"), index18716(t, ev, "rg_active=false sent")
			if prep > resign || resign > write {
				t.Fatalf("events %v: a healthy demotion must keep prep, resign, write", ev)
			}
			if took < 300*time.Millisecond {
				t.Fatalf("a healthy demotion returned after %s, before the helper acknowledged", took)
			}
		})
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

// TestLegacyHelperDownResignsOnlyTheEventRG18716 (#18716 review, P1-1 and
// P1-2). RG2 is cluster-secondary with its VRRP MASTER: the shape of a
// legitimate takeover in progress (the peer died after RG1's demotion was
// queued, and VRRP took RG2 over before the cluster promoted it). Handling
// RG1's demotion must resign RG1 only; resigning RG2 would open a no-VIP
// window on an RG this node may be about to own. And the RG1 resign must not
// wait on the transfer-readiness callback that GroupStates() runs for every
// group (routing/FRR queries, up to 2 s each in production).
func TestLegacyHelperDownResignsOnlyTheEventRG18716(t *testing.T) {
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
	var start time.Time
	var resignedRG1After atomic.Int64
	d.resignRethRGFn = func(rg int) vipReleaseBarrier {
		log.add(fmt.Sprintf("resign:%d", rg))
		if rg == 1 {
			resignedRG1After.Store(int64(time.Since(start)))
		}
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
	d.getOrCreateRGState(1).SetCluster(true)
	cm.SetGroupStateForTesting(2, cluster.StateSecondary)
	d.getOrCreateRGState(2).SetVRRP("reth2", true)
	var readinessCalls atomic.Int32
	cm.SetTransferReadinessFunc(func(int) (bool, []string) {
		readinessCalls.Add(1)
		time.Sleep(time.Second)
		return true, nil
	})

	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	start = time.Now()
	ev := cluster.ClusterEvent{GroupID: 1, OldState: cluster.StatePrimary, NewState: cluster.StateSecondary}
	if timer := d.handleClusterEvent(context.Background(), ev, nil); timer != nil {
		timer.Stop()
	}
	got := log.snapshot()
	index18716(t, got, "resign:1")
	if slices.Contains(got, "resign:2") {
		t.Fatalf("events %v: RG1's demotion resigned RG2, whose VRRP takeover may be legitimate", got)
	}
	if after := time.Duration(resignedRG1After.Load()); after > 500*time.Millisecond {
		t.Fatalf("RG1's resign came %s after the handler started (%d transfer-readiness calls); it must not wait on them",
			after, readinessCalls.Load())
	}
}

// TestLegacyHelperDownFenceFollowsTheVIPRelease18716 is the no-dual-VIP cell
// for the peer-requested failover (an evacuation of this sick node). The
// peer's CLUSTER promotes only on this node's applied-ack, so the ack must not
// come before the RETH VIPs are actually off this node. And it must come once
// they are: the bounded write fails by design against a silent helper, and
// before #18716 that failure aborted the evacuation, leaving the RG on the
// wedged node (#16592).
func TestLegacyHelperDownFenceFollowsTheVIPRelease18716(t *testing.T) {
	for _, tc := range []struct {
		name       string
		answers    bool
		answersAt  time.Duration // control starts answering this long into the demotion (0: never flips)
		releaseErr error
		wantErr    bool
	}{
		{"silent-clean-release", false, 0, nil, false},
		{"silent-failed-release", false, 0, errors.New("VIP removal failed"), true},
		{"control-answers", true, 0, nil, true},
		// Silent at entry, answering by the time the bound expires: the
		// FRESH sample must refuse the ack, as the write's failure is then
		// a refusal by a helper whose other workers may still forward.
		{"silent-at-entry-answers-mid-write", false, 100 * time.Millisecond, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, log := legacyDemotion18716(t, true, 5*time.Second)
			d.rethVIPReleaseTimeout = 5 * time.Second
			dp := d.dataplane().(*readinessDP18701)
			dp.controlAnswers.Store(tc.answers)
			// A wedged helper's write fails after its round trip, as
			// UpdateRGActive does; an answering one refuses it.
			dp.ha.err = errors.New("helper did not acknowledge rg_active=false")
			switch {
			case tc.answers:
				dp.ha.hold = 0
			case tc.answersAt > 0:
				// Past the 200 ms bound, so the bound expires after the flip.
				dp.ha.hold = 400 * time.Millisecond
			}
			barrier := newFakeVIPRelease()
			d.resignRethRGFn = func(rg int) vipReleaseBarrier {
				log.add(fmt.Sprintf("resign:%d", rg))
				return barrier
			}
			primeRG1Primary(t, d)
			d.armFailoverActuation(1, actuationReqID)
			if tc.answersAt > 0 {
				flip := time.AfterFunc(tc.answersAt, func() { dp.controlAnswers.Store(true) })
				t.Cleanup(func() { flip.Stop() })
			}
			demoteRG1(t, d)
			waited := make(chan error, 1)
			go func() { waited <- d.waitFailoverActuated(1, actuationReqID) }()
			if !tc.answers && tc.answersAt == 0 {
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

// TestLegacyTargetShapeHelperDown18716 (review P2-1, P2-2): the event RG is
// still VRRP MASTER at the edge. The cluster handler takes the stable router
// link-local off BEFORE the resign and writes nothing (desired stays true until
// VRRP goes BACKUP). The VRRP BACKUP arm then releases the link-local and the
// RA/DHCP services first, skips the prep against a silent control socket, and
// bounds the write. On both demotion edges.
func TestLegacyTargetShapeHelperDown18716(t *testing.T) {
	for _, edge := range demotionEdges18716 {
		t.Run(edge, func(t *testing.T) {
			d, log := legacyDemotion18716(t, true, 5*time.Second)
			d.tryPrepareDemotionFn = func(int) { log.add("prep"); time.Sleep(2 * time.Second) }
			primeRG1PrimaryVRRPMaster18716(t, d)
			start := time.Now()
			demoteRG1Edge18716(t, d, edge)
			took := time.Since(start)
			ev := log.snapshot()
			if index18716(t, ev, "ll-removed:1") > index18716(t, ev, "resign:1") {
				t.Fatalf("events %v: the stable router link-local must leave before the resign", ev)
			}
			if slices.Contains(ev, "rg_active=false sent") || slices.Contains(ev, "prep") || took > time.Second {
				t.Fatalf("events %v after %s: with RG1 still VRRP MASTER the cluster handler must not reach the prep or the write", ev, took)
			}
			armTook, ev := vrrpBackupRG1_18716(d, log)
			write := index18716(t, ev, "rg_active=false sent")
			if index18716(t, ev, "services-cleared:1") > write {
				t.Fatalf("events %v: the VRRP BACKUP arm must clear the services before the helper write", ev)
			}
			if slices.Contains(ev, "prep") {
				t.Fatalf("events %v: the VRRP BACKUP arm ran the prep against a silent control socket", ev)
			}
			if armTook > 1500*time.Millisecond {
				t.Fatalf("the VRRP BACKUP arm took %s against a helper that never acknowledges; the write must be bounded", armTook)
			}
		})
	}
}

// TestLegacyTargetShapeControlAnswers18716: a frozen worker whose control
// thread answers keeps the prep in the VRRP BACKUP arm, after the link-local
// and services, and the write waits for the helper's real answer.
func TestLegacyTargetShapeControlAnswers18716(t *testing.T) {
	d, log := legacyDemotion18716(t, true, 300*time.Millisecond)
	d.dataplane().(*readinessDP18701).controlAnswers.Store(true)
	primeRG1PrimaryVRRPMaster18716(t, d)
	demoteRG1(t, d)
	armTook, ev := vrrpBackupRG1_18716(d, log)
	svc, prep, write := index18716(t, ev, "services-cleared:1"), index18716(t, ev, "prep"), index18716(t, ev, "rg_active=false sent")
	if svc > prep || prep > write {
		t.Fatalf("events %v: want services, then prep, then the write", ev)
	}
	if armTook < 300*time.Millisecond {
		t.Fatalf("the VRRP BACKUP arm returned after %s, before an answering helper acknowledged", armTook)
	}
}

// TestLegacyTargetShapeHealthyKeepsTheOrder18716 (negative control): a healthy
// helper keeps the VRRP BACKUP arm's order: prep, write, then the link-local
// and services.
func TestLegacyTargetShapeHealthyKeepsTheOrder18716(t *testing.T) {
	d, log := legacyDemotion18716(t, false, 300*time.Millisecond)
	primeRG1PrimaryVRRPMaster18716(t, d)
	demoteRG1(t, d)
	_, ev := vrrpBackupRG1_18716(d, log)
	prep, write := index18716(t, ev, "prep"), index18716(t, ev, "rg_active=false sent")
	svc := index18716(t, ev, "services-cleared:1")
	if prep > write || write > svc {
		t.Fatalf("events %v: a healthy VRRP BACKUP arm must keep prep, write, services", ev)
	}
	if index18716(t, ev, "ll-removed:1") < write {
		t.Fatalf("events %v: a healthy demotion must not move the link-local release ahead of the write", ev)
	}
}

// TestLegacyTargetShapeFenceWaitsForTheLinkLocal18716 (review P2-2): in the
// target shape the fence acks on the release, and the release now includes the
// stable router link-local: the VRRP VIPs leaving is not enough while the IPv6
// default-router address is still on this node.
func TestLegacyTargetShapeFenceWaitsForTheLinkLocal18716(t *testing.T) {
	for _, tc := range []struct {
		name    string
		llErr   error
		wantErr bool
	}{
		{"link-local-gone", nil, false},
		{"link-local-still-present", errors.New("stable router link-local still on reth1"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, log := legacyDemotion18716(t, true, 5*time.Second)
			d.rethVIPReleaseTimeout = 5 * time.Second
			d.stableLLConfirmAbsentFn = func(int) error { return tc.llErr }
			barrier := newFakeVIPRelease()
			d.resignRethRGFn = func(rg int) vipReleaseBarrier {
				log.add(fmt.Sprintf("resign:%d", rg))
				return barrier
			}
			primeRG1PrimaryVRRPMaster18716(t, d)
			d.armFailoverActuation(1, actuationReqID)
			demoteRG1(t, d)
			waited := make(chan error, 1)
			go func() { waited <- d.waitFailoverActuated(1, actuationReqID) }()
			select {
			case err := <-waited:
				t.Fatalf("applied-ack resolved (err=%v) before the VRRP release; events %v", err, log.snapshot())
			case <-time.After(150 * time.Millisecond):
			}
			barrier.release(nil)
			select {
			case err := <-waited:
				if (err != nil) != tc.wantErr {
					t.Fatalf("applied-ack verdict = %v, want error %v", err, tc.wantErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("applied-ack never resolved")
			}
		})
	}
}
