package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

// readinessTrap19169 is a transfer-readiness callback that FAILS the test when
// invoked while armed. Only the entry point under test runs armed: the cell's
// own observation reads (some fixtures read weight through GroupStates) do not.
type readinessTrap19169 struct {
	armed atomic.Bool
	calls atomic.Int32
}

// trapReadiness19169 installs the trap on cm, ARMED.
func trapReadiness19169(t *testing.T, cm *cluster.Manager) *readinessTrap19169 {
	t.Helper()
	trap := &readinessTrap19169{}
	trap.armed.Store(true)
	cm.SetTransferReadinessFunc(func(rg int) (bool, []string) {
		if trap.armed.Load() {
			trap.calls.Add(1)
			t.Errorf("a failover-path entry point ran the transfer-readiness callback for RG%d:\n%s", rg, debug.Stack())
		}
		return true, nil
	})
	return trap
}

// observe runs fn with the trap disarmed.
func (trap *readinessTrap19169) observe(fn func()) {
	trap.armed.Store(false)
	defer trap.armed.Store(true)
	fn()
}

func (trap *readinessTrap19169) Load() int32 { return trap.calls.Load() }

// TestNoFailoverPathRunsTheReadinessCallback19169 is the census as a test, not
// a judgment: the cluster's transfer-readiness callback FAILS the test if any
// failover-path entry point invokes it. Each entry point runs in its own
// subtest from a FRESH fixture, through its OUTER entry, and must produce its
// own effect there (codex-e P2-2: one shared actuation assertion was satisfied
// by the first handler alone):
//   - a helper-down demotion: the event handler releases RG1's VIPs;
//   - the reconcile pass, with the demotion event dropped: the pass itself
//     releases RG1's VIPs;
//   - a direct-VIP reconcile of a group this node no longer owns;
//   - the helper-down release of a group this node no longer owns;
//   - the REAL transit-gate tick (reassertTransitGate) across every debt
//     transition: healthy, intentional stop (keepArm), unexpected exit,
//     crash loop and recovery, each with its own weight and debt verdict;
//   - an ownerless transfer-out accept and its confirmation (#18715).
//
// The first validation run of #19169 found reconcileRG0ConfigOwnership's
// GroupState(0) this way, a caller the hand census had marked off-path.
func TestNoFailoverPathRunsTheReadinessCallback19169(t *testing.T) {
	released := func(t *testing.T, log *order18701, before int, want string) {
		t.Helper()
		if !slices.Contains(log.snapshot()[before:], want) {
			t.Fatalf("events %v: this entry point did not produce %q itself", log.snapshot()[before:], want)
		}
	}
	t.Run("helper-down demotion", func(t *testing.T) {
		d, log := readinessDaemon19169(t, 0)
		calls := trapReadiness19169(t, d.cluster)
		if _, err := d.cluster.ManualFailover(1); err != nil {
			t.Fatalf("ManualFailover(1): %v", err)
		}
		before := len(log.snapshot())
		for handled := false; !handled; {
			select {
			case ev := <-d.cluster.Events():
				if ev.GroupID != 1 || ev.OldState != cluster.StatePrimary {
					continue
				}
				if timer := d.handleClusterEvent(context.Background(), ev, nil); timer != nil {
					timer.Stop()
				}
				handled = true
			case <-time.After(2 * time.Second):
				t.Fatal("no RG1 demotion event")
			}
		}
		released(t, log, before, "vips-removed:1")
		if calls.Load() != 0 {
			t.Fatalf("readiness ran %d times", calls.Load())
		}
	})
	t.Run("reconcile pass with the demotion event dropped", func(t *testing.T) {
		d, log := readinessDaemon19169(t, 0)
		calls := trapReadiness19169(t, d.cluster)
		if _, err := d.cluster.ManualFailover(1); err != nil {
			t.Fatalf("ManualFailover(1): %v", err)
		}
		for drained := false; !drained; {
			select {
			case <-d.cluster.Events():
			default:
				drained = true
			}
		}
		before := len(log.snapshot())
		d.reconcileRGState()
		released(t, log, before, "vips-removed:1")
		if calls.Load() != 0 {
			t.Fatalf("readiness ran %d times", calls.Load())
		}
	})
	t.Run("direct-VIP reconcile of a group no longer owned", func(t *testing.T) {
		d, log := readinessDaemon19169(t, 0)
		calls := trapReadiness19169(t, d.cluster)
		d.cluster.SetGroupStateForTesting(2, cluster.StateSecondary)
		before := len(log.snapshot())
		d.reconcileDirectVIPOwnership(2, "test")
		released(t, log, before, "vips-removed:2")
		if calls.Load() != 0 {
			t.Fatalf("readiness ran %d times", calls.Load())
		}
	})
	t.Run("helper-down release of a group no longer owned", func(t *testing.T) {
		d, log := readinessDaemon19169(t, 0)
		calls := trapReadiness19169(t, d.cluster)
		d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
		before := len(log.snapshot())
		d.releaseDirectVIPsHelperDown("test")
		released(t, log, before, "vips-removed:1")
		if calls.Load() != 0 {
			t.Fatalf("readiness ran %d times", calls.Load())
		}
	})
	t.Run("transit-gate tick across every debt transition", func(t *testing.T) {
		withBarrierRecorder(t)
		d, weight, rt := newReadinessDaemon18697(t)
		calls := trapReadiness19169(t, d.cluster)
		debts := func() (arm, crash bool) {
			for _, rg := range d.cluster.MonitorFailuresByGroup() {
				if rg.GroupID != 1 {
					continue
				}
				arm = slices.Contains(rg.MonitorFails, cluster.DataplaneArmMonitorIface)
				crash = slices.Contains(rg.MonitorFails, cluster.HelperCrashLoopMonitorIface)
			}
			return arm, crash
		}
		for _, step := range []struct {
			name                       string
			running, notReady, looping bool
			wantArm, wantCrash         bool
			wantWeight                 int
		}{
			{name: "healthy", running: true, wantWeight: 255},
			{name: "intentional stop (keepArm)", wantWeight: 255},
			{name: "unexpected exit", notReady: true, wantArm: true, wantWeight: 1},
			{name: "crash loop", looping: true, notReady: true, wantArm: true, wantCrash: true, wantWeight: 0},
			{name: "recovery", running: true, wantWeight: 255},
		} {
			rt.running.Store(step.running)
			rt.notReady.Store(step.notReady)
			rt.crashLoop.Store(step.looping)
			before := calls.Load()
			d.reassertTransitGate(step.name)
			if n := calls.Load() - before; n != 0 {
				t.Fatalf("%s: the transit-gate tick ran the readiness callback %d times", step.name, n)
			}
			arm, crash := debts()
			if arm != step.wantArm || crash != step.wantCrash {
				t.Fatalf("%s: RG1 arm debt %v crash-loop debt %v, want %v %v", step.name, arm, crash, step.wantArm, step.wantCrash)
			}
			var w int
			calls.observe(func() { w = weight() }) // the fixture reads weight via GroupStates
			if w != step.wantWeight {              // every row, the crash loop's weight 0 included
				t.Fatalf("%s: RG1 weight %d, want %d", step.name, w, step.wantWeight)
			}
		}
	})
	t.Run("ownerless transfer-out accept and confirmation", func(t *testing.T) {
		d, log, confirms := newOwnerless18715(t, 0, nil)
		calls := trapReadiness19169(t, d.cluster)
		if err := d.acceptOwnerlessTransferOut(1, actuationReqID); err != nil {
			t.Fatalf("an ownerless request was not accepted: %v", err)
		}
		if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
			t.Fatalf("the confirmed ownerless fence was not acked: %v", err)
		}
		if !slices.Contains(log.snapshot(), "rg_active=false sent") || *confirms != 1 {
			t.Fatalf("events %v confirms=%d: the accept must write and confirm", log.snapshot(), *confirms)
		}
		if calls.Load() != 0 {
			t.Fatalf("readiness ran %d times", calls.Load())
		}
	})
}

// r23's P3-2: a STATIC guard behind the census. No non-test file in pkg/daemon
// may call GroupStates( or .GroupState(, which run the transfer-readiness
// callback, outside the allowlist below (empty today). The census drives
// named entry points; this catches a new HA-path caller it would miss.
func TestNoProductionDaemonCallerOfGroupState19169(t *testing.T) {
	allow := map[string]bool{} // "file.go:line" of an approved caller, with a reason
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for i, line := range strings.Split(string(raw), "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if !strings.Contains(code, "GroupStates(") && !strings.Contains(code, ".GroupState(") {
				continue
			}
			if at := fmt.Sprintf("%s:%d", f, i+1); !allow[at] {
				bad = append(bad, at+": "+strings.TrimSpace(line))
			}
		}
	}
	if scanned < 50 {
		t.Fatalf("setup: scanned only %d non-test files; the guard is not looking at pkg/daemon", scanned)
	}
	if len(bad) > 0 {
		t.Fatalf("pkg/daemon production callers of GroupStates/GroupState (they run the transfer-readiness callback):\n%s", strings.Join(bad, "\n"))
	}
}
