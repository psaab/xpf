package daemon

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #7162: the bounded startup promotion hold for no-reth-vrrp /
// private-rg-election mode.
//
// RETH VRRP mode has suppressed startup preemption since #466
// (`vrrp.Manager.SetSyncHold`). These modes had no equivalent, so a node could
// promote an RG before bulk session sync delivered any conntrack/NAT state and
// reset every established flow.
//
// WHAT THESE TESTS ARE GUARDING AGAINST, in both directions. The obvious
// under-fix is no hold at all. The dangerous OVER-fix is a continuous
// `cluster.IsSyncReady()` conjunct — which is what #110 measured and rejected,
// because `syncReady` has no bound while the sync channel is down and would
// block promotion INDEFINITELY in exactly the degraded-peer case preemption
// exists for. So there is a cell for the hold applying, a cell for each release
// edge, and a cell that the release does not depend on peer state.

func noRethHoldDaemon(t *testing.T) *Daemon {
	t.Helper()
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-7162",
		"set chassis cluster node 0",
		"set chassis cluster no-reth-vrrp",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
	})
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm.Start(ctx)
	d := &Daemon{
		rgStates:       make(map[int]*rgStateMachine),
		cluster:        cm,
		store:          store,
		vrrpMgr:        vrrp.NewManager(),
		reconcileNowCh: make(chan struct{}, 1),
		linkByNameFn:   mockLinkByName(map[string]*testLink{"ge-0-0-0": newTestLink("ge-0-0-0", true)}),
	}
	d.setDataplane(newTakeoverReadyDP())
	return d
}

func rgReadiness(t *testing.T, d *Daemon) (bool, []string) {
	t.Helper()
	d.reconcileRGState()
	state := d.cluster.GroupState(1)
	if state == nil {
		t.Fatal("expected RG 1 state")
	}
	return state.Ready, state.ReadinessReasons
}

func hasHoldReason(reasons []string) bool {
	for _, r := range reasons {
		if strings.Contains(r, "session sync startup hold") {
			return true
		}
	}
	return false
}

// BEFORE bulk sync: the hold is active and the RG must not be takeover-ready.
func TestNoRethSyncHoldBlocksPromotionBeforeBulkSync7162(t *testing.T) {
	d := noRethHoldDaemon(t)

	// Control: without the hold this fixture is READY. Without this the cell
	// below could pass because the fixture is unready for an unrelated reason.
	if ready, reasons := rgReadiness(t, d); !ready {
		t.Fatalf("control: the fixture must be takeover-ready before the hold is "+
			"armed, else the assertion below measures the wrong thing: %v", reasons)
	}

	d.armNoRethSyncHold(time.Hour) // long, so only an explicit release ends it
	ready, reasons := rgReadiness(t, d)
	if ready {
		t.Error("the RG is takeover-ready during the startup hold: a node here can " +
			"promote before bulk session sync has delivered any conntrack/NAT " +
			"state, resetting every established flow (#7162)")
	}
	if !hasHoldReason(reasons) {
		t.Errorf("readiness is blocked but no reason names the sync hold, so an "+
			"operator cannot tell this from a VIP problem: %v", reasons)
	}
}

// AFTER bulk sync: the good release edge.
func TestNoRethSyncHoldReleasedByBulkSync7162(t *testing.T) {
	d := noRethHoldDaemon(t)
	d.armNoRethSyncHold(time.Hour)
	if ready, _ := rgReadiness(t, d); ready {
		t.Fatal("precondition: the hold must be blocking before the release is meaningful")
	}

	d.onSessionSyncBulkReceived()

	if d.inNoRethSyncHold() {
		t.Fatal("bulk sync completed but the hold is still active (#7162)")
	}
	if got := d.noRethSyncHoldEndReason(); got != "bulk-sync-complete" {
		t.Errorf("hold end reason = %q, want %q — the operator-visible reason must "+
			"distinguish a healthy release from the degraded timeout", got, "bulk-sync-complete")
	}
	if ready, reasons := rgReadiness(t, d); !ready || hasHoldReason(reasons) {
		t.Errorf("after bulk sync the RG must be takeover-ready: ready=%v reasons=%v",
			ready, reasons)
	}
}

// The TIMEOUT edge — and the #110 shape. The hold must release itself with NO
// peer connected, no sync peer, and cluster sync NOT ready. #110's
// armSyncReadyTimer bails its callback on !d.syncPeerConnected, so its fallback
// never fires in exactly the peer-absent case it exists for. A hold with that
// bug would never release here, which is the whole failure this cell exists to
// exclude.
func TestNoRethSyncHoldReleasesOnTimeoutWithNoPeer7162(t *testing.T) {
	d := noRethHoldDaemon(t)

	d.syncPeerConnected.Store(false)
	d.cluster.SetSyncReady(false)
	if d.cluster.IsSyncReady() {
		t.Fatal("precondition: cluster sync must be NOT ready, so a release here " +
			"cannot be attributed to sync having succeeded")
	}

	d.armNoRethSyncHold(40 * time.Millisecond)
	// #12579: poll continuously rather than sleeping past the narrow interval
	// between publishing the reason and clearing the active flag.

	deadline := time.Now().Add(3 * time.Second)
	for d.inNoRethSyncHold() {
		if time.Now().After(deadline) {
			t.Fatal("the startup hold never released with no peer connected. That is " +
				"#110's defect exactly: a bound that depends on the condition it is " +
				"bounding cannot fire in the case it exists for (#7162)")
		}
		// Keep polling concurrent with the two-state release publication;
		// sleeping here can skip over the narrow flag/reason interleaving.
		runtime.Gosched()
	}
	if got := d.noRethSyncHoldEndReason(); got != "timeout-degraded" {
		t.Errorf("hold end reason = %q, want %q so the degraded release is "+
			"distinguishable in `show chassis cluster`", got, "timeout-degraded")
	}
	if ready, reasons := rgReadiness(t, d); !ready || hasHoldReason(reasons) {
		t.Errorf("after the degraded timeout the RG must be takeover-ready — the "+
			"hold is a bounded startup suppression, not a permanent gate: "+
			"ready=%v reasons=%v", ready, reasons)
	}
}

// Releasing must DRIVE a reconcile, not merely flip a flag. Readiness is
// recomputed on a reconcile pass, so without this the node holds its RG
// secondary until some unrelated event happens to trigger one — the hold would
// be bounded in name only, the bound being on when the flag flips rather than on
// when anything acts on it.
func TestNoRethSyncHoldReleaseTriggersReconcile7162(t *testing.T) {
	d := noRethHoldDaemon(t)
	// Drain anything already queued so the assertion is about THIS release.
	select {
	case <-d.reconcileNowCh:
	default:
	}
	d.armNoRethSyncHold(time.Hour)
	d.releaseNoRethSyncHold("bulk-sync-complete")
	select {
	case <-d.reconcileNowCh:
	default:
		t.Fatal("releasing the hold did not trigger a reconcile, so readiness is " +
			"never recomputed and the RG stays secondary until an unrelated event " +
			"happens to drive one (#7162)")
	}
}

// NOT armed: modes that never arm the hold are bit-identical to before. This is
// the over-reach control — a hold that applied when it was never armed would
// gate RETH VRRP mode, which has its own suppression and must not get a second.
func TestNoRethSyncHoldAbsentWhenNeverArmed7162(t *testing.T) {
	d := noRethHoldDaemon(t)
	if d.inNoRethSyncHold() {
		t.Fatal("the hold must not be active before it is armed")
	}
	ready, reasons := rgReadiness(t, d)
	if !ready || hasHoldReason(reasons) {
		t.Errorf("an un-armed hold changed readiness: ready=%v reasons=%v", ready, reasons)
	}
}

// Release is idempotent and FIRST-WINS. The timer and the bulk-sync edge race by
// design; a second release must not overwrite the recorded reason, or a healthy
// release could be reported as degraded (or the reverse) purely on timing.
func TestNoRethSyncHoldReleaseIsFirstWins7162(t *testing.T) {
	d := noRethHoldDaemon(t)
	d.armNoRethSyncHold(time.Hour)
	d.releaseNoRethSyncHold("bulk-sync-complete")
	d.releaseNoRethSyncHold("timeout-degraded")
	if got := d.noRethSyncHoldEndReason(); got != "bulk-sync-complete" {
		t.Errorf("hold end reason = %q after a second release; the first release "+
			"must win or the reported reason depends on a race (#7162)", got)
	}
}
