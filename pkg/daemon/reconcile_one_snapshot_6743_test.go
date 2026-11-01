package daemon

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #2114 / #6743 r2-1, bound in r2 (B5): ONE dataplane snapshot per
// reconcile pass.
//
// reconcileRGState takes `reconcileDP := d.dataplane()` and
// `reconcileDPUserspaceActive := d.userspaceDataplaneActiveFor(reconcileDP)`
// once, at pass start, and feeds BOTH to every per-RG helper. The hazard
// the r2-1 change exists to prevent is a mid-pass cell change: one RG
// actuates through the old backend while a later RG observes a different
// one (or nil) and skips its deactivation, leaving rg_active=true set as
// the peer takes ownership.
//
// WHAT WAS UNBOUND, measured at 710a87569 with BUILD_RC=0:
//
//	G2  injectBlackholeRoutesFor(reconcileDPUserspaceActive, rgID) /
//	    removeBlackholeRoutesFor(...) reverted to the per-call
//	    injectBlackholeRoutes(rgID) / removeBlackholeRoutes(rgID)
//	    wrappers, with reconcileDPUserspaceActive reduced to `_ =`.
//	    pkg/daemon FULL_RC=0.
//	G3  takeoverReadinessForRG(reconcileDP, ...) ->
//	    takeoverReadinessForRG(d.dataplane(), ...).
//	    pkg/daemon FULL_RC=0.
//
// Both revert to master's behaviour, so this is an unbound ADDITION rather
// than a regression — but it is HA actuation code and the whole point of
// the change is a property no existing test could observe.
//
// HOW THE PROPERTY IS MADE OBSERVABLE. A count of cell loads is not
// reachable from a test (the cell is an atomic with no hook), and with a
// steady cell a snapshot and a per-call reload return the SAME object, so
// nothing distinguishes them. The fixture therefore CHANGES the cell from
// inside the pass: the first backend's TakeoverReady() — which the
// readiness loop calls before the actuation loop — publishes a second
// backend. After that instant:
//
//	snapshot form  every remaining per-RG helper still sees backend A,
//	               so B is never touched at all;
//	reverted form  the next RG's readiness resolves the cell afresh and
//	               lands on B (G3), and the blackhole wrappers reload the
//	               cell and call B.Mode() (G2).
//
// So `B was never touched` is the single assertion that carries both, and
// it does not depend on the per-RG iteration order (rgIDs comes from a Go
// map, so that order is deliberately not relied on).

// reconcileSnapshotDP is a publishable backend that records the two
// snapshot-fed capabilities and can swap the cell on its first readiness
// call.
type reconcileSnapshotDP struct {
	*dataplane.Manager
	name string

	modeCalls     atomic.Int64
	takeoverCalls atomic.Int64

	// onFirstTakeover runs once, inside the first TakeoverReady() call —
	// i.e. strictly mid-pass, after the snapshot has been taken and before
	// the remaining RGs are evaluated.
	onFirstTakeover func()
	swapped         atomic.Bool
}

func newReconcileSnapshotDP(name string) *reconcileSnapshotDP {
	return &reconcileSnapshotDP{Manager: dataplane.New(), name: name}
}

// Mode reports a forwarding-capable userspace mode, so
// injectBlackholeRoutesFor / removeBlackholeRoutesFor take their early
// return and this test never touches netlink.
func (r *reconcileSnapshotDP) Mode() dpuserspace.DataplaneMode {
	r.modeCalls.Add(1)
	return dpuserspace.ModeUserspaceCompat
}

func (r *reconcileSnapshotDP) TakeoverReady() (bool, []string) {
	r.takeoverCalls.Add(1)
	if r.onFirstTakeover != nil && r.swapped.CompareAndSwap(false, true) {
		r.onFirstTakeover()
	}
	return true, nil
}

// TestReconcilePassUsesOneDataplaneSnapshot is the fail-on-revert guard
// for both halves of r2-1.
//
// RED-on-revert (G3): takeoverReadinessForRG(reconcileDP, ...) ->
// takeoverReadinessForRG(d.dataplane(), ...) in reconcileRGState.
// RED-on-revert (G2): injectBlackholeRoutesFor(reconcileDPUserspaceActive,
// rgID) / removeBlackholeRoutesFor(...) -> the per-call
// injectBlackholeRoutes(rgID) / removeBlackholeRoutes(rgID) wrappers.
func TestReconcilePassUsesOneDataplaneSnapshot(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster authentication-key test-cluster-psk-6743",
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 2 node 0 priority 200",
		// Two userspace-configured RGs: userspaceRGConfigured() refuses
		// rgID <= 0, so RG 0 would never reach the readiness provider and
		// one RG could not distinguish a snapshot from a reload.
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces reth2 redundant-ether-options redundancy-group 2",
		"set interfaces reth2 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth2",
	})

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cm.Start(ctx)

	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cm,
		store:    store,
		vrrpMgr:  vrrp.NewManager(),
		linkByNameFn: mockLinkByName(map[string]*testLink{
			"ge-0-0-0": newTestLink("ge-0-0-0", true),
			"ge-0-0-1": newTestLink("ge-0-0-1", true),
		}),
	}

	second := newReconcileSnapshotDP("B")
	first := newReconcileSnapshotDP("A")
	// The mid-pass cell change: a commit-confirmed rollback's corrected
	// re-arm landing while the reconcile pass is walking its RGs.
	first.onFirstTakeover = func() { d.setDataplane(second) }
	d.setDataplane(first)

	d.reconcileRGState()

	// CONTROLS first: a green run must mean "the pass reached both sites
	// through the snapshot", not "the pass never got there".
	if got := first.modeCalls.Load(); got == 0 {
		t.Fatal("the reconcile pass never evaluated the userspace-active mode: the " +
			"blackhole half of this test is vacuous")
	}
	if got := first.takeoverCalls.Load(); got < 2 {
		t.Fatalf("the snapshot backend's TakeoverReady() ran %d time(s), want >= 2 — the "+
			"pass did not evaluate readiness for BOTH userspace RGs, so a per-RG reload "+
			"would have nothing to diverge on", got)
	}
	if !first.swapped.Load() {
		t.Fatal("the mid-pass cell change never fired: nothing distinguishes a snapshot " +
			"from a per-call reload in this run")
	}
	if d.dataplane() != dataplane.RuntimeDataPlane(second) {
		t.Fatal("the cell does not hold the second backend after the pass: the fixture's " +
			"swap did not take effect")
	}

	// THE PROPERTY. Everything after the swap must still run against the
	// snapshot, so the backend published mid-pass is untouched by THIS pass.
	if got := second.takeoverCalls.Load(); got != 0 {
		t.Fatalf("the backend published MID-PASS had TakeoverReady() called %d time(s): "+
			"takeoverReadinessForRG is reloading the cell per RG instead of using the "+
			"pass snapshot, so two RGs in one pass can be evaluated against different "+
			"backends (#6743 r2-1 G3)", got)
	}
	if got := second.modeCalls.Load(); got != 0 {
		t.Fatalf("the backend published MID-PASS had Mode() called %d time(s): the "+
			"blackhole reconciliation is reloading the cell per RG instead of using the "+
			"pass snapshot, so one RG can actuate as userspace-active while a later RG "+
			"in the same pass actuates as eBPF (#6743 r2-1 G2)", got)
	}
}

// TestReconcileBlackholeWrappersStillReloadPerCall is the over-reach
// control, in a SEPARATE body.
//
// The r2-1 change added the `...For` variants; it must NOT have turned the
// zero-arg wrappers into snapshot users, because the EVENT-path callers
// (a single RG transition outside a reconcile pass) legitimately want a
// fresh cell load. If someone "simplified" injectBlackholeRoutes to reuse a
// stored snapshot, the guard above would still pass while the event path
// silently went stale.
func TestReconcileBlackholeWrappersStillReloadPerCall(t *testing.T) {
	d := &Daemon{}

	first := newReconcileSnapshotDP("A")
	d.setDataplane(first)
	if !d.userspaceDataplaneActive() {
		t.Fatal("control: the fixture backend must report a forwarding-capable mode")
	}
	if got := first.modeCalls.Load(); got != 1 {
		t.Fatalf("Mode() calls = %d, want exactly 1 per zero-arg call", got)
	}

	second := newReconcileSnapshotDP("B")
	d.setDataplane(second)
	if !d.userspaceDataplaneActive() {
		t.Fatal("the wrapper did not resolve the newly published backend")
	}
	if got := second.modeCalls.Load(); got != 1 {
		t.Fatalf("the REPUBLISHED backend's Mode() calls = %d, want 1: the zero-arg "+
			"wrapper stopped taking a fresh cell load, so an event-path blackhole "+
			"decision would be made against a superseded backend", got)
	}
	if got := first.modeCalls.Load(); got != 1 {
		t.Fatalf("the superseded backend's Mode() calls = %d, want it to stay 1", got)
	}
}
