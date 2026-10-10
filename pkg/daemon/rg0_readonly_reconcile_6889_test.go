package daemon

import (
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// rg0_readonly_reconcile_6889_test.go — #6889.
//
// SetClusterReadOnly is the authority boundary for who may write config in a
// cluster, and its only production driver was the RG0 TRANSITION handler,
// reached from the event consumer. Manager.sendEvent is non-blocking and drops
// on a full channel, so the boundary could diverge from the state that decides
// it — and nothing re-drove it until the NEXT transition, so one burst of
// events could strand a node indefinitely.
//
// The divergence has two directions and both are bound here. The promotion drop
// fails CLOSED (a node that reports RG0 primary refuses to be configured); the
// demotion drop fails OPEN, which is the one the issue asks to be checked as
// part of the fix.

// clusteredDaemon6889 builds a daemon with a live cluster manager holding RG0,
// plus a real config store, and forces RG0 to st WITHOUT delivering the event —
// which is exactly the state a dropped event leaves behind.
func clusteredDaemon6889(t *testing.T, st cluster.NodeState, storeReadOnly bool) *Daemon {
	t.Helper()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
		},
	})
	cm.SetGroupStateForTesting(0, st)

	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  cm,
		vrrpMgr:  vrrp.NewManager(),
		rgStates: make(map[int]*rgStateMachine),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		opts:     Options{NoDataplane: true},
	}
	d.store.SetClusterReadOnly(storeReadOnly)
	return d
}

// TestDroppedPromotionLeavesTheStoreWritable6889 is the issue, asserted at the
// operator-visible boundary rather than on the bit.
//
// FAIL-ON-REVERT: remove the reconcileRG0ConfigOwnership call from
// reconcileRGState and this cell reds — EnterConfigureSession keeps returning
// ErrClusterReadOnly on a node that reports RG0 primary.
func TestDroppedPromotionLeavesTheStoreWritable6889(t *testing.T) {
	d := clusteredDaemon6889(t, cluster.StatePrimary, true /* store still read-only */)

	// Precondition: this is the split state, not a healthy one.
	if !d.cluster.IsLocalPrimary(0) {
		t.Fatal("precondition: the manager must report RG0 primary")
	}
	if !d.store.ClusterReadOnly() {
		t.Fatal("precondition: the store must still be read-only — that is the divergence")
	}
	if err := d.store.EnterConfigure(); err == nil {
		d.store.ExitConfigure()
		t.Fatal("precondition: EnterConfigure must FAIL before the reconcile, or this " +
			"cell cannot observe the fix")
	}

	d.reconcileRG0ConfigOwnership()

	if d.store.ClusterReadOnly() {
		t.Fatal("the read-only gate still disagrees with RG0 state after a reconcile " +
			"pass — a dropped promotion event strands the node (#6889)")
	}
	// The operator-visible property the issue names.
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure still refused on the RG0 primary after reconcile: %v", err)
	}
	d.store.ExitConfigure()
}

// TestDroppedDemotionClosesTheStore6889 is the OTHER direction, and it is the
// one the issue asks to be checked as part of the fix: today's divergence fails
// closed, but the same missing reconciliation would let it fail OPEN if a
// demotion event were dropped — a demoted standby that still accepts writes.
func TestDroppedDemotionClosesTheStore6889(t *testing.T) {
	for _, st := range []cluster.NodeState{cluster.StateSecondary, cluster.StateSecondaryHold} {
		t.Run(st.String(), func(t *testing.T) {
			d := clusteredDaemon6889(t, st, false /* store still writable */)
			if d.store.ClusterReadOnly() {
				t.Fatal("precondition: the store must start writable — that is the divergence")
			}

			d.reconcileRG0ConfigOwnership()

			if !d.store.ClusterReadOnly() {
				t.Fatalf("a node in RG0 %s still accepts config writes after a reconcile "+
					"pass — the dropped-demotion direction fails OPEN (#6889)", st)
			}
		})
	}
}

// TestReconcileIsSilentWhereTheEventHandlerIs6889 bounds the change.
//
// applyRG0OwnershipTransition acts on exactly three states. A reconcile that
// invented a gate decision for StateLost or StateDisabled would be introducing
// new behaviour through a recovery mechanism — the wrong place for it, and a
// change nobody reviewing #6889 would expect. Both directions are checked so
// the cell cannot pass by the gate happening to already hold the asserted value.
func TestReconcileIsSilentWhereTheEventHandlerIs6889(t *testing.T) {
	for _, st := range []cluster.NodeState{cluster.StateLost, cluster.StateDisabled} {
		for _, startReadOnly := range []bool{true, false} {
			d := clusteredDaemon6889(t, st, startReadOnly)
			d.reconcileRG0ConfigOwnership()
			if got := d.store.ClusterReadOnly(); got != startReadOnly {
				t.Fatalf("RG0 %s: the reconcile changed the gate %v -> %v, but the "+
					"transition handler has no case for this state (#6889)",
					st, startReadOnly, got)
			}
		}
	}
}

// TestReconcileLeavesTheGateAloneWithNoRG0_6889 covers the shape that is NOT a
// secondary: no RG0 in the config at all. GroupState(0) returns nil there, and
// "no RG0 exists" must not be confused with "RG0 exists and is secondary" —
// arming the gate on a cluster that never configured RG0 would lock the
// operator out of a node nothing was gating.
func TestReconcileLeavesTheGateAloneWithNoRG0_6889(t *testing.T) {
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 200}},
		},
	})
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		cluster:  cm,
		vrrpMgr:  vrrp.NewManager(),
		rgStates: make(map[int]*rgStateMachine),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		opts:     Options{NoDataplane: true},
	}
	if d.cluster.GroupState(0) != nil {
		t.Fatal("precondition: this fixture must have no RG0")
	}
	for _, startReadOnly := range []bool{true, false} {
		d.store.SetClusterReadOnly(startReadOnly)
		d.reconcileRG0ConfigOwnership()
		if got := d.store.ClusterReadOnly(); got != startReadOnly {
			t.Fatalf("with no RG0 configured the reconcile changed the gate %v -> %v",
				startReadOnly, got)
		}
	}
}

// TestReconcileNilSafe6889 — a standalone daemon has no cluster manager, and a
// recovery pass must not panic there. reconcileRGState already guards, but this
// function is also the one a future caller would reach for.
func TestReconcileNilSafe6889(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.reconcileRG0ConfigOwnership() // must not panic
	d2 := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
	d2.reconcileRG0ConfigOwnership() // cluster nil, store present
}

// TestReconcileRGStateDrivesTheGate6889 binds the WIRING.
//
// reconcileRG0ConfigOwnership is inert unless the dropped-event recovery path
// actually calls it. reconcileRGState IS that path — triggerReconcile feeds it
// on every event drop, and the 2s loop feeds it otherwise. Deleting the one
// call leaves every cell above green while a dropped event strands the node
// exactly as before.
func TestReconcileRGStateDrivesTheGate6889(t *testing.T) {
	d := clusteredDaemon6889(t, cluster.StatePrimary, true)

	// Drive the REAL recovery entry point, not the helper.
	d.reconcileRGState()

	if d.store.ClusterReadOnly() {
		t.Fatal("reconcileRGState did not reconcile the RG0 config-ownership gate — " +
			"it is the dropped-event recovery path, so a dropped promotion must not " +
			"leave the store read-only (#6889)")
	}
}

// TestNeverTransitionedSecondaryGetsGated6889_6890 records the cold-start
// secondary case: no ownership event is required for the first reconcile to
// derive the gate from RG0 state.
//
// RGs are initially created as StateSecondary (group_state.go), and the daemon
// can reach steady secondary state without crossing a transition edge. Before
// the first reconcile the zero-value store is writable; reconcileRG0ConfigOwnership
// then arms the gate even though applyRG0OwnershipTransition was never called
// by an event. This closes #6890 while preserving the distinction between
// initial-secondary seating and a real demotion (#12171).
func TestNeverTransitionedSecondaryGetsGated6889_6890(t *testing.T) {
	// A node seated as secondary before any ownership event. The dropped-
	// demotion control below records prior local Primary; this boot fixture
	// does not, so the reconcile must arm the same gate without confirming.
	d := clusteredDaemon6889(t, cluster.StateSecondary, false /* never armed */)

	if d.store.ClusterReadOnly() {
		t.Fatal("precondition: the gate must start UNARMED — that is #6890")
	}
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("precondition: an unarmed store must accept a session (this is the "+
			"gap): %v", err)
	}
	d.store.ExitConfigure()

	d.reconcileRGState()

	if !d.store.ClusterReadOnly() {
		t.Fatal("a node seated as RG0 secondary still accepts config writes after " +
			"the first reconcile — #6890 is not closed by the #6889 re-derivation")
	}
	if err := d.store.EnterConfigure(); err == nil {
		d.store.ExitConfigure()
		t.Fatal("EnterConfigure succeeded on an RG0 secondary after the reconcile armed " +
			"the gate")
	}
}

// TestReconcileRedrivesTheWholeTransitionNotJustTheBit6889 closes a gap the
// mutation matrix found in my own coverage.
//
// Replacing the reconcile's call to `applyRG0OwnershipTransition` with a bare
// `SetClusterReadOnly(wantReadOnly)` left every other cell in this file
// GREEN — they all assert the BIT, and the bit is identical either way. But the
// gate is not the transition's only consequence, and a dropped event skipped
// all of them:
//
//   - demotion CONFIRMS a pending commit-confirmed BEFORE going read-only
//     (#4378), so its rollback timer cannot fire on the demoted standby and
//     revert that node while the peer keeps the committed config;
//   - promotion reconciles config-sync to the peer, re-initiates synced IPsec
//     SAs and nudges DHCP lease-sync.
//
// The demotion consequence is the one with a safety story and a cheap
// observable, so it is what binds the decision. A reconcile that sets the bit
// alone leaves the window ARMED on a node that just became read-only —
// precisely the #4378 divergence, reintroduced through the recovery path.
// The reconcile must distinguish this dropped demotion from initial-secondary
// seating, so first observe local Primary with the gate already agreeing and
// then lose the transition event.
func TestReconcileRedrivesTheWholeTransitionNotJustTheBit6889(t *testing.T) {
	d := clusteredDaemon6889(t, cluster.StateSecondary, false)
	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	d.reconcileRG0ConfigOwnership() // gate agrees; reconciliation still observes Primary.
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)

	// Arm a commit-confirmed window: commit A, then commit-confirmed B.
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := d.store.LoadOverride("system { host-name A; }"); err != nil {
		t.Fatalf("LoadOverride A: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if err := d.store.LoadOverride("system { host-name B; }"); err != nil {
		t.Fatalf("LoadOverride B: %v", err)
	}
	if _, err := d.store.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	d.store.ExitConfigure()

	if !d.store.IsConfirmPending() {
		t.Fatal("precondition: a commit-confirmed window must be armed, or this cell " +
			"cannot observe whether the reconcile confirmed it")
	}

	d.reconcileRG0ConfigOwnership()

	// The gate — what every other cell already checks.
	if !d.store.ClusterReadOnly() {
		t.Fatal("the reconcile did not close the gate on an RG0 secondary")
	}
	// The consequence those cells CANNOT see.
	if d.store.IsConfirmPending() {
		t.Fatal("the reconcile went read-only with a commit-confirmed window still " +
			"ARMED — it set the bit instead of re-driving the transition, so the " +
			"#4378 confirm-on-demotion was skipped and that window's rollback timer " +
			"will fire on this demoted standby and diverge it from the peer (#6889)")
	}
}
