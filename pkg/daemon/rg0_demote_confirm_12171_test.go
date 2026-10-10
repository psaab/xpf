// #12171: a commit-confirmed window recovered at Load must not be
// auto-confirmed by the first RG0 Secondary reconcile after restart.
//
// New RGs start StateSecondary (cluster/group_state.go), and reconcileRGState
// re-derives the store's read-only gate from RG0's authoritative state FIRST
// on every 2s pass. After an xpfd restart the store gate is still its false
// zero value while RG0 already reports secondary. Before this fix, that
// mismatch drove applyRG0OwnershipTransition(StateSecondary), whose demotion
// arm unconditionally called ConfirmPendingOnDemotion. A window Load just
// re-armed was therefore confirmed even though this node was never RG0 primary
// in this incarnation and no peer took anything over — silently discarding the
// auto-rollback safety hatch the operator armed before the restart.
//
// Confirming on demotion is by design ONLY on a genuine demotion: this node
// held RG0 primary and is yielding ownership (#4378). Seating as secondary at
// startup — initial-secondary with no peer having taken over — still arms the
// read-only gate (#6890 stays closed) but leaves the recovered window armed,
// so its rollback timer can still fire and revert the unconfirmed config.
//
// The cells below bind the boot fixture (RED pre-fix), genuine-demotion and
// peer-takeover controls, and a self-election control.
package daemon

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

// recoveredSecondaryDaemon12171 builds the post-restart shape the issue
// names: a store whose commit-confirmed window was re-armed by Load (as after
// an xpfd restart inside the window), a live cluster manager holding RG0 in
// StateSecondary exactly as UpdateConfig initially seats a new RG, no peer
// heard from, and the store gate still at its false zero value. The skew
// callback reports no active clock-skew alarm, so #10875 recovery does NOT
// roll back first — recovery re-arms, which is the precondition this issue needs.
func recoveredSecondaryDaemon12171(t *testing.T) *Daemon {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xpf.conf")

	a := newConfigStore(t, path)
	if err := a.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := a.SetFromInput("system host-name Base"); err != nil {
		t.Fatalf("set host-name Base: %v", err)
	}
	if _, err := a.Commit(); err != nil {
		t.Fatalf("commit Base: %v", err)
	}
	if err := a.SetFromInput("system host-name Committed"); err != nil {
		t.Fatalf("set host-name Committed: %v", err)
	}
	if _, err := a.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	a.ExitConfigure()
	a.CancelConfirmTimerForTesting()

	s := newConfigStore(t, path)
	s.SetConfirmRecoveryClockSkewCheck(func(*config.Config) bool { return false })
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("precondition: Load must re-arm the still-live window (#4577)")
	}
	if _, _, _, ok := s.RecoveredConfirmWindow(); !ok {
		t.Fatal("precondition: the re-armed window must be marked recovered")
	}
	t.Cleanup(func() { _ = s.ConfirmCommit() })

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 100}},
		},
	})
	cm.SetGroupStateForTesting(0, cluster.StateSecondary)
	if got := cm.GroupState(0); got == nil || got.State != cluster.StateSecondary {
		t.Fatalf("precondition: fresh RG0 must seat StateSecondary, got %+v", got)
	}

	d := &Daemon{
		applySem:        semaphore.NewWeighted(1),
		cluster:         cm,
		vrrpMgr:         vrrp.NewManager(),
		rgStates:        make(map[int]*rgStateMachine),
		blackholeRoutes: make(map[int][]netlink.Route),
		store:           s,
		opts:            Options{NoDataplane: true},
	}
	if d.store.ClusterReadOnly() {
		t.Fatal("precondition: the gate must start unarmed (false zero value)")
	}
	return d
}

// TestRecoveredWindowSurvivesFirstSecondaryReconcile_12171 is the issue: the
// first reconcile tick after restart must arm the read-only gate but leave
// the recovered window ARMED — no demotion happened, this node was never
// primary, and no peer took over.
func TestRecoveredWindowSurvivesFirstSecondaryReconcile_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)

	d.reconcileRGState()

	if !d.store.ClusterReadOnly() {
		t.Fatal("the reconcile must still arm the read-only gate on an RG0 secondary (#6890)")
	}
	if !d.store.IsConfirmPending() {
		t.Fatal("the first post-restart RG0-Secondary reconcile CONFIRMED a recovered " +
			"commit-confirmed window nobody demoted from: IsConfirmPending=false, " +
			"so the auto-rollback safety hatch is silently gone (#12171)")
	}
	if _, _, _, ok := d.store.RecoveredConfirmWindow(); !ok {
		t.Error("the surviving window must still be the recovered one")
	}

	// The armed window must still roll back to the ORIGINAL target when its
	// timer fires — proving the reconcile preserved the window rather than
	// merely leaving a broken arm behind.
	d.store.InvokeRollbackTimerForTesting(d.store.ConfirmGenForTesting())
	if got := d.store.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("recovered-window timer rolled back to %q, want Base "+
			"(the reconcile must preserve the window intact)", got)
	}
}

// TestGenuineDemotionStillConfirmsRecoveredWindow_12171 is the control: an
// event that reports Primary→Secondary is a genuine demotion, so #4378 must
// still confirm the recovered window.
func TestGenuineDemotionStillConfirmsRecoveredWindow_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)

	d.applyRG0OwnershipTransition(cluster.StateSecondary, true)

	if d.store.IsConfirmPending() {
		t.Fatal("a recovered window must be confirmed on a genuine RG0 demotion")
	}
}

// TestRecoveredWindowConfirmsWhenPeerTakesOver_12171 covers a peer that
// becomes RG0 primary after initial-secondary reconciliation already armed
// the gate. Reconciliation must still confirm once takeover is observable.
func TestRecoveredWindowConfirmsWhenPeerTakesOver_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)

	d.reconcileRGState()
	if !d.store.IsConfirmPending() {
		t.Fatal("initial-secondary reconciliation without a peer must preserve the window")
	}

	d.cluster.SetPeerGroupStateForTesting(0, cluster.StatePrimary)
	d.reconcileRGState()
	if d.store.IsConfirmPending() {
		t.Fatal("a recovered window must be confirmed when the peer becomes RG0 primary")
	}
}

// TestSelfElectedPrimaryKeepsWindow_12171 is the control: a node that
// self-elects RG0 primary before secondary reconciliation owns its window.
func TestSelfElectedPrimaryKeepsWindow_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)

	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	d.reconcileRGState()
	if !d.store.IsConfirmPending() {
		t.Error("a self-elected RG0 primary must keep its pending window armed")
	}
}
