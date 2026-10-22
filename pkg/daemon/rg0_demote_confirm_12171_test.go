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
// The cells bind the clustered cold-boot fixture, repeated no-peer reconciles,
// delivered event and peer evidence, both stale-snapshot directions, non-primary
// state changes, the promotion latch, and peer-takeover log reasons.
package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

// recoveredSecondaryDaemon12171 builds the post-restart shape the issue
// names: a store whose commit-confirmed window was re-armed by Load (as after
// an xpfd restart inside the window), plus an RG0 in the clustered cold-boot
// non-preempt hold. No peer has been heard from, and the store gate is still
// at its false zero value. The skew callback reports no active clock-skew
// alarm, so #10875 recovery does NOT roll back first — recovery re-arms, which
// is the precondition this issue needs.
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
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 100}},
		},
	})
	if got := cm.GroupState(0); got == nil || got.State != cluster.StateSecondary {
		t.Fatalf("precondition: clustered cold boot must hold RG0 Secondary, got %+v", got)
	}

	d := &Daemon{
		applySem:                   semaphore.NewWeighted(1),
		cluster:                    cm,
		vrrpMgr:                    vrrp.NewManager(),
		rgStates:                   make(map[int]*rgStateMachine),
		blackholeRoutes:            make(map[int][]netlink.Route),
		store:                      s,
		opts:                       Options{NoDataplane: true},
		failoverActuations:         failoverActuationRegistry{timeout: 2 * time.Second},
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
	if d.store.ClusterReadOnly() {
		t.Fatal("precondition: the gate must start unarmed (false zero value)")
	}
	return d
}

func deliverRG0OwnershipEvent12171(d *Daemon, oldState, newState cluster.NodeState) {
	if timer := d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 0, OldState: oldState, NewState: newState,
	}, nil); timer != nil {
		timer.Stop()
	}
}

func captureRG0Logs12171(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func assertPeerTakeoverLogs12171(t *testing.T, logs *bytes.Buffer) {
	t.Helper()
	for _, want := range []string{
		"cluster: observed peer takeover of RG0, disabling config writes",
		"cluster: confirmed pending commit-confirmed after peer RG0 takeover",
	} {
		if !bytes.Contains(logs.Bytes(), []byte(want)) {
			t.Errorf("missing peer-takeover log %q in:\n%s", want, logs.String())
		}
	}
}

// TestRecoveredWindowSurvivesFirstSecondaryReconcile_12171 is the issue: the
// reconcile must arm the read-only gate but leave the recovered window ARMED
// across repeated passes — no demotion happened and no peer took over.
func TestRecoveredWindowSurvivesFirstSecondaryReconcile_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)

	for pass := 1; pass <= 3; pass++ {
		d.reconcileRGState()
		if !d.store.ClusterReadOnly() {
			t.Fatalf("reconcile pass %d did not arm the read-only gate (#6890)", pass)
		}
		if d.cluster.IsPeerPrimary(0) {
			t.Fatalf("precondition: peer became primary on pass %d", pass)
		}
		if !d.store.IsConfirmPending() {
			t.Fatalf("reconcile pass %d confirmed a recovered window with no peer primary: "+
				"the auto-rollback safety hatch is silently gone (#12171)", pass)
		}
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

// TestGenuineDemotionStillConfirmsRecoveredWindow_12171 delivers the actual
// RG0 Primary→Secondary event while a recovered window is pending. No
// promotion event or reconcile observes the intervening Primary state, so the
// event is the only demotion evidence.
func TestGenuineDemotionStillConfirmsRecoveredWindow_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)

	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	deliverRG0OwnershipEvent12171(d, cluster.StatePrimary, cluster.StateSecondary)

	if d.store.IsConfirmPending() {
		t.Fatal("a delivered Primary→Secondary event must confirm the recovered window")
	}
}

// TestRecoveredWindowConfirmsWhenPeerTakesOver_12171 covers a peer that
// becomes RG0 primary after initial-secondary reconciliation already armed
// the gate. Reconciliation must still confirm once takeover is observable and
// log the peer-takeover reason on the steady-state path.
func TestRecoveredWindowConfirmsWhenPeerTakesOver_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)

	d.reconcileRGState()
	if !d.store.IsConfirmPending() {
		t.Fatal("initial-secondary reconciliation without a peer must preserve the window")
	}

	logs := captureRG0Logs12171(t)
	d.cluster.SetPeerGroupStateForTesting(0, cluster.StatePrimary)
	d.reconcileRGState()
	if d.store.IsConfirmPending() {
		t.Fatal("a recovered window must be confirmed when the peer becomes RG0 primary")
	}
	assertPeerTakeoverLogs12171(t, logs)
}

// TestPeerAlreadyPrimaryConfirmsFirstSecondaryReconcile_12171 binds the
// peer-primary fallback on the first gate mismatch, including its log reason.
func TestPeerAlreadyPrimaryConfirmsFirstSecondaryReconcile_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)
	logs := captureRG0Logs12171(t)
	d.cluster.SetPeerGroupStateForTesting(0, cluster.StatePrimary)

	d.reconcileRG0ConfigOwnership()
	if !d.store.ClusterReadOnly() {
		t.Fatal("the first secondary reconcile must still arm the read-only gate")
	}
	if d.store.IsConfirmPending() {
		t.Fatal("first secondary reconcile with a primary peer did not confirm")
	}
	assertPeerTakeoverLogs12171(t, logs)
}

// TestStaleSecondarySnapshotDoesNotConsumePromotionLatch_12171 reproduces
// the GroupState readiness-callback interleaving: the snapshot says Secondary,
// then a self-election event runs before reconciliation compares the gate.
func TestStaleSecondarySnapshotDoesNotConsumePromotionLatch_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)
	d.reconcileRGState()
	if !d.store.IsConfirmPending() || !d.store.ClusterReadOnly() {
		t.Fatal("precondition: initial reconcile must preserve the window and arm the gate")
	}

	var once sync.Once
	d.cluster.SetTransferReadinessFunc(func(rgID int) (bool, []string) {
		if rgID == 0 {
			once.Do(func() {
				d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
				deliverRG0OwnershipEvent12171(d, cluster.StateSecondary, cluster.StatePrimary)
			})
		}
		return true, nil
	})
	d.reconcileRG0ConfigOwnership()

	if !d.cluster.IsLocalPrimary(0) {
		t.Fatal("precondition: node must be RG0 primary after the self-election")
	}
	if !d.store.IsConfirmPending() {
		t.Error("a stale Secondary snapshot consumed the self-election promotion latch")
	}
	if d.store.ClusterReadOnly() {
		t.Error("a stale Secondary snapshot re-armed the gate on the RG0 primary")
	}
}

// TestStalePrimarySnapshotDoesNotReopenConfigWrites_12171 is the mirror of
// the stale-Secondary self-election race above. The readiness callback changes
// RG0 from Primary to Secondary after the snapshot; reconciliation must not
// apply the stale Primary state and reopen writes on the now-secondary node.
func TestStalePrimarySnapshotDoesNotReopenConfigWrites_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)
	d.reconcileRGState()
	if !d.store.IsConfirmPending() || !d.store.ClusterReadOnly() {
		t.Fatal("precondition: initial secondary reconciliation must preserve the window and arm the gate")
	}

	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	deliverRG0OwnershipEvent12171(d, cluster.StateSecondary, cluster.StatePrimary)

	var once sync.Once
	d.cluster.SetTransferReadinessFunc(func(rgID int) (bool, []string) {
		if rgID == 0 {
			once.Do(func() {
				d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
				deliverRG0OwnershipEvent12171(d, cluster.StatePrimary, cluster.StateSecondary)
			})
		}
		return true, nil
	})
	d.reconcileRG0ConfigOwnership()

	if d.cluster.IsLocalPrimary(0) {
		t.Fatal("precondition: node must be RG0 secondary after the demotion")
	}
	if !d.store.ClusterReadOnly() {
		t.Error("a stale Primary snapshot re-opened config writes on an RG0 secondary")
	}
	if d.store.IsConfirmPending() {
		t.Error("the delivered Primary→Secondary event must confirm the recovered window")
	}
}

// TestNonPrimaryEventsDoNotConfirmRecoveredWindow_12171 rejects state changes
// within the non-primary set as demotion evidence.
func TestNonPrimaryEventsDoNotConfirmRecoveredWindow_12171(t *testing.T) {
	for _, transition := range []struct {
		name string
		old  cluster.NodeState
		new  cluster.NodeState
	}{
		{name: "secondary-to-hold", old: cluster.StateSecondary, new: cluster.StateSecondaryHold},
		{name: "hold-to-secondary", old: cluster.StateSecondaryHold, new: cluster.StateSecondary},
	} {
		t.Run(transition.name, func(t *testing.T) {
			d := recoveredSecondaryDaemon12171(t)
			d.reconcileRGState()
			if !d.store.IsConfirmPending() || !d.store.ClusterReadOnly() {
				t.Fatal("precondition: initial secondary reconciliation must preserve the window and arm the gate")
			}

			d.cluster.SetGroupStateForTesting(0, transition.new)
			deliverRG0OwnershipEvent12171(d, transition.old, transition.new)

			if !d.store.IsConfirmPending() {
				t.Fatalf("%s event confirmed a recovered window without a Primary old state", transition.name)
			}
			if !d.store.ClusterReadOnly() {
				t.Fatalf("%s event must leave config writes disabled", transition.name)
			}
		})
	}
}

// TestDroppedDemotionConsumesPromotionLatch_12171 pins the fallback for a
// dropped Primary→Secondary event: the promotion observed in this incarnation
// remains evidence for the next reconcile.
func TestDroppedDemotionConsumesPromotionLatch_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)
	d.reconcileRGState()
	if !d.store.IsConfirmPending() || !d.store.ClusterReadOnly() {
		t.Fatal("precondition: initial secondary reconciliation must preserve the window and arm the gate")
	}

	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	deliverRG0OwnershipEvent12171(d, cluster.StateSecondary, cluster.StatePrimary)
	if !d.store.IsConfirmPending() || d.store.ClusterReadOnly() {
		t.Fatal("promotion must leave the window armed and enable config writes")
	}

	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	d.reconcileRG0ConfigOwnership()
	if d.store.IsConfirmPending() {
		t.Error("reconciliation after a dropped demotion must confirm using the promotion latch")
	}
	if !d.store.ClusterReadOnly() {
		t.Error("reconciliation after a dropped demotion must arm the read-only gate")
	}
}

// TestSelfElectedPrimaryKeepsWindow_12171 is the control: after the initial
// secondary reconcile arms the gate, the node self-elects and reconciliation
// must open the gate without confirming its recovered window.
func TestSelfElectedPrimaryKeepsWindow_12171(t *testing.T) {
	d := recoveredSecondaryDaemon12171(t)

	d.reconcileRGState()
	if !d.store.IsConfirmPending() || !d.store.ClusterReadOnly() {
		t.Fatal("precondition: initial secondary reconciliation must preserve the window and arm the gate")
	}
	d.cluster.SetGroupStateForTesting(0, cluster.StatePrimary)
	d.reconcileRGState()
	if !d.store.IsConfirmPending() {
		t.Error("a self-elected RG0 primary must keep its pending window armed")
	}
	if d.store.ClusterReadOnly() {
		t.Error("a self-elected RG0 primary must have config writes enabled")
	}
}
