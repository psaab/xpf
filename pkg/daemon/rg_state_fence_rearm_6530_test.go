package daemon

import (
	"context"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// rearmRecorderHA records every rg_active write so a test can see whether the
// reconcile pass RE-DROVE an apply after an out-of-band write.
type rearmRecorderHA struct {
	mu     sync.Mutex
	writes []rgActiveWrite
}

type rgActiveWrite struct {
	rgID   int
	active bool
}

func (h *rearmRecorderHA) SetRGActive(_ context.Context, rgID int, active bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.writes = append(h.writes, rgActiveWrite{rgID: rgID, active: active})
	return nil
}

func (h *rearmRecorderHA) SetHAWatchdog(_ context.Context, _ int, _ uint64) error { return nil }


func (h *rearmRecorderHA) SyncFabricState(_ context.Context) error { return nil }

func (h *rearmRecorderHA) take() []rgActiveWrite {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]rgActiveWrite(nil), h.writes...)
	h.writes = nil
	return out
}

func (h *rearmRecorderHA) countOf(w rgActiveWrite) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, got := range h.writes {
		if got == w {
			n++
		}
	}
	return n
}

// rearmRecorderDP is a publishable backend whose HA() is the recorder above.
// Mode() reports a forwarding-capable userspace mode so
// injectBlackholeRoutesFor / removeBlackholeRoutesFor take their early return
// and this test never touches netlink.
type rearmRecorderDP struct {
	*dataplane.Manager
	ha *rearmRecorderHA
}

func (r *rearmRecorderDP) HA() dataplane.HAController      { return r.ha }
func (r *rearmRecorderDP) Mode() dpuserspace.DataplaneMode { return dpuserspace.ModeUserspaceCompat }

const fenceRearmClusterSet = "" +
	"set chassis cluster cluster-id 1\n" +
	"set chassis cluster node 0\n" +
	"set chassis cluster reth-count 1\n" +
	"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
	"set chassis cluster authentication-key test-cluster-psk-6530\n"

// #6530: a received peer fence writes rg_active=false straight to the
// dataplane, bypassing the RG state machine's transition path. Before the fix
// nothing told the state machine its `applied` marker had gone stale, so
// reconcileRGState's retry predicate (tr.Changed || s.NeedsApply()) saw
// desired == applied and never re-drove the apply. Forwarding stayed off with
// no retry — a persistent blackhole, not a glitch the next tick repairs.
//
// This drives the real path end to end: a reconcile pass converges RG1 active,
// a fence deactivates it, and the NEXT reconcile pass must re-drive
// SetRGActive(1, true). Nothing in the fixture pokes applied/applyPending by
// hand — the converged pre-fence state is produced by the production apply.
func TestFenceRearmsReconcileRetry(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-6530",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})

	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)

	rec := &rearmRecorderHA{}
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cm,
		store:    store,
		vrrpMgr:  vrrp.NewManager(),
	}
	d.setDataplane(&rearmRecorderDP{Manager: dataplane.New(), ha: rec})

	if !cm.IsLocalPrimary(1) {
		t.Fatal("fixture: node 0 must be primary for RG1 before the fence, " +
			"otherwise the desired rg_active is false and there is nothing to restore")
	}

	// Pass 1: converge. This is the production apply path — it ends with
	// MarkApplied(true), which is exactly the state that made the fence
	// invisible.
	d.reconcileRGState()
	if got := rec.countOf(rgActiveWrite{rgID: 1, active: true}); got == 0 {
		t.Fatalf("fixture: the first reconcile pass never activated RG1 (writes=%v); "+
			"the test would be vacuous", rec.take())
	}
	rec.take()

	s := d.getOrCreateRGState(1)
	if s.NeedsApply() {
		t.Fatal("fixture: RG1 has not converged after the first reconcile pass, " +
			"so a leftover retry — not the fence re-arm — could carry this test")
	}

	// The peer fences us.
	d.fenceAllRedundancyGroups(context.Background())
	fenceWrites := rec.take()
	sawFence := false
	for _, w := range fenceWrites {
		if w == (rgActiveWrite{rgID: 1, active: false}) {
			sawFence = true
		}
	}
	if !sawFence {
		t.Fatalf("fixture: the fence never deactivated RG1 (writes=%v)", fenceWrites)
	}

	// The property: the very next reconcile pass must re-drive the apply.
	// Cluster state is unchanged, so tr.Changed is false — s.NeedsApply() is
	// the only thing that can carry it.
	d.reconcileRGState()
	if got := rec.countOf(rgActiveWrite{rgID: 1, active: true}); got == 0 {
		t.Fatalf("the reconcile pass after a fence did not re-drive rg_active=true "+
			"(writes=%v): the retry is structurally blind and forwarding never returns",
			rec.take())
	}
	rec.take()

	// ...and having re-driven it, it converges rather than thrashing.
	if s.NeedsApply() {
		t.Error("RG1 still needs an apply after the post-fence re-drive succeeded")
	}
	d.reconcileRGState()
	if got := rec.take(); len(got) != 0 {
		t.Errorf("a converged RG re-wrote rg_active on a later pass: %v", got)
	}
}

// TestInvalidateAppliedRearmsAnySecondWriter is the generic half: the class of
// defect is "any writer that changes rg_active outside the state machine's
// transition path blinds the retry", and the fence is one instance. This binds
// the entry point itself, so a future third writer inherits a correct
// mechanism rather than a review-enforced invariant.
func TestInvalidateAppliedRearmsAnySecondWriter(t *testing.T) {
	t.Run("second writer contradicts the desired value", func(t *testing.T) {
		s := newRGStateMachine()
		tr := s.SetCluster(true)
		if !tr.Active {
			t.Fatal("fixture: cluster primary must make rg_active desired")
		}
		s.MarkApplied(true)
		if s.NeedsApply() {
			t.Fatal("fixture: a successful apply must converge before the second writer runs")
		}

		s.InvalidateApplied()

		if !s.NeedsApply() {
			t.Fatal("an out-of-band rg_active write left the retry disarmed")
		}
		// Reconcile is what the 2s loop calls every pass. It recomputes the
		// desired value; with the inputs unchanged it must NOT clear the
		// re-armed retry, or the pass that was supposed to repair the drift
		// would disarm it instead.
		tr = s.Reconcile(true, nil)
		if tr.Changed {
			t.Fatal("fixture: the desired value must be unchanged, so NeedsApply is " +
				"the only thing that can carry the retry")
		}
		if !s.NeedsApply() {
			t.Fatal("a reconcile pass disarmed the retry instead of re-driving it")
		}

		s.MarkApplied(true)
		if s.NeedsApply() {
			t.Error("a successful re-apply did not converge the state machine")
		}
	})

	t.Run("second writer agrees with the desired value", func(t *testing.T) {
		// The fence writes false while this node is already secondary, so the
		// value it wrote matches the desired one. InvalidateApplied still arms
		// the retry: a write that reported success may not have landed
		// completely, and "not known to have converged" is the only honest
		// reading. The cost is one idempotent re-apply, and it must converge
		// on that one — not thrash.
		s := newRGStateMachine()
		s.SetCluster(false)
		s.MarkApplied(false)
		if s.NeedsApply() {
			t.Fatal("fixture: a secondary RG with rg_active applied false must be converged")
		}

		s.InvalidateApplied()

		if !s.NeedsApply() {
			t.Fatal("a failed out-of-band write is not proof of convergence: the retry " +
				"must be armed even when the value written matches the desired one")
		}
		s.MarkApplied(false)
		if s.NeedsApply() {
			t.Error("the idempotent re-apply did not converge: this would thrash every 2s")
		}
	})
}

// TestInvalidateAppliedKeepsStructInvariant guards the internal invariant
// reconcileLocked depends on: applyPending is true exactly when applied !=
// active. If InvalidateApplied armed applyPending without moving applied, a
// later edit that recomputed applyPending from the comparison would silently
// disarm the re-arm.
func TestInvalidateAppliedKeepsStructInvariant(t *testing.T) {
	for _, primary := range []bool{true, false} {
		s := newRGStateMachine()
		s.SetCluster(primary)
		s.MarkApplied(primary)

		s.InvalidateApplied()

		s.mu.Lock()
		applied, active, pending := s.applied, s.active, s.applyPending
		s.mu.Unlock()
		if applied == active {
			t.Errorf("clusterPri=%t: applied=%t equals active=%t after InvalidateApplied; "+
				"the struct claims a convergence it did not observe", primary, applied, active)
		}
		if !pending {
			t.Errorf("clusterPri=%t: applyPending is false after InvalidateApplied", primary)
		}
	}
}
