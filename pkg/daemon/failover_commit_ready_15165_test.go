package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #15165 (B22-03): under no-private-rg-election the only commit-ready
// setter on the VRRP path needs AllVRRPMaster, which is false with zero
// instances. RG0 never gets a RETH VRRP instance, so the RG0 failover
// probe always timed out. These cells drive the real setters and probe.
//
// FAIL-ON-REVERT: removing the legacyNoRethVRRPCommitReady arms (or the
// probe's legacy arm) leaves the RG0 flag unset and the probe times out.

func legacyRG0Daemon15165(t *testing.T) (*Daemon, *midApplyFenceHA) {
	t.Helper()
	store := testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster authentication-key test-cluster-psk-15165",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	// Drain election events; handleClusterEvent / reconcile below are
	// driven directly.
	for drained := true; drained; {
		select {
		case <-cm.Events():
		default:
			drained = false
		}
	}
	rec := &midApplyFenceHA{}
	d := &Daemon{
		rgStates:                   make(map[int]*rgStateMachine),
		cluster:                    cm,
		store:                      store,
		vrrpMgr:                    vrrp.NewManager(),
		userspaceDemotionPrepUntil: make(map[int]time.Time),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 500 * time.Millisecond,
		localFailoverCommitDelay:   0,
	}
	d.setDataplane(&midApplyFenceDP{Manager: dataplane.New(), ha: rec})
	if d.isNoRethVRRP() {
		t.Fatal("fixture: legacy mode must have isNoRethVRRP()=false")
	}
	if !cm.IsLocalPrimary(0) {
		t.Fatal("fixture: node 0 must be RG0 primary")
	}
	cc := store.ActiveConfig().Chassis.Cluster
	if cc == nil || cc.PrivateRGElection || cc.NoRethVRRP {
		t.Fatalf("fixture: want legacy mode (PrivateRGElection=false, NoRethVRRP=false), got %+v", cc)
	}
	if got := d.expectedRethVRRPCounts()[0]; got != 0 {
		t.Fatalf("fixture: RG0 must expect zero RETH VRRP instances, got %d", got)
	}
	if got := d.expectedRethVRRPCounts()[1]; got != 1 {
		t.Fatalf("fixture: RG1 must expect one RETH VRRP instance, got %d", got)
	}
	return d, rec
}

func TestLegacyRG0CommitReadyOnClusterPromotion15165(t *testing.T) {
	d, _ := legacyRG0Daemon15165(t)

	if timer := d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 0, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
	}, nil); timer != nil {
		timer.Stop()
	}

	if !d.localFailoverCommitIsReady(0) {
		t.Fatal("legacy RG0 (no RETH VRRP instance by construction) must be " +
			"commit-ready once cluster primary and converged; without this the " +
			"RG0 failover probe times out deterministically (#15165)")
	}
	if err := d.waitLocalFailoverCommitReady([]int{0}); err != nil {
		t.Fatalf("legacy RG0 probe must return nil, got %v (#15165)", err)
	}
}

func TestLegacyRG0ProbeReadyWithoutSetterEvent15165(t *testing.T) {
	d, _ := legacyRG0Daemon15165(t)

	// Simulate a promotion whose cluster event was dropped: record the
	// cluster-primary desired state and its convergence directly, with
	// no setter having run. The probe's legacy arm must still return nil.
	s := d.getOrCreateRGState(0)
	tr := s.SetCluster(true)
	if !recordRGActiveAppliedIfCurrentOrStable(s, tr, true) {
		t.Fatal("fixture: RG0 convergence record must be accepted")
	}
	if d.localFailoverCommitIsReady(0) {
		t.Fatal("fixture: no setter must have run for RG0 in this cell")
	}
	if err := d.waitLocalFailoverCommitReady([]int{0}); err != nil {
		t.Fatalf("legacy RG0 probe arm must return nil for a converged primary, got %v (#15165)", err)
	}
}

func TestLegacyRG0ReconcileRaisesCommitReady15165(t *testing.T) {
	d, rec := legacyRG0Daemon15165(t)

	d.reconcileRGState()

	if got := rec.countOf(rgActiveWrite{rgID: 0, active: true}); got == 0 {
		t.Fatalf("fixture: RG0 was never activated (writes=%v)", rec.take())
	}
	if !d.localFailoverCommitIsReady(0) {
		t.Fatal("legacy RG0 must be commit-ready after an accepted reconcile apply (#15165)")
	}
}

func TestLegacyDataRGAwaitingVRRPStaysGated15165(t *testing.T) {
	d, _ := legacyRG0Daemon15165(t)

	// RG1 expects a RETH VRRP instance but none is MASTER yet. Neither
	// the reconcile pass nor the probe may raise its readiness.
	d.reconcileRGState()
	if d.localFailoverCommitIsReady(1) {
		t.Fatal("RG1 expects a RETH VRRP instance; readiness must stay gated on AllVRRPMaster (#15165 control)")
	}
	d.localFailoverCommitTimeout = 60 * time.Millisecond
	if err := d.waitLocalFailoverCommitReady([]int{1}); err == nil ||
		!strings.Contains(err.Error(), "timed out waiting for local failover activation settle") {
		t.Fatalf("RG1 probe must time out while its VRRP instance is not MASTER, got %v (#15165 control)", err)
	}

	// Once the instance is MASTER and the RG has converged, the existing
	// VRRP-path predicate must raise readiness (paired control).
	s := d.getOrCreateRGState(1)
	s.SetVRRP("reth1", true)
	if !s.AllVRRPMaster() {
		t.Fatal("fixture: RG1 must be all-MASTER after SetVRRP")
	}
	if !d.cluster.IsLocalPrimary(1) {
		t.Fatal("fixture: node 0 must be RG1 primary")
	}
	if s.NeedsApply() {
		tr := s.Reconcile(true, map[string]bool{"reth1": true})
		recordRGActiveAppliedIfCurrentOrStable(s, tr, true)
	}
	// This is the exact predicate the VRRP MASTER arm uses.
	if !(d.cluster.IsLocalPrimary(1) && s.AllVRRPMaster()) {
		t.Fatal("fixture: VRRP MASTER predicate must hold for RG1")
	}
	d.setLocalFailoverCommitReady(1, true)
	if err := d.waitLocalFailoverCommitReady([]int{1}); err != nil {
		t.Fatalf("RG1 probe must return nil once all-MASTER, got %v", err)
	}
}

func TestLegacyRG0NotReadyWhileApplyPending15165(t *testing.T) {
	d, _ := legacyRG0Daemon15165(t)

	s := d.getOrCreateRGState(0)
	s.SetCluster(true) // desired active, not yet applied
	if !s.NeedsApply() {
		t.Fatal("fixture: RG0 must need an apply after promotion")
	}
	if d.legacyNoRethVRRPCommitReady(0, s, false) {
		t.Fatal("legacy RG0 must not be commit-ready while rg_active is unconverged (#15165)")
	}
	d.localFailoverCommitTimeout = 60 * time.Millisecond
	if err := d.waitLocalFailoverCommitReady([]int{0}); err == nil {
		t.Fatal("RG0 probe must time out while rg_active is unconverged (#15165)")
	}
}

func TestLegacyPredicateRejectsDirectModeAndNonPrimary15165(t *testing.T) {
	d, _ := legacyRG0Daemon15165(t)
	s := d.getOrCreateRGState(0)
	tr := s.SetCluster(true)
	recordRGActiveAppliedIfCurrentOrStable(s, tr, true)

	if d.legacyNoRethVRRPCommitReady(0, s, true) {
		t.Error("direct/private-RG mode must not use the legacy predicate (its own setters cover it)")
	}
	d.cluster.SetGroupStateForTesting(0, cluster.StateSecondary)
	if d.legacyNoRethVRRPCommitReady(0, s, false) {
		t.Error("a non-primary node must not be legacy commit-ready")
	}
}

// Control: a daemon with no committed config must NOT be treated as
// legacy. isNoRethVRRP() is false there too, so a bare !noRethVRRP gate
// would fail open and return instantly-ready for RG0 — which is exactly
// what the pre-existing #5250 timeout cells pin against.
func TestLegacyPredicateRequiresCommittedLegacyConfig15165(t *testing.T) {
	d := &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 60 * time.Millisecond,
		localFailoverCommitDelay:   0,
	}
	if !d.cluster.IsLocalPrimary(0) {
		t.Fatal("fixture: node 0 must be RG0 primary")
	}
	if d.isNoRethVRRP() {
		t.Fatal("fixture: storeless daemon reads as !noRethVRRP — the trap this cell pins")
	}
	if err := d.waitLocalFailoverCommitReady([]int{0}); err == nil ||
		!strings.Contains(err.Error(), "timed out waiting for local failover activation settle") {
		t.Fatalf("storeless RG0 probe must time out (no affirmative legacy config), got %v (#15165)", err)
	}
}
