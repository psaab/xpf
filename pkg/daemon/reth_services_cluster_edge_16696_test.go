package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #16696 (R3-A34-04): in legacy non-strict mode rg-state desired =
// clusterPri || allVrrpMaster, so EITHER input can be the one that flips
// desired. Only the watchVRRPEvents and reconcile tr.Changed arms ran
// applyRethServicesForRG / clearRethServicesForRG; handleClusterEvent made
// rg-state edges but ran neither. When the cluster event flipped desired,
// the service edge was lost permanently: the later VRRP/reconcile inputs
// report Changed=false.
//
// Observable: the proxy-ARP nudge. Both apply and clear send it
// unconditionally (clear before its early returns), and no other code in
// these handlers does — the probe the source report used. The nudge
// channel is depth-1/coalescing, so counting is done by draining between
// steps: exactly one drainable nudge per service edge.
//
// RED on revert: drop the driveRethServicesEdge calls in
// handleClusterEvent and the first drain in each ordering row fails; drop
// the convergeRethServices arm in reconcileRGState and the converger rows
// fail; drop the marker writes and the converger re-drives every pass
// (idempotence rows fail).

func legacyServicesDaemon16696(t *testing.T) *Daemon {
	t.Helper()
	d := newRethFenceDaemon(t, &actuationHA{}, newFakeVIPRelease())
	d.proxyARPNudgeCh = make(chan struct{}, 1)
	// handleClusterEvent's promotion arm republishes connected routes
	// synchronously under applySem (#16270); the fence fixture leaves it nil.
	d.applySem = semaphore.NewWeighted(1)
	// RG1 starts secondary/inactive with services never applied.
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	return d
}

// syncCluster16696 keeps the cluster manager's view of RG1 in step with
// the synthetic event being driven, so reconcileRGState's authoritative
// re-derivation (IsLocalPrimary) agrees with the event stream.
func syncCluster16696(d *Daemon, rgID int, primary bool) {
	st := cluster.StateSecondary
	if primary {
		st = cluster.StatePrimary
	}
	d.cluster.SetGroupStateForTesting(rgID, st)
}

// serviceEdge16696 drains one pending nudge, reporting whether a service
// edge fired since the last drain.
func serviceEdge16696(d *Daemon) bool {
	select {
	case <-d.proxyARPNudgeCh:
		return true
	default:
		return false
	}
}

func handleCluster16696(t *testing.T, d *Daemon, rgID int, old, newState cluster.NodeState) {
	t.Helper()
	if timer := d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: rgID, OldState: old, NewState: newState,
	}, nil); timer != nil {
		timer.Stop()
	}
}

// Promotion, cluster-first: SetCluster(true) flips desired; the service
// edge must run on THIS event. The later VRRP MASTER must not re-apply.
func TestClusterFirstPromotionAppliesServices16696(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	s := d.getOrCreateRGState(1)

	handleCluster16696(t, d, 1, cluster.StateSecondary, cluster.StatePrimary)
	if !s.IsActive() {
		t.Fatal("setup: cluster promotion must make RG1 desired-active")
	}
	if !serviceEdge16696(d) {
		t.Fatal("#16696: cluster-first promotion ran no applyRethServicesForRG — " +
			"the new owner never gets its Kea RG groups or data-RG IPsec re-initiate")
	}

	// VRRP MASTER arrives second: desired already active, no double-apply.
	if tr := s.SetVRRP("reth1", true); tr.Changed {
		t.Fatalf("setup: second input must report Changed=false, got %+v", tr)
	}
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#16696: service marker lost after promotion")
	}
	// Direct converger probe: desired==applied, so it must be a no-op.
	// (A full reconcile pass also drives RG0 — the manager seats it
	// primary — whose nudge is not RG1 double-apply.)
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#16696: converger re-applied services on a converged RG")
	}
	syncCluster16696(d, 1, true)
	handleCluster16696(t, d, 1, cluster.StateSecondary, cluster.StatePrimary)
	if serviceEdge16696(d) {
		t.Fatal("#16696: double-apply — second cluster event re-ran services")
	}
}

// Promotion, VRRP-first (control): the VRRP input flips desired and the
// reconcile pass drives the edge; the later cluster event must not
// re-apply.
func TestVRRPFirstPromotionAppliesServicesOnce16696(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	s := d.getOrCreateRGState(1)

	tr := s.SetVRRP("reth1", true)
	if !tr.Changed || !tr.Active {
		t.Fatalf("setup: VRRP-first input must flip desired active, got %+v", tr)
	}
	// Drive the same call the watchVRRPEvents MASTER arm makes on this
	// transition (the arm itself needs a live manager event loop; the
	// transition and the call are the production pair).
	d.driveRethServicesEdge(1, tr, false)
	if !serviceEdge16696(d) {
		t.Fatal("#16696: VRRP-first promotion ran no applyRethServicesForRG (control row)")
	}

	// The synthetic SetVRRP bypassed reconcile's authoritative VRRP map,
	// so a reconcile pass would (correctly, in production terms) forget
	// the instance and demote — the cluster event is driven directly
	// here instead, with the manager synced to match.
	syncCluster16696(d, 1, true)
	handleCluster16696(t, d, 1, cluster.StateSecondary, cluster.StatePrimary)
	if serviceEdge16696(d) {
		t.Fatal("#16696: double-apply — cluster event re-ran services after VRRP-first promotion")
	}
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#16696: marker lost after cluster event")
	}
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#16696: converger re-applied services on a converged RG")
	}
}

// Demotion, VRRP-first (the ordinary preempt-failback order on the old
// owner): BACKUP while cluster is still primary changes nothing; the
// following cluster demotion flips desired and must clear services —
// Kea RG groups and the #15194 SA terminate live inside the clear.
func TestVRRPFirstDemotionClearsServicesOnClusterEdge16696(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	s := d.getOrCreateRGState(1)

	// Establish ownership: cluster primary + services applied.
	handleCluster16696(t, d, 1, cluster.StateSecondary, cluster.StatePrimary)
	if !serviceEdge16696(d) {
		t.Fatal("setup: promotion must apply services")
	}
	syncCluster16696(d, 1, true)

	// Peer's advert makes this node VRRP BACKUP while still cluster
	// primary: desired stays true, nothing may run.
	if tr := s.SetVRRP("reth1", false); tr.Changed {
		t.Fatalf("setup: BACKUP under cluster-primary must not flip desired, got %+v", tr)
	}
	if serviceEdge16696(d) {
		t.Fatal("setup: no service edge may run while desired is still active")
	}

	// Cluster demotion flips desired: the clear must run HERE.
	handleCluster16696(t, d, 1, cluster.StatePrimary, cluster.StateSecondary)
	if s.IsActive() {
		t.Fatal("setup: cluster demotion must make RG1 desired-inactive")
	}
	if !serviceEdge16696(d) {
		t.Fatal("#16696: VRRP-first demotion ran no clearRethServicesForRG on the cluster " +
			"edge — the old owner keeps its Kea RG groups and RG-anchored SAs")
	}

	if d.rethServicesAppliedFor(1) {
		t.Fatal("#16696: marker still applied after demotion clear")
	}
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#16696: converger re-cleared services on a converged RG")
	}
}

// Demotion, cluster-first (control): cluster demotion alone must NOT
// clear while VRRP still masters (desired = pri || master); the BACKUP
// that follows must.
func TestClusterDemotionWhileVRRPMasterKeepsServices16696(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	s := d.getOrCreateRGState(1)

	handleCluster16696(t, d, 1, cluster.StateSecondary, cluster.StatePrimary)
	if !serviceEdge16696(d) {
		t.Fatal("setup: promotion must apply services")
	}
	if tr := s.SetVRRP("reth1", true); tr.Changed {
		t.Fatalf("setup: VRRP MASTER after cluster promotion must be Changed=false, got %+v", tr)
	}

	handleCluster16696(t, d, 1, cluster.StatePrimary, cluster.StateSecondary)
	if !s.IsActive() {
		t.Fatal("OR semantics: VRRP MASTER alone must keep desired active after cluster demotion")
	}
	if serviceEdge16696(d) {
		t.Fatal("#16696: services cleared while the RG is still desired-active (VRRP MASTER)")
	}

	if tr := s.SetVRRP("reth1", false); !tr.Changed || tr.Active {
		t.Fatalf("setup: BACKUP after cluster demotion must flip desired inactive, got %+v", tr)
	}
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.reconcileRGState()
	if !serviceEdge16696(d) {
		t.Fatal("#16696: BACKUP after cluster demotion ran no clearRethServicesForRG")
	}
}

// Converger, promotion: an rg-state edge produced outside every service
// driver (the #15258 sync-hold mirror class — syncRGSyncHold discards the
// transition) leaves desired != the last driven ownership edge. The next
// reconcile pass must apply services exactly once.
func TestConvergerAppliesLostPromotionEdge16696(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	s := d.getOrCreateRGState(1)

	// Hold the RG, feed the VRRP MASTER under the hold (suppressed), then
	// release the hold through the mirror — whose transition no caller
	// consumes. This is the discarded-edge shape, produced with the real
	// state machine rather than by poking internals.
	s.SetSyncHold(true)
	if tr := s.SetVRRP("reth1", true); tr.Changed {
		t.Fatalf("setup: held MASTER must be suppressed, got %+v", tr)
	}
	s.SetSyncHold(false) // transition returned and discarded, as syncRGSyncHold does
	if !s.IsActive() {
		t.Fatal("setup: hold release must re-derive desired active")
	}
	if serviceEdge16696(d) {
		t.Fatal("setup: the discarded mirror transition must not itself run services")
	}

	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.reconcileRGState()
	if !serviceEdge16696(d) {
		t.Fatal("#16696: reconcile converger did not repair the lost promotion edge")
	}
	d.reconcileRGState()
	if serviceEdge16696(d) {
		t.Fatal("#16696: converger re-applied services on a converged RG (not idempotent)")
	}
}

// Converger, demotion: services applied, then desired drops via a
// discarded mirror transition. KernelUpgradeHold is the mirror whose
// daemon-side source reconcile re-derives from the cluster manager's
// (unarmed) hold, so with the manager unarmed the machine-side hold set
// here is mirrored back off — instead drive it through syncRGKernelUpgradeHold's
// own source: arm the manager hold via the state machine only and keep
// cluster primary false so Reconcile cannot re-activate. The pass's
// Reconcile(clusterPri=false, vrrpMaster) would re-activate via VRRP, so
// this row uses no VRRP instance: desired stays false from clusterPri=false.
func TestConvergerClearsLostDemotionEdge16696(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	s := d.getOrCreateRGState(1)

	handleCluster16696(t, d, 1, cluster.StateSecondary, cluster.StatePrimary)
	if !serviceEdge16696(d) {
		t.Fatal("setup: promotion must apply services")
	}

	// Discarded-edge demotion: clear the cluster input directly on the
	// state machine (no handler runs), as a mirror refresh would.
	if tr := s.SetCluster(false); !tr.Changed || tr.Active {
		t.Fatalf("setup: direct SetCluster(false) must flip desired inactive, got %+v", tr)
	}
	if serviceEdge16696(d) {
		t.Fatal("setup: the discarded transition must not itself run services")
	}

	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.reconcileRGState()
	if s.IsActive() {
		t.Fatal("setup: desired must stay inactive through the pass")
	}
	if !serviceEdge16696(d) {
		t.Fatal("#16696: reconcile converger did not repair the lost demotion edge")
	}
	d.reconcileRGState()
	if serviceEdge16696(d) {
		t.Fatal("#16696: converger re-cleared services on a converged RG (not idempotent)")
	}
}

// #17746: the #16696 converger compares desired ownership against the last
// driven edge. Previously apply/clear wrote that marker only at the tail,
// so reset/store/config early returns left the marker stale. Every degraded
// pass then repeated the ownership-epoch bump; clear also repeated its
// pre-guard proxy-ARP sweep. Entry marking stops that churn, while a pending
// bit keeps the skipped service tail owed. The converger waits while reset
// or config is unhealthy, then drives the tail once on recovery and clears
// pending. The existing #16696 fixture always has committed config and did
// not cover either the degraded or recovery paths.
//
// RED on reverting to tail-only markers: degraded marker assertions fail.
// RED on entry markers without pending recovery: the apply/reset/config and
// clear/config recovery assertions below fail after health returns. Epoch
// assertions prove later degraded passes do not repeat the epoch bump.
func resizeNudge17746(d *Daemon) {
	d.proxyARPNudgeCh = make(chan struct{}, 8)
}

// nilConfigStore17746 returns a real configstore.Store whose
// ActiveConfig() is nil (nothing committed yet) — apply/clear's last
// early-return arm, distinct from a nil store.
func nilConfigStore17746(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if s.ActiveConfig() != nil {
		t.Fatal("setup: fresh store must have a nil ActiveConfig")
	}
	return s
}

// Apply side: desired active is set through the state machine's discarded
// edge, but the store is nil. Convergence must advance the marker and set a
// pending tail, then stay quiet without repeating the ownership-epoch bump.
func TestConvergerApplyNilStoreAdvancesMarker17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	d.store = nil

	d.convergeRethServices(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: apply hit the nil-store early return without advancing the marker; " +
			"the converger will re-drive it on every reconcile pass")
	}
	degradedEpoch := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove apply on a degraded-converged RG")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != degradedEpoch {
		t.Fatalf("#17746: degraded apply re-bumped ownership epoch on a later pass: before=%d after=%d",
			degradedEpoch, got)
	}
}

// Apply side, last guard: store present but ActiveConfig() nil. Once the
// committed store is available again, the marker-converged RG must still get
// deferred tail driven exactly once by the converger.
func TestConvergerApplyNilConfigAdvancesMarker17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	healthy := d.store
	d.store = nilConfigStore17746(t)

	d.convergeRethServices(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: apply hit the nil-config early return without advancing the marker; " +
			"the converger will re-drive it on every reconcile pass")
	}
	degradedEpoch := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove apply on a degraded-converged RG")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != degradedEpoch {
		t.Fatalf("#17746: apply re-bumped ownership epoch while config was degraded: before=%d after=%d",
			degradedEpoch, got)
	}

	// Recovery: restore the committed store. The converger must drive the
	// apply tail exactly once for the RG that was degraded.
	d.store = healthy
	epochBeforeRecovery := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if !serviceEdge16696(d) {
		t.Fatal("#17746: converger did not drive the deferred apply tail after config recovery")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochBeforeRecovery+1 {
		t.Fatalf("#17746: recovery apply did not run exactly once: epoch before=%d after=%d",
			epochBeforeRecovery, got)
	}
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: marker must remain applied after the recovery drive")
	}
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove the apply tail after the recovery drive")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochBeforeRecovery+1 {
		t.Fatalf("#17746: converger re-drove recovery apply: epoch before=%d after=%d",
			epochBeforeRecovery, got)
	}
}

// If desired ownership changes again while an apply tail is pending, the new
// edge still has immediate work: clear's proxy-ARP sweep is before its config
// guard. A pending retry must be suppressed only when its marker matches the
// current desired state; suppressing this changed edge delays the safety sweep.
func TestPendingApplyDemotionWithNilConfigDrivesClearEdge17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	healthy := d.store
	d.store = nilConfigStore17746(t)

	d.convergeRethServices(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("setup: degraded apply must record active ownership")
	}
	if serviceEdge16696(d) {
		t.Fatal("setup: apply before its nil-config guard must not reach the proxy-ARP nudge")
	}
	epochAfterApply := d.ipsecRGOwnershipEpoch(1)

	if tr := s.SetCluster(false); !tr.Changed || tr.Active {
		t.Fatalf("setup: SetCluster(false) must flip desired inactive, got %+v", tr)
	}
	d.convergeRethServices(1)
	if !serviceEdge16696(d) {
		t.Fatal("#17746: pending apply suppressed the changed demotion edge's immediate proxy-ARP sweep")
	}
	if d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: changed demotion edge did not advance the marker to inactive")
	}
	epochAfterDemotion := d.ipsecRGOwnershipEpoch(1)
	if epochAfterDemotion != epochAfterApply+1 {
		t.Fatalf("#17746: changed demotion edge did not run exactly once: apply epoch=%d demotion epoch=%d",
			epochAfterApply, epochAfterDemotion)
	}

	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger repeated the degraded clear sweep while config remained unavailable")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochAfterDemotion {
		t.Fatalf("#17746: pending clear repeated its ownership-epoch bump: before=%d after=%d",
			epochAfterDemotion, got)
	}

	d.store = healthy
	epochBeforeRecovery := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if !serviceEdge16696(d) {
		t.Fatal("#17746: pending clear tail was not driven after config recovery")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochBeforeRecovery+1 {
		t.Fatalf("#17746: recovered clear tail did not run exactly once: before=%d after=%d",
			epochBeforeRecovery, got)
	}
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger repeated the recovered clear tail")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochBeforeRecovery+1 {
		t.Fatalf("#17746: converger repeated the recovered clear epoch bump: before=%d after=%d",
			epochBeforeRecovery, got)
	}
}

// Apply side, first guard: factory reset in progress. After the reset
// exits, the converger must drive the deferred apply tail exactly once
// even though the marker already reads applied.
func TestConvergerApplyResettingAdvancesMarker17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	d.enterResetGeneration()

	// The converger drives the degraded edge: the marker advances, so it
	// does not re-fire every pass, but the tail still owes a recovery drive.
	d.convergeRethServices(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: apply hit the reset early return without advancing the marker; " +
			"the converger will re-drive it on every reconcile pass")
	}
	degradedEpoch := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove apply while the reset is still in progress")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != degradedEpoch {
		t.Fatalf("#17746: apply re-bumped ownership epoch while reset was active: before=%d after=%d",
			degradedEpoch, got)
	}

	// Recovery: the reset exits, store untouched (committed throughout).
	// Converge must now drive the apply tail exactly once.
	d.exitResetGeneration()
	epochBeforeRecovery := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if !serviceEdge16696(d) {
		t.Fatal("#17746: converger did not drive the deferred apply tail after reset recovery")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochBeforeRecovery+1 {
		t.Fatalf("#17746: reset recovery apply did not run exactly once: epoch before=%d after=%d",
			epochBeforeRecovery, got)
	}
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove the apply tail after the recovery drive")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochBeforeRecovery+1 {
		t.Fatalf("#17746: converger re-drove reset recovery apply: epoch before=%d after=%d",
			epochBeforeRecovery, got)
	}
}

// Configured control: with the committed store present, apply and clear
// both proceed through their service work and record the corresponding
// ownership markers.
func TestConfiguredApplyClearTailsAdvanceMarker17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)

	d.applyRethServicesForRG(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#17746 control: configured apply left the marker cleared")
	}
	if state := d.rethServicesStateFor(1); state.pending {
		t.Fatalf("#17746 control: missing DHCP applier was misclassified as reset-fenced pending: %+v", state)
	}
	if !serviceEdge16696(d) {
		t.Fatal("#17746 control: configured apply did not reach its tail (no proxy-ARP nudge)")
	}

	d.clearRethServicesForRG(1)
	if d.rethServicesAppliedFor(1) {
		t.Fatal("#17746 control: configured clear left the marker applied")
	}
	if state := d.rethServicesStateFor(1); state.pending {
		t.Fatalf("#17746 control: missing DHCP applier was misclassified as reset-fenced pending: %+v", state)
	}
	if !serviceEdge16696(d) {
		t.Fatal("#17746 control: configured clear did not run past its guard (no proxy-ARP nudge)")
	}
}

// Clear side: services applied, desired drops via a discarded mirror
// transition (SetCluster(false) with no handler), store now nil. The clear
// edge sends its proxy-ARP sweep before the store guard. Pending state must
// suppress another sweep while the store is unavailable; the ActiveConfig
// recovery cell below proves the owed clear tail runs once config returns.
func TestConvergerClearNilStoreAdvancesMarker17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	d.applyRethServicesForRG(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("setup: configured apply must set the marker")
	}
	if !serviceEdge16696(d) {
		t.Fatal("setup: configured apply must nudge proxy-ARP")
	}
	if tr := s.SetCluster(false); !tr.Changed || tr.Active {
		t.Fatalf("setup: SetCluster(false) must flip desired inactive, got %+v", tr)
	}
	d.store = nil

	d.convergeRethServices(1)
	if d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: clear hit the nil-store early return without advancing the marker; " +
			"the converger will re-drive it on every reconcile pass")
	}
	// Exactly one edge fired for this degrade: drain it, and a second
	// converge must then be a no-op (no fresh nudge).
	if !serviceEdge16696(d) {
		t.Fatal("#17746: degraded clear sent no proxy-ARP sweep nudge")
	}
	degradedEpoch := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove clear on a degraded-converged RG " +
			"(fresh proxy-ARP nudge on the second pass)")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != degradedEpoch {
		t.Fatalf("#17746: degraded clear re-bumped ownership epoch: before=%d after=%d",
			degradedEpoch, got)
	}
}

// Clear side, last guard: store present but ActiveConfig() nil.
func TestConvergerClearNilConfigAdvancesMarker17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	d.applyRethServicesForRG(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("setup: configured apply must set the marker")
	}
	if !serviceEdge16696(d) {
		t.Fatal("setup: configured apply must nudge proxy-ARP")
	}
	if tr := s.SetCluster(false); !tr.Changed || tr.Active {
		t.Fatalf("setup: SetCluster(false) must flip desired inactive, got %+v", tr)
	}
	healthy := d.store
	d.store = nilConfigStore17746(t)

	d.convergeRethServices(1)
	if d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: clear hit the nil-config early return without advancing the marker; " +
			"the converger will re-drive it on every reconcile pass")
	}
	if !serviceEdge16696(d) {
		t.Fatal("#17746: degraded clear sent no proxy-ARP sweep nudge")
	}
	degradedEpoch := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove clear on a degraded-converged RG " +
			"(fresh proxy-ARP nudge on the second pass)")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != degradedEpoch {
		t.Fatalf("#17746: clear re-bumped ownership epoch while config was degraded: before=%d after=%d",
			degradedEpoch, got)
	}

	// Recovery: restore the committed store. The converger must drive the
	// clear tail exactly once (first observable: a fresh proxy-ARP nudge).
	d.store = healthy
	epochBeforeRecovery := d.ipsecRGOwnershipEpoch(1)
	d.convergeRethServices(1)
	if !serviceEdge16696(d) {
		t.Fatal("#17746: converger did not drive the deferred clear tail after config recovery")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochBeforeRecovery+1 {
		t.Fatalf("#17746: recovery clear did not run exactly once: epoch before=%d after=%d",
			epochBeforeRecovery, got)
	}
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove clear after the recovery drive " +
			"(fresh proxy-ARP nudge on the second pass)")
	}
	if got := d.ipsecRGOwnershipEpoch(1); got != epochBeforeRecovery+1 {
		t.Fatalf("#17746: converger re-drove recovery clear: epoch before=%d after=%d",
			epochBeforeRecovery, got)
	}
}

// blockedPreSeedRethApplier17746 holds applyRethServicesForRG after it has
// captured active ownership but before it enqueues the DHCP config.
type blockedPreSeedRethApplier17746 struct {
	*recordingDHCPApplier9349
	entered chan struct{}
	release <-chan struct{}
}

func (b *blockedPreSeedRethApplier17746) PreSeedMemfileMerged4WithAuthority(
	ctx context.Context,
	snapshot dhcpserver.LeaseSyncSnapshot,
	now time.Time,
	stillMastering bool,
	authority dhcpserver.LeaseSyncAuthority,
) error {
	b.entered <- struct{}{}
	<-b.release
	return b.recordingDHCPApplier9349.PreSeedMemfileMerged4WithAuthority(
		ctx, snapshot, now, stillMastering, authority)
}

// #18399: an apply may capture active RETH ownership and block in the
// pre-seed before enqueuing Kea. If a newer degraded clear marks the RG
// inactive and returns, the stale apply must not erase its pending retry
// when it later enqueues the old active config.
//
// RED on revert: entry-marker-only completion clears pending after the
// stale apply enqueues, leaving desired=false == marker=false. Recovery
// then skips clear and the stale active config remains the final enqueue.
func TestRev18399StaleApplyAfterClearMustBeReconciled(t *testing.T) {
	d := twoRGCanonicalDaemon16854(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(2)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	healthy := d.store
	d.sessionSync.SetPeerDHCPLeaseSnapshotForTesting(4, dhcpserver.LeaseSyncSnapshot{
		Received:   true,
		Generation: 7,
		Leases: []dhcpserver.SyncLease{
			{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"},
		},
		Scopes: []dhcpserver.LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Generation: 7, Served: true, Applied: true},
		},
	})

	release := make(chan struct{})
	var releaseOnce sync.Once
	releasePreSeed := func() { releaseOnce.Do(func() { close(release) }) }
	applyDone := make(chan struct{})
	t.Cleanup(func() {
		releasePreSeed()
		select {
		case <-applyDone:
		case <-time.After(5 * time.Second):
			t.Error("blocked apply did not return after releasing pre-seed")
		}
	})

	rec := &recordingDHCPApplier9349{}
	blocked := &blockedPreSeedRethApplier17746{
		recordingDHCPApplier9349: rec,
		entered:                  make(chan struct{}, 1),
		release:                  release,
	}
	d.dhcpServer = blocked

	go func() {
		d.applyRethServicesForRG(2)
		close(applyDone)
	}()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("apply did not reach the blocked pre-seed")
	}

	d.store = nil
	if tr := s.SetCluster(false); !tr.Changed || tr.Active {
		t.Fatalf("setup: SetCluster(false) must flip desired inactive, got %+v", tr)
	}
	d.clearRethServicesForRG(2)
	if !serviceEdge16696(d) {
		t.Fatal("degraded clear did not sweep proxy-ARP before its config guard")
	}
	if d.rethServicesAppliedFor(2) {
		t.Fatal("degraded clear did not record inactive ownership")
	}

	releasePreSeed()
	select {
	case <-applyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("apply did not return after releasing the pre-seed")
	}
	if !serviceEdge16696(d) {
		t.Fatal("stale apply did not complete its proxy-ARP reassert nudge")
	}

	pending := d.rethServicesStateFor(2).pending
	if !pending {
		t.Fatal("#18399: stale apply completion cleared the newer degraded clear's pending tail")
	}
	rec.mu.Lock()
	if len(rec.authorityAsyncCfg) != 1 || rec.authorityAsyncCfg[0] == nil {
		got := len(rec.authorityAsyncCfg)
		rec.mu.Unlock()
		t.Fatalf("blocked apply did not enqueue its captured active DHCP config: calls=%d", got)
	}
	rec.mu.Unlock()

	d.store = healthy
	d.convergeRethServices(2)
	if !serviceEdge16696(d) {
		t.Fatal("#18399: converger did not drive clear after the stale apply completed")
	}
	if d.rethServicesAppliedFor(2) {
		t.Fatal("#18399: converger did not retain inactive ownership after recovery")
	}
	pending = d.rethServicesStateFor(2).pending
	if pending {
		t.Fatal("#18399: pending tail remained after the recovered clear completed")
	}
	rec.mu.Lock()
	configCount := len(rec.authorityAsyncCfg)
	finalConfigIsNil := configCount > 0 && rec.authorityAsyncCfg[configCount-1] == nil
	rec.mu.Unlock()
	if configCount != 2 || !finalConfigIsNil {
		t.Fatalf("#18399: stale active DHCP config remained last after recovery; configs=%v", rec.authorityAsyncCfg)
	}
	d.convergeRethServices(2)
	if serviceEdge16696(d) {
		t.Fatal("#18399: converger re-drove the recovered clear")
	}
	rec.mu.Lock()
	configCount = len(rec.authorityAsyncCfg)
	rec.mu.Unlock()
	if configCount != 2 {
		t.Fatalf("#18399: recovered clear enqueued DHCP more than once: calls=%d", configCount)
	}
}

// FOLD2 shape 1: an apply passes its entry reset check and blocks in the
// DHCP pre-seed. A factory reset begins (resetting=true) while the apply is
// blocked; the enqueue is then fenced and returns 0 without enqueueing.
// The edge must stay PENDING so failed-reset recovery re-drives it exactly
// once.
func TestApplyResetFenceDuringPreSeedRetainsPending17746(t *testing.T) {
	d := twoRGCanonicalDaemon16854(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(2)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	d.sessionSync.SetPeerDHCPLeaseSnapshotForTesting(4, dhcpserver.LeaseSyncSnapshot{
		Received:   true,
		Generation: 7,
		Leases: []dhcpserver.SyncLease{
			{Family: 4, Address: "10.0.61.77", HWAddress: "bb:77"},
		},
		Scopes: []dhcpserver.LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.61.0/24", RGID: 2, Generation: 7, Served: true, Applied: true},
		},
	})

	release := make(chan struct{})
	var releaseOnce sync.Once
	releasePreSeed := func() { releaseOnce.Do(func() { close(release) }) }
	applyDone := make(chan struct{})
	t.Cleanup(func() {
		releasePreSeed()
		select {
		case <-applyDone:
		case <-time.After(5 * time.Second):
			t.Error("blocked apply did not return after releasing pre-seed")
		}
	})
	rec := &recordingDHCPApplier9349{}
	blocked := &blockedPreSeedRethApplier17746{
		recordingDHCPApplier9349: rec,
		entered:                  make(chan struct{}, 1),
		release:                  release,
	}
	d.dhcpServer = blocked

	go func() {
		d.applyRethServicesForRG(2)
		close(applyDone)
	}()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("apply did not reach the blocked pre-seed")
	}

	// The pre-seed already captured its session-sync handle. Avoid starting an
	// unrelated peer-seed worker when the later retry applies.
	d.sessionSync = nil
	// The pre-seed's reset check passed before entering its blocking applier.
	// Reset now begins before the apply can reach the DHCP enqueue.
	d.enterResetGeneration()
	// While reset is active, converger must be quiet.
	d.convergeRethServices(2)
	rec.mu.Lock()
	countWhileBlocked := len(rec.authorityAsyncCfg)
	rec.mu.Unlock()
	if countWhileBlocked != 0 {
		t.Fatalf("DHCP enqueue crossed reset during blocked apply: count=%d", countWhileBlocked)
	}

	releasePreSeed()
	select {
	case <-applyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("apply did not return after releasing the pre-seed")
	}
	if !serviceEdge16696(d) {
		t.Fatal("stale/reset-fenced apply did not complete its proxy-ARP nudge")
	}

	// Enqueue was reset-fenced: nothing enqueued, pending must be retained.
	rec.mu.Lock()
	countAfterFence := len(rec.authorityAsyncCfg)
	rec.mu.Unlock()
	if countAfterFence != 0 {
		t.Fatalf("reset-fenced apply must enqueue nothing, got %d", countAfterFence)
	}
	state := d.rethServicesStateFor(2)
	if !state.pending || !state.active {
		t.Fatalf("reset-fenced apply must retain pending active edge, got %+v", state)
	}

	// Converger while resetting must not drive.
	d.convergeRethServices(2)
	rec.mu.Lock()
	if len(rec.authorityAsyncCfg) != 0 {
		rec.mu.Unlock()
		t.Fatal("converger drove DHCP while reset active")
	}
	rec.mu.Unlock()

	// Failed-reset exit without commit: converger must drive owed apply exactly once.
	d.exitResetGeneration()
	epochBefore := d.ipsecRGOwnershipEpoch(2)
	d.convergeRethServices(2)
	if !serviceEdge16696(d) {
		t.Fatal("failed-reset recovery did not drive owed apply")
	}
	if got := d.ipsecRGOwnershipEpoch(2); got != epochBefore+1 {
		t.Fatalf("recovery apply did not run exactly once: epoch %d -> %d", epochBefore, got)
	}
	rec.mu.Lock()
	countRecovery := len(rec.authorityAsyncCfg)
	var recoveryInterfaces []string
	if countRecovery > 0 {
		recoveredConfig := rec.authorityAsyncCfg[countRecovery-1]
		finalNonNil := recoveredConfig != nil
		if finalNonNil && recoveredConfig.DHCPLocalServer != nil {
			if group := recoveredConfig.DHCPLocalServer.Groups["lan-pool"]; group != nil {
				recoveryInterfaces = append([]string(nil), group.Interfaces...)
			}
		}
	}
	rec.mu.Unlock()
	if countRecovery != 1 {
		t.Fatalf("recovery apply must enqueue exactly one active config, count=%d", countRecovery)
	}
	if len(recoveryInterfaces) != 1 || recoveryInterfaces[0] != "ge-0-0-1" {
		t.Fatalf("recovery apply config does not serve RG2 through its resolved member: interfaces=%v",
			recoveryInterfaces)
	}
	if st := d.rethServicesStateFor(2); st.pending || !st.active {
		t.Fatalf("pending must clear after recovery apply, got %+v", st)
	}
	// Second converge is a no-op.
	d.convergeRethServices(2)
	if serviceEdge16696(d) {
		t.Fatal("converger re-drove after recovery apply")
	}
	rec.mu.Lock()
	if len(rec.authorityAsyncCfg) != 1 {
		rec.mu.Unlock()
		t.Fatal("recovery apply enqueued more than once on second converge")
	}
	rec.mu.Unlock()
}

// FOLD2 shape 2: demotion edge arrives while reset is active. The changed
// edge must run immediately (proxy-ARP sweep), but its DHCP enqueue is
// fenced so the clear tail stays pending. After failed-reset exit the
// converger must drive the clear exactly once, enqueueing inactive config.
func TestClearDemotionDuringResetRetainsPending17746(t *testing.T) {
	d := twoRGCanonicalDaemon16854(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(2)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	// The test measures the apply/clear enqueue, not the asynchronous peer seed.
	d.sessionSync = nil
	rec := &recordingDHCPApplier9349{}
	d.dhcpServer = rec
	// Bring services active first so demotion has stale active work to remove.
	d.applyRethServicesForRG(2)
	if !serviceEdge16696(d) {
		t.Fatal("setup: configured apply must nudge proxy-ARP")
	}
	rec.mu.Lock()
	if len(rec.authorityAsyncCfg) != 1 || rec.authorityAsyncCfg[0] == nil {
		c := len(rec.authorityAsyncCfg)
		rec.mu.Unlock()
		t.Fatalf("setup: apply must enqueue one active config, got %d", c)
	}
	rec.mu.Unlock()
	if st := d.rethServicesStateFor(2); st.pending || !st.active {
		t.Fatalf("setup: apply must be converged active, got %+v", st)
	}

	if tr := s.SetCluster(false); !tr.Changed || tr.Active {
		t.Fatalf("setup: SetCluster(false) must flip desired inactive, got %+v", tr)
	}
	d.enterResetGeneration()
	// Changed demotion during reset must run immediately: sweep before guard.
	d.convergeRethServices(2)
	if !serviceEdge16696(d) {
		t.Fatal("demotion during reset did not run immediate proxy-ARP sweep")
	}
	if d.rethServicesAppliedFor(2) {
		t.Fatal("demotion during reset did not record inactive ownership")
	}
	// DHCP enqueue was fenced: still only setup apply enqueued, pending retained.
	rec.mu.Lock()
	if len(rec.authorityAsyncCfg) != 1 {
		c := len(rec.authorityAsyncCfg)
		rec.mu.Unlock()
		t.Fatalf("clear DHCP enqueue crossed reset fence, configs=%d", c)
	}
	rec.mu.Unlock()
	state := d.rethServicesStateFor(2)
	if !state.pending || state.active {
		t.Fatalf("reset-fenced clear must retain pending inactive edge, got %+v", state)
	}
	// Anti-churn: repeated converge while resetting drives nothing.
	epochDegraded := d.ipsecRGOwnershipEpoch(2)
	d.convergeRethServices(2)
	d.convergeRethServices(2)
	if serviceEdge16696(d) {
		t.Fatal("converger re-drove clear while reset active")
	}
	if got := d.ipsecRGOwnershipEpoch(2); got != epochDegraded {
		t.Fatalf("converger re-bumped epoch while reset active: %d -> %d", epochDegraded, got)
	}
	rec.mu.Lock()
	if len(rec.authorityAsyncCfg) != 1 {
		rec.mu.Unlock()
		t.Fatal("converger enqueued DHCP while reset active")
	}
	rec.mu.Unlock()

	// Failed-reset exit: owed clear runs exactly once with inactive (nil) final config.
	d.exitResetGeneration()
	epochBefore := d.ipsecRGOwnershipEpoch(2)
	d.convergeRethServices(2)
	if !serviceEdge16696(d) {
		t.Fatal("failed-reset recovery did not drive owed clear")
	}
	if got := d.ipsecRGOwnershipEpoch(2); got != epochBefore+1 {
		t.Fatalf("recovery clear did not run exactly once: epoch %d -> %d", epochBefore, got)
	}
	rec.mu.Lock()
	count := len(rec.authorityAsyncCfg)
	finalNil := count > 0 && rec.authorityAsyncCfg[count-1] == nil
	rec.mu.Unlock()
	if count != 2 || !finalNil {
		t.Fatalf("recovery clear must enqueue inactive config exactly once, count=%d finalNil=%v", count, finalNil)
	}
	if st := d.rethServicesStateFor(2); st.pending || st.active {
		t.Fatalf("pending must clear after recovery clear, got %+v", st)
	}
	d.convergeRethServices(2)
	if serviceEdge16696(d) {
		t.Fatal("converger re-drove after recovery clear")
	}
	rec.mu.Lock()
	if len(rec.authorityAsyncCfg) != 2 {
		rec.mu.Unlock()
		t.Fatal("recovery clear enqueued more than once")
	}
	rec.mu.Unlock()
}
