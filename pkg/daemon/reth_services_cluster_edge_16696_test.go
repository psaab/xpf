package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
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
	if !serviceEdge16696(d) {
		t.Fatal("#17746 control: configured apply did not reach its tail (no proxy-ARP nudge)")
	}

	d.clearRethServicesForRG(1)
	if d.rethServicesAppliedFor(1) {
		t.Fatal("#17746 control: configured clear left the marker applied")
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
