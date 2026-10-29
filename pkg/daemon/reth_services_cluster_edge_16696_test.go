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
// transition) leaves desired != last-applied. The next reconcile pass
// must apply services exactly once.
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

// #17746: the #16696 converger compares desired ownership against
// rethServicesApplied and re-drives apply/clear on every reconcile pass
// until the marker advances. The marker was written only at the TAIL of
// applyRethServicesForRG / clearRethServicesForRG, past early returns
// (factory reset in progress, store nil, ActiveConfig nil) that hit
// exactly in the degraded states the converger exists for — so a lost
// edge in one of those states spun forever: every retry bumped the IPsec
// ownership epoch, and clear also repeated its proxy-ARP sweep before the
// store/config guards. If conditions later allowed service work, the stale
// marker could re-drive those effects on each pass too. The marker must be
// written at entry so every early return still records the driven
// ownership. The 16696 fixture always has a committed store, so its six
// tests never exercised these arms.
//
// RED on revert: restore the tail-only marker writes and the first-converge
// marker assertions below fail. Clear also sends a fresh proxy-ARP sweep
// nudge before its store guard on every pass; apply returns before its
// nudge, so its marker assertion is the RED signal.
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

// Apply side: desired active (SetCluster flips the state machine, the
// discarded-edge shape) but the store is nil. The converge pass must
// advance the marker to applied and then go quiet.
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
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove apply on a degraded-converged RG")
	}
}

// Apply side, last guard: store present but ActiveConfig() nil.
func TestConvergerApplyNilConfigAdvancesMarker17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	d.store = nilConfigStore17746(t)

	d.convergeRethServices(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: apply hit the nil-config early return without advancing the marker; " +
			"the converger will re-drive it on every reconcile pass")
	}
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove apply on a degraded-converged RG")
	}
}

// Apply side, first guard: factory reset in progress. isResetting is
// Daemon state, so this arm is NOT store-gated; restoring the store
// below is the control proving the retry requirement survives.
func TestConvergerApplyResettingAdvancesMarker17746(t *testing.T) {
	d := legacyServicesDaemon16696(t)
	resizeNudge17746(d)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Changed || !tr.Active {
		t.Fatalf("setup: SetCluster(true) must flip desired active, got %+v", tr)
	}
	d.enterResetGeneration()

	// Edge-producer invocation (VRRP/cluster path): the marker advances
	// even though no service work runs against the half-wiped box.
	d.applyRethServicesForRG(1)
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: apply skipped its marker write while resetting; " +
			"the converger will re-drive it on every reconcile pass")
	}

	// Once the reset finishes, a normal configured apply must still reach
	// its nudge/tail. Reset the marker to model a distinct unapplied edge
	// and isolate that control from the reset early return.
	d.exitResetGeneration()
	d.markRethServicesApplied(1, false)
	d.applyRethServicesForRG(1)
	if !serviceEdge16696(d) {
		t.Fatal("#17746 control: configured apply did not run the full tail " +
			"(no proxy-ARP nudge) once the store returned")
	}
	if !d.rethServicesAppliedFor(1) {
		t.Fatal("#17746 control: configured apply left the marker cleared")
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
// transition (SetCluster(false) with no handler), store now nil. The
// clear edge sends the proxy-ARP sweep nudge BEFORE its store guard, so
// a non-advancing marker is observable as a fresh nudge on every
// converge pass.
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
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove clear on a degraded-converged RG " +
			"(fresh proxy-ARP nudge on the second pass)")
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
	d.store = nilConfigStore17746(t)

	d.convergeRethServices(1)
	if d.rethServicesAppliedFor(1) {
		t.Fatal("#17746: clear hit the nil-config early return without advancing the marker; " +
			"the converger will re-drive it on every reconcile pass")
	}
	if !serviceEdge16696(d) {
		t.Fatal("#17746: degraded clear sent no proxy-ARP sweep nudge")
	}
	d.convergeRethServices(1)
	if serviceEdge16696(d) {
		t.Fatal("#17746: converger re-drove clear on a degraded-converged RG " +
			"(fresh proxy-ARP nudge on the second pass)")
	}
}
