package daemon

import (
	"context"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
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
