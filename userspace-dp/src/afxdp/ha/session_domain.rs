// #7209: the SESSION DOMAIN handle — everything the peer-synced import path
// touches, held as shared references rather than reached through
// `&Coordinator`.
//
// WHY THIS TYPE EXISTS. `sync_session` arrives on its own socket and its own
// thread (#452), but it dispatched through the same `Arc<Mutex<ServerState>>`
// as every main-socket verb, so the socket split never split the critical
// section. `apply_snapshot` holds that mutex across a worker-readiness barrier
// (10 s), an mlx5 teardown quiesce (500 ms), worker `join()`s and BPF map-pin
// opens — while Go budgets 3 s for a session round-trip and #5380 ABORTS the
// remainder of a bulk batch on the first transport failure. So contention here
// does not cost latency, it costs up to 255 dropped session mirrors during the
// failover the path exists to serve.
//
// WHY IT IS A HANDLE AND NOT AN `Arc<Coordinator>`. The `Coordinator` has 42
// `&mut self` methods; sharing it would mean interior-mutability for all of
// them. But the import path's own subgraph is already `&self`-only — the type
// system proves it, since `upsert_synced_session(&self)` compiles — and every
// field it reaches is already shared:
//
//   * `sessions`  — `Arc<SessionManager>`; its maps are `Arc<Mutex<..>>`, its
//                   counters atomics, and it has ZERO `&mut self` methods;
//   * `workers`   — `WorkerRecordsReader`, the read-only view onto the SAME
//                   published record map the manager mutates;
//   * `bpf_maps`  — the shared `ArcSwap` CELL, so a `store` after a handle was
//                   taken is still visible to it;
//   * `rg_runtime`— already `Arc<ArcSwap<..>>`;
//   * `neighbors` — `dynamic_neighbors_ref` already returns an `Arc`.
//
// FORWARDING IS THE ONE THAT MOVES, and it moves to something better. The
// import path read `Coordinator::forwarding`, an owned field. It now reads the
// PUBLISHED `RuntimeView` — the same one the packet workers hold. That is not a
// concession made to escape the lock: a session resolved against the published
// forwarding agrees with the tables that will actually carry its packets,
// whereas `self.forwarding` mid-apply is a state no worker is using.
// `Coordinator::republish_runtime_validation` already reads the published
// forwarding in preference to the owned field, for the same reason, and says so.
//
// The two are not observably different today — both production sites that
// assign `self.forwarding` (`coordinator/snapshot_refresh.rs`,
// `coordinator/mod.rs`) publish immediately after, so they cannot diverge
// while a reader holds the mutex.

use super::*;
use crate::afxdp::coordinator::{
    BpfMaps, HaState, NeighborManager, SessionManager, WorkerManager, WorkerRecordsReader,
};

/// A cloneable, lock-free handle onto the peer-synced session domain.
///
/// Cheap to clone (seven `Arc` bumps) and valid for the coordinator's whole life:
/// none of the fields it mirrors is ever REASSIGNED on the `Coordinator` — only
/// mutated through its own interior synchronization — which is what makes a
/// handle taken at startup observe every later change rather than a snapshot.
/// That property is asserted by `session_domain_observes_later_publishes_7209`
/// rather than left to inspection.
#[derive(Clone)]
pub(crate) struct SessionDomain {
    pub(in crate::afxdp) sessions: Arc<SessionManager>,
    pub(in crate::afxdp) workers: WorkerRecordsReader,
    pub(in crate::afxdp) runtime: RuntimeViewReader,
    pub(in crate::afxdp) bpf_maps: Arc<ArcSwap<BpfMaps>>,
    /// #9560: the coordinator's steering-row owner registry, the instance its workers claim
    /// rows in, so an HA delete racing a teardown or bringup sees their claims.
    pub(in crate::afxdp) steering_owners: Arc<crate::afxdp::bpf_map::SteeringRowOwners>,
    pub(in crate::afxdp) rg_runtime: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    pub(in crate::afxdp) dynamic_neighbors: Arc<ShardedNeighborMap>,
    /// #6819 §7 test seam, SHARED rather than copied. The six tests that set it
    /// do so on the `Coordinator` after construction; a copied `usize` would
    /// leave the handle reading 0 and every cap assertion would pass against
    /// the production formula instead of the override — a seam that silently
    /// stops seaming.
    #[cfg(test)]
    pub(in crate::afxdp) synced_import_cap_override: Arc<std::sync::atomic::AtomicUsize>,
}

impl SessionDomain {
    /// Build a handle from the coordinator's own shared parts.
    ///
    /// Takes borrows of the live fields rather than an `&Coordinator`, so it
    /// can be called from inside `Coordinator::new`'s struct construction —
    /// and so the compiler enforces that it reads exactly these seven things.
    pub(in crate::afxdp) fn new(
        sessions: &Arc<SessionManager>,
        workers: &WorkerManager,
        ha: &HaState,
        neighbors: &NeighborManager,
        bpf_maps: &Arc<ArcSwap<BpfMaps>>,
        steering_owners: &Arc<crate::afxdp::bpf_map::SteeringRowOwners>,
        #[cfg(test)] synced_import_cap_override: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        Self {
            sessions: Arc::clone(sessions),
            workers: workers.records_reader(),
            runtime: ha.runtime_reader(),
            bpf_maps: Arc::clone(bpf_maps),
            steering_owners: Arc::clone(steering_owners),
            rg_runtime: Arc::clone(&ha.rg_runtime),
            dynamic_neighbors: Arc::clone(&neighbors.dynamic),
            #[cfg(test)]
            synced_import_cap_override: Arc::clone(synced_import_cap_override),
        }
    }

    /// The PUBLISHED forwarding state — the one the packet workers hold.
    ///
    /// One load, bound to a guard by the caller: two loads inside one import
    /// can straddle a publish and pair halves across generations, which is the
    /// defect #6592 closed and the reason [`RuntimeViewReader::load`] is the
    /// single-load primitive.
    #[inline]
    pub(crate) fn runtime_view(&self) -> arc_swap::Guard<Arc<RuntimeView>> {
        self.runtime.load()
    }
}

/// #7209: ONE load of the published runtime view, for the span of ONE request.
///
/// The single-load discipline is STRUCTURAL here rather than a comment. A
/// handler that took `synced_routing_domain` and `zone_name_to_id` as separate
/// calls would take two loads, and two loads inside one import can resolve the
/// session's domain against one generation and its zones against another — the
/// pairing defect #6592 closed, reintroduced one layer up. Holding the guard in
/// the type makes that impossible to write by accident.
pub(crate) struct SessionDomainView<'a> {
    domain: &'a SessionDomain,
    view: arc_swap::Guard<Arc<RuntimeView>>,
}

impl SessionDomain {
    /// Take this request's view. Cheap (one `ArcSwap` load), and the guard is
    /// held for as long as the returned value lives.
    #[inline]
    pub(crate) fn view(&self) -> SessionDomainView<'_> {
        SessionDomainView {
            domain: self,
            view: self.runtime.load(),
        }
    }

    /// Entries currently in the shared synced map.
    ///
    /// ENTRIES, not logical sessions: an admitted forward publishes two (itself
    /// and its synthesized reverse companion), which is the same distinction
    /// `synced_import_cap_for` is built around. Exposed so a test can assert an
    /// import LANDED, through the same handle the off-lock dispatch used —
    /// asserting on the control response alone would pass for a handler that
    /// acked without publishing.
    pub(crate) fn synced_entry_count(&self) -> usize {
        // `lock_shared_recover`, not a bare `lock`: every other shared-session
        // path CLEARS the poison, so a bare lock here would fire or not fire
        // purely on which thread locked first (#6652/#6653/#6654). The
        // `every_shared_session_lock_in_production_recovers_from_poison_6653`
        // scanner caught this one by CONTENT, from another module — the class of
        // guard a package-scoped test run cannot see.
        crate::afxdp::shared_ops::lock_shared_recover(&self.sessions.synced).len()
    }

    /// #7160 (#2387): count one import refused for an unresolvable routing
    /// domain. Separate from the refusal itself because the refusal is decided
    /// by the caller, which knows whether it is an upsert or a delete.
    pub(crate) fn note_unknown_routing_domain_import(&self) {
        self.sessions
            .import_unknown_routing_domain
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl SessionDomainView<'_> {
    /// The domain handle this view was taken from, for the verbs that do not
    /// read forwarding.
    #[inline]
    pub(crate) fn domain(&self) -> &SessionDomain {
        self.domain
    }

    /// #7160 (#2387): resolve a synced session's routing domain from the #7095
    /// cluster-stable ingress identity, against the PUBLISHED forwarding.
    ///
    /// Delegates to the shared free function, so this and
    /// `Coordinator::synced_routing_domain` cannot drift — the only difference
    /// between them is which `ForwardingState` they read.
    pub(crate) fn synced_routing_domain(
        &self,
        ingress_ifindex: i32,
        ingress_vlan_id: u16,
    ) -> Option<u32> {
        crate::afxdp::coordinator::synced_routing_domain_in(
            self.view.forwarding(),
            ingress_ifindex,
            ingress_vlan_id,
        )
    }

    /// The configured non-default routing domains. Same single-sourcing note.
    pub(crate) fn routing_domains(&self) -> Vec<u32> {
        crate::afxdp::coordinator::configured_routing_domains(self.view.forwarding())
    }

    /// #919: zone name -> ID, for translating a legacy peer's
    /// `SessionSyncRequest.ingress_zone` string when it does not populate the
    /// ID fields.
    pub(crate) fn zone_name_to_id(&self) -> &FastMap<String, u16> {
        &self.view.forwarding().zone_name_to_id
    }
}

#[cfg(test)]
mod session_domain_tests_7209 {
    use crate::afxdp::Coordinator;
    use std::sync::atomic::Ordering;

    /// THE SHARING PROPERTY, and the whole reason the handle may be cached.
    ///
    /// `lifecycle.rs` clones ONE handle at startup and gives it to the session
    /// thread for the process's life. That is only sound if the handle tracks
    /// the live channel rather than freezing a snapshot of it — every later
    /// `apply_snapshot` publishes a new forwarding, and an import resolving
    /// zones against startup state would file sessions under identities that no
    /// longer exist.
    ///
    /// FAIL-ON-REVERT: build `SessionDomain` from `runtime.load_full()` (a
    /// snapshot) instead of `runtime_reader()` (the channel) and this reds. It
    /// is the difference the type is FOR, and nothing else in the tree would
    /// notice it — every other cell publishes before it reads.
    #[test]
    fn session_domain_observes_later_publishes_7209() {
        let mut coordinator = Coordinator::new();
        // Taken BEFORE the publish, exactly as the session thread takes it
        // before the first apply_snapshot.
        let domain = coordinator.session_domain().clone();
        assert!(
            domain.view().zone_name_to_id().is_empty(),
            "fixture: nothing is published yet, or the assertion below cannot \
             distinguish a tracking handle from a frozen one"
        );

        let mut forwarding = super::ForwardingState::default();
        forwarding.zone_name_to_id.insert("trust".to_string(), 7);
        coordinator.set_forwarding_for_test(forwarding);

        assert_eq!(
            domain.view().zone_name_to_id().get("trust").copied(),
            Some(7),
            "the handle must observe a publish made AFTER it was cloned. A \
             snapshot-holding handle would resolve every import against startup \
             state for the life of the process"
        );
    }

    /// THE TEST SEAM ITSELF, bound directly rather than through an import.
    ///
    /// Several cells set `synced_import_cap_override` on the `Coordinator` and
    /// then drive an import. Once the import moved to this handle, a COPIED
    /// `usize` would leave the handle reading 0 and those cells would be
    /// measuring the production formula instead of the override they installed.
    ///
    /// I expected them to pass silently under that mutation and wrote this cell
    /// to be the only thing that caught it. MEASURED, THEY DO NOT: wiring the
    /// handle to a fresh cell reds four of the five, because an override of 0
    /// means "bound disabled", so the imports they expect to be REJECTED are
    /// accepted. The tests are more robust than the argument for this cell was.
    ///
    /// It earns its place on DIAGNOSIS rather than detection. Those four fail
    /// with "an import that should have been rejected was accepted", which
    /// points at the import logic; this one fails saying the override did not
    /// reach the handle, which is where the defect actually is.
    ///
    /// FAIL-ON-REVERT: construct the handle with a fresh
    /// `Arc<AtomicUsize>` instead of the coordinator's, and this reds.
    #[test]
    fn the_import_cap_override_reaches_the_session_domain_7209() {
        let coordinator = Coordinator::new();
        coordinator
            .synced_import_cap_override
            .store(3, Ordering::Relaxed);
        let empty = std::collections::BTreeMap::new();
        assert_eq!(
            coordinator.session_domain().synced_import_cap_for(&empty),
            6,
            "the override is a LOGICAL ceiling and the cap is in ENTRIES (a \
             forward plus its synthesized reverse), so 3 must arrive as 6. \
             Reading 0 here means the handle copied the override instead of \
             sharing it, and the six cells that set it are silently measuring \
             the production formula"
        );
    }
}
