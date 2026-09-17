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
    lock_ha_recover,
};

/// #9629: machine-readable prefix for a session fast-path refusal that must be
/// retried on the control socket (transitions, joins/leaves, CLEARs).
///
/// Go discriminates on this token (`process_control.go`), exactly like
/// `SYNCED_IMPORT_REFUSED_PREFIX`: a refusal is the CORRECT answer from a
/// HEALTHY helper, not a transport failure. The Go agreement test reads this
/// constant from source rather than pinning a literal.
pub const HA_REFRESH_NEEDS_CONTROL_SOCKET: &str = "ha-refresh-needs-control:";

/// #9629: outcome of the session lease fast path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HaRefreshOutcome {
    /// The refresh landed; the count is RGs with a fresh lease (matched RGs
    /// plus mismatched stored-active RGs). Never changes active flags or
    /// membership.
    Served(usize),
    /// The refresh needs the locked main path (CLEAR, membership change,
    /// stored-empty inventory creation, or pure no-op). Caller must NOT store.
    NeedsLock,
}

/// A cloneable, lock-free handle onto the peer-synced session domain.
///
/// Cheap to clone (eight `Arc` bumps) and valid for the coordinator's whole life:
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
    /// #9629: the HA leaf mutex (`HaState::ha_mutex`), shared — not copied —
    /// so the session fast path serializes against the locked path across the
    /// load→decisions→store section. Same `Arc`, same mutex, same µs hold.
    pub(in crate::afxdp) ha_mutex: Arc<Mutex<()>>,
    pub(in crate::afxdp) dynamic_neighbors: Arc<ShardedNeighborMap>,
    /// #6819 §7 test seam, SHARED rather than copied. The six tests that set it
    /// do so on the `Coordinator` after construction; a copied `usize` would
    /// leave the handle reading 0 and every cap assertion would pass against
    /// the production formula instead of the override — a seam that silently
    /// stops seaming.
    #[cfg(test)]
    pub(in crate::afxdp) synced_import_cap_override: Arc<std::sync::atomic::AtomicUsize>,
    /// #9629 test-only rendezvous sender, absent from release builds.
    #[cfg(test)]
    pub(in crate::afxdp) ha_refresh_attempt: Arc<Mutex<Option<std::sync::mpsc::Sender<()>>>>,
    /// #9629 test-only proceed gate paired with `ha_refresh_attempt`. It
    /// prevents the test worker from reaching the lock statement until the
    /// caller has established that the mutex is held.
    #[cfg(test)]
    pub(in crate::afxdp) ha_refresh_proceed: Arc<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
    /// #9629 test-only holding signal sent inside the acquired ha_mutex
    /// critical section. The paired release gate keeps the worker paused while
    /// the test probes ownership with its own try_lock.
    #[cfg(test)]
    pub(in crate::afxdp) ha_refresh_acquired:
        Arc<Mutex<Option<std::sync::mpsc::Sender<()>>>>,
    #[cfg(test)]
    pub(in crate::afxdp) ha_refresh_acquired_proceed:
        Arc<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
}
impl SessionDomain {
    /// #9629 test-only rendezvous: notify immediately before the fast path
    /// attempts its shared HA leaf mutex. The production build has no sender
    /// field or callback, so this cannot alter the lock ordering.
    #[cfg(test)]
    pub(crate) fn set_ha_refresh_attempt_sender_for_test(
        &self,
        sender: std::sync::mpsc::Sender<()>,
    ) {
        *self
            .ha_refresh_attempt
            .lock()
            .expect("HA refresh test hook lock") = Some(sender);
    }

    /// #9629 test-only rendezvous that gates the lock attempt after the
    /// pre-lock notification. The gate makes the held-mutex witness
    /// schedule-deterministic instead of relying on notification timing.
    #[cfg(test)]
    pub(crate) fn set_ha_refresh_rendezvous_for_test(
        &self,
        sender: std::sync::mpsc::Sender<()>,
        proceed: std::sync::mpsc::Receiver<()>,
    ) {
        self.set_ha_refresh_attempt_sender_for_test(sender);
        *self
            .ha_refresh_proceed
            .lock()
            .expect("HA refresh proceed hook lock") = Some(proceed);
    }
    /// #9629 test-only acquisition rendezvous paired with the pre-lock
    /// rendezvous. The sender fires inside the production critical section,
    /// then the receiver keeps that section held until the test probes it.
    #[cfg(test)]
    pub(crate) fn set_ha_refresh_acquired_rendezvous_for_test(
        &self,
        sender: std::sync::mpsc::Sender<()>,
        proceed: std::sync::mpsc::Receiver<()>,
    ) {
        *self
            .ha_refresh_acquired
            .lock()
            .expect("HA refresh acquired hook lock") = Some(sender);
        *self
            .ha_refresh_acquired_proceed
            .lock()
            .expect("HA refresh acquired proceed hook lock") = Some(proceed);
    }
    /// Build a handle from the coordinator's own shared parts.
    ///
    /// Takes borrows of the live fields rather than an `&Coordinator`, so it
    /// can be called from inside `Coordinator::new`'s struct construction —
    /// and so the compiler enforces that it reads exactly these eight things.
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
            ha_mutex: Arc::clone(&ha.ha_mutex),
            dynamic_neighbors: Arc::clone(&neighbors.dynamic),
            #[cfg(test)]
            synced_import_cap_override: Arc::clone(synced_import_cap_override),
            #[cfg(test)]
            ha_refresh_attempt: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            ha_refresh_proceed: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            ha_refresh_acquired: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            ha_refresh_acquired_proceed: Arc::new(Mutex::new(None)),
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

    /// #9629: the operator-facing HA status for one RG, read lock-free.
    ///
    /// Single-entry `Coordinator::ha_groups()` over the shared `rg_runtime`
    /// cell: the off-lock `update_ha_state` path (and its contention cell)
    /// observes refreshes through the handle without taking the snapshot
    /// mutex. `forwarding_active` is evaluated at call time, exactly as the
    /// coordinator shape does.
    pub(crate) fn ha_group_status(&self, rg_id: i32) -> Option<crate::HAGroupStatus> {
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        self.rg_runtime.load().get(&rg_id).map(|runtime| {
            let (lease_state, lease_until) = match runtime.lease {
                crate::afxdp::HAForwardingLease::Inactive => ("inactive".to_string(), 0),
                crate::afxdp::HAForwardingLease::ActiveUntil(until) => {
                    ("active".to_string(), until)
                }
            };
            crate::HAGroupStatus {
                rg_id,
                active: runtime.active,
                watchdog_timestamp: runtime.watchdog_timestamp,
                forwarding_active: runtime.is_forwarding_active(now_secs),
                lease_state,
                lease_until,
            }
        })
    }

    /// #9629: lease-only HA refresh over the shared `rg_runtime` cell, for the
    /// session socket. Never takes `ServerState`; serializes against the locked
    /// path via `ha_mutex` (lock-first: acquired BEFORE the `rg_runtime` load,
    /// held through every decision and the store).
    ///
    /// Contract build-map-then-diff-then-maybe-store: the incoming map last-wins
    /// (exactly like the locked insert loop) is built BEFORE the lock (local
    /// input parsing, no shared state); under the hold: incoming empty →
    /// NeedsLock (CLEAR owned by main); stored empty + any nonempty incoming
    /// → NeedsLock (watchdog must never create inventory — CLEAR-undo race);
    /// stored nonempty: key-set inequality → NeedsLock (join/leave); per-RG
    /// match → fresh `active_lease_until` from incoming watchdog; mismatch +
    /// stored active + VALID lease → fresh lease for STORED active/watchdog
    /// (liveness only, ownership stays); mismatch + stored inactive OR
    /// EXPIRED stored-active → keep stored (owned by main); zero refreshed →
    /// NeedsLock (pure no-op never recorded as publish), else store +
    /// Served(count). Never changes active flags or membership off-lock.
    pub(crate) fn try_refresh_ha_leases(
        &self,
        groups: &[crate::HAGroupStatus],
    ) -> HaRefreshOutcome {
        // Incoming map last-wins, before the lock (local build, no shared
        // state, keeps the µs hold minimal). Duplicates resolve exactly like
        // the locked-path insert loop (`state.insert` overwrites).
        let mut incoming: std::collections::BTreeMap<i32, (bool, u64)> =
            std::collections::BTreeMap::new();
        for group in groups {
            incoming.insert(group.rg_id, (group.active, group.watchdog_timestamp));
        }
        #[cfg(test)]
        {
            let attempt = self
                .ha_refresh_attempt
                .lock()
                .expect("HA refresh test hook lock")
                .as_ref()
                .cloned();
            if let Some(sender) = attempt {
                sender.send(()).expect("signal HA refresh mutex attempt");
            }
            let proceed = self
                .ha_refresh_proceed
                .lock()
                .expect("HA refresh proceed hook lock")
                .take();
            if let Some(receiver) = proceed {
                receiver
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("proceed HA refresh mutex attempt");
            }
        }
        // Lock FIRST, before the load — a transition landing between a pre-lock
        // decision and the store would recreate the stale-overwrite race this
        // mutex exists to close.
        let _held = lock_ha_recover(&self.ha_mutex);
        #[cfg(test)]
        {
            if let Some(sender) = self
                .ha_refresh_acquired
                .lock()
                .expect("HA refresh acquired hook lock")
                .take()
            {
                sender
                    .send(())
                    .expect("signal HA refresh mutex acquisition");
            }
            if let Some(receiver) = self
                .ha_refresh_acquired_proceed
                .lock()
                .expect("HA refresh acquired proceed hook lock")
                .take()
            {
                receiver
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("release HA refresh mutex acquisition");
            }
        }
        // Incoming empty is a CLEAR (standalone `clearHelperHAStateLocked` is
        // the only producer; `syncHAStateLocked` early-returns on empty).
        // Owned by the main path, never silently skipped or acked here.
        if incoming.is_empty() {
            return HaRefreshOutcome::NeedsLock;
        }
        let stored = self.rg_runtime.load();
        // Stored-empty check BEFORE key-set equality: with inventory creation
        // refused, ANY nonempty incoming on empty stored needs the main path
        // (transitions, joins AND first-inventory creation alike).
        // Stored empty + ANY nonempty incoming → NeedsLock: refuse inventory
        // creation on the refresh-only path. A standby watchdog snapshots
        // inactive inventory, a cluster→standalone apply then clears
        // successfully — and an outstanding session refresh arriving after the
        // clear must NOT restore the obsolete inventory (it would strand
        // standalone transit HAInactive until another clear/apply). The leaf
        // mutex serializes concurrent writers but cannot judge obsolescence,
        // so creation is owned exclusively by the main path. (An earlier
        // revision served stored-empty/all-inactive as side-effect-free; dual
        // review identified the CLEAR-undo race, hence this rule.)
        if stored.is_empty() {
            return HaRefreshOutcome::NeedsLock;
        }
        // Stored nonempty: membership must match exactly (join/leave owned by
        // main, with side effects).
        if stored.len() != incoming.len() || !stored.keys().eq(incoming.keys()) {
            return HaRefreshOutcome::NeedsLock;
        }
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        let mut state = std::collections::BTreeMap::new();
        let mut refreshed: usize = 0;
        for (rg_id, stored_runtime) in stored.iter() {
            let (incoming_active, incoming_watchdog) =
                incoming.get(rg_id).copied().unwrap_or((false, 0));
            // Key-sets equal, so `get` cannot miss; the fallback is
            // unreachable (kept to avoid `expect` inside the hold).
            if stored_runtime.active == incoming_active {
                // Match: full refresh from incoming (exactly like locked).
                state.insert(
                    *rg_id,
                    crate::afxdp::HAGroupRuntime {
                        active: incoming_active,
                        watchdog_timestamp: incoming_watchdog,
                        lease: if incoming_active {
                            crate::afxdp::HAGroupRuntime::active_lease_until(
                                incoming_watchdog,
                                now_secs,
                            )
                        } else {
                            crate::afxdp::HAForwardingLease::Inactive
                        },
                    },
                );
                refreshed += 1;
            } else if stored_runtime.active {
                // Mismatch, stored active (demotion pending, blocked on main):
                // mint a fresh receipt-anchored lease for STORED ownership —
                // but ONLY while the stored lease is still valid. An already
                // EXPIRED stored-active is never resurrected (fail-closed):
                // the demotion it was waiting on may have partially landed
                // elsewhere, and minting on a dead lease would re-arm
                // forwarding for an owner the control plane already dropped.
                //
                // Each receipt extends stored ownership by at most 11s wall
                // (the ~12s dual-active bound for one receipt). A continuously
                // renewed stale ownership can remain active until authoritative
                // demotion or bounded recovery finally lands; this path does
                // not promise an absolute wall-clock cap across such renewals.
                // The expired-stored-active check above is unconditional:
                // expired ownership is never resurrected.
                if stored_runtime.is_forwarding_active(now_secs) {
                    state.insert(
                        *rg_id,
                        crate::afxdp::HAGroupRuntime {
                            active: true,
                            watchdog_timestamp: stored_runtime.watchdog_timestamp,
                            lease: crate::afxdp::HAGroupRuntime::active_lease_until(
                                stored_runtime.watchdog_timestamp,
                                now_secs,
                            ),
                        },
                    );
                    refreshed += 1;
                } else {
                    state.insert(*rg_id, *stored_runtime);
                }
            } else {
                // Mismatch, stored inactive (activation pending): keep stored
                // untouched (no mint — inactive stays `Inactive`). Owned by
                // main with side effects; not counted as refreshed.
                state.insert(*rg_id, *stored_runtime);
            }
        }
        if refreshed == 0 {
            // Pure no-op (every RG mismatch stored-inactive, e.g. single-RG
            // activation pending): never record as publish. Main owns it.
            return HaRefreshOutcome::NeedsLock;
        }
        self.rg_runtime.store(Arc::new(state));
        HaRefreshOutcome::Served(refreshed)
    }

    /// #9629 test seam: share the HA leaf mutex with a test that must hold it
    /// across a fast-path call (race-closer serialization cell). The field is
    /// `pub(in crate::afxdp)`; `server/tests` is outside `afxdp`.
    #[cfg(test)]
    pub(crate) fn ha_mutex_for_test(&self) -> Arc<Mutex<()>> {
        Arc::clone(&self.ha_mutex)
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

/// #9629: timing-free decision table for `try_refresh_ha_leases`.
///
/// Each cell pins one rule of the build-map-then-diff-then-maybe-store
/// contract (stored-empty refuse-all, last-wins duplicates, valid-lease mint
/// vs expired never-resurrect, zero-refreshed → NeedsLock).
/// No sleeps, no threads; the race-closer serialization cell lives in
/// `server/tests.rs` with the `ha_mutex_for_test` handle.
#[cfg(test)]
mod try_refresh_9629_tests {
    use crate::afxdp::Coordinator;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::HaRefreshOutcome;

    fn group(rg_id: i32, active: bool, watchdog_timestamp: u64) -> crate::HAGroupStatus {
        crate::HAGroupStatus {
            rg_id,
            active,
            watchdog_timestamp,
            ..Default::default()
        }
    }

    fn seed(coordinator: &Coordinator, entries: &[(i32, bool)]) {
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        let mut state = BTreeMap::new();
        for (rg_id, active) in entries {
            state.insert(
                *rg_id,
                crate::afxdp::HAGroupRuntime {
                    active: *active,
                    watchdog_timestamp: now_secs,
                    lease: if *active {
                        crate::afxdp::HAGroupRuntime::active_lease_until(now_secs, now_secs)
                    } else {
                        crate::afxdp::HAForwardingLease::Inactive
                    },
                },
            );
        }
        coordinator.ha.rg_runtime.store(Arc::new(state));
    }

    fn stored_active(coordinator: &Coordinator, rg_id: i32) -> Option<bool> {
        coordinator
            .ha
            .rg_runtime
            .load()
            .get(&rg_id)
            .map(|runtime| runtime.active)
    }

    fn stored_forwarding_active(coordinator: &Coordinator, rg_id: i32) -> bool {
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        coordinator
            .ha
            .rg_runtime
            .load()
            .get(&rg_id)
            .map(|runtime| runtime.is_forwarding_active(now_secs))
            .unwrap_or(false)
    }

    /// Empty incoming is a CLEAR owned by main, even when stored is already
    /// empty (no-op must still route to main, never be acked here).
    #[test]
    fn empty_empty_needs_lock_9629() {
        let coordinator = Coordinator::new();
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[]),
            HaRefreshOutcome::NeedsLock
        );
        assert!(coordinator.ha.rg_runtime.load().is_empty());
    }

    /// Stored empty + any incoming active IS an activation on the locked path
    /// (`activated_owner_rgs` None-arm); serving it here would steal epoch
    /// bumps, fan-out, prewarm, republish and neighbor warm permanently.
    #[test]
    fn empty_active_needs_lock_9629() {
        let coordinator = Coordinator::new();
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, true, 0)]),
            HaRefreshOutcome::NeedsLock
        );
        assert!(coordinator.ha.rg_runtime.load().is_empty());
    }

    /// Stored empty + all incoming inactive is REFUSED (verdict item 2): an
    /// earlier revision served it as side-effect-free, but a standby watchdog
    /// snapshot arriving after a cluster→standalone CLEAR would restore the
    /// obsolete inventory and strand transit HAInactive. Watchdog refreshes
    /// must never create inventory; first inventory always arrives via main.
    #[test]
    fn empty_inactive_needs_lock_9629() {
        let coordinator = Coordinator::new();
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, false, 7), group(2, false, 8)]),
            HaRefreshOutcome::NeedsLock
        );
        assert!(coordinator.ha.rg_runtime.load().is_empty());
    }

    /// Duplicate `rg_id`s resolve last-wins exactly like the locked insert
    /// loop. Stored inactive + [active, inactive]: last-wins → match → Served;
    /// first-wins would read active → mismatch stored-inactive → NeedsLock.
    #[test]
    fn duplicate_conflict_last_wins_9629() {
        let coordinator = Coordinator::new();
        seed(&coordinator, &[(1, false)]);
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, true, 10), group(1, false, 20)]),
            HaRefreshOutcome::Served(1)
        );
        assert_eq!(stored_active(&coordinator, 1), Some(false));
    }

    /// Key-set equality is order-insensitive (reversed incoming still Served).
    #[test]
    fn reorder_served_9629() {
        let coordinator = Coordinator::new();
        seed(&coordinator, &[(1, true), (2, true)]);
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(2, true, 0), group(1, true, 0)]),
            HaRefreshOutcome::Served(2)
        );
        assert!(stored_forwarding_active(&coordinator, 1));
        assert!(stored_forwarding_active(&coordinator, 2));
    }

    /// Full flip to inactive with stored active mints fresh leases for STORED
    /// ownership (demotion pending, blocked on main) instead of skipping.
    /// Ownership unchanged, liveness fresh — Go-4 over skip starvation.
    #[test]
    fn full_flip_mints_stored_active_lease_9629() {
        let coordinator = Coordinator::new();
        seed(&coordinator, &[(1, true), (2, true)]);
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, false, 0), group(2, false, 0)]),
            HaRefreshOutcome::Served(2)
        );
        assert_eq!(stored_active(&coordinator, 1), Some(true));
        assert_eq!(stored_active(&coordinator, 2), Some(true));
        assert!(stored_forwarding_active(&coordinator, 1));
        assert!(stored_forwarding_active(&coordinator, 2));
    }

    /// Join (incoming key not in stored) is a membership change owned by main.
    #[test]
    fn join_needs_lock_9629() {
        let coordinator = Coordinator::new();
        seed(&coordinator, &[(1, true)]);
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, true, 0), group(2, true, 0)]),
            HaRefreshOutcome::NeedsLock
        );
        assert_eq!(coordinator.ha.rg_runtime.load().len(), 1);
        assert_eq!(stored_active(&coordinator, 2), None);
    }

    /// Leave (stored key not in incoming) is a membership change owned by main.
    #[test]
    fn leave_needs_lock_9629() {
        let coordinator = Coordinator::new();
        seed(&coordinator, &[(1, true), (2, true)]);
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, true, 0)]),
            HaRefreshOutcome::NeedsLock
        );
        assert_eq!(coordinator.ha.rg_runtime.load().len(), 2);
    }

    /// Pure no-op (every RG mismatch stored-inactive, e.g. single-RG
    /// activation pending) is never recorded as publish. Main owns it.
    #[test]
    fn all_mismatch_inactive_needs_lock_9629() {
        let coordinator = Coordinator::new();
        seed(&coordinator, &[(1, false)]);
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, true, 0)]),
            HaRefreshOutcome::NeedsLock
        );
        assert_eq!(stored_active(&coordinator, 1), Some(false));
    }

    /// Expired stored-active + incoming-inactive is NEVER resurrected
    /// (verdict item 3): the demotion it waited on may have partially landed
    /// elsewhere, so minting on a dead lease would re-arm an owner the
    /// control plane already dropped. Fail-closed: keep + NeedsLock.
    #[test]
    fn expired_stored_active_incoming_inactive_needs_lock_9629() {
        let coordinator = Coordinator::new();
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        coordinator.ha.rg_runtime.store(Arc::new(BTreeMap::from([(
            1,
            crate::afxdp::HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs.saturating_sub(11),
                lease: crate::afxdp::HAForwardingLease::ActiveUntil(
                    now_secs.saturating_sub(1),
                ),
            },
        )])));
        assert!(!stored_forwarding_active(&coordinator, 1));
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, false, 0)]),
            HaRefreshOutcome::NeedsLock
        );
        assert!(!stored_forwarding_active(&coordinator, 1));
    }

    /// Mismatch on a VALID stored-active lease mints (Go-4): the post-call
    /// `lease_until` strictly exceeds the seeded one, proving a mint rather
    /// than a keep (a non-minting implementation would also read active on a
    /// fresh seed, so activity alone cannot prove renewal). Seeded short
    /// (`now+2`) vs minted (`now+10`): ≥8s apart, truncation-proof.
    #[test]
    fn mismatch_renews_valid_stored_active_lease_9629() {
        let coordinator = Coordinator::new();
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        coordinator.ha.rg_runtime.store(Arc::new(BTreeMap::from([(
            1,
            crate::afxdp::HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs,
                lease: crate::afxdp::HAForwardingLease::ActiveUntil(
                    now_secs.saturating_add(2),
                ),
            },
        )])));
        let before = coordinator
            .ha
            .rg_runtime
            .load()
            .get(&1)
            .and_then(|runtime| match runtime.lease {
                crate::afxdp::HAForwardingLease::ActiveUntil(until) => Some(until),
                crate::afxdp::HAForwardingLease::Inactive => None,
            })
            .expect("seeded short active lease");
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, false, 0)]),
            HaRefreshOutcome::Served(1)
        );
        let after = coordinator
            .ha
            .rg_runtime
            .load()
            .get(&1)
            .and_then(|runtime| match runtime.lease {
                crate::afxdp::HAForwardingLease::ActiveUntil(until) => Some(until),
                crate::afxdp::HAForwardingLease::Inactive => None,
            })
            .expect("minted active lease");
        assert!(
            after > before,
            "refreshed lease_until ({after}) must strictly exceed seeded ({before}); equality would mean keep-not-mint"
        );
        assert_eq!(stored_active(&coordinator, 1), Some(true));
    }

    /// The helper's lease predicate is inclusive: a receipt is valid through
    /// `now == lease_until`, not only while `now < lease_until`. Pin the
    /// equality boundary directly so Go's stateful mirror cannot drift to a
    /// strict comparison.
    #[test]
    fn lease_until_equality_is_forwarding_active_9629() {
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        let runtime = crate::afxdp::HAGroupRuntime {
            active: true,
            watchdog_timestamp: 0,
            lease: crate::afxdp::HAForwardingLease::ActiveUntil(now_secs),
        };
        assert!(runtime.is_forwarding_active(now_secs));
    }
}
