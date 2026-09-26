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
    /// The refresh landed; count is RGs with a refreshed matching state plus
    /// valid mismatched stored-active leases. Never changes active flags or
    /// membership.
    Served(usize),
    /// The refresh needs the locked main path (CLEAR, membership change,
    /// stored-empty creation, expired matching stored-active, or pure no-op).
    /// Caller must NOT store.
    NeedsLock,
}

/// A cloneable, lock-free handle onto the peer-synced session domain.
///
/// Cheap to clone (the live references and two mutation-lifecycle cells are
/// all `Arc`s) and valid for the coordinator's whole life:
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
    /// #9629: the HA leaf mutex (`HaState::ha_mutex`), shared — not copied —
    /// so the session fast path serializes against the locked path across the
    /// load→decisions→store section. Same `Arc`, same mutex, same µs hold.
    pub(in crate::afxdp) ha_mutex: Arc<Mutex<()>>,
    pub(in crate::afxdp) helper_epoch: Arc<std::sync::atomic::AtomicU64>,
    pub(in crate::afxdp) helper_mutations: Arc<Mutex<HelperMutationStore>>,
    /// #10512: helper-owned READ captures survive page-to-page control
    /// requests. Tokens are opaque to Go; entries expire when idle.
    policy_captures: Arc<Mutex<std::collections::HashMap<String, PolicyCapture>>>,
    policy_capture_seq: Arc<std::sync::atomic::AtomicU64>,
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

/// Buffered helper-owned policy READ page state. The buffer is bounded by
/// `POLICY_CAPTURE_LIMIT`; the opaque token is only a map key.
struct PolicyCapture {
    rows: Vec<crate::protocol::SessionPolicyMatch>,
    errors: Vec<String>,
    offset: usize,
    last_used: std::time::Instant,
}
/// #10512: recorded outcome summary of one epoch-scoped helper mutation.
///
/// Replayed verbatim when the exact `(epoch, operation_id, mutation_id)`
/// triple is retried, so the replayed response is indistinguishable from the
/// first execution's. Every response field a tuple verb can set lives here.
#[derive(Clone, Debug, Default)]
pub(crate) struct HelperMutationOutcome {
    pub ok: bool,
    pub error: String,
    pub mirror_v4_count: u64,
    pub mirror_v6_count: u64,
    pub mirror_complete: bool,
    pub mirror_fence_id: u64,
    pub mirror_continuation: String,
    pub delete_outcomes: Vec<String>,
    pub delete_complete: bool,
    pub delete_errors: Vec<String>,
}

impl HelperMutationOutcome {
    pub(crate) fn from_response(response: &crate::ControlResponse) -> Self {
        Self {
            ok: response.ok,
            error: response.error.clone(),
            mirror_v4_count: response.session_mirror_v4_count,
            mirror_v6_count: response.session_mirror_v6_count,
            mirror_complete: response.session_mirror_complete,
            mirror_fence_id: response.session_mirror_fence_id,
            mirror_continuation: response.session_mirror_continuation.clone(),
            delete_outcomes: response.policy_delete_outcomes.clone(),
            delete_complete: response.policy_delete_complete,
            delete_errors: response.policy_delete_errors.clone(),
        }
    }

    pub(crate) fn apply_to_response(&self, response: &mut crate::ControlResponse) {
        response.ok = self.ok;
        response.error = self.error.clone();
        response.session_mirror_v4_count = self.mirror_v4_count;
        response.session_mirror_v6_count = self.mirror_v6_count;
        response.session_mirror_complete = self.mirror_complete;
        response.session_mirror_fence_id = self.mirror_fence_id;
        response.session_mirror_continuation = self.mirror_continuation.clone();
        response.policy_delete_outcomes = self.delete_outcomes.clone();
        response.policy_delete_complete = self.delete_complete;
        response.policy_delete_errors = self.delete_errors.clone();
    }
}

/// One recorded epoch-scoped mutation: the mutation id it ran under (for the
/// operation-id-reuse check), its outcome summary (for exact-pair replay),
/// and a recency sequence (for within-epoch LRU).
struct HelperMutationRecord {
    mutation_id: String,
    outcome: HelperMutationOutcome,
    last_used: u64,
}

/// #10512 (F-D): epoch-scoped LRU mutation store.
///
/// Replaces the random `HashMap::iter().next()` eviction, which could drop a
/// live in-flight retry's record while retaining stale epochs forever.
/// Eviction removes the oldest epoch first, then the least-recently-used
/// record within that epoch — and never an in-flight operation (one that
/// passed `helper_mutation_begin` but has not recorded its outcome yet).
#[derive(Default)]
pub(crate) struct HelperMutationStore {
    records: std::collections::HashMap<(u64, String), HelperMutationRecord>,
    in_flight: std::collections::HashSet<(u64, String)>,
    seq: u64,
}

/// Outcome of `SessionDomain::helper_mutation_begin`.
pub(crate) enum HelperMutationBegin {
    /// The exact triple already ran: replay this outcome without executing.
    Replay(HelperMutationOutcome),
    /// Execute the mutation, then `complete` the lease with its outcome.
    Proceed(HelperMutationLease),
}

/// In-flight guard for one epoch-scoped mutation. Completing records the
/// outcome; dropping without completing (any early return) releases the
/// in-flight mark without recording, so a failed op stays retryable under
/// the same ids and can never be evicted mid-execution.
pub(crate) struct HelperMutationLease {
    mutations: Arc<Mutex<HelperMutationStore>>,
    key: (u64, String),
    mutation_id: String,
    completed: bool,
}

impl HelperMutationLease {
    /// Record the terminal outcome. At capacity, evicts oldest-epoch-first /
    /// LRU-within-epoch; when every record is in-flight the insert runs over
    /// capacity rather than evicting a live op.
    pub(crate) fn complete(mut self, outcome: HelperMutationOutcome) {
        let mut store = self
            .mutations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.in_flight.remove(&self.key);
        const MAX_MUTATIONS: usize = 16_384;
        if store.records.len() >= MAX_MUTATIONS {
            let victim = store
                .records
                .iter()
                .filter(|(key, _)| !store.in_flight.contains(*key))
                .min_by_key(|((epoch, _), record)| (*epoch, record.last_used))
                .map(|(key, _)| key.clone());
            if let Some(victim) = victim {
                store.records.remove(&victim);
            }
        }
        store.seq = store.seq.wrapping_add(1);
        let seq = store.seq;
        let mutation_id = std::mem::take(&mut self.mutation_id);
        store.records.insert(
            self.key.clone(),
            HelperMutationRecord {
                mutation_id,
                outcome,
                last_used: seq,
            },
        );
        self.completed = true;
    }
}

impl Drop for HelperMutationLease {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.mutations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .in_flight
            .remove(&self.key);
    }
}
impl SessionDomain {
    /// Session mutations from a previous helper generation must not be applied
    /// after a restart. Zero preserves compatibility with pre-epoch peers.
    /// Monotonic re-adopt (P12, permit_epoch precedent): stale in-flight
    /// epochs from a superseded boot may still land first and are accepted
    /// (they execute once, idempotently); anything older than the adopted
    /// epoch is rejected; anything newer re-adopts. The old latch-on-first
    /// wedged double restarts (stale N+1 latching forever against N+2).
    pub(crate) fn accepts_helper_epoch(&self, epoch: u64) -> bool {
        if epoch == 0 {
            return true;
        }
        use std::sync::atomic::Ordering;
        let mut current = self.helper_epoch.load(Ordering::Acquire);
        loop {
            if epoch == current {
                return true;
            }
            if epoch < current {
                return false;
            }
            match self.helper_epoch.compare_exchange(
                current,
                epoch,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }
    /// Begin one epoch-scoped mutation. Returns the recorded outcome when the
    /// exact `(epoch, operation_id, mutation_id)` triple already ran — the
    /// caller replays it and returns without executing. Otherwise marks the
    /// op in-flight and returns a lease the caller completes with the
    /// terminal outcome (dropping it uncompleted releases the mark, so a
    /// failed op stays retryable). Reusing an operation id with a DIFFERENT
    /// mutation id is rejected; a NEW operation id carrying a known mutation
    /// id (repair/retry-after-unknown-outcome) proceeds and re-executes.
    pub(crate) fn helper_mutation_begin(
        &self,
        epoch: u64,
        operation_id: &str,
        mutation_id: &str,
    ) -> Result<HelperMutationBegin, &'static str> {
        let mut store = self
            .helper_mutations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (epoch, operation_id.to_string());
        let replay = store
            .records
            .get(&key)
            .map(|record| (record.mutation_id.clone(), record.outcome.clone()));
        if let Some((recorded_mutation, outcome)) = replay {
            if recorded_mutation != mutation_id {
                return Err("operation-id-reused");
            }
            store.seq = store.seq.wrapping_add(1);
            let seq = store.seq;
            if let Some(record) = store.records.get_mut(&key) {
                record.last_used = seq;
            }
            return Ok(HelperMutationBegin::Replay(outcome));
        }
        store.in_flight.insert(key.clone());
        Ok(HelperMutationBegin::Proceed(HelperMutationLease {
            mutations: Arc::clone(&self.helper_mutations),
            key,
            mutation_id: mutation_id.to_string(),
            completed: false,
        }))
    }
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
    /// and so the compiler enforces that it reads exactly these six live
    /// sources (plus the test-only cap seam).
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
            helper_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            helper_mutations: Arc::new(Mutex::new(HelperMutationStore::default())),
            policy_captures: Arc::new(Mutex::new(std::collections::HashMap::new())),
            policy_capture_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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


/// The READ wire deliberately uses compact `4`/`6` family tags rather than
/// leaking Linux's `AF_INET`/`AF_INET6` values (`2`/`10`) into Go.
pub(crate) fn policy_wire_family(addr_family: u8) -> u8 {
    match addr_family as i32 {
        libc::AF_INET => 4,
        libc::AF_INET6 => 6,
        _ => 0,
    }
}

pub(crate) fn policy_tuple_from_key(
    key: &SessionKey,
) -> Option<crate::protocol::SessionPolicyTuple> {
    let family = policy_wire_family(key.addr_family);
    (family != 0).then(|| crate::protocol::SessionPolicyTuple {
        addr_family: family,
        protocol: key.protocol,
        src_ip: key.src_ip.to_string(),
        dst_ip: key.dst_ip.to_string(),
        src_port: key.src_port,
        dst_port: key.dst_port,
        tunnel_discriminator: key.discriminator.to_wire(),
        routing_domain: key.routing_domain,
    })
}

pub(crate) fn policy_match_from_parts(
    key: &SessionKey,
    metadata: &SessionMetadata,
    decision_nat: crate::nat::NatDecision,
    session_id: u64,
    created_ns: u64,
) -> Option<crate::protocol::SessionPolicyMatch> {
    let family = policy_wire_family(key.addr_family);
    let tuple = policy_tuple_from_key(key)?;
    Some(crate::protocol::SessionPolicyMatch {
        addr_family: family,
        routing_domain: key.routing_domain,
        tuple,
        reverse_key: None,
        policy_id: metadata.policy_id,
        created_secs: created_ns / 1_000_000_000,
        created_ns,
        expected_rt_flow_session_id: session_id,
        companion_policy_id: 0,
        expected_companion_rt_flow_session_id: 0,
        // #10626: rename-rematch inputs for the Go capture. Zones come from
        // the live metadata; DNAT-ness is a translated dst (covers NPTv6 too,
        // which rewrites dst with no port rewrite — same rule the legacy Go
        // path applies to SessFlagDNAT + NATDstIP).
        ingress_zone_id: metadata.ingress_zone,
        egress_zone_id: metadata.egress_zone,
        dnat: decision_nat.rewrite_dst.is_some(),
        nat_dst_ip: decision_nat
            .rewrite_dst
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        nat_dst_port: decision_nat.rewrite_dst_port.unwrap_or(0),
    })
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
    /// Decode one READ tuple to a session key for an identity-conditional
    /// policy delete (Delete intent: an unstatable discriminator under-matches
    /// to `None`, and validation against the live derivation refuses rather
    /// than deleting by it anyway). The tuple's family tag is the compact 4/6
    /// (`policy_wire_family`), not `AF_INET`/`AF_INET6`, and its routing domain
    /// is RAW (0 = default instance, stated) — never the #7239 wire codec —
    /// so no domain decode applies. Inverse of `policy_tuple_from_key` for
    /// the delete path's exact-key needs.
    fn policy_key_from_tuple(
        tuple: &crate::protocol::SessionPolicyTuple,
    ) -> Result<SessionKey, String> {
        let discriminator = match crate::session::TunnelDiscriminator::from_wire(
            tuple.tunnel_discriminator,
        ) {
            crate::session::WireDiscriminator::Present(discriminator) => discriminator,
            crate::session::WireDiscriminator::Absent
            | crate::session::WireDiscriminator::Unrecognized => {
                crate::session::TunnelDiscriminator::None
            }
        };
        let addr_family = match tuple.addr_family {
            4 => libc::AF_INET as u8,
            6 => libc::AF_INET6 as u8,
            other => return Err(format!("policy tuple family {other}")),
        };
        let src_ip = tuple
            .src_ip
            .parse()
            .map_err(|e| format!("parse policy tuple src_ip {}: {e}", tuple.src_ip))?;
        let dst_ip = tuple
            .dst_ip
            .parse()
            .map_err(|e| format!("parse policy tuple dst_ip {}: {e}", tuple.dst_ip))?;
        Ok(SessionKey {
            addr_family,
            protocol: tuple.protocol,
            src_ip,
            dst_ip,
            src_port: tuple.src_port,
            dst_port: tuple.dst_port,
            discriminator,
            routing_domain: tuple.routing_domain,
        })
    }

    /// #10512: decode + validate one wire micro-batch, then run it. The
    /// `PolicyDeleteItem` worker type never crosses to the server layer, so
    /// the sync handler enters here with the wire matches. ANY malformed
    /// match fails the WHOLE batch closed: the capture is the delete's
    /// authorization, and a batch that cannot name every companion exactly
    /// must not run.
    pub(crate) fn delete_policy_batch_matches(
        &self,
        matches: &[crate::protocol::SessionPolicyMatch],
        forward_only: bool,
    ) -> (Vec<crate::afxdp::SyncedDeleteOutcome>, bool, Vec<String>) {
        let mut items = Vec::with_capacity(matches.len());
        for m in matches {
            if m.expected_rt_flow_session_id == 0 {
                return (
                    Vec::new(),
                    false,
                    vec!["policy-batch-identity-missing".to_string()],
                );
            }
            let forward = match Self::policy_key_from_tuple(&m.tuple) {
                Ok(key) => key,
                Err(err) => {
                    return (
                        Vec::new(),
                        false,
                        vec![format!("policy-batch-forward-key:{err}")],
                    )
                }
            };
            let captured = match (&m.reverse_key, m.expected_companion_rt_flow_session_id) {
                (None, 0) => None,
                (Some(tuple), expected) if expected != 0 => {
                    match Self::policy_key_from_tuple(tuple) {
                        Ok(key) => Some(key),
                        Err(err) => {
                            return (
                                Vec::new(),
                                false,
                                vec![format!("policy-batch-reverse-key:{err}")],
                            )
                        }
                    }
                }
                _ => {
                    return (
                        Vec::new(),
                        false,
                        vec!["policy-batch-companion-mismatch".to_string()],
                    )
                }
            };
            items.push(crate::afxdp::PolicyDeleteItem {
                key: forward,
                session_id: m.expected_rt_flow_session_id,
                forward_only,
                companion_session_id: m.expected_companion_rt_flow_session_id,
                captured_companion: captured,
            });
        }
        self.delete_policy_batch(&items)
    }

    /// #10512: one identity-conditional policy-delete micro-batch (plan §2.4:
    /// at most 64 matches, 128 gate keys). Shared HA state does not contain
    /// ordinary sessions, so the batch covers BOTH stores per match: a
    /// coordinator-side shared conditional remove plus a fenced worker
    /// remove envelope, under ONE all-keys gate lease, with one probe
    /// envelope and token-authorized repair per touched tuple.
    ///
    /// Phases, uniform (no short-circuit): acquire ALL keys + Finalizing →
    /// fenced remove envelope → shared conditional removes → probe envelope
    /// (+1 retry) → token-authorized repair → release. No SessionTable
    /// mutation precedes acquisition: a lease failure aborts with zero
    /// mutations. A remove abort cancels every queued fence, completes the
    /// shared half (quiesce — infallible, still fenced, so no zombie
    /// authority survives the failed batch), attempts one best-effort fenced
    /// repair, then fails loud. Any fan-out, lease, or mirror failure aborts
    /// the WHOLE batch with `complete=false` (the caller answers `ok=false`):
    /// outcomes are valid only on `(ok, complete)`.
    ///
    /// Dead workers: the remove fan-out fails on them (a panic during commit
    /// fails loud — revocation must not silently succeed alongside one),
    /// while the probe skips them (diagnostic only): dead tables die with
    /// their threads (no Arc<SessionTable> exists anywhere), so live-only
    /// evidence is complete and repair attempts stay sound.
    pub(in crate::afxdp) fn delete_policy_batch(
        &self,
        items: &[crate::afxdp::PolicyDeleteItem],
    ) -> (Vec<crate::afxdp::SyncedDeleteOutcome>, bool, Vec<String>) {
        use crate::afxdp::SyncedDeleteOutcome;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};
        const FANOUT_TIMEOUT: Duration = Duration::from_millis(250);

        if items.is_empty() {
            return (Vec::new(), true, Vec::new());
        }
        // Plan §2.4 caps, enforced before gate acquisition (Go packs under
        // them; this is defense against a corrupt or hostile sender).
        let key_count: usize = items
            .iter()
            .map(|item| 1 + usize::from(item.captured_companion.is_some()))
            .sum();
        if items.len() > 64 || key_count > 128 {
            return (
                Vec::new(),
                false,
                vec![format!(
                    "policy-batch-over-cap:{}:{}",
                    items.len(),
                    key_count
                )],
            );
        }

        let shared_removed = |outcome: &SyncedDeleteOutcome| {
            matches!(
                outcome,
                SyncedDeleteOutcome::Applied | SyncedDeleteOutcome::PartialCompanion
            )
        };

        // Lease ALL of the batch's keys together (plan §2.4 all-keys lease),
        // before ANY SessionTable mutation: a lease failure then aborts with
        // zero mutations (the liveness gate above is read-only). Uniform
        // phases — no short-circuit — so every ordering stays fenced.
        let mut lease_keys: Vec<SessionKey> = Vec::new();
        for item in items {
            lease_keys.push(item.key.clone());
            if let Some(companion) = item.captured_companion.as_ref() {
                lease_keys.push(companion.clone());
            }
        }
        let lease = match crate::afxdp::bpf_map::global_tuple_gate().acquire_lease(lease_keys) {
            Ok(lease) => lease,
            Err(err) => {
                eprintln!("xpf-ha: policy batch lease refused: {err}");
                return (
                    Vec::new(),
                    false,
                    vec![format!("policy-batch-lease-refused:{err}")],
                );
            }
        };
        if lease.begin_finalizing().is_err() {
            eprintln!("xpf-ha: policy batch lease busy at finalizing");
            drop(lease);
            return (
                Vec::new(),
                false,
                vec!["policy-batch-lease-busy".to_string()],
            );
        }
        // Hold clock starts at Finalizing: what the observer measures is the
        // fenced window (remove + shared + probe + repair), not acquisition.
        let lease_since = Instant::now();

        // Phase 2: fenced remove envelope. Each worker's command carries its
        // OWN fence mutex: workers tear down in parallel (the plan's parallel
        // envelopes — never W×64 serialized), while cancel validation stays
        // atomic with each worker's mutations. On ANY fan-out failure every
        // queued fence is cancelled in fan-out order — validation atomic with
        // the mutations — then the lease drops and the batch fails. No drain:
        // post-return mutation is impossible by construction, not by timing.
        // Lock order is always fan-out (worker-id) order, and no worker ever
        // holds more than its own fence: no cycle exists.
        let mut remove_fences: Vec<std::sync::Arc<std::sync::Mutex<crate::afxdp::PolicyDeleteBatchReport>>> =
            Vec::new();
        let mut applied_slots: Vec<std::sync::Arc<std::sync::Mutex<Vec<bool>>>> = Vec::new();
        // Phase-2 handoff: ONE intent vec per batch, shared across workers
        // (each arm pushes inside its fence scope — see the variant doc).
        let remove_intents: std::sync::Arc<
            std::sync::Mutex<Vec<crate::afxdp::DeferredRedirectDelete>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let remove_pending = std::sync::Arc::new(AtomicUsize::new(0));
        let mut remove_failed = false;
        let records = self.workers.load();
        for (worker_id, record) in records.iter() {
            if record.is_dead() {
                remove_failed = true;
                eprintln!("xpf-ha: policy batch remove worker-{worker_id}: dead");
                continue;
            }
            let fence = std::sync::Arc::new(std::sync::Mutex::new(
                crate::afxdp::PolicyDeleteBatchReport {
                    cancelled: false,
                    partial: vec![false; items.len()],
                    refused: vec![false; items.len()],
                },
            ));
            remove_fences.push(std::sync::Arc::clone(&fence));
            let slot = std::sync::Arc::new(std::sync::Mutex::new(vec![false; items.len()]));
            applied_slots.push(std::sync::Arc::clone(&slot));
            let command = crate::afxdp::WorkerCommand::DeletePolicyBatch {
                items: items.to_vec(),
                applied: slot,
                pending: std::sync::Arc::clone(&remove_pending),
                report: fence,
                intents: std::sync::Arc::clone(&remove_intents),
            };
            let mut queue = crate::afxdp::worker_queue::lock_recover(&record.handle.commands);
            remove_pending.fetch_add(1, Ordering::Release);
            if !crate::afxdp::worker_queue::push_bounded(&mut queue, command) {
                remove_pending.fetch_sub(1, Ordering::AcqRel);
                remove_failed = true;
                eprintln!("xpf-ha: policy batch remove worker-{worker_id}: queue-full");
            }
        }
        drop(records);
        if remove_pending.load(Ordering::Acquire) != 0 {
            let deadline = Instant::now() + FANOUT_TIMEOUT;
            while remove_pending.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if remove_pending.load(Ordering::Acquire) != 0 {
            remove_failed = true;
            eprintln!(
                "xpf-ha: policy batch remove: worker-ack-timeout:{}",
                remove_pending.load(Ordering::Acquire)
            );
        }
        // Phase-2 failure verdict (default: fan-out abort): set by the normal
        // phase-2 attempt below on failure so the abort sequence returns the
        // precise error. `&str`: all candidates are 'static; allocated once,
        // on the failure return only.
        let mut remove_error = "policy-batch-remove-aborted";
        // True once the normal path attempted phase 2 (success or failure):
        // the abort sequence skips its best-effort re-execution (deletes are
        // idempotent, but a second attempt is pure noise).
        let mut phase2_attempted = false;
        // Coordinator-owned phase 2, normal path: every worker acked, so
        // every intent is in hand (acks cover the fence-scoped stash).
        // Executed under the batch lease (dropped below after repair), which
        // serializes same-tuple installs — no replacement can land between
        // any worker's phase 1 and this execution, so no re-probe is needed.
        // On failure this sets flags and falls THROUGH into the abort
        // sequence below (shared quiesce + best-effort repair, then the
        // phase-2 verdict): returning directly would leave shared authority
        // contradicting already-removed worker state plus ghost mirrors.
        if !remove_failed {
            phase2_attempted = true;
            // Absent map degrades to fd -1 (repair sites do the same): the
            // registry retirement below MUST run even with no kernel map
            // bound (skipping would strand Worker claims for removed rows);
            // only the kernel write no-ops, exactly like the old worker path.
            let maps = self.bpf_maps.load();
            let fd = maps.session_map_fd.as_ref().map_or(-1, |fd| fd.fd);
            let stashed = remove_intents
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let map = crate::afxdp::bpf_map::SteeringMap {
                fd,
                owners: &self.steering_owners,
                holder: crate::afxdp::bpf_map::SteeringHolder::Coordinator,
            };
            if !Self::execute_deferred_redirects(map, &lease, &stashed) {
                remove_error = "policy-batch-deferred-failed";
                remove_failed = true;
            }
        }
        if remove_failed {
            // Cancel every queued fence in fan-out order. Each worker's
            // in-flight section (table work ONLY — workers issue no BPF in
            // this path) completes before its flag lands, so every mutation
            // is either final pre-return or never happens. Redirect deletes
            // run coordinator-side below, from the in-hand intents.
            for fence in &remove_fences {
                fence
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .cancelled = true;
            }
            // Coordinator-owned phase 2, abort path: execute the in-hand
            // intents while still fenced/leased (every worker either pushed
            // before its fence landed or observes `cancelled` and pushes
            // nothing — the set is complete). Best-effort: the batch fails
            // regardless, but fewer ghost rows is live+consistent. Intentions
            // that never arrive belong to dead workers whose tables died
            // with their threads (stale rows self-heal via overwrite).
            // Skipped when the normal path already attempted it (success or
            // failure — re-execution is idempotent but pure noise).
            if !phase2_attempted {
                // fd -1 when unbound (see the normal path): retirement runs
                // regardless; only the kernel write no-ops.
                let maps = self.bpf_maps.load();
                let fd = maps.session_map_fd.as_ref().map_or(-1, |fd| fd.fd);
                let stashed = remove_intents
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let map = crate::afxdp::bpf_map::SteeringMap {
                    fd,
                    owners: &self.steering_owners,
                    holder: crate::afxdp::bpf_map::SteeringHolder::Coordinator,
                };
                if !Self::execute_deferred_redirects(map, &lease, &stashed) {
                    eprintln!("xpf-ha: policy batch abort: deferred redirect execution failed");
                }
            }
            let applied_count: usize = applied_slots
                .iter()
                .map(|slot| {
                    slot.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .iter()
                        .filter(|applied| **applied)
                        .count()
                })
                .sum();
            eprintln!("xpf-ha: policy batch remove aborted with {applied_count} worker removals");
            // Quiesce: complete the deterministic shared half now (infallible,
            // still fenced) so the abort leaves no zombie authority behind —
            // shared converges with the partial worker state instead of
            // contradicting it. Outcomes discarded: the batch fails regardless.
            let _ = self.run_shared_policy_loop(items);
            // Best-effort final repair while still fenced: removals may have
            // landed pre-cancel, and the mirror must not misrepresent live
            // survivors as ghost rows. Always attempted: dead workers are
            // skipped inside the probe (their tables died with their threads,
            // so live-only evidence is complete). Retried once like the
            // success path — a stall that clears still repairs. The batch
            // fails regardless — revocation is incomplete — but
            // live+consistent beats live+ghost.
            let mut bares: Vec<SessionKey> = Vec::new();
            for item in items {
                for key in std::iter::once(&item.key).chain(item.captured_companion.iter()) {
                    let mut bare = key.clone();
                    bare.routing_domain = 0;
                    bare.discriminator = Default::default();
                    if !bares.contains(&bare) {
                        bares.push(bare);
                    }
                }
            }
            if !bares.is_empty() {
                let found: std::sync::Arc<
                    std::sync::Mutex<Vec<Option<crate::afxdp::worker::SyncedSessionEntry>>>,
                > = std::sync::Arc::new(std::sync::Mutex::new(vec![None; bares.len()]));
                let mut probed = self.probe_policy_bares(&bares, &found).is_ok();
                if !probed {
                    probed = self.probe_policy_bares(&bares, &found).is_ok();
                }
                if probed {
                    let view = self.runtime_view();
                    let forwarding = view.forwarding();
                    let maps = self.bpf_maps.load();
                    let v4_fd = maps.conntrack_v4_fd.as_ref().map_or(-1, |fd| fd.fd);
                    let v6_fd = maps.conntrack_v6_fd.as_ref().map_or(-1, |fd| fd.fd);
                    let _ = self.repair_policy_bares(
                        &lease,
                        forwarding,
                        v4_fd,
                        v6_fd,
                        &bares,
                        &found,
                    );
                }
            }
            self.record_policy_hold(lease_since);
            drop(lease);
            return (
                Vec::new(),
                false,
                vec![remove_error.to_string()],
            );
        }
        let mut worker_applied = vec![false; items.len()];
        let mut worker_partial = vec![false; items.len()];
        let mut worker_refused = vec![false; items.len()];
        for slot in &applied_slots {
            let applied = slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (index, did) in applied.iter().enumerate() {
                worker_applied[index] |= did;
            }
        }
        for fence in &remove_fences {
            let report = fence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for index in 0..items.len() {
                worker_partial[index] |= report.partial[index];
                worker_refused[index] |= report.refused[index];
            }
        }
        // Shared conditional removes, under the lease (same helper the abort
        // path uses to quiesce): no SessionTable mutation precedes
        // acquisition. Cannot fail (outcomes only, no transport).
        let shared_outcome = self.run_shared_policy_loop(items);

        // Probe + repair every tuple anything removed (shared or worker),
        // deduplicated: the lease above serializes same-tuple installs, so
        // each probe result is authoritative for its repair.
        let mut probe_bares: Vec<SessionKey> = Vec::new();
        for (index, item) in items.iter().enumerate() {
            if !shared_removed(&shared_outcome[index]) && !worker_applied[index] {
                continue;
            }
            for key in std::iter::once(&item.key).chain(item.captured_companion.iter()) {
                let mut bare = key.clone();
                bare.routing_domain = 0;
                bare.discriminator = Default::default();
                if !probe_bares.contains(&bare) {
                    probe_bares.push(bare);
                }
            }
        }
        // Probe + repair every tuple anything removed (shared or worker),
        // deduplicated: the lease serializes same-tuple installs, so each
        // probe result is authoritative for its repair. A first probe failure
        // retries once unconditionally — dead workers are skipped inside the
        // probe (their tables died with their threads), so only a live stall
        // can fail, and the probe is read-only, so retry-to-success is sound
        // (unlike remove, where a retry would only re-fence an
        // already-incomplete revocation).
        let probe_found: std::sync::Arc<
            std::sync::Mutex<Vec<Option<crate::afxdp::worker::SyncedSessionEntry>>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(vec![None; probe_bares.len()]));
        let mut probed = probe_bares.is_empty()
            || self.probe_policy_bares(&probe_bares, &probe_found).is_ok();
        if !probed {
            probed = self.probe_policy_bares(&probe_bares, &probe_found).is_ok();
        }
        let mut mirror_ok = false;
        if probed {
            let view = self.runtime_view();
            let forwarding = view.forwarding();
            let maps = self.bpf_maps.load();
            let v4_fd = maps.conntrack_v4_fd.as_ref().map_or(-1, |fd| fd.fd);
            let v6_fd = maps.conntrack_v6_fd.as_ref().map_or(-1, |fd| fd.fd);
            mirror_ok = self.repair_policy_bares(
                &lease,
                forwarding,
                v4_fd,
                v6_fd,
                &probe_bares,
                &probe_found,
            );
        }
        self.record_policy_hold(lease_since);
        drop(lease);
        if !probed {
            return (
                Vec::new(),
                false,
                vec!["policy-batch-probe-aborted".to_string()],
            );
        }
        if !mirror_ok {
            return (
                Vec::new(),
                false,
                vec!["policy-batch-mirror-failed".to_string()],
            );
        }
        let outcomes = items
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let applied =
                    shared_removed(&shared_outcome[index]) || worker_applied[index];
                let partial = matches!(
                    shared_outcome[index],
                    SyncedDeleteOutcome::PartialCompanion
                ) || worker_partial[index]
                    || (worker_refused[index] && applied);
                if applied {
                    if partial {
                        SyncedDeleteOutcome::PartialCompanion
                    } else {
                        SyncedDeleteOutcome::Applied
                    }
                } else if worker_refused[index]
                    || matches!(
                        shared_outcome[index],
                        SyncedDeleteOutcome::RefusedIdentity
                    )
                {
                    SyncedDeleteOutcome::RefusedIdentity
                } else {
                    SyncedDeleteOutcome::StaleForward
                }
            })
            .collect();
        (outcomes, true, Vec::new())
    }

    /// Record one Finalizing hold (`since` → now) into the batch observer
    /// (count, total, max). Called exactly once per leased batch, at every
    /// release site past finalizing — success and abort paths alike, so the
    /// average covers pathological holds too, not just clean ones.
    fn record_policy_hold(&self, since: std::time::Instant) {
        use std::sync::atomic::Ordering;
        let held_ns = since.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        self.sessions.policy_batch_count.fetch_add(1, Ordering::Relaxed);
        self.sessions
            .policy_batch_hold_ns
            .fetch_add(held_ns, Ordering::Relaxed);
        self.sessions
            .policy_batch_hold_max_ns
            .fetch_max(held_ns, Ordering::Relaxed);
    }

    /// Coordinator-owned phase 2: execute worker-collected redirect-delete
    /// intents. Called after phase-1 acks (normal) or after setting
    /// cancelled (abort) — always under the caller's Finalizing batch lease
    /// (the `&GateLease` parameter is the proof, mirroring
    /// `repair_policy_bares`). No re-probe: the lease serializes
    /// same-tuple installs, so no replacement can land between any phase 1
    /// and this execution. Each intent executes under ITS collecting
    /// worker's holder bit (claims are per-holder — Coordinator-holder
    /// execution would strand worker claims and skip every delete). Every
    /// intent is mechanically verified against the lease before its
    /// execution — an uncovered intent is a caller bug that fails loud,
    /// never an unfenced delete. Returns false on any cover failure
    /// (attempts all intents, like the repair); BPF delete errors are
    /// fire-and-forget (pre-existing: the worker path never observed them
    /// either).
    pub(in crate::afxdp) fn execute_deferred_redirects(
        map: crate::afxdp::bpf_map::SteeringMap<'_>,
        lease: &crate::afxdp::bpf_map::GateLease,
        intents: &[crate::afxdp::DeferredRedirectDelete],
    ) -> bool {
        let mut ok = true;
        for intent in intents {
            if !lease.covers(&intent.key) {
                eprintln!("xpf-ha: policy batch deferred redirect for unleased tuple");
                ok = false;
                continue;
            }
            crate::afxdp::bpf_map::delete_session_map_redirect_for_session(
                crate::afxdp::bpf_map::SteeringMap {
                    holder: crate::afxdp::bpf_map::SteeringHolder::Worker(intent.worker_id),
                    ..map
                },
                &intent.key,
                intent.decision,
                &intent.metadata,
                intent.origin,
            );
        }
        ok
    }

    /// Run every match's shared conditional remove (lease-less: the caller
    /// holds the batch lease across the whole batch). Cannot fail — outcomes
    /// only, no transport — so both the success path and the abort path
    /// (quiesce: complete the deterministic shared half before the final
    /// probe+repair, leaving no zombie authority behind a failed batch) call
    /// it exactly once per batch.
    fn run_shared_policy_loop(
        &self,
        items: &[crate::afxdp::PolicyDeleteItem],
    ) -> Vec<crate::afxdp::SyncedDeleteOutcome> {
        items
            .iter()
            .map(|item| {
                self.remove_shared_policy_item(
                    &item.key,
                    item.session_id,
                    item.companion_session_id,
                    item.captured_companion.as_ref(),
                    item.forward_only,
                )
            })
            .collect()
    }

    /// One probe fan-out over `bares`, filling `found` (first reporter wins
    /// per slot; slots may already hold earlier-attempt survivors — state is
    /// stable under the batch lease, so reuse is sound). Dead workers are
    /// skipped (diagnostic only): their tables died with their threads, so
    /// live-only evidence is complete. `Ok` iff every live worker acked with
    /// no full queue.
    fn probe_policy_bares(
        &self,
        bares: &[SessionKey],
        found: &std::sync::Arc<std::sync::Mutex<Vec<Option<crate::afxdp::worker::SyncedSessionEntry>>>>,
    ) -> Result<(), String> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};
        let pending = std::sync::Arc::new(AtomicUsize::new(0));
        let records = self.workers.load();
        for (worker_id, record) in records.iter() {
            if record.is_dead() {
                // Dead tables are dropped with their threads (no Arc<SessionTable>
                // exists anywhere: thread-owned plain field), so a dead worker
                // holds nothing to probe. Skip (diagnostic only); live-only
                // evidence is complete by that proof.
                eprintln!("xpf-ha: policy batch probe worker-{worker_id}: dead, skipped");
                continue;
            }
            let command = crate::afxdp::WorkerCommand::ProbePolicyBatch {
                bares: bares.to_vec(),
                found: std::sync::Arc::clone(found),
                pending: std::sync::Arc::clone(&pending),
            };
            let mut queue = crate::afxdp::worker_queue::lock_recover(&record.handle.commands);
            pending.fetch_add(1, Ordering::Release);
            if !crate::afxdp::worker_queue::push_bounded(&mut queue, command) {
                pending.fetch_sub(1, Ordering::AcqRel);
                eprintln!("xpf-ha: policy batch probe worker-{worker_id}: queue-full");
                return Err(format!("worker-{worker_id}:queue-full"));
            }
        }
        drop(records);
        if pending.load(Ordering::Acquire) != 0 {
            let deadline = Instant::now() + Duration::from_millis(250);
            while pending.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if pending.load(Ordering::Acquire) != 0 {
            let outstanding = pending.load(Ordering::Acquire);
            eprintln!("xpf-ha: policy batch probe: worker-ack-timeout:{outstanding}");
            return Err(format!("worker-ack-timeout:{outstanding}"));
        }
        Ok(())
    }

    /// Token-authorized repair for probed tuples, under the caller's
    /// Finalizing batch lease: a survivor anywhere (worker probe or a shared
    /// entry this batch did not remove) republishes; proven absence deletes
    /// the bare row. Either live value satisfies the mirror invariant (a
    /// tuple with any live session carries a LIVE tenant's value); the shared
    /// scan runs after the worker probe so it observes the freshest shared
    /// state. Every tuple is mechanically verified against the lease before
    /// its repair — an uncovered tuple is a caller bug that fails loud, never
    /// an unfenced repair. Returns false on any mirror-write failure.
    fn repair_policy_bares(
        &self,
        lease: &crate::afxdp::bpf_map::GateLease,
        forwarding: &super::ForwardingState,
        conntrack_v4_fd: std::os::unix::io::RawFd,
        conntrack_v6_fd: std::os::unix::io::RawFd,
        bares: &[SessionKey],
        found: &std::sync::Arc<std::sync::Mutex<Vec<Option<crate::afxdp::worker::SyncedSessionEntry>>>>,
    ) -> bool {
        let mut mirror_ok = true;
        for (tuple_index, bare) in bares.iter().enumerate() {
            if !lease.covers(bare) {
                eprintln!("xpf-ha: policy batch repair of unleased tuple");
                mirror_ok = false;
                continue;
            }
            let survivor = found
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(tuple_index)
                .cloned()
                .flatten()
                .or_else(|| {
                    crate::afxdp::shared_ops::lock_shared_recover(&self.sessions.synced)
                        .values()
                        .find(|candidate| {
                            let mut candidate_bare = candidate.key.clone();
                            candidate_bare.routing_domain = 0;
                            candidate_bare.discriminator = Default::default();
                            candidate_bare == *bare
                        })
                        .cloned()
                });
            match survivor {
                Some(entry) => {
                    if !matches!(
                        self.publish_mirror_only(forwarding, &entry),
                        crate::afxdp::bpf_map::ConntrackPublishResult::Written
                            | crate::afxdp::bpf_map::ConntrackPublishResult::IntentionallySkipped
                    ) {
                        mirror_ok = false;
                    }
                }
                None => {
                    if !crate::afxdp::bpf_map::delete_bpf_conntrack_entry_under_gate(
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        bare,
                    ) {
                        mirror_ok = false;
                    }
                }
            }
        }
        mirror_ok
    }

    /// #10512: enumerate policy-tagged sessions from the helper-owned
    /// authority. The request is fanned out to every live worker because the
    /// worker table is the only place that retains the creation/identity pair
    /// needed for an identity-conditional delete. The shared synced map is
    pub(crate) fn list_sessions_by_policy(
        &self,
        request: &crate::protocol::SessionPolicyListRequest,
    ) -> (
        Vec<crate::protocol::SessionPolicyMatch>,
        bool,
        Vec<String>,
        String,
    ) {
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::{Duration, Instant};
        use crate::afxdp::POLICY_READ_CAPTURE_LIMIT as CAPTURE_LIMIT;
        const PAGE_ROWS: usize = 4096;
        const CAPTURE_IDLE: Duration = Duration::from_secs(30);

        let now = Instant::now();
        {
            let mut captures = self
                .policy_captures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            captures.retain(|_, capture| now.duration_since(capture.last_used) <= CAPTURE_IDLE);
            if !request.continuation.is_empty() {
                let Some(mut capture) = captures.remove(&request.continuation) else {
                    return (
                        Vec::new(),
                        false,
                        vec!["stale-capture".to_string()],
                        String::new(),
                    );
                };
                let start = capture.offset.min(capture.rows.len());
                let end = start.saturating_add(PAGE_ROWS).min(capture.rows.len());
                let page = capture.rows[start..end].to_vec();
                capture.offset = end;
                capture.last_used = now;
                let complete = end >= capture.rows.len() && capture.errors.is_empty();
                let errors = capture.errors.clone();
                let continuation = if end < capture.rows.len() {
                    captures.insert(request.continuation.clone(), capture);
                    request.continuation.clone()
                } else {
                    String::new()
                };
                return (page, complete, errors, continuation);
            }
        }

        let wanted: HashSet<u32> =
            request.policy_ids.iter().copied().filter(|id| *id != 0).collect();
        if wanted.is_empty() {
            return (Vec::new(), true, Vec::new(), String::new());
        }
        let family_allowed = |family: u8| {
            request.families.is_empty()
                || request.families.iter().any(|candidate| *candidate == family)
        };
        let class_allowed = |is_reverse: bool| {
            request.classes.is_empty()
                || request.classes.iter().any(|class| {
                    (is_reverse && class == "reverse") || (!is_reverse && class == "forward")
                })
        };

        let collected = Arc::new(Mutex::new(crate::afxdp::PolicyReadCollector::default()));
        let overflow = Arc::new(AtomicBool::new(false));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let pending = Arc::new(AtomicUsize::new(0));
        let mut complete = true;
        let mut queued = 0usize;
        let records = self.workers.load();
        for (worker_id, record) in records.iter() {
            if record.is_dead() {
                errors
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(format!("worker-{worker_id}:dead"));
                complete = false;
                continue;
            }
            let command = crate::afxdp::WorkerCommand::ListSessionsByPolicy {
                request: request.clone(),
                collected: Arc::clone(&collected),
                overflow: Arc::clone(&overflow),
                errors: Arc::clone(&errors),
                pending: Arc::clone(&pending),
            };
            let mut queue = crate::afxdp::worker_queue::lock_recover(&record.handle.commands);
            // Reserve the acknowledgement before enqueueing: a worker can
            // consume a command immediately after the queue lock is released.
            pending.fetch_add(1, Ordering::Release);
            if crate::afxdp::worker_queue::push_bounded(&mut queue, command) {
                queued += 1;
            } else {
                pending.fetch_sub(1, Ordering::AcqRel);
                errors
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(format!("worker-{worker_id}:queue-full"));
                complete = false;
            }
        }
        drop(records);

        // Worker acknowledgements are bounded: a dead/stalled worker must
        // produce an incomplete READ rather than hold the control socket.
        let deadline = Instant::now() + Duration::from_millis(250);
        while pending.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        if pending.load(Ordering::Acquire) != 0 {
            errors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!(
                    "worker-ack-timeout:{}",
                    pending.load(Ordering::Acquire)
                ));
            complete = false;
        }
        if queued == 0 {
            complete = false;
            errors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push("worker-local-scan-unavailable".to_string());
        }

        // Rows arrive deduplicated and capped: workers admitted through the
        // shared collector during the scan (no post-clone dedup/truncate, no
        // O(W×sessions) transient). Move them out (no clone) plus the
        // overflow verdict.
        let mut collector = collected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut rows = collector.take_rows();
        let overflowed = collector.overflowed();
        drop(collector);
        let mut all_errors = errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        if request.mode == "legacy" && request.before_secs.is_none() {
            all_errors.push("legacy-before-secs-missing".to_string());
            complete = false;
        }
        if overflowed || rows.len() > CAPTURE_LIMIT {
            // overflowed: the admission cap tripped during collection
            // (authoritative). The length check is defense-in-depth (reserve
            // accounting can only skew via an arm bug, caught by debug_assert
            // in tests).
            rows.truncate(CAPTURE_LIMIT);
            all_errors.push("capture-limit".to_string());
            complete = false;
        }
        let token = format!(
            "policy-{:016x}",
            self.policy_capture_seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let row_count = rows.len();
        let end = row_count.min(PAGE_ROWS);
        let page = rows[..end].to_vec();
        let continuation = if end < row_count {
            self.policy_captures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    token.clone(),
                    PolicyCapture {
                        rows,
                        errors: all_errors.clone(),
                        offset: end,
                        last_used: now,
                    },
                );
            token
        } else {
            String::new()
        };
        let page_complete = end >= row_count && complete && all_errors.is_empty();
        (page, page_complete, all_errors, continuation)
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
    /// stored nonempty: key-set inequality → NeedsLock (join/leave); match +
    /// stored active + VALID lease → fresh `active_lease_until` from incoming
    /// watchdog; match + EXPIRED stored-active → NeedsLock without storing any
    /// RG state; mismatch + stored active + VALID lease → fresh lease for
    /// STORED active/watchdog (liveness only, ownership stays); mismatch +
    /// stored inactive OR EXPIRED stored-active → keep stored (owned by main);
    /// zero refreshed → NeedsLock (pure no-op never recorded as publish), else
    /// store + Served(count). Never changes active flags or membership off-lock.
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
                // Match: full refresh from incoming (exactly like locked) —
                // but an already-EXPIRED stored-active must use the locked
                // path (#10787). Return before any RG state can be stored,
                // even if another RG is otherwise refreshable.
                if incoming_active && !stored_runtime.is_forwarding_active(now_secs) {
                    return HaRefreshOutcome::NeedsLock;
                }
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

    /// #10720 F4: count peer-synced imports refused for an incomplete key.
    pub(crate) fn note_incomplete_synced_key_import(&self) {
        self.sessions
            .import_incomplete_key
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
    pub(crate) fn publish_mirror_only(
        &self,
        entry: &crate::afxdp::worker::SyncedSessionEntry,
    ) -> Result<(), &'static str> {
        let _lease = crate::afxdp::bpf_map::global_tuple_gate()
            .acquire_lease([entry.key.clone()])
            .map_err(|_| "gate-busy")?;
        match self
            .domain
            .publish_mirror_only(self.view.forwarding(), entry)
        {
            crate::afxdp::bpf_map::ConntrackPublishResult::Written
            | crate::afxdp::bpf_map::ConntrackPublishResult::IntentionallySkipped => Ok(()),
            crate::afxdp::bpf_map::ConntrackPublishResult::GateBusy => Err("gate-busy"),
            crate::afxdp::bpf_map::ConntrackPublishResult::KernelError => {
                Err("mirror-write-failed")
            }
            crate::afxdp::bpf_map::ConntrackPublishResult::NoMap => {
                Err("mirror-map-unavailable")
            }
        }
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

    /// P12-A (double-restart wedge): a stale in-flight epoch that lands
    /// first must not wedge the latch against the current generation —
    /// N+1 then N+2 both accepted (pre-fix N+2 was rejected forever).
    #[test]
    fn helper_epoch_double_restart_readopts_10583() {
        let coordinator = Coordinator::new();
        let domain = coordinator.session_domain();
        assert!(domain.accepts_helper_epoch(8), "stale-first N+1 lands");
        assert!(
            domain.accepts_helper_epoch(9),
            "current N+2 must re-adopt, not wedge"
        );
        assert!(domain.accepts_helper_epoch(9), "adopted epoch is stable");
    }

    /// P12-B (single-restart control): first latch + idempotent re-accept.
    #[test]
    fn helper_epoch_single_restart_latches_10583() {
        let coordinator = Coordinator::new();
        let domain = coordinator.session_domain();
        assert!(domain.accepts_helper_epoch(8), "first latch accepts");
        assert!(domain.accepts_helper_epoch(8), "same epoch re-accepts");
    }

    /// P12-C (stale-rejected control): anything older than adopted fails.
    #[test]
    fn helper_epoch_older_rejected_after_adopt_10583() {
        let coordinator = Coordinator::new();
        let domain = coordinator.session_domain();
        assert!(domain.accepts_helper_epoch(9));
        assert!(
            !domain.accepts_helper_epoch(8),
            "older-than-adopted must be rejected"
        );
        assert!(
            !domain.accepts_helper_epoch(1),
            "much older must be rejected"
        );
    }

    /// P12-F (epoch-0 bypass): legacy/unstamped requests always pass
    /// and never disturb the latch.
    #[test]
    fn helper_epoch_zero_bypasses_10583() {
        let coordinator = Coordinator::new();
        let domain = coordinator.session_domain();
        assert!(domain.accepts_helper_epoch(0), "zero bypasses on fresh latch");
        assert!(domain.accepts_helper_epoch(9));
        assert!(domain.accepts_helper_epoch(0), "zero bypasses after adopt");
        assert!(
            domain.accepts_helper_epoch(9),
            "adopted epoch survives zero bypasses"
        );
        assert!(
            !domain.accepts_helper_epoch(8),
            "zero bypass must not reset the latch"
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

    /// An expired matching active RG forces NeedsLock before another healthy
    /// RG can be published; neither stored runtime is changed.
    #[test]
    fn expired_matching_active_needs_lock_before_any_publish_10787() {
        let coordinator = Coordinator::new();
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        let expired = crate::afxdp::HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs.saturating_sub(11),
            lease: crate::afxdp::HAForwardingLease::ActiveUntil(now_secs.saturating_sub(1)),
        };
        let healthy = crate::afxdp::HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: crate::afxdp::HAForwardingLease::ActiveUntil(now_secs.saturating_add(2)),
        };
        coordinator.ha.rg_runtime.store(Arc::new(BTreeMap::from([
            (1, expired),
            (2, healthy),
        ])));
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, true, 0), group(2, true, 0)]),
            HaRefreshOutcome::NeedsLock
        );
        let stored = coordinator.ha.rg_runtime.load();
        assert_eq!(
            stored.get(&1).expect("expired runtime remains").lease,
            expired.lease
        );
        assert_eq!(
            stored
                .get(&1)
                .expect("expired runtime remains")
                .watchdog_timestamp,
            expired.watchdog_timestamp
        );
        assert_eq!(
            stored.get(&2).expect("healthy runtime remains").lease,
            healthy.lease
        );
        assert_eq!(
            stored
                .get(&2)
                .expect("healthy runtime remains")
                .watchdog_timestamp,
            healthy.watchdog_timestamp
        );
    }

    /// A matching active refresh still renews a valid stored lease.
    #[test]
    fn matching_active_renews_valid_lease_10787() {
        let coordinator = Coordinator::new();
        let now_secs = crate::afxdp::monotonic_nanos() / 1_000_000_000;
        coordinator.ha.rg_runtime.store(Arc::new(BTreeMap::from([(
            1,
            crate::afxdp::HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs,
                lease: crate::afxdp::HAForwardingLease::ActiveUntil(now_secs.saturating_add(2)),
            },
        )])));
        let domain = coordinator.session_domain().clone();
        assert_eq!(
            domain.try_refresh_ha_leases(&[group(1, true, 0)]),
            HaRefreshOutcome::Served(1)
        );
        let stored = coordinator.ha.rg_runtime.load();
        let renewed = stored.get(&1).expect("active runtime remains stored");
        assert!(renewed.is_forwarding_active(now_secs));
        assert!(matches!(
            renewed.lease,
            crate::afxdp::HAForwardingLease::ActiveUntil(until)
                if until > now_secs.saturating_add(2)
        ));
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
