use super::*;
mod bpf_maps;
mod cos_leases;
mod cos_state;
mod ha_state;
mod idle_lease_sync_8121;
mod inject;
mod learned_route_capped_now;
mod neighbor_manager;
mod reconcile;
mod refresh_bindings;
mod session_manager;
mod snapshot_refresh;
mod status;
mod status_wg;
mod supervisor;
mod tunnel_supervision;
mod wg_control;
mod worker_manager;
pub(crate) use bpf_maps::BpfMaps;
pub(crate) use idle_lease_sync_8121::{IdleLeaseImportCounts, PoolDisplayLease, PoolIdleLease};
// #3789: the full-`reconcile` abort outcome, so `server/helpers.rs`
// (`reconcile_status_bindings`) and the control-socket handler can name
// the fallible return type.
pub(crate) use reconcile::ReconcileError;
pub(crate) use reconcile::{MandatoryPin, ReconcileStage, WorkerBindShortfall};
// #1890: re-import the split-out CoS builders at coordinator scope so
// pre-split references keep resolving unchanged — `status.rs` and
// `tests.rs` reach them through `use super::*`, and
// `reconcile/bringup.rs` through `super::super::` paths.
use cos_leases::{
    aggregate_cos_statuses_across_workers,
    build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes,
    build_cos_owner_worker_by_queue,
};
// #1890: these builders' only out-of-file consumers are `tests.rs`
// fixtures — gate the re-import so release builds don't carry an
// unused-imports warning.
#[cfg(test)]
use cos_leases::{
    build_cos_owner_worker_by_queue_from_binding_ifindexes,
    build_cos_owner_worker_by_queue_with_fallback_ifindexes,
    build_shared_cos_queue_leases_reusing_existing,
    build_shared_cos_queue_vtime_floors_reusing_existing, build_shared_cos_root_leases,
    build_shared_cos_root_leases_reusing_existing, build_worker_binding_ifindexes_from_identities,
    unique_interface_owner_worker_id,
};
pub(crate) use cos_state::SharedCoSState;
#[cfg(test)]
pub(crate) use cos_state::PrePublishSiblings;
pub(in crate::afxdp) use ha_state::HaState;
pub(in crate::afxdp) use routing_domain::{configured_routing_domains, synced_routing_domain_in};
pub(crate) use neighbor_manager::NeighborManager;
/// #7413: re-exported so `main_tests.rs` — the one `neigh-monitor` spawner
/// outside `coordinator/tests.rs` — can take the same guard. `mod
/// neighbor_manager` is private, and `mod coordinator` is private in
/// `afxdp/mod.rs`, so the guard needs a re-export at each level to be reachable
/// crate-wide; see `afxdp/mod.rs` for the second one.
#[cfg(test)]
pub(crate) use neighbor_manager::neigh_monitor_test_serial;
pub(crate) use neighbor_manager::WarmItem;
pub(in crate::afxdp) use neighbor_manager::{
    WARM_GC_INTERVAL_NS, WARM_GC_MAX_AGE_NS, WARM_PER_KEY_RATE_LIMIT_NS, WARM_QUEUE_DEPTH,
    WARM_SWEEP_RATE_LIMIT_NS,
};
pub(in crate::afxdp) use session_manager::SessionManager;
use supervisor::spawn_supervised_aux;
pub(in crate::afxdp) use worker_manager::WorkerManager;
pub(in crate::afxdp) use worker_manager::WorkerRecordsReader;
// #6242: the per-worker transactional runtime record. Named by `bringup.rs`
// (construction), `status.rs` / HA control fan-out (cold reads), and the test
// modules (`status_tests.rs`, `ha_tests.rs`, `tests.rs`) that seed workers.
pub(in crate::afxdp) use worker_manager::WorkerRuntimeRecord;

/// #1866 D3: canonical `id:port@ifindex` summary of a forwarding
/// state's WireGuard endpoint set, for transition logging.
fn wg_endpoint_set_summary(state: &ForwardingState) -> String {
    let mut parts: Vec<String> = state
        .tunnel_endpoints
        .values()
        .filter(|ep| ep.mode == "wireguard")
        .map(|ep| format!("{}:{}@{}", ep.id, ep.wg_listen_port, ep.logical_ifindex))
        .collect();
    parts.sort();
    parts.join(",")
}

/// #1873 R-D: ids whose owner changed across a snapshot apply — absent
/// in `next`, present with a DIFFERENT logical interface name, or
/// NEWLY APPEARING in `next` (absent in `previous` — Codex code r2:
/// an id with no owner in the previous state cannot have a
/// legitimately live session, so any entry still storing it — e.g. a
/// synced copy installed with an unresolvable id during an HA config
/// skew — predates `previous` and must be purged before the new
/// owner's row becomes reachable). Compared on the LOGICAL config
/// name (never linux_name — a cosmetic kernel rename must not purge
/// sessions).
///
/// `include_new_appearances` must be FALSE for the first snapshot
/// apply of a helper's life (previous state is the pristine default):
/// there every configured id "appears", and purging would wipe
/// legitimately synced sessions installed before the first apply.
pub(in crate::afxdp) fn tunnel_remap_purge_ids(
    previous: &ForwardingState,
    next: &ForwardingState,
    include_new_appearances: bool,
) -> Vec<u16> {
    let owners: Vec<(u16, String)> = previous
        .tunnel_endpoints
        .iter()
        .map(|(id, ep)| (*id, ep.interface.clone()))
        .collect();
    tunnel_remap_purge_ids_from_owners(&owners, next, include_new_appearances)
}

/// #1873 R-D (AGY code r3): owners-list flavor for the reconcile path,
/// where `stop_inner(false)` has already defaulted `coord.forwarding`
/// and the diff baseline must be the owner map captured before
/// teardown.
pub(in crate::afxdp) fn tunnel_remap_purge_ids_from_owners(
    prior_owners: &[(u16, String)],
    next: &ForwardingState,
    include_new_appearances: bool,
) -> Vec<u16> {
    let mut purge_ids: Vec<u16> = Vec::new();
    for (id, prev_interface) in prior_owners {
        match next.tunnel_endpoints.get(id) {
            None => purge_ids.push(*id),
            Some(next_ep) if next_ep.interface != *prev_interface => purge_ids.push(*id),
            Some(_) => {}
        }
    }
    if include_new_appearances {
        for id in next.tunnel_endpoints.keys() {
            if !prior_owners.iter().any(|(prev_id, _)| prev_id == id) {
                purge_ids.push(*id);
            }
        }
    }
    purge_ids
}

/// #1873 R-D (AGY code r4): filter the preserved synced-session replay
/// list by the remap purge set, MIRRORING delete_synced_session's
/// companion semantics — drop every entry whose stored id is purged,
/// plus the derived reverse companion (reverse_session_key over the
/// forward key + NAT decision) of each dropped FORWARD entry, which
/// itself carries tunnel_endpoint_id == 0 in asymmetric topologies and
/// would otherwise be resurrected as a half-dead pair by the bringup
/// replay. A reverse-marked entry drops standalone (its unmarked
/// forward keeps forwarding without the tunnel), matching the live
/// purge's delete_synced_session(is_reverse) behavior.
pub(in crate::afxdp) fn filter_replayed_synced_sessions(
    entries: &mut Vec<SyncedSessionEntry>,
    purge_ids: &[u16],
) {
    if purge_ids.is_empty() || entries.is_empty() {
        return;
    }
    // #4975: index the drop set in a HashSet rather than a Vec. The
    // retain phase tests membership once per surviving entry, so a
    // `Vec::contains` scan made the dominant phase O(entries × drop_keys)
    // — quadratic when an HA-recovery tunnel remap coincides with a large
    // synced-session set (entries bounded by the 131,072 worker ceiling).
    // A HashSet makes the retain step O(entries) amortized. Membership
    // testing is the only thing that changes: `entries.retain` still
    // walks the vector in place, so survivor order is preserved. Pre-size
    // to entries.len() (each purged entry contributes at most 2 keys —
    // itself plus its derived reverse companion — so this covers the
    // common case without reallocation).
    let mut drop_keys: std::collections::HashSet<crate::session::SessionKey> =
        std::collections::HashSet::with_capacity(entries.len());
    for entry in entries.iter() {
        let id = entry.decision.resolution.tunnel_endpoint_id;
        if id != 0 && purge_ids.contains(&id) {
            drop_keys.insert(entry.key.clone());
            if !entry.metadata.is_reverse {
                drop_keys.insert(crate::session::reverse_session_key(
                    &entry.key,
                    entry.decision.nat,
                ));
            }
        }
    }
    if !drop_keys.is_empty() {
        entries.retain(|entry| !drop_keys.contains(&entry.key));
    }
}

/// #1866 D3: log a WG endpoint-set transition between two forwarding
/// states. Silent when the set is unchanged (the common case) — fires
/// only on real add/remove/port/attachment changes, so the cadence is
/// state-transition-only per the logging rules.
pub(in crate::afxdp) fn log_wg_endpoint_set_transition(
    path: &str,
    old: &ForwardingState,
    new: &ForwardingState,
) {
    let old_set = wg_endpoint_set_summary(old);
    let new_set = wg_endpoint_set_summary(new);
    if old_set != new_set {
        eprintln!("xpf-userspace-dp: WG endpoint set changed ({path}): [{old_set}] => [{new_set}]");
    }
}

/// #3773 (M13): stable, order-independent summary of a fabric-skip set for
/// transition logging (`name:reason`, sorted). Empty when no fabric link was
/// skipped — the common healthy case.
fn fabric_skip_set_summary(skips: &[FabricLinkSkip]) -> String {
    let mut items: Vec<String> = skips
        .iter()
        .map(|s| format!("{}:{}", s.name, s.reason.as_str()))
        .collect();
    items.sort();
    items.join(", ")
}

/// #3773 (M13): log a fabric-skip-set transition between two forwarding
/// states, mirroring `log_wg_endpoint_set_transition`. Silent when the skip set
/// is unchanged (the common case, including the healthy empty=>empty), so a
/// PERSISTENTLY malformed/unresolved fabric logs ONCE when it first appears (or
/// changes reason) rather than on every 30s `SyncFabricState` refresh / route
/// churn `bump_fib` — state-transition cadence per the logging rules. Names
/// each skipped fabric and why, so an operator triaging a dead HA
/// cross-chassis path has a journal line instead of a silent skip. The
/// cumulative `FABRIC_LINK_SKIPPED_MALFORMED` / `FABRIC_LINK_UNRESOLVED_PEER`
/// atomics (status/Prometheus) quantify it in parallel.
pub(in crate::afxdp) fn log_fabric_skip_transition(
    path: &str,
    old: &[FabricLinkSkip],
    new: &[FabricLinkSkip],
) {
    let old_set = fabric_skip_set_summary(old);
    let new_set = fabric_skip_set_summary(new);
    if old_set != new_set {
        eprintln!(
            "xpf-userspace-dp: fabric skip set changed ({path}): [{old_set}] => [{new_set}]"
        );
    }
}

pub struct Coordinator {
    /// #7209: **the REFCOUNT is the guarantee, not the swap.** Do NOT simplify
    /// to a `Mutex<BpfMaps>` or a plain field — a mutex serialises access
    /// without extending any lifetime, and every test would still pass, because
    /// nothing reads these concurrently yet. Rationale on `BpfMaps` itself.
    /// #7209: the CELL is shared, not just its contents. A session-domain
    /// handle holds this same `Arc<ArcSwap<..>>`, so a `store` the coordinator
    /// makes is visible to a reader that took its handle before the store —
    /// which a cloned `ArcSwap` would not give.
    pub(crate) bpf_maps: Arc<ArcSwap<BpfMaps>>,
    pub(crate) slow_path: Option<Arc<SlowPathReinjector>>,
    pub(crate) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    /// #1881: GRE local-origin thread lifecycle entries keyed by
    /// tunnel_endpoint_id. Reconciled by the same three-pass shape as
    /// `wg_control_threads` (finished sweep → attachment-stale prune →
    /// spawn with backoff); content changes never restart a thread —
    /// the loop tracks the shared forwarding ArcSwap (plan D.1).
    pub(crate) tunnel_sources: BTreeMap<u16, LocalTunnelSourceEntry>,
    /// #1432 S2a / #1866: WG control-thread lifecycle entries keyed by
    /// tunnel_endpoint_id. Each entry records the engine Arc address +
    /// TUN attachment the thread was spawned with (so the apply-time
    /// stale prune detects identity AND attachment changes), survives
    /// thread exit as a tombstone carrying the respawn backoff stamp,
    /// and is removed only when the endpoint leaves the desired set.
    pub(crate) wg_control_threads: BTreeMap<u16, WgControlEntry>,
    pub(crate) last_slow_path_status: SlowPathStatus,
    /// #2408/#5801/#6097: the last snapshot slow-path MTU the day-2 reconcile
    /// ATTEMPTED on the live (preserved) reinjector. Since #5801 the reconcile
    /// reprograms the running TUN via `SIOCSIFMTU` rather than only warning, so
    /// this records reconcile ATTEMPTS, not warnings (renamed from
    /// `last_slow_path_mtu_warned`). It dedups the attempt to once per distinct
    /// desired value so a steady-state reconcile loop — or a persistently
    /// degraded TUN whose `live_mtu` never converges — does not re-issue the
    /// ioctl every tick; the next DISTINCT desired value retries.
    pub(crate) last_slow_path_mtu_reconciled: i32,
    /// #7209: the lock-free handle onto this coordinator's peer-synced session
    /// domain, handed to the session-socket thread so `sync_session` need not
    /// take the `ServerState` mutex.
    pub(crate) session_domain: crate::afxdp::SessionDomain,
    pub(in crate::afxdp) ha: HaState,
    pub(crate) cos: SharedCoSState,
    pub(crate) neighbors: NeighborManager,
    /// #7209: shared behind one `Arc` so a session-domain handle can hold the
    /// SAME manager the coordinator mutates through, rather than a snapshot of
    /// it. Every `SessionManager` method already takes `&self` — its maps are
    /// `Arc<Mutex<..>>` and its counters are atomics — so this needs no
    /// interior-mutability work and no per-counter `Arc`, which is what the
    /// abandoned `724ebb5bc` stack was reaching for six counters at a time.
    pub(in crate::afxdp) sessions: Arc<SessionManager>,
    /// #6471: node-shared live-IKE-exchange table backing the Stage-11
    /// established-vs-forged discriminator on the IPsec secondary path.
    /// Runtime state (NOT config): lives outside `ForwardingState` so a
    /// snapshot apply does not wipe the seeds, and outside `SessionManager`
    /// (it is IKE admission state, not an HA-synced session map). Shared
    /// with every packet worker (via `WorkerSharedDataplane`) and the GRE
    /// local-origin threads (via the tunnel-spawn site).
    pub(in crate::afxdp) ike_exchanges: crate::afxdp::forwarding::SharedIkeExchangeTable,
    /// #7699: the node-shared PPTP control-segment inbox. Why it is shared and
    /// not per-worker is on [`crate::session::pptp_control::PptpControlInbox`].
    pub(in crate::afxdp) pptp_control:
        std::sync::Arc<crate::session::pptp_control::PptpControlInbox>,
    pub(in crate::afxdp) workers: WorkerManager,
    pub(crate) mirror_targets: Arc<ArcSwap<MirrorTargetMap>>,
    pub(crate) forwarding: ForwardingState,
    pub(crate) policy_counters: PolicyCounterStore,
    /// #2218: per-rule NAT translation hit counters (SNAT/DNAT/static),
    /// owned alongside `policy_counters` and threaded into the
    /// forwarding-state build so parsed rules share its `Arc`s.
    pub(crate) nat_counters: crate::nat::NatCounterStore,
    pub(crate) recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
    pub(crate) recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    pub(crate) last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
    pub(crate) validation: ValidationState,
    pub(crate) reconcile_calls: u64,
    /// #2522: count of teardowns that paid the 500ms mlx5 zero-copy
    /// EBUSY quiesce. Bumped only when live workers were torn down AND a
    /// rebind follows (snapshot-apply path); the `no_snapshot` /
    /// shutdown teardown no longer pays (and no longer counts) it. This
    /// is an INTERNAL / test counter — it is read only by the #2522
    /// regression tests and is NOT wired to any gRPC / Prometheus /
    /// status surface. Wiring it into the status surface (a wire change)
    /// is a possible follow-up.
    pub(crate) reconcile_quiesce_count: u64,
    /// #8558: the per-slot TERMINAL bind-failure reasons from the most recent
    /// fail-closed worker bring-up, keyed by binding slot.
    ///
    /// It exists because the fail-closed teardown destroys the diagnostic that
    /// the recovery keyed on. `bring_up_workers`' `BindIncomplete` arm calls
    /// `stop_inner(false)`, which empties `workers.live`; `refresh_bindings`
    /// then routes every now-workerless slot through `zero_unbound_slot`, and
    /// that ends with `binding.last_error.clear()`. So the `"Device or resource
    /// busy"` a bind actually returned was gone from the status the Go manager
    /// polls, and `hasBusyBindingsWedgeLocked`'s `busyErr` term — a substring
    /// match on exactly that field — could never be true. Its only other route
    /// in, `repaired`, needs a forwarding-LIVE (`Ready`) binding, of which a
    /// fail-closed reconcile leaves none. Recovery for the fault it exists for
    /// was unreachable, silently, while looking alive.
    ///
    /// A one-shot restore into `bindings` would not have fixed it: EVERY
    /// control response runs `refresh_status` -> `refresh_bindings`, so the
    /// ~1 Hz status poll re-erased it within a second, and the Go predicate
    /// requires the wedge to persist 5s before firing. The cause therefore has
    /// to live somewhere the refresh READS, which is what this map is.
    ///
    /// LIFECYCLE — cleared by `stop_inner`, populated only by the
    /// `BindIncomplete` arm immediately after it:
    /// - every snapshot reconcile clears it in `tear_down` and repopulates only
    ///   if this bring-up fails, so it always describes the CURRENT state;
    /// - a `no_snapshot` / disarm / shutdown teardown clears it and never
    ///   repopulates, so a legitimately-unbound slot reports no error;
    /// - a PRE-teardown abort (integrity / mandatory-pin) does not reach
    ///   `stop_inner`, and correctly leaves the previous contents alone — the
    ///   prior workers are still running and the state did not move.
    ///
    /// It can never put an error on a HEALTHY slot: `refresh_bindings` consults
    /// it only on the branch where a slot has NO `live` entry, and a bound slot
    /// always has one.
    pub(crate) last_bind_failures: BTreeMap<u32, String>,
    /// #2522 test seam (per-instance, NOT a process-global): under
    /// `cfg(test)` `tear_down`'s quiesce records its requested duration
    /// here and skips the real `thread::sleep`, so each test asserts
    /// against its OWN coordinator with no cross-test race. Absent from
    /// release builds.
    #[cfg(test)]
    pub(crate) last_quiesce_ms: u64,
    /// #4952 test seam (per-instance, NOT a process-global): under
    /// `cfg(test)`, `bring_up_workers` treats a positive value as N forced
    /// worker-thread spawn failures — it declines to call
    /// `spawn_supervised_worker` and synthesizes the EAGAIN/ENOMEM
    /// `std::io::Error` a real `pthread_create` returns under resource
    /// exhaustion, decrementing the counter for each planned worker. This
    /// exercises the POST-TEARDOWN fail-closed propagation deterministically
    /// (a real spawn failure is not provokable in-process). Always 0 in
    /// release builds; per-instance so parallel tests never race.
    #[cfg(test)]
    pub(crate) force_worker_spawn_fail: u32,
    /// #5143 test seam: force the FIRST `force_worker_bind_incomplete` spawned
    /// workers to report an INCOMPLETE startup bound-slot set (a spawned
    /// worker whose in-thread XSK/UMEM bind failed for one or more planned
    /// bindings but keeps heartbeating). Instead of the real `worker_loop`
    /// (which cannot bind a real XSK in-process), a joinable STUB thread is
    /// spawned that reports a bound set MISSING one planned slot, then
    /// heartbeats until stopped — so the post-spawn readiness barrier's
    /// fail-close + stop/join is unit-verifiable. Distinct from
    /// `force_worker_spawn_fail` (which fails the spawn itself, pre-report).
    /// Always 0 in release builds; per-instance so parallel tests never race.
    #[cfg(test)]
    pub(crate) force_worker_bind_incomplete: u32,
    /// #6242 test seam: number of worker spawns to let SUCCEED before the
    /// `force_worker_spawn_fail` failure fires. `force_worker_spawn_fail` alone
    /// always fails the FIRST planned worker, so it cannot characterise
    /// PARTIAL-success rollback (workers `0..K-1` launched, worker `K` fails).
    /// With `force_worker_spawn_fail = 1` and `force_worker_spawn_fail_skip = K`
    /// the first `K` workers spawn and the `(K+1)`th fails — proving the #4952
    /// differential preserves the already-launched workers' records. Counts
    /// DOWN as workers are let through; the forced failure only fires once it
    /// reaches 0. Always 0 in release builds; per-instance.
    #[cfg(test)]
    pub(crate) force_worker_spawn_fail_skip: u32,
    /// #6242 test seam: when true, EVERY worker whose spawn is not force-failed
    /// launches a benign STUB thread (reports its FULL planned bound set so the
    /// readiness barrier passes, then heartbeats until stopped) instead of the
    /// real `worker_loop`, which cannot bind a real XSK in-process. Lets a
    /// MULTI-worker test drive partial-success spawn rollback without running
    /// the real dataplane body on the already-launched workers. Always false in
    /// release builds; per-instance.
    #[cfg(test)]
    pub(crate) force_worker_healthy_stub: bool,
    /// #5674 test seam (per-instance, NOT a process-global): when nonzero,
    /// `synced_import_cap()` returns TWICE this value (the override expresses a
    /// LOGICAL ceiling; `synced_import_cap()` doubles it) instead of the real
    /// `2 * worker_count * DEFAULT_MAX_SESSIONS` ENTRY ceiling. Lets a test
    /// exercise the synced-import admission boundary without inserting
    /// `DEFAULT_MAX_SESSIONS` (131072) entries. Always 0 in release builds
    /// (the field does not exist); per-instance so parallel tests never race.
    #[cfg(test)]
    /// #7209: SHARED with the session-domain handle, not copied. The six
    /// tests that set it do so on this struct after construction; a copied
    /// `usize` would leave the handle reading 0, so every cap assertion would
    /// silently measure the production formula instead of the override — a
    /// test seam that stops seaming without failing.
    pub(crate) synced_import_cap_override: Arc<std::sync::atomic::AtomicUsize>,
    /// #5166 test seam (per-instance, NOT a process-global): under
    /// `cfg(test)`, `refresh_runtime_snapshot_inner` records a clone of the
    /// `cos.owner_worker_by_queue` map here at the exact instant just before
    /// it makes the new `ForwardingState` worker-visible (the `ha.runtime`
    /// store). The ordering-regression test asserts this snapshot already
    /// reflects the new generation's queues — i.e. the CoS maps are published
    /// BEFORE forwarding. Reverting the #5166 reorder captures the stale map
    /// and the test goes RED. Absent from release builds; per-instance so
    /// parallel tests never race.
    #[cfg(test)]
    pub(crate) cos_owner_at_forwarding_publish: Option<BTreeMap<(i32, u8), u32>>,
    /// #6592 test seam (per-instance, NOT a process-global), inherited from
    /// the #6291 `validation_at_forwarding_publish` it replaces. Under
    /// `cfg(test)`, `publish_runtime_view` records the coordinator's INTENDED
    /// pair — `(self.validation, the ForwardingState it is about to publish)`
    /// — plus the still-worker-visible PREVIOUS `RuntimeView`, at the exact
    /// instant just before the view store.
    ///
    /// Two things are asserted from it (`coordinator/tests.rs`):
    /// - The intended pair EQUALS the pair a worker then observes. A publish
    ///   site that built its view from a stale validation (or that published
    ///   forwarding through some path other than this choke point) goes RED.
    /// - The retained previous view is NOT the post-publish view. That makes
    ///   the seam PROVE ITS OWN POSITION: hoisting the store above this
    ///   capture — which would let the first assert pass vacuously by reading
    ///   an already-published view — goes RED too. It retains an `Arc` rather
    ///   than a raw pointer deliberately: dropping it would let the next
    ///   `Arc::new` reuse the freed address and fool `ptr_eq`.
    ///
    /// Absent from release builds; per-instance so parallel tests never race.
    #[cfg(test)]
    pub(crate) runtime_view_at_publish: Option<(Arc<RuntimeView>, Arc<RuntimeView>)>,
    /// #6593: every worker-visible sibling structure that MUST be published
    /// before the runtime view, captured at the instant just before the view
    /// store. See `PrePublishSiblings` for the invariant and why it retains
    /// `Arc`s. Absent from release builds; per-instance so parallel tests
    /// never race.
    #[cfg(test)]
    pub(crate) prepublish_siblings: Option<PrePublishSiblings>,
    /// #6244: typed reconcile progress + failure identity. Replaces the
    /// former free-form `String` side-channel; the legacy operator string is
    /// rendered only at the `reconcile_debug` / `debug_reconcile_stage` wire
    /// boundary and inside `ReconcileError`'s `Display`. Written on the cold
    /// reconcile / status boundary, read at ~1 Hz status polls — never on the
    /// packet path.
    pub(crate) last_reconcile_stage: ReconcileStage,
    pub(crate) poll_mode: crate::PollMode,
    pub(crate) event_stream: Option<crate::event_stream::EventStreamSender>,
    pub(crate) cos_owner_worker_by_queue: BTreeMap<(i32, u8), u32>,
    /// Monotonic timestamp (secs) of the last HA flow cache flush (#312).
    pub(crate) last_cache_flush_at: Arc<AtomicU64>,
    /// Per-RG epoch counters for O(1) flow cache invalidation on demotion.
    /// Shared with all worker threads; bumped atomically on demotion/activation.
    pub(crate) rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
    // #6242: the former horizontal per-worker owners `worker_panics` (#925),
    // `worker_exception_rings` and `worker_last_resolution` (#5289) — three
    // `BTreeMap<u32, Arc<...>>` keyed by `worker_id` in parallel with
    // `WorkerManager.handles` — are consolidated into
    // `WorkerManager.records: BTreeMap<u32, WorkerRuntimeRecord>`. One worker's
    // panic slot + exception ring + last-resolution slot now live on its
    // record (`rec.panic` / `rec.exception_ring` / `rec.last_resolution`),
    // registered and rolled back as a single unit alongside its handle.
}

impl Coordinator {
    pub fn new() -> Self {
        // #7209: the shared parts are bound to locals first so the
        // session-domain handle can be built from the SAME values the struct
        // takes. Building it here rather than on demand is what makes it a
        // handle onto live state: none of these six is ever REASSIGNED on the
        // coordinator (checked — zero `self.<field> = ` sites for each), only
        // mutated through its own interior synchronization, so a handle taken
        // at construction observes every later change.
        let bpf_maps = Arc::new(ArcSwap::from_pointee(BpfMaps::default()));
        let ha = HaState::new();
        let neighbors = NeighborManager::new();
        let sessions = Arc::new(SessionManager::new());
        let workers = WorkerManager::new();
        #[cfg(test)]
        let synced_import_cap_override = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let session_domain = crate::afxdp::SessionDomain::new(
            &sessions,
            &workers,
            &ha,
            &neighbors,
            &bpf_maps,
            #[cfg(test)]
            &synced_import_cap_override,
        );
        Self {
            session_domain,
            bpf_maps,
            slow_path: None,
            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            tunnel_sources: BTreeMap::new(),
            wg_control_threads: BTreeMap::new(),
            last_slow_path_status: SlowPathStatus::default(),
            last_slow_path_mtu_reconciled: 0,
            ha,
            cos: SharedCoSState::new(),
            neighbors,
            sessions,
            ike_exchanges: Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new()),
            pptp_control: Arc::new(crate::session::pptp_control::PptpControlInbox::default()),
            workers,
            mirror_targets: Arc::new(ArcSwap::from_pointee(MirrorTargetMap::default())),
            forwarding: ForwardingState::default(),
            policy_counters: PolicyCounterStore::default(),
            nat_counters: crate::nat::NatCounterStore::default(),
            recent_exceptions: Arc::new(Mutex::new(ExceptionEventRing::new())),
            recent_session_deltas: Arc::new(Mutex::new(VecDeque::with_capacity(
                MAX_RECENT_SESSION_DELTAS,
            ))),
            last_resolution: Arc::new(Mutex::new(None)),
            validation: ValidationState::default(),
            reconcile_calls: 0,
            reconcile_quiesce_count: 0,
            last_bind_failures: BTreeMap::new(),
            #[cfg(test)]
            last_quiesce_ms: 0,
            #[cfg(test)]
            force_worker_spawn_fail: 0,
            #[cfg(test)]
            force_worker_bind_incomplete: 0,
            #[cfg(test)]
            force_worker_spawn_fail_skip: 0,
            #[cfg(test)]
            force_worker_healthy_stub: false,
            #[cfg(test)]
            synced_import_cap_override: Arc::clone(&synced_import_cap_override),
            #[cfg(test)]
            cos_owner_at_forwarding_publish: None,
            #[cfg(test)]
            runtime_view_at_publish: None,
            #[cfg(test)]
            prepublish_siblings: None,
            last_reconcile_stage: ReconcileStage::Idle,
            poll_mode: crate::PollMode::BusyPoll,
            event_stream: None,
            cos_owner_worker_by_queue: BTreeMap::new(),
            last_cache_flush_at: Arc::new(AtomicU64::new(0)),
            rg_epochs: Arc::new(std::array::from_fn(|_| AtomicU32::new(0))),
            // #6242: per-worker panic / exception-ring / last-resolution slots
            // now live on `WorkerManager.records` (initialised by
            // `WorkerManager::new`), not on three sibling Coordinator maps.
        }
    }

    pub fn stop(&mut self) {
        self.stop_inner(true);
        // #6244: an explicit stop records the terminal lifecycle stage (the
        // "stopped" write moved out of `stop_inner`, which is also called
        // mid-reconcile where the caller sets its own stage).
        self.last_reconcile_stage = ReconcileStage::Stopped;
        // NOTE: Do NOT tear down event_stream here. The event stream must
        // survive across XSK bind/unbind cycles (e.g. when forwarding_armed
        // is temporarily false during startup). Use stop_with_event_stream()
        // for final process shutdown.
    }

    /// Full shutdown including the event stream. Called only on process exit.
    pub fn stop_with_event_stream(&mut self) {
        self.stop_inner(true);
        // #6244: explicit stop -> terminal lifecycle stage (see `stop`).
        self.last_reconcile_stage = ReconcileStage::Stopped;
        if let Some(mut es) = self.event_stream.take() {
            es.stop();
        }
    }

    /// Start the event stream sender. The I/O thread connects to the daemon
    /// listener at `socket_path` and pushes binary-framed session events.
    pub fn start_event_stream(&mut self, socket_path: &str) {
        self.event_stream = Some(crate::event_stream::EventStreamSender::new(socket_path));
    }

    /// Get a lightweight handle for worker threads to push events.
    pub fn event_stream_worker_handle(
        &self,
    ) -> Option<crate::event_stream::EventStreamWorkerHandle> {
        self.event_stream.as_ref().map(|es| es.worker_handle())
    }

    /// Event stream statistics for status reporting.
    pub fn event_stream_stats(&self) -> Option<crate::event_stream::EventStreamStats> {
        self.event_stream.as_ref().map(|es| es.stats())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn dynamic_neighbors_ref(&self) -> &Arc<ShardedNeighborMap> {
        &self.neighbors.dynamic
    }

    /// #919: zone name → ID lookup, used by main.rs's
    /// `build_synced_session_entry` to translate legacy
    /// `SessionSyncRequest.ingress_zone` strings to u16 IDs when
    /// older peers don't populate the new ID fields.
    /// #7209: the session-domain handle — a cloneable, lock-free view of
    /// everything the peer-synced import path touches.
    ///
    /// Handed to the session-socket thread at startup so `sync_session` is
    /// served without the `ServerState` mutex, which `apply_snapshot` holds
    /// across a 10 s readiness barrier, a 500 ms teardown quiesce, worker
    /// `join()`s and BPF map-pin opens — past the 3 s round-trip budget Go
    /// gives it, and #5380 aborts the rest of a bulk batch on the first such
    /// failure.
    #[inline]
    pub(crate) fn session_domain(&self) -> &crate::afxdp::SessionDomain {
        &self.session_domain
    }

    /// #7209: the peer-synced import verbs, delegated to the session-domain
    /// handle that now owns them.
    ///
    /// These are thin on purpose. The implementations moved to `SessionDomain`
    /// so the session socket can drive them without the `ServerState` mutex;
    /// keeping the coordinator's own surface pointed at the SAME code — rather
    /// than leaving a second copy behind — is what stops the 87 existing call
    /// sites from quietly becoming tests of a decommissioned path.
    pub fn upsert_synced_session(
        &self,
        entry: crate::afxdp::SyncedSessionEntry,
    ) -> crate::afxdp::SyncedImportOutcome {
        self.session_domain.upsert_synced_session(entry)
    }

    /// See [`Coordinator::upsert_synced_session`].
    pub fn synced_session_contains(&self, key: &crate::session::SessionKey) -> bool {
        self.session_domain.synced_session_contains(key)
    }

    /// See [`Coordinator::upsert_synced_session`].
    pub fn delete_synced_session(&self, key: crate::session::SessionKey) {
        self.session_domain.delete_synced_session(key)
    }

    /// See [`Coordinator::upsert_synced_session`].
    pub fn delete_synced_session_gen(&self, key: crate::session::SessionKey, delete_gen: u64) {
        self.session_domain.delete_synced_session_gen(key, delete_gen)
    }

    /// See [`Coordinator::upsert_synced_session`].
    pub(in crate::afxdp) fn synced_import_cap_for(
        &self,
        records: &BTreeMap<u32, Arc<WorkerRuntimeRecord>>,
    ) -> usize {
        self.session_domain.synced_import_cap_for(records)
    }

    /// See [`Coordinator::upsert_synced_session`].
    #[cfg(test)]
    pub(crate) fn test_install_local_forward_session(&self, idx: u16) {
        self.session_domain.test_install_local_forward_session(idx)
    }

    pub fn zone_name_to_id_ref(&self) -> &FastMap<String, u16> {
        &self.forwarding.zone_name_to_id
    }

    /// Apply an authoritative manager-neighbor push from the Go control
    /// plane. Returns `true` if the push was applied, `false` if it was
    /// FENCED as a stale / reordered replace (#6034).
    ///
    /// `generation` is the monotonically increasing replace generation the
    /// Go manager stamps on each `update_neighbors` message. When non-zero,
    /// a replace whose generation is <= the last applied one is rejected
    /// WITHOUT touching the table — this guards against an out-of-order or
    /// duplicated delivery clobbering a newer table (defense-in-depth; the
    /// synchronous single control socket does not itself reorder). A
    /// generation of 0 means an unversioned (pre-#6034) sender and is always
    /// applied without advancing the fence, for backward compatibility.
    pub fn apply_manager_neighbors(
        &mut self,
        replace: bool,
        generation: u64,
        neighbors: &[(i32, IpAddr, NeighborEntry)],
    ) -> bool {
        // #6034: replace-generation fence. Reject a stale / reordered
        // authoritative replace before mutating any neighbor state.
        if generation != 0
            && generation
                <= self
                    .neighbors
                    .applied_manager_generation
                    .load(Ordering::Acquire)
        {
            return false;
        }
        let old_manager_keys = if replace {
            self.neighbors
                .manager_keys
                .lock()
                .map(|manager_keys| manager_keys.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            if replace {
                manager_keys.clear();
            }
            for (ifindex, ip, _) in neighbors {
                manager_keys.insert((*ifindex, *ip));
            }
        }
        // #949: replace + insert under a single bulk acquisition so
        // readers see either the pre-replace or post-replace state,
        // never a half-replaced set. `bulk_replace_neighbors` locks all
        // 64 shards in shard-index order (deadlock-free invariant).
        // #3048: it also bumps `mac_change_epoch` when this Go-snapshot
        // push REPLACES a neighbor's MAC with a different one (the
        // fourth neighbor-MAC write path — the in-process monitor, the
        // data-path learn, and the on-demand resolver are the other
        // three). `old_manager_keys` is empty when `!replace`, so the
        // removes are skipped exactly as before.
        self.neighbors
            .dynamic
            .bulk_replace_neighbors(&old_manager_keys, neighbors);
        if replace {
            for key in &old_manager_keys {
                self.forwarding.neighbors.remove(key);
            }
        }
        for (ifindex, ip, entry) in neighbors {
            self.forwarding.neighbors.insert((*ifindex, *ip), *entry);
        }
        if replace || !neighbors.is_empty() {
            // Clone the full ForwardingState to publish neighbor changes.
            // This copies routes/policies too, but update_neighbors fires
            // infrequently (only when kernel ARP/NDP changes, gated by
            // neighborsEqual in the Go manager). The clone cost is
            // negligible vs packet processing.
            //
            // #6592: published through the one choke point, so the neighbor
            // update carries the CURRENT validation rather than leaving a
            // second, independently-ordered store to get right.
            self.publish_runtime_view();
        }
        self.neighbors.generation.fetch_add(1, Ordering::Relaxed);
        // #6034: advance the applied replace generation so a later stale /
        // reordered replace is fenced. Only versioned pushes move it.
        if generation != 0 {
            self.neighbors
                .applied_manager_generation
                .store(generation, Ordering::Release);
        }
        true
    }

    pub(crate) fn stop_inner(&mut self, clear_synced_state: bool) {
        // #5165: signal AND JOIN the neighbor monitor before any downstream
        // teardown clears/rebuilds the shared neighbor map. The bare stop store
        // (pre-#5165) left the monitor detached: a retired old-generation
        // monitor blocked in recv() could apply a queued kernel event to
        // `dynamic` after a fresh baseline repopulated it. Joining (bounded by
        // the monitor's 500ms SO_RCVTIMEO) is the real no-mutation-after-stop
        // guard, mirroring the resolver join below.
        self.neighbors.stop_and_join_monitor();
        // #1636 / #6314: stop the neighbor warmer, drop the producer handle so
        // the worker's recv side disconnects, and JOIN it — mirroring the
        // monitor (above) and resolver (below) siblings. Signalling + dropping
        // the queue alone left the warmer detached (the pre-#5165 odd-one-out):
        // a warmer blocked in recv_timeout could fire one stray ARP/NDP solicit
        // or mutate `last_probed_at` after this teardown cleared the dataplane.
        // Joining (bounded by the warmer's 500ms recv timeout) is the real
        // no-mutation-after-stop guard.
        self.neighbors.stop_and_join_warmer();
        // #1769: stop the on-demand resolver. Signal stop, drop the
        // producer handle so the recv side disconnects promptly, then
        // JOIN the worker before returning. Joining (not just signalling)
        // is what enforces no-mutation-after-stop: a detached resolver
        // blocked in its GET could otherwise insert/remove on
        // dynamic_neighbors after a subsequent reconcile spawned a fresh
        // resolver. Join latency is bounded by the 500ms recv timeout +
        // the 200ms GET timeout, well under TimeoutStopSec.
        if let Some(resolver_stop) = self.neighbors.resolver_stop.take() {
            resolver_stop.store(true, Ordering::Relaxed);
        }
        self.neighbors.resolver = None;
        if let Some(join) = self.neighbors.resolver_join.take() {
            let _ = join.join();
        }
        // Note: the resolver is joined here BEFORE workers.stop_and_clear
        // below, so a worker still running during teardown could observe
        // the resolver thread gone and `try_send` into a consumer-dropped
        // channel. That is harmless: enqueue is non-blocking and a failed
        // send is counted as enqueue_drops/disconnected, never blocks the
        // worker, and the resolver thread is provably gone so no stale
        // mutation can occur. The next reconcile spawns a fresh resolver
        // and re-installs the handle on every worker.
        // #1881: entries may be tombstones (`handle == None`); stop
        // then join live handles, clear everything (tombstones too —
        // after a stop the next reconcile re-legitimates entries).
        for entry in self.tunnel_sources.values_mut() {
            if let Some(handle) = entry.handle.as_ref() {
                handle.request_stop();
            }
        }
        for entry in self.tunnel_sources.values_mut() {
            if let Some(handle) = entry.handle.as_mut() {
                if let Some(join) = handle.join.take() {
                    let _ = join.join();
                }
            }
        }
        self.tunnel_sources.clear();
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
        // #1432 S2a: stop + join WG control threads. The persistent wgN
        // TUN is owned by the Go control plane and intentionally NOT
        // torn down here (it must survive a reload — AGY r3 Hazard B).
        // #1866: tombstones are cleared too — after a stop the next
        // reconcile re-legitimates entries from a coherent snapshot.
        for entry in self.wg_control_threads.values_mut() {
            if let Some(handle) = entry.handle.as_ref() {
                handle.request_stop();
            }
        }
        for entry in self.wg_control_threads.values_mut() {
            if let Some(handle) = entry.handle.as_mut() {
                if let Some(join) = handle.join.take() {
                    let _ = join.join();
                }
            }
        }
        self.wg_control_threads.clear();
        // #7092: reclaim the outgoing generation's NAT holder bits BEFORE
        // `stop_and_clear` drops the records — after it the ids are gone and
        // nothing can name them again. Why all ids, and why this is not the
        // `dead`-keyed sweep, is on `retire_all_worker_holders`.
        self.retire_all_worker_holders();
        // #7209: ONE load bound to a local — two loads could straddle a store
        // and mix generations, and the local keeps the fds alive for the call.
        let maps = self.bpf_maps.load();
        self.workers.stop_and_clear(
            maps.map_fd.as_ref(),
            maps.heartbeat_map_fd.as_ref(),
        );
        // #8558: the recorded bind-failure causes describe the worker set that
        // was just stopped, so they die with it. Clearing HERE rather than at
        // the top of `reconcile` is what covers the teardowns that never enter
        // `reconcile` at all — `Coordinator::stop` (the disarm /
        // `reconcile_status_bindings` no-forwarding branch) and the
        // `no_snapshot` shutdown path — so a legitimately-unbound slot never
        // reports the previous generation's bind error. The `BindIncomplete`
        // arm repopulates it immediately AFTER calling `stop_inner`, which is
        // the only ordering that leaves the causes standing.
        self.last_bind_failures.clear();
        self.mirror_targets
            .store(Arc::new(MirrorTargetMap::default()));
        // #6242: the per-worker panic slots (#925) + exception rings +
        // last-resolution slots (#5289) are dropped by `stop_and_clear` above
        // as part of the teardown's record publish (#7209 `clear_records`,
        // formerly `records.clear()`) — one drop per worker record, not three
        // separate `Coordinator.*.clear()` calls followed by the dead
        // content-clear loops the old layout ran (see below).
        self.cos_owner_worker_by_queue.clear();
        self.cos
            .owner_worker_by_queue
            .store(Arc::new(BTreeMap::new()));
        self.cos
            .owner_live_by_queue
            .store(Arc::new(BTreeMap::new()));
        self.cos.root_leases.store(Arc::new(BTreeMap::new()));
        self.cos.exact_backlogs.store(Arc::new(BTreeMap::new()));
        self.cos.queue_leases.store(Arc::new(BTreeMap::new()));
        self.cos.queue_vtime_floors.store(Arc::new(BTreeMap::new()));
        self.last_slow_path_status = self
            .slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_default();
        self.slow_path = None;
        // #7209: ONE store of the whole set; the previous set's fds close when
        // the last holder releases (see `BpfMaps`). With no readers this is
        // identical to the seven field assignments it replaces.
        self.bpf_maps.store(Arc::new(BpfMaps::default()));
        self.forwarding = ForwardingState::default();
        // #6592: reset BOTH halves before the single worker-visible publish.
        // `self.validation` was defaulted further down pre-#6592 — after the
        // old `shared_validation` / `ha.forwarding` stores — which was
        // harmless while the two were independent Arcs stored with explicit
        // values, but would now publish a default forwarding paired with the
        // OUTGOING validation. `self.workers.stop_and_clear(...)` above has
        // already joined every worker thread so this teardown has no live
        // readers either way; publishing the coherent default pair keeps the
        // "every published view is the intended pair" invariant true at every
        // site, including this one.
        self.validation = ValidationState::default();
        // Publishing through the choke point clones `self.forwarding`, which the
        // line above just defaulted — ~20 empty-collection clones rather than a
        // direct `RuntimeView::default()` construction. Semantically identical
        // and teardown-only (once per stop / reconcile), so the uniformity of
        // one publish path is worth more here than skipping a handful of empty
        // `Vec::new`s.
        self.publish_runtime_view();
        self.ha.fabrics.store(Arc::new(Vec::new()));
        self.neighbors.generation.store(0, Ordering::Relaxed);
        // #949: clear all shards atomically vs readers.
        self.neighbors.dynamic.with_all_shards(|bulk| {
            for shard in bulk.each_shard_mut() {
                shard.clear();
            }
        });
        if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            manager_keys.clear();
        }
        // #1636: reset warmer rate-limit + telemetry so a re-bind starts
        // clean. The worker thread itself is torn down above; a fresh one
        // is spawned on the next bring-up.
        if let Ok(mut probed) = self.neighbors.last_probed_at.lock() {
            probed.clear();
        }
        self.neighbors
            .last_warm_sweep_ns
            .store(0, Ordering::Relaxed);
        self.neighbors
            .warned_disconnect
            .store(false, Ordering::Relaxed);
        if clear_synced_state {
            // #6653: RECOVERING locks. `if let Ok(..)` SKIPS a poisoned map,
            // so a teardown crossing a contained worker panic left some
            // surfaces full and others empty — a torn state no later code is
            // written to expect. On the next start, lookups resolve stale
            // sessions and the survivors still count toward the #5674
            // aggregate admission ceiling, refusing legitimate imports. A
            // teardown must leave every surface empty, poisoned or not.
            lock_shared_recover(&self.sessions.synced).clear();
            lock_shared_recover(&self.sessions.nat).clear();
            lock_shared_recover(&self.sessions.forward_wire).clear();
            self.sessions.owner_rg_indexes.clear();
        }
        if let Ok(mut recent) = self.recent_exceptions.lock() {
            recent.clear();
        }
        // #6242: the pre-#6242 layout ALSO ran two per-worker content-clear
        // loops here (`worker_exception_rings` / `worker_last_resolution`
        // `.lock().clear()`), but `stop_and_clear` above already emptied the
        // maps via `.clear()`, so those loops iterated an empty map and never
        // executed a body — dead since #5289. Dropping each record's ring +
        // slot `Arc` dropped by the teardown's record publish (#7209
        // `clear_records`) frees the underlying storage; there
        // is nothing left to content-clear. The loops are removed, not
        // duplicated onto `records`.
        if let Ok(mut recent) = self.recent_session_deltas.lock() {
            recent.clear();
        }
        if let Ok(mut last) = self.last_resolution.lock() {
            *last = None;
        }
        // #6592: `self.validation` is defaulted ABOVE, immediately before the
        // `publish_runtime_view` teardown store, so the published pair is
        // coherent. It used to be reset here.
        self.workers.last_planned_workers = 0;
        self.workers.last_planned_bindings = 0;
        self.workers.last_planned_worker_slots = 0;
        // #6244: `stop_inner` no longer writes `last_reconcile_stage`. It is
        // called mid-reconcile by `tear_down` (which then records its own
        // progress) and by the bring-up fail-closed path (which records the
        // preserved failure identity right after) — in both the "stopped"
        // write was a transient the caller immediately overwrote, and in
        // bring-up it forced an overwrite-then-restore dance. An EXPLICIT stop
        // records `ReconcileStage::Stopped` in `stop` / `stop_with_event_stream`
        // instead, so a terminal failure identity is never clobbered by a
        // teardown that is part of the same reconcile attempt.
    }

    /// Snapshot the committed shared sessions so a reconcile can replay them
    /// after the workers are replaced.
    ///
    /// #6652: RECOVERING lock. This was `.lock().map(..).unwrap_or_default()`,
    /// so a poisoned mutex yielded an EMPTY vector — which the reconcile path
    /// then preserved as "the sessions to bring back", replaying nothing while
    /// the shared map still held them. Whether a reconcile preserved state
    /// depended on which thread happened to lock first, because every other
    /// shared-session path CLEARS the poison; that nondeterminism is the
    /// defect, not merely the empty result.
    pub(crate) fn snapshot_shared_session_entries(&self) -> Vec<SyncedSessionEntry> {
        lock_shared_recover(&self.sessions.synced)
            .values()
            .cloned()
            .collect()
    }

    /// #7209 item 1 (shape ii): rebuild each replayed forward entry's reverse
    /// companion under the LIVE forwarding table, repair the stored one, and
    /// return the repairs keyed by companion key.
    ///
    /// WHY THE REPLAY IS THE RIGHT PLACE. The companion is synthesized at IMPORT
    /// time from `Coordinator.forwarding`, and
    /// `synthesized_synced_reverse_entry` has exactly one early return — on
    /// `is_reverse`. There is no forwarding-dependent `None` arm, so an import
    /// taken while that table cannot resolve the reply path does not degrade
    /// gracefully: it publishes a companion carrying `NoRoute`, ifindex 0 and
    /// owner RG 0 into all four shared surfaces, and into the kernel session map
    /// whenever the local-replace guard holds.
    ///
    /// Nothing re-derived it. The replay republished `entry.decision` verbatim,
    /// and the only mechanism that ever rebuilt a companion was
    /// `prewarm_reverse_synced_sessions_for_owner_rgs` at RG ACTIVATION — which
    /// a mid-life `apply_snapshot` on an already-active node never reaches. So
    /// the wrong reply-path row was permanent for any node that did not
    /// subsequently fail over.
    ///
    /// `reconcile` reaches the replay AFTER `snapshot::apply_snapshot` has
    /// assigned `coord.forwarding = new_forwarding`, so the table read here is
    /// the new generation's, not the emptied one `stop_inner` left. That
    /// ordering is what makes the replay a repair point at all, and it is why
    /// this is the same shape #8171 established for the entries themselves.
    ///
    /// Scoped to peer-synced and shared-promoted forwards, mirroring
    /// `prewarm_reverse_synced_sessions_for_owner_rgs`'s own
    /// `allow_reverse_prewarm` gate — a locally-originated entry's companion is
    /// not this path's to rebuild.
    ///
    /// Only an ACTUAL disagreement is repaired and counted. A steady-state
    /// reconcile re-derives the identical value for every companion, so counting
    /// unconditionally would make the metric a function of how often the box
    /// reconciles rather than of how often a companion was built from a table
    /// that could not answer.
    fn rederived_reverse_companions(
        &self,
        entries: &[SyncedSessionEntry],
    ) -> FastMap<SessionKey, SyncedSessionEntry> {
        let ha_state = self.ha.rg_runtime.load();
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let mut fresh_by_key: FastMap<SessionKey, SyncedSessionEntry> = FastMap::default();
        for entry in entries {
            if entry.metadata.is_reverse {
                continue;
            }
            if !(entry.origin.is_peer_synced()
                || matches!(entry.origin, SessionOrigin::SharedPromote))
            {
                continue;
            }
            if let Some(reverse) = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
                &self.forwarding,
                ha_state.as_ref(),
                self.dynamic_neighbors_ref(),
                entry,
                now_secs,
            ) {
                fresh_by_key.insert(reverse.key.clone(), reverse);
            }
        }
        let mut repairs: FastMap<SessionKey, SyncedSessionEntry> = FastMap::default();
        let mut repaired = 0u64;
        for entry in entries {
            if !entry.metadata.is_reverse {
                continue;
            }
            let Some(fresh) = fresh_by_key.get(&entry.key) else {
                continue;
            };
            if entry.decision == fresh.decision
                && entry.metadata.owner_rg_id == fresh.metadata.owner_rg_id
            {
                continue;
            }
            crate::afxdp::shared_ops::publish_shared_session(
                &self.sessions.synced,
                &self.sessions.nat,
                &self.sessions.forward_wire,
                &self.sessions.owner_rg_indexes,
                fresh,
            );
            repairs.insert(fresh.key.clone(), fresh.clone());
            repaired += 1;
        }
        if repaired > 0 {
            self.sessions
                .synced_reverse_rederived
                .fetch_add(repaired, Ordering::Relaxed);
        }
        repairs
    }

    pub(crate) fn replay_synced_sessions(
        &self,
        entries: &[SyncedSessionEntry],
        worker_command_queues: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
        session_map_fd: c_int,
    ) -> usize {
        if entries.is_empty() {
            return 0;
        }
        let worker_queues = worker_command_queues.values().cloned().collect::<Vec<_>>();
        // #7209 item 1 (shape ii): rebuild each forward entry's reverse
        // companion under the LIVE tables before anything is published, so a
        // companion synthesized from a forwarding table that could not resolve
        // the reply path is repaired here rather than replayed verbatim.
        //
        // DELIBERATELY IN THIS FUNCTION rather than in `replay_preserved_
        // sessions`, which is where the first draft put it. That wrapper is the
        // only production caller today, so both placements are correct for
        // production — but this is the choke point every replay goes through,
        // and putting the repair in the wrapper left the cell that drives THIS
        // function unable to observe it. A guard that cannot see the mechanism
        // it names is not a guard on it.
        let rebuilt = self.rederived_reverse_companions(entries);
        for entry in entries {
            // A repaired companion is what gets published and fanned out; the
            // stored one is also corrected in the shared map, which is the
            // authority a later prewarm, export or replay reads. Repairing only
            // one of the two would leave the stale value to be re-adopted.
            let entry = rebuilt.get(&entry.key).unwrap_or(entry);
            // #1789: a failed replay publish silently loses an arbitrary
            // prefix of synced state after reconcile (was `let _ =`). No
            // binding context here — shared counter.
            if publish_live_session_entry(
                session_map_fd,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
            )
            .is_err()
            {
                SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
            replicate_session_upsert(&worker_queues, entry);
        }
        entries.len()
    }

    /// #1636 option C: proactive neighbor warm at config-apply.
    ///
    /// Walks the current forwarding state's configured next-hops (static
    /// + dynamic routes, fabric peers) and enqueues a warm probe for each
    /// `(egress_ifindex, hop)` that is NOT already resolved, NOT recently
    /// probed, and whose owning RG is currently forwarding-active on this
    /// node. The warmer worker fires the probes off the coordinator hot
    /// path.
    ///
    /// `force = true` bypasses the 1s snapshot-level rate-limit (used by
    /// the RG-promote path so a newly-active RG gets warmed immediately
    /// without waiting for the next snapshot apply). Per-key 5s
    /// rate-limit and per-RG gate always apply.
    ///
    /// Takes `&self` (not `&mut self`): `last_warm_sweep_ns` and
    /// `warm_generation` are atomics so this can be called from both
    /// `refresh_runtime_snapshot` (`&mut self`) and the RG-promote path.
    pub(in crate::afxdp) fn queue_warm_pass(&self, force: bool) {
        // Nothing to do until the warmer worker is spawned.
        let Some(tx) = self.neighbors.warm_queue.as_ref() else {
            return;
        };
        let now = monotonic_nanos();
        if !force {
            let last = self.neighbors.last_warm_sweep_ns.load(Ordering::Acquire);
            if now.saturating_sub(last) < WARM_SWEEP_RATE_LIMIT_NS {
                return;
            }
            // CAS to claim the sweep slot; if another caller raced us,
            // let them run the sweep.
            if self
                .neighbors
                .last_warm_sweep_ns
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }
        } else {
            self.neighbors
                .last_warm_sweep_ns
                .store(now, Ordering::Release);
        }

        // Generation bump only on ADMITTED sweeps. In-flight items from
        // prior generations are dropped on dequeue by the warmer worker.
        let sweep_gen = self
            .neighbors
            .warm_generation
            .fetch_add(1, Ordering::Release)
            + 1;

        let snapshot = &self.forwarding;
        let rg_runtime = self.ha.rg_runtime.load();
        let now_secs = now / 1_000_000_000;
        let mut seen: FastSet<(i32, IpAddr)> = FastSet::default();

        let mut enqueue = |egress_ifindex: i32, hop: IpAddr| {
            if egress_ifindex <= 0 {
                return;
            }
            // Never warm broadcast/multicast/loopback/unspecified.
            match hop {
                IpAddr::V4(v4) => {
                    if v4.is_unspecified()
                        || v4.is_loopback()
                        || v4.is_multicast()
                        || v4.is_broadcast()
                    {
                        return;
                    }
                }
                IpAddr::V6(v6) => {
                    if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                        return;
                    }
                }
            }
            let key = (egress_ifindex, hop);
            if !seen.insert(key) {
                return;
            }
            // Already resolved (static/manager neighbor or dynamic cache)?
            if snapshot.neighbors.contains_key(&key) || self.neighbors.dynamic.contains_key(&key) {
                return;
            }
            // Per-RG HA gate: only warm next-hops whose owning RG is
            // forwarding-active on this node. Standby RGs are skipped.
            let rg_id = owner_rg_for_flow(snapshot, egress_ifindex);
            let rg_active = rg_runtime
                .get(&rg_id)
                .map(|group| group.is_forwarding_active(now_secs))
                .unwrap_or(false);
            if !rg_active {
                return;
            }
            let Some(name) = snapshot.ifindex_to_name.get(&egress_ifindex) else {
                return;
            };
            let item = WarmItem {
                ifindex: egress_ifindex,
                hop,
                iface_name: name.clone(),
                generation: sweep_gen,
                rg_id,
            };
            match tx.try_send(item) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    self.neighbors.warm_drops.fetch_add(1, Ordering::Relaxed);
                    #[cfg(feature = "debug-log")]
                    eprintln!(
                        "xpf-userspace-dp: warm queue full (cap={}); dropping {:?}",
                        WARM_QUEUE_DEPTH, key
                    );
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.neighbors
                        .warm_disconnected
                        .fetch_add(1, Ordering::Relaxed);
                    // Once-only operator-visible log (not debug-gated):
                    // under route churn this would otherwise fire per key.
                    if !self
                        .neighbors
                        .warned_disconnect
                        .swap(true, Ordering::Relaxed)
                    {
                        eprintln!(
                            "xpf-userspace-dp: ERROR: neighbor warmer worker disconnected; \
                             proactive neighbor warming is DISABLED until restart"
                        );
                    }
                }
            }
        };

        // Static + dynamic (FRR-populated) route next-hops, both families.
        // Tunnel routes (tunnel_endpoint_id != 0) are skipped: their HA
        // ownership is the tunnel endpoint's RG, not the underlay egress
        // RG (forwarding uses owner_rg_for_resolution, which switches on
        // tunnel_endpoint_id) — gating them via owner_rg_for_flow(egress)
        // here would warm on the wrong RG (Codex r1 High #1). Tunnel
        // endpoints are also explicitly out of warm scope per the plan
        // (AGY plan r1 #3); their underlay next-hops, if relevant, appear
        // as ordinary (tunnel_endpoint_id == 0) routes.
        // #2389: warm EVERY equal-cost next-hop's neighbor (not just the
        // first), so a multipath route's alternate paths are pre-resolved
        // and selectable on the hot path.
        for routes in snapshot.routes_v4.values() {
            for route in routes {
                for nh in &route.next_hops {
                    if nh.tunnel_endpoint_id != 0 {
                        continue;
                    }
                    if let Some(hop) = nh.next_hop {
                        enqueue(nh.ifindex, IpAddr::V4(hop));
                    }
                }
            }
        }
        for routes in snapshot.routes_v6.values() {
            for route in routes {
                for nh in &route.next_hops {
                    if nh.tunnel_endpoint_id != 0 {
                        continue;
                    }
                    if let Some(hop) = nh.next_hop {
                        enqueue(nh.ifindex, IpAddr::V6(hop));
                    }
                }
            }
        }
        // Fabric peers: warm the peer over the fabric parent ifindex
        // (AGY r7 #3 — FabricLink.parent_ifindex is the egress ifindex).
        for fabric in &snapshot.fabrics {
            enqueue(fabric.parent_ifindex, fabric.peer_addr);
        }
    }

    /// #1636: called from the cluster RG-promote path when an RG
    /// transitions to forwarding-active on this node. Clears the
    /// per-key rate-limit (so probes that failed during the transient
    /// down state are not locked out for 5s) and triggers an immediate
    /// forced warm pass for the newly-active RG's next-hops.
    pub(in crate::afxdp) fn on_rg_promote_active(&self) {
        if let Ok(mut map) = self.neighbors.last_probed_at.lock() {
            map.clear();
        }
        self.queue_warm_pass(true);
    }

    // NOTE (#1636): a per-ifindex `last_probed_at` clear on link-UP was
    // specified in the plan (AGY plan r3 #3) to drop probes fired during
    // a link-negotiation window. It is NOT wired here: there is no
    // userspace link-state (RTM_NEWLINK) monitor to call it from, and the
    // RG-promote clear already covers the dominant failover case. Shipping
    // an unwired helper would be a false guarantee (Copilot r1), so it is
    // deferred until a link-state monitor exists. The 5s per-key window
    // self-heals a transient-down lockout regardless.

    pub fn policy_rule_counters(&self) -> Vec<crate::protocol::PolicyRuleCounterStatus> {
        self.forwarding.policy.counter_snapshots()
    }

    pub fn clear_policy_counters(&self) {
        self.policy_counters.clear();
    }

    /// #2218: per-rule NAT translation hit-counter snapshots reported back
    /// to the Go control plane via `ProcessStatus.nat_rule_counters`.
    pub fn nat_rule_counters(&self) -> Vec<crate::protocol::NatRuleCounterStatus> {
        self.nat_counters.snapshots()
    }

    /// #2218: operator clear of NAT translation hit counters (the Go side
    /// also clears the corresponding offset entries; this resets the
    /// helper-side atomics).
    pub fn clear_nat_counters(&self) {
        self.nat_counters.clear();
    }

    /// #3651: per-zone ingress/egress traffic-volume snapshot for
    /// `ProcessStatus.zone_traffic_counters`.
    ///
    /// TWO filters. A row is published only when its zone is BOTH (a) currently
    /// configured and (b) holding a live hot-path slot.
    ///
    /// (b) is load-bearing — see the carried-forward-store case below. (a) is
    /// DEFENCE IN DEPTH: no reachable runtime divergence has been demonstrated
    /// for it (apply-time `reconcile` prunes unconfigured zones and the
    /// reserved-id path is filtered identically in policy.rs), so it is kept and
    /// tested as a belt, not claimed as a live guard.
    ///
    /// Filter (b) exists because the store OUTLIVES the slot map. Config apply
    /// carries the store forward and `reconcile` retains every still-configured
    /// zone (`forwarding_build/mod.rs`), while `ZoneCounterSlotMap::build`
    /// assigns only `ZONE_COUNTER_ASSIGNABLE_SLOTS` slots in sorted zone-id
    /// order. So a zone that accumulated traffic and is then pushed past
    /// capacity by a later config — 63 lower-id zones added alongside it —
    /// stays configured, keeps its retained nonzero totals, and gets slot 0.
    /// Without this filter its stale row keeps publishing: the Go side mirrors
    /// it, and Prometheus emits a FROZEN total forever while every subsequent
    /// packet on that zone goes uncounted. That is strictly worse than omitting
    /// the zone, because a frozen counter looks alive — an authoritative number
    /// that is wrong, which is the exact failure the per-zone surface work
    /// exists to prevent.
    ///
    /// Dropping the row makes such a zone read as `ErrCounterNotPopulated`
    /// end-to-end, which is the honest answer: its traffic genuinely is not
    /// being counted. `zone_counter_overflow_active` carries the reason on the
    /// wire — though #6845 tracks that it has no consumer on any surface yet,
    /// so today an operator sees "not available" without the why.
    ///
    /// NOTE: this is only half the fix. The Go status loop must REPLACE its
    /// offset map from each snapshot rather than merge into it, or a row that
    /// stops being published leaves a stale offset behind
    /// (`Manager.ReplaceZoneCounterOffsets`).
    pub fn zone_traffic_counters(&self) -> Vec<crate::protocol::ZoneTrafficCounterStatus> {
        let configured = &self.forwarding.zone_id_to_name;
        crate::afxdp::zone_counters::publishable_zone_rows(
            &self.forwarding.zone_counter_store,
            &self.forwarding.zone_counter_slot_map,
            |zone_id| configured.contains_key(&zone_id),
        )
    }

    /// #3651: true when the configured zone count exceeded the hot-path slot
    /// capacity, so some zones are silently uncounted (surfaced on the wire as
    /// `zone_counter_overflow_active`).
    pub fn zone_counter_overflow_active(&self) -> bool {
        self.forwarding.zone_counter_slot_map.overflow_active
    }

    /// #3651: the zone-counter wire layout version this helper emits.
    pub fn zone_counter_layout_version(&self) -> u32 {
        crate::afxdp::zone_counters::ZONE_COUNTER_LAYOUT_VERSION
    }

    /// #3651: operator clear of per-zone traffic counters. Resets the helper's
    /// cumulative store so the pre-clear total is not snapped back on the next
    /// 1 s status poll (the load-bearing half of the operator clear).
    ///
    /// #6843: a cleared zone then reads as NOT POPULATED rather than as zero.
    /// `ZoneCounterStore::snapshot` omits all-zero rows, so a just-cleared zone
    /// produces no row, and the Go side replaces its offset map from that
    /// snapshot (`ReplaceZoneCounterOffsets`) rather than overwriting row by
    /// row — so the offset is dropped, not set to 0. Surfaces render
    /// "not available" until traffic repopulates the row.
    pub fn clear_zone_counters(&self) {
        self.forwarding.zone_counter_store.clear();
    }

    /// #3651: per-zone SYN/ICMP/UDP flood-EVENT snapshot for
    /// `ProcessStatus.zone_flood_counters`.
    ///
    /// Same two filters as `zone_traffic_counters`, for the same reasons: a row
    /// publishes only when its zone is BOTH currently configured AND holding a
    /// live slot. The slot filter is the load-bearing one — the store outlives
    /// the slot map, so a zone pushed past capacity by a later config keeps its
    /// retained flood counts while no longer being counted, and publishing that
    /// row would mirror a FROZEN total that under-reports every subsequent
    /// attack while looking alive. The configured filter is defence in depth
    /// (apply-time `reconcile` already prunes unconfigured zones).
    ///
    /// NOTE: this is only half the fix. The Go status loop must REPLACE its
    /// offset map from each snapshot rather than merge into it, or a row that
    /// stops being published leaves a stale offset behind
    /// (`Manager.ReplaceFloodCounterOffsets`).
    pub fn zone_flood_counters(&self) -> Vec<crate::protocol::ZoneFloodCounterStatus> {
        let configured = &self.forwarding.zone_id_to_name;
        crate::afxdp::flood_counters::publishable_flood_rows(
            &self.forwarding.flood_counter_store,
            &self.forwarding.flood_counter_slot_map,
            |zone_id| configured.contains_key(&zone_id),
        )
    }

    /// #3651: true when the configured zone count exceeded the flood-counter
    /// slot capacity, so some zones' flood events go uncounted (surfaced on the
    /// wire as `flood_counter_overflow_active`).
    pub fn flood_counter_overflow_active(&self) -> bool {
        self.forwarding.flood_counter_slot_map.overflow_active
    }

    /// #3651: the flood-counter wire layout version this helper emits.
    pub fn flood_counter_layout_version(&self) -> u32 {
        crate::afxdp::flood_counters::FLOOD_COUNTER_LAYOUT_VERSION
    }

    /// #3651: operator clear of per-zone flood counters. Resets the helper's
    /// cumulative store so the pre-clear total is not snapped back on the next
    /// 1 s status poll (the load-bearing half of the operator clear — clearing
    /// only the Go offset map would be undone within a second).
    ///
    /// A cleared zone then reads as NOT POPULATED rather than as zero:
    /// `FloodCounterStore::snapshot` omits all-zero rows, so a just-cleared zone
    /// produces no row, and the Go side replaces its offset map from that
    /// snapshot (`ReplaceFloodCounterOffsets`) rather than overwriting row by
    /// row — so the offset is dropped, not set to 0.
    pub fn clear_flood_counters(&self) {
        self.forwarding.flood_counter_store.clear();
    }

    /// TEST SCAFFOLDING (#6938): seed one zone with a recorded flood event,
    /// exactly as a worker leaves it after `record_zone_flood_drop` + a flush.
    ///
    /// It exists because the binding that matters lives OUTSIDE this package:
    /// `server::helpers::status::refresh_status` publishing these rows, and the
    /// `clear_flood_counters` handler arm clearing them. Those call sites were
    /// unbound precisely because every existing test reached past them into
    /// `crate::afxdp`, which `pkg`-external tests cannot do — so the seam had to
    /// be opened deliberately rather than by moving the tests inward, which
    /// would have measured the coordinator again instead of its callers.
    #[cfg(test)]
    pub(crate) fn seed_flood_counter_for_test(&mut self, zone: u16, name: &str) {
        use crate::afxdp::flood_counters::{
            flush_recorded_flood_counters, record_zone_flood_drop, FloodCounterSlotMap,
        };
        let map = FloodCounterSlotMap::build(&[zone], &self.forwarding.flood_counter_store);
        record_zone_flood_drop(&map, zone, "syn-flood");
        flush_recorded_flood_counters(&self.forwarding.flood_counter_store, &map);
        self.forwarding.flood_counter_slot_map = std::sync::Arc::new(map);
        self.forwarding.zone_id_to_name.insert(zone, name.to_string());
    }

    /// #6983: the zone-TRAFFIC twin of `seed_flood_counter_for_test`, opened
    /// for the same reason and on the same seam. `server::tests` cannot reach
    /// into `crate::afxdp` to record and flush a zone tally itself, so binding
    /// the status publication from the caller's side needs a seeder here.
    #[cfg(test)]
    pub(crate) fn seed_zone_traffic_counter_for_test(&mut self, zone: u16, name: &str, bytes: u64) {
        use crate::afxdp::zone_counters::{
            flush_recorded_zone_counters, record_zone_traffic, ZoneCounterSlotMap,
        };
        let map = ZoneCounterSlotMap::build(&[zone], &self.forwarding.zone_counter_store);
        record_zone_traffic(&map, zone, 0, bytes);
        flush_recorded_zone_counters(&self.forwarding.zone_counter_store, &map);
        self.forwarding.zone_counter_slot_map = std::sync::Arc::new(map);
        self.forwarding.zone_id_to_name.insert(zone, name.to_string());
    }

    /// Current in-memory FIB generation (the value flow-cache lookups
    /// validate against). Read by the `bump_fib_generation` control handler
    /// to build a rollback-rejection error and by tests.
    pub fn fib_generation(&self) -> u32 {
        self.validation.fib_generation
    }

    /// #6592: the ONE place a `RuntimeView` becomes worker-visible.
    ///
    /// Every publish path funnels through here, and the view is built from
    /// `self.validation` AT THE STORE — so the pair a worker observes is the
    /// coordinator's intended pair by construction, at every site, with no
    /// ordering discipline to get wrong. Before #6592 validation and
    /// forwarding were two independent `ArcSwap`s and coherence depended on
    /// each site storing them in the right order AND every reader loading them
    /// in the opposite order; an acquire/release pair can only exclude ONE of
    /// the two torn orientations that way (see `types/runtime_view.rs`).
    ///
    /// Callers must have finished mutating `self.validation` and
    /// `self.forwarding` before calling: this is the release store that
    /// publishes everything committed before it, so the #5166 CoS-map /
    /// `ha.fabrics` stores must also already have happened.
    fn store_runtime_view(&mut self, forwarding: Arc<ForwardingState>) {
        let view = Arc::new(RuntimeView::new(self.validation, forwarding));
        // #6592 test seam — records the INTENDED pair and the still-visible
        // PREVIOUS view, so the regression test can assert both that a worker
        // observes exactly this pair and that the capture sits BEFORE the
        // store (hoist resistance). Absent from release builds.
        #[cfg(test)]
        {
            self.runtime_view_at_publish = Some((view.clone(), self.ha.runtime.load_full()));
            // #6593: capture EVERY sibling that must already be worker-visible
            // here, not just the CoS owner map. Taken at the same instant and
            // from the same choke point, so no publish path can bypass it.
            self.prepublish_siblings = Some(PrePublishSiblings {
                cos_owner_worker_by_queue: self.cos.owner_worker_by_queue.load_full(),
                cos_owner_live_by_queue: self.cos.owner_live_by_queue.load_full(),
                cos_root_leases: self.cos.root_leases.load_full(),
                cos_exact_backlogs: self.cos.exact_backlogs.load_full(),
                cos_queue_leases: self.cos.queue_leases.load_full(),
                cos_queue_vtime_floors: self.cos.queue_vtime_floors.load_full(),
                ha_fabrics: self.ha.fabrics.load_full(),
                previous_view: self.ha.runtime.load_full(),
            });
        }
        self.ha.runtime.publish(view);
    }

    /// #6592: publish the current `self.forwarding` paired with the current
    /// `self.validation`. Clones the forwarding tables (as every pre-#6592
    /// `ha.forwarding.store(Arc::new(self.forwarding.clone()))` site did) and
    /// rotates the worker-visible forwarding `Arc`, so workers take their
    /// rotation branch.
    pub(crate) fn publish_runtime_view(&mut self) {
        let forwarding = Arc::new(self.forwarding.clone());
        self.store_runtime_view(forwarding);
    }

    /// #6592: publish a VALIDATION-ONLY change, reusing the forwarding `Arc`
    /// that is already worker-visible.
    ///
    /// This is what preserves #1188 across the atomic pairing. The alternative
    /// design — inlining `ValidationState` into `ForwardingState` — would make
    /// every FIB bump clone the whole forwarding state here and rotate the
    /// worker-visible `Arc`, forcing each worker through its expensive
    /// rotation branch (screen-profile and opening-override clones, cold-path
    /// slot rescan, input-filter session purges, CoS runtime reset) for a
    /// change that touched no table. Reusing the published `Arc` keeps the
    /// worker's `Arc::ptr_eq` short-circuit hitting exactly as before; the
    /// only cost is one small `RuntimeView` allocation on a cold path.
    ///
    /// It deliberately reads the PUBLISHED forwarding rather than
    /// `self.forwarding`: republishing means "same tables, newer stamps", and
    /// the published `Arc` is by definition the tables workers already hold.
    pub(crate) fn republish_runtime_validation(&mut self) {
        let forwarding = self.ha.runtime.load().forwarding().clone();
        self.store_runtime_view(forwarding);
    }

    /// #6592 test accessor: the WORKER-VISIBLE validation — the validation half
    /// of the currently published [`RuntimeView`]. Replaces the reads of the
    /// former `shared_validation` `ArcSwap` in tests that assert what a worker
    /// would observe.
    ///
    /// It is distinct from `self.validation` only in WHERE it is read from, not
    /// in value: since #3766 there is no reachable state in which the two
    /// disagree. Every site that assigns `self.validation` publishes it before
    /// the function can return — `refresh_runtime_snapshot_inner` and
    /// `apply_snapshot` both do the whole fallible build BEFORE the assignment,
    /// leaving no `return` / `?` / panic between assignment and publish;
    /// `bump_fib_generation` refuses a rollback before writing anything; and
    /// `stop_inner` defaults both halves adjacently. That property is
    /// LOAD-BEARING for this PR: `update_neighbors` and `refresh_fabric_links`
    /// now publish through `publish_runtime_view`, which carries
    /// `self.validation` along with the forwarding they came to update. On
    /// master those sites stored forwarding only and never touched validation,
    /// so if an abort COULD strand a bumped `self.validation`, a later
    /// `SyncFabricState` or neighbor push would publish that stranded
    /// generation against old forwarding — the #6592 mirror, moved to the
    /// writer side. It cannot, and that must stay true.
    #[cfg(test)]
    pub(crate) fn published_validation(&self) -> ValidationState {
        self.ha.runtime.load().validation()
    }

    /// #6592 test fixture: stand in for "a prior generation was successfully
    /// published and workers are running on it". Replaces the former
    /// `shared_validation.store(...)` fixture calls.
    ///
    /// It sets `self.validation` and publishes through the SAME choke point the
    /// production paths use, rather than storing a view directly. Two reasons:
    /// the seeded state is coherent by construction (a fixture cannot
    /// accidentally seed a validation the coordinator does not hold), and the
    /// tree is left with exactly ONE `ha.runtime.store(` — so
    /// `tests/runtime_view_publish_canary.rs` can pin that count with no
    /// cfg(test) exemption to reason about. Callers may still assign
    /// `self.validation` themselves first; that is now redundant but reads as
    /// the intent.
    #[cfg(test)]
    pub(crate) fn seed_published_validation(&mut self, validation: ValidationState) {
        self.validation = validation;
        self.republish_runtime_validation();
    }

    /// Bump just the FIB generation counter without a full snapshot rebuild.
    /// Workers will invalidate flow cache entries with stale FIB generations.
    ///
    /// #3767 (H5): flow-cache validation is EQUALITY based, not monotone —
    /// `flow_cache.rs` treats an entry as stale only when
    /// `entry.stamp.fib_generation != lookup.fib_generation`. So publishing an
    /// OLD or reused generation (a stale/duplicate/corrupt control message, or
    /// a shim counter that was reset to a lower value) would make cache
    /// entries that a prior bump already invalidated MATCH validation again,
    /// reviving a forwarding decision after a route withdrawal / failover.
    ///
    /// A lightweight route-only overlay bump is monotone by construction on
    /// the Go side (`Manager.BumpFIBGeneration` increments the shim counter),
    /// so a value strictly lower than the current in-memory generation is
    /// never legitimate here — reject it and leave `self.validation` and the
    /// shared validation Arc untouched. A full-snapshot generation transition
    /// runs through `refresh_runtime_snapshot`, which assigns `self.validation`
    /// directly and is intentionally NOT gated by this monotonicity check, so
    /// a legitimate config-transition reset still lands.
    ///
    /// Returns `true` when the bump was applied, `false` when it was refused

    /// as a rollback.
    #[must_use]
    pub fn bump_fib_generation(&mut self, fib_generation: u32) -> bool {
        if fib_generation < self.validation.fib_generation {
            return false;
        }
        self.validation.fib_generation = fib_generation;
        // #6592: publish the new stamps paired with the forwarding tables
        // workers already hold. No rebuild, no forwarding-Arc rotation —
        // `republish_runtime_validation` reuses the published `Arc`, so the
        // #1188 short-circuit still short-circuits.
        self.republish_runtime_validation();
        true
    }
}

/// #2218: collect the nonzero per-rule NAT counter ids referenced by a
/// snapshot (SNAT + DNAT + static), for `NatCounterStore::reconcile_ids`.
/// Mirrors `policy_counters.reconcile_rules(&snapshot.policies)`.
pub(super) fn snapshot_active_nat_counter_ids(
    snapshot: &crate::protocol::ConfigSnapshot,
) -> Vec<u32> {
    let mut ids: Vec<u32> = Vec::new();
    for rule in &snapshot.source_nat_rules {
        if rule.counter_id != 0 {
            ids.push(rule.counter_id);
        }
    }
    for rule in &snapshot.destination_nat_rules {
        if rule.counter_id != 0 {
            ids.push(rule.counter_id);
        }
    }
    for rule in &snapshot.static_nat_rules {
        if rule.counter_id != 0 {
            ids.push(rule.counter_id);
        }
    }
    ids
}

fn build_mirror_target_map(
    identities: &BTreeMap<u32, BindingIdentity>,
    live: &BTreeMap<u32, Arc<BindingLiveState>>,
) -> MirrorTargetMap {
    let mut out = MirrorTargetMap::default();
    for (slot, ident) in identities {
        let Some(binding_live) = live.get(slot) else {
            continue;
        };
        out.insert(ident, binding_live.clone());
    }
    out
}

#[cfg(test)]
impl Coordinator {
    /// #2962 test seam: install a worker handle whose `session_export_ack`
    /// never advances on its own, and return the ack atomic so the caller
    /// (e.g. the server-level dispatcher test in `crate::server::tests`) can
    /// control when the owner-RG export ack-wait completes. Lets a test
    /// prove the global `ServerState` lock is NOT held across the wait.
    pub(crate) fn test_install_export_worker(&mut self, worker_id: u32) -> Arc<AtomicU64> {
        let ack = Arc::new(AtomicU64::new(0));
        let handle = WorkerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            heartbeat: Arc::new(AtomicU64::new(0)),
            commands: Arc::new(Mutex::new(VecDeque::new())),
            session_export_ack: ack.clone(),
            cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(super::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(super::cold_path_hist::WorkerColdPathAtomics::new()),
        };
        // #6242: register the whole runtime record (handle + empty
        // observability slots) as one op — the export test only drives the
        // handle's `session_export_ack`.
        self.workers.register(worker_id, WorkerRuntimeRecord::for_test(handle), None);
        ack
    }

    /// #9344: seed a live binding with `count` pending session deltas so a
    /// control-socket-level export test can drive the CAPPED/paged path.
    ///
    /// The unit tests around `wait_and_collect` can build these buffers
    /// directly; a dispatcher-level test cannot, because it only holds the
    /// `ServerState` mutex. Without this the whole path from a
    /// `SessionExportRequest` to `ControlResponse.session_export_more` is
    /// untested end to end — which is exactly the seam a mutation of the
    /// handler's one assignment line survived.
    pub(crate) fn test_seed_binding_session_deltas(&mut self, slot: u32, count: usize) {
        let live = std::sync::Arc::new(super::BindingLiveState::new());
        for _ in 0..count {
            live.push_session_delta(crate::protocol::SessionDeltaInfo::default());
        }
        self.workers.live.insert(slot, live);
    }
}

// #7160 (#2387): the routing-domain accessors the session-sync handler calls.
// Split out of this file to keep it under the modularity floor
// (docs/engineering-style.md); it is one cohesive pair of readers over
// `self.forwarding`, so it is a clean seam rather than an arbitrary cut.
#[path = "routing_domain.rs"]
mod routing_domain;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
