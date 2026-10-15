// #13075 (D4-12) — session expiry / GC teardown helpers, extracted from
// loop_body/mod.rs (pure code motion; see that file's header).
//
// These run on the worker's ~1s GC sweep and on control-plane delete
// dispatch — never per packet. Contents: missing-neighbor seed retirement
// (#10419), the expired-session reap (SNAT/NAT64 release + BPF teardown +
// flow-cache eviction, #3776/#4381/#6211), the #10591 production test
// seams, the DeleteSynced flow-cache invalidation (#6457), and the
// create-counted expiry counter (#2428). The seams keep their
// `pub(in crate::afxdp)` visibility via the re-export in mod.rs, so
// `worker/mod.rs` and the #10591 window tests are unchanged.
//
// `use super::*;` chains through loop_body/mod.rs to worker/mod.rs.

use super::*;

/// #10419: retire a missing-neighbor seed's shared publication when its local
/// session expires. Seeds intentionally do not emit Close deltas, so they need
/// this separate path; the origin and stable session id fence the removal to
/// the exact expired incarnation and preserve a same-key replacement.
pub(super) fn retire_expired_missing_neighbor_seeds(
    expired_entries: &[crate::session::ExpiredSession],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
) {
    for expired_entry in expired_entries {
        if expired_entry.origin != SessionOrigin::MissingNeighborSeed
            || expired_entry.session_id == 0
        {
            continue;
        }
        let expired_session_id = expired_entry.session_id;
        let _ = crate::afxdp::shared_ops::remove_shared_session_if(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &expired_entry.key,
            |entry| {
                entry.origin == SessionOrigin::MissingNeighborSeed
                    && entry.session_id == expired_session_id
            },
        );
    }
}

/// #3776: apply the per-worker teardown side effects for every session the GC
/// wheel reaped this sweep — release its SNAT allocation, delete its BPF
/// redirect/conntrack entries, AND invalidate the per-worker flow-cache slot(s)
/// that back it.
///
/// The flow-cache invalidation is the half of #2220 that was never shipped.
/// #2220 (PR #2233) added only the keepalive: on a cache HIT the hot path
/// touches the backing session so an ACTIVELY-forwarding flow's session cannot
/// be reaped out from under a live cache entry. It does not cover a flow that
/// idles PAST its timeout — the GC reaps the session and releases its SNAT
/// port, but the flow-cache slot survives (config/fib generation, RG epoch, and
/// RG lease are all unchanged, and the slot is not LRU-evicted). If traffic
/// later resumes on the same 5-tuple it HITS the surviving `RewriteDescriptor`
/// and is forwarded WITHOUT a live session — a stateful-firewall bypass (no
/// policy re-evaluation, no session install, no `show security flow session`
/// row, not HA-synced) — and via a SNAT port that `release_source_nat_allocation`
/// may already have handed to a different flow (NAT-port reuse / reverse-path
/// collision). Evicting the slot here forces the next packet to MISS the cache
/// and re-run full session lookup/creation + policy (fail-closed: no forwarding
/// without a live session, no stale-SNAT reuse via a surviving descriptor).
/// Mirrors the RST-teardown eviction in `worker/lifecycle.rs`.
///
/// Cache ownership: the flow cache is per-binding and worker-owned, and this
/// runs on the owning worker's GC sweep, so the eviction is a same-thread
/// mutation — no cross-thread flush is needed. We invalidate on EVERY binding of
/// this worker because a reaped session does not carry the ingress ifindex the
/// cache is keyed on. That is both safe and precise: the session table is keyed
/// by the 5-tuple ALONE, so at most one live session — hence at most one VALID
/// descriptor — can exist for a given key, and `invalidate_slot` only drops a
/// slot whose key AND ingress_ifindex both match. On a non-owning binding the
/// call therefore either no-ops or drops a STALE prior-flow slot with the same
/// tuple (which should go anyway); it can never drop another live flow's entry.
/// Forward and reverse directions are each their own `ExpiredSession` with their
/// own key, so both directions' slots are covered. This is the reap path
/// (bounded by the ~1/s GC sweep), so it adds no per-packet cost and does not
/// regress the #2220 keepalive fast path.

#[allow(clippy::too_many_arguments)]
pub(super) fn reap_expired_sessions(
    bindings: &mut [BindingWorker],
    expired_entries: &[crate::session::ExpiredSession],
    forwarding: &ForwardingState,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    now_ns: u64,
    // #6211 F2: THIS worker's id, taken from `WorkerLaunchPlan::worker_id` at
    // the top of `worker_loop` — the worker's own identity established at
    // spawn, NOT read off a `BindingWorker` slot.
    //
    // This is the reap that motivates the whole holder set. Post-failover the
    // active's periodic `UpsertSynced` refresh stops and RSS lands traffic on
    // exactly ONE worker, so the other N-1 replicas of a synced session idle out
    // with nothing refreshing them. Whichever expires first must NOT free a
    // `(pool_addr, port)` the still-forwarding worker is using.
    worker_id: u32,
) {
    for expired_entry in expired_entries {
        release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &expired_entry.key,
            expired_entry.decision.nat,
            expired_entry.metadata.is_reverse,
            now_ns,
            worker_id,
        );
        // #4381: return the reaped NAT64 forward flow's translated pool port to
        // its allocator (self-gated on the forward NAT64 entry).
        crate::nat64::release_nat64_allocation_for_worker(
            &forwarding.nat64,
            &expired_entry.key,
            expired_entry.decision.nat,
            expired_entry.metadata.is_reverse,
            now_ns,
            worker_id,
        );
        delete_session_map_entry_for_removed_session_with_origin(
            session_map,
            &expired_entry.key,
            expired_entry.decision,
            &expired_entry.metadata,
            expired_entry.origin,
            conntrack_v4_fd,
            conntrack_v6_fd,
        );
        for binding in bindings.iter_mut() {
            binding
                .flow
                .flow_cache
                .invalidate_slot(&expired_entry.key, binding.ifindex);
        }
    }
}
/// #10591 test seam: execute the production expire+reap pair in one call.
///
/// The worker loop calls `expire_stale_entries_ha`, then
/// `reap_expired_sessions` (with `retire_expired_missing_neighbor_seeds`,
/// `session_expires` accounting, and `drain_and_flush_all` between them that
/// this seam does NOT drive). The window harness must exercise BOTH arms; an
/// expire-only test leaves cached descriptors alive, while a reap-only test
/// cannot observe the wheel's expiry classification.
///
/// Divergences from the loop (documented, not silent): callers in the window
/// cells pass `ha=None` where production passes `Some(&ha_ctx)` (synced rows
/// AGE instead of HOLD — benign while rows stay traffic-fresh); the steering
/// map is `SteeringMap::unshared_for_test(-1)` with dummy conntrack fds
/// `-1/-1` and `worker_id 0` (BPF/conntrack teardown and per-worker NAT
/// accounting no-op); row removal plus flow-cache eviction are real and
/// asserted. Cross-worker propagation is not driven.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn production_sweep_for_test(
    sessions: &mut crate::session::SessionTable,
    bindings: &mut [BindingWorker],
    forwarding: &ForwardingState,
    now_ns: u64,
    ha: Option<&crate::session::ExpireHaContext<'_>>,
) -> Vec<crate::session::ExpiredSession> {
    let expired_entries = sessions.expire_stale_entries_ha(now_ns, ha);
    let session_map = crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1);
    reap_expired_sessions(
        bindings,
        &expired_entries,
        forwarding,
        session_map,
        -1,
        -1,
        now_ns,
        0,
    );
    expired_entries
}
/// #10591 test seam: execute the production commit-time zone purge at the
/// snapshot-rotation boundary. This keeps the window sibling out of private
/// `session_glue` helpers while still driving the same old/new set derivation
/// and pair-aware purge that `worker_loop` uses, with the
/// same dummy-map/fd/worker-id divergences as `production_sweep_for_test`
/// (fresh shared maps, no peer commands, no HA delete propagation).
#[cfg(test)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn production_rotation_purge_for_test(
    sessions: &mut crate::session::SessionTable,
    binding: &BindingWorker,
    old_forwarding: &ForwardingState,
    new_forwarding: &ForwardingState,
    now_ns: u64,
) -> (usize, usize) {
    let removed_zone_ids = removed_zone_ids_for_rotation(old_forwarding, new_forwarding);
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let purged = purge_sessions_with_removed_zone_ids(
        sessions,
        binding.bpf_maps.session_map.handle(),
        -1,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        new_forwarding,
        &removed_zone_ids,
        now_ns,
        0,
    );
    (removed_zone_ids.len(), purged)
}

/// #6457: invalidate the per-worker flow-cache slot(s) backing every session
/// a control-plane `WorkerCommand::DeleteSynced` dropped this tick.
///
/// This is the delete-path twin of #3776's GC-reap invalidation in
/// `reap_expired_sessions` above. Three control-plane flows funnel through
/// `DeleteSynced` — the operator's `clear security flow session [all]`
/// (`ClearAllSessions` / singular `DeleteSession` in the Go manager), the
/// cluster-stale sweep (`BatchDeleteSessions`), and HA DeleteSynced
/// propagation from the peer (`delete_synced_session_gen` fan-out plus
/// cross-worker `replicate_session_delete`). None of them bumps
/// config/fib generation, RG epoch, or RG lease, and none is an LRU
/// eviction, so without this eviction a revoked-but-still-active 5-tuple
/// kept HITTING its cached `RewriteDescriptor` on the owning worker —
/// forwarded indefinitely with no session row, no policy re-evaluation,
/// no `show security flow session` visibility, and no HA sync (a fail-open
/// revocation primitive: the operator's explicit `clear` did not stop
/// forwarding). Evicting here forces the next packet on the tuple to MISS
/// the cache and re-run full session lookup/creation + policy — fail-closed.
///
/// Ownership and precision mirror the reap path: the flow cache is
/// per-binding and worker-owned and this runs on the owning worker's
/// command dispatch, so the eviction is a same-thread mutation — no
/// cross-thread flush. Every binding is walked because a deleted session
/// does not carry the ingress ifindex the cache is keyed on; the session
/// table is keyed by the 5-tuple alone, so at most one live session —
/// hence at most one VALID descriptor — exists per key, and
/// `invalidate_slot` drops only a slot whose key AND ingress_ifindex both
/// match (on a non-owning binding it either no-ops or evicts a stale
/// prior-flow slot with the same tuple, never another live flow's entry).
/// `delete_synced_session_gen` fans out the forward AND reverse keys, so
/// both directions' slots are covered. The work is bounded by the
/// control-plane delete rate (one Vec push per delete inside
/// `handle_delete_synced`, one `invalidate_slot` walk per binding per
/// delete here) — zero per-packet cost: the hit path is untouched and
/// empty-delete ticks skip the call entirely.
pub(super) fn invalidate_flow_cache_slots_for_deleted_sessions(
    bindings: &mut [BindingWorker],
    deleted_keys: &[crate::session::SessionKey],
) {
    for key in deleted_keys {
        for binding in bindings.iter_mut() {
            binding
                .flow
                .flow_cache
                .invalidate_slot(key, binding.ifindex);
        }
    }
}

/// #2428: count only the create-counted LOCAL-origin expired sessions for
/// the `session_expires` counter (which the Go control plane reads as
/// `GlobalCtrSessionsClosed`).
///
/// `session_creates` is bumped ONLY on the four local poll-descriptor install
/// paths — `ForwardFlow` / `ReverseFlow` / `LocalMiss` /
/// `MissingNeighborSeed`. Every other origin is synced-derived and never
/// create-counted:
///   - `SyncImport` / `SharedMaterialize` / `WorkerLocalImport` — installed
///     via the HA sync path (`upsert_synced_with_origin` /
///     `WorkerCommand::UpsertLocal`);
///   - `SharedPromote` — a re-tag of an already-synced (uncounted) entry by
///     `maybe_promote_synced_session` (`session_glue/promote.rs`); its
///     `promote_synced_with_origin` install does NOT touch `session_creates`.
///     `is_peer_synced()` returns FALSE for `SharedPromote`, so an earlier
///     `!is_peer_synced()` filter would have COUNTED a promote expiry that
///     was never create-counted — re-introducing the underflow on a node
///     that promotes synced sessions post-failover. `shared_ops.rs` already
///     groups `SharedPromote` with the peer-synced set for the wire-alias
///     contract; this counter is consistent with that.
///
/// Counting any non-create-counted origin's expiry inflates `session_expires`
/// past `session_creates`, wrapping the unsigned Go subtraction
/// `session_creates - session_expires` to ~1.8e19. We therefore match on the
/// EXACT complement of the create-counted set via an exhaustive `match` (NO
/// wildcard) so a future 9th `SessionOrigin` variant forces a compile-time
/// decision here rather than silently defaulting to "counted". The Go-side
/// `dataplane.CurrentSessions` saturating floor is the defense-in-depth
/// backstop.
pub(super) fn count_local_session_expiries(
    origins: impl Iterator<Item = crate::session::SessionOrigin>,
) -> u64 {
    use crate::session::SessionOrigin;
    origins
        .filter(|o| match o {
            // The four create-counted local install paths: count their expiry.
            SessionOrigin::ForwardFlow
            | SessionOrigin::ReverseFlow
            | SessionOrigin::LocalMiss
            | SessionOrigin::MissingNeighborSeed => true,
            // #7770: a fabric PUNT SEED is installed without bumping
            // `session_creates` — the punting node deliberately keeps its
            // operator-visible create accounting unchanged, because the
            // AUTHORITATIVE session for a punted flow is the peer's. Its expiry
            // must therefore not be counted either, or `session_creates -
            // session_expires` wraps.
            SessionOrigin::FabricPuntSeed => false,
            // Synced-derived, never create-counted: must NOT be expire-counted.
            // #10038 item 5: TUN-origin joins them (shared-hit `created` is
            // false, publish bumps nothing — counting its expiry would wrap
            // the Current-sessions gauge the same way).
            SessionOrigin::SyncImport
            | SessionOrigin::SharedMaterialize
            | SessionOrigin::SharedPromote
            | SessionOrigin::WorkerLocalImport
            | SessionOrigin::TunOrigin => false,
        })
        .count() as u64
}

/// Retry teardown for locally removed pressure victims whose all-key tuple
/// lease was contended. These records are outside the session table and would
/// otherwise never reach ordinary expiry cleanup.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn retry_deferred_pressure_sheds(
    sessions: &mut crate::session::SessionTable,
    bindings: &mut [BindingWorker],
    forwarding: &ForwardingState,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    dnat_fds: &crate::afxdp::checksum::DnatTableFds,
    worker_id: u32,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &crate::afxdp::types::WorkerCommandQueues,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    now_ns: u64,
) {
    let shed_sessions = sessions.take_deferred_pressure_shed();
    if shed_sessions.is_empty() {
        return;
    }
    let shed_keys: Vec<_> = shed_sessions.iter().map(|shed| shed.key.clone()).collect();
    let Ok(_lease) = crate::afxdp::bpf_map::global_tuple_gate().acquire_lease(shed_keys) else {
        sessions.defer_pressure_shed(shed_sessions);
        return;
    };
    for shed in shed_sessions {
        let shared_removal = crate::afxdp::shared_ops::remove_shared_session_if(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &shed.key,
            |current| {
                crate::afxdp::poll_descriptor::is_pressure_shed_shared_opening(current, &shed)
            },
        );
        if matches!(
            shared_removal,
            crate::afxdp::shared_ops::SharedRemoval::Declined
        ) {
            if sessions.probe_with_origin(&shed.key).is_none() {
                crate::nat::release_source_nat_allocation_for_worker(
                    &forwarding.iface_nat_allocators,
                    &forwarding.source_nat_rules,
                    &shed.key,
                    shed.decision.nat,
                    shed.is_reverse,
                    now_ns,
                    worker_id,
                );
                crate::nat64::release_nat64_allocation_for_worker(
                    &forwarding.nat64,
                    &shed.key,
                    shed.decision.nat,
                    shed.is_reverse,
                    now_ns,
                    worker_id,
                );
            }
            continue;
        }
        let session_map = bindings
            .first()
            .map_or(session_map, |binding| binding.bpf_maps.session_map.handle());
        crate::afxdp::bpf_map::release_coordinator_session_rows(session_map, &shed.key);
        let _ = crate::afxdp::bpf_map::delete_bpf_conntrack_entry_under_gate(
            conntrack_v4_fd,
            conntrack_v6_fd,
            &shed.key,
        );
        if !shed.is_reverse {
            crate::afxdp::checksum::delete_dnat_table_entry(dnat_fds, &shed.key, shed.decision.nat);
        }
        crate::afxdp::bpf_map::delete_live_session_entry(
            session_map,
            &shed.key,
            shed.decision.nat,
            shed.is_reverse,
        );
        for binding in bindings.iter_mut() {
            binding
                .flow
                .flow_cache
                .invalidate_slot(&shed.key, binding.ifindex);
        }
        crate::nat::release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &shed.key,
            shed.decision.nat,
            shed.is_reverse,
            now_ns,
            worker_id,
        );
        crate::nat64::release_nat64_allocation_for_worker(
            &forwarding.nat64,
            &shed.key,
            shed.decision.nat,
            shed.is_reverse,
            now_ns,
            worker_id,
        );
        crate::afxdp::session_glue::replicate_session_delete_repairing(
            peer_worker_commands,
            worker_commands_by_id,
            forwarding,
            &shed.key,
            shed.decision.nat,
            shed.is_reverse,
            now_ns,
        );
    }
}
