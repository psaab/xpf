use super::*;

pub(in crate::afxdp) mod commands;
mod delete_drop_sweep;
mod promote;

pub(in crate::afxdp) use delete_drop_sweep::{DeleteDropSweep, DELETE_DROP_SWEEP_BUDGET};
use promote::{
    SharedSessionRefs, maybe_promote_synced_session, purge_translated_synced_hit,
    should_keep_synced_hit_transient,
};

pub(super) fn resolution_target_for_session(
    flow: &SessionFlow,
    decision: SessionDecision,
) -> IpAddr {
    decision.nat.rewrite_dst.unwrap_or(flow.dst_ip)
}

pub(super) fn cached_session_resolution(
    forwarding: &ForwardingState,
    cached: ForwardingResolution,
) -> Option<ForwardingResolution> {
    if cached.disposition != ForwardingDisposition::ForwardCandidate {
        return None;
    }
    if cached.egress_ifindex <= 0 || cached.neighbor_mac.is_none() {
        return None;
    }
    let mut fallback = cached;
    fallback.disposition = ForwardingDisposition::ForwardCandidate;
    if fallback.tx_ifindex <= 0 {
        fallback.tx_ifindex = resolve_tx_binding_ifindex(forwarding, fallback.egress_ifindex);
    }
    if let Some(egress) = forwarding.egress.get(&fallback.egress_ifindex) {
        if fallback.src_mac.is_none() {
            fallback.src_mac = Some(egress.src_mac);
        }
        if fallback.tx_vlan_id == 0 {
            fallback.tx_vlan_id = egress.vlan_id;
        }
    }
    Some(fallback)
}

pub(super) fn populate_egress_resolution(
    state: &ForwardingState,
    egress_ifindex: i32,
    resolution: &mut ForwardingResolution,
) {
    if egress_ifindex <= 0 {
        return;
    }
    if let Some(egress) = state.egress.get(&egress_ifindex) {
        resolution.tx_ifindex = if egress.bind_ifindex > 0 {
            egress.bind_ifindex
        } else {
            egress_ifindex
        };
        resolution.src_mac = Some(egress.src_mac);
        resolution.tx_vlan_id = egress.vlan_id;
    } else if resolution.tx_ifindex <= 0 {
        resolution.tx_ifindex = egress_ifindex;
    }
}

pub(super) fn lookup_forwarding_resolution_for_session(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
    decision: SessionDecision,
) -> ForwardingResolution {
    lookup_forwarding_resolution_for_session_with_cache(
        forwarding,
        dynamic_neighbors,
        flow,
        decision,
        true,
    )
}

fn lookup_forwarding_resolution_for_session_with_cache(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
    decision: SessionDecision,
    allow_cached_fast_path: bool,
) -> ForwardingResolution {
    if decision.resolution.disposition == ForwardingDisposition::LocalDelivery {
        return decision.resolution;
    }
    if decision.resolution.tunnel_endpoint_id != 0 {
        // #1873 (Codex code r2): the session's stored tunnel resolution
        // carries the owning netdev's kernel ifindex (egress_ifindex =
        // endpoint.logical_ifindex at resolve time). If the id has
        // since been re-owned by a DIFFERENT netdev (temporal hash
        // reuse: remove tunnel A, add tunnel B whose name folds to the
        // same id), the stale session must NEVER adopt the new owner —
        // no matter which forwarding state this worker held when the
        // session was created. Kernel ifindexes are not reused within
        // a boot, so inequality is authoritative. Tunnel-marked NoRoute
        // funnels the frame into the R-C gate (drop + count), never the
        // slow path and never B's encap.
        if decision.resolution.egress_ifindex > 0 {
            if let Some(row) = forwarding
                .tunnel_endpoints
                .get(&decision.resolution.tunnel_endpoint_id)
            {
                if row.logical_ifindex != decision.resolution.egress_ifindex {
                    // PRESERVE the stale egress_ifindex: several paths
                    // write the re-resolved value back into the stored
                    // entry (maybe_promote_synced_session, UpsertSynced)
                    // — zeroing it would erase the discriminator and let
                    // the NEXT packet adopt the new owner. With it
                    // preserved the entry stays gated until purged/GC'd.
                    let mut gated = super::no_route_resolution(None);
                    gated.tunnel_endpoint_id = decision.resolution.tunnel_endpoint_id;
                    gated.egress_ifindex = decision.resolution.egress_ifindex;
                    return gated;
                }
            }
        }
        let resolved = super::resolve_tunnel_forwarding_resolution(
            forwarding,
            Some(dynamic_neighbors),
            decision.resolution.tunnel_endpoint_id,
            0,
        );
        return match resolved.disposition {
            ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
                cached_session_resolution(forwarding, decision.resolution).unwrap_or(resolved)
            }
            _ => resolved,
        };
    }
    if allow_cached_fast_path {
        if let Some(cached) = cached_session_resolution(forwarding, decision.resolution) {
            return cached;
        }
    }
    let target = resolution_target_for_session(flow, decision);
    if let Some(local) = super::interface_nat_local_resolution(forwarding, target) {
        return local;
    }
    // #2734: spread ECMP equal-cost members by the per-FLOW 5-tuple hash
    // (the session forward key) so distinct flows to the same destination
    // take different paths, while every packet of one flow stays pinned to
    // one member (the resolution is cached on the session entry, and the
    // hash is deterministic within a boot).
    let resolved = lookup_forwarding_resolution_with_dynamic_for_flow(
        forwarding,
        dynamic_neighbors,
        target,
        &flow.forward_key,
    );
    match resolved.disposition {
        ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
            cached_session_resolution(forwarding, decision.resolution).unwrap_or(resolved)
        }
        _ => resolved,
    }
}

fn lookup_forwarding_resolution_for_synced_session(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
    decision: SessionDecision,
) -> ForwardingResolution {
    lookup_forwarding_resolution_for_session_with_cache(
        forwarding,
        dynamic_neighbors,
        flow,
        decision,
        false,
    )
}

pub(super) fn owner_rg_is_locally_active(
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    owner_rg_id: i32,
    now_secs: u64,
) -> bool {
    owner_rg_id > 0
        && matches!(ha_state.get(&owner_rg_id), Some(group) if group.is_forwarding_active(now_secs))
}

pub(super) fn synced_entry_allows_local_replace(
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    owner_rg_id: i32,
    now_secs: u64,
) -> bool {
    if owner_rg_is_locally_active(ha_state, owner_rg_id, now_secs) {
        return false;
    }
    if owner_rg_id == 0
        && ha_state
            .values()
            .any(|group| group.is_forwarding_active(now_secs))
    {
        return false;
    }
    true
}

pub(super) fn redirect_session_resolution_for_metadata(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    metadata: &SessionMetadata,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive || metadata.fabric_ingress {
        return resolution;
    }
    resolve_zone_encoded_fabric_redirect_by_id(forwarding, metadata.ingress_zone)
        .or_else(|| resolve_fabric_redirect(forwarding))
        .unwrap_or(resolution)
}

pub(super) fn owner_rg_is_unseeded(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    resolution: ForwardingResolution,
) -> bool {
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
    owner_rg_id > 0
        && matches!(
            ha_state.get(&owner_rg_id),
            None | Some(HAGroupRuntime {
                active: false,
                watchdog_timestamp: 0,
                ..
            })
        )
}

fn should_bypass_unseeded_tunnel_ha(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
) -> bool {
    resolution.disposition == ForwardingDisposition::ForwardCandidate
        && now_secs <= ha_startup_grace_until_secs
        && forwarding
            .tunnel_endpoint_by_ifindex
            .contains_key(&ingress_ifindex)
        && owner_rg_is_unseeded(forwarding, ha_state, resolution)
}

pub(super) struct WorkerCommandResults {
    pub cancelled_keys: Vec<SessionKey>,
    /// #6457: every session key dropped by a `WorkerCommand::DeleteSynced`
    /// this tick, recorded unconditionally by `handle_delete_synced` (even
    /// when the worker's session table had no entry — a stale flow-cache
    /// slot outlives its table entry, so the invalidate must not gate on
    /// the lookup). `apply_worker_commands` has no `BindingWorker` access;
    /// the worker loop (`worker/loop_body/mod.rs`) drains this list and
    /// calls `flow_cache.invalidate_slot(&key, binding.ifindex)` on every
    /// binding it owns — the same pattern #3776's `reap_expired_sessions`
    /// uses on the GC path — so a revoked 5-tuple MISSES the cache on its
    /// next packet and re-runs full session lookup + policy instead of
    /// forwarding via a stale cached permit with no live session (the
    /// operator `clear security flow session`, cluster-stale sweep, and HA
    /// DeleteSynced paths all funnel through this command).
    pub deleted_synced_keys: Vec<SessionKey>,
    pub exported_sequences: Vec<u64>,
    /// #7919: answers to `QuerySessionCounters` processed this tick. The
    /// command handler reads the table (it has `sessions` in scope); the WORKER
    /// LOOP publishes into the per-worker reply atomics, because that is where
    /// `runtime_atomics` lives. Same split as the export: decide here, publish
    /// where the handles are.
    pub session_counter_answers: Vec<SessionCounterAnswer>,
    /// #2653: the union of owner RGs requested by every
    /// `ExportOwnerRGSessions` command processed this tick. The command
    /// handler NO LONGER emits the open deltas itself — doing so pushed the
    /// entire owned-session set (up to `DEFAULT_MAX_SESSIONS` = 32x the 4096
    /// delta ring) into the ring in one shot, overflowing it and silently
    /// dropping sessions 4097..N from the HA bulk snapshot. Instead the
    /// handler records the RGs here and the worker loop performs the same
    /// chunked drain-as-you-export the #2442 loss-of-sync resync uses
    /// (collect candidates -> emit in < cap chunks -> drain between chunks),
    /// so the complete snapshot ships without overflowing the ring.
    pub export_owner_rgs: Vec<i32>,
    pub shaped_tx_requests: Vec<TxRequest>,
    /// #941 Work item C: set when at least one
    /// `WorkerCommand::VacateAllSharedExactSlots` was processed.
    /// `apply_worker_commands` cannot vacate directly because it has
    /// no `BindingWorker` access — the outer poll loop in `worker.rs`
    /// dispatches based on this flag.
    pub vacate_all_shared_exact_slots: bool,
    /// #7201: the shared queue still held commands after this call's
    /// [`WORKER_COMMAND_DRAIN_BUDGET`] slice was taken.
    ///
    /// The worker loop MUST fold this into `did_work`. It is not a statistic:
    /// `did_work` is set only by `poll_binding`, so without this the loop
    /// classifies a budget-split drain as IDLE, and on a node with no traffic
    /// yet — the standby that has just been promoted, which is exactly when the
    /// RG-activation burst arrives — `idle_iters` passes `IDLE_SPIN_ITERS` and
    /// every remaining slice waits behind a 1 ms `poll(2)` in Interrupt mode.
    /// The budget would then have replaced a bounded 3.85 ms stall with ~16 ms
    /// of drain.
    pub commands_backlogged: bool,
}

impl WorkerCommandResults {
    /// The no-work result: nothing dispatched, nothing left behind.
    ///
    /// `commands_backlogged: false` is load-bearing, not a filler default — it
    /// is what keeps an empty or lock-contended pass out of `did_work`.
    pub(super) fn empty() -> Self {
        WorkerCommandResults {
            cancelled_keys: Vec::new(),
            deleted_synced_keys: Vec::new(),
            exported_sequences: Vec::new(),
            session_counter_answers: Vec::new(),
            export_owner_rgs: Vec::new(),
            shaped_tx_requests: Vec::new(),
            vacate_all_shared_exact_slots: false,
            commands_backlogged: false,
        }
    }
}

fn force_live_redirect_for_worker_synced_entry(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    allow_replace_local: bool,
    has_routing_domains: bool,
) -> bool {
    allow_replace_local
        && uses_kernel_local_session_map_entry(key, decision, metadata, origin, has_routing_domains)
}

pub(super) fn session_key_has_lo0_filter(forwarding: &ForwardingState, key: &SessionKey) -> bool {
    match key.addr_family {
        family if family == libc::AF_INET as u8 => {
            forwarding.filter_state.lo0_filter_v4_fast.is_some()
        }
        family if family == libc::AF_INET6 as u8 => {
            forwarding.filter_state.lo0_filter_v6_fast.is_some()
        }
        _ => false,
    }
}

pub(super) fn republish_local_delivery_sessions_for_lo0_filter(
    sessions: &SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
) -> usize {
    let mut republished = 0usize;
    sessions.iter_with_origin(|key, decision, metadata, _origin| {
        if metadata.is_reverse
            || decision.resolution.disposition != ForwardingDisposition::LocalDelivery
            || !session_key_has_lo0_filter(forwarding, key)
        {
            return;
        }
        if session_map_fd >= 0 {
            // #1789: count failed lo0-filter republishes (was `let _ =`).
            // No binding context in this glue path — shared counter.
            if publish_live_session_entry(
                session_map_fd,
                key,
                decision.nat,
                metadata.is_reverse,
            )
            .is_err()
            {
                SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
        }
        republished += 1;
    });
    republished
}

pub(super) fn purge_sessions_for_input_dscp_filter_revalidation(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    // #8114 item 4: forwarded to `delete_terminal_filtered_session` so a
    // `DeleteSynced` a full sibling queue refuses is attributed and repaired.
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    forwarding: &ForwardingState,
    purge_v4: bool,
    purge_v6: bool,
    now_ns: u64,
    // #6211 F2: THIS worker's id — the purge tears down sessions that may be
    // peer-synced, whose reservation every worker holds.
    worker_id: u32,
) -> usize {
    if !purge_v4 && !purge_v6 {
        return 0;
    }
    let mut stale = Vec::new();
    sessions.iter_with_origin(|key, decision, metadata, origin| {
        let family_matches =
            (purge_v4 && key.addr_family == libc::AF_INET as u8)
                || (purge_v6 && key.addr_family == libc::AF_INET6 as u8);
        if family_matches {
            stale.push((key.clone(), decision, metadata.clone(), origin));
        }
    });
    let purged = stale.len();
    for (key, decision, metadata, origin) in stale {
        // #5622: `delete_terminal_filtered_session` now owns the per-entry
        // source-NAT / NAT64 release AND the forward<->reverse companion
        // teardown, so the purge no longer releases separately (that would
        // double-process the pair). Both halves of a translated flow are in
        // `stale`; the helper is idempotent, so whichever half is visited first
        // frees the shared reservation once and the second visit is a no-op.
        delete_terminal_filtered_session(
            sessions,
            session_map_fd,
            conntrack_v4_fd,
            conntrack_v6_fd,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            peer_worker_commands,
            worker_commands_by_id,
            forwarding,
            &key,
            decision,
            &metadata,
            origin,
            now_ns,
            worker_id,
        );
    }
    purged
}

pub(in crate::afxdp::session_glue) fn publish_worker_session_map_entry(
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    allow_replace_local: bool,
) {
    if session_map_fd < 0 {
        return;
    }
    let has_lo0_filter = session_key_has_lo0_filter(forwarding, key);
    // #9517: on a node WITH routing domains this is always false, so the row is
    // published as REDIRECT and an aliased publish can no longer flip a peer's
    // REDIRECT row to PASS_TO_KERNEL.
    let uses_kernel_local =
        uses_kernel_local_session_map_entry(key, decision, metadata, origin, forwarding.has_routing_domains);
    if uses_kernel_local && has_lo0_filter {
        // A PASS_TO_KERNEL session-map entry cannot re-run userspace lo0
        // filters. Keep the packet visible to the helper while lo0
        // filtering is configured; the session-hit path enforces the
        // current lo0 terms before reinjection.
        //
        // #1789: count failed publishes (was `let _ =`). No binding
        // context in this glue path — shared counter.
        if publish_live_session_entry(session_map_fd, key, decision.nat, metadata.is_reverse)
            .is_err()
        {
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    // #1789: capture the previously-discarded publish result. Only the
    // publish outcome is counted; `delete_live_session_entry` below is a
    // removal, not a publish, and keeps its existing semantics.
    let publish_result = if force_live_redirect_for_worker_synced_entry(
        key,
        decision,
        metadata,
        origin,
        allow_replace_local,
        forwarding.has_routing_domains,
    ) {
        publish_live_session_entry(session_map_fd, key, decision.nat, metadata.is_reverse)
    } else {
        if uses_kernel_local {
            delete_live_session_entry(session_map_fd, key, decision.nat, metadata.is_reverse);
        }
        publish_session_map_entry_for_session_with_origin(
            session_map_fd,
            key,
            decision,
            metadata,
            origin,
            forwarding.has_routing_domains,
        )
    };
    if publish_result.is_err() {
        SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn delete_terminal_filtered_session(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    // #8114 item 4: the same queues keyed by worker id, forwarded to
    // `delete_terminal_half` so a `DeleteSynced` a full sibling queue refuses
    // can be attributed and repaired.
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    now_ns: u64,
    // #6211 F2: THIS worker's id, threaded from `WorkerLaunchPlan::worker_id`
    // in the worker loop. A peer-synced reservation is held by every worker, so
    // a release must drop THIS worker's bit rather than free the port outright.
    worker_id: u32,
) {
    // #5622: a translated LocalDelivery terminal hit (host-inbound deny, lo0
    // input-filter deny, or `to-zone junos-host` deny on the session-HIT path)
    // can fire on EITHER the forward or the reverse companion entry. The
    // pre-#5622 body deleted ONLY the supplied key and released NO allocator
    // state, so the same-worker forward<->reverse COMPANION entry AND the
    // source-NAT / NAT64 pool RESERVATION were both left behind — a resource
    // leak the ordinary idle reap (`reap_expired_sessions`) and the DSCP-filter
    // purge (`purge_sessions_for_input_dscp_filter_revalidation`) already avoid
    // by releasing per entry. Tear down BOTH halves and release each allocation
    // exactly as the reap path does per `ExpiredSession`.
    //
    // The companion key is recovered with `reverse_session_key(key, nat)` from
    // the resolved entry's OWN nat decision — the transform is its own inverse
    // given the reversed decision, so it yields the forward key from a reverse
    // hit and the reverse key from a forward hit (the same hop
    // `companion_keeps_alive` / `account_packet` use). The allocation release
    // self-gates on `is_reverse` and keys on the forward flow, so freeing both
    // halves returns the reservation EXACTLY ONCE (the reverse call is a no-op)
    // — no double free. `release_flow` is idempotent (returns false when the
    // flow was already freed), so a caller that hands both halves in turn (the
    // DSCP purge) stays correct too.
    let companion_key = reverse_session_key(key, decision.nat);
    let companion = if companion_key != *key {
        sessions.entry_with_origin(&companion_key)
    } else {
        None
    };

    delete_terminal_half(
        worker_id,
        sessions,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        peer_worker_commands,
        worker_commands_by_id,
        forwarding,
        key,
        decision,
        metadata,
        origin,
        now_ns,
    );

    if let Some((companion_decision, companion_metadata, companion_origin)) = companion {
        delete_terminal_half(
            worker_id,
            sessions,
            session_map_fd,
            conntrack_v4_fd,
            conntrack_v6_fd,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            peer_worker_commands,
            worker_commands_by_id,
            forwarding,
            &companion_key,
            companion_decision,
            &companion_metadata,
            companion_origin,
            now_ns,
        );
    }
}

/// #5622: tear down ONE direction of a terminal-filtered session — release its
/// source-NAT / NAT64 pool reservation (self-gated on `is_reverse`, so only the
/// forward half actually frees), drop its live BPF/session-map + conntrack
/// aliases, remove it from the worker-local table + the shared HA maps, queue
/// the cross-worker `DeleteSynced`, and emit its close delta (suppressed for a
/// reverse entry). Called once per direction by `delete_terminal_filtered_session`
/// so a translated LocalDelivery terminal hit performs the SAME full-pair
/// teardown the idle reap and DSCP purge do.
#[allow(clippy::too_many_arguments)]
fn delete_terminal_half(
    worker_id: u32,
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    // #8114 item 4: the same queues keyed by worker id, so a `DeleteSynced` a
    // full sibling queue REFUSES can be attributed and that sibling's NAT
    // holder bit released on its behalf. See
    // `replicate_session_delete_repairing`.
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    now_ns: u64,
) {
    release_source_nat_allocation_for_worker(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        key,
        decision.nat,
        metadata.is_reverse,
        now_ns,
        worker_id,
    );
    crate::nat64::release_nat64_allocation_for_worker(
        &forwarding.nat64,
        key,
        decision.nat,
        metadata.is_reverse,
        now_ns,
        worker_id,
    );
    delete_session_map_entry_for_removed_session_with_origin(
        session_map_fd,
        key,
        decision,
        metadata,
        origin,
        conntrack_v4_fd,
        conntrack_v6_fd,
    );
    sessions.delete(key);
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
    );
    replicate_session_delete_repairing(
        peer_worker_commands,
        worker_commands_by_id,
        forwarding,
        key,
        decision.nat,
        metadata.is_reverse,
        now_ns,
    );
    sessions.emit_close_delta_with_origin(key.clone(), decision, metadata.clone(), origin);
}

/// #2442: the filter half of `export_forward_sessions_for_owner_rgs`. Walks the
/// owner-RG index and returns the export candidates (forward, locally-owned,
/// forwarding-disposition sessions) WITHOUT pushing any delta. Both callers
/// re-emit through the SAME `chunked_drain_as_you_export!` macro in
/// `worker::loop_body` (#2653): the `ExportOwnerRGSessions` command path (now
/// recorded in `WorkerCommandResults.export_owner_rgs`, not emitted inline) and
/// the loss-of-sync resync path both emit in `RESYNC_EXPORT_CHUNK`-sized chunks,
/// draining the ring to empty between chunks so a worker owning up to
/// `DEFAULT_MAX_SESSIONS` (32× the delta ring) never re-overflows the ring it is
/// trying to recover, and ship a complete snapshot.
pub(crate) fn forward_export_candidates_for_owner_rgs(
    sessions: &SessionTable,
    owner_rgs: &[i32],
) -> Vec<(SessionKey, SessionDecision, SessionMetadata, SessionOrigin)> {
    if owner_rgs.is_empty() {
        return Vec::new();
    }
    let mut export = Vec::new();
    for key in sessions.owner_rg_session_keys(owner_rgs) {
        let Some((decision, metadata, origin)) = sessions.entry_with_origin(&key) else {
            continue;
        };
        if metadata.is_reverse
            || origin.is_peer_synced()
            || origin.is_transient_local_seed()
            || metadata.fabric_ingress
        {
            continue;
        }
        if !matches!(
            decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
        ) {
            continue;
        }
        export.push((key, decision, metadata, origin));
    }
    export
}

// #2442: widened from `pub(in crate::afxdp::session_glue)` to `pub(crate)` so
// the session-module resync test can re-emit owned forward sessions through the
// same table-truth walk the `ExportOwnerRGSessions` command uses.
//
// #2653: this naive "emit the whole candidate set at once" helper is no longer
// on the production path. BOTH the worker-loop loss-of-sync resync AND the
// single-shot `ExportOwnerRGSessions` command now use the chunked
// drain-as-you-export (collect via `forward_export_candidates_for_owner_rgs`
// -> emit in < ring-cap chunks -> drain between chunks, see `worker::loop_body`)
// so a worker owning more sessions than the 4096-slot ring never overflows it
// mid-export. The unbounded helper is retained only as a test fixture that
// drives the candidate-selection walk directly (forward yes, reverse /
// peer-synced / transient-seed / fabric-ingress no), hence `#[cfg(test)]`.
#[cfg(test)]
pub(crate) fn export_forward_sessions_for_owner_rgs(
    sessions: &mut SessionTable,
    owner_rgs: &[i32],
) {
    for (key, decision, metadata, origin) in
        forward_export_candidates_for_owner_rgs(sessions, owner_rgs)
    {
        sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
    }
}

pub(super) fn apply_worker_commands(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    _conntrack_v4_fd: c_int,
    _conntrack_v6_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    // #6211 F2: THIS worker's id, threaded from `WorkerLaunchPlan::worker_id`
    // in the worker loop. A peer-synced reservation is held by every worker, so
    // a release must drop THIS worker's bit rather than free the port outright.
    worker_id: u32,
    // #7201: worker-owned, recycled across calls. The drain moves its bounded
    // slice in here instead of `mem::take`-ing the shared deque, so the shared
    // deque keeps its allocation (the producers hold the lock; they were paying
    // to regrow it from zero capacity on every pass) and this buffer keeps its
    // own. Entered empty and left empty — the dispatch loop below drains it.
    scratch: &mut VecDeque<WorkerCommand>,
) -> WorkerCommandResults {
    // Hot path: try_lock avoids blocking on the mutex when another thread
    // holds it (rare) and avoids the cost of lock+unlock on empty queues
    // when there's nothing to do (common case during steady-state forwarding).
    // #1807: a poisoned mutex is recovered (committed-prefix + clear_poison
    // policy, worker_queue.rs) and the recovered deque is processed as
    // normal — treating poison as absence-of-work made the worker
    // permanently deaf to coordinator commands.
    //
    // #7201: this takes a BOUNDED PREFIX, not the whole deque. Every command is
    // a session-table mutation plus a BPF-map publish syscall, and the worker
    // does not touch its AF_XDP rings until the loop below finishes — so an
    // unbounded drain is unserviced ring time. See
    // `worker_queue::WORKER_COMMAND_DRAIN_BUDGET` for the measurement and the
    // ring arithmetic that fix the slice size.
    let commands_backlogged = match worker_queue::try_lock_recover(commands) {
        Some(mut pending) => {
            if pending.is_empty() {
                return WorkerCommandResults::empty();
            }
            worker_queue::drain_bounded_into(&mut pending, scratch)
        }
        None => {
            // Could not take the lock this pass. The queue is not known to be
            // empty — a producer holds it — but reporting a backlog here would
            // pin the loop to `did_work` on nothing more than lock contention,
            // so leave it to the next pass, which is one poll away.
            return WorkerCommandResults::empty();
        }
    };
    // Sample monotonic time ONCE per tick so every handler sees the same
    // `now_ns` / `now_secs` and there is no intra-tick clock skew between
    // session-table side effects (#1346 plan v2 invariant 3).
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let mut cancelled_keys: Vec<SessionKey> = Vec::new();
    // #6457: keys dropped by `DeleteSynced` this tick, drained by the
    // worker loop into per-binding flow-cache invalidations (the struct
    // field comment carries the full rationale). Not pre-sized — delete
    // bursts are control-plane paced and the common no-delete tick pays
    // no allocation (same policy as `cancelled_keys`).
    let mut deleted_synced_keys: Vec<SessionKey> = Vec::new();
    // #5155: companion dedup set for `handle_demote_owner_rgs`. Kept
    // beside `cancelled_keys` (not pre-sized) so the O(1) membership
    // test persists across the multiple DemoteOwnerRGS arms in one
    // dispatch loop while common (no-demote) ticks pay no allocation.
    let mut cancelled_keys_seen: rustc_hash::FxHashSet<SessionKey> =
        rustc_hash::FxHashSet::default();
    let mut exported_sequences = Vec::new();
    let mut session_counter_answers: Vec<SessionCounterAnswer> = Vec::new();
    let mut export_owner_rgs: Vec<i32> = Vec::new();
    let mut shaped_tx_requests = Vec::new();
    let mut vacate_all_shared_exact_slots = false;
    for cmd in scratch.drain(..) {
        match cmd {
            WorkerCommand::DemoteOwnerRGS { owner_rgs } => {
                commands::handle_demote_owner_rgs(
                    sessions,
                    session_map_fd,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    owner_rgs,
                    now_ns,
                    now_secs,
                    &mut cancelled_keys,
                    &mut cancelled_keys_seen,
                );
            }
            WorkerCommand::RefreshOwnerRGS { owner_rgs } => {
                commands::handle_refresh_owner_rgs(
                    sessions,
                    session_map_fd,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    owner_rgs,
                    now_ns,
                    now_secs,
                );
            }
            WorkerCommand::ExportOwnerRGSessions {
                sequence,
                owner_rgs,
            } => {
                commands::handle_export_owner_rg_sessions(
                    &mut exported_sequences,
                    &mut export_owner_rgs,
                    sequence,
                    owner_rgs,
                );
            }
            WorkerCommand::QuerySessionCounters { sequence, key } => {
                // READ-ONLY. `counters_with_replica_flag` looks the key up
                // without touching the table; nothing here installs, refreshes
                // or expires anything. A diagnostic that perturbed the state it
                // reports would be worse than no diagnostic.
                let answer = match sessions.counters_with_replica_flag(&key) {
                    Some((counters, replica)) => SessionCounterAnswer {
                        sequence,
                        found: true,
                        replica,
                        fwd_packets: counters.fwd_packets,
                        fwd_bytes: counters.fwd_bytes,
                        rev_packets: counters.rev_packets,
                        rev_bytes: counters.rev_bytes,
                    },
                    None => SessionCounterAnswer {
                        sequence,
                        found: false,
                        replica: false,
                        fwd_packets: 0,
                        fwd_bytes: 0,
                        rev_packets: 0,
                        rev_bytes: 0,
                    },
                };
                session_counter_answers.push(answer);
            }
            WorkerCommand::UpsertSynced(entry) => {
                commands::handle_upsert_synced(
                    sessions,
                    session_map_fd,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    entry,
                    now_ns,
                    now_secs,
                    worker_id,
                );
            }
            WorkerCommand::UpsertLocal(entry) => {
                // Kept inline (#1346 plan v2 §4.1): lifting a short
                // delegate to its own sibling file is negative value.
                //
                // #1870: local-tunnel pair entries are coordinator-
                // authoritative replicas of state ALREADY published to
                // the shared maps (the tunnel.rs publish precedes the
                // enqueue). Routing them through the capped
                // install_with_protocol_with_origin let max_sessions
                // refuse the worker-table copy while the reactive
                // shared-hit materialization
                // (materialize_shared_session_hit) reinstalls the
                // reverse entry uncapped on the next reply packet — a
                // futile cap that only polluted create_drops and
                // delayed/voided the prewarm. Use the uncapped
                // sync-family install these SyncImport-origin entries
                // belong to. allow_replace_local=true preserves the
                // pre-#1870 replace semantics (the capped install
                // clobbered any same-key entry below cap); the data is
                // locally generated — the producer only runs when the
                // tunnel resolution is ForwardCandidate
                // (build_local_origin_tunnel_tx_request) — so the
                // "don't let peer data clobber local sessions" guard
                // does not apply.
                debug_assert!(
                    entry.origin.is_peer_synced(),
                    "UpsertLocal entries must carry a sync-family origin; a \
                     local origin would have pushed an HA delta on the old \
                     install path"
                );
                let installed = sessions.upsert_synced_with_origin(
                    SessionInstall {
                        key: entry.key,
                        decision: entry.decision,
                        metadata: entry.metadata,
                        origin: entry.origin,
                        now_ns,
                        protocol: entry.protocol,
                        tcp_flags: entry.tcp_flags,
                        // #5212: preserve the entry's id (a local-tunnel replica
                        // carries 0 => fresh local alloc, the pre-#5212 behavior).
                        session_id: entry.session_id,
                    },
                    /* allow_replace_local = */ true,
                );
                // The only false exit is the local-clobber guard, which
                // allow_replace_local=true bypasses — infallible by
                // construction (#1855 contract: assert in debug, inert
                // in release).
                debug_assert!(
                    installed,
                    "upsert_synced_with_origin(_, true) is infallible"
                );
                let _ = installed;
            }
            WorkerCommand::DeleteSynced(key) => {
                commands::handle_delete_synced(
                    sessions,
                    session_map_fd,
                    forwarding,
                    ha_state,
                    key,
                    now_ns,
                    now_secs,
                    &mut deleted_synced_keys,
                    worker_id,
                );
            }
            WorkerCommand::EnqueueShapedLocal(req) => {
                // Trivial variant — kept inline (#1346 plan v2 §4.1).
                shaped_tx_requests.push(req);
            }
            WorkerCommand::InstallPptpCall { call, control, learned_ns } => {
                // #7699: learn the association on THIS worker. A collision is
                // refused rather than merged (two calls sharing one handle
                // share one session), and counted so a refusal is not silent.
                if let Err(e) = sessions.pptp_mut().install(call, control, learned_ns) {
                    debug_log!("PPTP association refused: {:?}", e);
                }
            }
            WorkerCommand::ForgetPptpCall(handle) => {
                // #7699: a stale association re-pairs a REUSED 16-bit call id
                // onto a dead handle, so teardown must land on every worker.
                sessions.pptp_mut().remove(handle);
            }
            WorkerCommand::VacateAllSharedExactSlots => {
                // Trivial variant — kept inline (#1346 plan v2 §4.1).
                // #941 Work item C: signal the outer poll loop to vacate
                // all shared_exact slots (we don't have BindingWorker
                // access here, so we set the flag and let
                // `worker.rs:818-822` dispatch).
                vacate_all_shared_exact_slots = true;
            }
        }
    }
    WorkerCommandResults {
        cancelled_keys,
        deleted_synced_keys,
        exported_sequences,
        session_counter_answers,
        export_owner_rgs,
        shaped_tx_requests,
        vacate_all_shared_exact_slots,
        commands_backlogged,
    }
}


/// #4800: calls to [`replicate_session_upsert`] (one per new flow), and the
/// total number of `UpsertSynced` commands those calls enqueued — the
/// second is `calls * sibling_worker_count`, so the ratio recovers the
/// N-way fan-out multiplier without the analysis layer having to know the
/// worker count out of band.
pub(crate) static SESSION_REPLICATION_UPSERTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SESSION_REPLICATION_ENQUEUED: AtomicU64 = AtomicU64::new(0);

/// #4800: sibling worker-queue mutex acquisitions in
/// [`replicate_session_upsert`] that found the queue already held.
///
/// The denominator is `SESSION_REPLICATION_ENQUEUED`, which is incremented
/// once per sibling IMMEDIATELY BEFORE that sibling's acquisition — so the
/// pair is a ratio over acquisitions actually ATTEMPTED, at every instant and
/// not merely once a call has returned. Booking the whole fan-out up front
/// (the pre-fix order) understated contention by the sibling count for any
/// scrape landing mid-call.
pub(crate) static SESSION_REPLICATION_LOCK_CONTENDED: AtomicU64 = AtomicU64::new(0);

/// #4800: sum of the per-call deepest sibling-queue depth observed at
/// replication push time. Divided by `SESSION_REPLICATION_UPSERTS` over the
/// same window this is the MEAN worst-sibling depth per replicated flow —
/// the queue-backlog statistic the analysis layer actually uses.
///
/// This exists because the high-water max below CANNOT be differenced. A
/// process-lifetime `fetch_max` never falls, so across any window
/// `after - before == 0` means either "no backlog" or "a backlog up to the
/// previous all-time high" — ambiguous over the entire useful range — while
/// the absolute value stays elevated forever after one spike. Reading the
/// max as a window value made every cell after the first spike report a
/// replication backlog, which is exactly the site the #2852 Phase-2
/// decision turns on: a systematic bias toward the wrong answer. A SUM is
/// differenceable by construction and carries no history into the next
/// window.
///
/// Contention and depth remain distinct findings: contention says producers
/// collided on the mutex, depth says the consuming worker is not draining as
/// fast as producers enqueue. Different failures, different remedies.
///
/// Accumulated once per call (the max across this call's siblings) rather
/// than once per enqueue, so the cost stays O(1) in the sibling count.
pub(crate) static SESSION_REPLICATION_QUEUE_DEPTH_SUM: AtomicU64 = AtomicU64::new(0);

/// #4800: high-water sibling-queue depth observed at replication push time
/// (monotonic max, never reset).
///
/// OPERATOR GAUGE ONLY — "the deepest this queue has ever been since the
/// helper started". It is deliberately NOT an input to any harness verdict:
/// see `SESSION_REPLICATION_QUEUE_DEPTH_SUM` above for why a lifetime max
/// cannot answer a per-window question. Do not wire it back into an
/// attribution; `newflow_ceiling_analyze.py` has a guard test asserting it
/// cannot produce a culprit.
///
/// Sampled once per call (the max across this call's siblings) rather than
/// once per enqueue, so the cost is O(1) in the sibling count.
pub(crate) static SESSION_REPLICATION_QUEUE_DEPTH_MAX: AtomicU64 = AtomicU64::new(0);

pub(super) fn replicate_session_upsert(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    entry: &SyncedSessionEntry,
) {
    // #4800: in test builds only, hold the shared side of the counter lock for
    // the whole fan-out, so a reading test excludes this mover without the
    // caller having to opt in. The previous hand-written inventory had already
    // missed two real movers (`coordinator::sync_worker_session_tables` and
    // `promote::maybe_promote_synced_session`).
    //
    // This does NOT make the mover set closed: the `SESSION_REPLICATION_*`
    // statics are `pub(crate)` and any module can bump one directly, and
    // `worker_queue::lock_recover_counting` takes an arbitrary counter. It
    // covers the movers reachable through today's call graph, which is a
    // convention, not an invariant. See `afxdp::counter_test_lock`.
    #[cfg(test)]
    let _counter_guard = crate::afxdp::counter_test_lock::counter_mover_guard();
    let replica = synced_replica_entry(entry);
    // #4800: two O(1) counter updates per call rather than per sibling.
    SESSION_REPLICATION_UPSERTS.fetch_add(1, Ordering::Relaxed);
    let mut deepest = 0u64;
    for commands in worker_commands {
        // #4800: count this sibling's acquisition ATTEMPT immediately before
        // making it, NOT the whole fan-out up front.
        //
        // Pre-booking `worker_commands.len()` here made the contention ratio
        // structurally wrong for any scrape taken mid-call, which is every
        // scrape under load. With 16 sibling queues and queue 0 held, the old
        // order recorded 16 enqueues and 1 contended acquisition and then
        // BLOCKED — a scrape in that window reports 6.25% contention, under the
        // analyzer's 10% threshold, while 100% of the acquisitions actually
        // attempted had blocked. The denominator counted work that had not been
        // tried yet. Incrementing per iteration keeps `contended <= enqueued` a
        // ratio over ATTEMPTED acquisitions at every instant, and leaves the
        // at-rest value identical (every attempt completes), so the fan-out
        // ratio `enqueued / upserts` is unchanged.
        SESSION_REPLICATION_ENQUEUED.fetch_add(1, Ordering::Relaxed);
        // #1807: recover-and-push — `if let Ok` silently DROPPED the
        // UpsertSynced replica for a poisoned worker queue.
        // #4800: ...and count the acquisitions that had to block.
        let mut pending =
            worker_queue::lock_recover_counting(commands, &SESSION_REPLICATION_LOCK_CONTENDED);
        worker_queue::push_bounded(&mut pending, WorkerCommand::UpsertSynced(replica.clone()));
        deepest = deepest.max(pending.len() as u64);
    }
    if deepest != 0 {
        // The SUM is the differenceable statistic the harness reads; the MAX
        // is the operator's all-time high-water and is never a verdict input.
        SESSION_REPLICATION_QUEUE_DEPTH_SUM.fetch_add(deepest, Ordering::Relaxed);
        SESSION_REPLICATION_QUEUE_DEPTH_MAX.fetch_max(deepest, Ordering::Relaxed);
    }
}

/// #8114 item 4: a `DeleteSynced` a sibling worker's queue REFUSED, because it
/// was already at `MAX_PENDING_WORKER_COMMANDS`.
///
/// Counted separately from `WORKER_COMMAND_QUEUE_DROPS` (which counts every
/// refused command of any kind) because the consequences of losing a DELETE are
/// specific: the sibling keeps its local session entry and flow-cache slot for a
/// session that no longer exists, AND keeps its NAT holder bit, so the
/// reservation is held for the life of the allocator.
pub(crate) static SESSION_DELETE_REPLICA_DROPPED: AtomicU64 = AtomicU64::new(0);

/// #9048: a peer `DeleteSynced` REFUSED because the key named a live session
/// this node created itself and is actively forwarding for.
///
/// Non-zero means the cluster is, or recently was, DUAL-PRIMARY for some
/// redundancy group: the delta emitter is gated on `IsPrimaryForRGFn`, so in
/// normal operation exactly one node emits deletes and the receiver's entries
/// at those keys carry a peer-synced origin, leaving the guard inert. A
/// climbing count is therefore a split-brain indicator, not a tuning knob —
/// and it is deliberately a COUNTER rather than a log line, because the
/// condition that produces it produces one per closing flow.
///
/// The refusal is the conservative side of the trade: a session that lingers
/// until it ages out, against a live flow torn down mid-transfer.
pub(crate) static PEER_DELETE_REFUSED_LOCAL_OWNED: AtomicU64 = AtomicU64::new(0);

/// #8114 item 4: refused deletes whose owning worker was IDENTIFIED and whose
/// NAT teardown was therefore run on its behalf.
///
/// The difference `SESSION_DELETE_REPLICA_DROPPED - SESSION_DELETE_REPLICA_DROP_REPAIRED`
/// is the number of refused deletes that could not be attributed to a worker id
/// — a caller that had no `worker_commands_by_id` to resolve against. It is
/// deliberately a SECOND counter rather than a conditional increment of the
/// first: a single number could not distinguish "no drops" from "drops nobody
/// repaired", and those have opposite remediations.
pub(crate) static SESSION_DELETE_REPLICA_DROP_REPAIRED: AtomicU64 = AtomicU64::new(0);

/// #8586: per-worker epoch, bumped when a cross-worker `DeleteSynced` replica
/// for THAT worker was refused by its full queue.
///
/// It is the out-of-band signal the refused worker needs, and it has to be
/// out-of-band by construction: the thing that must reach it cannot travel
/// through the queue that is full. One relaxed load per worker per loop pass on
/// the read side, one relaxed increment per refusal on the write side.
///
/// WHY IT COUNTS DELETES AND NOT QUEUE PRESSURE. Measured on
/// `loss:xpf-userspace-fw0` (#8586): ordinary session ESTABLISHMENT pins the
/// queue at the 4096 cap and discards 85,668 commands over 32,768 creates —
/// and ZERO of them are deletes. What is lost there is `UpsertSynced` replicas,
/// whose content the shared map still holds. A trigger keyed on queue depth, or
/// on `WORKER_COMMAND_QUEUE_DROPS`, would therefore fire continuously through
/// normal traffic and reconcile nothing. The harmful loss is confined to a
/// revocation burst or an RG activation: one `clear security flow session` over
/// 32,770 entries refused 30,786 delete replicas, and the two conditions come
/// apart cleanly enough to key on.
///
/// Indexed by worker id, bounded by `MAX_NAT_HOLDER_WORKERS` — the same ceiling
/// `replan_bindings` refuses to mint past, so a worker id is always in range.
/// A refusal whose worker id could NOT be resolved bumps nothing: there is no
/// worker to name. Those are the `SESSION_DELETE_REPLICA_DROPPED -
/// SESSION_DELETE_REPLICA_DROP_REPAIRED` remainder, measured at 0 across 30,786
/// refusals.
pub(crate) static SESSION_DELETE_DROP_EPOCH: [AtomicU64;
    crate::nat::MAX_NAT_HOLDER_WORKERS as usize] =
    [const { AtomicU64::new(0) }; crate::nat::MAX_NAT_HOLDER_WORKERS as usize];

/// #8586: read a worker's delete-drop epoch. Out of range reads 0 (an id past
/// the planner's own ceiling cannot have been bumped either, so the pair is
/// consistent and a reconcile is never raised for a worker that cannot exist).
pub(crate) fn session_delete_drop_epoch(worker_id: u32) -> u64 {
    SESSION_DELETE_DROP_EPOCH
        .get(worker_id as usize)
        .map(|e| e.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// #8114 item 4: what one `replicate_session_delete_repairing` fan-out did,
/// per call.
///
/// `dropped` counts sibling queues that REFUSED the delete; `repaired` counts
/// the subset of those whose worker id resolved, so the NAT teardown ran on
/// their behalf. `dropped - repaired` is the unattributable remainder — a caller
/// with no id map to resolve against. Two fields rather than one because a
/// single number cannot distinguish "no drops" from "drops nobody repaired", and
/// those have opposite remediations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DeleteReplicationOutcome {
    pub(super) dropped: u32,
    pub(super) repaired: u32,
}

/// Resolve a worker command queue to the worker id that owns it.
///
/// By `Arc` IDENTITY, not by position: `peer_worker_commands` is built in
/// `reconcile/bringup.rs` as
/// `.filter(|(id, _)| **id != worker_id).map(|(_, queue)| queue.clone())`, so the
/// ids are gone by the time the fan-out sees the slice, and its ORDER relative
/// to the id-keyed map depends on which worker is excluded. Asking the map
/// "which id is THIS allocation?" cannot desynchronise the way a parallel
/// `&[u32]` would — the two structures hold the same `Arc`s, not the same facts
/// written down twice.
///
/// `None` when the caller passed a map that does not contain the queue, which is
/// the case for fixtures that do not exercise the repair. That is a no-op, not a
/// wrong repair.
fn worker_id_for_command_queue(
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    queue: &Arc<Mutex<VecDeque<WorkerCommand>>>,
) -> Option<u32> {
    worker_commands_by_id
        .iter()
        .find(|(_, candidate)| Arc::ptr_eq(candidate, queue))
        .map(|(id, _)| *id)
}

pub(super) fn replicate_session_delete(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    key: &SessionKey,
) {
    for commands in worker_commands {
        // #1807: recover-and-push — `if let Ok` silently DROPPED the
        // DeleteSynced replica for a poisoned worker queue.
        let mut pending = worker_queue::lock_recover(commands);
        if !worker_queue::push_bounded(&mut pending, WorkerCommand::DeleteSynced(key.clone())) {
            // #8114 item 4: still unrepaired on this path — see
            // `replicate_session_delete_repairing`. Counted so the drop is not
            // silent even where it cannot be repaired.
            SESSION_DELETE_REPLICA_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// #8114 item 4: `replicate_session_delete`, plus the NAT teardown a sibling
/// worker will now never run because its queue refused the `DeleteSynced`.
///
/// The drop is not a missed optimisation. `handle_delete_synced` is what a
/// worker does with the command, and it releases that worker's source-NAT and
/// NAT64 holder bits; the port is freed by whichever worker drops the LAST bit.
/// A worker that never receives the command never drops its bit, so the
/// reservation is held for the life of the allocator — the same stranding
/// `Coordinator::delete_synced_session_gen` repairs on the control-plane side
/// (#6979 F4, whose probe recorded "queue-drop delta 1, pool port still
/// occupied, `dead` false, dead-worker sweep freed 0").
///
/// WHY RELEASING ON ITS BEHALF CANNOT OVER-RELEASE, which is the direction of
/// error that would matter: the command was REFUSED, so that worker will never
/// run this teardown itself, and `release_flow` no-ops unless the allocator's
/// `live_by_flow[flow].translated` equals this exact tuple — so a worker whose
/// own `UpsertSynced` is still queued (no reservation taken yet) is untouched.
/// The rule at `PortAllocator::drop_holder_locked` is satisfied: this clears the
/// bit of a worker that provably cannot forward this flow again. It is also why
/// "just release for every worker id" is NOT a substitute for resolving the id —
/// that would clear the bit of a worker still forwarding the flow, and its port
/// could then be handed to another.
///
/// NOT REPAIRED HERE, deliberately, and it is the half the issue names first:
/// the sibling also never deletes its LOCAL session-table entry or invalidates
/// its flow-cache slots, so it can keep serving the revoked session until the
/// entry ages out. Neither is reachable from this thread — both live behind that
/// worker's `&mut SessionTable` and its own per-binding caches — and the signal
/// that would have to reach it cannot travel through the queue that is full. The
/// NAT reservation is the part with no other owner, so it is the part repaired.
///
/// Returns a PER-CALL [`DeleteReplicationOutcome`] as well as bumping the
/// process-wide counters. The counters are the operator signal; the return
/// value is what a cell can assert on without racing every other test in the
/// binary, which the globals cannot offer (they are shared across the parallel
/// test threads, so `before + 1` is a flake waiting for a busy run).
#[allow(clippy::too_many_arguments)]
pub(super) fn replicate_session_delete_repairing(
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> DeleteReplicationOutcome {
    let mut outcome = DeleteReplicationOutcome::default();
    for commands in peer_worker_commands {
        let mut pending = worker_queue::lock_recover(commands);
        let queued =
            worker_queue::push_bounded(&mut pending, WorkerCommand::DeleteSynced(key.clone()));
        // Release the command queue BEFORE touching allocator mutexes: the two
        // are unrelated locks and holding both would invent an ordering, which
        // is the lock-graph change a green suite cannot see.
        drop(pending);
        if queued {
            continue;
        }
        SESSION_DELETE_REPLICA_DROPPED.fetch_add(1, Ordering::Relaxed);
        outcome.dropped += 1;
        let Some(worker_id) = worker_id_for_command_queue(worker_commands_by_id, commands) else {
            continue;
        };
        SESSION_DELETE_REPLICA_DROP_REPAIRED.fetch_add(1, Ordering::Relaxed);
        outcome.repaired += 1;
        // #8586: tell the refused worker. Its local session entry and its
        // flow-cache slots for this key are the half #8576 could not repair
        // from here — they live behind that worker's own `&mut SessionTable`
        // and per-binding caches — so it has to reconcile them itself, and the
        // signal cannot go through the queue that just refused the command.
        if let Some(epoch) = SESSION_DELETE_DROP_EPOCH.get(worker_id as usize) {
            epoch.fetch_add(1, Ordering::Relaxed);
        }
        // Byte-for-byte the two releases `handle_delete_synced` would have run,
        // with that worker's id as the holder, so the mask empties on the same
        // last-release rule and the port is returned exactly once.
        release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            key,
            nat,
            is_reverse,
            now_ns,
            worker_id,
        );
        crate::nat64::release_nat64_allocation_for_worker(
            &forwarding.nat64,
            key,
            nat,
            is_reverse,
            now_ns,
            worker_id,
        );
    }
    outcome
}

/// #8586: drop this worker's LOCAL entries for peer-synced sessions that shared
/// authority no longer holds, and hand their keys back for flow-cache eviction.
///
/// This is the half of a refused cross-worker `DeleteSynced` that #8576 could
/// not repair from the DELETING worker: that worker released the refused
/// worker's NAT holder bit on its behalf, but the refused worker's own session
/// entry and per-binding flow-cache slots live behind its `&mut SessionTable`
/// and are reachable only from its own loop. The signal that it must run this
/// cannot travel through the queue that refused the command, which is why the
/// trigger is the out-of-band `SESSION_DELETE_DROP_EPOCH`.
///
/// SCOPED BY `SessionOrigin::is_peer_synced()`, and the exclusions are the
/// safety property rather than a detail:
///
/// - `SharedPromote` is EXCLUDED, and it is the one a reader would expect to be
///   in. It is synced-DERIVED but no longer peer-AUTHORITATIVE: it is the origin
///   an entry receives after local traffic has promoted it, so this node owns it
///   and shared authority is not the arbiter of whether it should exist.
///   Reconciling it away would delete a live local session. (`loop_body`'s
///   "synced-derived, never create-counted" arm DOES include `SharedPromote`;
///   it asks a different question and is correct for it. Using that
///   classification here would be the bug.)
/// - `FabricPuntSeed` and `MissingNeighborSeed` are transient-local by
///   construction — never HA-exported, never Open-delta'd — so they are live
///   local sessions that are ABSENT from the shared map by design. A naive
///   "drop what the shared map does not have" sweep deletes them on its first
///   pass. That is the worse-failure-mode #8586 declined to build against an
///   unestablished premise, and `is_peer_synced()` excludes them.
///
/// What it deliberately does NOT do: release NAT, remove shared state, or
/// replicate a delete. The deleting worker already removed shared authority and
/// already ran #8576's NAT teardown for THIS worker's holder bit; repeating
/// either here would double-process a pair, and re-replicating would recurse.
/// Local table plus local caches is the whole remit.
///
/// The shared-map lock is held only across the membership FILTER, not across
/// the table walk: the walk clones candidate keys first. Sibling workers take
/// that same lock on their packet path, and a full-table walk under it would
/// stall them for the length of this worker's session table.
/// Run the delete-drop reconcile to completion.
///
/// #9327: the worker loop no longer calls this — it steps a [`DeleteDropSweep`]
/// across passes so no single pass exceeds the ring-fill budget. This wrapper
/// is the whole-table semantics in one call, which is what the behavioural
/// cells (#8586: which ORIGINS are swept) want to assert without modelling the
/// pacing. Keeping the semantics and the pacing testable separately is the
/// point: a cell that had to drive the cursor to check an origin rule would be
/// asserting two things at once.
pub(in crate::afxdp) fn reconcile_peer_synced_against_shared(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    evicted_keys: &mut Vec<SessionKey>,
) -> usize {
    let mut sweep = DeleteDropSweep::default();
    sweep.arm();
    let mut total = 0;
    while sweep.is_running() {
        total += sweep.step(sessions, shared_sessions, evicted_keys);
    }
    total
}

pub(super) fn should_teardown_tcp_rst(_meta: UserspaceDpMeta, _flow: Option<&SessionFlow>) -> bool {
    // Do not immediately delete live sessions on an observed TCP RST.
    //
    // On the current HA userspace dataplane, stray or misclassified reply-side
    // RSTs can appear while the real flow is still active. Immediate teardown
    // removes the pinned live-session keys from USERSPACE_SESSIONS, which then
    // causes userspace-xdp to stop redirecting valid reply traffic and the
    // kernel to emit follow-on RSTs that collapse the connection entirely.
    //
    // The session table already marks TCP entries as closing when FIN/RST is
    // seen and ages them on the shorter TCP_CLOSING timeout. Rely on that
    // path for now until RST provenance is made trustworthy again.
    false
}

pub(super) fn teardown_tcp_rst_flow(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forward_key: &SessionKey,
    nat: NatDecision,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    let reverse_key = reverse_session_key(forward_key, nat);
    sessions.delete(forward_key);
    sessions.delete(&reverse_key);
    delete_live_session_entry(current.bpf_maps.session_map_fd, forward_key, nat, false);
    delete_live_session_entry(current.bpf_maps.session_map_fd, &reverse_key, nat, true);
    delete_bpf_conntrack_entry(
        current.bpf_maps.conntrack_v4_fd,
        current.bpf_maps.conntrack_v6_fd,
        forward_key,
    );
    delete_bpf_conntrack_entry(
        current.bpf_maps.conntrack_v4_fd,
        current.bpf_maps.conntrack_v6_fd,
        &reverse_key,
    );
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        forward_key,
    );
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        &reverse_key,
    );
    replicate_session_delete(peer_worker_commands, forward_key);
    replicate_session_delete(peer_worker_commands, &reverse_key);
    cancel_pending_forwards(current, pending_forwards, forward_key, &reverse_key);
    cancel_queued_flow(
        left,
        current,
        right,
        forward_key,
        &reverse_key,
        shared_recycles,
    );
}

pub(super) fn cancel_queued_flow(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    for binding in left.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key, Some(shared_recycles));
    }
    cancel_queued_flow_on_binding(current, forward_key, reverse_key, Some(shared_recycles));
    for binding in right.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key, Some(shared_recycles));
    }
    route_cancelled_shared_recycles(left, current, right, shared_recycles);
}

fn route_cancelled_shared_recycles(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if shared_recycles.is_empty() {
        return;
    }
    for (slot, offset) in shared_recycles.drain(..) {
        if let Some(binding) = left
            .iter_mut()
            .chain(core::iter::once(&mut *current))
            .chain(right.iter_mut())
            .find(|binding| binding.slot == slot)
        {
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
        } else {
            eprintln!(
                "xpf-userspace-dp: dropping shared UMEM recycle for unknown slot {} offset {}",
                slot, offset
            );
            current.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            current
                .live
                .tx_shared_recycle_unknown_slot_drops
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(super) fn cancel_queued_flow_on_binding(
    binding: &mut BindingWorker,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
    shared_recycles: Option<&mut Vec<(u32, u64)>>,
) {
    let mut shared_recycles = shared_recycles;
    let mut kept_local = VecDeque::with_capacity(binding.tx_pipeline.pending_tx_local.len());
    while let Some(req) = binding.tx_pipeline.pending_tx_local.pop_front() {
        if tx_request_matches_flow(&req, forward_key, reverse_key) {
            continue;
        }
        kept_local.push_back(req);
    }
    binding.tx_pipeline.pending_tx_local = kept_local;

    let mut kept_prepared = VecDeque::with_capacity(binding.tx_pipeline.pending_tx_prepared.len());
    while let Some(req) = binding.tx_pipeline.pending_tx_prepared.pop_front() {
        if prepared_request_matches_flow(&req, forward_key, reverse_key) {
            recycle_cancelled_prepared(binding, &req, shared_recycles.as_deref_mut());
            continue;
        }
        kept_prepared.push_back(req);
    }
    binding.tx_pipeline.pending_tx_prepared = kept_prepared;

    // #706: the cross-worker redirect inbox (`binding.live.pending_tx`) is
    // now a lock-free MPSC ring (`MpscInbox`). In-place filtering from an
    // arbitrary thread is not safe on that structure — only the owner
    // worker may drain it. We accept that packets already sitting in the
    // redirect inbox for a now-canceled flow will drain out on the next
    // owner poll and hit the wire; the peer already saw a RST, so the
    // extra late packets are ignored (or provoke a benign RST-for-RST
    // response) rather than causing protocol harm. The worker-owned
    // `pending_tx_local` and `pending_tx_prepared` queues above are still
    // filtered because they are never touched by another thread.

    update_binding_debug_state(binding);
}

pub(super) fn cancel_pending_forwards(
    binding: &mut BindingWorker,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    let mut kept = Vec::with_capacity(pending_forwards.len());
    for req in pending_forwards.drain(..) {
        if pending_forward_matches_flow(&req, forward_key, reverse_key) {
            binding
                .tx_pipeline
                .pending_fill_frames
                .push_back(req.desc.addr);
            continue;
        }
        kept.push(req);
    }
    *pending_forwards = kept;
}

pub(super) fn recycle_cancelled_prepared(
    binding: &mut BindingWorker,
    req: &PreparedTxRequest,
    shared_recycles: Option<&mut Vec<(u32, u64)>>,
) {
    recycle_cancelled_prepared_offset_with_shared(
        &mut binding.tx_pipeline.free_tx_frames,
        &mut binding.tx_pipeline.pending_fill_frames,
        shared_recycles,
        binding.slot,
        req.recycle,
        req.offset,
    );
}

pub(super) fn tx_request_matches_flow(
    req: &TxRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

pub(super) fn prepared_request_matches_flow(
    req: &PreparedTxRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

pub(super) fn pending_forward_matches_flow(
    req: &PendingForwardRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

fn materialize_shared_session_hit(
    sessions: &mut SessionTable,
    resolved: &mut ResolvedSessionLookup,
    now_ns: u64,
    tcp_flags: u8,
) -> SessionLookup {
    if let Some(shared) = resolved.shared_entry.take() {
        let replica = synced_replica_entry(&shared);
        sessions.upsert_synced_with_origin(
            SessionInstall {
                key: replica.key.clone(),
                decision: replica.decision,
                metadata: replica.metadata.clone(),
                origin: shared.origin.materialized_shared_hit_origin(),
                now_ns,
                protocol: replica.protocol,
                tcp_flags,
                // #5212: a reactive materialize of a shared-map hit inherits the
                // shared entry's id — the peer's id for a synced session (so the
                // eventual close correlates), 0 for a local entry (fresh alloc).
                session_id: replica.session_id,
            },
            false,
        );
        return SessionLookup {
            decision: replica.decision,
            metadata: replica.metadata,
        };
    }
    resolved.lookup.clone()
}

pub(super) fn resolve_flow_session_decision(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
    now_ns: u64,
    now_secs: u64,
    protocol: u8,
    tcp_flags: u8,
    ingress_ifindex: i32,
    // #9383: the arrival frame's VLAN id, needed ONLY to resolve
    // `ingress_ifindex` (a physical bind port) to the LOGICAL unit ifindex the
    // zone ledger is keyed by. A caller with no VLAN context passes 0, which
    // resolves logical == physical for every untagged port.
    ingress_vlan_id: u16,
    fabric_ingress: bool,
    ha_startup_grace_until_secs: u64,
    // #6211 F2: THIS worker's id, threaded from `WorkerLaunchPlan::worker_id`
    // in the worker loop. A peer-synced reservation is held by every worker, so
    // a release must drop THIS worker's bit rather than free the port outright.
    worker_id: u32,
) -> Option<ResolvedFlowSessionDecision> {
    // Bundle the four shared-session refs once per call. `SharedSessionRefs`
    // is `#[derive(Copy)]`, so the three downstream uses below
    // (purge_translated_synced_hit + 2× maybe_promote_synced_session) each
    // get a free by-value copy — structurally same codegen as the
    // explicit-argument form (4 pointer-sized fields, no Drop). cargo-asm
    // 0.1.16 cannot parse this codebase's symbols, so the empirical gate
    // is the smoke-plus-test-failover pass on the loss userspace cluster.
    let shared = SharedSessionRefs {
        sessions: shared_sessions,
        nat_sessions: shared_nat_sessions,
        forward_wire_sessions: shared_forward_wire_sessions,
        owner_rg_indexes: shared_owner_rg_indexes,
    };
    if let Some(mut hit) = lookup_session_across_scopes(
        sessions,
        shared_sessions,
        shared_forward_wire_sessions,
        &flow.forward_key,
        now_ns,
        tcp_flags,
    ) {
        let hit_origin = hit.origin;
        let poison_key = hit
            .shared_entry
            .as_ref()
            .map(|entry| (&entry.key, entry.decision, &entry.metadata, entry.origin))
            .or_else(|| {
                Some((
                    hit.key.as_ref(&flow.forward_key),
                    hit.lookup.decision,
                    &hit.lookup.metadata,
                    hit_origin,
                ))
            });
        let keep_transient = poison_key.is_some_and(|(key, decision, metadata, origin)| {
            should_keep_synced_hit_transient(ha_state, now_secs, key, decision, metadata, origin)
        });
        if keep_transient && let Some((key, decision, metadata, origin)) = poison_key {
            purge_translated_synced_hit(
                sessions,
                session_map_fd,
                shared,
                key,
                decision,
                metadata,
                origin,
                forwarding,
                now_ns,
                worker_id,
            );
        }
        let resolved = if keep_transient {
            hit.lookup.clone()
        } else {
            materialize_shared_session_hit(sessions, &mut hit, now_ns, tcp_flags)
        };
        let resolved_key = hit.key.as_ref(&flow.forward_key);
        let mut decision = resolved.decision;
        let resolution_target = resolution_target_for_session(flow, decision);
        let looked_up_resolution = if hit_origin.is_peer_synced() {
            lookup_forwarding_resolution_for_synced_session(
                forwarding,
                dynamic_neighbors,
                flow,
                decision,
            )
        } else {
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision)
        };
        let looked_up_resolution = super::prefer_local_forward_candidate_for_fabric_ingress(
            forwarding,
            ha_state,
            dynamic_neighbors,
            now_secs,
            fabric_ingress,
            resolution_target,
            looked_up_resolution,
        );
        let enforced_resolution = enforce_session_ha_resolution(
            forwarding,
            ha_state,
            now_secs,
            looked_up_resolution,
            ingress_ifindex,
            ha_startup_grace_until_secs,
        );
        decision.resolution = redirect_session_via_fabric_if_needed(
            forwarding,
            enforced_resolution,
            fabric_ingress,
            resolved.metadata.ingress_zone,
        );
        let metadata = if keep_transient {
            resolved.metadata
        } else {
            maybe_promote_synced_session(
                sessions,
                session_map_fd,
                shared,
                peer_worker_commands,
                forwarding,
                resolved_key,
                decision,
                resolved.metadata,
                hit_origin,
                fabric_ingress,
                now_ns,
                protocol,
                tcp_flags,
            )
        };
        return Some(ResolvedFlowSessionDecision {
            key: resolved_key.clone(),
            decision,
            metadata,
            origin: hit_origin,
            created: false,
            install_failed: false,
        });
    }

    // #7169: the main packet path — the one that INSTALLS a reverse session
    // from the match, making the adjudication durable. Revalidate the arrival
    // zone against the session being synthesized.
    //
    // A fabric-ingress packet is exempt and must be: it arrives on the fabric
    // link from the peer node, so its arrival zone is the fabric rather than
    // the flow's logical ingress. Constraining it would break cross-chassis
    // forwarding, which is a correctness break, not a hardening.
    let reverse_ingress = if fabric_ingress {
        crate::afxdp::shared_ops::ReverseIngress::Unconstrained
    } else {
        // #9383: key the zone ledger on the LOGICAL (VLAN unit) arrival ifindex,
        // not the raw physical one `meta.ingress_ifindex` carries.
        //
        // `ifindex_to_zone_id` deliberately PROPAGATES a zoned child unit's zone
        // onto its parent's ifindex (#921/#3618), so on a trunk whose units sit
        // in different zones the physical key answers with whichever unit won the
        // propagation. Measured on a `build_forwarding_state` trunk with unit 42
        // in `lan` and unit 43 UNZONED, both `parent_ifindex = 41`:
        // `ifindex_to_zone_id[41] = Some(lan)` while
        // `resolve_ingress_logical_ifindex(41, vlan 20) = Some(43)` and
        // `ifindex_to_zone_id[43] = None`. The physical lookup answers
        // `Zone(lan)` where the logical resolution answers "unzoned" — a
        // different ANSWER, not a different spelling of the same one.
        //
        // That matters here more than at most sites: a match admitted by a wrong
        // arrival zone makes `install_reverse_session_from_forward_match` MINT a
        // reverse session, and reverse entries are exempt from zone-policy
        // re-derivation by design (`policy_revalidation.rs` gate 1), so the
        // synthesized session then rides the established fast path with no
        // further adjudication. Every zone / filter / pre-routing-NAT admission
        // site already resolves the logical unit first (#3021/#5802).
        //
        // `.unwrap_or(ingress_ifindex)` is the same fallback those sites use: an
        // untagged port, and any arrival with no `(parent, vlan)` mapping,
        // resolves logical == physical and is byte-identical to pre-#9383.
        let arrival_logical =
            crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
                forwarding,
                ingress_ifindex,
                ingress_vlan_id,
            )
            .unwrap_or(ingress_ifindex);
        match forwarding.ifindex_to_zone_id.get(&arrival_logical).copied() {
            Some(z) => crate::afxdp::shared_ops::ReverseIngress::Zone(z),
            // Fail CLOSED. An unmapped arrival interface gives nothing to
            // revalidate against, and treating that as "no constraint" would
            // reopen the hole for exactly the traffic least accounted for.
            None => crate::afxdp::shared_ops::ReverseIngress::Unzoned,
        }
    };
    let forward_match = lookup_forward_nat_across_scopes(
        sessions,
        shared_nat_sessions,
        &flow.forward_key,
        reverse_ingress,
    )?;
    let (resolved, reverse_installed) = install_reverse_session_from_forward_match(
        sessions,
        session_map_fd,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        peer_worker_commands,
        forwarding,
        ha_state,
        dynamic_neighbors,
        &flow.forward_key,
        forward_match,
        now_ns,
        now_secs,
        ha_startup_grace_until_secs,
        protocol,
        tcp_flags,
    );

    let mut decision = resolved.decision;
    let resolution_target = resolution_target_for_session(flow, decision);
    let looked_up_resolution =
        lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision);
    let looked_up_resolution = super::prefer_local_forward_candidate_for_fabric_ingress(
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
        fabric_ingress,
        resolution_target,
        looked_up_resolution,
    );
    let enforced_resolution = enforce_session_ha_resolution(
        forwarding,
        ha_state,
        now_secs,
        looked_up_resolution,
        ingress_ifindex,
        ha_startup_grace_until_secs,
    );
    decision.resolution = redirect_session_via_fabric_if_needed(
        forwarding,
        enforced_resolution,
        fabric_ingress,
        resolved.metadata.ingress_zone,
    );
    // Reverse sessions created from forward NAT matches are locally
    // created (ReverseFlow), not peer-synced, so they won't be promoted.
    let metadata = maybe_promote_synced_session(
        sessions,
        session_map_fd,
        shared,
        peer_worker_commands,
        forwarding,
        &flow.forward_key,
        decision,
        resolved.metadata,
        SessionOrigin::ReverseFlow,
        fabric_ingress,
        now_ns,
        protocol,
        tcp_flags,
    );
    Some(ResolvedFlowSessionDecision {
        key: flow.forward_key.clone(),
        decision,
        metadata,
        origin: SessionOrigin::ReverseFlow,
        // #1861 §5.4 + AGY r1 F1: `created` reports the ACTUAL install
        // outcome (was unconditionally true — session_creates over-counted
        // at cap and publish_bpf_conntrack_entry fired for a session that
        // does not exist locally). `install_failed` keeps the failed-repair
        // reply out of the flow cache so the repair re-fires per packet
        // and succeeds on the first packet after the table drops below
        // max_sessions.
        created: reverse_installed,
        install_failed: !reverse_installed,
    })
}

pub(super) fn redirect_session_via_fabric_if_needed(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    fabric_ingress: bool,
    ingress_zone: u16,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if fabric_ingress {
        return resolution;
    }
    resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone)
        .or_else(|| resolve_fabric_redirect(forwarding))
        .unwrap_or(resolution)
}

pub(super) fn enforce_session_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
) -> ForwardingResolution {
    let enforced = enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution);
    if enforced.disposition == ForwardingDisposition::HAInactive
        && should_bypass_unseeded_tunnel_ha(
            forwarding,
            ha_state,
            now_secs,
            resolution,
            ingress_ifindex,
            ha_startup_grace_until_secs,
        )
    {
        return resolution;
    }
    enforced
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
// #4800: publish + sibling-replication contention accounting for the
// new-flow-install ceiling harness. Kept in its own file rather than
// appended to `tests.rs` (already ~7k lines).
#[cfg(test)]
#[path = "newflow_contention_tests.rs"]
mod newflow_contention_tests;
// #9517: the worker publish path's routing-domain WIRING, driven against the
// `bpf_map` write recorder. Its own file for the same reason as the one above.
#[cfg(test)]
#[path = "routing_domain_publish_9517_tests.rs"]
mod routing_domain_publish_9517_tests;

// #6600: the coordinator's pre-publish NAT reservation resolves the synced zone
// pair through the SAME helper the worker-side upsert uses, so the two cannot
// land on different allocators.
pub(in crate::afxdp) use commands::upsert_synced::synced_source_nat_zone_pair;

/// #7919: one worker's answer to a `QuerySessionCounters` request.
///
/// `found` is carried separately from the counters because "I hold this session
/// and it has no traffic" and "I do not hold this session" are different facts,
/// and the query exists to tell them apart. A single zeroed row would collapse
/// them and answer neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionCounterAnswer {
    pub sequence: u64,
    pub found: bool,
    /// True when the held entry is a peer-synced/replica origin. A replica
    /// reporting VOLUME would falsify the premise the investigation rests on —
    /// that replicas are created at zero and cannot advance — so the answer
    /// carries what it would take to notice that.
    pub replica: bool,
    pub fwd_packets: u64,
    pub fwd_bytes: u64,
    pub rev_packets: u64,
    pub rev_bytes: u64,
}
