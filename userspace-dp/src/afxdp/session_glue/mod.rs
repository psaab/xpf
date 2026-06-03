use super::*;

mod commands;
mod promote;

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
    let resolved = lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target);
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
    pub exported_sequences: Vec<u64>,
    pub shaped_tx_requests: Vec<TxRequest>,
    /// #941 Work item C: set when at least one
    /// `WorkerCommand::VacateAllSharedExactSlots` was processed.
    /// `apply_worker_commands` cannot vacate directly because it has
    /// no `BindingWorker` access — the outer poll loop in `worker.rs`
    /// dispatches based on this flag.
    pub vacate_all_shared_exact_slots: bool,
    /// #1748: structured acks accumulated for each rebalance command applied
    /// this tick. The outer loop writes each into the worker's
    /// `rebalance_ack` slot + publishes the seq (Release) so the controller's
    /// barrier can confirm key + origin before proceeding.
    pub rebalance_acks: Vec<crate::afxdp::RebalanceAck>,
}

fn force_live_redirect_for_worker_synced_entry(
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    allow_replace_local: bool,
) -> bool {
    allow_replace_local && uses_kernel_local_session_map_entry(decision, metadata, origin)
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
            let _ = publish_live_session_entry(
                session_map_fd,
                key,
                decision.nat,
                metadata.is_reverse,
            );
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
    forwarding: &ForwardingState,
    purge_v4: bool,
    purge_v6: bool,
    now_ns: u64,
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
        // #1748: an interface-down / admin purge on W_old must NOT release the
        // SNAT port the abandoned RebalancedOut copy carries — W_new owns the
        // live session and the SNAT allocation. Double-release would free a
        // port W_new is still using.
        if !origin.is_rebalanced_out() {
            release_source_nat_allocation(
                &forwarding.source_nat_rules,
                &key,
                decision.nat,
                metadata.is_reverse,
                now_ns,
            );
        }
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
            &key,
            decision,
            &metadata,
            origin,
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
    let uses_kernel_local = uses_kernel_local_session_map_entry(decision, metadata, origin);
    if uses_kernel_local && has_lo0_filter {
        // A PASS_TO_KERNEL session-map entry cannot re-run userspace lo0
        // filters. Keep the packet visible to the helper while lo0
        // filtering is configured; the session-hit path enforces the
        // current lo0 terms before reinjection.
        let _ = publish_live_session_entry(session_map_fd, key, decision.nat, metadata.is_reverse);
        return;
    }
    let _ = if force_live_redirect_for_worker_synced_entry(
        decision,
        metadata,
        origin,
        allow_replace_local,
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
        )
    };
}

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
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) {
    // #1748: `delete_session_map_entry_for_removed_session_with_origin` already
    // early-returns for RebalancedOut (no redirect/conntrack delete). The rest
    // of the shared-state teardown below must ALSO be suppressed for the
    // abandoned W_old copy: removing the SHARED session-map entry, broadcasting
    // DeleteSynced, or emitting a Close delta would all tear down the state
    // W_new is actively forwarding against. The local slab entry is still
    // removed so W_old reclaims its own memory.
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
    if origin.is_rebalanced_out() {
        return;
    }
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
    );
    replicate_session_delete(peer_worker_commands, key);
    sessions.emit_close_delta_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        origin,
    );
}

pub(in crate::afxdp::session_glue) fn export_forward_sessions_for_owner_rgs(
    sessions: &mut SessionTable,
    owner_rgs: &[i32],
) {
    if owner_rgs.is_empty() {
        return;
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
            // #1748: the abandoned W_old copy must not be exported as an Open
            // delta to the peer — W_new is the exporting owner now.
            || origin.is_rebalanced_out()
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
    for (key, decision, metadata, origin) in export {
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
) -> WorkerCommandResults {
    // Hot path: try_lock avoids blocking on the mutex when another thread
    // holds it (rare) and avoids the cost of lock+unlock on empty queues
    // when there's nothing to do (common case during steady-state forwarding).
    let pending = match commands.try_lock() {
        Ok(mut pending) => {
            if pending.is_empty() {
                return WorkerCommandResults {
                    cancelled_keys: Vec::new(),
                    exported_sequences: Vec::new(),
                    shaped_tx_requests: Vec::new(),
                    vacate_all_shared_exact_slots: false,
                    rebalance_acks: Vec::new(),
                };
            }
            core::mem::take(&mut *pending)
        }
        Err(_) => {
            return WorkerCommandResults {
                cancelled_keys: Vec::new(),
                exported_sequences: Vec::new(),
                shaped_tx_requests: Vec::new(),
                vacate_all_shared_exact_slots: false,
                rebalance_acks: Vec::new(),
            };
        }
    };
    // Sample monotonic time ONCE per tick so every handler sees the same
    // `now_ns` / `now_secs` and there is no intra-tick clock skew between
    // session-table side effects (#1346 plan v2 invariant 3).
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let mut cancelled_keys: Vec<SessionKey> = Vec::new();
    let mut exported_sequences = Vec::new();
    let mut shaped_tx_requests = Vec::new();
    let mut vacate_all_shared_exact_slots = false;
    let mut rebalance_acks: Vec<crate::afxdp::RebalanceAck> = Vec::new();
    for cmd in pending {
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
                    sessions,
                    &mut exported_sequences,
                    sequence,
                    owner_rgs,
                );
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
                );
            }
            WorkerCommand::UpsertLocal(entry) => {
                // Trivial variant — kept inline (#1346 plan v2 §4.1):
                // lifting a 3-line delegate to its own sibling file is
                // negative value.
                sessions.install_with_protocol_with_origin(
                    entry.key,
                    entry.decision,
                    entry.metadata,
                    entry.origin,
                    now_ns,
                    entry.protocol,
                    entry.tcp_flags,
                );
            }
            WorkerCommand::DeleteSynced(key) => {
                commands::handle_delete_synced(sessions, session_map_fd, key, now_ns);
            }
            WorkerCommand::EnqueueShapedLocal(req) => {
                // Trivial variant — kept inline (#1346 plan v2 §4.1).
                shaped_tx_requests.push(req);
            }
            WorkerCommand::VacateAllSharedExactSlots => {
                // Trivial variant — kept inline (#1346 plan v2 §4.1).
                // #941 Work item C: signal the outer poll loop to vacate
                // all shared_exact slots (we don't have BindingWorker
                // access here, so we set the flag and let
                // `worker.rs:818-822` dispatch).
                vacate_all_shared_exact_slots = true;
            }
            // #1748: rebalance ownership-transfer barrier steps. Each is a
            // dedicated origin-only mutation on the SessionTable (no delta, no
            // shared publish, no NAT). The structured ack carries the observed
            // origin so the controller confirms the EXACT key reached the EXACT
            // state before the barrier proceeds. `result=false` when the key is
            // absent (the controller rolls back).
            WorkerCommand::PromoteRebalanced { seq, key } => {
                // #1751 live BLOCKER: for a SAME-NODE count-balance move the
                // destination worker (W_new) does NOT pre-hold the flow's
                // session — the flow currently lives on W_old, and W_new only
                // materializes a fresh ForwardFlow entry once the ntuple rule
                // steers packets there. promote_rebalanced_owner flips an
                // EXISTING entry to RebalancedOwner (the HA case where a
                // peer-synced replica is present), but when the key is ABSENT
                // that is the EXPECTED same-node case, NOT a failure — the
                // ownership is established on arrival. So a promote is a
                // best-effort claim: result=true whether the entry was present
                // (flipped) or absent (will materialize). The controller no
                // longer fails the move on an absent W_new entry.
                let _present = sessions.promote_rebalanced_owner(&key, now_ns);
                rebalance_acks.push(crate::afxdp::RebalanceAck {
                    seq,
                    // Some(RebalancedOwner) if we flipped an existing replica;
                    // None if the key is absent (same-node, materialize later).
                    origin: sessions.origin_of(&key),
                    key,
                    // A promote claim always succeeds; the move's correctness
                    // does not require W_new to pre-hold the entry (same-node).
                    result: true,
                });
            }
            WorkerCommand::DemoteRebalanced { seq, key } => {
                let result = sessions.demote_rebalanced_out(&key);
                rebalance_acks.push(crate::afxdp::RebalanceAck {
                    seq,
                    origin: sessions.origin_of(&key),
                    key,
                    result,
                });
            }
            WorkerCommand::RestoreRebalancedOwner { seq, key } => {
                let result = sessions.restore_rebalanced_owner(&key, now_ns);
                rebalance_acks.push(crate::afxdp::RebalanceAck {
                    seq,
                    origin: sessions.origin_of(&key),
                    key,
                    result,
                });
            }
            WorkerCommand::DemoteRebalancedReplica { seq, key } => {
                // Reverse barrier: hand W_new's RebalancedOwner back to a
                // worker-local replica. WorkerLocalImport is the correct
                // resting origin for a materialized synced replica that this
                // worker holds but does not own.
                let result = sessions.demote_rebalanced_replica(&key);
                rebalance_acks.push(crate::afxdp::RebalanceAck {
                    seq,
                    origin: sessions.origin_of(&key),
                    key,
                    result,
                });
            }
        }
    }
    WorkerCommandResults {
        cancelled_keys,
        exported_sequences,
        shaped_tx_requests,
        vacate_all_shared_exact_slots,
        rebalance_acks,
    }
}


pub(super) fn replicate_session_upsert(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    entry: &SyncedSessionEntry,
) {
    let replica = synced_replica_entry(entry);
    for commands in worker_commands {
        if let Ok(mut pending) = commands.lock() {
            pending.push_back(WorkerCommand::UpsertSynced(replica.clone()));
        }
    }
}

pub(super) fn replicate_session_delete(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    key: &SessionKey,
) {
    for commands in worker_commands {
        if let Ok(mut pending) = commands.lock() {
            pending.push_back(WorkerCommand::DeleteSynced(key.clone()));
        }
    }
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
    fabric_ingress: bool,
    ha_startup_grace_until_secs: u64,
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
        });
    }

    let forward_match =
        lookup_forward_nat_across_scopes(sessions, shared_nat_sessions, &flow.forward_key)?;
    let resolved = install_reverse_session_from_forward_match(
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
        created: true,
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
