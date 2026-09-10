use super::*;

/// Shared-session backing references that travel together at every
/// site that touches synced sessions. Grouping them collapses the
/// 16-param `maybe_promote_synced_session` and 10-param
/// `purge_translated_synced_hit` signatures that triggered #1346.
/// (Issue body rounded these to 17/11 by counting `&mut sessions`
/// as a leading param; the actual `fn` declarations on
/// `origin/master` carry 16 and 10 typed args respectively.)
///
/// `Copy` because the struct is 4 `&`-references (= 32 bytes on
/// x86-64) with no destructor. Passing it by value at the 3 call
/// sites in `resolve_flow_session_decision` should compile to the
/// same register/stack use vs. passing the 4 references
/// individually. Note: `cargo-asm 0.1.16` panics parsing this
/// codebase's symbols, so a programmatic before/after asm diff was
/// not produced. The zero-cost claim rests on the structural
/// argument (Copy + pointer-sized fields + no Drop) and is
/// empirically gated by the smoke-plus-test-failover pass in the PR.
#[derive(Clone, Copy)]
pub(in crate::afxdp::session_glue) struct SharedSessionRefs<'a> {
    pub sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
}

/// Predicate: is `key` the forward (NAT-translated) side of a
/// synced session? Used to distinguish translated forward hits from
/// reverse-side hits when deciding whether to purge a transient
/// peer-synced entry.
pub(in crate::afxdp::session_glue) fn is_translated_forward_session_key(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) -> bool {
    if metadata.is_reverse {
        return false;
    }
    decision.nat.rewrite_src == Some(key.src_ip) || decision.nat.rewrite_dst == Some(key.dst_ip)
}

/// Predicate: should a peer-synced hit be kept as transient (i.e.
/// purged from the shared maps so the local node re-resolves) rather
/// than being installed locally? True when the local node is not the
/// active owner of the session's RG and the key is the translated
/// forward side.
pub(in crate::afxdp::session_glue) fn should_keep_synced_hit_transient(
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) -> bool {
    origin.is_peer_synced()
        && !owner_rg_is_locally_active(ha_state, metadata.owner_rg_id, now_secs)
        && is_translated_forward_session_key(key, decision, metadata)
}

/// Promote a synced session hit into a locally-owned session when
/// the local node is now the active owner. No-op if the session is
/// not promotable or not currently in a `ForwardCandidate` state.
///
/// On successful promotion, the session is re-published to the
/// kernel session map, mirrored into the shared maps under
/// `SharedPromote` origin, and replicated to peer worker commands.
///
/// Behavior unchanged from the pre-#1346 free function; only the
/// signature changed (16 → 13 params via `SharedSessionRefs`).
pub(in crate::afxdp::session_glue) fn maybe_promote_synced_session(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared: SharedSessionRefs<'_>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    fabric_ingress: bool,
    now_ns: u64,
    protocol: u8,
    tcp_flags: u8,
) -> SessionMetadata {
    if !origin.is_promotable_synced()
        || decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
    {
        return metadata;
    }

    let mut promoted = metadata;
    if promoted.owner_rg_id <= 0 {
        promoted.owner_rg_id = owner_rg_for_resolution(forwarding, decision.resolution);
    }
    if fabric_ingress {
        promoted.fabric_ingress = true;
    }
    if sessions.promote_synced_with_origin(SessionUpdate {
        key,
        decision,
        metadata: promoted.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns,
        protocol,
        tcp_flags,
    }) {
        // #1789: count a failed shared-promote publish (shim would miss the
        // key -> NO_SESSION degraded path for the promoted flow).
        if publish_session_map_entry_for_session(
            session_map_fd,
            key,
            decision,
            &promoted,
            forwarding.has_routing_domains,
        )
        .is_err()
        {
            crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let promoted_entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: promoted.clone(),
            origin: SessionOrigin::SharedPromote,
            protocol,
            tcp_flags,
            // Local shared-promote: no peer install generation (#2170).
            generation: 0,
            // #5212: promote re-publishes an entry already live in the table;
            // its stable id is preserved on the entry itself (the promote Open
            // delta reads it via `entry_by_key`), so this shared replica needs
            // no id (0 = "alloc a fresh local id" on any re-import).
            session_id: 0,
        };
        publish_shared_session(
            shared.sessions,
            shared.nat_sessions,
            shared.forward_wire_sessions,
            shared.owner_rg_indexes,
            &promoted_entry,
        );
        replicate_session_upsert(peer_worker_commands, &promoted_entry);
    }
    promoted
}

/// Purge a translated peer-synced hit: drop the entry from the shared
/// maps, delete the kernel session-map entry, remove the local
/// session-table entry, AND return the source-NAT / NAT64 pool
/// reservation this forward session reserved at install. Used when the
/// local node is not the active owner of a translated forward session —
/// leaving the hit live would route traffic to the wrong node.
///
/// #5295: the purged entry is a peer-synced FORWARD translated session
/// (the guard below rejects reverse/non-translated keys), so at install
/// `handle_upsert_synced` reserved its translated `(pool_addr, port)` in
/// THIS node's local allocator via `reserve_synced_source_nat_allocation`
/// / `reserve_synced_nat64_allocation`. Tearing the session down without
/// the matching release LEAKED that reservation — every alias-owned
/// transient purge burned a pool port, exhausting the standby's source-NAT
/// / NAT64 pool under sustained HA churn. Mirror the `handle_delete_synced`
/// (and `delete_terminal_filtered_session`) teardown: release under the
/// same `metadata.is_reverse` ownership guard so a reverse/alias entry (or
/// a non-pool / non-reserved session) frees nothing and a double-free is
/// impossible — `release_flow` is a no-op when the flow was never tracked.
///
/// Behavior otherwise unchanged from the pre-#1346 free function; the
/// signature carries `forwarding` + `now_ns` for the reservation release
/// (was 7 params, now 9 after the #5295 additions).
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp::session_glue) fn purge_translated_synced_hit(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared: SharedSessionRefs<'_>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    forwarding: &ForwardingState,
    now_ns: u64,
    // #6211 F2: THIS worker's id. This purge tears down a PEER-SYNCED forward
    // session, whose reservation every worker holds, so it must drop only this
    // worker's bit.
    worker_id: u32,
) {
    if !origin.is_peer_synced() || !is_translated_forward_session_key(key, decision, metadata) {
        return;
    }
    remove_shared_session(
        shared.sessions,
        shared.nat_sessions,
        shared.forward_wire_sessions,
        shared.owner_rg_indexes,
        key,
    );
    delete_session_map_entry_for_removed_session(session_map_fd, key, decision, metadata);
    sessions.delete(key);
    // #5295: return the pool reservation to the local allocator, exactly as
    // `handle_delete_synced` does on the delete-sync teardown. `is_reverse` is
    // the ownership guard (a reverse entry owns no source-NAT/NAT64 reservation);
    // both calls are a no-op for a non-pool / non-reserved session.
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
}
