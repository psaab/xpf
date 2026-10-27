use super::*;

/// #16185: the conntrack map fd pair that travels with the shared
/// session maps. `v4`/`v6` are named fields at one construction site
/// (instead of two bare `c_int` arguments at every call), so the
/// pair is built once and reviewed once. Named fields do not make
/// a same-typed transposition uncompilable (`v4: <v6 fd>` still
/// type-checks); the wiring cells in
/// `shared_session_refs_16185_tests.rs` pin the IPv4 fd to its
/// consumers (the IPv6 fd has no wiring cell; both cells drive
/// IPv4 keys through the v4 test fd). `-1` means unavailable
/// (no-op), matching the
/// pre-bundle scalar convention.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct ConntrackFds {
    pub v4: c_int,
    pub v6: c_int,
}

/// #16185: one packet's two clocks. `ns` (monotonic nanoseconds) and
/// `secs` (seconds for the HA-lease checks in the resolve path) are
/// two readings of the same monotonic clock: `secs == ns / 1_000_000_000`.
/// #17069: construction is only through [`Tick::from_ns`], which
/// derives `secs` from `ns`, so the pairing the bundle asserts cannot
/// be broken by a zero-filled or independently sampled `secs`. The
/// sole `secs` reader is the resolve path (`resolve.rs` reads
/// `shared.tick.secs` for `should_keep_synced_hit_transient` and the
/// HA forwarding-active checks); teardown/housekeeping bundles fed
/// through this constructor therefore carry the real seconds value
/// instead of the pre-#17069 `secs: 0`, which would have read every
/// non-zero HA lease as active (fail-open at time 0) had a teardown
/// consumer ever read it. `Tick` carries only these two: the HA
/// startup-grace deadline stays a separate named argument because it
/// is a deadline, not a clock reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct Tick {
    pub ns: u64,
    pub secs: u64,
}

impl Tick {
    /// The only clock constructor: both fields from one monotonic
    /// reading, `secs` derived so the two can never disagree.
    pub(in crate::afxdp) fn from_ns(ns: u64) -> Self {
        Self {
            ns,
            secs: ns / 1_000_000_000,
        }
    }

    /// Test-only decoupled clock: HA-lease cells need a `secs` that
    /// `from_ns` cannot express (e.g. `ns: 1_000_000, secs: 1_000`
    /// against a lease expiring at 500). Production has no caller:
    /// every production bundle goes through `from_ns`, so the
    /// `secs == ns / 1_000_000_000` invariant holds outside tests.
    #[cfg(test)]
    pub(in crate::afxdp) fn from_parts(ns: u64, secs: u64) -> Self {
        Self { ns, secs }
    }
}

/// Shared-session backing references that travel together at every
/// site that touches synced sessions. Grouping them collapses the
/// 16-param `maybe_promote_synced_session` and 10-param
/// `purge_translated_synced_hit` signatures that triggered #1346.
/// (Issue body rounded these to 17/11 by counting `&mut sessions`
/// as a leading param; the actual `fn` declarations on
/// `origin/master` carry 16 and 10 typed args respectively.)
///
/// #16185 extends this existing bundle - deliberately NOT a parallel
/// `SharedSessionCtx` - with the groupings that travel with the
/// shared maps at the resolve/teardown call sites: the peer/command
/// queues, `conntrack` ([`ConntrackFds`]) and `tick` ([`Tick`]).
/// `session_map` stays a separate argument: it is the caller's
/// per-binding steering handle, not shared-map wiring, and
/// `WorkerContext` keeps owning the broader poll context.
/// `worker_commands_by_id` is normalised to `&WorkerCommandQueues`
/// here (the type `resolve_*`/`promote.rs` already used); the
/// `delete_terminal_*` twins previously took the bare
/// `&BTreeMap<...>` deref target, so this also closes the validator
/// open check on the two queue-map types with one answer.
///
/// `Copy` because the struct is 6 `&`-references plus two small
/// `Copy` value groupings (conntrack fd pair + tick) with no
/// destructor. Passing it by value should compile to the same
/// register/stack use vs. passing the fields individually. Note:
/// `cargo-asm 0.1.16` panics parsing this codebase's symbols, so a
/// programmatic before/after asm diff was not produced. The
/// zero-cost claim rests on the structural argument (Copy +
/// pointer-sized fields + no Drop) and is empirically gated by the
/// iperf witness in the PR.
#[derive(Clone, Copy)]
pub(in crate::afxdp) struct SharedSessionRefs<'a> {
    pub sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
    pub peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
    pub worker_commands_by_id: &'a WorkerCommandQueues,
    pub conntrack: ConntrackFds,
    pub tick: Tick,
}

impl<'a> SharedSessionRefs<'a> {
    /// The no-conntrack, no-clock bundle for callers that only carry
    /// the shared maps (the old `-1, -1` scalar convention):
    /// conntrack fds `-1` (unavailable) and a zero tick. Production
    /// poll sites construct the full struct literally so every field
    /// is visible at the call site.
    pub(in crate::afxdp) fn detached(
        sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
        peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
        worker_commands_by_id: &'a WorkerCommandQueues,
    ) -> Self {
        Self {
            sessions,
            nat_sessions,
            forward_wire_sessions,
            owner_rg_indexes,
            peer_worker_commands,
            worker_commands_by_id,
            conntrack: ConntrackFds { v4: -1, v6: -1 },
            tick: Tick::from_ns(0),
        }
    }

    /// This bundle with different conntrack fds and tick (the
    /// `_with_conntrack` entry points receive the fds/clock from
    /// their caller and graft them onto the shared-map bundle).
    pub(in crate::afxdp) fn with_conntrack_tick(
        mut self,
        conntrack: ConntrackFds,
        tick: Tick,
    ) -> Self {
        self.conntrack = conntrack;
        self.tick = tick;
        self
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) enum SessionHitVerdict {
    Owner,
    Foreign,
    Unresolved,
}

/// Promote a synced session hit into a locally-owned session when
/// the local node is now the active owner. No-op if the session is
/// not promotable or not currently in a `ForwardCandidate` state.
///
/// On successful promotion, the session is re-published to the
/// kernel session map, mirrored into the shared maps under
/// `SharedPromote` origin, and replicated to peer worker commands.
///
/// The compatibility wrapper keeps the pre-#1346 13-argument shape for tests;
/// the production variant adds the two conntrack fds to invalidate only origin.
fn promote_synced_session_with_conntrack(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    fabric_ingress: bool,
    protocol: u8,
    tcp_flags: u8,
    ack: Option<u32>,
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
    // #13939: `promote_synced_with_origin` preserves any FIN/RST for the
    // Owner-only deferred-close step after the authority verdict.
    if sessions.promote_synced_with_origin(SessionUpdate {
        key,
        decision,
        metadata: promoted.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: shared.tick.ns,
        protocol,
        tcp_flags,
        ack,
    }) {
        // #10612 (M4): fence stale replays at promote-publish ingress. A row
        // that lingered through an unvalidated purge (purge no-op) must not be
        // published to shared/BPF/peer after its zones vanished. The local
        // flip above stands (the row is live locally); only the authoritative
        // republish is fenced.
        if crate::afxdp::session_glue::synced_entry_is_stale_replay(
            SessionOrigin::SharedPromote,
            &promoted,
            forwarding,
        ) {
            crate::afxdp::session_glue::note_stale_replay_fence_drop();
            return promoted;
        }
        // The helper's promotion flips a peer-synced row to local ownership.
        // Clear only the origin bit in the conntrack mirror; counters,
        // timestamps, NAT state, and creation time remain untouched.
        crate::afxdp::bpf_map::update_session_cluster_synced_origin(
            shared.conntrack.v4,
            shared.conntrack.v6,
            key,
            false,
        );
        // #1789: count a failed shared-promote publish (shim would miss the
        // key -> NO_SESSION degraded path for the promoted flow).
        if publish_session_map_entry_for_session(
            session_map,
            key,
            decision,
            &promoted,
            forwarding.has_routing_domains,
            forwarding.has_multiple_zones,
        )
        .is_err()
        {
            crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let promoted_entry = SyncedSessionEntry { key: key.clone(),
        decision,
        metadata: promoted.clone(),
        leak_incarnation: sessions.leak_incarnation(key).unwrap_or(0),
        origin: SessionOrigin::SharedPromote,
        protocol,
        tcp_flags,
        // Local shared-promote: no peer install generation (#2170).
        generation: 0,
        // #9582: carry the promoted session's stable id (preserved on the live
        // entry, #5212), so replicas and shared-map materializations ADOPT it.
        // With 0 each re-import minted its own id, and a replica could not
        // announce a close under the id the peer and the #9412 memo know.
        session_id: sessions.session_id_for(key),
        // #9412: republish the promoted session with its LIVE close class, so
        // a worker materializing it from the shared maps keeps the close state.
        tcp_close_class: sessions.close_class_wire_for(key), tcp_handshake_state: sessions.handshake_state_wire_for(key), rev_packets: sessions.rev_packets_for(key), fwd_packets: sessions.fwd_packets_for(key), pptp_call_ids: sessions.pptp_call_ids_wire_for(key),
        persistent_lease_hold: sessions.persistent_lease_hold_for(key),
        source_nat_static: sessions.source_nat_static_for(key), };
        publish_shared_session(
            shared.sessions,
            shared.nat_sessions,
            shared.forward_wire_sessions,
            shared.owner_rg_indexes,
            &promoted_entry,
        );
        replicate_session_upsert(shared.peer_worker_commands, shared.worker_commands_by_id, &promoted_entry);
    }
    promoted
}

pub(in crate::afxdp) fn maybe_promote_synced_session(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    fabric_ingress: bool,
    protocol: u8,
    tcp_flags: u8,
    verdict: SessionHitVerdict,
) -> SessionMetadata {
    if verdict != SessionHitVerdict::Owner {
        return metadata;
    }
    // No-conntrack leg: force `-1, -1` so a caller that grafted real
    // fds onto the bundle cannot leak them into this entry point.
    let shared = shared.with_conntrack_tick(ConntrackFds { v4: -1, v6: -1 }, shared.tick);
    promote_synced_session_with_conntrack(
        sessions,
        session_map,
        shared,
        forwarding,
        key,
        decision,
        metadata,
        origin,
        fabric_ingress,
        protocol,
        tcp_flags,
        None,
    )
}
/// Evaluate the session-hit verdict before applying any deferred synced
/// materialization, purge, or promotion. Foreign and unresolved packets leave
/// the decision, metadata, shared maps, and local session state untouched.
pub(in crate::afxdp) fn maybe_promote_synced_session_with_conntrack(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    tcp_flags: u8,
    worker_id: u32,
    verdict: SessionHitVerdict,
    resolved: &mut ResolvedFlowSessionDecision,
    evicted_keys: &mut Vec<SessionKey>,
) {
    if verdict != SessionHitVerdict::Owner {
        return;
    }
    apply_deferred_synced_purge(
        sessions,
        session_map,
        shared,
        forwarding,
        worker_id,
        verdict,
        resolved,
        evicted_keys,
    );

    super::apply_deferred_shared_materialization(
        sessions,
        forwarding,
        shared.tick.ns,
        tcp_flags,
        verdict,
        resolved,
    );

    let Some(promotion) = resolved.deferred_synced_promotion.take() else {
        return;
    };
    // The deferred promotion carries its own install tick; graft it
    // so the promote leg stamps the install time, not the purge's.
    let shared = shared.with_conntrack_tick(
        shared.conntrack,
        Tick::from_ns(promotion.now_ns),
    );
    resolved.metadata = promote_synced_session_with_conntrack(
        sessions,
        session_map,
        shared,
        forwarding,
        &promotion.key,
        promotion.decision,
        promotion.metadata,
        promotion.origin,
        promotion.fabric_ingress,
        promotion.protocol,
        promotion.tcp_flags,
        promotion.ack,
    );
}


/// Purge a translated peer-synced hit: drop the entry from the shared
/// maps, delete the kernel session-map entry, remove the local session-table
/// entry, AND return the source-NAT / NAT64 pool reservation this forward
/// session reserved at install. Used when the local node is not the active
/// owner of a translated forward session — leaving the hit live would route
/// traffic to the wrong node.
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
/// #13674 (D11-08): this purge also owns the remaining teardown legs its
/// sibling purges (`purge_one_install_table_key`) run. It must (a) delete
/// the BPF conntrack mirror — the plain
/// `delete_session_map_entry_for_removed_session` hardcodes `-1,-1`
/// conntrack fds, leaving a stale kernel row the next packet would hit;
/// (b) fan `DeleteSynced` to sibling workers only if the shared session
/// captured by the lookup still has the same identity, so a replacement
/// under the key cannot be revoked by this stale hit; and (c) push the key
/// into `evicted_keys` so the worker invalidates flow-cache slots on every
/// binding. Sibling workers evict through their delete-sync teardown.
///
/// `key` identifies the stored session and is the tuple tested by the
/// translated-forward guard. `forwarding`, `now_ns`, and `worker_id` scope
/// the local NAT reservation release.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp::session_glue) fn purge_translated_synced_hit_with_context(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    shared_identity: Option<(u64, u64)>,
    forwarding: &ForwardingState,
    // #6211 F2: THIS worker's id. This purge tears down a PEER-SYNCED forward
    // session, whose reservation every worker holds, so it must drop only this
    // worker's bit.
    worker_id: u32,
    evicted_keys: &mut Vec<SessionKey>,
) -> bool {
    if !origin.is_peer_synced() || !is_translated_forward_session_key(key, decision, metadata) {
        return false;
    }
    let removed = if let Some((shared_session_id, generation)) = shared_identity {
        remove_shared_session_if(
            shared.sessions,
            shared.nat_sessions,
            shared.forward_wire_sessions,
            shared.owner_rg_indexes,
            key,
            |entry| entry.session_id == shared_session_id && entry.generation == generation,
        )
    } else {
        SharedRemoval::Absent
    };
    let session_id = sessions.session_id_for(key);
    let delete_result =
        delete_session_map_entry_for_removed_session_with_origin_and_id(
            session_map,
            key,
            decision,
            metadata,
            origin,
            shared.conntrack.v4,
            shared.conntrack.v6,
            session_id,
        );
    if delete_result == crate::afxdp::bpf_map::ConntrackDeleteResult::GateBusy {
        sessions.defer_conntrack_delete(crate::session::DeferredConntrackDelete {
            key: key.clone(),
            session_id,
        });
    }
    let persistent_hold_16615 = sessions.take_persistent_lease_hold(key);
    sessions.delete(key);
    evicted_keys.push(key.clone());
    if let (SharedRemoval::Removed(_), Some((session_id, _))) = (removed, shared_identity) {
        replicate_session_delete_conditional(
            shared.peer_worker_commands,
            shared.worker_commands_by_id,
            forwarding,
            key,
            decision.nat,
            metadata.is_reverse,
            shared.tick.ns,
            session_id,
            None,
            0,
        );
    }
    // #5295: return the pool reservation to the local allocator, exactly as
    // `handle_delete_synced` does on the delete-sync teardown. `is_reverse` is
    // the ownership guard (a reverse entry owns no source-NAT/NAT64 reservation);
    // both calls are a no-op for a non-pool / non-reserved session.
    crate::nat::release_source_nat_allocation_for_worker_with_hold(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        key,
        decision.nat,
        metadata.is_reverse,
        shared.tick.ns,
        worker_id,
        persistent_hold_16615,
    );
    crate::nat64::release_nat64_allocation_for_worker(
        &forwarding.nat64,
        key,
        decision.nat,
        metadata.is_reverse,
        shared.tick.ns,
        worker_id,
    );
    true
}
/// Backwards-compatible internal wrapper for tests and callers that have no
/// conntrack fds, sibling command queues, or flow-cache invalidation owner.
#[cfg(test)]
pub(in crate::afxdp::session_glue) fn purge_translated_synced_hit(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    forwarding: &ForwardingState,
    worker_id: u32,
) {
    let mut evicted_keys = Vec::new();
    purge_translated_synced_hit_with_context(
        sessions,
        session_map,
        shared,
        key,
        decision,
        metadata,
        origin,
        None,
        forwarding,
        worker_id,
        &mut evicted_keys,
    );
}
fn apply_deferred_synced_purge(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    worker_id: u32,
    verdict: SessionHitVerdict,
    resolved: &mut ResolvedFlowSessionDecision,
    evicted_keys: &mut Vec<SessionKey>,
) {
    if verdict != SessionHitVerdict::Owner {
        return;
    }
    let Some(purge) = resolved.deferred_synced_purge.take() else {
        return;
    };
    purge_translated_synced_hit_with_context(
        sessions,
        session_map,
        shared,
        &purge.key,
        purge.decision,
        &purge.metadata,
        purge.origin,
        purge.shared_identity,
        forwarding,
        worker_id,
        evicted_keys,
    );
}
