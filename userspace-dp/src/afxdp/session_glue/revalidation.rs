use super::*;

pub(in crate::afxdp) fn session_key_has_lo0_filter(forwarding: &ForwardingState, key: &SessionKey) -> bool {
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

pub(in crate::afxdp) fn republish_local_delivery_sessions_for_lo0_filter(sessions: &SessionTable,
session_map: SteeringMap<'_>,
forwarding: &ForwardingState,
lo0_filter_changed: bool,) -> usize {
    // #11330: skip the full-table walk unless the lo0 filter changed
    // semantically. The caller compares the old/new snapshots O(1) per
    // family; without this gate every forwarding rotation pays O(N).
    if !lo0_filter_changed {
        return 0;
    }
    let mut republished = 0usize;
    sessions.iter_with_origin(|key, decision, metadata, _origin| {
        if metadata.is_reverse
            || decision.resolution.disposition != ForwardingDisposition::LocalDelivery
            || !session_key_has_lo0_filter(forwarding, key)
        {
            return;
        }
        if session_map.fd >= 0 {
            // #1789: count failed lo0-filter republishes (was `let _ =`).
            // No binding context in this glue path — shared counter.
            if publish_live_session_entry(session_map, key, decision.nat, metadata.is_reverse)
                .is_err()
            {
                SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
        }
        republished += 1;
    });
    republished
}

pub(in crate::afxdp) fn purge_sessions_for_input_dscp_filter_revalidation(sessions: &mut SessionTable,
session_map: SteeringMap<'_>,
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
worker_id: u32,) -> usize {
    if !purge_v4 && !purge_v6 {
        return 0;
    }
    let mut stale = Vec::new();
    sessions.iter_with_origin(|key, decision, metadata, origin| {
        let family_matches = (purge_v4 && key.addr_family == libc::AF_INET as u8)
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
            session_map,
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

/// #10510: derive the zone ids that disappeared during this worker's
/// forwarding-state rotation. The state maps are built from the validated
/// snapshot zone set; an empty map on either side means the producer did not
/// provide a populated zone set, so the safe answer is no removal rather than
/// interpreting an empty new set as deletion of every old zone.
/// `zone_set_validated` is carried by the producer only after it has supplied
/// a populated, collision-free zone set. Both generations must carry the
/// marker; absent/false is a safe no-op for legacy, empty, or quarantined
/// snapshots because the id-keyed maps cannot distinguish quarantine from
/// genuine disappearance.
pub(in crate::afxdp) fn removed_zone_ids_for_rotation(old_forwarding: &ForwardingState,
new_forwarding: &ForwardingState,) -> FastSet<u16> {
    if !old_forwarding.zone_set_validated
        || !new_forwarding.zone_set_validated
        || old_forwarding.zone_id_to_name.is_empty()
        || new_forwarding.zone_id_to_name.is_empty()
    {
        return FastSet::default();
    }
    old_forwarding
        .zone_id_to_name
        .iter()
        .filter(|(zone_id, old_name)| {
            **zone_id != 0
                && new_forwarding
                    .zone_id_to_name
                    .get(zone_id)
                    .is_none_or(|new_name| new_name != *old_name)
        })
        .map(|(zone_id, _)| *zone_id)
        .collect()
}

/// #10510: purge peer-derived, unbound sessions whose recorded zone identity
/// disappeared from the old snapshot. Policy id zero is overloaded on the
/// wire, so the sync-derived and unbound predicates are required in addition
/// to the zone-set test. The existing terminal delete owns pair expansion,
/// NAT release, BPF/shared-map cleanup, and HA delete propagation.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn purge_sessions_with_removed_zone_ids(sessions: &mut SessionTable,
session_map: SteeringMap<'_>,
conntrack_v4_fd: c_int,
conntrack_v6_fd: c_int,
shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
forwarding: &ForwardingState,
removed_zone_ids: &FastSet<u16>,
now_ns: u64,
worker_id: u32,) -> usize {
    if removed_zone_ids.is_empty() {
        return 0;
    }
    let mut stale = Vec::new();
    sessions.iter_with_origin(|key, decision, metadata, origin| {
        if metadata.is_reverse
            || metadata.policy_counter.is_some()
            || metadata.policy_id != 0
            || !(origin.is_peer_synced() || origin == SessionOrigin::SharedPromote)
            || (!removed_zone_ids.contains(&metadata.ingress_zone)
                && !removed_zone_ids.contains(&metadata.egress_zone))
        {
            return;
        }
        stale.push((key.clone(), decision, metadata.clone(), origin));
    });
    let purged = stale.len();
    for (key, decision, metadata, origin) in stale {
        delete_terminal_filtered_session(
            sessions,
            session_map,
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

/// #10612: stale-replay fence — is this synced entry's recorded zone identity
/// absent from the CURRENT validated zone set?
///
/// The #10510 rotation purge is a one-shot delete: it removes the unbound
/// sync-derived id-0 rows whose zones vanished and retains nothing. Every
/// replay/install ingress must therefore re-validate zone membership against
/// the current view at install time, or a pre-purge snapshot re-published
/// post-purge reinstalls the exact row the purge deleted (shared map and
/// worker table alike).
///
/// Mirrors the purge predicate it fences (`purge_sessions_with_removed_zone_ids`):
/// unbound (`policy_counter.is_none()`), `policy_id == 0`, sync-family
/// (`is_peer_synced()` or `SharedPromote`), either recorded zone absent from
/// the current set. Same fail-opens: an unvalidated or empty current set
/// admits (legacy/empty-snapshot safe), and zone id 0 never matches
/// (`populate_zones` never admits it; 0 is unknown/unset on the wire).
///
/// Deliberately does NOT mirror the purge's `is_reverse` exemption (review
/// finding 10619/M2): the purge deletes the pair via the forward (companion
/// expansion), but the fence drops only the fenced entry — exempting reverses
/// would install stale reverse halves standalone after their forward was
/// dropped. Zone-membership is pair-symmetric (the check ORs both legs), so
/// live reverses (zones present) still admit while stale-zone reverses drop,
/// exactly like forwards. Legitimate rotation survivors, including reverse
/// halves, remain replayable via zone presence, not via exemption.
///
/// Never-member zones (an id absent from the current set that was never a
/// member, e.g. legacy/foreign rows): the fence drops these on REPLAY paths
/// (fail-closed on unvalidatable input). Local installs are unaffected (the
/// fence guards sync/replay ingress only, never the local path).
///
/// #10620 vintage arm: cross-generation id reuse (same id, new name).
/// `removed_zone_ids_for_rotation` treats same-id/different-name as REMOVED
/// (the purge deletes those rows), but `contains_key` sees the reused id, so
/// the stateless arm above ADMITS a stale replay the purge deleted — a dead
/// zone-A row reinstalling under zone-B's live id. The entry now carries the
/// vintage it was stamped under (`ingress_zone_check` / `egress_zone_check` =
/// `zone_identity_check` of the then-current name for that id); a leg whose
/// stamped check differs from the CURRENT name's check for the same id is
/// stale and drops. Fail-open on either side unknown: a 0 stamped check
/// (unstamped row, id-0 leg, peer import without vintage) or a 0/absent
/// current leg falls back to the stateless arm. Same preconditions as the
/// stateless arm (unbound + id-0 + sync-family + validated set);
/// pair-symmetric OR over both legs, no is_reverse exemption.
pub(in crate::afxdp) fn synced_entry_is_stale_replay(
    origin: SessionOrigin,
    metadata: &SessionMetadata,
    forwarding: &ForwardingState,
) -> bool {
    // NOTE: no is_reverse exemption (see doc above). Reverses are judged by
    // zone membership exactly like forwards.
    if !forwarding.zone_set_validated || forwarding.zone_id_to_name.is_empty() {
        return false;
    }
    if metadata.policy_counter.is_some() || metadata.policy_id != 0 {
        return false;
    }
    if !(origin.is_peer_synced() || origin == SessionOrigin::SharedPromote) {
        return false;
    }
    let zone_absent = |zone: u16| zone != 0 && !forwarding.zone_id_to_name.contains_key(&zone);
    if zone_absent(metadata.ingress_zone) || zone_absent(metadata.egress_zone) {
        return true;
    }
    // #10620: the id is present — compare the vintage the entry was stamped
    // under against the CURRENT name's check for the same id. A mismatch is
    // a stale generation (A's dead row under B's live id) and drops. The
    // `None` arm is unreachable (absence returned above) and fails open.
    let vintage_stale = |zone: u16, stamped: u32| {
        if zone == 0 || stamped == 0 {
            return false;
        }
        match forwarding.zone_id_to_name.get(&zone) {
            Some(current_name) => stamped != crate::session::zone_identity_check(current_name),
            None => false,
        }
    };
    vintage_stale(metadata.ingress_zone, metadata.ingress_zone_check)
        || vintage_stale(metadata.egress_zone, metadata.egress_zone_check)
}
/// #10612 (R2 observability): process-wide count of stale-zone replay drops
/// across all 8 fence decision sites (worker arm, coordinator filter, coordinator
/// purge, import, prewarm, promote, materialize-as-miss, republish BPF skip). Bumped per fence DECISION (the worker drain evicts
/// already-counted drops; the purge bumps only on actual removal). A row
/// judged at two sites (filter + purge) counts twice — honest: two distinct
/// decisions. Mirrors the
/// `SESSION_PUBLISH_ERRORS_SHARED` static pattern (no stats-handle threading).
pub(in crate::afxdp) static STALE_REPLAY_FENCE_DROPS: AtomicU64 = AtomicU64::new(0);

/// Bump [`STALE_REPLAY_FENCE_DROPS`] for one refused stale replay.
pub(in crate::afxdp) fn note_stale_replay_fence_drop() {
    STALE_REPLAY_FENCE_DROPS.fetch_add(1, Ordering::Relaxed);
}

/// #9526: the stable rule id of the OLD snapshot's literal first policy (the
/// rule at positional `policy_id` 0) when the NEW snapshot no longer contains
/// it, because that policy was deleted or renamed (a rename is delete + add by
/// stable id). `None` otherwise, including when the old snapshot names no
/// single first policy (`PolicyState::first_policy_rule_id`).
///
/// Only this one policy needs the helper. The Go commit sweep clears every
/// other deleted policy's sessions by `policy_id`, and it must skip 0 because
/// host-local, neighbor-seed, fabric, tunnel and older-peer sessions carry 0
/// too (pkg/daemon/daemon_policy_invalidate.go). Left alone, the first
/// policy's sessions are NOT reliably reaped: the #8356 re-derivation declines
/// every reverse packet, and reverse traffic keeps the forward half alive
/// (`companion_keeps_alive`), so a one-way reverse-sustained flow kept
/// transiting under the deleted policy.
pub(in crate::afxdp) fn deleted_first_policy_rule_id(old_policy: &crate::policy::PolicyState,
new_policy: &crate::policy::PolicyState,) -> Option<String> {
    let rule_id = old_policy.first_policy_rule_id()?;
    if new_policy.has_rule_id(rule_id) {
        return None;
    }
    Some(rule_id.to_string())
}

/// #9526: purge every forward session bound to `rule_id` (a deleted first
/// policy, see `deleted_first_policy_rule_id`) together with its reverse
/// companion. The discriminator is the admitting rule's counter handle a
/// session binds at install; host-local, neighbor-seed, fabric, tunnel and
/// peer-synced sessions bind none, so they are never touched. Teardown is
/// `delete_terminal_filtered_session`, the same full-pair path the DSCP purge
/// uses: NAT release, BPF and conntrack aliases, the shared HA maps, the
/// cross-worker `DeleteSynced`, and a close delta the daemon turns into an HA
/// peer delete. Returns the number of forward sessions purged.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn purge_sessions_bound_to_deleted_first_policy(sessions: &mut SessionTable,
session_map: SteeringMap<'_>,
conntrack_v4_fd: c_int,
conntrack_v6_fd: c_int,
shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
forwarding: &ForwardingState,
rule_id: &str,
now_ns: u64,
worker_id: u32,) -> usize {
    let mut bound = Vec::new();
    sessions.iter_with_origin(|key, decision, metadata, origin| {
        if metadata.is_reverse {
            return;
        }
        if metadata
            .policy_counter
            .as_ref()
            .is_some_and(|counter| counter.rule_id() == rule_id)
        {
            bound.push((key.clone(), decision, metadata.clone(), origin));
        }
    });
    let purged = bound.len();
    for (key, decision, metadata, origin) in bound {
        delete_terminal_filtered_session(
            sessions,
            session_map,
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

pub(crate) fn publish_worker_session_map_entry(
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    allow_replace_local: bool,
) {
    if session_map.fd < 0 {
        return;
    }
    let has_lo0_filter = session_key_has_lo0_filter(forwarding, key);
    // #9517: on a node WITH routing domains this is always false, so the row is
    // published as REDIRECT and an aliased publish can no longer flip a peer's
    // REDIRECT row to PASS_TO_KERNEL.
    let uses_kernel_local = uses_kernel_local_session_map_entry(
        key,
        decision,
        metadata,
        origin,
        forwarding.has_routing_domains,
    );
    if uses_kernel_local && has_lo0_filter {
        // A PASS_TO_KERNEL session-map entry cannot re-run userspace lo0
        // filters. Keep the packet visible to the helper while lo0
        // filtering is configured; the session-hit path enforces the
        // current lo0 terms before reinjection.
        //
        // #1789: count failed publishes (was `let _ =`). No binding
        // context in this glue path — shared counter.
        if publish_live_session_entry(session_map, key, decision.nat, metadata.is_reverse).is_err()
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
        publish_live_session_entry(session_map, key, decision.nat, metadata.is_reverse)
    } else {
        // #9560 round 3: NO pre-delete here. It released the entry's whole old row
        // set before the new publish was attempted, so a failed PASS_TO_KERNEL or
        // SNAT-reverse REDIRECT write left the session with NO rows at all — the
        // failure-safe migration `publish_entry` exists to provide (release the rows
        // the new decision does not name, only after every write succeeded) was
        // bypassed by the very path that needed it. The publish below is entry-level
        // for both arms, so the kernel-local <-> live row-set change migrates there.
        publish_session_map_entry_for_session_with_origin(
            session_map,
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
pub(in crate::afxdp) fn delete_terminal_filtered_session(sessions: &mut SessionTable,
session_map: SteeringMap<'_>,
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
worker_id: u32,) {
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
        session_map,
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
            session_map,
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
    session_map: SteeringMap<'_>,
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
        session_map,
        key,
        decision,
        metadata,
        origin,
        conntrack_v4_fd,
        conntrack_v6_fd,
    );
    let closed_id = sessions.session_id_for(key);
    sessions.delete(key);
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
    );
    // #9560 round 3: shared authority for this key is gone, so the coordinator's claim
    // on its rows goes too. The coordinator claims what it publishes for shared
    // authority (HA import, bringup replay, activation prewarm); a claim left behind
    // here is one no worker teardown can ever release.
    release_coordinator_session_rows(session_map, key);
    replicate_session_delete_repairing(
        peer_worker_commands,
        worker_commands_by_id,
        forwarding,
        key,
        decision.nat,
        metadata.is_reverse,
        now_ns,
    );
    sessions.emit_close_delta_with_origin(key.clone(), decision, metadata.clone(), origin, false, closed_id);
}

/// #9856: slice size for the collecting export-candidate walk below. The
/// worker loop (M2c) drives the cursor directly across passes; this Vec
/// path remains for tests and transitional callers.
const FORWARD_EXPORT_CANDIDATE_SLICE: usize = 2048;

/// #2442: the filter half of `export_forward_sessions_for_owner_rgs`. Walks the
/// table via the #9856 budgeted export cursor (epoch ≤ kick + owner-RG set)
/// and returns the export candidates (forward, locally-held,
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
    kick_epoch: u64,
) -> Vec<(SessionKey, SessionDecision, SessionMetadata, SessionOrigin)> {
    if owner_rgs.is_empty() {
        return Vec::new();
    }
    // #9856: collect via the budgeted export cursor (epoch ≤ kick + owner-RG
    // set + candidate gates) instead of the owner-RG index walk. Same set
    // for kick_epoch = u64::MAX; a real kick epoch excludes post-kick
    // installs and reused-key new incarnations by construction.
    let mut export = Vec::new();
    let mut cursor = 0;
    loop {
        match sessions.iter_export_budgeted(
            cursor,
            FORWARD_EXPORT_CANDIDATE_SLICE,
            kick_epoch,
            owner_rgs,
            |key, decision, metadata, origin| {
                export.push((key.clone(), decision, metadata.clone(), origin));
                true
            },
        ) {
            crate::session::ExportWalkOutcome::ResumeAt(next) => cursor = next,
            crate::session::ExportWalkOutcome::Complete => break,
        }
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
// worker-local-replica / transient-seed / TUN-origin no; fabric-ingress is
// authoritative and included), hence `#[cfg(test)]`.
#[cfg(test)]
pub(crate) fn export_forward_sessions_for_owner_rgs(
    sessions: &mut SessionTable,
    owner_rgs: &[i32],
) {
    for (key, decision, metadata, origin) in
        forward_export_candidates_for_owner_rgs(sessions, owner_rgs, u64::MAX)
    {
        sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
    }
}

/// Apply due #11360 repairs from the current shared authority. These must run
/// at their queue boundary and before later queued commands; stale replay
/// filtering and eviction use the same worker-loop path as queued upserts.
/// If a later delete removed the shared row, run the existing worker delete
/// path so an earlier queued upsert cannot leave stale local state behind.
pub(in crate::afxdp) fn apply_session_import_repairs(
    repairs: &[worker_queue::SessionImportRepair],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    stale_replay_dropped_keys: &mut Vec<SessionKey>,
    deleted_synced_keys: &mut Vec<SessionKey>,
    worker_id: u32,
) {
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let entries = {
        let shared = crate::afxdp::shared_ops::lock_shared_recover(shared_sessions);
        repairs
            .iter()
            .map(|repair| (repair.clone(), shared.get(&repair.key).cloned()))
            .collect::<Vec<_>>()
    };
    for (repair, entry) in entries {
        if let Some(entry) = entry {
            if synced_entry_is_stale_replay(entry.origin, &entry.metadata, forwarding) {
                note_stale_replay_fence_drop();
                stale_replay_dropped_keys.push(entry.key.clone());
            } else {
                commands::handle_upsert_synced(
                    sessions,
                    session_map,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    entry,
                    now_ns,
                    now_secs,
                    worker_id,
                );
            }
        } else {
            commands::handle_delete_synced(
                sessions,
                session_map,
                forwarding,
                ha_state,
                repair.key.clone(),
                now_ns,
                now_secs,
                deleted_synced_keys,
                worker_id,
            );
        }
        worker_queue::complete_session_import_repair(worker_id, &repair);
    }
}

