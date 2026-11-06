use super::*;

pub(in crate::afxdp) fn demote_shared_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: &[i32],
) {
    if owner_rgs.is_empty() {
        return;
    }
    let mut demoted_entries = Vec::new();
    {
        let mut sessions = lock_shared_recover(shared_sessions);
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.sessions, owner_rgs) {
            if let Some(entry) = sessions.get_mut(&key) {
                // Preserve every transient-local provenance in each alias:
                // later materialization must never make a local seed HA-exportable.
                if entry.origin.is_local_tun_origin() || entry.origin.is_transient_local_seed() {
                    continue;
                }
                let previous = entry.clone();
                entry.origin = SessionOrigin::SyncImport;
                demoted_entries.push((previous, entry.clone()));
            }
        }
    }
    for (previous, entry) in demoted_entries {
        refresh_reverse_prewarm_owner_rg_indexes(
            &shared_owner_rg_indexes.reverse_prewarm_sessions,
            forwarding,
            dynamic_neighbors,
            Some(&previous),
            Some(&entry),
        );
    }
    {
        let mut sessions = lock_shared_recover(shared_nat_sessions);
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.nat_sessions, owner_rgs) {
            if let Some(entry) = sessions.get_mut(&key) {
                if entry.origin.is_local_tun_origin() || entry.origin.is_transient_local_seed() {
                    continue;
                }
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
    {
        let mut sessions = lock_shared_recover(shared_forward_wire_sessions);
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.forward_wire_sessions, owner_rgs)
        {
            if let Some(entry) = sessions.get_mut(&key) {
                if entry.origin.is_local_tun_origin() || entry.origin.is_transient_local_seed() {
                    continue;
                }
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
}

pub(in crate::afxdp) fn synced_replica_entry(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
    let mut replica = entry.clone();
    replica.origin = entry.origin.worker_replica_origin();
    replica
}

/// Union the forward owner-RG session keys with the narrower
/// reverse-prewarm keys, deduplicated, preserving order: every `forward`
/// key first (in its original order), then each `reverse` key not already
/// present, in first-seen order.
///
/// #4069: membership is tested against a hash set built once (O(M)), so the
/// merge is O(N+M) — N reverse keys, M forward keys. The prior inline
/// `forward.contains(&key)` re-scanned the growing forward Vec once per
/// reverse key, i.e. O(N·M). This merge runs on the RG-activation prewarm,
/// which is on the failover critical path (~60ms/~130ms budget); on a busy
/// cluster with thousands of synced sessions the quadratic scan measurably
/// slowed how quickly a newly-primary node fully forwarded. The result set
/// (and its order) is identical to the old dedup — only the membership data
/// structure changed.
pub(in crate::afxdp) fn merge_owner_rg_candidate_keys(
    mut forward: Vec<SessionKey>,
    reverse: Vec<SessionKey>,
) -> Vec<SessionKey> {
    // Seed the membership set with the forward keys (O(M)), then probe each
    // reverse key in O(1). `insert` returns true only for a not-yet-seen
    // key, which is exactly the old `!forward.contains(&key)` predicate and
    // also folds out duplicates within `reverse` itself.
    let mut seen: FastSet<SessionKey> = forward.iter().cloned().collect();
    for key in reverse {
        if seen.insert(key.clone()) {
            forward.push(key);
        }
    }
    forward
}

/// Pre-warm reverse companions in shared session maps at RG activation.
///
/// With deterministic reverse companions (#310), the Go sync path already
/// pre-installs reverse entries via UpsertSynced. This function still runs
/// at activation to re-resolve egress with local forwarding state.
///
/// #8612: the parenthetical that used to sit here — "the pre-installed
/// entries carry the peer's interface indices/MACs" — described the
/// pre-#7097 world and has been false since that scrub. They carry ZERO
/// there: `ScrubNodeLocal` zeroes `FibIfindex`, `FibVlanID`, the MACs and
/// the ingress pair on every peer-owned row. The re-resolution is therefore
/// not a correction of the peer's numbering, it is the ONLY source of that
/// numbering — which is why the re-resolve must run and cannot be skipped as
/// an optimisation.
///
/// The one field that now survives is `FibGen` under
/// `LogFlagUserspaceTunnelEndpoint`, because there it is a
/// `StableTunnelEndpointID` (a fold of the interface NAME, identical on both
/// nodes) rather than a node-local number. That is the identity this
/// re-resolution has nothing to rebuild from if it is erased in transit.
///
/// Use the union of the shared owner-RG session index and the narrower
/// reverse-prewarm index here. Activation is infrequent, and locally promoted
/// sessions can exist in the shared table without appearing in the
/// reverse-prewarm subset, while split-RG reverse companions can still resolve
/// to an activated RG even when the forward entry's current owner RG is
/// different. Both cases need their forward entries restored to worker
/// SessionTables and, when applicable, their reverse companions synthesized
/// again on activation.
pub(in crate::afxdp) fn prewarm_reverse_synced_sessions_for_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: &[i32],
    now_secs: u64,
) {
    if owner_rgs.is_empty() {
        return;
    }
    let publish_session_map = session_map.fd >= 0;
    let owner_rg_set: std::collections::BTreeSet<i32> = owner_rgs.iter().copied().collect();
    // #4069: dedup the forward and reverse-prewarm key sets in O(N+M) via a
    // hash set (see merge_owner_rg_candidate_keys) instead of the former
    // O(N·M) `Vec::contains` scan on this failover-critical prewarm path.
    let candidate_keys = merge_owner_rg_candidate_keys(
        owner_rg_session_keys_serialized(
            shared_sessions,
            &shared_owner_rg_indexes.sessions,
            owner_rgs,
        ),
        owner_rg_session_keys_serialized(
            shared_sessions,
            &shared_owner_rg_indexes.reverse_prewarm_sessions,
            owner_rgs,
        ),
    );
    // #2402: acquire the shared-session guard with poison RECOVERY. The
    // prior `.lock().map(..).unwrap_or_default()` swallowed a poisoned
    // lock into EMPTY (forward_entries, reverse_entries) — so if a worker
    // had panicked while holding this mutex, RG activation proceeded as if
    // there were NO sessions to promote and silently dropped every active
    // synced session at the exact moment of failover. Recover the existing
    // map and compute from it instead.
    let (forward_entries, reverse_entries) = {
        let sessions = lock_shared_recover(shared_sessions);
        let mut forward_entries = Vec::new();
        let mut reverse_entries = Vec::new();
        for key in candidate_keys {
            let Some(entry) = sessions.get(&key) else {
                continue;
            };
            if entry.metadata.is_reverse {
                continue;
            }
            // #10612 (M4): fence stale replays at prewarm ingress. A pre-purge
            // snapshot lingering in shared must not be BPF-published or fanned
            // out after the purge deleted it. Checked here (before reverse
            // synthesis) so a stale forward suppresses both halves.
            if crate::afxdp::session_glue::synced_entry_is_stale_replay(
                entry.origin,
                &entry.metadata,
                forwarding,
            ) {
                crate::afxdp::session_glue::note_stale_replay_fence_drop();
                continue;
            }
            let allow_reverse_prewarm = entry.origin.is_peer_synced()
                || matches!(entry.origin, SessionOrigin::SharedPromote);
            let Some(reverse) = synthesized_synced_reverse_entry(
                forwarding,
                ha_state,
                dynamic_neighbors,
                entry,
                now_secs,
            ) else {
                // Collect forward entry even if reverse can't be synthesized,
                // as long as the forward session belongs to an activated RG.
                if owner_rg_set.contains(&entry.metadata.owner_rg_id) {
                    forward_entries.push(entry.clone());
                }
                continue;
            };
            if owner_rg_set.contains(&entry.metadata.owner_rg_id)
                || owner_rg_set.contains(&reverse.metadata.owner_rg_id)
            {
                forward_entries.push(entry.clone());
                if allow_reverse_prewarm {
                    reverse_entries.push(reverse);
                }
            }
        }
        (forward_entries, reverse_entries)
    };
    if forward_entries.is_empty() && reverse_entries.is_empty() {
        return;
    }
    // Push forward entries to workers so their local SessionTables have
    // the promoted sessions. Without this, workers only have reverse
    // sessions and incoming traffic on existing flows misses the forward
    // session lookup.
    //
    // Also publish forward sessions to the USERSPACE_SESSIONS BPF map
    // synchronously (#475). Without this, there is a window between RG
    // activation and the workers processing UpsertSynced where the XDP
    // shim has no REDIRECT entry for forward flows. Packets arrive as
    // session misses and can resolve to HAInactive if the worker hasn't
    // yet applied the HA state update.
    let mut fwd_publish_errors = 0u32;
    for forward in &forward_entries {
        if publish_session_map
            && publish_session_map_entry_for_session(
                session_map,
                &forward.key,
                forward.decision,
                &forward.metadata,
                forwarding.has_routing_domains,
                forwarding.has_multiple_zones,
            )
            .is_err()
        {
            fwd_publish_errors += 1;
            // #1789: fold the activation-prewarm forward publish failures
            // into the global publish-error total. Semantically identical
            // to every other counted site (a USERSPACE_SESSIONS publish
            // that returned Err); the local fwd_publish_errors count is
            // kept only for the existing one-shot eprintln below, so this
            // is one increment per failure, not a double count.
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
        for commands in worker_commands {
            // #1807: recover-and-push — `if let Ok` silently DROPPED the
            // activation-prewarm UpsertSynced for a poisoned worker queue.
            // #15950: raw ForwardFlow/LocalMiss rows need the replica
            // transform, but a SharedPromote row is locally-owned promoted
            // authority and must be restored as SharedPromote (its worker
            // copy is protected by the local-replace guard in upsert).
            let replica = if forward.origin == SessionOrigin::SharedPromote {
                forward.clone()
            } else {
                synced_replica_entry(forward)
            };
            let mut pending = worker_queue::lock_recover(commands);
            worker_queue::push_bounded(
                &mut pending,
                WorkerCommand::UpsertSynced(replica),
            );
        }
    }
    if fwd_publish_errors > 0 {
        eprintln!(
            "xpf-ha: prewarm forward BPF publish: {} errors out of {} entries",
            fwd_publish_errors,
            forward_entries.len()
        );
    }
    for reverse in reverse_entries {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &reverse,
        );
        if publish_session_map {
            // #1789: the reverse-prewarm publish in the same activation
            // path was still swallowed with `let _ =`; count it like the
            // forward loop above.
            if publish_session_map_entry_for_session(
                session_map,
                &reverse.key,
                reverse.decision,
                &reverse.metadata,
                forwarding.has_routing_domains,
                forwarding.has_multiple_zones,
            )
            .is_err()
            {
                SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
        }
        for commands in worker_commands {
            // #1807: recover-and-push — `if let Ok` silently DROPPED the
            // reverse-prewarm UpsertSynced for a poisoned worker queue.
            let mut pending = worker_queue::lock_recover(commands);
            worker_queue::push_bounded(
                &mut pending,
                WorkerCommand::UpsertSynced(synced_replica_entry(&reverse)),
            );
        }
    }
}

/// Republish USERSPACE_SESSIONS BPF map entries for ALL shared sessions
/// belonging to the given owner RGs.
///
/// Called during RG activation (#475) to close the gap where sessions
/// exist in the shared table (received via sync) but their BPF map entries
/// were deleted during the previous demotion cycle. The `reverse_prewarm`
/// index only covers sessions added via `upsert_synced_session` — locally
/// originated sessions that were demoted then re-synced may not appear
/// there. This function uses the comprehensive `sessions` owner-RG index
/// to ensure no session is missed.
pub(in crate::afxdp) fn republish_bpf_session_entries_for_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    session_map: SteeringMap<'_>,
    owner_rgs: &[i32],
    // #9517: this republishes peer-synced sessions on RG activation, which is
    // exactly where PASS_TO_KERNEL rows come from.
    // #10612 (N1): takes forwarding (not just the domains bool) to fence
    // stale-zone rows: a shared-transient stale row must not be BPF-resurrected.
    forwarding: &ForwardingState,
) -> u32 {
    if owner_rgs.is_empty() {
        return 0;
    }
    let keys = owner_rg_session_keys_serialized(
        shared_sessions,
        &shared_owner_rg_indexes.sessions,
        owner_rgs,
    );
    // Collect entries under the lock, then release before BPF syscalls
    // to avoid blocking concurrent session insert/remove/lookup.
    let entries: Vec<_> = {
        // #2402: recover a poisoned lock instead of returning 0 — a prior
        // worker panic must not void the activation BPF-map republish.
        let sessions = lock_shared_recover(shared_sessions);
        keys.iter()
            .filter_map(|key| {
                sessions
                    .get(key)
                    .map(|e| (e.key.clone(), e.decision, e.metadata.clone(), e.origin))
            })
            .collect()
    };
    let mut published = 0u32;
    let mut errors = 0u32;
    for (key, decision, metadata, origin) in &entries {
        // #10612 (N1): skip stale-zone rows (fence BEFORE the BPF publish,
        // mirroring prewarm). BPF-only gap: narrow race, heals on demotion.
        if crate::afxdp::session_glue::synced_entry_is_stale_replay(*origin, metadata, forwarding) {
            crate::afxdp::session_glue::note_stale_replay_fence_drop();
            continue;
        }
        if publish_session_map_entry_for_session(
            session_map,
            key,
            *decision,
            metadata,
            forwarding.has_routing_domains,
            forwarding.has_multiple_zones,
        )
        .is_ok()
        {
            published += 1;
        } else {
            errors += 1;
            // #1789: feed the activation-republish failures into the same
            // always-on total as every other USERSPACE_SESSIONS publish site.
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
    }
    if errors > 0 {
        eprintln!(
            "xpf-ha: republish_bpf_session_entries: {} errors out of {} attempted",
            errors,
            published + errors
        );
    }
    published
}

pub(in crate::afxdp) fn owner_rg_session_keys(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rgs: &[i32],
) -> Vec<SessionKey> {
    let mut keys = FastSet::default();
    {
        // #2402: recover poison so the owner-RG index is not silently
        // emptied (which hides every session from promotion/demotion).
        let index = lock_shared_recover(index);
        for owner_rg_id in owner_rgs {
            if let Some(entries) = index.get(owner_rg_id) {
                keys.extend(entries.iter().cloned());
            }
        }
    }
    keys.into_iter().collect()
}

pub(in crate::afxdp) fn owner_rg_session_keys_serialized(
    sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rgs: &[i32],
) -> Vec<SessionKey> {
    // #2402: hold the shared-session lock (recovering poison) to serialize
    // against concurrent insert/remove while the index is read.
    let _sessions = lock_shared_recover(sessions);
    owner_rg_session_keys(index, owner_rgs)
}

/// Maintain the reverse-prewarm owner-RG index across one entry transition:
/// `(Some, None)` is a delete, `(None, Some)` an insert, `(Some, Some)` a
/// replace of the same key.
///
/// #7209: THE INDEX IS ADD-ONLY WHILE THE ENTRY IS LIVE. Un-filing happens
/// exactly once, when the entry is authoritatively REMOVED — and that is done
/// by `remove_shared_session`, not here, so that every removal path is covered
/// rather than only the coordinator's delete verb.
///
/// An entry's buckets are `reverse_prewarm_owner_rg_candidates`: the RG named
/// by its own metadata (which travels with the entry, so it cannot drift) and
/// the RG that owns the egress interface a reply to `key.src_ip` would leave
/// by — read out of the FIB, and therefore a property of WHEN the question is
/// asked. So a refresh can only ever compute the buckets the FIB can name
/// *right now*, which is a strict SUBSET of the truth whenever the FIB is
/// momentarily blind to the reply path: a RETH member down with the route not
/// yet re-homed, or `stop_inner` having emptied `forwarding` between a failed
/// reconcile and its retry.
///
/// THE TWO DIRECTIONS ARE NOT SYMMETRIC, which is the whole design.
///
///   * An EXTRA bucket costs one re-synthesis that
///     `prewarm_reverse_synced_sessions_for_owner_rgs` then discards — it
///     re-derives the reverse companion under live tables and re-checks
///     `owner_rg_set.contains(..)` before keeping anything. The consumer
///     absorbs over-filing by construction.
///   * A MISSING bucket is never checked, because the key never enters the
///     candidate set at all. The session is simply not pre-resolved when that
///     RG activates.
///
/// So over-filing degrades a scan and under-filing drops reply traffic at a
/// failover. Anything this function cannot re-derive, it must not remove.
///
/// HISTORY, because the shape here is the second attempt and the first one
/// shipped. Originally the removal half recomputed the PREVIOUS entry's
/// candidate set against the CURRENT forwarding, which stranded a key
/// permanently whenever a route moved between RGs during the entry's life —
/// the index is only READ, never rebuilt, by the activation prewarm, so
/// nothing ever named that bucket again. PR #8479 fixed that by making every
/// refresh un-file from EVERY bucket and re-file `candidates(next)`, which
/// removed the strand and introduced the inverse defect above: a refresh
/// landing in a blind-FIB window narrowed the filing and nothing restored it.
/// Splitting the two — add-only here, authoritative un-file at removal — is
/// what gets both, and it is why the un-file no longer needs `forwarding` at
/// all and could therefore move to the one place every removal goes through.
pub(in crate::afxdp) fn refresh_reverse_prewarm_owner_rg_indexes(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    previous_entry: Option<&SyncedSessionEntry>,
    next_entry: Option<&SyncedSessionEntry>,
) {
    let Some(next_entry) = next_entry else {
        // A removal. Un-file authoritatively — the entry is gone, so no bucket
        // it holds can still be wanted, and no FIB lookup is needed to know
        // that. `remove_shared_session` already does this for every removal
        // path; keeping it here too makes the coordinator's delete verb
        // self-contained and the operation is idempotent.
        if let Some(previous_entry) = previous_entry {
            // #2402: recover poison so index maintenance is not skipped after
            // a prior worker panic.
            let mut index = lock_shared_recover(index);
            remove_owner_rg_index_key_from_every_bucket_locked(&mut index, &previous_entry.key);
        }
        return;
    };
    // The entry is live: ADD what the FIB can name now, remove nothing.
    // `previous_entry` is deliberately unused on this arm — its buckets were
    // filed by an earlier call that could see a FIB this one may not.
    let next_owner_rgs =
        reverse_prewarm_owner_rg_candidates(forwarding, dynamic_neighbors, next_entry);
    let mut index = lock_shared_recover(index);
    for owner_rg_id in next_owner_rgs {
        index
            .entry(owner_rg_id)
            .or_insert_with(FastSet::default)
            .insert(next_entry.key.clone());
    }
}

/// #7209: drop `key` from every owner-RG bucket, pruning buckets it emptied.
///
/// Needs no `forwarding`, which is the point: an authoritative un-file must not
/// depend on a table that may be unable to name the buckets the key is in.
///
/// The `retain` predicate also drops buckets that were ALREADY empty. That is
/// not a behaviour change: `remove_owner_rg_index_entry_locked` has always
/// pruned on emptying, so an empty bucket is unreachable state, and
/// `owner_rg_session_keys` reads through `get`, for which an empty set and an
/// absent one are indistinguishable.
///
/// COST, stated honestly. `HashMap::retain` is O(CAPACITY), not O(len), so this
/// walks the whole allocation and the pruning does not shrink its high-water
/// capacity. Capacity is bounded by the number of DISTINCT owner-RG ids ever
/// filed, which on a real chassis cluster is single digits — but the helper
/// does not enforce that: `metadata.owner_rg_id` arrives from the peer as a raw
/// `i32` and every positive value is filed. A peer sending N distinct ids
/// therefore inflates this walk. That is a bound worth enforcing at the import
/// boundary rather than assuming here; it is not enforced today. Runs once per
/// authoritative removal (never per refresh) on the control thread, and
/// allocates nothing.
pub(super) fn remove_owner_rg_index_key_from_every_bucket_locked(
    index: &mut OwnerRgSessionIndex,
    key: &SessionKey,
) {
    index.retain(|_, keys| {
        keys.remove(key);
        !keys.is_empty()
    });
}

/// #7209: test-only view of the candidate set, so a cell can assert which
/// arrangement its fixture is actually in rather than assuming it.
#[cfg(test)]
pub(in crate::afxdp) fn reverse_prewarm_owner_rg_candidates_for_test(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: &SyncedSessionEntry,
) -> FastSet<i32> {
    reverse_prewarm_owner_rg_candidates(forwarding, dynamic_neighbors, entry)
}

fn reverse_prewarm_owner_rg_candidates(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: &SyncedSessionEntry,
) -> FastSet<i32> {
    let mut owner_rgs = FastSet::default();
    if entry.metadata.is_reverse || !entry.origin.is_peer_synced() {
        return owner_rgs;
    }
    // #8486: PEER-SUPPLIED, so it is bounded here. `reverse_owner_rg_id` below
    // is derived from THIS node's own forwarding state and needs no bound.
    if is_fileable_owner_rg(entry.metadata.owner_rg_id) {
        owner_rgs.insert(entry.metadata.owner_rg_id);
    }
    // #12086 R1-F2: derive the reply target's native table exactly as
    // `synthesized_synced_reverse_entry` does. A forward PBR install stamp is
    // directional and can name a table with no route to the reply target.
    // Keep an Unresolvable native table in the add-only index as a best-effort
    // default-table candidate: over-filing is discarded by the activation
    // consumer, while under-filing omits the reverse owner RG entirely (#7209).
    let reverse_table = match super::forwarding::native_route_table_for_flow_target(
        forwarding,
        entry.key.routing_domain,
        entry.metadata.ingress_ifindex as i32,
        entry.metadata.ingress_vlan_id,
        None,
        entry.key.src_ip,
    ) {
        super::forwarding::NativeRouteTable::Default
        | super::forwarding::NativeRouteTable::Unresolvable { .. } => None,
        super::forwarding::NativeRouteTable::Table { table, .. } => Some(table),
    };
    let reverse_table = reverse_table.as_deref();
    let reverse_resolution =
        super::interface_nat_local_resolution(forwarding, entry.key.src_ip, reverse_table)
            .unwrap_or_else(|| {
                super::forwarding::lookup_forwarding_resolution_in_table_with_dynamic(
                    forwarding,
                    dynamic_neighbors,
                    entry.key.src_ip,
                    reverse_table,
                )
                .resolution
            });
    let reverse_owner_rg_id = owner_rg_for_resolution(forwarding, reverse_resolution);
    if reverse_owner_rg_id > 0 {
        owner_rgs.insert(reverse_owner_rg_id);
    }
    owner_rgs
}

pub(super) fn update_owner_rg_index(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    key: &SessionKey,
    previous_owner_rg: Option<i32>,
    owner_rg_id: i32,
) {
    if let Some(previous_owner_rg) = previous_owner_rg
        && previous_owner_rg != owner_rg_id
    {
        remove_owner_rg_index_entry(index, previous_owner_rg, key);
    }
    // #8486: the bound is here, on the FILING, not on the import.
    if !is_fileable_owner_rg(owner_rg_id) {
        return;
    }
    // #2402: recover poison (owner-RG index maintenance).
    let mut index = lock_shared_recover(index);
    index
        .entry(owner_rg_id)
        .or_insert_with(FastSet::default)
        .insert(key.clone());
}

pub(super) fn remove_owner_rg_index_entry(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rg_id: i32,
    key: &SessionKey,
) {
    if owner_rg_id <= 0 {
        return;
    }
    // #2402: recover poison (owner-RG index maintenance).
    let mut index = lock_shared_recover(index);
    remove_owner_rg_index_entry_locked(&mut index, owner_rg_id, key);
}

fn remove_owner_rg_index_entry_locked(
    index: &mut OwnerRgSessionIndex,
    owner_rg_id: i32,
    key: &SessionKey,
) {
    if let Some(keys) = index.get_mut(&owner_rg_id) {
        keys.remove(key);
        if keys.is_empty() {
            index.remove(&owner_rg_id);
        }
    }
}
