use super::super::*;
use crate::afxdp::DeferredRedirectDelete;

/// Apply one identity-conditional delete from a micro-batch envelope. The
/// session id is checked immediately before dispatching the ordinary teardown
/// so a queued policy delete cannot remove a tuple reincarnation that
/// replaced the captured row.
///
/// The check-then-teardown is atomic with respect to the table: this worker
/// is the table's sole mutator (single-threaded ownership — no other thread
/// can name these entries), and OS preemption mid-handler freezes the table
/// rather than interleaving foreign mutations, so the teardown removes
/// exactly what the check validated. Cross-worker / cross-attempt fencing is
/// the CALLER's job: the batch arm holds the report mutex (the abort fence)
/// across the cancel check and the whole per-item loop, so a coordinator
/// abort either lands before an item's check (the item then skips) or after
/// its teardown completed (its effects are final before the coordinator
/// returns).
///
/// The companion is removed ONLY on full key equality between the live
/// derivation (from the MATCHED forward's NAT — the coordinator cannot derive
/// it) and the captured companion: a mismatch preserves it (partial) rather
/// than deleting by an uncertain key, and an unexpected live companion
/// (capture expects none) refuses BEFORE any removal. Mirror (conntrack)
/// repair is deliberately NOT done here: only the coordinator, holding the
/// batch's Finalizing gate lease after every worker reports, can distinguish
/// "no survivor anywhere" (delete the bare row) from "a survivor on another
/// worker" (republish its value).
pub(in crate::afxdp::session_glue) fn handle_remove_policy_item(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    item: &crate::afxdp::PolicyDeleteItem,
    report: &mut crate::afxdp::PolicyDeleteBatchReport,
    index: usize,
    now_ns: u64,
    now_secs: u64,
    deleted_keys: &mut Vec<SessionKey>,
    worker_id: u32,
    deferred_redirects: &mut Vec<DeferredRedirectDelete>,
) -> bool {
    if item.session_id == 0 || sessions.session_id_for(&item.key) != item.session_id {
        return false;
    }
    // Validate the companion half BEFORE removing anything.
    let mut remove_companion: Option<SessionKey> = None;
    if !item.forward_only {
        let derived = sessions
            .probe_with_origin(&item.key)
            .map(|(lookup, _)| reverse_session_key(&item.key, lookup.decision.nat));
        match (&item.captured_companion, item.companion_session_id) {
            (None, 0) => {
                if let Some(companion) = derived.as_ref() {
                    if sessions.session_id_for(companion) != 0 {
                        report.refused[index] = true;
                        return false;
                    }
                }
            }
            (Some(captured), expected) if expected != 0 => match derived {
                Some(derived) if derived == *captured => {
                    // 0 is the unknown sentinel (never allocated to a live
                    // entry): an absent expected companion is already
                    // converged — the idle race won between READ and delete —
                    // not partial. Only a LIVE different incarnation preserves
                    // and reports.
                    match sessions.session_id_for(&derived) {
                        0 => {}
                        actual if actual == expected => {
                            remove_companion = Some(derived);
                        }
                        _ => {
                            report.partial[index] = true;
                        }
                    }
                }
                // Live derivation disagrees with the capture: preserve the
                // companion, remove the id-exact forward below, report
                // partial. Never delete by a key the capture did not name.
                _ => {
                    report.partial[index] = true;
                }
            },
            _ => {
                report.refused[index] = true;
                return false;
            }
        }
    }
    // Self-reversing tuple (forward and companion are the SAME key): the
    // forward call below removes it and collects its intent, so a second
    // call would find nothing and fall into the absent branch — which
    // issues BPF under the abort fence. Drop it: the forward intent's
    // execution releases a SUPERSET of that branch (derived rows plus every
    // row the holder holds for the owner, `release_entry`'s held arm), so
    // nothing — table or alias claims — is stranded.
    if remove_companion.as_ref().is_some_and(|companion| companion == &item.key) {
        remove_companion = None;
    }
    handle_delete_synced_with_guard(
        sessions,
        session_map,
        forwarding,
        ha_state,
        item.key.clone(),
        now_ns,
        now_secs,
        deleted_keys,
        worker_id,
        false,
        false,
        &mut *deferred_redirects,
        0,
        None,
    );
    if let Some(companion) = remove_companion {
        handle_delete_synced_with_guard(
            sessions,
            session_map,
            forwarding,
            ha_state,
            companion,
            now_ns,
            now_secs,
            deleted_keys,
            worker_id,
        false,
        false,
        &mut *deferred_redirects,
        0,
        None,
    );
    }
    true
}

/// Apply `WorkerCommand::ProbePolicyBatch`: one table walk serving every
/// unfilled bare-tuple slot with its first same-bare-tuple entry as a
/// republish candidate. Read-only: no table, steering, or BPF mutation, so no
/// fence is needed. First reporter wins per slot; every survivor describes
/// the same live tuple, so any one republishes correctly (the same
/// arbitrariness as the shared path's `.find()` survivor pick).
pub(in crate::afxdp::session_glue) fn handle_probe_policy_tuples(
    sessions: &SessionTable,
    bares: &[SessionKey],
    found: &std::sync::Mutex<Vec<Option<SyncedSessionEntry>>>,
) {
    {
        let slots = found
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slots.iter().all(Option::is_some) {
            return;
        }
    }
    let wanted: std::collections::HashSet<&SessionKey> = bares.iter().collect();
    let mut hits: Vec<(usize, SyncedSessionEntry)> = Vec::new();
    sessions.iter_with_origin(|key, decision, metadata, origin| {
        let mut key_bare = key.clone();
        key_bare.routing_domain = 0;
        key_bare.discriminator = Default::default();
        if !wanted.contains(&key_bare) {
            return;
        }
        let Some(index) = bares.iter().position(|bare| *bare == key_bare) else {
            return;
        };
        if hits.iter().any(|(filled, _)| *filled == index) {
            return;
        }
        hits.push((
            index,
            SyncedSessionEntry {
                key: key.clone(),
                decision,
                metadata: metadata.clone(),
                leak_incarnation: 0,
                origin,
                protocol: key.protocol,
                tcp_flags: 0,
                generation: 0,
                session_id: sessions.session_id_for(key),
                tcp_close_class: 0,
            },
        ));
    });
    if !hits.is_empty() {
        let mut slots = found
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (index, entry) in hits {
            if slots[index].is_none() {
                slots[index] = Some(entry);
            }
        }
    }
}

/// Apply `WorkerCommand::DeleteSynced`: drop the session and either
/// republish the kernel session-map alias (if the session table had
/// an entry to inspect) or just delete the live entry.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::DeleteSynced` match arm.
///
/// #6457: the deleted key is ALSO pushed onto `deleted_keys` so the worker
/// loop (which owns the per-binding flow caches `apply_worker_commands`
/// cannot see) invalidates every flow-cache slot backing it. The key is
/// recorded UNCONDITIONALLY — even when this worker's session table has no
/// entry (`delete_alias` is `None`): a stale cached `RewriteDescriptor`
/// outlives the table entry it was seeded from (that survival is exactly
/// the bug), so gating the record on the table lookup would leave the
/// stale permit in place. A superfluous record costs one no-op
/// `invalidate_slot` per binding (key+ifindex mismatch) — bounded by the
/// control-plane delete rate, never per-packet.
pub(in crate::afxdp::session_glue) fn handle_delete_synced(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    key: SessionKey,
    now_ns: u64,
    now_secs: u64,
    deleted_keys: &mut Vec<SessionKey>,
    worker_id: u32,
) {
    handle_delete_synced_with_guard(
        sessions,
        session_map,
        forwarding,
        ha_state,
        key,
        now_ns,
        now_secs,
        deleted_keys,
        worker_id,
        true,
        true,
        &mut Vec::new(),
        0,
        None,
    );
}

/// #10512 scoped HA worker teardown: identity-conditional twin of
/// [`handle_delete_synced`] — the entry goes only when its live session
/// id still matches the captured one.
pub(in crate::afxdp::session_glue) fn handle_delete_synced_conditional(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    key: SessionKey,
    expected_id: u64,
    now_ns: u64,
    now_secs: u64,
    deleted_keys: &mut Vec<SessionKey>,
    worker_id: u32,
    companion: Option<SessionKey>,
) {
    handle_delete_synced_with_guard(
        sessions,
        session_map,
        forwarding,
        ha_state,
        key,
        now_ns,
        now_secs,
        deleted_keys,
        worker_id,
        true,
        true,
        &mut Vec::new(),
        expected_id,
        companion,
    );
}
fn handle_delete_synced_with_guard(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    key: SessionKey,
    now_ns: u64,
    now_secs: u64,
    deleted_keys: &mut Vec<SessionKey>,
    worker_id: u32,
    enforce_peer_owner: bool,
    remove_mirror: bool,
    deferred_redirects: &mut Vec<DeferredRedirectDelete>,
    expected_id: u64,
    // #10512 scoped companion: torn down in this same handler after the
    // forward (never a standalone command — a declined forward must leave
    // it untouched). Unconditional once the forward matched (plan-literal;
    // same-thread atomic on the worker).
    companion: Option<SessionKey>,
) {
    // #10512 scoped HA delete: only the captured incarnation may go — a
    // replacement installed after the shared remove (queue delay) keeps
    // its row. Zero disables (legacy unconditional path). First: a
    // mismatched entry belongs to a different incarnation entirely, so no
    // other guard may even read it.
    if expected_id != 0 && sessions.session_id_for(&key) != expected_id {
        return;
    }
    let (delete_alias, existing_origin) = match sessions.probe_with_origin(&key) {
        Some((lookup, origin)) => (Some(lookup), Some(origin)),
        None => (None, None),
    };
    // `deferred_redirects` intentionally accumulates across calls: the batch
    // arm owns ONE vec for the whole batch (forward + companion items),
    // stashes it into the shared handoff INSIDE the fence scope, and the
    // COORDINATOR drains + executes after phase-1 acks. No per-call
    // emptiness invariant holds here — a second removal queuing behind the
    // first is the design, not a bug.
    // #9048: REFUSE a peer delete that would tear down a LIVE LOCAL session.
    //
    // This is the delete-side mirror of the install-side clobber guard in
    // `SessionTable::upsert_synced_with_origin` ("Reject peer data that would
    // clobber a locally-owned session"). Until now only the INSTALL verb had
    // one, and the asymmetry was invisible because the two verbs are guarded
    // in different files at different layers.
    //
    // WHY THE GENERATION GUARD DOES NOT COVER THIS, and why looking there is
    // the natural mistake. `deleteGenGuardV4` (Go, pkg/cluster) refuses only
    // when the STORED generation is non-zero, and `recvGenV4` is populated
    // solely by `recordInstalledGenV4` — prior PEER installs. A session this
    // node created itself has no stored generation, so the guard has no
    // ordering information and admits the delete. That is CORRECT for the
    // question it asks: it is a per-key reordering guard for one sender's
    // stream (#2170), not an ownership guard, and gen-0 means "I cannot order
    // this", not "this is safe". The ownership question is a different guard,
    // and on this verb it did not exist.
    //
    // WHEN IT FIRES. Only when both nodes are primary for the same RG — the
    // delta EMITTER is already gated on `IsPrimaryForRGFn`, so in normal
    // operation exactly one node emits and the receiver's entries at those
    // keys are peer-synced origin, leaving this guard inert. In a
    // dual-primary split both nodes forward the same flows, both create
    // LOCAL sessions under the same 5-tuples, and either node closing its
    // copy syncs a delete that tears down the other's LIVE session
    // mid-flight. Refusing is the conservative side: the worst case is a
    // session that lingers until it ages out, against a live flow killed
    // outright.
    //
    // Nothing else below runs either — not the NAT pool release, not the
    // session-map delete, and NOT the `deleted_keys` record. #6457 records
    // that key unconditionally so a stale flow-cache permit cannot outlive
    // the table entry it was seeded from; here the table entry SURVIVES, so
    // the permit is still backed and invalidating it would be wrong in the
    // one direction #6457 does not consider.
    // #9714 F4: the predicate is the INSTALL side's
    // `synced_entry_allows_local_replace`, not `owner_rg_is_locally_active`. The
    // latter hard-requires `owner_rg_id > 0`, so an entry whose owner RG is 0 —
    // UNKNOWN, not "no RG" — was unprotected on this verb while
    // `upsert_synced_with_origin` already declined to clobber it whenever ANY
    // redundancy group is forwarding-active. Owner 0 is reachable for a synced
    // forward session through the ingress-zone fallback, so this was not a
    // corner. The coordinator's #9714 guard carried the identical fail-open and
    // moved in the same change: install and delete now ask one question.
    let refuse = enforce_peer_owner
        && matches!(existing_origin, Some(origin) if !origin.is_peer_synced())
        && delete_alias.as_ref().is_some_and(|lookup| {
            !synced_entry_allows_local_replace(ha_state, lookup.metadata.owner_rg_id, now_secs)
        });
    if refuse {
        PEER_DELETE_REFUSED_LOCAL_OWNED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    sessions.delete(&key);
    deleted_keys.push(key.clone());
    if let Some(lookup) = delete_alias {
        // #4388: release the NAT pool port reserved for this peer-synced
        // session at install (`handle_upsert_synced` /
        // `reserve_synced_source_nat_allocation`) so the standby's local
        // allocator can reuse it. This is the same-key mirror of the
        // reservation and a no-op for a non-pool / non-reserved session
        // (`release_flow` returns false when the flow was never tracked).
        release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &key,
            lookup.decision.nat,
            lookup.metadata.is_reverse,
            now_ns,
            worker_id,
        );
        // #4512: mirror for NAT64. `handle_upsert_synced` now RESERVES a
        // peer-synced NAT64 forward flow's translated pool port in this node's
        // local allocator (`reserve_synced_nat64_allocation`), so this release
        // frees it on delete-sync with the same flow key — the standby-side
        // reserve/release pair that stops a post-failover local flow from
        // reusing the synced port (a no-op for a non-NAT64 / non-reserved
        // session, mirroring the source-NAT release above).
        crate::nat64::release_nat64_allocation_for_worker(
            &forwarding.nat64,
            &key,
            lookup.decision.nat,
            lookup.metadata.is_reverse,
            now_ns,
            worker_id,
        );
        if remove_mirror {
            delete_session_map_entry_for_removed_session(
                session_map,
                &key,
                lookup.decision,
                &lookup.metadata,
            );
        } else {
            // Batched policy path (deferred mode): collect the redirect
            // delete for phase 2 instead of issuing the BPF syscall here.
            // The abort fence is held across this whole call, and BPF
            // syscalls can stall (reclaim) — holding them would let a slow
            // worker wedge the coordinator's abort indefinitely. Table work
            // above is microsecond, syscall-free, and tree-standard to hold.
            deferred_redirects.push(DeferredRedirectDelete {
                key: key.clone(),
                decision: lookup.decision,
                metadata: lookup.metadata.clone(),
                origin: existing_origin.expect("lookup origin"),
                worker_id,
            });
        }
    } else {
        // #9560 round 3: the local entry is already gone, so there is no decision to
        // derive this session's rows from — and the bare key is only ONE of them. Its
        // NAT and forward-wire aliases were claimed by this worker too, and releasing
        // just the key left them claimed by a holder that will never name them again.
        release_all_session_rows(session_map, &key);
    }
    // Scoped companion (see param doc): same-handler teardown after the
    // forward, unconditional (legacy parity — the standalone reverse
    // command it replaces never checked either). Reached only when the
    // forward matched (mismatch returned at the top), so a declined
    // forward leaves both halves untouched.
    if let Some(companion_key) = companion {
        handle_delete_synced_with_guard(
            sessions,
            session_map,
            forwarding,
            ha_state,
            companion_key,
            now_ns,
            now_secs,
            deleted_keys,
            worker_id,
            enforce_peer_owner,
            remove_mirror,
            deferred_redirects,
            0,
            None,
        );
    }
}
