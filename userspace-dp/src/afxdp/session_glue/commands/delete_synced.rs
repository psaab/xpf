use super::super::*;

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
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    // #9048: the local HA view, so a peer delete cannot tear down a session
    // this node is actively forwarding for. Same two inputs the sibling
    // `handle_upsert_synced` arm already takes.
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    key: SessionKey,
    now_ns: u64,
    now_secs: u64,
    deleted_keys: &mut Vec<SessionKey>,
    // #6211 F2: THIS worker's id. `DeleteSynced` is replicated to EVERY worker
    // queue (`replicate_session_delete`), so each worker drops its own holder
    // bit and the port is freed by whichever worker happens to be last.
    worker_id: u32,
) {
    let (delete_alias, existing_origin) = match sessions.lookup_with_origin(&key, now_ns, 0) {
        Some((lookup, origin)) => (Some(lookup), Some(origin)),
        None => (None, None),
    };
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
    let refuse = matches!(existing_origin, Some(origin) if !origin.is_peer_synced())
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
        delete_session_map_entry_for_removed_session(
            session_map_fd,
            &key,
            lookup.decision,
            &lookup.metadata,
        );
    } else {
        delete_live_session_key(session_map_fd, &key);
    }
}
