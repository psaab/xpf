use super::super::*;

/// Apply `WorkerCommand::DemoteOwnerRGS`: walk each demoted owner RG,
/// re-resolve forwarding for every demoted session, re-publish the
/// kernel session-map entry, and append demoted keys (deduped) to
/// `cancelled_keys`.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::DemoteOwnerRGS` match arm. Takes a narrow
/// `&mut Vec<SessionKey>` because the dispatcher builds the
/// `WorkerCommandResults` accumulator after the loop (per #1346
/// plan v2).
///
/// #5155: the dedup uses a companion `cancelled_keys_seen`
/// `FxHashSet` for an O(1) membership test rather than a linear
/// `cancelled_keys.iter().any(..)` scan. `SessionTable::demote_owner_rg`
/// only flips origin to `SyncImport` — it does NOT remove the entry
/// from `owner_rg_sessions[rg]` — so a repeated `Demote{[rg]}` in the
/// same command stream re-discovers the same key and the dedup is
/// load-bearing (see the dispatcher order-pin test). The old scan was
/// O(N^2) over the growing `cancelled_keys` Vec: `demote_owner_rg`
/// yields unique keys per RG, so every `.any()` reached the tail. With
/// `max_sessions` = 131072 that is ~8.6e9 `SessionKey` comparisons on
/// the packet worker before the heartbeat store — a failover-time
/// stall. The set makes the whole pass O(N). The set is threaded from
/// the caller so the dedup persists across the multiple
/// `handle_demote_owner_rgs` calls in one dispatch loop, exactly as the
/// shared `cancelled_keys` Vec did. `cancelled_keys` stays a Vec so the
/// first-occurrence output order is preserved (the downstream
/// `cancel_queued_flow_on_binding` iteration and the order-pin test both
/// observe it).
pub(in crate::afxdp::session_glue) fn handle_demote_owner_rgs(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
    cancelled_keys: &mut Vec<SessionKey>,
    cancelled_keys_seen: &mut rustc_hash::FxHashSet<SessionKey>,
) {
    let mut seen_owner_rgs = std::collections::BTreeSet::new();
    for owner_rg_id in owner_rgs {
        if !seen_owner_rgs.insert(owner_rg_id) {
            continue;
        }
        for demoted_key in sessions.demote_owner_rg(owner_rg_id) {
            let Some((decision, metadata, _origin)) = sessions.entry_with_origin(&demoted_key)
            else {
                continue;
            };
            let flow = SessionFlow {
                src_ip: demoted_key.src_ip,
                dst_ip: demoted_key.dst_ip,
                forward_key: demoted_key.clone(),
            };
            let resolution_target = resolution_target_for_session(&flow, decision);
            let looked_up_resolution = lookup_forwarding_resolution_for_session(
                forwarding,
                dynamic_neighbors,
                &flow,
                decision,
            );
            let looked_up_resolution = super::super::prefer_local_forward_candidate_for_fabric_ingress(
                forwarding,
                ha_state,
                dynamic_neighbors,
                now_secs,
                metadata.fabric_ingress,
                resolution_target,
                looked_up_resolution,
            );
            let enforced_resolution =
                enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, looked_up_resolution);
            let refreshed_decision = SessionDecision {
                resolution: redirect_session_via_fabric_if_needed(
                    forwarding,
                    enforced_resolution,
                    metadata.fabric_ingress,
                    metadata.ingress_zone,
                ),
                ..decision
            };
            let rewrote_session = refreshed_decision.resolution.disposition
                != ForwardingDisposition::HAInactive
                && sessions.refresh_for_ha_transition(
                    &demoted_key,
                    refreshed_decision,
                    metadata.clone(),
                    now_ns,
                );
            let Some((decision, metadata, origin)) = sessions.entry_with_origin(&demoted_key)
            else {
                continue;
            };
            let owner_rg_id = metadata.owner_rg_id;
            let publish_decision = if rewrote_session {
                decision
            } else {
                refreshed_decision
            };
            let publish_metadata = if rewrote_session {
                metadata
            } else {
                metadata.clone()
            };
            publish_worker_session_map_entry(
                session_map,
                forwarding,
                &demoted_key,
                publish_decision,
                &publish_metadata,
                origin,
                synced_entry_allows_local_replace(ha_state, owner_rg_id, now_secs),
            );
            // #5155: O(1) membership via the companion set. `insert`
            // returns true only on first sight of the key, so the Vec
            // still records each key once in first-occurrence order.
            if cancelled_keys_seen.insert(demoted_key.clone()) {
                cancelled_keys.push(demoted_key);
            }
        }
    }
}
