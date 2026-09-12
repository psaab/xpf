use super::super::*;

/// One HA-managed session's refreshed publish plan, as produced by
/// [`collect_refresh_owner_rgs_items`]: the re-resolved decision, the
/// re-stamped metadata, the origin, and the freshly recomputed
/// `allow_replace_local` that `publish_worker_session_map_entry` needs
/// to decide between the userspace REDIRECT fast path and a kernel-local
/// `PASS_TO_KERNEL` entry.
pub(in crate::afxdp::session_glue) type RefreshOwnerRgsItem =
    (SessionKey, SessionDecision, SessionMetadata, SessionOrigin, bool);

/// Apply `WorkerCommand::RefreshOwnerRGS`: re-evaluate every
/// HA-managed worker session (not just those currently indexed under
/// the activated RG) and republish refreshed session-map entries.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::RefreshOwnerRGS` match arm. The wider scan handles
/// split-RG reverse companions that can remain owned by RG2 while a
/// move of RG1 changes whether they should locally forward or
/// fabric-redirect.
pub(in crate::afxdp::session_glue) fn handle_refresh_owner_rgs(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
) {
    if !owner_rgs.iter().any(|owner_rg_id| *owner_rg_id > 0) {
        return;
    }

    let refresh = collect_refresh_owner_rgs_items(
        sessions,
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
    );

    for (key, refreshed_decision, refreshed_metadata, origin, allow_replace_local) in refresh {
        // #5152: gate the LIVENESS re-stamp on the refreshed disposition,
        // exactly as the demote path (`handle_demote_owner_rgs`) does. The
        // wider activation scan re-touches EVERY HA-managed session — including
        // unrelated split-RG sessions this newly-activated node does NOT own.
        // `refresh_for_ha_transition` zeroes `first_held_ns`/`seen_rg_epoch`
        // and re-stamps `last_seen_ns` (the #2120 §6.4 promotion write-site):
        // correct for a session this node now forwards, but WRONG for one that
        // re-resolves to `HAInactive`. Re-stamping a non-forwarding entry would
        // reset its bounded-leak HOLD clock, defeating the standby leak ceiling
        // for a redundancy group that never activated here. Only re-stamp
        // liveness for a genuinely-forwarding session.
        let rewrote_session = refreshed_decision.resolution.disposition
            != ForwardingDisposition::HAInactive
            && sessions.refresh_for_ha_transition(
                &key,
                refreshed_decision,
                refreshed_metadata.clone(),
                now_ns,
            );
        // Still publish the refreshed forwarding decision for every scanned
        // session that is still present — the documented reason for the wider
        // scan is to land split-RG local-forward<->fabric-redirect transitions
        // in the session map, and the demote path likewise publishes
        // regardless of whether it re-stamped liveness. `rewrote_session`
        // already proves the entry is present for the forwarding case; for a
        // skipped (HAInactive) session, confirm it did not vanish between the
        // collect scan and here (mirrors demote's `entry_with_origin(..) else
        // continue`).
        if !rewrote_session && sessions.entry_with_origin(&key).is_none() {
            continue;
        }
        publish_worker_session_map_entry(
            session_map,
            forwarding,
            &key,
            refreshed_decision,
            &refreshed_metadata,
            origin,
            // #4805: recompute `allow_replace_local` per session from
            // the CURRENT HA state — do NOT hardcode `false`. A
            // standby-owned peer-synced `LocalDelivery` session must stay
            // on the userspace REDIRECT fast path (fabric-redirect / drop
            // under policy), not fall through to a kernel-local
            // `PASS_TO_KERNEL` entry that delivers host-bound traffic
            // straight to this standby node's own stack with no policy
            // enforcement. The wider activation scan re-touches sessions
            // owned by RGs OTHER than the one that just moved (split-RG),
            // so the value it publishes must match the session's own
            // owner-RG state exactly as the initial-sync path
            // (`handle_upsert_synced`) does — hence the per-session
            // `synced_entry_allows_local_replace`, computed alongside the
            // refreshed metadata in `collect_refresh_owner_rgs_items`.
            allow_replace_local,
        );
    }
}

/// Re-evaluate every HA-managed worker session and produce its refreshed
/// publish plan (decision + metadata + origin + per-session
/// `allow_replace_local`) without mutating the session table.
///
/// Split out from `handle_refresh_owner_rgs` (#4805) so the
/// `allow_replace_local` computation is unit-testable without a live BPF
/// session-map fd: the publish disposition for a synced `LocalDelivery`
/// entry is fully determined by
/// `force_live_redirect_for_worker_synced_entry(decision, metadata,
/// origin, allow_replace_local)`, and this is the single site that
/// computes that argument for the activation refresh path.
pub(in crate::afxdp::session_glue) fn collect_refresh_owner_rgs_items(
    sessions: &SessionTable,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
) -> Vec<RefreshOwnerRgsItem> {
    // Activation must re-evaluate all HA-managed worker sessions, not
    // just those currently indexed under the activated RG. Split-RG
    // reverse companions can remain owned by RG2 while a move of RG1
    // changes whether they should locally forward or fabric-redirect.
    // Activation is infrequent, so do the wider worker scan here
    // instead of trusting potentially stale RG ownership buckets.
    let mut refresh = Vec::new();
    sessions.iter_with_origin(|key, decision, metadata, origin| {
        if metadata.owner_rg_id <= 0 && !metadata.fabric_ingress {
            return;
        }
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        };
        let resolution_target = resolution_target_for_session(&flow, decision);
        let looked_up_resolution =
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, &flow, decision);
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
        let mut refreshed_metadata = metadata.clone();
        let refreshed_owner_rg = owner_rg_for_resolution(forwarding, refreshed_decision.resolution);
        if refreshed_owner_rg > 0 {
            refreshed_metadata.owner_rg_id = refreshed_owner_rg;
        }
        // #4805: the publish disposition rides `allow_replace_local`. Compute
        // it from the refreshed owner RG (the RG that the entry being
        // published is stamped with) against the current HA state, exactly as
        // `handle_upsert_synced` computes it for the initial-sync path. A
        // standby-owned entry gets `true` (force live REDIRECT); an
        // owner-active entry gets `false` (kernel-local publish).
        let allow_replace_local =
            synced_entry_allows_local_replace(ha_state, refreshed_metadata.owner_rg_id, now_secs);
        refresh.push((
            key.clone(),
            refreshed_decision,
            refreshed_metadata,
            origin,
            allow_replace_local,
        ));
    });
    refresh
}
