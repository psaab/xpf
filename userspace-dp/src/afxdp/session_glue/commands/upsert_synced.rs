use super::super::*;

/// #6211: resolve the ACTIVE node's `(from_zone, to_zone)` NAME pair for a
/// synced session, so the standby's source-NAT reservation lands on the rule
/// the active actually matched rather than on the first rule whose pool merely
/// CONTAINS the translated address (which diverges when two rules carry
/// overlapping pool addresses in separate allocators).
///
/// The IDs come off the HA session-sync wire (`SessionSyncRequest`'s
/// `ingress_zone_id`/`egress_zone_id`, with the legacy name strings resolved
/// through `zone_name_to_id` for an older peer — see
/// `build_synced_session_entry`), so this is a pure local lookup: no new wire
/// field, and an old peer degrades to `None`.
///
/// `None` whenever EITHER side fails to resolve to a non-empty local zone name
/// — an unknown/dropped zone, or config drift between the nodes. `populate_zones`
/// never admits id 0 or an empty name, but the emptiness check is enforced here
/// too rather than assumed: an empty `from_zone` would silently EXCLUDE every
/// zone-scoped rule instead of leaving the axis unconstrained, which is the one
/// way this narrowing could pick a worse rule than the pre-#6211 fallback.
/// #6600: `pub(in crate::afxdp)` so the COORDINATOR's pre-publish reservation
/// resolves the zone pair through the SAME function the worker does. If the two
/// ever disagreed, the coordinator would reserve on one allocator and the worker
/// on another — the coordinator's check would pass while the port the session
/// actually names stayed unreserved, which is the defect wearing a new shape.
pub(in crate::afxdp) fn synced_source_nat_zone_pair<'a>(
    forwarding: &'a ForwardingState,
    metadata: &crate::session::SessionMetadata,
) -> crate::nat::SyncedNatZones<'a> {
    let from = forwarding.zone_id_to_name.get(&metadata.ingress_zone)?;
    let to = forwarding.zone_id_to_name.get(&metadata.egress_zone)?;
    (!from.is_empty() && !to.is_empty()).then_some((from.as_str(), to.as_str()))
}

/// Apply `WorkerCommand::UpsertSynced`: re-resolve the synced
/// forward session with local egress (regardless of HA state — #326),
/// upsert into the session table, and publish the kernel session-map
/// entry if the upsert took.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::UpsertSynced` match arm.
///
/// Synced sessions arrive with the remote node's interface indices
/// and MACs which don't work on this node. By resolving on receipt
/// (even on standby), sessions are immediately forwarding-ready at
/// activation — the helper no longer needs a second activation-time
/// forward scan to fix them up. HA enforcement still happens at
/// packet time via flow cache validation
/// (`enforce_ha_resolution_snapshot`).
pub(in crate::afxdp::session_glue) fn handle_upsert_synced(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    mut entry: SyncedSessionEntry,
    now_ns: u64,
    now_secs: u64,
    // #6211 F2: THIS worker's id, from `WorkerLaunchPlan::worker_id` via
    // `apply_worker_commands`. The synced entry is fanned out to every live worker,
    // so the reservation below must record which worker took it.
    worker_id: u32,
) {
    let key = entry.key.clone();
    // #14669: the peer's stamped owner_rg_id is not this node's ownership.
    // Compute allow_replace_local / is_active only AFTER a cache-free local
    // re-resolution yields the local owner. The cached variant would serve
    // the peer's LocalDelivery verbatim (foreign local_ifindex) and its
    // neighbor fallback would reuse the peer's egress/MAC on NoRoute.
    let mut allow_replace_local =
        synced_entry_allows_local_replace(ha_state, entry.metadata.owner_rg_id, now_secs);
    if !entry.metadata.is_reverse {
        // #9752 round 3: resolve with the EFFECTIVE stamp. A (0,0) re-import
        // over a stamped stored entry is an old sender's resend, and the
        // install below preserves the stamp — resolving with the incoming
        // (0,0) would install a default-table resolution under it.
        if let Some((domain, check)) =
            sessions.preserved_install_table_for(&key, &entry.decision, entry.session_id)
        {
            entry.decision.install_table_domain = domain;
            entry.decision.install_table_check = check;
        }
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        };
        let peer_resolution = entry.decision.resolution;
        let raw_resolved = lookup_forwarding_resolution_for_session_without_cache(
            forwarding,
            dynamic_neighbors,
            &flow,
            entry.decision,
        )
        .resolution;
        let new_owner = owner_rg_for_resolution(forwarding, raw_resolved);
        if new_owner > 0 {
            entry.metadata.owner_rg_id = new_owner;
        }
        allow_replace_local =
            synced_entry_allows_local_replace(ha_state, entry.metadata.owner_rg_id, now_secs);
        let is_active = !allow_replace_local;
        // On active node, enforce HA snapshot to filter out sessions
        // for inactive RGs. On standby, skip HA enforcement — store
        // the resolved ForwardCandidate so the session is ready when
        // activation happens. The packet path enforces HA state via
        // flow cache validation.
        let mut re_resolved = if is_active {
            enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, raw_resolved)
        } else {
            raw_resolved
        };
        // #326 standby readiness: when the local FIB has no route /
        // neighbor yet, keep the session forwarding-ready at activation
        // from the peer candidate, but ONLY after cached_session_resolution
        // revalidates its egress/neighbor against THIS node's live state
        // (foreign or stale bindings are rejected). Never reached for a
        // peer LocalDelivery: that disposition is not a ForwardCandidate,
        // so the foreign local_ifindex cannot survive (#14669).
        if !is_active
            && matches!(
                re_resolved.disposition,
                ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor
            )
        {
            if let Some(fallback) =
                cached_session_resolution(forwarding, dynamic_neighbors, peer_resolution)
            {
                re_resolved = fallback;
            }
        }
        // #9752: a terminal re-resolve arms the purge walk (D8).
        if re_resolved.disposition == ForwardingDisposition::TableUnavailable {
            flag_install_table_purge(worker_id);
        }
        if re_resolved.disposition != ForwardingDisposition::HAInactive {
            entry.decision.resolution = re_resolved;
        }
    }
    // #9951: a zero token carries no leak provenance and is recomputed locally
    // for peer-synced rows (wire imports always arrive as zero). A nonzero
    // token was computed before this row was published (sibling fan-out and
    // bring-up replay preserve it), so keep it as revocation evidence instead
    // of discarding it — recomputing after removal would install an unstamped
    // session the resolver arms can never revoke.
    if entry.origin.is_peer_synced() && entry.leak_incarnation == 0 {
        let target = if entry.metadata.is_reverse {
            entry.key.dst_ip
        } else {
            let flow = SessionFlow {
                src_ip: entry.key.src_ip,
                dst_ip: entry.key.dst_ip,
                forward_key: entry.key.clone(),
            };
            resolution_target_for_session(&flow, entry.decision)
        };
        entry.leak_incarnation =
            super::super::leak_incarnation_for_session(forwarding, entry.decision, target)
                .unwrap_or(0);
    }

    let metadata = entry.metadata.clone();
    // #6979 F3: the REPLACED session's reservation identity, captured before
    // `upsert_synced_with_origin` removes the entry and discards `_previous`.
    //
    // Most replacements need nothing here: `reserve_flow` is keyed on the
    // ORIGINAL 5-tuple (`SourceNatFlowKey`), so when the new decision also
    // reserves, it finds the incumbent under the same flow and retires it with
    // release semantics (#6528). That covers a NAT -> different-NAT re-decision.
    //
    // It does NOT cover a replacement that never reaches `reserve_flow`. The
    // reserve is gated twice — here on `is_peer_synced() && !is_reverse`, and
    // inside `reserve_synced_source_nat_allocation_with_holder` on
    // `nat.rewrite_src.is_some()` — so a NAT -> NO-NAT re-decision (the active
    // re-evaluates a reused 5-tuple after its NAT rule is withdrawn), a flip to
    // a reverse entry, or a peer-synced -> local-origin replace all install the
    // new session while the old port stays reserved forever. Nothing else frees
    // it: delete-sync releases the CURRENT decision, which no longer names that
    // port.
    let previous_reservation = sessions.entry_with_origin(&key);
    // #9412: the Copy fields read after the install, captured before
    // `into_session_install` consumes the entry. It carries the peer's stable
    let (entry_origin, entry_decision, leak_incarnation) =
        (entry.origin, entry.decision, entry.leak_incarnation);
    let pptp_call_ids = entry.pptp_call_ids;
    let leak_key = entry.key.clone();
    if sessions.upsert_synced_with_origin(entry.into_session_install(now_ns), allow_replace_local) {
        if leak_incarnation != 0 {
            sessions.stamp_leak_incarnation(&leak_key, leak_incarnation);
        }
        // #6979 F3 + #14669: release the replaced reservation when the new
        // entry will NOT re-reserve this flow in the SAME allocator, or will
        // not reserve at all. Mirrors `handle_delete_synced`'s teardown —
        // same helpers, same holder id. `reserve_flow`'s stale-tuple eviction
        // only retires an incumbent in the allocator the NEW reservation
        // lands in, so a Pool A -> Pool B / Pool -> static / SNAT -> NAT64
        // (or reverse) move would strand Pool A's holder bit forever. The
        // release sweep is keyed on the PREVIOUS translated tuple and
        // no-ops in allocators not holding that exact tuple, so releasing
        // before re-reserving cannot free the new (different-tuple)
        // reservation; for a same-tuple refresh the translated tuple is
        // unchanged and this branch is not taken, preserving the holder bit.
        let new_entry_reserves = entry_origin.is_peer_synced()
            && !metadata.is_reverse
            && entry_decision.nat.rewrite_src.is_some();
        let reservation_target_changed = previous_reservation.as_ref().is_some_and(
            |(prev_decision, prev_metadata, _)| {
                prev_metadata.is_reverse != metadata.is_reverse
                    || prev_decision.nat != entry_decision.nat
                    || prev_metadata.ingress_zone != metadata.ingress_zone
                    || prev_metadata.egress_zone != metadata.egress_zone
            },
        );
        if !new_entry_reserves || reservation_target_changed {
            if let Some((prev_decision, prev_metadata, _)) = previous_reservation {
                release_source_nat_allocation_for_worker(
                    &forwarding.iface_nat_allocators,
                    &forwarding.source_nat_rules,
                    &key,
                    prev_decision.nat,
                    prev_metadata.is_reverse,
                    now_ns,
                    worker_id,
                );
                crate::nat64::release_nat64_allocation_for_worker(
                    &forwarding.nat64,
                    &key,
                    prev_decision.nat,
                    prev_metadata.is_reverse,
                    now_ns,
                    worker_id,
                );
            }
        }
        // #4388: reserve the synced session's translated NAT pool port in this
        // node's LOCAL source-NAT allocator. The standby imports the active
        // node's pre-computed NAT decision but never runs `allocate_translation`,
        // so without this its allocator does not know `(pool_addr, port)` is in
        // use — post-failover a new local flow could reuse it, colliding two
        // sessions on one NAT source tuple. Only forward, peer-synced entries
        // reserve (a reverse entry carries the destination rewrite, not the
        // pool source port; a local-origin entry already allocated its port on
        // the active path). The reservation is freed by the standard teardown
        // (`release_source_nat_allocation`) on reap or delete-sync.
        if entry_origin.is_peer_synced() && !metadata.is_reverse {
            reserve_synced_source_nat_allocation_for_worker(
                &forwarding.iface_nat_allocators,
                &forwarding.source_nat_rules,
                &key,
                entry_decision.nat,
                metadata.is_reverse,
                // #6211: the active's zone pair, so the reservation lands in
                // the allocator the active used when two rules share a pool
                // address. `None` (old peer / unknown zone) keeps the
                // pre-#6211 first-pool-match.
                synced_source_nat_zone_pair(forwarding, &metadata),
                // #6528: the stale-tuple eviction inside `reserve_flow` retires
                // the incumbent with release semantics; a persistent lease that
                // falls to zero active flows re-arms its idle expiry off this
                // clock.
                now_ns,
                // #6211 F2: record this worker as a HOLDER. Every worker
                // reserves the same `(flow, translated)` against ONE shared
                // allocator; without the holder bit the first worker to reap or
                // delete-sync frees a port the others still forward through.
                worker_id,
            );
            // #4512: same treatment for NAT64. The translated `(pool v4, port)`
            // rides the synced `NatDecision` (`rewrite_src_port`), but the
            // standby never runs `allocate_source`, so without this its NAT64
            // allocator does not know the port is in use — post-failover a
            // fresh local NAT64 flow could reuse it, two flows colliding on one
            // translated source (RFC 6146 BIB violation across a cross-node
            // failover). No-op for a non-NAT64 decision. Freed by the same
            // `release_nat64_allocation` on reap / delete-sync.
            crate::nat64::reserve_synced_nat64_allocation_for_worker(
                &forwarding.nat64,
                &key,
                entry_decision.nat,
                metadata.is_reverse,
                // #6528: same clock, same reason as the source-NAT reserve.
                now_ns,
                worker_id,
            );
        }
        // #15153 (B11-01): re-derive the PPTP association from the pair the
        // shared entry still carries. A worker respawn / full reconcile
        // replays only UpsertSynced (replicate_session_upsert, replay_late,
        // and the #11360/#15105 repair re-read all funnel here), so without
        // this the respawned worker holds the Pptp(H) session but no
        // association to resolve GRE data to Pptp(H) — it falls to
        // pre-#7699 unassociated/flowless handling. The import-time
        // InstallPptpAssociation command cannot cover this: it is queued
        // once per import on the OLD worker generation. Synthesized
        // reverse companions carry pptp_call_ids 0, and a reverse key's
        // endpoints are swapped, so gating on the forward Pptp(_)
        // discriminator plus a decodable pair keeps this exact. The
        // install is idempotent for an identical call and preserves a
        // local control binding; a handle mismatch (pair decodes to a
        // different handle than the key names) is not re-derived — that
        // disagreement was already refused at HA import.
        if let crate::session::TunnelDiscriminator::Pptp(handle) = key.discriminator {
            if let Some(call) = crate::session::pptp::PptpCall::from_wire_call_ids_in_domain(
                key.routing_domain,
                pptp_call_ids,
                key.src_ip,
                key.dst_ip,
            ) {
                if call.handle() == handle {
                    let _ = sessions.pptp_mut().install_synced_association(call, now_ns);
                }
            }
        }
        publish_worker_session_map_entry(
            session_map,
            forwarding,
            &key,
            entry_decision,
            &metadata,
            entry_origin,
            allow_replace_local,
        );
    }
}
