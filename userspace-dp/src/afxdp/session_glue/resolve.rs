use super::*;

/// #16217 (FZDiag35): the stamp-free reverse conversion test,
/// extracted verbatim from the session-hit slow path so the
/// stamp=2 unit cell judges the production predicate, not a copy.
/// Returns the zone-encoded FabricRedirect to adopt when ALL of:
/// the hit is a reverse hit, the packet did not arrive on the
/// fabric link (anti-loop), the current disposition is a local
/// ForwardCandidate, and the reply destination's connected owner
/// RG is KNOWN (>0) and NOT forwarding-active locally. Soundness
/// (no false-convert shape): a destination whose connected owner
/// is locally active is the ordinary locally-served reply and
/// keeps its candidate; an unknown owner (no connected prefix —
/// gateway/default-routed) is not peer-ownership and never
/// converts. The session's stored owner stamp is deliberately NOT
/// consulted: pre-fix rows carry the reply-egress row's RG there.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn reverse_hit_departed_destination_redirect(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    fabric_link_ingress: bool,
    is_reverse: bool,
    resolution_target: IpAddr,
    table: Option<&str>,
    egress_zone: u32,
    disposition: ForwardingDisposition,
) -> Option<ForwardingResolution> {
    if !is_reverse
        || fabric_link_ingress
        || disposition != ForwardingDisposition::ForwardCandidate
    {
        return None;
    }
    let dest_rg = super::connected_owner_rg_for_target_in_table(
        forwarding,
        resolution_target,
        table,
    );
    let destination_local = dest_rg > 0
        && ha_state
            .get(&dest_rg)
            .is_some_and(|group| group.is_forwarding_active(now_secs));
    if dest_rg > 0 && !destination_local {
        super::forwarding::resolve_zone_encoded_fabric_redirect_by_id(forwarding, egress_zone)
    } else {
        None
    }
}

pub(super) fn materialize_shared_session_hit(sessions: &mut SessionTable,
resolved: &mut ResolvedSessionLookup,
forwarding: &ForwardingState,
now_ns: u64,
tcp_flags: u8,) -> (SessionLookup, bool) {
    materialize_shared_session_hit_adopted(sessions, resolved, forwarding, now_ns, tcp_flags, false)
}

/// #16217 (FZDiag30): adopted variant. `fabric_adopted` is true only
/// when the poll fabric-adoption gate has already proven this tuple
/// belongs to an Established session and this node is the RG owner
/// post-takeover. A synced replica materialized for such a flow may
/// replace a non-peer-synced local incumbent (`allow_replace_local`):
/// the incumbent is the stale pre-failover row (e.g. a
/// MissingNeighborSeed / locally seeded row) that the adoption
/// resolve supersedes, and refusing to clobber it left
/// `install_failed=true` on every adopted hit, so the flow-cache seed
/// gate (`flow_cache_seed.rs`) never installed an entry and every
/// packet re-took the slow path. Non-adopted materializations keep
/// `allow_replace_local=false` bit-identically (the #10582 clobber
/// guard).
pub(super) fn materialize_shared_session_hit_adopted(sessions: &mut SessionTable,
resolved: &mut ResolvedSessionLookup,
forwarding: &ForwardingState,
now_ns: u64,
tcp_flags: u8,
fabric_adopted: bool,) -> (SessionLookup, bool) { if let Some(shared) = resolved.shared_entry.take() {
    // #10612 (N2): fence stale-zone shared hits at materialize ingress.
    // A shared-transient stale row (import fail-open linger racing
    // validation) must materialize as a MISS, not install into the
    // worker table (the later arm-drop would not remove it).
    if synced_entry_is_stale_replay(shared.origin, &shared.metadata, forwarding) {
        note_stale_replay_fence_drop();
        return (resolved.lookup.clone(), false);
    }
    let mut replica = synced_replica_entry(&shared);
    // A zero token carries no leak provenance and is recomputed locally
    // for peer-synced rows. A nonzero token was computed before this
    // shared row was published (and survives demotion), so preserve it as
    // revocation evidence.
    if shared.origin.is_peer_synced() && replica.leak_incarnation == 0 {
        let target = if replica.metadata.is_reverse {
            replica.key.dst_ip
        } else {
            let flow = SessionFlow {
                src_ip: replica.key.src_ip,
                dst_ip: replica.key.dst_ip,
                forward_key: replica.key.clone(),
            };
            resolution_target_for_session(&flow, replica.decision)
        };
        replica.leak_incarnation =
            leak_incarnation_for_session(forwarding, replica.decision, target).unwrap_or(0);
    }
    let incumbent_persistent_hold = sessions.persistent_lease_hold_for(&replica.key);
    // A shared row's hold belongs to its publisher, not this worker. Acquire
    // one local reference on that exact allocator and lease incarnation
    // before installing a releasable local hold. The destination tuple check
    // prevents a stale row from joining a different lease under the same key.
    let acquired_persistent_hold = if let Some(hold) = replica.persistent_lease_hold {
        let expected_translated = crate::nat::TranslatedTuple {
            ip: replica.key.dst_ip,
            port: replica.key.dst_port,
        };
        if !crate::nat::acquire_recorded_persistent_inbound_hold(
            &forwarding.source_nat_rules,
            hold,
            expected_translated,
            now_ns,
        ) {
            return (resolved.lookup.clone(), true);
        }
        Some(hold.with_owner(crate::nat::PersistentLeaseOwner::LocalWorker))
    } else {
        None
    };
    // #17058: build the install via the one shared mapping
    // (`into_session_install`), then apply the materialize overrides:
    // the shared-hit origin and the packet's tcp_flags, and the locally
    // acquired persistent hold (the shared row's hold belongs to its
    // publisher). Every other field (id, close/handshake state,
    // counters, SNAT provenance) is the replica's carried value.
    // Snapshot the post-install reads first: `into_session_install`
    // consumes the replica, and the lookup/stamp below still need them.
    let replica_key = replica.key.clone();
    let replica_decision = replica.decision;
    let replica_metadata = replica.metadata.clone();
    let replica_session_id = replica.session_id;
    let replica_source_nat_static = replica.source_nat_static;
    let replica_leak_incarnation = replica.leak_incarnation;
    let mut install = replica.into_session_install(now_ns);
    install.origin = shared.origin.materialized_shared_hit_origin();
    install.tcp_flags = tcp_flags;
    install.persistent_lease_hold = acquired_persistent_hold;
    let materialized = sessions.upsert_synced_with_origin(
        install,
        fabric_adopted,
    );
    if materialized {
        // The install replaced and discarded the incumbent table entry. Its
        // exact local reference is no longer owned, even when the new entry
        // selected the same lease (the pre-install acquire made a second one).
        if let Some(hold) = incumbent_persistent_hold {
            crate::nat::release_recorded_persistent_inbound_hold(
                &forwarding.source_nat_rules,
                hold,
                now_ns,
            );
        }
    } else if let Some(hold) = acquired_persistent_hold {
        // A refused materialization did not adopt the local reference.
        crate::nat::release_recorded_persistent_inbound_hold(
            &forwarding.source_nat_rules,
            hold,
            now_ns,
        );
    }
    // A refused shared repair must not mutate the incumbent local row's
    // leak provenance. The stamp is evidence for the materialized replica
    // only; failed clobber attempts return install_failed instead.
    if materialized
        && let Some(incarnation) =
            (replica_leak_incarnation != 0).then_some(replica_leak_incarnation)
    {
        sessions.stamp_leak_incarnation(&replica_key, incarnation);
    }
    return (
        SessionLookup {
            decision: replica_decision,
            metadata: replica_metadata,
            forwarding_generation: ForwardingGenerationStamp::default(),
            aux: SessionLookupAux {
                session_id: replica_session_id,
                source_nat_static: replica_source_nat_static,
                leak_incarnation: replica_leak_incarnation,
            },
        },
        !materialized,
    );
}
(resolved.lookup.clone(), false) }

/// #17063: persist a deferred forwarding revalidation — the single
/// source of truth for the #12265 Owner-persist step. The production
/// poll path calls this after its #9519 Owner verdict
/// (`foreign_arrival_zone.is_none()`); the `#[cfg(test)]` wrapper
/// below calls it after its caller-supplied Owner verdict. Tests
/// therefore exercise the same persist production runs, never a
/// re-spelled copy.
pub(in crate::afxdp) fn apply_deferred_forwarding_revalidation(
    sessions: &mut SessionTable,
    resolved: &mut ResolvedFlowSessionDecision,
) {
    let Some(revalidation) = resolved.deferred_forwarding_revalidation.take() else {
        return;
    };
    if revalidation.invalidate_policy_revalidation {
        sessions.invalidate_policy_revalidation(&resolved.key);
    }
    // #14941: `new_egress_zone` is direction-relative (the hit
    // packet's egress leg). Map it to the forward flow's egress
    // before persisting: a reverse hit's resolved zone is the
    // forward ingress and must not overwrite forward `egress_zone`
    // / reverse `ingress_zone`.
    let forward_zone = crate::afxdp::shared_ops::forward_egress_zone_for_hit(
        resolved.metadata.is_reverse,
        revalidation.new_egress_zone,
        resolved.metadata.ingress_zone,
    )
    .as_option();
    sessions.revalidate_forwarding_resolution_with_egress_zone(
        &resolved.key,
        revalidation.resolution,
        revalidation.owner_rg_id,
        forward_zone,
    );
    if let Some(owner_rg_id) = revalidation.owner_rg_id {
        resolved.metadata.owner_rg_id = owner_rg_id;
    }
    if let Some(zone) = forward_zone {
        if resolved.metadata.is_reverse {
            resolved.metadata.ingress_zone = zone;
        } else {
            resolved.metadata.egress_zone = zone;
        }
    }
}

/// #17063: test-only convenience over the production
/// `resolve_flow_session_decision_with_conntrack_and_payload_and_ack`
/// entry point. It carries no packet frame (payload honestly 0, ack
/// honestly `None`), no conntrack fds (`-1, -1` via the caller's
/// bundle), applies the deferred promotion under the caller-supplied
/// verdict exactly as the poll Owner site does, and — only for an
/// Owner verdict — persists the deferred forwarding revalidation
/// through [`apply_deferred_forwarding_revalidation`], the same
/// helper the poll path calls. `fabric_ingress` and
/// `fabric_link_ingress` are separate arguments so a cell can drive
/// `fabric_ingress=true, fabric_link_ingress=false` (a logical fabric
/// arrival that did not arrive on the fabric link).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn resolve_flow_session_decision(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
    protocol: u8,
    tcp_flags: u8,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    fabric_ingress: bool,
    fabric_link_ingress: bool,
    ha_startup_grace_until_secs: u64,
    worker_id: u32,
    verdict: SessionHitVerdict,
) -> Option<ResolvedFlowSessionDecision> {
    let mut resolved = resolve_flow_session_decision_with_conntrack_and_payload_and_ack(
        sessions,
        session_map,
        shared,
        forwarding,
        ha_state,
        dynamic_neighbors,
        flow,
        protocol,
        tcp_flags,
        0,
        ingress_ifindex,
        ingress_vlan_id,
        fabric_ingress,
        fabric_link_ingress,
        ha_startup_grace_until_secs,
        worker_id,
        None,
        None,
        false,
        None,
    )?;
    let mut purged_keys = Vec::new();
    maybe_promote_synced_session_with_conntrack(
        sessions,
        session_map,
        shared.with_conntrack_tick(ConntrackFds { v4: -1, v6: -1 }, shared.tick),
        forwarding,
        tcp_flags,
        worker_id,
        verdict,
        &mut resolved,
        &mut purged_keys,
    );
    if verdict == SessionHitVerdict::Owner {
        apply_deferred_forwarding_revalidation(sessions, &mut resolved);
    }

    Some(resolved)
}


/// #16042: production variant carrying TCP payload progress and the
/// parsed segment ack. This is the entry point the production poll
/// session-hit path calls; the poll fabric-adoption miss site calls
/// it with `ack = None`, since no segment ack is parsed there.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn resolve_flow_session_decision_with_conntrack_and_payload_and_ack(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
    protocol: u8,
    tcp_flags: u8,
    payload_len: u32,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    fabric_ingress: bool,
    fabric_link_ingress: bool,
    ha_startup_grace_until_secs: u64,
    worker_id: u32,
    prevalidated_forward_nat_match: Option<crate::session::ForwardSessionMatch>,
    ack: Option<u32>,
    fabric_adopted: bool,
    adopted_recovery: Option<AdoptedRecovery>,
) -> Option<ResolvedFlowSessionDecision> {
    resolve_flow_session_decision_with_conntrack_inner(
        sessions, session_map, shared, forwarding, ha_state,
        dynamic_neighbors, flow, protocol, tcp_flags, payload_len,
        ingress_ifindex, ingress_vlan_id, fabric_ingress, fabric_link_ingress,
        ha_startup_grace_until_secs, worker_id, prevalidated_forward_nat_match, ack,
        fabric_adopted, adopted_recovery,
    )
}

/// Materialize a shared entry only after the packet's Owner verdict.
pub(in crate::afxdp::session_glue) fn apply_deferred_shared_materialization(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    now_ns: u64,
    tcp_flags: u8,
    verdict: SessionHitVerdict,
    resolved: &mut ResolvedFlowSessionDecision,
) {
    if verdict != SessionHitVerdict::Owner {
        return;
    }
    let Some(entry) = resolved
        .deferred_shared_materialization
        .take()
        .map(|deferred| deferred.entry)
    else {
        return;
    };
    let mut hit = ResolvedSessionLookup::shared(entry);
    let (_, install_failed) = materialize_shared_session_hit_adopted(
        sessions,
        &mut hit,
        forwarding,
        now_ns,
        tcp_flags,
        resolved.fabric_adopted,
    );
    resolved.install_failed = install_failed;
    if resolved.session_id == 0 && !install_failed {
        resolved.session_id = sessions.session_id_for(&resolved.key);
    }
    if install_failed {
        resolved.deferred_synced_promotion = None;
    }
}


#[allow(clippy::too_many_arguments)]
fn resolve_flow_session_decision_with_conntrack_inner(sessions: &mut SessionTable,
session_map: SteeringMap<'_>,
shared: SharedSessionRefs<'_>,
forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
protocol: u8,
tcp_flags: u8,
payload_len: u32,
ingress_ifindex: i32,
ingress_vlan_id: u16,
fabric_ingress: bool,
fabric_link_ingress: bool,
ha_startup_grace_until_secs: u64,
worker_id: u32,
prevalidated_forward_nat_match: Option<crate::session::ForwardSessionMatch>,
ack: Option<u32>,
fabric_adopted: bool,
adopted_recovery: Option<AdoptedRecovery>,) -> Option<ResolvedFlowSessionDecision> {
    if !crate::session::PMechSessionDirectory::global()
        .probe_packet_key(&flow.forward_key)
        .is_fallthrough()
    {
        return None;
    }
    let now_ns = shared.tick.ns;
    let now_secs = shared.tick.secs;
    if let Some(mut hit) = lookup_session_across_scopes_with_shared_and_payload(
        sessions,
        shared.sessions,
        shared.nat_sessions,
        shared.forward_wire_sessions,
        shared.owner_rg_indexes,
        &flow.forward_key,
        now_ns,
        tcp_flags,
        payload_len,
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
        let shared_was_present = hit.shared_entry.is_some();
        // Preserve the shared session incarnation before materialization takes
        // its entry out of `hit`; local-only hits read it from the table below.
        let shared_session_id = hit.shared_entry.as_ref().map(|entry| entry.session_id);
        let shared_leak_incarnation = hit.shared_entry.as_ref().map(|entry| entry.leak_incarnation);
        // #14666: a local-first hit (UpsertSynced/Demote materialized the
        // row, shared_entry None) still names a shared incarnation: the
        // local row adopted the peer's session_id at import
        // (into_session_install) and the shared entry under the same key
        // carries that id. Look it up now (read-only clone under the
        // shared lock) so the purge can conditionally remove it; the
        // purge re-checks (session_id, generation) under the removal
        // lock, so a replacement published meanwhile declines and is
        // preserved. Generation is not stored on the local row, so for
        // local hits the shared lookup is the only source — if the
        // shared entry is already gone, identity stays None and the
        // purge correctly takes the Absent/no-replicate branch.
        let shared_identity = hit
            .shared_entry
            .as_ref()
            .map(|entry| (entry.session_id, entry.generation))
            .or_else(|| {
                if !hit_origin.is_peer_synced() {
                    return None;
                }
                let local_id = hit.lookup.aux.session_id;
                if local_id == 0 {
                    return None;
                }
                let key = hit.key.as_ref(&flow.forward_key);
                lock_shared_recover(shared.sessions)
                    .get(key)
                    .filter(|entry| entry.session_id == local_id)
                    .map(|entry| (entry.session_id, entry.generation))
            });
        let source_nat_static = match hit.shared_entry.as_ref() {
            Some(entry) => entry.source_nat_static,
            // #13079: reuse the lookup's aux snapshot, no re-probe.
            None => hit.lookup.aux.source_nat_static,
        };
        let keep_transient = poison_key.is_some_and(|(key, decision, metadata, origin)| {
            should_keep_synced_hit_transient(ha_state, now_secs, key, decision, metadata, origin)
        });
        let session_id_before_purge = shared_session_id
            .filter(|session_id| *session_id != 0)
            .or_else(|| (!shared_was_present).then_some(hit.lookup.aux.session_id))
            .unwrap_or(0);
        let source_nat_validation_key = if keep_transient {
            shared_source_nat_original_key(
                shared.forward_wire_sessions,
                &flow.forward_key,
                hit.key.as_ref(&flow.forward_key),
                hit.lookup.decision,
                &hit.lookup.metadata,
                hit_origin,
                source_nat_static,
                session_id_before_purge,
            )
        } else {
            None
        };
        let deferred_synced_purge = if keep_transient {
            poison_key.map(|(key, decision, metadata, origin)| DeferredSyncedPurge {
                key: key.clone(),
                decision,
                metadata: metadata.clone(),
                origin,
                shared_identity,
            })
        } else {
            None
        };
        let deferred_shared_materialization = if keep_transient {
            None
        } else {
            hit.shared_entry
                .clone()
                .map(|entry| DeferredSharedMaterialization { entry })
        };
        let resolved = hit.lookup.clone();
        let resolved_key = hit.key.as_ref(&flow.forward_key);
        let forwarding_stale =
            sessions.forwarding_resolution_is_stale(resolved.forwarding_generation);
        let session_id = shared_session_id
            .filter(|session_id| *session_id != 0)
            .unwrap_or_else(|| {
                if keep_transient {
                    session_id_before_purge
                } else {
                    // #13079: the resolved lookup already carries it.
                    resolved.aux.session_id
                }
            });
        let previous_policy_to_zone_id = forwarding_stale.then(|| {
            if resolved.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                resolved.metadata.egress_zone
            } else {
                forwarding.egress_zone_id(resolved.decision.resolution.egress_ifindex)
            }
        });
        let mut decision = resolved.decision;
        let resolution_target = resolution_target_for_session(flow, decision);
        let leak_incarnation = shared_leak_incarnation
            .filter(|incarnation| *incarnation != 0)
            .or_else(|| sessions.leak_incarnation(&resolved_key));
        let leak_revoked = leak_incarnation.is_some_and(|incarnation| {
            !super::forwarding::leak_incarnation_is_live(forwarding, resolution_target, incarnation)
        });
        let looked_up_resolution = if let Some(stamped_incarnation) =
            leak_incarnation.filter(|_| leak_revoked)
        {
            // #9951: a revoked provenance stamp bypasses every cached arm,
            // including the synced-session fallback (which intentionally
            // keeps cached fallback for ordinary peer imports).
            let refreshed = lookup_forwarding_resolution_for_session_without_cache(
                forwarding,
                dynamic_neighbors,
                flow,
                decision,
            )
            .resolution;
            let current_incarnation =
                leak_incarnation_for_session(forwarding, decision, resolution_target);
            if current_incarnation.is_some_and(|current| current != stamped_incarnation) {
                super::no_route_resolution(None)
            } else {
                refreshed
            }
        } else if forwarding_stale {
            lookup_forwarding_resolution_for_session_without_cache(
                forwarding,
                dynamic_neighbors,
                flow,
                decision,
            )
            .resolution
        } else if hit_origin.is_peer_synced() {
            lookup_forwarding_resolution_for_synced_session(
                forwarding,
                dynamic_neighbors,
                flow,
                decision,
            )
            .resolution
        } else {
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision)
                .resolution
        };
        let looked_up_resolution = super::prefer_local_forward_candidate_for_fabric_ingress(
            forwarding,
            ha_state,
            dynamic_neighbors,
            now_secs,
            fabric_ingress,
            resolution_target,
            install_table_name_for_session(forwarding, decision, resolution_target),
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
        // #16217: a fabric-adopted ForwardCandidate must not die on
        // the ha_inactive terminal (see `fabric_adopted_resolution`).
        let enforced_resolution = if fabric_adopted {
            fabric_adopted_resolution(forwarding, ha_state, now_secs, looked_up_resolution, enforced_resolution, dynamic_neighbors, resolution_target, adopted_recovery.as_ref())
        } else {
            enforced_resolution
        };
        // #15958b: a stored FabricRedirect companion must not be
        // re-resolved onto a gateway/default route. On the punt origin
        // the connected LAN prefix is HA-suppressed, so the FIB lookup
        // above answers the LAN target with the WAN gateway route
        // (ForwardCandidate egressing in the WAN zone, owner =
        // locally-active WAN RG); HA enforcement keeps it and the
        // reply leaves on the WAN egress instead of the fabric. When
        // the stored decision was FabricRedirect and the re-resolved
        // candidate egresses in a different zone than the companion's
        // destination (egress) zone, the route does not reach the LAN
        // owner: retain the redirect.
        if resolved.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            // M1: never re-redirect a packet that arrived on the fabric
            // link (anti-loop, mirroring redirect_session_via_fabric_if_needed).
            // Per-address destination owner (round-2 item 1): the RG
            // of the connected interface serving resolution_target,
            // not any RG in the destination zone.
            let session_table = install_table_name_for_session(forwarding, decision, resolution_target);
            let dest_rg = super::connected_owner_rg_for_target_in_table(forwarding, resolution_target, session_table);
            // Unknown owner (dest_rg==0) is NOT peer-ownership: keep the candidate (no redirect).
            let destination_owner_active = dest_rg == 0 || (dest_rg > 0
                && ha_state
                    .get(&dest_rg)
                    .is_some_and(|group| group.is_forwarding_active(now_secs)));
            // Composition (item 3): HAInactive conversion first; the
            // zone-egress helper only converts a surviving candidate.
            let enforced_resolution = redirect_session_via_fabric_if_needed(
                forwarding,
                enforced_resolution,
                fabric_link_ingress,
                resolved.metadata.ingress_zone,
            );
            decision.resolution = if fabric_link_ingress {
                enforced_resolution
            } else {
                super::rehome_or_retain_fabric_redirect_16524(
                    forwarding,
                    resolved.decision.resolution,
                    enforced_resolution,
                    resolved.metadata.egress_zone,
                    destination_owner_active,
                    dest_rg == 0,
                    Some(resolution_target),
                    session_table,
                )
            };
        } else {
            decision.resolution = redirect_session_via_fabric_if_needed_at(
                forwarding,
                ha_state,
                now_secs,
                enforced_resolution,
                fabric_link_ingress,
                resolved.metadata.ingress_zone,
            );
        }
        // #16217 (FZDiag34 reverse leg; FZDiag35 conversion):
        // a REVERSE hit whose stored decision still egresses LOCALLY
        // (ForwardCandidate) while the reply destination's connected
        // owner has departed this node must cross the fabric to the
        // new owner — it must NOT be re-served/re-seeded from the
        // departed member. Live fw0 (trace cellX): reverse hits
        // re-resolve from the stored reverse decision egress=5
        // (ge-0-0-1, RG1's member; the member's egress row carries
        // the surviving RG2, so neither HA enforcement nor the
        // egress-row departed arms can see RG1's departure) and TX
        // every WAN reply into the dead member; the cache arm evicts
        // once and the slow path re-seeds the same candidate
        // forever.
        //
        // FZDiag35: the conversion no longer gates on the session's
        // stored owner stamp at all. That stamp was derived from the
        // reply-egress row at synthesis (RG2, surviving) for the
        // stamp=2 half of live rows, so the old metadata gate could
        // never convert them — the gate is dropped and the test is
        // purely destination-based: `dest_rg`, the connected owner
        // of the reply destination (the client LAN prefix's owner
        // RG, RG1 at seed), must be KNOWN (>0) and NOT
        // forwarding-active locally. Soundness: this is a reverse
        // hit on a local ForwardCandidate, so the reply would TX
        // toward `resolution_target` (the client); if that
        // destination's connected owner is a departed RG, local TX
        // is by definition into the departed member — the fabric
        // redirect to the new owner is the only correct serve.
        // There is NO false-convert shape: a destination whose
        // connected owner is locally active (the ordinary
        // locally-served reply) keeps `destination_local` and is
        // served bit-identically; an unknown owner (dest_rg==0,
        // e.g. a gateway/default-routed destination with no
        // connected prefix) is not peer-ownership and never
        // converts. Anti-loop: a fabric-link arrival never
        // re-redirects. Non-reverse hits are bit-identical.
        if let Some(redirect) = reverse_hit_departed_destination_redirect(
            forwarding,
            ha_state,
            now_secs,
            fabric_link_ingress,
            resolved.metadata.is_reverse,
            resolution_target,
            install_table_name_for_session(forwarding, decision, resolution_target),
            resolved.metadata.egress_zone,
            decision.resolution.disposition,
        ) {
            decision.resolution = redirect;
        }
        // #9752: a terminal outcome arms this worker's purge walk (D8).
        if decision.resolution.disposition == ForwardingDisposition::TableUnavailable {
            flag_install_table_purge(worker_id);
        }
        let metadata = resolved.metadata.clone();
        let deferred_synced_promotion = (!keep_transient).then(|| DeferredSyncedPromotion {
            key: resolved_key.clone(),
            decision,
            metadata: metadata.clone(),
            origin: hit_origin,
            fabric_ingress,
            protocol,
            tcp_flags,
            now_ns,
            ack,
        });
        let deferred_forwarding_revalidation =
            if forwarding_stale && !keep_transient {
                let policy_to_zone_id =
                    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                        metadata.egress_zone
                    } else {
                        forwarding.egress_zone_id(decision.resolution.egress_ifindex)
                    };
                let invalidate_policy_revalidation = previous_policy_to_zone_id
                    .is_some_and(|previous| previous != policy_to_zone_id);
                let owner_rg_id = matches!(
                    decision.resolution.disposition,
                    ForwardingDisposition::ForwardCandidate
                        | ForwardingDisposition::FabricRedirect
                        | ForwardingDisposition::HAInactive
                        | ForwardingDisposition::LocalDelivery
                )
                .then(|| owner_rg_for_resolution(forwarding, decision.resolution));
                // #14318: only a locally-forwarding route (or the recorded
                // zone behind a fabric redirect, already in policy_to_zone_id)
                // names the flow's new egress zone. Terminal routes do not.
                let new_egress_zone = if decision.resolution.disposition
                    == ForwardingDisposition::FabricRedirect
                {
                    Some(policy_to_zone_id)
                } else if matches!(
                    decision.resolution.disposition,
                    ForwardingDisposition::ForwardCandidate
                        | ForwardingDisposition::MissingNeighbor
                ) && decision.resolution.egress_ifindex != 0
                {
                    Some(policy_to_zone_id)
                } else {
                    None
                };
                Some(DeferredForwardingRevalidation {
                    resolution: decision.resolution,
                    owner_rg_id,
                    invalidate_policy_revalidation,
                    new_egress_zone,
                })
            } else {
                None
            };
        return Some(ResolvedFlowSessionDecision {
            key: resolved_key.clone(),
            session_id,
            timeout_secs: sessions.timeout_secs_for(&resolved_key),
            decision,
            source_nat_static,
            metadata,
            origin: hit_origin,
            source_nat_validation_key,
            created: false,
            install_failed: false,
            authority_deferred: hit.authority_deferred,
            deferred_forwarding_revalidation,
            deferred_synced_promotion,
            deferred_shared_materialization,
            deferred_synced_purge,
            fabric_adopted,
        });
    }
    // #11061: a synthetic/quarantined reply domain cannot be reinterpreted
    // through a mixed-zero NAT candidate. Let policy/native routing handle it;
    // building a reverse decision here could borrow a domain-0 MAIN session.
    if crate::session::is_quarantined_routing_domain(flow.forward_key.routing_domain) {
        return None;
    }
    // #7169: the main packet path — the one that INSTALLS a reverse session
    // from the match, making the adjudication durable. Revalidate the arrival
    // zone against the session being synthesized.
    //
    // A fabric-ingress packet is exempt and must be: it arrives on the fabric
    // link from the peer node, so its arrival zone is the fabric rather than
    // the flow's logical ingress. Constraining it would break cross-chassis
    // forwarding, which is a correctness break, not a hardening.
    let reverse_ingress = if fabric_ingress {
        crate::afxdp::shared_ops::ReverseIngress::Unconstrained
    } else {
        // #9383: key the zone ledger on the LOGICAL (VLAN unit) arrival ifindex,
        // not the raw physical one `meta.ingress_ifindex` carries.
        //
        // `ifindex_to_zone_id` deliberately PROPAGATES a zoned child unit's zone
        // onto its parent's ifindex (#921/#3618), so on a trunk whose units sit
        // in different zones the physical key answers with whichever unit won the
        // propagation. Measured on a `build_forwarding_state` trunk with unit 42
        // in `lan` and unit 43 UNZONED, both `parent_ifindex = 41`:
        // `ifindex_to_zone_id[41] = Some(lan)` while
        // `resolve_ingress_logical_ifindex(41, vlan 20) = Some(43)` and
        // `ifindex_to_zone_id[43] = None`. The physical lookup answers
        // `Zone(lan)` where the logical resolution answers "unzoned" — a
        // different ANSWER, not a different spelling of the same one.
        //
        // That matters here more than at most sites: a match admitted by a wrong
        // arrival zone makes `install_reverse_session_from_forward_match` MINT a
        // reverse session, and reverse entries are exempt from zone-policy
        // re-derivation by design (`policy_revalidation.rs` gate 1), so the
        // synthesized session then rides the established fast path with no
        // further adjudication. Every zone / filter / pre-routing-NAT admission
        // site already resolves the logical unit first (#3021/#5802).
        //
        // `.unwrap_or(ingress_ifindex)` is the same fallback those sites use: an
        // untagged port, and any arrival with no `(parent, vlan)` mapping,
        // resolves logical == physical and is byte-identical to pre-#9383.
        let arrival_logical = crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
            forwarding,
            ingress_ifindex,
            ingress_vlan_id,
        )
        .unwrap_or(ingress_ifindex);
        match forwarding.ifindex_to_zone_id.get(&arrival_logical).copied() {
            Some(z) => crate::afxdp::shared_ops::ReverseIngress::Zone(z),
            // Fail CLOSED. An unmapped arrival interface gives nothing to
            // revalidate against, and treating that as "no constraint" would
            // reopen the hole for exactly the traffic least accounted for.
            None => crate::afxdp::shared_ops::ReverseIngress::Unzoned,
        }
    };
    let forward_match = if let Some(prevalidated) = prevalidated_forward_nat_match {
        // Recheck the domain-zero reverse tuple at consumption time. The
        // caller's proof authorizes this candidate only, not a general
        // relaxation of reverse-NAT domain admission.
        let mut unique_reply_key = flow.forward_key.clone();
        unique_reply_key.routing_domain = 0;
        let Some(current_match) =
            sessions.find_unique_established_forward_nat_match_at(&unique_reply_key, now_ns)
        else {
            return None;
        };
        if current_match.key != prevalidated.key
            || !crate::afxdp::shared_ops::shared_forward_nat_candidate_is_unique(
                shared.nat_sessions,
                shared.owner_rg_indexes,
                &unique_reply_key,
                &current_match.key,
                current_match.decision.nat,
            )
        {
            return None;
        }
        current_match
    } else {
        lookup_forward_nat_across_scopes_at(
            sessions,
            shared.nat_sessions,
            forwarding,
            shared.owner_rg_indexes,
            &flow.forward_key,
            reverse_ingress,
            now_ns,
        )?
    };
    let (resolved, reverse_installed) = install_reverse_session_from_forward_match(
        sessions,
        session_map,
        shared.sessions,
        shared.nat_sessions,
        shared.forward_wire_sessions,
        shared.owner_rg_indexes,
        shared.peer_worker_commands,
        shared.worker_commands_by_id,
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
        lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision)
            .resolution;
    let looked_up_resolution = super::prefer_local_forward_candidate_for_fabric_ingress(
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
        fabric_ingress,
        resolution_target,
        install_table_name_for_session(forwarding, decision, resolution_target),
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
    // #16217: same adopted-ForwardCandidate exemption as the hit arm.
    let enforced_resolution = if fabric_adopted {
        fabric_adopted_resolution(forwarding, ha_state, now_secs, looked_up_resolution, enforced_resolution, dynamic_neighbors, resolution_target, adopted_recovery.as_ref())
    } else {
        enforced_resolution
    };
    // #15958b: same retained-redirect guard as the hit arm above.
    if resolved.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
        let rev_table = install_table_name_for_session(forwarding, resolved.decision, resolution_target_for_session(flow, resolved.decision));
        let dest_rg = super::connected_owner_rg_for_target_in_table(forwarding, resolution_target_for_session(flow, resolved.decision), rev_table);
        // Unknown owner (dest_rg==0): keep candidate.
        let destination_owner_active = dest_rg == 0 || (dest_rg > 0
            && ha_state
                .get(&dest_rg)
                .is_some_and(|group| group.is_forwarding_active(now_secs)));
        let enforced_resolution = redirect_session_via_fabric_if_needed(
            forwarding,
            enforced_resolution,
            fabric_link_ingress,
            resolved.metadata.ingress_zone,
        );
        decision.resolution = if fabric_link_ingress {
            enforced_resolution
        } else {
            super::rehome_or_retain_fabric_redirect_16524(
                forwarding,
                resolved.decision.resolution,
                enforced_resolution,
                resolved.metadata.egress_zone,
                destination_owner_active,
                dest_rg == 0,
                Some(resolution_target_for_session(flow, resolved.decision)),
                rev_table,
            )
        };
    } else {
        decision.resolution = redirect_session_via_fabric_if_needed_at(
            forwarding,
            ha_state,
            now_secs,
            enforced_resolution,
            fabric_link_ingress,
            resolved.metadata.ingress_zone,
        );
    }
    // #9752: terminal observation arms the purge walk (D8; reverse arm).
    if decision.resolution.disposition == ForwardingDisposition::TableUnavailable {
        flag_install_table_purge(worker_id);
    }
    let metadata = resolved.metadata;
    // #13079: one install snapshot for both fields.
    let install_info = sessions.installed_session_info(&flow.forward_key);
    Some(ResolvedFlowSessionDecision {
        key: flow.forward_key.clone(),
        session_id: install_info.map(|info| info.session_id).unwrap_or(0),
        timeout_secs: install_info.map(|info| info.timeout_secs).unwrap_or(0),
        decision,
        source_nat_static: resolved.aux.source_nat_static,
        metadata,
        origin: SessionOrigin::ReverseFlow,
        source_nat_validation_key: None,
        // #1861 §5.4 + AGY r1 F1: `created` reports the ACTUAL install
        // outcome (was unconditionally true — session_creates over-counted
        // at cap and publish_bpf_conntrack_entry fired for a session that
        // does not exist locally). `install_failed` keeps the failed-repair
        // reply out of the flow cache so the repair re-fires per packet
        // and succeeds on the first packet after the table drops below
        // max_sessions.
        created: reverse_installed,
        install_failed: !reverse_installed,
        // #10636: reverse-synthesized from a forward match (close, if any,
        // was stamped at install); never a deferred local hit.
        authority_deferred: false,
        deferred_synced_promotion: None,
        deferred_shared_materialization: None,
        deferred_forwarding_revalidation: None,
        deferred_synced_purge: None,
        fabric_adopted: false,
    })
}

pub(in crate::afxdp) fn redirect_session_via_fabric_if_needed(forwarding: &ForwardingState,
resolution: ForwardingResolution,
fabric_ingress: bool,
ingress_zone: u32,) -> ForwardingResolution {
    redirect_session_via_fabric_if_needed_at(
        forwarding,
        &BTreeMap::new(),
        0,
        resolution,
        fabric_ingress,
        ingress_zone,
    )
}

/// #16216: as `redirect_session_via_fabric_if_needed`, plus the rescue
/// of a DiscardRoute that carries cluster-terminal provenance. The HA
/// demotion preserves the FIB's `source_ifindex` stamp; when that
/// would-be egress's RG is peer-owned at conversion time, the packet
/// belongs to the peer — redirect it across the fabric so the new
/// owner creates (or hits) the authoritative session there, instead
/// of dropping on the split node forever. Operator discards carry no
/// stamp and never rescue; a fabric-ingress packet never re-redirects.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn redirect_session_via_fabric_if_needed_at(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
now_secs: u64,
resolution: ForwardingResolution,
fabric_ingress: bool,
ingress_zone: u32,) -> ForwardingResolution {
    let rescuable = matches!(
        resolution.disposition,
        ForwardingDisposition::HAInactive | ForwardingDisposition::ClusterTerminalHAInactive
    ) || crate::afxdp::forwarding::discard_route_is_cluster_terminal_peer_owned(
        forwarding, ha_state, now_secs, &resolution,
    );
    if !rescuable {
        return resolution;
    }
    if fabric_ingress {
        return resolution;
    }
    resolve_fabric_redirect_for_ingress_zone(forwarding, Some(ingress_zone))
        .unwrap_or(resolution)
}
/// #16217: reclassify the HA-enforcement outcome for a FABRIC-ADOPTED
/// flow. The poll fabric-adoption gate
/// (`fabric_adoption_established_for_wire`) has already proven, for
/// this exact NAT'd wire tuple, that the session is Established and
/// that this node is the RG owner post-takeover; the adoption decision
/// IS the HA-activity proof for this packet. A ForwardCandidate the
/// ordinary slow path produced (the pre-failover serving shape) must
/// therefore not be terminated as `HAInactive` /
/// `ClusterTerminalHAInactive` by the poll_descriptor HA-activity
/// enforcement on the receiving worker — that terminal is the last
/// resolution the adopted tuples died on live (`ha_inactive
/// ingress-ifindex=4 egress-ifindex=14` on fw1 while RG1 read active).
/// Only the adopted resolution converts: a ForwardCandidate that HA
/// enforcement demoted is restored verbatim, and any other enforced
/// outcome (a genuine ForwardCandidate, LocalDelivery, ...) is kept
/// as enforced.
///
/// #16217 (FZDiag24): the second adoptable shape is a looked-up
/// `MissingNeighbor` whose egress RG is known. At the takeover
/// instant the new owner's FIB already nominates the WAN egress
/// (egress 14, next-hop 172.16.80.200) but the neighbor is not yet
/// resolved, so the FIB answers `MissingNeighbor` with
/// `neighbor_mac == None`; HA enforcement then strips it at
/// `forwarding/ha.rs` (`!is_forwarding_active -> HAInactive`, which
/// keeps `..resolution` and therefore the neighbor-less shape). The
/// pre-fix helper required `looked_up == ForwardCandidate`, so this
/// demoted `MissingNeighbor` was kept as `HAInactive` forever and
/// every post-FO transient reply hit the session-HIT with
/// `session_hit_fabric_adopted=true` yet still dropped (FZDiag24:
/// 3,308 `MissingNeighbor -> HAInactive` + 2,688
/// `ClusterTerminalHAInactive` resolutions, zero misses). For an
/// adopted flow the neighbor must be RECOMPUTED from the live FIB
/// instead of trusting the stripped shape: a fresh FIB lookup for
/// the packet destination that yields a `ForwardCandidate` (neighbor
/// now resolved, egress RG known) restores that candidate verbatim.
/// If the fresh lookup still answers `MissingNeighbor` with a
/// known egress RG, the adopted hit returns that retryable shape
/// instead of the terminal (FZDiag27): adoption proved
/// establishment and (via the gate) ownership, and the missing
/// piece is only the neighbor, so the poll path drops this packet
/// without terminalizing the flow, drives the neighbor probe, and
/// the next retransmit re-enters this restore once the neighbor
/// lands. Any other recomputed disposition keeps the HA terminal.
/// The recompute is gated on the looked-up egress RG being known
/// (>0): an unknown egress (rg 0) never restores.
///
/// Non-adopted flows never reach this helper (`fabric_adopted ==
/// false` at every other callsite), so the fail-closed terminal
/// stands for them bit-identically. HAInactive with unknown ownership
/// (egress RG 0: resolution never named an owner) stays terminal even
/// for adopted flows -- adoption proved session establishment, not
/// route ownership. Positive non-ownership is enforced at the
/// adoption gate and on every subsequent hit, not by re-imposing the
/// lagging snapshot's terminal here. The `dynamic_neighbors` /
/// `target` arguments are used ONLY by the MissingNeighbor and
/// ClusterTerminal recomputes; the ForwardCandidate arm ignores
/// them.
///
/// #16217 (FZDiag27): the third adoptable shape is a looked-up
/// `ClusterTerminalHAInactive` ITSELF. The stored `SyncImport` row
/// carries the cluster terminal (exported while neither node owned
/// the egress RG), so the synced-session lookup returns the stored
/// terminal verbatim: egress 0, no next-hop, and
/// `owner_rg_for_resolution` reads 0 off it — neither arm above
/// could ever fire and the fallthrough kept the terminal on every
/// adopted hit (live: hundreds of hits with
/// `stored == looked == enforced == ClusterTerminalHAInactive`).
/// The egress RG is therefore recovered from the FIB, not from the
/// terminal, with the same recompute as the MissingNeighbor arm.
/// A recomputed `ForwardCandidate` with a resolved neighbor MAC
/// and a known egress RG restores; a recomputed `MissingNeighbor`
/// (egress known, neighbor not yet landed) is returned AS
/// `MissingNeighbor` — retryable, never re-terminalized — so the
/// poll path drops this packet without terminalizing the flow and
/// the next retransmit re-enters this restore; any other
/// recomputed disposition keeps the HA terminal fail-closed.
///
/// #16217 (FZDiag28): recompute an adopted resolution against the
/// NODE neighbor map -- the dynamic map the warm pass at RG
/// activation (`Coordinator::queue_warm_pass` over the shared
/// synced rows) and the kernel monitor populate for every worker,
/// not the per-worker/per-binding pending_neigh representative frame
/// `retry_pending_neigh` parks. The FIB recompute already consults
/// this map via `lookup_forwarding_resolution_with_dynamic`; this
/// helper names the adoption-side contract and unit-pins it: a hop
/// present ONLY in the node map (never in any worker's
/// `forwarding.neighbors` snapshot, never parked) still restores
/// the adopted flow to the ForwardCandidate carrying that MAC.
///
/// #16217 (FZDiag29): live, `fabric_adopted_resolution` still did not
/// restore SyncImport rows whose stored disposition is
/// `ClusterTerminalHAInactive`. Trace (Wire26, FZ28 FILE sink):
/// `stored=looked=enforced=ClusterTerminalHAInactive, looked_egress=0`
/// for 128/146 adopted hits. That is EXPECTED to reach the
/// ClusterTerminal arm below — so the arm's recompute itself must be
/// answering a terminal. It does: the destination (172.16.80.200) is
/// ON-LINK via the connected /24 on the WAN RETH, but post-failover
/// that connected prefix is HA-suppressed on the previous BACKUP
/// (its RG was peer-owned until the failover), so `connected_v4`
/// holds no covering row; LPM falls to the pref-200 cluster Null0
/// default and the recompute returns `ClusterTerminalHAInactive`
/// again. Every unit fixture for this arm inserted the connected
/// /24 directly into `connected_v4`, so the recompute always found
/// ForwardCandidate/MissingNeighbor and the arm looked correct —
/// the live FIB shape (cluster-terminal row present, connected row
/// suppressed, egress RG recovered only from
/// `connected_*_by_ifindex` / the terminal's `source_ifindex` stamp)
/// was never exercised.
///
/// The fix uses the RESOLUTION TARGET (`dst`, the post-NAT
/// destination named by `resolution_target_for_session`), never
/// `looked_up.egress_ifindex` (0 on the terminal, so any egress-gated
/// recovery reads 0 and dead-ends): when the plain FIB recompute of
/// `dst` is itself a cluster terminal, recover the would-be egress
/// from the terminal stamp (`source_ifindex`, the
/// `select_source_ifindex_*` attribution the FIB stamped before
/// zeroing the egress — which already consults
/// `connected_*_by_ifindex`, so it works exactly when the transit
/// connected row is suppressed) and, failing that, from the
/// connected LPM over `connected_*_by_ifindex` for `dst`. If that
/// egress is known (owner RG > 0) and a neighbor for `(egress, dst)`
/// is resolved in the static snapshot or the node map, restore a
/// ForwardCandidate on that egress carrying the MAC; if the egress
/// is known but the neighbor is unresolved, return the retryable
/// MissingNeighbor on that egress; otherwise keep the terminal.
/// #16217 (Opus final4 fold): the gate-proved context the adopted
/// recovery is judged against. The poll callsites build it ONLY when
/// `fabric_adoption_gate_for_wire` qualified the tuple: the gate
/// resolved the candidate's OWN stored decision in the session's
/// validated install table and proved this node forwarding-active
/// owner of the resulting egress RG (fresh authoritative set). The
/// recovery below may therefore restore a candidate ONLY when the
/// candidate's egress RG equals `proved_rg` — adoption proved
/// establishment AND ownership of that one RG, never of whatever
/// egress a MAIN-table re-resolution happens to name. `None` (every
/// non-adopted caller) keeps the terminal bit-identically.
#[derive(Clone)]
pub(in crate::afxdp) struct AdoptedRecovery {
    /// The session decision the gate proved ownership from: its
    /// `install_table_domain`/`install_table_check` name the validated
    /// install table every recovery re-resolution must run in (never
    /// MAIN for a tenant session), and its NAT names the post-NAT
    /// target.
    pub(in crate::afxdp) decision: SessionDecision,
    /// The per-flow ECMP hash key (canonical forward key), so the
    /// recovery spread matches the session re-resolve.
    pub(in crate::afxdp) flow_key: crate::session::SessionKey,
    /// Egress RG the gate proved this node owns (forwarding-active,
    /// fresh authoritative set). A recovered candidate whose egress
    /// RG differs (or is unknown, 0) is refused.
    pub(in crate::afxdp) proved_rg: i32,
}

/// #16217 (Opus final4 fold): re-resolve the adopted target in the
/// session's VALIDATED install table — the same table the gate
/// judged ownership in — never MAIN. `Unresolvable` (stale domain /
/// owner mismatch / absent family) yields no resolution: the
/// recovery cannot name an egress in a table it cannot validate, so
/// the terminal stands. ECMP spread uses the canonical flow key,
/// exactly as `lookup_forwarding_resolution_for_session_with_cache`.
fn adopted_resolution_in_install_table(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    recovery: &AdoptedRecovery,
    target: IpAddr,
) -> Option<ForwardingResolution> {
    match super::resolve_install_table_for_session(forwarding, recovery.decision, target) {
        super::InstallTable::Unresolvable => None,
        super::InstallTable::Table(table) => Some(
            super::forwarding::lookup_forwarding_resolution_with_dynamic_for_flow_in_table(
                forwarding,
                dynamic_neighbors,
                target,
                &recovery.flow_key,
                table,
            )
            .resolution,
        ),
        super::InstallTable::Default => Some(
            super::forwarding::lookup_forwarding_resolution_with_dynamic_for_flow(
                forwarding,
                dynamic_neighbors,
                target,
                &recovery.flow_key,
            )
            .resolution,
        ),
    }
}

/// #16217 (Opus final4 fold): may the recovery restore/return
/// `resolution`? Only a named egress whose RG is EXACTLY the
/// gate-proved RG. A candidate egressing under any other RG (a
/// MAIN-table tenant leak, a gateway route into another RG, an
/// unknown egress) is not what adoption proved and is refused.
fn adopted_recovery_egress_matches_proof(
    forwarding: &ForwardingState,
    recovery: &AdoptedRecovery,
    resolution: ForwardingResolution,
) -> bool {
    recovery.proved_rg > 0
        && super::forwarding::owner_rg_for_resolution(forwarding, resolution) == recovery.proved_rg
}

pub(in crate::afxdp) fn adopted_cluster_terminal_target_resolution(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    target: IpAddr,
    terminal: ForwardingResolution,
    recovery: &AdoptedRecovery,
) -> Option<ForwardingResolution> {
    // Egress recovery, in attribution order: the FIB's own stamp on
    // the terminal, then the connected LPM for the target IN THE
    // SESSION'S INSTALL TABLE (which consults
    // `connected_*_by_ifindex` — the suppressed-row ledger).
    let table =
        super::install_table_name_for_session(forwarding, recovery.decision, target);
    let mut egress_ifindex = terminal.source_ifindex;
    if egress_ifindex <= 0 {
        egress_ifindex =
            super::connected_ifindex_for_target_in_table(forwarding, target, table);
    }
    if egress_ifindex <= 0 {
        return None;
    }
    let probe = ForwardingResolution {
        disposition: ForwardingDisposition::MissingNeighbor,
        egress_ifindex,
        tx_ifindex: egress_ifindex,
        next_hop: Some(target),
        neighbor_mac: None,
        source_ifindex: 0,
        ..terminal
    };
    // Opus final4: the recovered egress must be the gate-proved RG's
    // egress — a connected row in another table/RG never restores.
    if !adopted_recovery_egress_matches_proof(forwarding, recovery, probe) {
        return None;
    }
    let neighbor = super::forwarding::lookup_neighbor_entry(
        forwarding,
        Some(dynamic_neighbors),
        egress_ifindex,
        target,
    );
    match neighbor {
        Some(entry) => {
            let mut restored = probe;
            restored.disposition = ForwardingDisposition::ForwardCandidate;
            restored.neighbor_mac = Some(entry.mac);
            super::populate_egress_resolution(forwarding, egress_ifindex, &mut restored);
            Some(restored)
        }
        None => Some(probe),
    }
}

pub(in crate::afxdp) fn adopted_resolution_from_node_neighbor_map(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    target: IpAddr,
    recovery: &AdoptedRecovery,
) -> Option<ForwardingResolution> {
    adopted_resolution_in_install_table(forwarding, dynamic_neighbors, recovery, target)
}

pub(in crate::afxdp) fn fabric_adopted_resolution(
    forwarding: &ForwardingState,
    _ha_state: &BTreeMap<i32, HAGroupRuntime>,
    _now_secs: u64,
    looked_up: ForwardingResolution,
    enforced: ForwardingResolution,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    target: IpAddr,
    recovery: Option<&AdoptedRecovery>,
) -> ForwardingResolution {
    if !matches!(
        enforced.disposition,
        ForwardingDisposition::HAInactive | ForwardingDisposition::ClusterTerminalHAInactive
    ) {
        return enforced;
    }
    // Opus final4: without the gate-proved context there is no
    // adoption proof to restore against — every non-adopted caller
    // keeps the terminal bit-identically.
    let Some(recovery) = recovery else {
        return enforced;
    };
    if looked_up.disposition == ForwardingDisposition::ForwardCandidate {
        // Restore the candidate only when its egress RG is EXACTLY
        // the gate-proved RG: adoption proved establishment and
        // ownership of that RG (fresh authoritative set), not of any
        // egress the looked-up resolution happens to name. Unknown
        // (0) or mismatched egress RG keeps the terminal.
        if !adopted_recovery_egress_matches_proof(forwarding, recovery, looked_up) {
            return enforced;
        }
        if looked_up.neighbor_mac.is_some() {
            return looked_up;
        }
        // The looked-up candidate lost its neighbor MAC (the parked
        // representative resolved first on another worker/binding).
        // Re-resolve IN THE SESSION'S INSTALL TABLE and consult the
        // node neighbor map: a hop the warm pass landed there
        // restores the candidate with that MAC — only under the
        // gate-proved RG.
        let Some(recomputed) =
            adopted_resolution_from_node_neighbor_map(forwarding, dynamic_neighbors, target, recovery)
        else {
            return looked_up;
        };
        if recomputed.disposition == ForwardingDisposition::ForwardCandidate
            && recomputed.neighbor_mac.is_some()
            && adopted_recovery_egress_matches_proof(forwarding, recovery, recomputed)
        {
            return recomputed;
        }
        return looked_up;
    }
    if looked_up.disposition == ForwardingDisposition::MissingNeighbor {
        // FZDiag24 arm: HA enforcement stripped the (already
        // neighbor-less) MissingNeighbor to HAInactive. Recompute
        // the neighbor/egress from the FIB IN THE SESSION'S INSTALL
        // TABLE: a fresh ForwardCandidate (neighbor resolved since
        // the look-up) replaces the terminal; a still-missing
        // neighbor under the gate-proved RG is returned AS
        // MissingNeighbor (retryable, FZDiag27) so the poll path
        // drops this packet without terminalizing the flow.
        // Anything else (no install-table cover, unknown/mismatched
        // egress RG) keeps the terminal fail-closed.
        if !adopted_recovery_egress_matches_proof(forwarding, recovery, looked_up) {
            return enforced;
        }
        let Some(recomputed) =
            adopted_resolution_from_node_neighbor_map(forwarding, dynamic_neighbors, target, recovery)
        else {
            return enforced;
        };
        if recomputed.disposition == ForwardingDisposition::ForwardCandidate
            && recomputed.neighbor_mac.is_some()
            && adopted_recovery_egress_matches_proof(forwarding, recovery, recomputed)
        {
            return recomputed;
        }
        if recomputed.disposition == ForwardingDisposition::MissingNeighbor
            && adopted_recovery_egress_matches_proof(forwarding, recovery, recomputed)
        {
            return recomputed;
        }
        return enforced;
    }
    if looked_up.disposition == ForwardingDisposition::ClusterTerminalHAInactive {
        // FZDiag27 arm: the looked-up shape IS the terminal (stored
        // on the SyncImport row), so it names no egress RG and the
        // arms above can never fire. Recover the egress from the
        // live FIB IN THE SESSION'S INSTALL TABLE with the same
        // recompute the MissingNeighbor arm uses, then judge the
        // recomputed shape against the gate-proved RG: a resolved
        // ForwardCandidate (neighbor MAC present, egress RG ==
        // proved) restores; a still-missing neighbor under the
        // proved RG is returned AS MissingNeighbor (retryable);
        // anything else keeps the terminal fail-closed.
        let Some(recomputed) =
            adopted_resolution_from_node_neighbor_map(forwarding, dynamic_neighbors, target, recovery)
        else {
            return enforced;
        };
        if recomputed.disposition == ForwardingDisposition::ForwardCandidate
            && recomputed.neighbor_mac.is_some()
            && adopted_recovery_egress_matches_proof(forwarding, recovery, recomputed)
        {
            return recomputed;
        }
        if recomputed.disposition == ForwardingDisposition::MissingNeighbor
            && adopted_recovery_egress_matches_proof(forwarding, recovery, recomputed)
        {
            return recomputed;
        }
        // FZDiag29: the install-table recompute itself answered the
        // cluster terminal (the connected prefix covering the target
        // is HA-suppressed in `connected_v4` post-failover, so LPM
        // falls to the pref-200 cluster Null0). Recover the would-be
        // egress from the RESOLUTION TARGET (`target` = dst), not
        // from `looked_up` (egress 0): the terminal's `source_ifindex`
        // stamp / the connected LPM over `connected_*_by_ifindex` IN
        // THE INSTALL TABLE name it, and only an egress under the
        // gate-proved RG restores.
        if recomputed.disposition == ForwardingDisposition::ClusterTerminalHAInactive {
            // Prefer the fresh recompute's stamp; fall back to the
            // looked-up terminal's (identical FIB, either names it).
            let stamped = if recomputed.source_ifindex > 0 {
                recomputed
            } else {
                looked_up
            };
            if let Some(recovered) = adopted_cluster_terminal_target_resolution(
                forwarding,
                dynamic_neighbors,
                target,
                stamped,
                recovery,
            ) {
                return recovered;
            }
        }
        return enforced;
    }
    enforced
}


pub(in crate::afxdp) fn enforce_session_ha_resolution(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
now_secs: u64,
resolution: ForwardingResolution,
ingress_ifindex: i32,
ha_startup_grace_until_secs: u64,) -> ForwardingResolution {
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

