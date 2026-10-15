use super::*;

pub(super) fn materialize_shared_session_hit(sessions: &mut SessionTable,
resolved: &mut ResolvedSessionLookup,
forwarding: &ForwardingState,
now_ns: u64,
tcp_flags: u8,) -> (SessionLookup, bool) { if let Some(shared) = resolved.shared_entry.take() {
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
    let materialized = sessions.upsert_synced_with_origin(
        SessionInstall {
            key: replica.key.clone(),
            decision: replica.decision,
            metadata: replica.metadata.clone(),
            origin: shared.origin.materialized_shared_hit_origin(),
            now_ns,
            protocol: replica.protocol,
            tcp_flags,
            // #5212: a reactive materialize of a shared-map hit inherits the
            // shared entry's id — the peer's id for a synced session (so the
            // eventual close correlates), 0 for a local entry (fresh alloc).
            session_id: replica.session_id,
            // #9412: a materialized shared hit keeps the synced close class, so
            // a closing peer copy is not reset to the established window by the
            // worker that happens to see its next packet.
            tcp_close_class: replica.tcp_close_class,
            tcp_handshake_state: replica.tcp_handshake_state,
            source_nat_static: replica.source_nat_static,
        },
        false,
    );
    // A refused shared repair must not mutate the incumbent local row's
    // leak provenance. The stamp is evidence for the materialized replica
    // only; failed clobber attempts return install_failed instead.
    if materialized
        && let Some(incarnation) =
            (replica.leak_incarnation != 0).then_some(replica.leak_incarnation)
    {
        sessions.stamp_leak_incarnation(&replica.key, incarnation);
    }
    return (
        SessionLookup {
            decision: replica.decision,
            metadata: replica.metadata,
            forwarding_generation: ForwardingGenerationStamp::default(),
        },
        !materialized,
    );
}
(resolved.lookup.clone(), false) }

// Test and non-worker callers retain the no-conntrack transition behavior.
// The production poll path uses the `_with_conntrack` variant so helper
// promote/demote transitions can invalidate only the origin bit in the mirror.
pub(in crate::afxdp) fn resolve_flow_session_decision(sessions: &mut SessionTable,
session_map: SteeringMap<'_>,
shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
now_ns: u64,
now_secs: u64,
protocol: u8,
tcp_flags: u8,
ingress_ifindex: i32,
ingress_vlan_id: u16,
fabric_ingress: bool,
ha_startup_grace_until_secs: u64,
worker_id: u32,
verdict: SessionHitVerdict,) -> Option<ResolvedFlowSessionDecision> {
    let mut resolved = resolve_flow_session_decision_with_conntrack(
        sessions,
        session_map,
        -1,
        -1,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        peer_worker_commands,
        empty_worker_commands_by_id(),
        forwarding,
        ha_state,
        dynamic_neighbors,
        flow,
        now_ns,
        now_secs,
        protocol,
        tcp_flags,
        ingress_ifindex,
        ingress_vlan_id,
        fabric_ingress,
        fabric_ingress,
        ha_startup_grace_until_secs,
        worker_id,
        None,
    )?;
    maybe_promote_synced_session_with_conntrack(
        sessions,
        session_map,
        -1,
        -1,
        SharedSessionRefs {
            sessions: shared_sessions,
            nat_sessions: shared_nat_sessions,
            forward_wire_sessions: shared_forward_wire_sessions,
            owner_rg_indexes: shared_owner_rg_indexes,
        },
        peer_worker_commands,
        empty_worker_commands_by_id(),
        forwarding,
        now_ns,
        tcp_flags,
        worker_id,
        verdict,
        &mut resolved,
    );
    if verdict == SessionHitVerdict::Owner
        && let Some(revalidation) = resolved.deferred_forwarding_revalidation.take()
    {
        if revalidation.invalidate_policy_revalidation {
            sessions.invalidate_policy_revalidation(&resolved.key);
        }
        sessions.revalidate_forwarding_resolution(
            &resolved.key,
            revalidation.resolution,
            revalidation.owner_rg_id,
        );
        if let Some(owner_rg_id) = revalidation.owner_rg_id {
            resolved.metadata.owner_rg_id = owner_rg_id;
        }
    }

    Some(resolved)
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
    let (_, install_failed) =
        materialize_shared_session_hit(sessions, &mut hit, forwarding, now_ns, tcp_flags);
    resolved.install_failed = install_failed;
    if resolved.session_id == 0 && !install_failed {
        resolved.session_id = sessions.session_id_for(&resolved.key);
    }
    if install_failed {
        resolved.deferred_synced_promotion = None;
    }
}

pub(in crate::afxdp) fn resolve_flow_session_decision_with_conntrack(sessions: &mut SessionTable,
session_map: SteeringMap<'_>,
conntrack_v4_fd: c_int,
conntrack_v6_fd: c_int,
shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
worker_commands_by_id: &WorkerCommandQueues,
forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
now_ns: u64,
now_secs: u64,
protocol: u8,
tcp_flags: u8,
ingress_ifindex: i32,
// #9383: the arrival frame's VLAN id, needed ONLY to resolve
// `ingress_ifindex` (a physical bind port) to the LOGICAL unit ifindex the
// zone ledger is keyed by. A caller with no VLAN context passes 0, which
// resolves logical == physical for every untagged port.
ingress_vlan_id: u16,
// `fabric_ingress` is the validated stamp/overlay semantic used by
// session policy; `fabric_link_ingress` is the physical parent-or-overlay
// arrival semantic used by the anti-loop redirect guard.
fabric_ingress: bool,
fabric_link_ingress: bool,
ha_startup_grace_until_secs: u64,
// #6211 F2: THIS worker's id, threaded from `WorkerLaunchPlan::worker_id`
// in the worker loop. A peer-synced reservation is held by every worker, so
// a release must drop THIS worker's bit rather than free the port outright.
worker_id: u32,
// Only the unique unstamped-fabric reverse-NAT exception supplies this.
prevalidated_forward_nat_match: Option<crate::session::ForwardSessionMatch>,) -> Option<ResolvedFlowSessionDecision> {
    if !crate::session::PMechSessionDirectory::global()
        .probe_packet_key(&flow.forward_key)
        .is_fallthrough()
    {
        return None;
    }
    // Bundle the four shared-session refs once per call. `SharedSessionRefs`
    // is `#[derive(Copy)]`, so the three downstream uses below
    // (purge_translated_synced_hit + 2× maybe_promote_synced_session) each
    // get a free by-value copy — structurally same codegen as the
    // explicit-argument form (4 pointer-sized fields, no Drop). cargo-asm
    // 0.1.16 cannot parse this codebase's symbols, so the empirical gate
    // is the smoke-plus-test-failover pass on the loss userspace cluster.
    let shared = SharedSessionRefs {
        sessions: shared_sessions,
        nat_sessions: shared_nat_sessions,
        forward_wire_sessions: shared_forward_wire_sessions,
        owner_rg_indexes: shared_owner_rg_indexes,
    };
    if let Some(mut hit) = lookup_session_across_scopes_with_shared(
        sessions,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        &flow.forward_key,
        now_ns,
        tcp_flags,
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
        let source_nat_static = match hit.shared_entry.as_ref() {
            Some(entry) => entry.source_nat_static,
            None => sessions.source_nat_static_for(hit.key.as_ref(&flow.forward_key)),
        };
        let keep_transient = poison_key.is_some_and(|(key, decision, metadata, origin)| {
            should_keep_synced_hit_transient(ha_state, now_secs, key, decision, metadata, origin)
        });
        let session_id_before_purge = shared_session_id
            .filter(|session_id| *session_id != 0)
            .or_else(|| {
                (!shared_was_present)
                    .then(|| sessions.session_id_for(hit.key.as_ref(&flow.forward_key)))
            })
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
                    sessions.session_id_for(resolved_key)
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
        decision.resolution = redirect_session_via_fabric_if_needed(
            forwarding,
            enforced_resolution,
            fabric_link_ingress,
            resolved.metadata.ingress_zone,
        );
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
                Some(DeferredForwardingRevalidation {
                    resolution: decision.resolution,
                    owner_rg_id,
                    invalidate_policy_revalidation,
                })
            } else {
                None
            };
        return Some(ResolvedFlowSessionDecision {
            key: resolved_key.clone(),
            session_id,
            decision,
            source_nat_static,
            metadata,
            origin: hit_origin,
            source_nat_validation_key,
            created: false,
            install_failed: false,
            close_deferred: hit.close_deferred,
            deferred_forwarding_revalidation,
            deferred_synced_promotion,
            deferred_shared_materialization,
            deferred_synced_purge,
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
                shared_nat_sessions,
                shared_owner_rg_indexes,
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
            shared_nat_sessions,
            forwarding,
            shared_owner_rg_indexes,
            &flow.forward_key,
            reverse_ingress,
            now_ns,
        )?
    };
    let (resolved, reverse_installed) = install_reverse_session_from_forward_match(
        sessions,
        session_map,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        peer_worker_commands,
        worker_commands_by_id,
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
    decision.resolution = redirect_session_via_fabric_if_needed(
        forwarding,
        enforced_resolution,
        fabric_link_ingress,
        resolved.metadata.ingress_zone,
    );
    // #9752: terminal observation arms the purge walk (D8; reverse arm).
    if decision.resolution.disposition == ForwardingDisposition::TableUnavailable {
        flag_install_table_purge(worker_id);
    }
    let metadata = resolved.metadata;
    Some(ResolvedFlowSessionDecision {
        key: flow.forward_key.clone(),
        session_id: sessions.session_id_for(&flow.forward_key),
        decision,
        source_nat_static: None,
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
        close_deferred: false,
        deferred_synced_promotion: None,
        deferred_shared_materialization: None,
        deferred_forwarding_revalidation: None,
        deferred_synced_purge: None,
    })
}

pub(in crate::afxdp) fn redirect_session_via_fabric_if_needed(forwarding: &ForwardingState,
resolution: ForwardingResolution,
fabric_ingress: bool,
ingress_zone: u16,) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if fabric_ingress {
        return resolution;
    }
    resolve_fabric_redirect_for_ingress_zone(forwarding, Some(ingress_zone))
        .unwrap_or(resolution)
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

