use super::*;

pub(in crate::afxdp) fn build_reverse_session_from_forward_match(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
forward_match: ForwardSessionMatch,
now_secs: u64,
ha_startup_grace_until_secs: u64,) -> SessionLookup {
    // #10312: an RI-native forward stores its ingress routing domain on the
    // key. Use that domain for the reply target, not the PBR installing table:
    // PBR is directional, while the reply must find the original client in
    // the client's native instance.
    let table_context = crate::afxdp::forwarding::native_route_table_for_flow_target(
        forwarding,
        forward_match.key.routing_domain,
        forward_match.metadata.ingress_ifindex as i32,
        forward_match.metadata.ingress_vlan_id,
        None,
        forward_match.key.src_ip,
    );
    let (table, install_table_domain, install_table_check, table_unresolvable) = match table_context
    {
        crate::afxdp::forwarding::NativeRouteTable::Default => (None, 0, 0, false),
        crate::afxdp::forwarding::NativeRouteTable::Table {
            table,
            domain,
            check,
        } => (Some(table), domain, check, false),
        crate::afxdp::forwarding::NativeRouteTable::Unresolvable { domain } => {
            (None, domain, 0, true)
        }
    };
    let mut lookup = build_reverse_session_from_forward_match_in_table(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match,
        now_secs,
        ha_startup_grace_until_secs,
        table.as_deref(),
    );
    if table_unresolvable {
        lookup.decision.resolution = crate::afxdp::forwarding::table_unavailable_resolution();
    }
    // `_in_table` stays zero-stamped because it resolves in whatever table its
    // caller names; each caller stamps that table's identity. This native-RI
    // wrapper stamps its derived identity and the TUN-origin builders stamp
    // their tunnel instance's (#12503), so both carry it into later session
    // re-resolves.
    lookup.decision.install_table_domain = install_table_domain;
    lookup.decision.install_table_check = install_table_check;
    lookup
}

/// Table-scoped twin of `build_reverse_session_from_forward_match` (#10038
/// item 6): threads `table` into the reply-target resolution. `None`
/// preserves default-instance behavior while the untabled wrapper performs
/// native-RI derivation (#10312).

#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn build_reverse_session_from_forward_match_in_table(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
forward_match: ForwardSessionMatch,
now_secs: u64,
ha_startup_grace_until_secs: u64,
table: Option<&str>,) -> SessionLookup {
    let requires_fabric_return = forward_match.metadata.fabric_ingress
        || forward_match.decision.resolution.disposition == ForwardingDisposition::FabricRedirect;
    let resolution = reverse_resolution_for_session_in_table(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match.key.src_ip,
        forward_match.metadata.ingress_zone,
        requires_fabric_return,
        now_secs,
        forward_match.decision.resolution.tunnel_endpoint_id != 0
            && now_secs <= ha_startup_grace_until_secs,
        table,
    );
    let metadata = SessionMetadata {
        // #7169: this zone pair comes from the STORED forward session, i.e.
        // from where the ORIGINAL flow went — not from where this packet
        // arrived. That is safe only because the caller now revalidates the
        // arrival zone against `metadata.egress_zone` before a match is
        // returned (see `ReverseIngress`), so by the time this runs the two are
        // necessarily equal. Remove that check and this line silently
        // adjudicates a packet in a zone it never arrived in.
        ingress_zone: forward_match.metadata.egress_zone,
        egress_zone: forward_match.metadata.ingress_zone,
        ingress_zone_check: crate::session::zone_vintage_check_for_id(
            &forwarding.zone_id_to_name,
            forward_match.metadata.egress_zone,
        ),
        egress_zone_check: crate::session::zone_vintage_check_for_id(
            &forwarding.zone_id_to_name,
            forward_match.metadata.ingress_zone,
        ),
        // #7917: DELIBERATELY 0, and not to be "fixed" by inheriting
        // `forward_match.metadata.ingress_ifindex`.
        //
        // A synthesized reverse companion must not take the forward
        // direction's ingress identity: the forward flow's ingress is a
        // PREDICTION of where a reply will arrive, not an OBSERVATION of where
        // it did. 0 means "unobserved", which is truthful; inheriting would
        // make the row confidently wrong, which #6928 refused on the grounds
        // that a wrong interface is strictly worse than none.
        //
        // #7169 was filed listing this zero as part of the defect. It is not.
        // The defect was that nothing checked the ARRIVAL against the session
        // being synthesized, which is a different repair — and the tempting one
        // makes the record worse while leaving the hole open.
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        // Reverse companions are owned by the RG that currently owns the
        // client-side egress resolution, not necessarily the RG that owned the
        // original forward session. This matters during failback when a second
        // RG comes up later and stale reverse entries must be repointed away
        // from prior FabricRedirect results.
        owner_rg_id: owner_rg_for_resolution(forwarding, resolution),
        fabric_ingress: forward_match.metadata.fabric_ingress,
        is_reverse: true,
        // #4565: inherit the forward session's NAT64 reverse info (original v6
        // src/dst) so a peer-PROMOTED NAT64 session's synthesized reverse
        // companion can translate the server's v4 reply back to IPv6 after
        // failover. `build_nat64_forwarded_frame`'s reverse (v4->v6) branch
        // hard-requires this — without it the frame builder returns None and the
        // reply is dropped. `None` for every non-NAT64 forward session (the
        // forward metadata carries `None`), bit-identical to the prior behavior.
        nat64_reverse: forward_match.metadata.nat64_reverse,
        // #2508: inherit the forward session's per-policy log selection so
        // the reverse companion's close delta carries a consistent gate.
        log_session_init: forward_match.metadata.log_session_init,
        log_session_close: forward_match.metadata.log_session_close,
        // #3056: inherit the admitting policy ID from the forward session so a
        // materialized reverse companion attributes the same policy in its
        // BPF-compat conntrack row.
        policy_id: forward_match.metadata.policy_id,
        // #5153: inherit the forward session's per-application idle timeout so
        // the reverse companion ages on the admitting app's window, not the
        // global timeout. Both halves of one stateful flow share the same
        // application, so the app's `inactivity-timeout` governs either
        // direction. `companion_keeps_alive` (expire.rs) uses the companion's
        // OWN `expires_after_ns` — derived from this field via
        // `session_timeout_ns` — to decide whether to keep the idle-crossed
        // forward half alive; hardcoding `None` here made the reverse
        // companion's window fall back to the global timeout (e.g. 300s),
        // extending a 30s app timeout toward the global one. `None` for every
        // forward session with no per-app override (the forward metadata
        // carries `None`), bit-identical to the prior behavior. Residual of
        // #3227/#3301/#4380.
        inactivity_timeout_ns: forward_match.metadata.inactivity_timeout_ns,
        // #3073: inherit the admitting rule's hit-counter handle from the
        // forward session so a materialized reverse companion's reply traffic
        // counts against the same policy. #3322: inherit the reorder-stable
        // bound handle too so the reply counts against the admitting rule
        // even after a live policy reorder.
        policy_counter_idx: forward_match.metadata.policy_counter_idx,
        policy_counter: forward_match.metadata.policy_counter.clone(),
    };
    let decision = SessionDecision {
        resolution: redirect_session_resolution_for_metadata(forwarding, resolution, &metadata),
        nat: forward_match.decision.nat.reverse(
            forward_match.key.src_ip,
            forward_match.key.dst_ip,
            forward_match.key.src_port,
            forward_match.key.dst_port,
        ),
        install_table_domain: 0,
        install_table_check: 0,
    };
    SessionLookup {
        decision,
        metadata,
        forwarding_generation: ForwardingGenerationStamp::default(),
    }
}

pub(in crate::afxdp) fn synthesized_synced_reverse_entry(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
entry: &SyncedSessionEntry,
now_secs: u64,) -> Option<SyncedSessionEntry> {
    let table_context = crate::afxdp::forwarding::native_route_table_for_flow_target(
        forwarding,
        entry.key.routing_domain,
        entry.metadata.ingress_ifindex as i32,
        entry.metadata.ingress_vlan_id,
        None,
        entry.key.src_ip,
    );
    let (table, install_table_domain, install_table_check, table_unresolvable) = match table_context
    {
        crate::afxdp::forwarding::NativeRouteTable::Default => (None, 0, 0, false),
        crate::afxdp::forwarding::NativeRouteTable::Table {
            table,
            domain,
            check,
        } => (Some(table), domain, check, false),
        crate::afxdp::forwarding::NativeRouteTable::Unresolvable { domain } => {
            (None, domain, 0, true)
        }
    };
    let mut reverse = synthesized_synced_reverse_entry_in_table(
        forwarding,
        ha_state,
        dynamic_neighbors,
        entry,
        now_secs,
        table.as_deref(),
    )?;
    if table_unresolvable {
        reverse.decision.resolution = crate::afxdp::forwarding::table_unavailable_resolution();
    }
    // `_in_table` stays zero-stamped; each caller stamps the identity of the
    // table it named: this untabled wrapper the native-RI identity, the
    // TUN-origin builders their tunnel instance's (#12503).
    reverse.decision.install_table_domain = install_table_domain;
    reverse.decision.install_table_check = install_table_check;
    Some(reverse)
}
/// Table-scoped twin of `synthesized_synced_reverse_entry` (#10038):
/// the reply-target resolution runs in `table`. `None` preserves
/// default-instance behavior while the untabled wrapper performs native-RI
/// derivation (#10312); explicit table-scoped callers include both the
/// TUN-origin builders and the native-RI wrapper.
pub(in crate::afxdp) fn synthesized_synced_reverse_entry_in_table(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
entry: &SyncedSessionEntry,
now_secs: u64,
table: Option<&str>,) -> Option<SyncedSessionEntry> {
    if entry.metadata.is_reverse {
        return None;
    }
    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = build_reverse_session_from_forward_match_in_table(
        forwarding,
        ha_state,
        dynamic_neighbors,
        ForwardSessionMatch {
            key: entry.key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
            forwarding_generation: ForwardingGenerationStamp::default(),
        },
        now_secs,
        0,
        table,
    );
    let metadata = reverse.metadata;
    Some(SyncedSessionEntry {
        key: reverse_key,
        decision: reverse.decision,
        metadata,
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: entry.protocol,
        tcp_flags: entry.tcp_flags,
        // #2170: the reverse companion inherits the forward entry's install
        // generation so a delete refusal is consistent across both halves.
        generation: entry.generation,
        session_id: 0,
        // #9412: the reverse half carries the SAME close class as the forward
        // import. With 0, every close-state Update (and the takeover prewarm)
        // re-installed the reverse copy on the established window, and
        // `companion_keeps_alive` then held the closing forward alive with it.
        tcp_close_class: entry.tcp_close_class,
        tcp_handshake_state: entry.tcp_handshake_state,
        source_nat_static: None,
    })
}

/// #10312: the reverse resolution plus the native installing-table identity
/// derived from the original forward ingress. PBR's installing table is
/// deliberately ignored here: a PBR term is directional, while the reply
/// target belongs to the forward ingress interface's native routing instance.
pub(in crate::afxdp) struct ReverseSessionResolution {
    pub(in crate::afxdp) resolution: ForwardingResolution,
    pub(in crate::afxdp) install_table: Option<String>,
    pub(in crate::afxdp) install_table_domain: u32,
    pub(in crate::afxdp) install_table_check: u32,
}

#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn reverse_resolution_for_flow(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
ingress_ifindex: i32,
ingress_vlan_id: u16,
ingress_zone: u16,
fabric_ingress: bool,
now_secs: u64,
allow_unseeded_tunnel_local: bool,) -> ReverseSessionResolution {
    let table_context = crate::afxdp::forwarding::native_route_table_for_flow_target(
        forwarding,
        flow.forward_key.routing_domain,
        ingress_ifindex,
        ingress_vlan_id,
        fabric_ingress.then_some(ingress_zone),
        flow.src_ip,
    );
    let (install_table, install_table_domain, install_table_check, table_unresolvable) =
        match table_context {
            crate::afxdp::forwarding::NativeRouteTable::Default => (None, 0, 0, false),
            crate::afxdp::forwarding::NativeRouteTable::Table {
                table,
                domain,
                check,
            } => (Some(table), domain, check, false),
            crate::afxdp::forwarding::NativeRouteTable::Unresolvable { domain } => {
                (None, domain, 0, true)
            }
        };
    let resolution = if table_unresolvable {
        crate::afxdp::forwarding::table_unavailable_resolution()
    } else {
        reverse_resolution_for_session_in_table(
            forwarding,
            ha_state,
            dynamic_neighbors,
            flow.src_ip,
            ingress_zone,
            fabric_ingress,
            now_secs,
            allow_unseeded_tunnel_local,
            install_table.as_deref(),
        )
    };
    ReverseSessionResolution {
        resolution,
        install_table,
        install_table_domain,
        install_table_check,
    }
}

pub(in crate::afxdp) fn reverse_resolution_for_session(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
target_ip: IpAddr,
ingress_zone: u16,
fabric_ingress: bool,
now_secs: u64,
allow_unseeded_tunnel_local: bool,) -> ForwardingResolution {
    reverse_resolution_for_session_in_table(
        forwarding,
        ha_state,
        dynamic_neighbors,
        target_ip,
        ingress_zone,
        fabric_ingress,
        now_secs,
        allow_unseeded_tunnel_local,
        None,
    )
}
/// #10312: the exact session-miss constructor used by the transit poll path.
/// Keeping the reverse resolution and the reverse decision's installing-table
/// stamp together prevents a caller from resolving in one VRF and storing a
/// zero-stamped decision that later falls back to MAIN.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn reverse_session_decision_for_flow(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
ingress_ifindex: i32,
ingress_vlan_id: u16,
ingress_zone: u16,
fabric_ingress: bool,
now_secs: u64,
allow_unseeded_tunnel_local: bool,
nat: NatDecision,) -> (ReverseSessionResolution, SessionDecision) {
    let context = reverse_resolution_for_flow(
        forwarding,
        ha_state,
        dynamic_neighbors,
        flow,
        ingress_ifindex,
        ingress_vlan_id,
        ingress_zone,
        fabric_ingress,
        now_secs,
        allow_unseeded_tunnel_local,
    );
    let decision = SessionDecision {
        resolution: context.resolution,
        nat: nat.reverse(
            flow.src_ip,
            flow.dst_ip,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
        ),
        install_table_domain: context.install_table_domain,
        install_table_check: context.install_table_check,
    };
    (context, decision)
}

/// Table-scoped twin of `reverse_resolution_for_session` (#10038 item 6):
/// the reply-target FIB lookup (and the table-scoped local-delivery
/// decision, #3769) runs in `table` instead of the default table, so a
/// VRF reverse resolves against its instance's connected/local view.
/// `None` preserves default-instance behavior. Besides the TUN-origin
/// builders, the native-RI reverse synthesis (#10312) passes `Some`;
/// remaining transit/HA VRF synthesis gaps are out of scope.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn reverse_resolution_for_session_in_table(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
target_ip: IpAddr,
ingress_zone: u16,
fabric_ingress: bool,
now_secs: u64,
allow_unseeded_tunnel_local: bool,
table: Option<&str>,) -> ForwardingResolution {
    let resolved = super::interface_nat_local_resolution(forwarding, target_ip, table)
        .unwrap_or_else(|| {
            super::forwarding::lookup_forwarding_resolution_in_table_with_dynamic(
                forwarding,
                dynamic_neighbors,
                target_ip,
                table,
            )
            .resolution
        });
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolved);
    if fabric_ingress
        && owner_rg_id > 0
        && !matches!(
            ha_state.get(&owner_rg_id),
            Some(group) if group.is_forwarding_active(now_secs)
        )
        && let Some(redirect) =
            super::forwarding::resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone)
    {
        return redirect;
    }
    let enforced = enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolved);
    if allow_unseeded_tunnel_local
        && enforced.disposition == ForwardingDisposition::HAInactive
        && owner_rg_is_unseeded(forwarding, ha_state, resolved)
    {
        return resolved;
    }
    enforced
}

pub(in crate::afxdp) fn install_reverse_session_from_forward_match(sessions: &mut SessionTable,
session_map: SteeringMap<'_>,
shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
worker_commands_by_id: &WorkerCommandQueues,
forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
reverse_key: &SessionKey,
forward_match: ForwardSessionMatch,
now_ns: u64,
now_secs: u64,
ha_startup_grace_until_secs: u64,
protocol: u8,
tcp_flags: u8,) -> (SessionLookup, bool) {
    let reverse = build_reverse_session_from_forward_match(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match,
        now_secs,
        ha_startup_grace_until_secs,
    );
    let reverse_leak_incarnation = crate::afxdp::session_glue::leak_incarnation_for_session(
        forwarding,
        reverse.decision,
        reverse_key.dst_ip,
    )
    .unwrap_or(0);
    // #1861 §5.4: the synthesized decision is returned EVEN when the
    // install fails (max_sessions) so the reply keeps forwarding — but
    // the caller must know the outcome: `created` telemetry and the
    // flow-cache eligibility gate both key off it. Caching a decision
    // with no backing session would suppress this repair until cache
    // invalidation (Codex #1861 r1 C1).
    let installed = sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        reverse.decision,
        reverse.metadata.clone(),
        SessionOrigin::ReverseFlow,
        now_ns,
        protocol,
        tcp_flags,
    );
    if installed {
        if reverse_leak_incarnation != 0 {
            sessions.stamp_leak_incarnation(reverse_key, reverse_leak_incarnation);
        }
        // #1789: count failed reverse-install publishes (was `let _ =`).
        // No binding context in this shared-ops path — shared counter.
        if publish_live_session_entry(session_map, reverse_key, reverse.decision.nat, true).is_err()
        {
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
        let reverse_entry = SyncedSessionEntry {
            key: reverse_key.clone(),
            decision: reverse.decision,
            metadata: reverse.metadata.clone(),
            leak_incarnation: reverse_leak_incarnation,
            origin: SessionOrigin::ReverseFlow,
            protocol,
            tcp_flags,
            // Local reverse-flow learning: no peer install generation (#2170).
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
            tcp_handshake_state: sessions.handshake_state_wire_for(reverse_key),
            source_nat_static: None,
        };
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &reverse_entry,
        );
        replicate_session_upsert(peer_worker_commands, worker_commands_by_id, &reverse_entry);
    }
    (reverse, installed)
}

