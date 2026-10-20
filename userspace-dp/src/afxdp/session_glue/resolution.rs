use super::*;

pub(in crate::afxdp) fn resolution_target_for_session(flow: &SessionFlow,
decision: SessionDecision,) -> IpAddr {
    decision.nat.rewrite_dst.unwrap_or(flow.dst_ip)
}

/// Resolve the policy discriminator used by a helper policy-list read.
///
/// `prepublish` requests target IDs from the currently published policy
/// snapshot. A session's stored `policy_id` is its admission-time positional
/// value, so bound rows resolve through their stable rule handle. Unbound
/// peer-synced and SharedPromote rows are excluded from prepublish ID matching
/// because their scalar may be stale; locally authored unbound rows retain
/// scalar behavior. Legacy reads retain their timestamp-fenced scalar behavior.
pub(crate) fn policy_id_for_list_request(
    forwarding: &ForwardingState,
    metadata: &crate::session::SessionMetadata,
    origin: crate::session::SessionOrigin,
    mode: &str,
) -> Option<u32> {
    if mode != "prepublish" {
        return Some(metadata.policy_id);
    }
    let Some(counter) = metadata.policy_counter.as_ref() else {
        return (!(origin.is_peer_synced() || origin == crate::session::SessionOrigin::SharedPromote))
            .then_some(metadata.policy_id);
    };
    if counter.rule_id().is_empty() {
        return (!(origin.is_peer_synced() || origin == crate::session::SessionOrigin::SharedPromote))
            .then_some(metadata.policy_id);
    }
    Some(
        forwarding
            .policy
            .reresolve_session_policy_id(Some(counter), metadata.policy_id),
    )
}

/// #9752: the table-independent local outcome for an unresolvable installing
/// table is the any-table NAT wildcard (mirroring `fib.rs:274-284` with
/// ifindex 0 — no connected scan is possible without a table). Interface-NAT
/// addresses are table-owned (#12086), so they cannot be admitted here without
/// knowing which routing table owns the packet.
///
/// Deliberately NOT bumping `LOCAL_DELIVERY_IFINDEX0`, which counts
/// table-OWNED-no-ifindex, a different cause (asserted in cell 10).
pub(in crate::afxdp) fn local_resolution_without_install_table(
    forwarding: &ForwardingState,
    target: IpAddr,
) -> Option<ForwardingResolution> {
    let wildcard_owned = match target {
        IpAddr::V4(ip) => {
            forwarding.local_v4.contains(&ip) && forwarding.local_nat_any_table_v4.contains(&ip)
        }
        IpAddr::V6(ip) => {
            forwarding.local_v6.contains(&ip) && forwarding.local_nat_any_table_v6.contains(&ip)
        }
    };
    wildcard_owned.then(|| ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    })
}

/// #9752: per-worker purge-request flags, set when a re-resolve observes a
/// terminal installing-table outcome. Atomic (not plain bool) deliberately:
/// the observation sites span four functions across two files and share only
/// `worker_id`, so threading a `&mut bool` would churn every signature for a
/// cold-path single store; one relaxed store per terminal outcome plus one
/// load per loop pass. Same shape and ceiling as
/// `SESSION_DELETE_DROP_EPOCH` below.
pub(crate) static INSTALL_TABLE_PURGE_NEEDED: [std::sync::atomic::AtomicBool;
    crate::nat::MAX_NAT_HOLDER_WORKERS as usize] = [const { std::sync::atomic::AtomicBool::new(false) };
    crate::nat::MAX_NAT_HOLDER_WORKERS as usize];

pub(in crate::afxdp) fn flag_install_table_purge(worker_id: u32) {
    if let Some(slot) = INSTALL_TABLE_PURGE_NEEDED.get(worker_id as usize) {
        slot.store(true, Ordering::Relaxed);
    }
}

pub(in crate::afxdp) fn take_install_table_purge_flag(worker_id: u32) -> bool {
    INSTALL_TABLE_PURGE_NEEDED
        .get(worker_id as usize)
        .map(|slot| slot.swap(false, Ordering::Relaxed))
        .unwrap_or(false)
}

/// #9752: a session's installing table, resolved and validated. The ONE
/// classifier shared by D4 re-resolve and every `prefer_local` / validation
/// call site (plus the D8 purge predicate, which mirrors it): `Default`
/// (unstamped — existing behavior), `Table` (validated, borrow the string),
/// or `Unresolvable` (unknown domain, owner mismatch, or absent family —
/// table-independent locals or terminal, never a wrong-table lookup).
/// Callers map `Default`/`Unresolvable` to a `None` table argument; for
/// `Unresolvable` that argument is unreached (the input resolution is
/// always `LocalDelivery` or terminal there, both early-returned — proven
/// in plan v4.1 §5 D4 and pinned by cell 10).
pub(in crate::afxdp) enum InstallTable <'a> {
    Default,
    Table(&'a str),
    Unresolvable,
}

pub(in crate::afxdp) fn resolve_install_table_for_session(forwarding: &ForwardingState,
decision: SessionDecision,
target: IpAddr,) -> InstallTable<'_> {
    if decision.install_table_domain == 0 {
        return InstallTable::Default;
    }
    let present = forwarding
        .install_tables
        .get(&decision.install_table_domain)
        .filter(|row| row.h2 == decision.install_table_check)
        .and_then(|row| match target {
            IpAddr::V4(_) => row.v4.as_deref(),
            IpAddr::V6(_) => row.v6.as_deref(),
        });
    match present {
        Some(table) => InstallTable::Table(table),
        None => InstallTable::Unresolvable,
    }
}

pub(in crate::afxdp) fn cached_session_resolution(forwarding: &ForwardingState,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
cached: ForwardingResolution,) -> Option<ForwardingResolution> {
    if cached.disposition != ForwardingDisposition::ForwardCandidate {
        return None;
    }
    if cached.egress_ifindex <= 0 || cached.neighbor_mac.is_none() {
        return None;
    }
    // #11315: recheck the live neighbor binding before serving a stored
    // session resolution. The decision caches neighbor_mac at install; a
    // gateway failover can replace it, and FAILED/INCOMPLETE can remove it.
    // Either a contradictory or missing live binding makes the cached MAC
    // stale. The subsequent first learn after removal does not advance the
    // #3048 shard epoch, so accepting the cached MAC while absent could leave
    // it in the flow cache through recovery.
    if let (Some(next_hop), Some(stored_mac)) = (cached.next_hop, cached.neighbor_mac) {
        let ifindex = super::outer_neighbor_ifindex(forwarding, Some(dynamic_neighbors), &cached);
        let Some(live) =
            super::lookup_neighbor_entry(forwarding, Some(dynamic_neighbors), ifindex, next_hop)
        else {
            return None;
        };
        if live.mac != stored_mac {
            return None;
        }
    }
    let mut fallback = cached;
    fallback.disposition = ForwardingDisposition::ForwardCandidate;
    if fallback.tx_ifindex <= 0 {
        fallback.tx_ifindex = resolve_tx_binding_ifindex(forwarding, fallback.egress_ifindex);
    }
    if let Some(egress) = forwarding.egress.get(&fallback.egress_ifindex) {
        if fallback.src_mac.is_none() {
            fallback.src_mac = Some(egress.src_mac);
        }
        if fallback.tx_vlan_id == 0 {
            fallback.tx_vlan_id = forwarding.egress_tx_vlan_id(fallback.egress_ifindex);
        }
    }
    Some(fallback)
}

pub(in crate::afxdp) fn populate_egress_resolution(state: &ForwardingState,
egress_ifindex: i32,
resolution: &mut ForwardingResolution,) {
    if egress_ifindex <= 0 {
        return;
    }
    if let Some(egress) = state.egress.get(&egress_ifindex) {
        resolution.tx_ifindex = if egress.bind_ifindex > 0 {
            egress.bind_ifindex
        } else {
            egress_ifindex
        };
        resolution.src_mac = Some(egress.src_mac);
        resolution.tx_vlan_id = state.egress_tx_vlan_id(egress_ifindex);
    } else if resolution.tx_ifindex <= 0 {
        resolution.tx_ifindex = egress_ifindex;
    }
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_for_session(forwarding: &ForwardingState,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
decision: SessionDecision,) -> ForwardingLookupResult {
    lookup_forwarding_resolution_for_session_with_cache(
        forwarding,
        dynamic_neighbors,
        flow,
        decision,
        true,
        true,
    )
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_for_session_without_cache(forwarding: &ForwardingState,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
decision: SessionDecision,) -> ForwardingLookupResult {
    lookup_forwarding_resolution_for_session_with_cache(
        forwarding,
        dynamic_neighbors,
        flow,
        decision,
        false,
        false,
    )
}
/// #9752: the `prefer_local` / validation table argument for a session: the
/// validated installing table, or `None` for default (correct) and for
/// unresolvable (unreached — the input there is always `LocalDelivery` or
/// terminal, both early-returned; see `resolve_install_table_for_session`).
pub(in crate::afxdp) fn install_table_name_for_session(forwarding: &ForwardingState,
decision: SessionDecision,
target: IpAddr,) -> Option<&str> {
    match resolve_install_table_for_session(forwarding, decision, target) {
        InstallTable::Table(table) => Some(table),
        InstallTable::Default | InstallTable::Unresolvable => None,
    }
}

/// #9951/#10312: derive leak provenance from the validated installing-table
/// identity. `Unresolvable` is deliberately distinct from `Default`: it must
/// not use `None`, because that would inspect MAIN and could stamp an
/// unrelated leak after the native RI identity was invalidated.
pub(in crate::afxdp) fn leak_incarnation_for_session(forwarding: &ForwardingState,
decision: SessionDecision,
target: IpAddr,) -> Option<u64> {
    let source_table = match resolve_install_table_for_session(forwarding, decision, target) {
        InstallTable::Default => None,
        InstallTable::Table(table) => Some(table),
        InstallTable::Unresolvable => return None,
    };
    super::forwarding::leak_incarnation_for_resolution(forwarding, target, source_table)
}

pub(super) fn lookup_forwarding_resolution_for_session_with_cache(forwarding: &ForwardingState,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
decision: SessionDecision,
allow_cached_fast_path: bool,
allow_cached_fallback: bool,) -> ForwardingLookupResult { // #9752: validate a stamped installing table BEFORE any stored-resolution
// shortcut (Codex-r2-F2/F5: cached reuse, the lookup fallback, and the
// tunnel/local arms must not serve a session whose table is gone).
// Zero-stamped sessions skip validation entirely (existing behavior
// below, bit-exact — including the LocalDelivery-before-tunnel order
// that LocalDelivery+tunnel-ID outcomes depend on (Codex-r3-F2a)).
// Family presence is read off the POST-NAT target (cell 14: a NAT64
// v6→v4 rewrite uses the v4 table).
let table: Option<&str> = match resolve_install_table_for_session(
    forwarding,
    decision,
    resolution_target_for_session(flow, decision),
) {
    InstallTable::Default => None,
    InstallTable::Table(table) => Some(table),
    // Unknown domain, owner change, or absent family: serve a
    // table-independent local outcome if one exists, else terminal.
    // No cached reuse, no FIB lookup, no fallback.
    InstallTable::Unresolvable => {
        let target = resolution_target_for_session(flow, decision);
        let resolution = if let Some(local) =
            local_resolution_without_install_table(forwarding, target)
        {
            local
        } else {
            super::table_unavailable_resolution()
        };
        return ForwardingLookupResult {
            resolution,
            selected_route: None,
        };
    }
};
if allow_cached_fast_path
    && decision.resolution.disposition == ForwardingDisposition::LocalDelivery
{
    return ForwardingLookupResult {
        resolution: decision.resolution,
        selected_route: None,
    };
}
if decision.resolution.tunnel_endpoint_id != 0 {
    // #1873 (Codex code r2): the session's stored tunnel resolution
    // carries the owning netdev's kernel ifindex (egress_ifindex =
    // endpoint.logical_ifindex at resolve time). If the id has
    // since been re-owned by a DIFFERENT netdev (temporal hash
    // reuse: remove tunnel A, add tunnel B whose name folds to the
    // same id), the stale session must NEVER adopt the new owner —
    // no matter which forwarding state this worker held when the
    // session was created. Kernel ifindexes are not reused within
    // a boot, so inequality is authoritative. Tunnel-marked NoRoute
    // funnels the frame into the R-C gate (drop + count), never the
    // slow path and never B's encap.
    if decision.resolution.egress_ifindex > 0 {
        if let Some(row) = forwarding
            .tunnel_endpoints
            .get(&decision.resolution.tunnel_endpoint_id)
        {
            if row.logical_ifindex != decision.resolution.egress_ifindex {
                // PRESERVE the stale egress_ifindex: several paths
                // write the re-resolved value back into the stored
                // entry (maybe_promote_synced_session, UpsertSynced)
                // — zeroing it would erase the discriminator and let
                // the NEXT packet adopt the new owner. With it
                // preserved the entry stays gated until purged/GC'd.
                let mut gated = super::no_route_resolution(None);
                gated.tunnel_endpoint_id = decision.resolution.tunnel_endpoint_id;
                gated.egress_ifindex = decision.resolution.egress_ifindex;
                return ForwardingLookupResult {
                    resolution: gated,
                    selected_route: None,
                };
        }
    }
    }
    let mut resolved = super::resolve_tunnel_forwarding_resolution(
        forwarding,
        Some(dynamic_neighbors),
        decision.resolution.tunnel_endpoint_id,
        0,
    );
    resolved.route_mtu = decision.resolution.route_mtu;
    let resolution = match resolved.disposition {
        ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor
            if allow_cached_fallback =>
        {
            cached_session_resolution(forwarding, dynamic_neighbors, decision.resolution)
                .unwrap_or(resolved)
        }
        _ => resolved,
    };
    return ForwardingLookupResult {
        resolution,
        selected_route: None,
    };
}
if allow_cached_fast_path {
    if let Some(cached) =
        cached_session_resolution(forwarding, dynamic_neighbors, decision.resolution)
    {
        return ForwardingLookupResult {
            resolution: cached,
            selected_route: None,
        };
    }
}
let target = resolution_target_for_session(flow, decision);
if let Some(local) = super::interface_nat_local_resolution(forwarding, target, table) {
    return ForwardingLookupResult {
        resolution: local,
        selected_route: None,
    };
}
// #2734: spread ECMP equal-cost members by the per-FLOW 5-tuple hash
// (the session forward key) so distinct flows to the same destination
// take different paths, while every packet of one flow stays pinned to
// one member (the resolution is cached on the session entry, and the
// hash is deterministic within a boot).
let resolved = match table {
    // #9752: re-resolve in the installing table (per-flow ECMP spread
    // preserved — the table must not disturb it).
    Some(table) => super::lookup_forwarding_resolution_with_dynamic_for_flow_in_table(
        forwarding,
        dynamic_neighbors,
        target,
        &flow.forward_key,
        table,
    ),
    None => lookup_forwarding_resolution_with_dynamic_for_flow(
        forwarding,
        dynamic_neighbors,
        target,
        &flow.forward_key,
    ),
};
match resolved.resolution.disposition {
    ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor
        if allow_cached_fallback =>
    {
        match cached_session_resolution(
            forwarding,
            dynamic_neighbors,
            decision.resolution,
        ) {
            Some(resolution) => ForwardingLookupResult {
                resolution,
                selected_route: None,
            },
            None => resolved,
        }
    }
    _ => resolved,
} }

pub(super) fn lookup_forwarding_resolution_for_synced_session(forwarding: &ForwardingState,
dynamic_neighbors: &Arc<ShardedNeighborMap>,
flow: &SessionFlow,
decision: SessionDecision,) -> ForwardingLookupResult { lookup_forwarding_resolution_for_session_with_cache(
    forwarding,
    dynamic_neighbors,
    flow,
    decision,
    false,
    true,
) }

pub(in crate::afxdp) fn owner_rg_is_locally_active(ha_state: &BTreeMap<i32, HAGroupRuntime>,
owner_rg_id: i32,
now_secs: u64,) -> bool {
    owner_rg_id > 0
        && matches!(ha_state.get(&owner_rg_id), Some(group) if group.is_forwarding_active(now_secs))
}

pub(in crate::afxdp) fn synced_entry_allows_local_replace(ha_state: &BTreeMap<i32, HAGroupRuntime>,
owner_rg_id: i32,
now_secs: u64,) -> bool {
    if owner_rg_is_locally_active(ha_state, owner_rg_id, now_secs) {
        return false;
    }
    if owner_rg_id == 0
        && ha_state
            .values()
            .any(|group| group.is_forwarding_active(now_secs))
    {
        return false;
    }
    true
}

/// #15958b: the RG that owns `target` as a connected destination:
/// the redundancy group of the interface whose connected prefix
/// contains the address (per-address ownership, not per-zone —
/// a co-zoned interface owned by a different RG must not decide).
/// `connected_*_by_ifindex` is populated for every interface
/// regardless of HA suppression, so a peer-owned connected prefix
/// still names its owner here. 0 when no connected prefix matches.
pub(in crate::afxdp) fn connected_owner_rg_for_target(
    forwarding: &ForwardingState,
    target: IpAddr,
) -> i32 {
    // Source 1: connected_* rows (the FIB's own connected route
    // structs: prefix + ifindex) — longest prefix wins.
    let mut best: Option<(u8, i32)> = None;
    match target {
        IpAddr::V4(ip) => {
            for row in &forwarding.connected_v4 {
                if row.prefix.contains(ip) {
                    let len = row.prefix.prefix_len();
                    if best.is_none_or(|(best_len, _)| len >= best_len) {
                        best = Some((len, owner_rg_for_flow(forwarding, row.ifindex)));
                    }
                }
            }
            if best.is_none() {
                for (ifindex, prefixes) in &forwarding.connected_v4_by_ifindex {
                    for prefix in prefixes {
                        if prefix.contains(ip) {
                            let len = prefix.prefix_len();
                            if best.is_none_or(|(best_len, _)| len >= best_len) {
                                best = Some((len, owner_rg_for_flow(forwarding, *ifindex)));
                            }
                        }
                    }
                }
            }
        }
        IpAddr::V6(ip) => {
            for row in &forwarding.connected_v6 {
                if row.prefix.contains(ip) {
                    let len = row.prefix.prefix_len();
                    if best.is_none_or(|(best_len, _)| len >= best_len) {
                        best = Some((len, owner_rg_for_flow(forwarding, row.ifindex)));
                    }
                }
            }
            if best.is_none() {
                for (ifindex, prefixes) in &forwarding.connected_v6_by_ifindex {
                    for prefix in prefixes {
                        if prefix.contains(ip) {
                            let len = prefix.prefix_len();
                            if best.is_none_or(|(best_len, _)| len >= best_len) {
                                best = Some((len, owner_rg_for_flow(forwarding, *ifindex)));
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some((_, rg)) = best {
        return rg;
    }
    // Source 2: the interface-NAT local table (an interface address
    // IS its own connected /32) and the local-address sets: the
    // target is this node's own interface address; its owner is that
    // interface's RG.
    match target {
        IpAddr::V4(ip) => {
            if let Some(by_table) = forwarding.interface_nat_v4.get(&ip) {
                for ifindex in by_table.values() {
                    let rg = owner_rg_for_flow(forwarding, *ifindex);
                    if rg > 0 {
                        return rg;
                    }
                }
            }
            if forwarding.local_v4.contains(&ip) {
                // Owning interface unknown from the set alone; fall
                // through to unknown (0) rather than guessing an RG.
                return 0;
            }
        }
        IpAddr::V6(ip) => {
            if let Some(by_table) = forwarding.interface_nat_v6.get(&ip) {
                for ifindex in by_table.values() {
                    let rg = owner_rg_for_flow(forwarding, *ifindex);
                    if rg > 0 {
                        return rg;
                    }
                }
            }
        }
    }
    0
}

/// #15958b: shared zone-egress redirect rule for a fabric-ingress
/// reverse row. When re-resolution yields a ForwardCandidate that
/// egresses in a zone other than the companion's destination
/// (egress) zone, the route does not reach the destination owner —
/// on the punt origin the connected LAN prefix is HA-suppressed, so
/// the FIB answers the LAN target with the WAN gateway route (owner
/// = locally-active WAN RG) and HA enforcement keeps it. The reply
/// must instead cross the fabric to the destination owner.
///
/// Conditions:
/// * `fabric_link_ingress` — the packet arrives ON the fabric link:
///   anti-loop refusal, mirroring every other redirect site.
/// * The DESTINATION ADDRESS's owning RG (per-address connected
///   ownership, `connected_owner_rg_for_target`) must be peer-owned:
///   known (> 0) and NOT forwarding-active. A co-zoned interface
///   owned by a different, active RG does not suppress the redirect,
///   and an unzoned/`egress_zone_id == 0` candidate alone is not
///   proof of peer ownership. Callers pass
///   `destination_owner_active` computed from that per-address RG.
///
/// Composition: callers run `redirect_session_via_fabric_if_needed`
/// FIRST for the HAInactive family; this helper only converts a
/// surviving ForwardCandidate. Stored-FabricRedirect retention,
/// failback re-homing and current-peer retargeting live in
/// `rehome_or_retain_fabric_redirect_15958b`.
pub(in crate::afxdp) fn fabric_redirect_for_zone_egress_15958b(
    forwarding: &ForwardingState,
    candidate: ForwardingResolution,
    destination_zone: u16,
    fabric_link_ingress: bool,
    destination_owner_active: bool,
) -> ForwardingResolution {
    if fabric_link_ingress || destination_owner_active {
        return candidate;
    }
    if candidate.disposition != ForwardingDisposition::ForwardCandidate {
        return candidate;
    }
    // GLM2: the destination zone must be KNOWN from a source other
    // than this helper's own egress_zone_id read (the candidate's
    // egress row): a destination zone with no interface/connected
    // row is UNKNOWN, and absence of evidence is not peer-ownership
    // — keep the candidate rather than hijack a locally-owned
    // in-zone reverse to FabricRedirect. Known = some egress row
    // carries the zone, or some connected prefix is served from it.
    let destination_zone_known = forwarding.egress.iter().any(|(ifindex, _)| {
        forwarding.egress_zone_id(*ifindex) == destination_zone
    }) || forwarding
        .connected_v4_by_ifindex
        .keys()
        .chain(forwarding.connected_v6_by_ifindex.keys())
        .any(|ifindex| forwarding.egress_zone_id(*ifindex) == destination_zone);
    if !destination_zone_known {
        return candidate;
    }
    if forwarding.egress_zone_id(candidate.egress_ifindex) == destination_zone {
        return candidate;
    }
    super::forwarding::resolve_zone_encoded_fabric_redirect_by_id(forwarding, destination_zone)
        .unwrap_or(candidate)
}

/// #15958b round-3: re-home-or-retain decision for a stored
/// FabricRedirect companion, applied per packet (hit) and per HA
/// transition (refresh/demote), AFTER the HAInactive composition.
///
/// Order (item 1): if the destination address's RG is locally
/// forwarding-active NOW, the candidate wins — the companion
/// re-homes to local forwarding and the retained marker must not
/// defeat failback. This check runs before retention, per packet.
///
/// Otherwise (item 2): the redirect is re-resolved against the
/// CURRENT fabric list, so a replaced peer (new parent/MAC) is the
/// target — never the stored stale parent binding. If no redirect
/// is resolvable (peer identity unresolved/down), return a
/// FabricRedirect marker with zeroed egress/tx: the dispatcher
/// finds no sendable fabric binding and counts
/// `fabric_redirect_unsendable_drops` (fail closed) instead of
/// transmitting to a stale parent or laundering to WAN egress.
pub(in crate::afxdp) fn rehome_or_retain_fabric_redirect_15958b(
    forwarding: &ForwardingState,
    stored: ForwardingResolution,
    candidate: ForwardingResolution,
    destination_zone: u16,
    destination_owner_active: bool,
) -> ForwardingResolution {
    if candidate.disposition == ForwardingDisposition::FabricRedirect {
        return candidate;
    }
    if destination_owner_active {
        return candidate;
    }
    if candidate.disposition != ForwardingDisposition::ForwardCandidate {
        return candidate;
    }
    let destination_zone_known = forwarding.egress.iter().any(|(ifindex, _)| {
        forwarding.egress_zone_id(*ifindex) == destination_zone
    }) || forwarding
        .connected_v4_by_ifindex
        .keys()
        .chain(forwarding.connected_v6_by_ifindex.keys())
        .any(|ifindex| forwarding.egress_zone_id(*ifindex) == destination_zone);
    if !destination_zone_known {
        return candidate;
    }
    match super::forwarding::resolve_zone_encoded_fabric_redirect_by_id(
        forwarding,
        destination_zone,
    ) {
        Some(current_redirect) => current_redirect,
        None => ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            egress_ifindex: 0,
            tx_ifindex: 0,
            neighbor_mac: None,
            src_mac: None,
            next_hop: None,
            ..stored
        },
    }
}

pub(in crate::afxdp) fn redirect_session_resolution_for_metadata(forwarding: &ForwardingState,
resolution: ForwardingResolution,
metadata: &SessionMetadata,) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive || metadata.fabric_ingress {
        return resolution;
    }
    resolve_fabric_redirect_for_ingress_zone(forwarding, Some(metadata.ingress_zone))
        .unwrap_or(resolution)
}

pub(in crate::afxdp) fn owner_rg_is_unseeded(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
resolution: ForwardingResolution,) -> bool {
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
    owner_rg_id > 0
        && matches!(
            ha_state.get(&owner_rg_id),
            None | Some(HAGroupRuntime {
                active: false,
                watchdog_timestamp: 0,
                ..
            })
        )
}

pub(super) fn should_bypass_unseeded_tunnel_ha(forwarding: &ForwardingState,
ha_state: &BTreeMap<i32, HAGroupRuntime>,
now_secs: u64,
resolution: ForwardingResolution,
ingress_ifindex: i32,
ha_startup_grace_until_secs: u64,) -> bool { resolution.disposition == ForwardingDisposition::ForwardCandidate
    && now_secs <= ha_startup_grace_until_secs
    && forwarding
        .tunnel_endpoint_by_ifindex
        .contains_key(&ingress_ifindex)
    && owner_rg_is_unseeded(forwarding, ha_state, resolution) }

