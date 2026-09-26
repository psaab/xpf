//! #5650: core FIB forwarding resolution — packet-destination parse, table /
//! next-table walk, per-family (v4/v6) route resolution, ECMP hashing and
//! next-hop selection, and the no-route/connected/static route choice. This is
//! the per-packet FIB-resolution hot path; the split is pure code-motion out of
//! `forwarding/mod.rs`, preserving instruction-level behavior and `#[inline]`
//! attributes exactly.

use std::borrow::Cow;

use super::*;

pub(in crate::afxdp) fn is_connected_v4_directed_broadcast(
    state: &ForwardingState,
    ifindex: i32,
    destination: IpAddr,
) -> bool {
    match destination {
        IpAddr::V4(ip) => state
            .connected_v4_directed_broadcast_neighbor_keys
            .contains(&(ifindex, ip)),
        IpAddr::V6(_) => false,
    }
}

pub(in crate::afxdp) const DEFAULT_V4_TABLE: &str = "inet.0";

pub(in crate::afxdp) const DEFAULT_V6_TABLE: &str = "inet6.0";

const MAX_NEXT_TABLE_DEPTH: usize = 8;

pub(in crate::afxdp) fn classify_metadata(
    meta: UserspaceDpMeta,
    validation: ValidationState,
) -> PacketDisposition {
    if !validation.snapshot_installed {
        return PacketDisposition::NoSnapshot;
    }
    if meta.config_generation != validation.config_generation {
        return PacketDisposition::ConfigGenerationMismatch;
    }
    if meta.fib_generation != validation.fib_generation {
        return PacketDisposition::FibGenerationMismatch;
    }
    match meta.addr_family as i32 {
        libc::AF_INET | libc::AF_INET6 => PacketDisposition::Valid,
        _ => PacketDisposition::UnsupportedPacket,
    }
}

/// #4674: returns `Cow<'static, str>` rather than an owned `String`. The
/// common cases — the default-table remaps (`inet.0`↔`inet6.0`) — borrow the
/// `'static` `DEFAULT_V4_TABLE`/`DEFAULT_V6_TABLE` constants and never
/// allocate. Only the rare per-VRF suffix rewrite (`<inst>.inet.0`↔
/// `<inst>.inet6.0`) or a non-canonical passthrough owns a heap string. This
/// removes the per-new-flow FIB-resolution alloc that `.to_string()` forced at
/// every lookup-path caller (see `lookup_forwarding_resolution_inner_ecmp`,
/// which now defaults to `Cow::Borrowed(DEFAULT_V*_TABLE)`).
/// #7204 (A1-b7-F5): borrows the caller's name when no rewrite is needed.
///
/// The return type used to be `Cow<'static, str>`, and that `'static` — not the
/// rewriting — is what made this allocate on the hot path. Four of the six arms
/// allocated, but two of them are IDENTITY arms: they hand back exactly the name
/// they were given, and copied it only because a borrow could not outlive the
/// call under `'static`. Tying the output lifetime to the input turns those two
/// into `Cow::Borrowed` and leaves an allocation only where a family rewrite
/// genuinely produces a NEW string.
///
/// That identity arm is the common case, not the rare one: a lookup for family F
/// against a table already in family F (`vrf-a.inet.0` asked for v4) matches
/// neither the default-table arm nor the opposite-family suffix, so every
/// same-family resolution was paying a `to_string` to get its own argument back.
///
/// Interning into a `TableId` — the fix #7204 proposes — would also remove the
/// allocation, at the cost of a new id type threaded through PBR and next-table
/// recursion plus a snapshot-build interning pass. It is not needed to make the
/// identity arm free, and the callers do not need an owned value at all: every
/// hot-path use is a comparison, a `visited` membership test, or a map lookup,
/// all of which take `&str`.
pub(in crate::afxdp) fn canonical_route_table(table: &str, is_ipv6: bool) -> Cow<'_, str> {
    if is_ipv6 {
        if table == DEFAULT_V4_TABLE {
            return Cow::Borrowed(DEFAULT_V6_TABLE);
        }
        if let Some(prefix) = table.strip_suffix(".inet.0") {
            return Cow::Owned(format!("{prefix}.inet6.0"));
        }
        return Cow::Borrowed(table);
    }
    if table == DEFAULT_V6_TABLE {
        return Cow::Borrowed(DEFAULT_V4_TABLE);
    }
    if let Some(prefix) = table.strip_suffix(".inet6.0") {
        return Cow::Owned(format!("{prefix}.inet.0"));
    }
    Cow::Borrowed(table)
}
/// #9955: synthetic leak snapshots from config statics may carry a bare
/// routing-instance name (the Go config builder preserves that existing
/// representation), while `routes_v[46]` is keyed by family-qualified table
/// names. Canonicalize those targets once during FIB construction; live
/// ip-rule snapshots already carry the qualified spelling.
pub(in crate::afxdp) fn canonical_next_table(table: &str, is_ipv6: bool) -> Cow<'_, str> {
    if table == DEFAULT_V4_TABLE || table == DEFAULT_V6_TABLE || table.ends_with(".inet.0") || table.ends_with(".inet6.0") {
        return canonical_route_table(table, is_ipv6);
    }
    if table.is_empty() {
        return Cow::Borrowed(table);
    }
    Cow::Owned(format!(
        "{table}.{}",
        if is_ipv6 { "inet6.0" } else { "inet.0" }
    ))
}
/// #10653: the routing-instance name a canonical transport-table name
/// belongs to — the endpoint side of the GRE decap transport-domain
/// match.
///
/// `TunnelEndpoint.transport_table` is canonicalized at build
/// (`canonical_route_table` in `forwarding_build/tunnels.rs`), so it is
/// one of: a default table (`inet.0`/`inet6.0`), a per-instance table
/// (`<instance>.inet.0`/`<instance>.inet6.0`), empty (unset — the
/// pre-VRF / default shape), or a bare instance name passed through
/// untouched. The default spellings and empty map to `""` (the default
/// VRF — the same `""` `ifindex_to_routing_instance` yields for an
/// interface in no instance); a qualified table maps to its instance by
/// stripping the family suffix; anything else is returned as-is, which
/// keeps a bare instance name comparing correctly.
///
/// The suffix strip anchors at the END (`strip_suffix`), so a dotted
/// instance containing ".inet" (`a.inet.b` -> `a.inet.b.inet.0`) keeps
/// its full name — the same LastIndex semantics Go's
/// `parseNextTableInstance` uses (#5632).
///
/// Why a NAME and not the numeric domain: the numeric routing domain
/// (`SessionKey.routing_domain`, `ifindex_to_routing_domain`) is
/// `StableRoutingInstanceTableID`, a Go-computed hash OF this name.
/// Rust treats it as opaque and never recomputes it; comparing the
/// names compares the same identity losslessly (finer than the hash —
/// a collision the commit gate missed would alias numerically but not
/// here).
pub(in crate::afxdp) fn transport_instance_of_table(table: &str) -> &str {
    if table.is_empty() || table == DEFAULT_V4_TABLE || table == DEFAULT_V6_TABLE {
        return "";
    }
    table
        .strip_suffix(".inet.0")
        .or_else(|| table.strip_suffix(".inet6.0"))
        .unwrap_or(table)
}

pub(in crate::afxdp) fn parse_packet_destination(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    // #9900 F-095: nibble-gate the stamp, but keep it as the fallback: this is
    // a read-only dst parse, so double-garbage (bad stamp AND unparseable
    // ethertype) keeps the old stamp-indexed behavior (usually `None` via the
    // length guards below) instead of growing a new NoRoute cliff.
    let l3 = crate::afxdp::frame::verified_l3_or_stamp(frame, meta.l3_offset, meta.addr_family);
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            )))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            )))
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn resolve_forwarding(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> ForwardingResolution {
    let Some(dst) = parse_packet_destination(area, desc, meta) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    };
    lookup_forwarding_resolution_with_dynamic(state, dynamic_neighbors, dst)
}

#[cfg(test)]
pub(in crate::afxdp) fn lookup_forwarding_for_ip(
    state: &ForwardingState,
    dst: IpAddr,
) -> ForwardingDisposition {
    lookup_forwarding_resolution(state, dst).disposition
}

pub(in crate::afxdp) fn lookup_forwarding_resolution(
    state: &ForwardingState,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, None, dst, None)
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, None)
}

/// #2734: like `lookup_forwarding_resolution_with_dynamic`, but selects an
/// equal-cost next-hop by the per-FLOW 5-tuple hash (from the session
/// forward key) so distinct flows to the same destination spread across
/// ECMP members. Used by the session forwarding-resolution path.
pub(in crate::afxdp) fn lookup_forwarding_resolution_with_dynamic_for_flow(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
    flow_key: &crate::session::SessionKey,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner_ecmp(
        state,
        Some(dynamic_neighbors),
        dst,
        None,
        Some(ecmp_hash_flow(flow_key)),
    )
}

/// #9752: like `lookup_forwarding_resolution_with_dynamic_for_flow`, but in
/// an explicit route table: the session re-resolve path. The per-flow ECMP
/// hash (`#2734`) is preserved — the installing table must not disturb
/// flow spread.
pub(in crate::afxdp) fn lookup_forwarding_resolution_with_dynamic_for_flow_in_table(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
    flow_key: &crate::session::SessionKey,
    table: &str,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner_ecmp(
        state,
        Some(dynamic_neighbors),
        dst,
        Some(table),
        Some(ecmp_hash_flow(flow_key)),
    )
}

/// #9951: identify the exact inter-VRF leak selected by the immutable FIB
/// walk. This deliberately does not re-run neighbor/ECMP/HA resolution:
/// those mutable inputs can change between the session lookup and provenance
/// stamping, which must never turn a valid leak match into an unstamped one.
/// The first matching leak whose target table has a route is the same
/// precedence-ordered rule selected by the forwarding walk.
pub(in crate::afxdp) fn leak_incarnation_for_resolution(
    state: &ForwardingState,
    target: IpAddr,
    source_table: Option<&str>,
) -> Option<u64> {
    match target {
        IpAddr::V4(ip) => {
            let table = source_table
                .map(|name| canonical_route_table(name, false))
                .unwrap_or(Cow::Borrowed(DEFAULT_V4_TABLE));
            if local_v4_owned_by_table(state, ip, table.as_ref()) {
                return None;
            }
            state.leak_rules_v4.get(table.as_ref()).and_then(|rules| {
                rules
                    .iter()
                    .filter(|leak| leak.prefix.contains(ip))
                    .find_map(|leak| {
                        let next_table = canonical_next_table(&leak.next_table, false);
                        table_has_v4_route(state, ip, next_table.as_ref())
                            .then_some(leak.incarnation)
                    })
            })
        }
        IpAddr::V6(ip) => {
            let table = source_table
                .map(|name| canonical_route_table(name, true))
                .unwrap_or(Cow::Borrowed(DEFAULT_V6_TABLE));
            if local_v6_owned_by_table(state, ip, table.as_ref()) {
                return None;
            }
            state.leak_rules_v6.get(table.as_ref()).and_then(|rules| {
                rules
                    .iter()
                    .filter(|leak| leak.prefix.contains(ip))
                    .find_map(|leak| {
                        let next_table = canonical_next_table(&leak.next_table, true);
                        table_has_v6_route(state, ip, next_table.as_ref())
                            .then_some(leak.incarnation)
                    })
            })
        }
    }
}

/// #9951: an old session is valid only while the exact leak incarnation it
/// recorded still owns this destination. A removed and re-added rule has a
/// fresh incarnation and therefore fails closed rather than passing an ABA
/// check.
pub(in crate::afxdp) fn leak_incarnation_is_live(
    state: &ForwardingState,
    target: IpAddr,
    incarnation: u64,
) -> bool {
    if incarnation == 0 {
        return true;
    }
    match target {
        IpAddr::V4(ip) => state
            .leak_incarnations_v4
            .get(&incarnation)
            .is_some_and(|prefixes| prefixes.iter().any(|prefix| prefix.contains(ip))),
        IpAddr::V6(ip) => state
            .leak_incarnations_v6
            .get(&incarnation)
            .is_some_and(|prefixes| prefixes.iter().any(|prefix| prefix.contains(ip))),
    }
}
pub(in crate::afxdp) fn lookup_forwarding_resolution_in_table_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, table)
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner_ecmp(state, dynamic_neighbors, dst, table, None)
}

/// #2734: as `lookup_forwarding_resolution_inner`, plus an optional
/// per-flow ECMP spread key. `ecmp_flow_hash = Some(h)` selects the
/// equal-cost member by the 5-tuple flow hash (per-flow spread); `None`
/// falls back to the per-destination hash (#2389 behavior) for callers
/// without a flow context.
pub(in crate::afxdp) fn lookup_forwarding_resolution_inner_ecmp(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    match dst {
        IpAddr::V4(ip) => {
            let table = table
                .map(|table| canonical_route_table(table, false))
                .unwrap_or(Cow::Borrowed(DEFAULT_V4_TABLE));
            lookup_forwarding_resolution_v4(
                state,
                dynamic_neighbors,
                ip,
                &table,
                0,
                true,
                ecmp_flow_hash,
            )
        }
        IpAddr::V6(ip) => {
            let table = table
                .map(|table| canonical_route_table(table, true))
                .unwrap_or(Cow::Borrowed(DEFAULT_V6_TABLE));
            lookup_forwarding_resolution_v6(
                state,
                dynamic_neighbors,
                ip,
                &table,
                0,
                true,
                ecmp_flow_hash,
            )
        }
    }
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_v4(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    // #9955: this wrapper enters the two-stage resolver with the rule stage
    // enabled. Leak-selected targets call the same table resolver with that
    // stage disabled, matching kernel ip-rule semantics.
    lookup_forwarding_resolution_v4_inner(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        true,
        allow_tunnels,
        ecmp_flow_hash,
    )
}

#[inline]
fn local_v4_owned_by_table(state: &ForwardingState, ip: Ipv4Addr, table: &str) -> bool {
    state.local_v4.contains(&ip)
        && (state.local_nat_any_table_v4.contains(&ip)
            || state
                .local_tables_v4
                .get(&ip)
                .is_some_and(|tables| tables.contains(table)))
}

#[inline]
fn table_has_v4_route(state: &ForwardingState, ip: Ipv4Addr, table: &str) -> bool {
    state.routes_v4.get(table).is_some_and(|routes| {
        routes
            .iter()
            .any(|entry| entry.next_table.is_empty() && entry.prefix.contains(ip))
    }) || state
        .connected_v4
        .iter()
        .any(|entry| entry.table == table && entry.prefix.contains(ip))
        || local_v4_owned_by_table(state, ip, table)
}

#[inline]
fn local_delivery_resolution_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
) -> Option<ForwardingResolution> {
    if !local_v4_owned_by_table(state, ip, table) {
        return None;
    }
    // #10645: match the row's unmasked HOST address, not the masked
    // `prefix.addr()` network (equal to the host only for a /32 — every
    // wider interface address previously fell through to ifindex 0,
    // collapsing owner-RG attribution and stripping fabric zone stamps).
    // Duplicate host addresses can be shared by interfaces in one table.
    // Pick the lowest ifindex explicitly so local-delivery ownership does not
    // depend on interface snapshot / connected-route insertion order.
    let local_ifindex = state
        .connected_v4
        .iter()
        .filter(|entry| entry.table == table && entry.host == ip)
        .map(|entry| entry.ifindex)
        .min()
        .unwrap_or(0);
    if local_ifindex == 0 {
        LOCAL_DELIVERY_IFINDEX0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex,
        egress_ifindex: local_ifindex,
        tx_ifindex: local_ifindex,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    })
}

#[inline]
fn local_delivery_resolution_v6(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
) -> Option<ForwardingResolution> {
    let local_ifindex = if local_v6_owned_by_table(state, ip, table) {
        // #10645: match the row's unmasked HOST address (see the v4 arm).
        // As with v4, make duplicate-host ownership deterministic rather than
        // depending on interface snapshot order.
        state
            .connected_v6
            .iter()
            .filter(|entry| entry.table == table && entry.host == ip)
            .map(|entry| entry.ifindex)
            .min()
            .unwrap_or(0)
    } else {
        // #10692: Linux puts the subnet-router anycast address of an assigned
        // connected prefix in table local, ahead of the ordinary connected
        // route. Mirror that priority for the prefix network address, but only
        // where an anycast IID exists. RFC 6164 removes subnet-router anycast
        // on /127 point-to-point links; /128 has no host bits, and /0's `::`
        // is the unspecified address rather than an assignable subnet anycast.
        // `connected_v6` is longest-prefix-first and table-scoped (#2388), so
        // the first matching row supplies the owning interface without
        // allocating or crossing VRF boundaries.
        state
            .connected_v6
            .iter()
            .find(|entry| {
                entry.table == table
                    && (1..127).contains(&entry.prefix.prefix_len())
                    && entry.prefix.addr() == ip
            })
            .map(|entry| entry.ifindex)?
    };
    if local_ifindex == 0 {
        LOCAL_DELIVERY_IFINDEX0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex,
        egress_ifindex: local_ifindex,
        tx_ifindex: local_ifindex,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    })
}

fn lookup_forwarding_resolution_v4_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    evaluate_leaks: bool,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    // Target-table lookups must retain the local/NAT decision that the outer
    // entry point makes for the source table. This is also before the depth
    // guard, matching the existing outer local-delivery precedence.
    if let Some(resolution) = local_delivery_resolution_v4(state, ip, table) {
        return resolution;
    }
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    }
    if evaluate_leaks {
        // #9955: stage one is the kernel's priority-ordered ip-rule walk. A
        // matching leak whose target table has no route is a miss, not a
        // terminal NoRoute; continue to the next leak and then to this
        // table's LPM stage. The target call disables this stage: an ip-rule
        // action performs LPM in its selected table and does not restart the
        // rule list.
        if let Some(leaks) = state.leak_rules_v4.get(table) {
            for leak in leaks.iter().filter(|leak| leak.prefix.contains(ip)) {
                let next_table_name = canonical_next_table(&leak.next_table, false);
                if !table_has_v4_route(state, ip, next_table_name.as_ref()) {
                    continue;
                }
                return lookup_forwarding_resolution_v4_inner(
                    state,
                    dynamic_neighbors,
                    ip,
                    next_table_name.as_ref(),
                    depth + 1,
                    false,
                    allow_tunnels,
                    ecmp_flow_hash,
                );
            }
        }
    }
    let static_match = state
        .routes_v4
        .get(table)
        .and_then(|routes| {
            routes
                .iter()
                .find(|entry| entry.next_table.is_empty() && entry.prefix.contains(ip))
        });
    // #2388: connected routes are table-scoped — only consider a connected
    // prefix that belongs to the table being resolved, so a per-VRF /
    // next-table lookup never matches another routing-instance's connected
    // prefix. The vec is sorted longest-prefix-first, so the first matching
    // in-table entry is the most specific.
    let connected_match = state
        .connected_v4
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    match choose_v4_route(static_match, connected_match) {
        Some(ResolvedRouteV4::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(Some(IpAddr::V4(ip)))
                };
            }
            let neighbor = lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V4(ip));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(ip)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        Some(ResolvedRouteV4::Static(route)) => {
            if route.discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    tx_ifindex: 0,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            // #9955: next-table entries are removed from the table-local FIB
            // during build and are handled by the priority-ordered rule stage
            // above. Keeping this branch absent is what prevents a target
            // table miss from being selected again by the source-table LPM.
            // #2389/#2734: select one equal-cost next-hop, skipping a dead
            // one. Spread by the per-flow 5-tuple hash when supplied,
            // else fall back to the per-destination hash.
            let spread_hash = ecmp_flow_hash.unwrap_or_else(|| ecmp_hash_v4(ip));
            let selected = select_route_next_hop(&route.next_hops, spread_hash, |nh| {
                // #2923: tunnel candidates use TUNNEL liveness (endpoint +
                // resolvable underlay), NOT the direct-neighbor gate they can
                // never satisfy. Without this branch a live direct member in a
                // mixed ECMP group starves the tunnel path.
                if nh.tunnel_endpoint_id != 0 {
                    return tunnel_next_hop_live(
                        state,
                        dynamic_neighbors,
                        nh.tunnel_endpoint_id,
                        depth,
                    );
                }
                // #5161: an interface-only member (`next_hop == None` — a
                // directly-connected / point-to-point "via <if>" candidate)
                // resolves its neighbor from the PER-FLOW destination `ip`, not
                // a stable gateway. The coordinator warmer cannot pre-resolve
                // that address (the on-link destination is a whole prefix,
                // unknown at route-sweep time), so gating liveness on an
                // already-present destination neighbor drops the member out of
                // the live set the moment any explicit-next_hop member resolves
                // — ECMP collapses to width-1. Treat an up interface-only
                // member as LIVE and let the MissingNeighbor cold path resolve
                // the destination lazily per flow, mirroring the single-member
                // resolution path (which forwards a missing-neighbor direct hop
                // as MissingNeighbor, never a drop).
                if nh.next_hop.is_none() {
                    return nh.ifindex > 0;
                }
                let target = nh.next_hop.unwrap_or(ip);
                nh.ifindex > 0
                    && lookup_neighbor_entry(state, dynamic_neighbors, nh.ifindex, IpAddr::V4(target))
                        .is_some()
            });
            let (next_hop, ifindex, tunnel_endpoint_id) = match selected {
                Some(nh) => (nh.next_hop, nh.ifindex, nh.tunnel_endpoint_id),
                None => (None, 0, 0),
            };
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(next_hop.map(IpAddr::V4).or(Some(IpAddr::V4(ip))))
                };
            }
            if ifindex <= 0 {
                return no_route_resolution(next_hop.map(IpAddr::V4));
            }
            let target = next_hop.unwrap_or(ip);
            let neighbor =
                lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V4(target));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => no_route_resolution(None),
    }
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_v6(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_v6_inner(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        true,
        allow_tunnels,
        ecmp_flow_hash,
    )
}

#[inline]
fn local_v6_owned_by_table(state: &ForwardingState, ip: Ipv6Addr, table: &str) -> bool {
    state.local_v6.contains(&ip)
        && (state.local_nat_any_table_v6.contains(&ip)
            || state
                .local_tables_v6
                .get(&ip)
                .is_some_and(|tables| tables.contains(table)))
}

#[inline]
fn table_has_v6_route(state: &ForwardingState, ip: Ipv6Addr, table: &str) -> bool {
    state.routes_v6.get(table).is_some_and(|routes| {
        routes
            .iter()
            .any(|entry| entry.next_table.is_empty() && entry.prefix.contains(ip))
    }) || state
        .connected_v6
        .iter()
        .any(|entry| entry.table == table && entry.prefix.contains(ip))
        || local_v6_owned_by_table(state, ip, table)
}

fn lookup_forwarding_resolution_v6_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    evaluate_leaks: bool,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    if let Some(resolution) = local_delivery_resolution_v6(state, ip, table) {
        return resolution;
    }
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    }
    if evaluate_leaks {
        // #9955: perform the rule stage once. The target lookup disables
        // `evaluate_leaks`, so a target-table miss resumes this same rule
        // list rather than restarting it from the selected table.
        if let Some(leaks) = state.leak_rules_v6.get(table) {
            for leak in leaks.iter().filter(|leak| leak.prefix.contains(ip)) {
                let next_table_name = canonical_next_table(&leak.next_table, true);
                if !table_has_v6_route(state, ip, next_table_name.as_ref()) {
                    continue;
                }
                return lookup_forwarding_resolution_v6_inner(
                    state,
                    dynamic_neighbors,
                    ip,
                    next_table_name.as_ref(),
                    depth + 1,
                    false,
                    allow_tunnels,
                    ecmp_flow_hash,
                );
            }
        }
    }
    let static_match = state
        .routes_v6
        .get(table)
        .and_then(|routes| {
            routes
                .iter()
                .find(|entry| entry.next_table.is_empty() && entry.prefix.contains(ip))
        });
    // #2388: connected routes are table-scoped (see the v4 lookup).
    let connected_match = state
        .connected_v6
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    match choose_v6_route(static_match, connected_match) {
        Some(ResolvedRouteV6::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(Some(IpAddr::V6(ip)))
                };
            }
            let neighbor = lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V6(ip));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(ip)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        Some(ResolvedRouteV6::Static(route)) => {
            if route.discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    tx_ifindex: 0,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            // #9955: next-table entries are handled by the priority-ordered
            // rule stage before this table-local LPM; they are not ordinary
            // routes and cannot turn a target-table miss into a second
            // recursive lookup.
            // #2389/#2734: select one equal-cost next-hop, skipping a dead
            // one. Spread by the per-flow 5-tuple hash when supplied,
            // else fall back to the per-destination hash.
            let spread_hash = ecmp_flow_hash.unwrap_or_else(|| ecmp_hash_v6(ip));
            let selected = select_route_next_hop(&route.next_hops, spread_hash, |nh| {
                // #2923: tunnel candidates use TUNNEL liveness (endpoint +
                // resolvable underlay), NOT the direct-neighbor gate they can
                // never satisfy. Without this branch a live direct member in a
                // mixed ECMP group starves the tunnel path.
                if nh.tunnel_endpoint_id != 0 {
                    return tunnel_next_hop_live(
                        state,
                        dynamic_neighbors,
                        nh.tunnel_endpoint_id,
                        depth,
                    );
                }
                // #5161: an interface-only member (`next_hop == None`) resolves
                // its neighbor from the PER-FLOW destination `ip`, which the
                // warmer cannot pre-resolve (a whole prefix, unknown at
                // route-sweep time). Gating on an already-present destination
                // neighbor starves it out of the live set once any
                // explicit-next_hop member resolves — ECMP collapses to
                // width-1. Treat an up interface-only member as LIVE; the
                // MissingNeighbor cold path resolves the destination lazily per
                // flow. See the v4 twin for the full rationale.
                if nh.next_hop.is_none() {
                    return nh.ifindex > 0;
                }
                let target = nh.next_hop.unwrap_or(ip);
                nh.ifindex > 0
                    && lookup_neighbor_entry(state, dynamic_neighbors, nh.ifindex, IpAddr::V6(target))
                        .is_some()
            });
            let (next_hop, ifindex, tunnel_endpoint_id) = match selected {
                Some(nh) => (nh.next_hop, nh.ifindex, nh.tunnel_endpoint_id),
                None => (None, 0, 0),
            };
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(next_hop.map(IpAddr::V6).or(Some(IpAddr::V6(ip))))
                };
            }
            if ifindex <= 0 {
                return no_route_resolution(next_hop.map(IpAddr::V6));
            }
            let target = next_hop.unwrap_or(ip);
            let neighbor =
                lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V6(target));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => no_route_resolution(None),
    }
}

pub(in crate::afxdp) fn no_route_resolution(next_hop: Option<IpAddr>) -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }
}

/// #9752: the terminal resolution for a session whose installing table is
/// not resolvable in the current config (retired/unknown instance, owner
/// change, or absent family without a table-independent local outcome).
/// Zeroed egress (the `DiscardRoute` shape at `:479-484`): no attribution
/// downstream can resurrect it, and it is slow-path-ineligible,
/// uncacheable, and never kernel-passed by construction.
pub(in crate::afxdp) fn table_unavailable_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::TableUnavailable,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }
}

enum ResolvedRouteV4<'a> {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static(&'a RouteEntryV4),
}

enum ResolvedRouteV6<'a> {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static(&'a RouteEntryV6),
}

fn choose_v4_route<'a>(
    static_match: Option<&'a RouteEntryV4>,
    connected_match: Option<&'a ConnectedRouteV4>,
) -> Option<ResolvedRouteV4<'a>> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV4::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV4::Static(route)),
        (None, Some(conn)) => Some(ResolvedRouteV4::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

fn choose_v6_route<'a>(
    static_match: Option<&'a RouteEntryV6>,
    connected_match: Option<&'a ConnectedRouteV6>,
) -> Option<ResolvedRouteV6<'a>> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV6::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV6::Static(route)),
        (None, Some(conn)) => Some(ResolvedRouteV6::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

/// #2389/#2734: select one equal-cost next-hop candidate for a forwarding
/// static route. Prefers a candidate whose neighbor is resolved (skips a
/// dead/unresolved first next-hop — the load-bearing correctness fix); if
/// several resolve, distributes deterministically by the supplied
/// `flow_hash`; if none resolve, falls back to the same hashed pick so the
/// kernel slow-path can drive ARP/NDP.
///
/// #2734: the spread key is now per-FLOW. The session resolution path
/// threads the 5-tuple flow hash (`ecmp_hash_flow`, the same seeded
/// FxHasher the flow cache already feeds the session 5-tuple — see
/// `ecmp_hash_flow`) into `select_route_next_hop`, so distinct flows to
/// the SAME destination spread across equal-cost members while every
/// packet of a single flow pins to one member (flow-consistent — no
/// intra-flow reordering). Callers without a flow context (tunnel outer
/// resolution, `inject`, bare-dst lookups) pass `None`, which falls back
/// to the per-DESTINATION hash (`ecmp_hash_v4`/`ecmp_hash_v6`) — the
/// #2389 behavior. The retained candidate vector (Vec<RouteNextHop>) is
/// what makes per-flow selection a localized runtime change.
/// Deterministic ECMP spread mixer. A fixed-seed splitmix64 finalizer over
/// the input word — used for the per-destination fallback. Stable across
/// reloads and workers so every worker maps the same input to the same
/// equal-cost path (a flow's packets never split across paths). Not a
/// security hash.
fn ecmp_hash_bytes(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn ecmp_hash_v4(ip: Ipv4Addr) -> u64 {
    ecmp_hash_bytes(u32::from(ip) as u64)
}

fn ecmp_hash_v6(ip: Ipv6Addr) -> u64 {
    let bits = u128::from(ip);
    ecmp_hash_bytes((bits as u64) ^ ((bits >> 64) as u64))
}

/// #2734: per-FLOW ECMP spread key over the full 5-tuple.
///
/// Hashes the session forward 5-tuple (`addr_family`/`protocol`/`src_ip`/
/// `dst_ip`/`src_port`/`dst_port`) with the SAME per-boot, per-process
/// seeded `FxHasher` the flow cache uses (`hot_hash_seed::hot_path_hash_seed`
/// — #2364), so the cost is one already-vetted hash and the per-flow
/// mapping reshuffles each restart (defeats offline collision construction)
/// while staying stable for a flow's lifetime within a boot. The seed is
/// node-local: ECMP selection picks among THIS node's equal-cost members
/// and is not part of any wire/HA-synced structure, so a per-node seed is
/// correct (HA peers re-derive their own pick under their own seed, exactly
/// as the flow cache and fabric-queue hash do). Determinism within a boot
/// guarantees flow consistency — every packet of one flow hashes to the
/// same member, no intra-flow reordering. `select_route_next_hop` reduces
/// this modulo the live-member count, so the spread tracks the live pool.
fn ecmp_hash_flow(key: &crate::session::SessionKey) -> u64 {
    ecmp_hash_flow_seeded(crate::hot_hash_seed::hot_path_hash_seed(), key)
}

/// Seed-parameterized core of `ecmp_hash_flow`. Split out so tests can pin
/// the seed and assert (a) intra-seed stability (flow consistency) and
/// (b) that distinct 5-tuples spread. Production calls through
/// `ecmp_hash_flow`, which supplies the per-boot process seed.
pub(in crate::afxdp) fn ecmp_hash_flow_seeded(seed: u64, key: &crate::session::SessionKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::with_seed(seed as usize);
    key.hash(&mut hasher);
    hasher.finish()
}

/// #2922: select one equal-cost next-hop in a SINGLE liveness pass.
///
/// The liveness predicate (`is_live`) is NOT pure — the IPv4/IPv6 callers
/// probe the shared dynamic-neighbor map, which the monitor thread mutates
/// concurrently. The previous two-pass form (`count()` then `nth()`)
/// evaluated `is_live` twice per candidate, so (a) a neighbor removed
/// between the two passes made `live > 0` true at count time but
/// `nth(pick)` yield `None` → spurious no-route even though a live
/// candidate existed at count time, and (b) every session-miss ECMP
/// lookup ran two full sets of neighbor hash probes on the hot path.
///
/// Fix: materialize the live candidates into a stack `SmallVec` of
/// references in one pass, so the count and the selection observe the
/// SAME liveness snapshot. ECMP fanout is small (a handful of equal-cost
/// members), so the inline capacity (8) covers the common case without a
/// heap allocation. Selection semantics are unchanged: when any member is
/// live, the pick is `ip_hash % live_count` over the live set in original
/// candidate order (so the same flow pins to the same member given the
/// same liveness); when none are live, fall back to the same hashed pick
/// over the full candidate vector so the kernel slow-path can drive
/// ARP/NDP.
/// #2923: ECMP candidate liveness for a TUNNEL next-hop.
///
/// A tunnel candidate (`tunnel_endpoint_id != 0`) is NOT a neighbor-resolved
/// L2 next-hop on the logical tunnel ifindex, so the direct-neighbor liveness
/// gate (`ifindex > 0 && lookup_neighbor_entry(...)`) always marks it dead.
/// In a MIXED direct+tunnel ECMP group a live direct member makes `live > 0`,
/// which restricts selection to direct candidates and starves the tunnel path
/// even when its underlay is fully up.
///
/// A tunnel next-hop is live iff its endpoint exists AND the OUTER transport
/// resolves to a FORWARDABLE disposition. `resolve_tunnel_outer` already
/// rejects the structurally-broken cases (unknown endpoint, local-delivery
/// outer, tunnel-interface recursion loop) by returning `None`, but a tunnel
/// whose underlay ROUTE is withdrawn still returns
/// `Some(ForwardingResolution { disposition: NoRoute, egress_ifindex: 0, .. })`
/// — a bare `.is_some()` would mark that DEAD tunnel live, and in a mixed
/// group ~half the flows would hash to it and DROP (NoRoute) despite a fully
/// live direct member (#2923 review finding). So gate on the OUTER
/// disposition:
///
/// * `ForwardCandidate` — outer next-hop neighbor resolved, fully usable.
/// * `MissingNeighbor` — outer route present, ARP/NDP pending; the cold path
///   drives resolution, so this is LIVE, matching the direct-hop branch which
///   keeps an `ifindex > 0` next-hop selectable while its neighbor resolves
///   (a tunnel marked MissingNeighbor egresses the logical tunnel ifindex and
///   the cold path probes the OUTER hop via `outer_neighbor_ifindex`).
///
/// Every other disposition (`NoRoute`, `DiscardRoute`, `NextTableUnsupported`,
/// etc.) means the underlay cannot forward → DEAD, so selection skips it and a
/// live alternate (direct or another tunnel) carries the flow. Reusing
/// `resolve_tunnel_outer` keeps liveness identical to what selection later
/// resolves via `resolve_tunnel_forwarding_resolution`. `depth` is forwarded
/// so the outer re-resolution honors the same next-table recursion budget as
/// the caller.
fn tunnel_next_hop_live(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> bool {
    matches!(
        resolve_tunnel_outer(state, dynamic_neighbors, tunnel_endpoint_id, depth)
            .map(|outer| outer.disposition),
        Some(ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor)
    )
}

/// #7204 (A1-b7-F6): the largest ECMP fanout this build can be asked to select
/// from, and therefore the width the liveness mask must cover.
///
/// Not a tuning knob. It is the ceiling the control plane renders:
/// `pkg/frr/config_render.go`'s `resolveECMP` sets `ecmpMaxPaths = 64` for any
/// load-balancing export policy, and `pkg/frr/protocols_render.go` emits that
/// verbatim as FRR's `maximum-paths`. Junos `routing-options maximum-ecmp` is
/// listed Missing in docs/feature-gaps.md, so no operator knob raises it.
///
/// Lowering this does not change which member is selected -- the fallback below
/// is equivalent -- it silently reintroduces the per-lookup allocation this item
/// removed, for fanouts between the new value and 64. That is why it is pinned
/// by a test against the rendered ceiling rather than left as a bare literal.
pub(in crate::afxdp) const MAX_SUPPORTED_ECMP_FANOUT: usize = 64;

pub(in crate::afxdp) fn select_route_next_hop<'a, T: Copy>(
    candidates: &'a [T],
    ip_hash: u64,
    is_live: impl Fn(&T) -> bool,
) -> Option<&'a T> {
    if candidates.is_empty() {
        return None;
    }
    // #7204 (A1-b7-F6): record liveness in a BITMASK, not a list of references.
    //
    // The collection never needed the references. It is used for exactly two
    // things — how many candidates are live, and which one is the Nth live in
    // candidate order — and a `u64` answers both in 8 bytes with `count_ones`
    // and a bit walk. `SmallVec<[&T; 8]>` was 64 bytes of inline stack that
    // spilled to the heap from fanout 9 up, on the packet-driven session-miss
    // path.
    //
    // WHY NOT A BIGGER INLINE ARRAY. The supported ECMP ceiling is 64
    // (`pkg/frr/config_render.go` resolveECMP -> `maximum-paths 64`, and Junos
    // `routing-options maximum-ecmp` is Missing per docs/feature-gaps.md, so no
    // operator knob raises it). `[&T; 64]` would never spill, but it costs 512
    // bytes of stack on EVERY call including the 1-4 fanout that real multi-WAN
    // configs actually run — paying the worst case always, to avoid an
    // allocation almost nobody reaches. The mask costs 8 bytes at every fanout
    // and allocates at none of them, so the trade does not have to be made.
    //
    // WHY NOT TWO PASSES over the candidates instead. `is_live` is not a field
    // read: both call sites reach `tunnel_next_hop_live`, which resolves a
    // tunnel endpoint and consults the neighbour map. The original comment's
    // "single liveness evaluation" is load-bearing, and this preserves it —
    // `is_live` is still called exactly `candidates.len()` times.
    //
    // SELECTION IS UNCHANGED. The bit walk yields the pick-th SET bit in
    // ascending index order, which is the same element `live[pick]` named.
    // ECMP picks must stay flow-consistent, so this had to be an equivalence,
    // not merely a valid choice.
    const MASK_BITS: usize = MAX_SUPPORTED_ECMP_FANOUT;
    if candidates.len() <= MASK_BITS {
        let mut live_mask: u64 = 0;
        for (i, c) in candidates.iter().enumerate() {
            if is_live(c) {
                live_mask |= 1u64 << i;
            }
        }
        let live_count = live_mask.count_ones() as u64;
        if live_count > 0 {
            let mut pick = ip_hash % live_count;
            let mut remaining = live_mask;
            loop {
                let idx = remaining.trailing_zeros() as usize;
                if pick == 0 {
                    return candidates.get(idx);
                }
                pick -= 1;
                remaining &= remaining - 1;
            }
        }
        let pick = (ip_hash % candidates.len() as u64) as usize;
        return candidates.get(pick);
    }

    // Above the supported ceiling the mask cannot represent every candidate, so
    // fall back to the original collect. Unreachable through configuration —
    // nothing renders more than 64 paths — but a route arriving with more must
    // still be selected from correctly rather than silently truncated to the
    // first 64.
    let live: smallvec::SmallVec<[&'a T; 8]> =
        candidates.iter().filter(|c| is_live(c)).collect();
    if !live.is_empty() {
        let pick = (ip_hash % live.len() as u64) as usize;
        live.get(pick).copied()
    } else {
        let pick = (ip_hash % candidates.len() as u64) as usize;
        candidates.get(pick)
    }
}
