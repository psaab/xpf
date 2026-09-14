//! #5650: core FIB forwarding resolution — packet-destination parse, table /
//! next-table walk, per-family (v4/v6) route resolution, ECMP hashing and
//! next-hop selection, and the no-route/connected/static route choice. This is
//! the per-packet FIB-resolution hot path; the split is pure code-motion out of
//! `forwarding/mod.rs`, preserving instruction-level behavior and `#[inline]`
//! attributes exactly.

use super::*;
use std::borrow::Cow;

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

pub(in crate::afxdp) fn parse_packet_destination(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    let l3 = meta.l3_offset as usize;
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
            if state.local_v4.contains(&ip) {
                // #3151: local-delivery (to-self) attribution is table-scoped,
                // exactly like the route-path connected scan (#2388). When the
                // same local IP exists in more than one routing-instance, a
                // to-self packet in VRF A must NOT resolve its
                // local/egress/tx ifindex to VRF B's connected entry — that
                // would mis-attribute zone/security-policy and HA RG ownership
                // (owner_rg_for_flow(egress_ifindex)) across VRFs. Filter the
                // connected scan by the canonical ingress table; the default
                // routing-instance (inet.0) case still matches default-table
                // connected routes.
                // #3769: the local-delivery DECISION is now table-scoped too,
                // not just the #3151 ifindex attribution. `local_v4` is a
                // GLOBAL membership set, so a NAT/DNAT external IP owned in
                // VRF B (or an interface IP owned only in another
                // routing-instance) would otherwise short-circuit a VRF-A
                // packet to LocalDelivery, bypassing the VRF-A FIB +
                // zone/policy + HA-RG owner check. `local_tables_v4` records,
                // per local address, the tables that own it (paired with every
                // `local_v4` insert); deliver locally only when the RESOLVING
                // table is one of them. NOTE: the membership DECISION cannot
                // use the connected scan — `ConnectedRouteV4` stores the MASKED
                // network address, so `prefix.addr() == host` matches only a
                // /32 (and never a NAT-only IP, which has no connected route).
                // #3769: an UNSCOPED NAT/DNAT external (`local_nat_any_table_v4`)
                // is table-agnostic (mirrors `scope_ok`'s empty-instance
                // wildcard); a named-VRF / interface address must match the
                // resolving table exactly.
                let owned_here = state.local_nat_any_table_v4.contains(&ip)
                    || state
                        .local_tables_v4
                        .get(&ip)
                        .is_some_and(|tables| tables.contains(table.as_ref()));
                if !owned_here {
                    // Owned in a DIFFERENT table only (cross-VRF) — fall
                    // through to the VRF-A route lookup instead of leaking to
                    // LocalDelivery.
                } else {
                    // #3151: ifindex attribution stays via the table-scoped
                    // connected scan (the /32-HA case). A NAT-only external IP
                    // or a non-/32 interface host IP has no exact connected
                    // match → ifindex 0 (unchanged pre-#3769 behaviour), now
                    // reached only when the table genuinely owns the address.
                    let local_ifindex = state
                        .connected_v4
                        .iter()
                        .find(|entry| entry.table == table && entry.prefix.addr() == ip)
                        .map(|entry| entry.ifindex)
                        .unwrap_or(0);
                    if local_ifindex == 0 {
                        // #3769 L5: table-owned local target with no interface
                        // ifindex (NAT-only, or a non-/32 interface IP whose
                        // ingress-interface path was bypassed). Gated on table
                        // ownership; counted for diagnostics.
                        LOCAL_DELIVERY_IFINDEX0
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::LocalDelivery,
                        local_ifindex,
                        egress_ifindex: local_ifindex,
                        tx_ifindex: local_ifindex,
                        tunnel_endpoint_id: 0,
                        next_hop: None,
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
            }
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
            if state.local_v6.contains(&ip) {
                // #3151: table-scoped local-delivery attribution (see the v4
                // branch above and the #2388 route-path connected scan).
                // #3769: table-scoped local-delivery DECISION (see the v4
                // branch). A NAT/DNAT external IP owned in another VRF, or an
                // interface IP owned only in another routing-instance, must not
                // short-circuit a VRF-A packet to LocalDelivery. `local_v6`
                // membership alone is global; gate on `local_tables_v6` (plus
                // the unscoped-wildcard `local_nat_any_table_v6`, see the v4
                // branch).
                let owned_here = state.local_nat_any_table_v6.contains(&ip)
                    || state
                        .local_tables_v6
                        .get(&ip)
                        .is_some_and(|tables| tables.contains(table.as_ref()));
                if !owned_here {
                    // Owned in a DIFFERENT table only (cross-VRF) — fall
                    // through to the route lookup.
                } else {
                    // #3151: ifindex attribution via the table-scoped connected
                    // scan (matches a /128 host; a NAT-only or non-/128 IP →
                    // ifindex 0, now reached only when this table owns the IP).
                    let local_ifindex = state
                        .connected_v6
                        .iter()
                        .find(|entry| entry.table == table && entry.prefix.addr() == ip)
                        .map(|entry| entry.ifindex)
                        .unwrap_or(0);
                    if local_ifindex == 0 {
                        // #3769 L5: table-owned local target, no interface
                        // ifindex; gated on table ownership, counted.
                        LOCAL_DELIVERY_IFINDEX0
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::LocalDelivery,
                        local_ifindex,
                        egress_ifindex: local_ifindex,
                        tx_ifindex: local_ifindex,
                        tunnel_endpoint_id: 0,
                        next_hop: None,
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
            }
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
    // #3768 (M6): each top-level resolution starts a fresh visited-table
    // chain for A->B->A next-table cycle detection. The tunnel-underlay
    // sub-resolution (resolve_tunnel_outer) also enters through this public
    // wrapper, so it correctly starts its own independent chain.
    // #7204 (A1-b7-F5), the visited half: MEASURED AND DELIBERATELY LEFT.
    //
    // #7204 proposes a fixed `[TableId; MAX_NEXT_TABLE_DEPTH]` stack here. It is
    // not worth it, for the reason that decided the ECMP fanout in #8083: do not
    // pay the worst case on every call to remove a cost the common path never
    // incurs.
    //
    //   * `Vec::new()` does not allocate. A resolution that never traverses a
    //     next-table -- the overwhelming majority -- pays nothing here.
    //   * The clones happen only on an actual next-table hop, and
    //     MAX_NEXT_TABLE_DEPTH bounds them at 8: bounded work on a configured,
    //     non-default feature path.
    //   * An inline `[_; 8]` stack would cost ~192 bytes on EVERY resolution,
    //     including all the ones that never push.
    //
    // The allocation this item is really about was in `canonical_route_table`,
    // which copied its own argument on every same-family lookup to satisfy a
    // `'static` return. That one is fixed, and it was on the common path.
    let mut visited: Vec<String> = Vec::new();
    lookup_forwarding_resolution_v4_inner(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        allow_tunnels,
        ecmp_flow_hash,
        &mut visited,
    )
}

fn lookup_forwarding_resolution_v4_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    visited: &mut Vec<String>,
) -> ForwardingResolution {
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
    let static_match = state
        .routes_v4
        .get(table)
        .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
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
            if !route.next_table.is_empty() {
                // #3768 (M5): canonicalize the recursive next-table name for
                // THIS address family before loop detection and recursion.
                // routes_v4 is keyed by canonical_route_table(table, false),
                // so a v4 next-table string is already canonical here; the
                // canonicalization is defense-in-depth (a stale/mis-derived
                // "<inst>.inet6.0" on the v4 side would otherwise miss). The
                // symmetric v6 site is where this actually rewrites (see the
                // Go #3768 H6 fix + the v6 lookup below).
                let next_table_name = canonical_route_table(&route.next_table, false);
                // #3768 (M6): reject a next-table that revisits the current
                // table (direct self-loop) OR any table already on this
                // resolution's chain (A->B->A cross-table cycle). Without the
                // visited set an A->B->A cycle burned to MAX_NEXT_TABLE_DEPTH
                // on every packet and masked the config defect.
                if next_table_name == table || visited.iter().any(|t| t == &next_table_name) {
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
                visited.push(table.to_string());
                return lookup_forwarding_resolution_v4_inner(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                    ecmp_flow_hash,
                    visited,
                );
            }
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
    // #3768 (M6): fresh visited-table chain per top-level resolution (see
    // the v4 wrapper).
    let mut visited: Vec<String> = Vec::new();
    lookup_forwarding_resolution_v6_inner(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        allow_tunnels,
        ecmp_flow_hash,
        &mut visited,
    )
}

fn lookup_forwarding_resolution_v6_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    visited: &mut Vec<String>,
) -> ForwardingResolution {
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
    let static_match = state
        .routes_v6
        .get(table)
        .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
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
            if !route.next_table.is_empty() {
                // #3768 (M5): canonicalize the recursive next-table name for
                // the v6 family before loop detection + recursion. routes_v6
                // is keyed by canonical_route_table(table, true) =
                // "<inst>.inet6.0"; canonicalizing here rewrites a
                // "<inst>.inet.0" next-table string (e.g. a pre-#3768-H6 Go
                // snapshot, or a next_table authored in v4 form) onto the v6
                // table so the lookup hits instead of blackholing.
                let next_table_name = canonical_route_table(&route.next_table, true);
                // #3768 (M6): self-loop + A->B->A cross-table cycle guard
                // (see the v4 site).
                if next_table_name == table || visited.iter().any(|t| t == &next_table_name) {
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
                visited.push(table.to_string());
                return lookup_forwarding_resolution_v6_inner(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                    ecmp_flow_hash,
                    visited,
                );
            }
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
