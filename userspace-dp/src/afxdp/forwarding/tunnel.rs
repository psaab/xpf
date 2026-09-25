//! #5650: tunnel outer-header forwarding resolution and neighbor-entry lookup /
//! parsing for tunnel next-hops. Pure code-motion split out of
//! `forwarding/mod.rs` (behavior-identical).

use super::*;

/// Resolve a tunnel endpoint's OUTER transport destination.
///
/// Shared SSOT for the outer-hop lookup: returns the OUTER
/// `ForwardingResolution` (whose `egress_ifindex` is the OUTER L3 egress
/// interface where the outer next-hop neighbor is keyed, NOT the tunnel
/// logical ifindex), or `None` when the endpoint id is unknown OR the
/// outer destination resolves to local delivery / a tunnel interface (the
/// recursion guard). `resolve_tunnel_forwarding_resolution` re-maps the
/// returned resolution onto the tunnel logical ifindex; the cold-path
/// `outer_neighbor_ifindex` helper reads `egress_ifindex` straight off it
/// to key the outer-hop ARP/NDP probe + neighbor map + neg-cache.
pub(in crate::afxdp) fn resolve_tunnel_outer(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> Option<ForwardingResolution> {
    let endpoint = state.tunnel_endpoints.get(&tunnel_endpoint_id)?;
    let outer = match endpoint.destination {
        // #2734: tunnel OUTER resolution is per-tunnel-endpoint, not
        // per-inner-flow — no 5-tuple flow hash applies here, so pass
        // None (per-destination spread across outer-transport ECMP).
        IpAddr::V4(ip) => lookup_forwarding_resolution_v4(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
            None,
        ),
        IpAddr::V6(ip) => lookup_forwarding_resolution_v6(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
            None,
        ),
    };
    if outer.disposition == ForwardingDisposition::LocalDelivery
        || state.tunnel_interfaces.contains(&outer.egress_ifindex)
    {
        return None;
    }
    Some(outer)
}

pub(in crate::afxdp) fn resolve_tunnel_forwarding_resolution(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> ForwardingResolution {
    let Some(endpoint) = state.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return no_route_resolution(None);
    };
    let logical_ifindex = endpoint.logical_ifindex;
    let destination = endpoint.destination;
    let Some(outer) = resolve_tunnel_outer(state, dynamic_neighbors, tunnel_endpoint_id, depth)
    else {
        return no_route_resolution(Some(destination));
    };
    ForwardingResolution {
        disposition: outer.disposition,
        local_ifindex: outer.local_ifindex,
        egress_ifindex: logical_ifindex,
        tx_ifindex: outer.tx_ifindex,
        tunnel_endpoint_id,
        next_hop: outer.next_hop,
        neighbor_mac: outer.neighbor_mac,
        src_mac: outer.src_mac,
        tx_vlan_id: outer.tx_vlan_id,
    }
}

/// The ifindex on which `resolution.next_hop` must be neighbor-resolved
/// (ARP/NDP probe + neighbor-map key + negative-cache key) on the cold
/// path. For a normal (non-tunnel) resolution this is `egress_ifindex`.
/// For a tunnel-marked resolution it is the OUTER transport's L3 egress
/// ifindex — where the outer next-hop neighbor (e.g. the GRE outer hop)
/// actually lives — which differs from `resolution.egress_ifindex` (the
/// tunnel LOGICAL ifindex, used for zone/policy/CoS) and from
/// `resolution.tx_ifindex` (the VLAN PARENT for a VLAN outer transport;
/// neighbors are keyed by the L3 subif, so `tx_ifindex` would be the wrong
/// key).
///
/// Computed from LIVE forwarding state at use time, so it is inherently
/// peer-local and needs no wire field / HA-sync trust — synced sessions
/// re-resolve on upsert. The outer re-resolution reuses the shared
/// `resolve_tunnel_outer` SSOT (the same lookup the original resolution
/// ran), so there is no logic duplication. Cold-path only (MissingNeighbor
/// arm), never the fast path.
///
/// The `> 0` guard (vs `== 0`) is the conservative fallback: if the
/// endpoint vanished or the re-resolved outer egress is non-positive, fall
/// back to `resolution.egress_ifindex` rather than emit a probe on ifindex
/// 0.
pub(in crate::afxdp) fn outer_neighbor_ifindex(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    resolution: &ForwardingResolution,
) -> i32 {
    if resolution.tunnel_endpoint_id == 0 {
        return resolution.egress_ifindex;
    }
    match resolve_tunnel_outer(state, dynamic_neighbors, resolution.tunnel_endpoint_id, 0) {
        Some(outer) if outer.egress_ifindex > 0 => outer.egress_ifindex,
        _ => resolution.egress_ifindex,
    }
}

pub(in crate::afxdp) fn lookup_neighbor_entry(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ifindex: i32,
    target: IpAddr,
) -> Option<NeighborEntry> {
    // The neighbor may be static, kernel-imported, or packet-learned; none
    // may resolve a directed broadcast on this connected egress.
    if super::is_connected_v4_directed_broadcast(state, ifindex, target) {
        return None;
    }

    if let Some(entry) = state.neighbors.get(&(ifindex, target)).copied() {
        return Some(entry);
    }
    let Some(dynamic_neighbors) = dynamic_neighbors else {
        return None;
    };
    if let Some(entry) = dynamic_neighbors.get(&(ifindex, target)) {
        return Some(entry);
    }
    // The worker hot path must not block on shelling out to `ip neigh` or
    // active probes. Runtime neighbor discovery is maintained asynchronously
    // by the helper's own netlink dump+subscribe path.
    None
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn parse_neighbor_entries(output: &str) -> Vec<(IpAddr, NeighborEntry)> {
    let mut out = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        // #3771 (M12): the NUD state is the FINAL token of an `ip neigh` row
        // (REACHABLE / STALE / FAILED / ...). Classify ONLY that token with the
        // allowlist. The pre-#3771 denylist was applied to EVERY field, which
        // only worked because an IP / MAC / `lladdr` never contained the
        // "failed" / "incomplete" substrings; the allowlist would reject those
        // non-state fields and drop every row, so we must scope it to the state.
        match fields.last() {
            Some(state) if neighbor_state_usable(state) => {}
            _ => continue,
        }
        let Ok(ip) = fields[0].parse::<IpAddr>() else {
            continue;
        };
        let Some(lladdr) = fields.iter().position(|field| *field == "lladdr") else {
            continue;
        };
        let Some(candidate) = fields.get(lladdr + 1) else {
            continue;
        };
        let Some(mac) = parse_mac(candidate).or_else(|| parse_mac(candidate.trim())) else {
            continue;
        };
        out.push((ip, NeighborEntry { mac }));
    }
    out
}
