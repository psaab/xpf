//! FIB / neighbor / fabric population for `build_forwarding_state`.
//!
//! Owns:
//!
//! - [`sort_connected`] — sort `state.connected_v[46]` by prefix length.
//! - [`populate_routes`] — walk `snapshot.routes`, push into
//!   `state.routes_v[46]` keyed by canonical table name.
//! - [`sort_routes`] — sort each route table by prefix length.
//! - [`populate_neighbors`] — copy usable neighbors into
//!   `state.neighbors`.
//! - [`populate_fabrics`] — append `FabricLink` entries to
//!   `state.fabrics`, resolving local + peer MACs through
//!   [`IfaceIndex`] and the populated `state.neighbors` map.
//!
//! Also hosts the route-target resolution helpers
//! ([`resolve_route_next_hops_v4`] etc.) re-exported by
//! `forwarding_build/mod.rs` as `pub(in crate::afxdp)` for the
//! other afxdp siblings that consume them via `use
//! self::forwarding_build::*;` in `afxdp/mod.rs`.

use super::super::*;
use super::interfaces::IfaceIndex;
use crate::RouteSnapshot;
use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_LEAK_INCARNATION: AtomicU64 = AtomicU64::new(1);

fn leak_identity_matches_v4(a: &LeakRuleV4, b: &LeakRuleV4) -> bool {
    a.prefix == b.prefix && a.next_table == b.next_table && a.rule_priority == b.rule_priority
}

fn leak_identity_matches_v6(a: &LeakRuleV6, b: &LeakRuleV6) -> bool {
    a.prefix == b.prefix && a.next_table == b.next_table && a.rule_priority == b.rule_priority
}

/// #9951: retain a leak's incarnation across a config rebuild when the exact
/// rule remains. A rule absent from the previous state receives a fresh
/// process-local incarnation, so remove -> re-add cannot resurrect sessions
/// that still carry the removed rule's stamp.
pub(super) fn assign_leak_incarnations(
    state: &mut ForwardingState,
    previous: Option<&ForwardingState>,
) {
    for (table, leaks) in &mut state.leak_rules_v4 {
        let old = previous.and_then(|prev| prev.leak_rules_v4.get(table));
        for leak in leaks {
            leak.incarnation = old
                .and_then(|rules| rules.iter().find(|candidate| leak_identity_matches_v4(candidate, leak)))
                .map(|candidate| candidate.incarnation)
                .unwrap_or_else(|| NEXT_LEAK_INCARNATION.fetch_add(1, Ordering::Relaxed));
        }
    }
    for (table, leaks) in &mut state.leak_rules_v6 {
        let old = previous.and_then(|prev| prev.leak_rules_v6.get(table));
        for leak in leaks {
            leak.incarnation = old
                .and_then(|rules| rules.iter().find(|candidate| leak_identity_matches_v6(candidate, leak)))
                .map(|candidate| candidate.incarnation)
                .unwrap_or_else(|| NEXT_LEAK_INCARNATION.fetch_add(1, Ordering::Relaxed));
        }
    }
}

/// #9951: build the per-incarnation liveness index once per forwarding
/// snapshot so established-session hits do not scan every source-table rule.
pub(super) fn rebuild_leak_incarnation_indexes(state: &mut ForwardingState) {
    state.leak_incarnations_v4.clear();
    state.leak_incarnations_v6.clear();
    for leaks in state.leak_rules_v4.values() {
        for leak in leaks {
            if leak.incarnation != 0 {
                state
                    .leak_incarnations_v4
                    .entry(leak.incarnation)
                    .or_default()
                    .push(leak.prefix);
            }
        }
    }
    for leaks in state.leak_rules_v6.values() {
        for leak in leaks {
            if leak.incarnation != 0 {
                state
                    .leak_incarnations_v6
                    .entry(leak.incarnation)
                    .or_default()
                    .push(leak.prefix);
            }
        }
    }
}
pub(super) fn sort_connected(state: &mut ForwardingState) {
    state
        .connected_v4
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    state
        .connected_v6
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
}

/// Reject a numeric next-hop literal that the family-specific parser below
/// would otherwise turn into `(None, None)` (or an interface-only path).
/// Non-IP tokens and explicit interface-only forms retain their existing
/// parsing behavior. Negative and next-table routes do not use an IP gateway.
fn validate_route_next_hop_family(
    route: &RouteSnapshot,
    is_ipv6: bool,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    if route.discard || !route.next_table.is_empty() {
        return Ok(());
    }
    for next_hop in &route.next_hops {
        let ip_part = next_hop
            .split_once('@')
            .map_or(next_hop.as_str(), |(address, _)| address);
        let Ok(address) = ip_part.parse::<IpAddr>() else {
            continue;
        };
        let mismatch = matches!(
            (address, is_ipv6),
            (IpAddr::V4(_), true) | (IpAddr::V6(_), false)
        );
        if mismatch {
            return Err(crate::policy::SnapshotIntegrityError::RouteNextHopFamilyMismatch {
                table: route.table.clone(),
                destination: route.destination.clone(),
                next_hop: next_hop.clone(),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IndexedStaticRouteV4<'a> {
    prefix: PrefixV4,
    route: &'a RouteSnapshot,
}

#[derive(Clone, Copy)]
struct IndexedStaticRouteV6<'a> {
    prefix: PrefixV6,
    route: &'a RouteSnapshot,
}

/// Snapshot-order-independent route index used during FIB construction.
#[derive(Default)]
struct RecursiveGatewayRoutes<'a> {
    v4: BTreeMap<String, Vec<IndexedStaticRouteV4<'a>>>,
    v6: BTreeMap<String, Vec<IndexedStaticRouteV6<'a>>>,
}

impl<'a> RecursiveGatewayRoutes<'a> {
    fn from_snapshot(snapshot: &'a ConfigSnapshot) -> Self {
        let mut index = Self::default();
        for route in &snapshot.routes {
            if let Ok(prefix) = route.destination.parse::<Ipv4Net>() {
                let table = canonical_route_table(&route.table, false).into_owned();
                index
                    .v4
                    .entry(table)
                    .or_default()
                    .push(IndexedStaticRouteV4 {
                        prefix: PrefixV4::from_net(prefix),
                        route,
                    });
            } else if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
                let table = canonical_route_table(&route.table, true).into_owned();
                index
                    .v6
                    .entry(table)
                    .or_default()
                    .push(IndexedStaticRouteV6 {
                        prefix: PrefixV6::from_net(prefix),
                        route,
                    });
            }
        }
        for routes in index.v4.values_mut() {
            routes.sort_by(|a, b| {
                b.prefix
                    .prefix_len()
                    .cmp(&a.prefix.prefix_len())
                    .then(a.route.preference.cmp(&b.route.preference))
            });
        }
        for routes in index.v6.values_mut() {
            routes.sort_by(|a, b| {
                b.prefix
                    .prefix_len()
                    .cmp(&a.prefix.prefix_len())
                    .then(a.route.preference.cmp(&b.route.preference))
            });
        }
        index
    }
}

const MAX_RECURSIVE_STATIC_DEPTH: usize = 8;

fn recursive_static_target_v4(
    state: &ForwardingState,
    routes: &RecursiveGatewayRoutes<'_>,
    ip: Ipv4Addr,
    table: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    visited: &mut [Option<Ipv4Addr>; MAX_RECURSIVE_STATIC_DEPTH],
    depth: usize,
) -> Option<(Ipv4Addr, i32, u16)> {
    if depth >= MAX_RECURSIVE_STATIC_DEPTH || visited[..depth].contains(&Some(ip)) {
        return None;
    }
    visited[depth] = Some(ip);
    let resolved = (|| {
        let candidates = routes.v4.get(table)?;
        let prefix_len = candidates
            .iter()
            .filter(|entry| entry.prefix.contains(ip))
            .map(|entry| entry.prefix.prefix_len())
            .max()?;
        for entry in candidates
            .iter()
            .filter(|entry| entry.prefix.prefix_len() == prefix_len && entry.prefix.contains(ip))
        {
            let route = entry.route;
            if route.discard || !route.next_table.is_empty() {
                return None;
            }
            for spec in &route.next_hops {
                let (gateway, interface) = parse_route_next_hop(spec);
                let allow_default_interface = gateway.is_some() || spec.starts_with('@');
                if let Some(name) = interface.as_deref() {
                    if let Some(ifindex) = explicit_ifindex_in_route_table(
                        name,
                        allow_default_interface,
                        names,
                        linux_names,
                        state,
                        table,
                    ) {
                        let tunnel_endpoint_id = state
                            .tunnel_endpoint_by_ifindex
                            .get(&ifindex)
                            .copied()
                            .unwrap_or(0);
                        return Some((gateway.unwrap_or(ip), ifindex, tunnel_endpoint_id));
                    }
                    continue;
                }
                let Some(gateway) = gateway else {
                    continue;
                };
                if let Some((ifindex, tunnel_endpoint_id)) =
                    infer_connected_route_target_v4(state, gateway, table)
                {
                    return Some((gateway, ifindex, tunnel_endpoint_id));
                }
                if let Some(resolved) = recursive_static_target_v4(
                    state,
                    routes,
                    gateway,
                    table,
                    names,
                    linux_names,
                    visited,
                    depth + 1,
                ) {
                    return Some(resolved);
                }
            }
        }
        None
    })();
    resolved
}

fn recursive_static_target_v6(
    state: &ForwardingState,
    routes: &RecursiveGatewayRoutes<'_>,
    ip: Ipv6Addr,
    table: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    visited: &mut [Option<Ipv6Addr>; MAX_RECURSIVE_STATIC_DEPTH],
    depth: usize,
) -> Option<(Ipv6Addr, i32, u16)> {
    if depth >= MAX_RECURSIVE_STATIC_DEPTH || visited[..depth].contains(&Some(ip)) {
        return None;
    }
    visited[depth] = Some(ip);
    let resolved = (|| {
        let candidates = routes.v6.get(table)?;
        let prefix_len = candidates
            .iter()
            .filter(|entry| entry.prefix.contains(ip))
            .map(|entry| entry.prefix.prefix_len())
            .max()?;
        for entry in candidates
            .iter()
            .filter(|entry| entry.prefix.prefix_len() == prefix_len && entry.prefix.contains(ip))
        {
            let route = entry.route;
            if route.discard || !route.next_table.is_empty() {
                return None;
            }
            for spec in &route.next_hops {
                let (gateway, interface) = parse_route_next_hop_v6(spec);
                let allow_default_interface = gateway.is_some() || spec.starts_with('@');
                if let Some(name) = interface.as_deref() {
                    if let Some(ifindex) = explicit_ifindex_in_route_table(
                        name,
                        allow_default_interface,
                        names,
                        linux_names,
                        state,
                        table,
                    ) {
                        let tunnel_endpoint_id = state
                            .tunnel_endpoint_by_ifindex
                            .get(&ifindex)
                            .copied()
                            .unwrap_or(0);
                        return Some((gateway.unwrap_or(ip), ifindex, tunnel_endpoint_id));
                    }
                    continue;
                }
                let Some(gateway) = gateway else {
                    continue;
                };
                if let Some((ifindex, tunnel_endpoint_id)) =
                    infer_connected_route_target_v6(state, gateway, table)
                {
                    return Some((gateway, ifindex, tunnel_endpoint_id));
                }
                if let Some(resolved) = recursive_static_target_v6(
                    state,
                    routes,
                    gateway,
                    table,
                    names,
                    linux_names,
                    visited,
                    depth + 1,
                ) {
                    return Some(resolved);
                }
            }
        }
        None
    })();
    resolved
}

fn recursive_gateway_target_v4(
    state: &ForwardingState,
    routes: &RecursiveGatewayRoutes<'_>,
    ip: Ipv4Addr,
    table: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
) -> Option<(Ipv4Addr, i32, u16)> {
    let mut visited = [None; MAX_RECURSIVE_STATIC_DEPTH];
    recursive_static_target_v4(
        state,
        routes,
        ip,
        table,
        names,
        linux_names,
        &mut visited,
        0,
    )
}

fn recursive_gateway_target_v6(
    state: &ForwardingState,
    routes: &RecursiveGatewayRoutes<'_>,
    ip: Ipv6Addr,
    table: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
) -> Option<(Ipv6Addr, i32, u16)> {
    let mut visited = [None; MAX_RECURSIVE_STATIC_DEPTH];
    recursive_static_target_v6(
        state,
        routes,
        ip,
        table,
        names,
        linux_names,
        &mut visited,
        0,
    )
}

pub(super) fn populate_routes(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    use crate::policy::SnapshotIntegrityError;
    state
        .forwarding_tables
        .extend(snapshot.forwarding_tables.iter().cloned());
    let recursive_routes = RecursiveGatewayRoutes::from_snapshot(snapshot);
    for route in &snapshot.routes {
        // #3771 (L1): reject a NEGATIVE route preference. The FIB tie-breaks
        // same-prefix routes by ascending preference (`sort_routes`); a negative
        // value (e.g. i32::MIN) would sort ahead of every route and silently
        // hijack the selection for that prefix. Checked before the family/prefix
        // parse so it applies to every route shape.
        if route.preference < 0 {
            return Err(SnapshotIntegrityError::RoutePreferenceOutOfRange {
                table: route.table.clone(),
                destination: route.destination.clone(),
                preference: route.preference,
            });
        }
        // #11411: a negative route MTU is invalid. Do not cast it to u32,
        // where it would become an effectively unbounded MTU and disable PTB.
        if route.mtu < 0 {
            return Err(SnapshotIntegrityError::RouteMtuOutOfRange {
                table: route.table.clone(),
                destination: route.destination.clone(),
                mtu: route.mtu,
            });
        }
        if let Ok(prefix) = route.destination.parse::<Ipv4Net>() {
            // #3771 (M4): the destination parses as IPv4 — a NON-EMPTY declared
            // family must agree ("inet"), else the route's family metadata
            // contradicts the FIB it would install into. Fail CLOSED rather than
            // install into routes_v4 while `family` claims v6.
            if route_family_mismatch(&route.family, false) {
                return Err(SnapshotIntegrityError::RouteFamilyMismatch {
                    table: route.table.clone(),
                    destination: route.destination.clone(),
                    family: route.family.clone(),
                });
            }
            validate_route_next_hop_family(route, false)?;
            // #4446: compute the route's canonical install table BEFORE
            // resolving its next-hops, so a bare-gateway static route infers
            // its egress ifindex ONLY from a connected prefix in its OWN
            // table (mirrors the #2388 lookup-site connected filter, but at
            // BUILD time so the correct ifindex is baked into RouteEntryV4).
            let table = canonical_route_table(&route.table, false).into_owned();
            let next_hops = resolve_route_next_hops_v4_with_routes(
                route,
                &iface_ctx.name_to_ifindex,
                &iface_ctx.linux_to_ifindex,
                state,
                &table,
                &recursive_routes,
            );
            let prefix = PrefixV4::from_net(prefix);
            if !route.discard
                && route.next_table.is_empty()
                && next_hops.is_empty()
                && !state.connected_v4.iter().any(|connected| {
                    connected.table == table && connected.prefix == prefix
                })
            {
                return Err(SnapshotIntegrityError::RouteEmptyNextHops {
                    table: route.table.clone(),
                    destination: route.destination.clone(),
                });
            }
            if !route.next_table.is_empty() {
                state
                    .leak_rules_v4
                    .entry(table)
                    .or_default()
                    .push(LeakRuleV4 {
                        prefix,
                        next_table: canonical_next_table(&route.next_table, false).into_owned(),
                        rule_priority: route.rule_priority,
                        incarnation: 0,
                    });
            } else {
                state
                    .routes_v4
                    .entry(table)
                    .or_default()
                    .push(RouteEntryV4 {
                        prefix,
                        next_hops,
                        discard: route.discard,
                        next_table: String::new(),
                        preference: route.preference,
                        mtu: route.mtu as u32,
                        rule_priority: route.rule_priority,
                    });
            }
            continue;
        }
        if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
            // #3771 (M4): the destination parses as IPv6 — a NON-EMPTY declared
            // family must agree ("inet6").
            if route_family_mismatch(&route.family, true) {
                return Err(SnapshotIntegrityError::RouteFamilyMismatch {
                    table: route.table.clone(),
                    destination: route.destination.clone(),
                    family: route.family.clone(),
                });
            }
            validate_route_next_hop_family(route, true)?;
            // #4446: canonical install table computed before next-hop
            // resolution (see the v4 arm) so the connected-prefix inference
            // is scoped to the route's own table.
            let table = canonical_route_table(&route.table, true).into_owned();
            let next_hops = resolve_route_next_hops_v6_with_routes(
                route,
                &iface_ctx.name_to_ifindex,
                &iface_ctx.linux_to_ifindex,
                state,
                &table,
                &recursive_routes,
            );
            let prefix = PrefixV6::from_net(prefix);
            if !route.discard
                && route.next_table.is_empty()
                && next_hops.is_empty()
                && !state.connected_v6.iter().any(|connected| {
                    connected.table == table && connected.prefix == prefix
                })
            {
                return Err(SnapshotIntegrityError::RouteEmptyNextHops {
                    table: route.table.clone(),
                    destination: route.destination.clone(),
                });
            }
            if !route.next_table.is_empty() {
                state
                    .leak_rules_v6
                    .entry(table)
                    .or_default()
                    .push(LeakRuleV6 {
                        prefix,
                        next_table: canonical_next_table(&route.next_table, true).into_owned(),
                        rule_priority: route.rule_priority,
                        incarnation: 0,
                    });
            } else {
                state
                    .routes_v6
                    .entry(table)
                    .or_default()
                    .push(RouteEntryV6 {
                        prefix,
                        next_hops,
                        discard: route.discard,
                        next_table: String::new(),
                        preference: route.preference,
                        mtu: route.mtu as u32,
                        rule_priority: route.rule_priority,
                    });
            }
            continue;
        }
        // #6568 (member 1): the destination parses as NEITHER family. Before
        // this the loop body simply ended here — no Err, no counter, no log —
        // at a boundary whose whole #2409/#2410/#3771 contract is "no silent
        // skips", and for a discard/reject route that silence is a traffic
        // FAIL-OPEN: the blackhole entry is absent, the packet matches a
        // less-specific route and is forwarded. Fail CLOSED, like every sibling
        // check in this function.
        return Err(SnapshotIntegrityError::RouteDestinationUnparseable {
            table: route.table.clone(),
            destination: route.destination.clone(),
        });
    }
    Ok(())
}

/// #3771 (M4): true iff `family` is a NON-EMPTY declared address family that
/// does not match the actual family (`is_ipv6`). An empty family (older /
/// omitted producer) is unconstrained — the pre-fix parse-only behaviour — and
/// is never a mismatch. Any non-empty string other than the matching canonical
/// token ("inet" for v4, "inet6" for v6) is a mismatch, so a corrupt / unknown
/// family also fails closed.
fn route_family_mismatch(family: &str, is_ipv6: bool) -> bool {
    let fam = family.trim();
    if fam.is_empty() {
        return false;
    }
    if is_ipv6 {
        !fam.eq_ignore_ascii_case("inet6")
    } else {
        !fam.eq_ignore_ascii_case("inet")
    }
}

pub(super) fn sort_routes(state: &mut ForwardingState) {
    // #2390/#11792: order each ordinary table by descending prefix length
    // (longest-match first), then ascending Junos preference (lower = more
    // preferred). Go represents same-preference QNH metric tiers as separate
    // rows ordered by metric; stable sort preserves that producer order so
    // lookup can ECMP within a row, then fall through to later metric rows.
    for routes in state.routes_v4.values_mut() {
        routes.sort_by(|a, b| {
            b.prefix
                .prefix_len()
                .cmp(&a.prefix.prefix_len())
                .then(a.preference.cmp(&b.preference))
        });
    }
    for routes in state.routes_v6.values_mut() {
        routes.sort_by(|a, b| {
            b.prefix
                .prefix_len()
                .cmp(&a.prefix.prefix_len())
                .then(a.preference.cmp(&b.preference))
        });
    }
    // #9955/#11396: leak priorities are the kernel's stage-one ordering key.
    // The Go producer maps prefix length and leak kind into one shared LPM-first
    // range, so more-specific leaks sort first across sources. Keep this stable
    // priority sort and preserve producer order for equal-priority ties.
    for leaks in state.leak_rules_v4.values_mut() {
        leaks.sort_by_key(|leak| leak.rule_priority);
    }
    for leaks in state.leak_rules_v6.values_mut() {
        leaks.sort_by_key(|leak| leak.rule_priority);
    }
}

pub(super) fn populate_neighbors(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    for neigh in &snapshot.neighbors {
        if neigh.ifindex <= 0 {
            continue;
        }
        let Ok(ip) = neigh.ip.parse::<IpAddr>() else {
            continue;
        };
        // #3771 (M11): fail CLOSED on a neighbor whose NON-EMPTY declared family
        // contradicts its parsed IP, rather than installing it under the wrong
        // family. Checked before the state / MAC skips so a family-metadata
        // corruption is surfaced regardless of whether the entry is installable.
        if neighbor_family_mismatch(&neigh.family, &ip) {
            return Err(crate::policy::SnapshotIntegrityError::NeighborFamilyMismatch {
                interface: neigh.interface.clone(),
                ip: neigh.ip.clone(),
                family: neigh.family.clone(),
            });
        }
        // #11033: a usable NUD row must not make a connected subnet
        // directed-broadcast destination forwardable on its own egress.
        if crate::afxdp::forwarding::is_connected_v4_directed_broadcast(
            state,
            neigh.ifindex,
            ip,
        ) {
            continue;
        }

        // #3771 (M12): allowlist neighbor states — skip a known-unusable state
        // (failed/incomplete) silently and COUNT an unknown/future state
        // (none/empty/corrupt), instead of the pre-fix denylist that installed
        // every unrecognized state that happened to carry a parseable IP+MAC.
        match classify_neighbor_state(&neigh.state) {
            NeighborStateClass::Usable => {}
            NeighborStateClass::KnownUnusable => continue,
            NeighborStateClass::Unknown => {
                NEIGHBOR_UNKNOWN_STATE_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
        }
        let Some(mac) = parse_mac(&neigh.mac) else {
            continue;
        };
        state
            .neighbors
            .insert((neigh.ifindex, ip), NeighborEntry { mac });
    }
    Ok(())
}

/// #3771 (M11): true iff `family` is a NON-EMPTY declared address family that
/// does not match the actual family of `ip`. An empty family (older / omitted
/// producer) is unconstrained and never a mismatch; any non-empty non-matching
/// value (including a corrupt/unknown token) fails closed.
fn neighbor_family_mismatch(family: &str, ip: &IpAddr) -> bool {
    let fam = family.trim();
    if fam.is_empty() {
        return false;
    }
    match ip {
        IpAddr::V4(_) => !fam.eq_ignore_ascii_case("inet"),
        IpAddr::V6(_) => !fam.eq_ignore_ascii_case("inet6"),
    }
}

pub(super) fn populate_fabrics(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) {
    for fabric in &snapshot.fabrics {
        // #3773 (M13): resolve the peer address + local/peer MAC through the
        // build-time iface/neighbor context, then classify the skip-vs-install
        // decision through the SHARED helper so this snapshot-build path and
        // the runtime-refresh path (`resolve_fabric_links_from_snapshots`)
        // stay in lockstep. A skipped link is COUNTED (malformed vs
        // unresolved-peer) and RECORDED by name in `state.fabric_skips` — no
        // more silent `continue`.
        let peer_addr = fabric.peer_address.parse::<IpAddr>().ok();
        let local_mac = parse_mac(&fabric.local_mac)
            .or_else(|| iface_ctx.mac_by_ifindex.get(&fabric.parent_ifindex).copied());
        let peer_mac = peer_addr.and_then(|addr| {
            parse_mac(&fabric.peer_mac).or_else(|| {
                state
                    .neighbors
                    .get(&(fabric.overlay_ifindex, addr))
                    .or_else(|| state.neighbors.get(&(fabric.parent_ifindex, addr)))
                    .map(|entry| entry.mac)
            })
        });
        match crate::afxdp::forwarding::build_fabric_link_or_skip(
            fabric, peer_addr, local_mac, peer_mac,
        ) {
            Ok(link) => state.fabrics.push(link),
            Err(skip) => state.fabric_skips.push(skip),
        }
    }
}

/// #2389: resolve EVERY configured next-hop of a static route into a
/// `RouteNextHopV4` candidate. A discard / next-table route has no forwarding
/// next-hop (returns empty). An explicit interface resolves when it belongs to
/// the route's canonical table. In a Go-marked forwarding-instance table, an
/// explicit default-instance interface in routing domain zero is also accepted
/// for a qualified gateway (#11420, #11684) or an interface-only `@interface`
/// member (#12036); other explicit cross-instance interfaces stay unresolved
/// and never fall back to gateway inference.
/// At FIB construction, bare gateways first infer from connected prefixes in
/// their own canonical table (#4446), then recursively resolve through
/// same-table static routes; the terminal gateway and egress ifindex are baked
/// into the member because lookup consumes `nh.next_hop` and `nh.ifindex`.
/// Candidates whose interface fails to resolve are retained with ifindex 0.
pub(in crate::afxdp) fn resolve_route_next_hops_v4(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
) -> Vec<RouteNextHopV4> {
    resolve_route_next_hops_v4_with_routes(
        route,
        names,
        linux_names,
        state,
        table,
        &RecursiveGatewayRoutes::default(),
    )
}

fn resolve_route_next_hops_v4_with_routes(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
    recursive_routes: &RecursiveGatewayRoutes<'_>,
) -> Vec<RouteNextHopV4> {
    if route.discard || !route.next_table.is_empty() {
        return Vec::new();
    }
    route
        .next_hops
        .iter()
        .enumerate()
        .map(|(index, nh)| {
            let weight = route
                .next_hop_weights
                .get(index)
                .copied()
                .filter(|weight| *weight != 0)
                .unwrap_or(1);
            let (parsed_next_hop, interface) = parse_route_next_hop(nh.as_str());
            let allow_forwarding_instance_default_interface =
                parsed_next_hop.is_some() || nh.starts_with('@');
            let (next_hop, ifindex, tunnel_endpoint_id) = resolve_next_hop_target_v4(
                parsed_next_hop,
                interface.as_deref(),
                allow_forwarding_instance_default_interface,
                names,
                linux_names,
                state,
                table,
                recursive_routes,
            );
            let logical_interface = interface
                .as_deref()
                .filter(|name| names.contains_key(*name))
                .or_else(|| {
                    state
                        .ifindex_to_config_name
                        .get(&ifindex)
                        .map(String::as_str)
                })
                .or(interface.as_deref())
                .unwrap_or("");
            RouteNextHopV4 {
                next_hop,
                ifindex,
                logical_interface_id: crate::afxdp::types::ecmp_logical_interface_id(
                    logical_interface,
                ),
                tunnel_endpoint_id,
                weight,
            }
        })
        .collect()
}

pub(in crate::afxdp) fn resolve_route_next_hops_v6(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
) -> Vec<RouteNextHopV6> {
    resolve_route_next_hops_v6_with_routes(
        route,
        names,
        linux_names,
        state,
        table,
        &RecursiveGatewayRoutes::default(),
    )
}

fn resolve_route_next_hops_v6_with_routes(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
    recursive_routes: &RecursiveGatewayRoutes<'_>,
) -> Vec<RouteNextHopV6> {
    if route.discard || !route.next_table.is_empty() {
        return Vec::new();
    }
    route
        .next_hops
        .iter()
        .enumerate()
        .map(|(index, nh)| {
            let weight = route
                .next_hop_weights
                .get(index)
                .copied()
                .filter(|weight| *weight != 0)
                .unwrap_or(1);
            let (parsed_next_hop, interface) = parse_route_next_hop_v6(nh.as_str());
            let allow_forwarding_instance_default_interface =
                parsed_next_hop.is_some() || nh.starts_with('@');
            let (next_hop, ifindex, tunnel_endpoint_id) = resolve_next_hop_target_v6(
                parsed_next_hop,
                interface.as_deref(),
                allow_forwarding_instance_default_interface,
                names,
                linux_names,
                state,
                table,
                recursive_routes,
            );
            let logical_interface = interface
                .as_deref()
                .filter(|name| names.contains_key(*name))
                .or_else(|| {
                    state
                        .ifindex_to_config_name
                        .get(&ifindex)
                        .map(String::as_str)
                })
                .or(interface.as_deref())
                .unwrap_or("");
            RouteNextHopV6 {
                next_hop,
                ifindex,
                logical_interface_id: crate::afxdp::types::ecmp_logical_interface_id(
                    logical_interface,
                ),
                tunnel_endpoint_id,
                weight,
            }
        })
        .collect()
}

fn route_table_instance(table: &str) -> Option<&str> {
    if table == "inet.0" || table == "inet6.0" {
        return Some("");
    }
    let instance = table
        .strip_suffix(".inet.0")
        .or_else(|| table.strip_suffix(".inet6.0"))?;
    (!instance.is_empty()).then_some(instance)
}

fn explicit_ifindex_in_route_table(
    name: &str,
    allow_forwarding_instance_default_interface: bool,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
) -> Option<i32> {
    let route_instance = route_table_instance(table)?;
    let ifindex = resolve_ifindex(name, names, linux_names)?;
    let interface_instance = state.ifindex_to_routing_instance.get(&ifindex)?;
    if interface_instance == route_instance {
        return Some(ifindex);
    }
    let is_default_domain = state
        .ifindex_to_routing_domain
        .get(&ifindex)
        .copied()
        .unwrap_or(0)
        == 0;
    (allow_forwarding_instance_default_interface
        && interface_instance.is_empty()
        && is_default_domain
        && state.forwarding_tables.contains(table))
    .then_some(ifindex)
}

fn resolve_next_hop_target_v4(
    next_hop: Option<Ipv4Addr>,
    interface: Option<&str>,
    allow_forwarding_instance_default_interface: bool,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
    recursive_routes: &RecursiveGatewayRoutes<'_>,
) -> (Option<Ipv4Addr>, i32, u16) {
    if let Some(name) = interface {
        return explicit_ifindex_in_route_table(
            name,
            allow_forwarding_instance_default_interface,
            names,
            linux_names,
            state,
            table,
        )
        .map(|ifindex| {
            (
                next_hop,
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .unwrap_or((next_hop, 0, 0));
    }
    let Some(ip) = next_hop else {
        return (None, 0, 0);
    };
    if let Some((ifindex, tunnel_endpoint_id)) = infer_connected_route_target_v4(state, ip, table) {
        return (Some(ip), ifindex, tunnel_endpoint_id);
    }
    recursive_gateway_target_v4(state, recursive_routes, ip, table, names, linux_names)
        .map(|(gateway, ifindex, tunnel_endpoint_id)| (Some(gateway), ifindex, tunnel_endpoint_id))
        .unwrap_or((Some(ip), 0, 0))
}

fn resolve_next_hop_target_v6(
    next_hop: Option<Ipv6Addr>,
    interface: Option<&str>,
    allow_forwarding_instance_default_interface: bool,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
    recursive_routes: &RecursiveGatewayRoutes<'_>,
) -> (Option<Ipv6Addr>, i32, u16) {
    if let Some(name) = interface {
        return explicit_ifindex_in_route_table(
            name,
            allow_forwarding_instance_default_interface,
            names,
            linux_names,
            state,
            table,
        )
        .map(|ifindex| {
            (
                next_hop,
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .unwrap_or((next_hop, 0, 0));
    }
    let Some(ip) = next_hop else {
        return (None, 0, 0);
    };
    if let Some((ifindex, tunnel_endpoint_id)) = infer_connected_route_target_v6(state, ip, table) {
        return (Some(ip), ifindex, tunnel_endpoint_id);
    }
    recursive_gateway_target_v6(state, recursive_routes, ip, table, names, linux_names)
        .map(|(gateway, ifindex, tunnel_endpoint_id)| (Some(gateway), ifindex, tunnel_endpoint_id))
        .unwrap_or((Some(ip), 0, 0))
}

/// Route literals are family-checked by `populate_routes` before this parser is
/// called. Without that guard, a valid IPv6 gateway on an IPv4 route would
/// silently produce `(None, None)` and the route would become NoRoute.
pub(in crate::afxdp) fn parse_route_next_hop(spec: &str) -> (Option<Ipv4Addr>, Option<String>) {
    let (ip_part, if_part) = if let Some((lhs, rhs)) = spec.split_once('@') {
        (lhs, rhs)
    } else {
        (spec, "")
    };
    let ip = if ip_part.is_empty() {
        None
    } else {
        ip_part.parse::<Ipv4Addr>().ok()
    };
    let iface = if if_part.is_empty() {
        None
    } else {
        Some(if_part.to_string())
    };
    (ip, iface)
}

pub(in crate::afxdp) fn parse_route_next_hop_v6(spec: &str) -> (Option<Ipv6Addr>, Option<String>) {
    let (ip_part, if_part) = if let Some((lhs, rhs)) = spec.split_once('@') {
        (lhs, rhs)
    } else {
        (spec, "")
    };
    let ip = if ip_part.is_empty() {
        None
    } else {
        ip_part.parse::<Ipv6Addr>().ok()
    };
    let iface = if if_part.is_empty() {
        None
    } else {
        Some(if_part.to_string())
    };
    (ip, iface)
}

pub(in crate::afxdp) fn resolve_ifindex(
    name: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
) -> Option<i32> {
    names
        .get(name)
        .copied()
        .or_else(|| linux_names.get(name).copied())
}

pub(in crate::afxdp) fn infer_connected_route_target_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
) -> Option<(i32, u16)> {
    // #4446: Gateway -> egress-interface inference at FIB-build time:
    // "which interface in the ROUTE'S OWN table can reach this next-hop
    // gateway IP". The connected scan is filtered on `entry.table == table`
    // (the canonical install table threaded from `populate_routes`),
    // mirroring the #2388 lookup-site connected filter. Without the filter
    // the scan was GLOBAL and a bare-gateway static route in VRF A could
    // bind VRF B's overlapping connected prefix -> cross-VRF wrong egress:
    // the inferred ifindex is baked into `RouteEntryV4.next_hops` and used
    // verbatim at lookup, so the lookup-time #2388 filter could NOT correct
    // it. A route-leak / next-table cross-VRF reach is not affected: a
    // leaked route is emitted as a `NextTable` snapshot with no forwarding
    // next-hop (never reaches this inference), and the recursion re-resolves
    // in the target table's own scope. `connected_v4` is sorted
    // longest-prefix-first, so the first in-table match is the most specific.
    state
        .connected_v4
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}

pub(in crate::afxdp) fn infer_connected_route_target_v6(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
) -> Option<(i32, u16)> {
    if ip.is_unicast_link_local() {
        // #11322: the daemon adds a synthetic fe80::/64 candidate for every
        // IPv6-capable interface. Mirror that with connected IPv6 rows in this
        // table, not only rows whose observed prefix contains the gateway:
        // link-local addresses may be absent from a snapshot. Address scope is
        // carried from the interface snapshot: only RT_SCOPE_UNIVERSE (0) is
        // an eligible candidate. This excludes incidental kernel LINK rows
        // (such as networkd's automatic fe80 address) while preserving an
        // explicitly configured link-local address, whose configured scope is
        // Universe. As before, only infer when candidates collapse to one
        // egress; returning the first sorted entry would forward ambiguously.
        let mut target: Option<(i32, u16)> = None;
        for entry in state
            .connected_v6
            .iter()
            .filter(|entry| entry.table == table && entry.scope == 0)
        {
            let candidate = (entry.ifindex, entry.tunnel_endpoint_id);
            match target {
                Some(existing) if existing != candidate => return None,
                Some(_) => {}
                None => target = Some(candidate),
            }
        }
        return target;
    }

    // #4446: table-scoped gateway inference — see
    // `infer_connected_route_target_v4` for the full rationale. Global
    // next-hops keep longest-prefix selection.
    state
        .connected_v6
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}
