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
//! Also hosts private route-target resolution helpers used while building FIB rows.

use super::super::*;
use super::interfaces::IfaceIndex;
use crate::RouteSnapshot;
use std::collections::{BTreeMap, HashMap};
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
                .and_then(|rules| {
                    rules
                        .iter()
                        .find(|candidate| leak_identity_matches_v4(candidate, leak))
                })
                .map(|candidate| candidate.incarnation)
                .unwrap_or_else(|| NEXT_LEAK_INCARNATION.fetch_add(1, Ordering::Relaxed));
        }
    }
    for (table, leaks) in &mut state.leak_rules_v6 {
        let old = previous.and_then(|prev| prev.leak_rules_v6.get(table));
        for leak in leaks {
            leak.incarnation = old
                .and_then(|rules| {
                    rules
                        .iter()
                        .find(|candidate| leak_identity_matches_v6(candidate, leak))
                })
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
            return Err(
                crate::policy::SnapshotIntegrityError::RouteNextHopFamilyMismatch {
                    table: route.table.clone(),
                    destination: route.destination.clone(),
                    next_hop: next_hop.clone(),
                },
            );
        }
    }
    Ok(())
}

/// Snapshot-order-independent prefix index used during FIB construction.
/// Each route table is keyed by canonical network and prefix length, making
/// recursive longest-prefix selection bounded by the address width.
#[derive(Default)]
struct RecursiveGatewayRoutes<'a> {
    v4: BTreeMap<String, HashMap<(u32, u8), Vec<&'a RouteSnapshot>>>,
    v6: BTreeMap<String, HashMap<(u128, u8), Vec<&'a RouteSnapshot>>>,
}

#[cfg(test)]
thread_local! {
    static RECURSIVE_CANDIDATE_EXAMINATIONS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_candidate_examination() {
    RECURSIVE_CANDIDATE_EXAMINATIONS.with(|count| count.set(count.get() + 1));
}

#[cfg(not(test))]
#[inline(always)]
fn note_candidate_examination() {}

#[cfg(test)]
fn candidate_examinations() -> u64 {
    RECURSIVE_CANDIDATE_EXAMINATIONS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn reset_candidate_examinations() {
    RECURSIVE_CANDIDATE_EXAMINATIONS.with(|count| count.set(0));
}

impl<'a> RecursiveGatewayRoutes<'a> {
    fn from_snapshot(snapshot: &'a ConfigSnapshot) -> Self {
        let mut index = Self::default();
        for route in &snapshot.routes {
            if let Ok(prefix) = route.destination.parse::<Ipv4Net>() {
                let prefix = PrefixV4::from_net(prefix);
                let table = canonical_route_table(&route.table, false).into_owned();
                index
                    .v4
                    .entry(table)
                    .or_default()
                    .entry((u32::from(prefix.addr()), prefix.prefix_len()))
                    .or_default()
                    .push(route);
            } else if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
                let prefix = PrefixV6::from_net(prefix);
                let table = canonical_route_table(&route.table, true).into_owned();
                index
                    .v6
                    .entry(table)
                    .or_default()
                    .entry((u128::from(prefix.addr()), prefix.prefix_len()))
                    .or_default()
                    .push(route);
            }
        }
        for prefixes in index.v4.values_mut() {
            for routes in prefixes.values_mut() {
                routes.sort_by_key(|route| route.preference);
            }
        }
        for prefixes in index.v6.values_mut() {
            for routes in prefixes.values_mut() {
                routes.sort_by_key(|route| route.preference);
            }
        }
        index
    }

    fn v4_candidates(&self, ip: Ipv4Addr, table: &str) -> Option<&[&'a RouteSnapshot]> {
        let prefixes = self.v4.get(table)?;
        let address = u32::from(ip);
        for len in (0..=32).rev() {
            note_candidate_examination();
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            if let Some(routes) = prefixes.get(&(address & mask, len as u8)) {
                return Some(routes);
            }
        }
        None
    }

    fn v6_candidates(&self, ip: Ipv6Addr, table: &str) -> Option<&[&'a RouteSnapshot]> {
        let prefixes = self.v6.get(table)?;
        let address = u128::from(ip);
        for len in (0..=128).rev() {
            note_candidate_examination();
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            if let Some(routes) = prefixes.get(&(address & mask, len as u8)) {
                return Some(routes);
            }
        }
        None
    }
}

const MAX_RECURSIVE_STATIC_DEPTH: usize = 8;
// Limit total recursive route/gateway probes per authored next-hop. This turns
// adversarial branching route graphs into bounded, fail-closed work.
const MAX_RECURSIVE_STATIC_WORK: usize = 512;

// Recursive ECMP weights multiply along a route chain (authored weight ×
// covering-member weight). Keep that explicit policy in the u32 ABI by
// saturating on overflow; duplicate terminal paths sum with the same bound.
fn route_member_weight(route: &RouteSnapshot, index: usize) -> u32 {
    route
        .next_hop_weights
        .get(index)
        .copied()
        .filter(|weight| *weight != 0)
        .unwrap_or(1)
}

type RecursiveTargetV4 = (Ipv4Addr, i32, u16, u32);
type RecursiveTargetV6 = (Ipv6Addr, i32, u16, u32);

fn recursive_static_target_v4<'a>(
    state: &ForwardingState,
    routes: &RecursiveGatewayRoutes<'a>,
    ip: Ipv4Addr,
    table: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    excluded_routes: &mut [Option<&'a RouteSnapshot>; MAX_RECURSIVE_STATIC_DEPTH],
    visited: &mut [Option<Ipv4Addr>; MAX_RECURSIVE_STATIC_DEPTH],
    depth: usize,
    work: &mut usize,
) -> Vec<RecursiveTargetV4> {
    if depth >= MAX_RECURSIVE_STATIC_DEPTH || visited[..depth].contains(&Some(ip)) || *work == 0 {
        return Vec::new();
    }
    *work -= 1;
    visited[depth] = Some(ip);
    let Some(prefixes) = routes.v4.get(table) else {
        return Vec::new();
    };
    let address = u32::from(ip);
    for prefix_len in (0..=32).rev() {
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let Some(matching) = prefixes.get(&(address & mask, prefix_len as u8)) else {
            continue;
        };
        let mut offset = 0;
        while offset < matching.len() {
            while offset < matching.len()
                && excluded_routes[..=depth]
                    .iter()
                    .flatten()
                    .any(|excluded| std::ptr::eq(matching[offset], *excluded))
            {
                offset += 1;
            }
            if offset == matching.len() {
                break;
            }
            let route = matching[offset];
            offset += 1;
            if route.discard {
                return Vec::new();
            }
            if !route.next_table.is_empty() {
                continue;
            }
            let mut expanded = Vec::new();
            for (index, spec) in route.next_hops.iter().enumerate() {
                if *work == 0 {
                    break;
                }
                *work -= 1;
                let weight = route_member_weight(route, index);
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
                        let endpoint = state
                            .tunnel_endpoint_by_ifindex
                            .get(&ifindex)
                            .copied()
                            .unwrap_or(0);
                        expanded.push((gateway.unwrap_or(ip), ifindex, endpoint, weight));
                    }
                    continue;
                }
                let Some(gateway) = gateway else {
                    continue;
                };
                if let Some((ifindex, endpoint)) =
                    infer_connected_route_target_v4(state, gateway, table)
                {
                    expanded.push((gateway, ifindex, endpoint, weight));
                    continue;
                }
                if depth + 1 < MAX_RECURSIVE_STATIC_DEPTH {
                    excluded_routes[depth + 1] = Some(route);
                }
                let children = recursive_static_target_v4(
                    state,
                    routes,
                    gateway,
                    table,
                    names,
                    linux_names,
                    excluded_routes,
                    visited,
                    depth + 1,
                    work,
                );
                if depth + 1 < MAX_RECURSIVE_STATIC_DEPTH {
                    excluded_routes[depth + 1] = None;
                }
                expanded.extend(children.into_iter().map(
                    |(terminal, ifindex, endpoint, child_weight)| {
                        (
                            terminal,
                            ifindex,
                            endpoint,
                            weight.saturating_mul(child_weight),
                        )
                    },
                ));
                if *work == 0 {
                    return Vec::new();
                }
            }
            if *work == 0 {
                return Vec::new();
            }
            if !expanded.is_empty() {
                return merge_recursive_targets_v4(expanded);
            }
        }
    }
    Vec::new()
}

fn merge_recursive_targets_v4(targets: Vec<RecursiveTargetV4>) -> Vec<RecursiveTargetV4> {
    let mut merged = BTreeMap::new();
    for (gateway, ifindex, endpoint, weight) in targets {
        let total = merged.entry((gateway, ifindex, endpoint)).or_insert(0u32);
        *total = total.saturating_add(weight);
    }
    merged
        .into_iter()
        .map(|((gateway, ifindex, endpoint), weight)| (gateway, ifindex, endpoint, weight))
        .collect()
}

fn recursive_static_target_v6<'a>(
    state: &ForwardingState,
    routes: &RecursiveGatewayRoutes<'a>,
    ip: Ipv6Addr,
    table: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    excluded_routes: &mut [Option<&'a RouteSnapshot>; MAX_RECURSIVE_STATIC_DEPTH],
    visited: &mut [Option<Ipv6Addr>; MAX_RECURSIVE_STATIC_DEPTH],
    depth: usize,
    work: &mut usize,
) -> Vec<RecursiveTargetV6> {
    // Link-local next hops have no global table scope and must never recurse.
    if ip.is_unicast_link_local()
        || depth >= MAX_RECURSIVE_STATIC_DEPTH
        || visited[..depth].contains(&Some(ip))
        || *work == 0
    {
        return Vec::new();
    }
    *work -= 1;
    visited[depth] = Some(ip);
    let Some(prefixes) = routes.v6.get(table) else {
        return Vec::new();
    };
    let address = u128::from(ip);
    for prefix_len in (0..=128).rev() {
        let mask = if prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - prefix_len)
        };
        let Some(matching) = prefixes.get(&(address & mask, prefix_len as u8)) else {
            continue;
        };
        let mut offset = 0;
        while offset < matching.len() {
            while offset < matching.len()
                && excluded_routes[..=depth]
                    .iter()
                    .flatten()
                    .any(|excluded| std::ptr::eq(matching[offset], *excluded))
            {
                offset += 1;
            }
            if offset == matching.len() {
                break;
            }
            let route = matching[offset];
            offset += 1;
            if route.discard {
                return Vec::new();
            }
            if !route.next_table.is_empty() {
                continue;
            }
            let mut expanded = Vec::new();
            let mut blocks_walk_up = false;
            for (index, spec) in route.next_hops.iter().enumerate() {
                if *work == 0 {
                    break;
                }
                *work -= 1;
                let weight = route_member_weight(route, index);
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
                        let endpoint = state
                            .tunnel_endpoint_by_ifindex
                            .get(&ifindex)
                            .copied()
                            .unwrap_or(0);
                        expanded.push((gateway.unwrap_or(ip), ifindex, endpoint, weight));
                    }
                    continue;
                }
                let Some(gateway) = gateway else {
                    continue;
                };
                if gateway.is_unicast_link_local() {
                    blocks_walk_up = true;
                    continue;
                }
                if let Some((ifindex, endpoint)) =
                    infer_connected_route_target_v6(state, gateway, table)
                {
                    expanded.push((gateway, ifindex, endpoint, weight));
                    continue;
                }
                if depth + 1 < MAX_RECURSIVE_STATIC_DEPTH {
                    excluded_routes[depth + 1] = Some(route);
                }
                let children = recursive_static_target_v6(
                    state,
                    routes,
                    gateway,
                    table,
                    names,
                    linux_names,
                    excluded_routes,
                    visited,
                    depth + 1,
                    work,
                );
                if depth + 1 < MAX_RECURSIVE_STATIC_DEPTH {
                    excluded_routes[depth + 1] = None;
                }
                expanded.extend(children.into_iter().map(
                    |(terminal, ifindex, endpoint, child_weight)| {
                        (
                            terminal,
                            ifindex,
                            endpoint,
                            weight.saturating_mul(child_weight),
                        )
                    },
                ));
                if *work == 0 {
                    return Vec::new();
                }
            }
            if *work == 0 {
                return Vec::new();
            }
            if !expanded.is_empty() {
                return merge_recursive_targets_v6(expanded);
            }
            if blocks_walk_up {
                // Preserve the unresolved terminal as an ifindex-zero member.
                // This marker prevents every parent from walking up to a
                // global default route after a nested bare link-local gateway.
                return vec![(ip, 0, 0, 1)];
            }
        }
    }
    Vec::new()
}

fn merge_recursive_targets_v6(targets: Vec<RecursiveTargetV6>) -> Vec<RecursiveTargetV6> {
    let mut merged = BTreeMap::new();
    for (gateway, ifindex, endpoint, weight) in targets {
        let total = merged.entry((gateway, ifindex, endpoint)).or_insert(0u32);
        *total = total.saturating_add(weight);
    }
    merged
        .into_iter()
        .map(|((gateway, ifindex, endpoint), weight)| (gateway, ifindex, endpoint, weight))
        .collect()
}

fn recursive_gateway_target_v4<'a>(
    state: &ForwardingState,
    routes: &RecursiveGatewayRoutes<'a>,
    ip: Ipv4Addr,
    table: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    excluded_route: &'a RouteSnapshot,
) -> Vec<RecursiveTargetV4> {
    let mut work = MAX_RECURSIVE_STATIC_WORK;
    let mut visited = [None; MAX_RECURSIVE_STATIC_DEPTH];
    let mut excluded_routes = [None; MAX_RECURSIVE_STATIC_DEPTH];
    excluded_routes[0] = Some(excluded_route);
    recursive_static_target_v4(
        state,
        routes,
        ip,
        table,
        names,
        linux_names,
        &mut excluded_routes,
        &mut visited,
        0,
        &mut work,
    )
}

fn recursive_gateway_target_v6<'a>(
    state: &ForwardingState,
    routes: &RecursiveGatewayRoutes<'a>,
    ip: Ipv6Addr,
    table: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    excluded_route: &'a RouteSnapshot,
) -> Vec<RecursiveTargetV6> {
    let mut work = MAX_RECURSIVE_STATIC_WORK;
    let mut visited = [None; MAX_RECURSIVE_STATIC_DEPTH];
    let mut excluded_routes = [None; MAX_RECURSIVE_STATIC_DEPTH];
    excluded_routes[0] = Some(excluded_route);
    recursive_static_target_v6(
        state,
        routes,
        ip,
        table,
        names,
        linux_names,
        &mut excluded_routes,
        &mut visited,
        0,
        &mut work,
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
                && !state
                    .connected_v4
                    .iter()
                    .any(|connected| connected.table == table && connected.prefix == prefix)
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
                && !state
                    .connected_v6
                    .iter()
                    .any(|connected| connected.table == table && connected.prefix == prefix)
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
            return Err(
                crate::policy::SnapshotIntegrityError::NeighborFamilyMismatch {
                    interface: neigh.interface.clone(),
                    ip: neigh.ip.clone(),
                    family: neigh.family.clone(),
                },
            );
        }
        // #11033: a usable NUD row must not make a connected subnet
        // directed-broadcast destination forwardable on its own egress.
        if crate::afxdp::forwarding::is_connected_v4_directed_broadcast(state, neigh.ifindex, ip) {
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
pub(crate) fn neighbor_family_mismatch(family: &str, ip: &IpAddr) -> bool {
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
        let local_mac = parse_mac(&fabric.local_mac).or_else(|| {
            iface_ctx
                .mac_by_ifindex
                .get(&fabric.parent_ifindex)
                .copied()
        });
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
        .flat_map(|(index, nh)| {
            let weight = route_member_weight(route, index);
            let (parsed_next_hop, interface) = parse_route_next_hop(nh.as_str());
            let targets = resolve_next_hop_target_v4(
                parsed_next_hop,
                interface.as_deref(),
                parsed_next_hop.is_some() || nh.starts_with('@'),
                names,
                linux_names,
                state,
                table,
                recursive_routes,
                route,
            );
            targets.into_iter().map(
                move |(next_hop, ifindex, tunnel_endpoint_id, recursive_weight)| {
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
                        weight: weight.saturating_mul(recursive_weight),
                    }
                },
            )
        })
        .collect()
}

/// #2389: resolve every authored IPv6 next-hop to one or more terminal members.
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
        .flat_map(|(index, nh)| {
            let weight = route_member_weight(route, index);
            let (parsed_next_hop, interface) = parse_route_next_hop_v6(nh.as_str());
            let targets = resolve_next_hop_target_v6(
                parsed_next_hop,
                interface.as_deref(),
                parsed_next_hop.is_some() || nh.starts_with('@'),
                names,
                linux_names,
                state,
                table,
                recursive_routes,
                route,
            );
            targets.into_iter().map(
                move |(next_hop, ifindex, tunnel_endpoint_id, recursive_weight)| {
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
                        weight: weight.saturating_mul(recursive_weight),
                    }
                },
            )
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
    excluded_route: &RouteSnapshot,
) -> Vec<(Option<Ipv4Addr>, i32, u16, u32)> {
    if let Some(name) = interface {
        let ifindex = explicit_ifindex_in_route_table(
            name,
            allow_forwarding_instance_default_interface,
            names,
            linux_names,
            state,
            table,
        )
        .unwrap_or(0);
        return vec![(
            next_hop,
            ifindex,
            state
                .tunnel_endpoint_by_ifindex
                .get(&ifindex)
                .copied()
                .unwrap_or(0),
            1,
        )];
    }
    let Some(ip) = next_hop else {
        return vec![(None, 0, 0, 1)];
    };
    if let Some((ifindex, endpoint)) = infer_connected_route_target_v4(state, ip, table) {
        return vec![(Some(ip), ifindex, endpoint, 1)];
    }
    let expanded = recursive_gateway_target_v4(
        state,
        recursive_routes,
        ip,
        table,
        names,
        linux_names,
        excluded_route,
    );
    if expanded.is_empty() {
        vec![(Some(ip), 0, 0, 1)]
    } else {
        expanded
            .into_iter()
            .map(|(gateway, ifindex, endpoint, weight)| (Some(gateway), ifindex, endpoint, weight))
            .collect()
    }
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
    excluded_route: &RouteSnapshot,
) -> Vec<(Option<Ipv6Addr>, i32, u16, u32)> {
    if let Some(name) = interface {
        let ifindex = explicit_ifindex_in_route_table(
            name,
            allow_forwarding_instance_default_interface,
            names,
            linux_names,
            state,
            table,
        )
        .unwrap_or(0);
        return vec![(
            next_hop,
            ifindex,
            state
                .tunnel_endpoint_by_ifindex
                .get(&ifindex)
                .copied()
                .unwrap_or(0),
            1,
        )];
    }
    let Some(ip) = next_hop else {
        return vec![(None, 0, 0, 1)];
    };
    if let Some((ifindex, endpoint)) = infer_connected_route_target_v6(state, ip, table) {
        return vec![(Some(ip), ifindex, endpoint, 1)];
    }
    // #12398 B1: ambiguous link-local gateways never recurse globally.
    if ip.is_unicast_link_local() {
        return vec![(Some(ip), 0, 0, 1)];
    }
    let expanded = recursive_gateway_target_v6(
        state,
        recursive_routes,
        ip,
        table,
        names,
        linux_names,
        excluded_route,
    );
    if expanded.is_empty() {
        vec![(Some(ip), 0, 0, 1)]
    } else {
        expanded
            .into_iter()
            .map(|(gateway, ifindex, endpoint, weight)| (Some(gateway), ifindex, endpoint, weight))
            .collect()
    }
}

/// Route literals are family-checked by `populate_routes` before this parser is
/// called. Without that guard, a valid IPv6 gateway on an IPv4 route would
/// silently produce `(None, None)` and the route would become NoRoute.
fn parse_route_next_hop(spec: &str) -> (Option<Ipv4Addr>, Option<String>) {
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

fn parse_route_next_hop_v6(spec: &str) -> (Option<Ipv6Addr>, Option<String>) {
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

fn resolve_ifindex(
    name: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
) -> Option<i32> {
    names
        .get(name)
        .copied()
        .or_else(|| linux_names.get(name).copied())
}

fn infer_connected_route_target_v4(
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

fn infer_connected_route_target_v6(
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
#[cfg(test)]
mod recursive_cycle_guard_12398_tests {
    use super::*;

    #[test]
    fn repeated_gateway_is_rejected_before_static_lookup_12398() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "ge-0-0-1".into(),
                ifindex: 201,
                addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "192.0.2.1/24".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            routes: vec![RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "10.14.0.0/24".into(),
                next_hops: vec!["192.0.2.254".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        let routes = RecursiveGatewayRoutes::from_snapshot(&snapshot);
        let gateway = Ipv4Addr::new(10, 14, 0, 1);
        let mut visited = [None; MAX_RECURSIVE_STATIC_DEPTH];
        visited[0] = Some(gateway);
        let mut work = MAX_RECURSIVE_STATIC_WORK;
        let mut excluded_routes = [None; MAX_RECURSIVE_STATIC_DEPTH];
        excluded_routes[0] = Some(&snapshot.routes[0]);

        let resolved = recursive_static_target_v4(
            &state,
            &routes,
            gateway,
            "inet.0",
            &BTreeMap::new(),
            &BTreeMap::new(),
            &mut excluded_routes,
            &mut visited,
            1,
            &mut work,
        );

        assert!(
            resolved.is_empty(),
            "a repeated gateway must be rejected instead of resolving through itself"
        );
    }
}
#[cfg(test)]
mod recursive_prefix_index_12617_tests {
    use super::*;
    use std::time::Instant;

    fn snapshot_v4(count: usize) -> ConfigSnapshot {
        let routes = (0..count)
            .map(|n| RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: format!("10.{}.{}.{} /32", (n >> 16) & 255, (n >> 8) & 255, n & 255)
                    .replace(" ", ""),
                next_hops: vec!["203.0.113.1".into()],
                ..Default::default()
            })
            .collect();
        ConfigSnapshot {
            routes,
            ..Default::default()
        }
    }

    #[test]
    fn recursive_prefix_index_uses_prefix_width_not_table_size_12617() {
        let snapshot = snapshot_v4(65_536);
        let index = RecursiveGatewayRoutes::from_snapshot(&snapshot);
        reset_candidate_examinations();
        let candidates = index
            .v4_candidates("10.0.0.17".parse().unwrap(), "inet.0")
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].destination, "10.0.0.17/32");
        assert_eq!(
            candidate_examinations(),
            1,
            "a /32 hit requires one keyed prefix probe regardless of 65,536 table rows"
        );
        reset_candidate_examinations();
        assert!(index
            .v4_candidates("203.0.113.1".parse().unwrap(), "inet.0")
            .is_none());
        assert_eq!(
            candidate_examinations(),
            33,
            "an IPv4 miss probes at most the 33 prefix lengths"
        );
    }

    #[test]
    fn recursive_prefix_index_keeps_lpm_and_route_tie_order_12617() {
        let snapshot = ConfigSnapshot {
            routes: vec![
                RouteSnapshot {
                    table: "inet.0".into(),
                    destination: "10.0.0.0/8".into(),
                    preference: 1,
                    ..Default::default()
                },
                RouteSnapshot {
                    table: "inet.0".into(),
                    destination: "10.1.0.0/16".into(),
                    preference: 20,
                    ..Default::default()
                },
                RouteSnapshot {
                    table: "inet.0".into(),
                    destination: "10.1.0.0/16".into(),
                    preference: 10,
                    ..Default::default()
                },
                RouteSnapshot {
                    table: "inet.0".into(),
                    destination: "0.0.0.0/0".into(),
                    preference: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let index = RecursiveGatewayRoutes::from_snapshot(&snapshot);
        let routes = index
            .v4_candidates("10.1.2.3".parse().unwrap(), "inet.0")
            .unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].preference, 10);
        assert_eq!(routes[1].preference, 20);
        assert_eq!(
            index
                .v4_candidates("11.1.2.3".parse().unwrap(), "inet.0")
                .unwrap()[0]
                .destination,
            "0.0.0.0/0"
        );
    }

    #[test]
    fn recursive_prefix_index_ipv6_hit_and_miss_are_bounded_12617() {
        let snapshot = ConfigSnapshot {
            routes: vec![RouteSnapshot {
                table: "inet6.0".into(),
                destination: "2001:db8:1::/64".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let index = RecursiveGatewayRoutes::from_snapshot(&snapshot);
        reset_candidate_examinations();
        assert_eq!(
            index
                .v6_candidates("2001:db8:1::42".parse().unwrap(), "inet6.0")
                .unwrap()[0]
                .destination,
            "2001:db8:1::/64"
        );
        assert_eq!(candidate_examinations(), 65);
        reset_candidate_examinations();
        assert!(index
            .v6_candidates("2001:db8:2::42".parse().unwrap(), "inet6.0")
            .is_none());
        assert_eq!(candidate_examinations(), 129);
    }

    #[test]
    fn recursive_static_probe_budget_exhausts_closed_at_512_12617() {
        let misses = (1..=511).map(|n| format!("192.0.{}.{}", 2 + n / 256, n % 256));
        let mut next_hops: Vec<String> = misses.collect();
        next_hops.push("198.51.100.1".into());
        let snapshot = ConfigSnapshot {
            routes: vec![
                RouteSnapshot {
                    table: "inet.0".into(),
                    destination: "10.0.0.0/24".into(),
                    next_hops,
                    ..Default::default()
                },
                RouteSnapshot {
                    table: "inet.0".into(),
                    destination: "198.51.100.1/32".into(),
                    next_hops: vec!["192.0.4.1".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let index = RecursiveGatewayRoutes::from_snapshot(&snapshot);
        let mut state = ForwardingState::default();
        state.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net("192.0.4.0/24".parse().unwrap()),
            host: "192.0.4.1".parse().unwrap(),
            ifindex: 7,
            tunnel_endpoint_id: 0,
            table: "inet.0".into(),
        });
        let mut work = MAX_RECURSIVE_STATIC_WORK;
        let mut excluded_routes = [None; MAX_RECURSIVE_STATIC_DEPTH];
        excluded_routes[0] = Some(&snapshot.routes[1]);
        let resolved = recursive_static_target_v4(
            &state,
            &index,
            "10.0.0.1".parse().unwrap(),
            "inet.0",
            &BTreeMap::new(),
            &BTreeMap::new(),
            &mut excluded_routes,
            &mut [None; MAX_RECURSIVE_STATIC_DEPTH],
            0,
            &mut work,
        );
        assert!(
            resolved.is_empty(),
            "the reachable terminal beyond the budget must fail closed"
        );
        assert_eq!(
            work, 0,
            "the 512th recursive probe consumes the whole budget"
        );
    }

    #[test]
    #[ignore = "manual learned-table build scaling probe for issue #12617"]
    fn recursive_prefix_index_build_scaling_probe_12617() {
        for count in [1_000, 4_000, 16_000, 65_000] {
            let snapshot = snapshot_v4(count);
            let started = Instant::now();
            let state = build_forwarding_state(&snapshot);
            println!(
                "rows={count} full_build_us={}",
                started.elapsed().as_micros()
            );
            std::hint::black_box(state);
        }
    }
}
