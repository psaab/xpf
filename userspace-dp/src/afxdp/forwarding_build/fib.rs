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

pub(super) fn sort_connected(state: &mut ForwardingState) {
    state
        .connected_v4
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    state
        .connected_v6
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
}

pub(super) fn populate_routes(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    use crate::policy::SnapshotIntegrityError;
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
            // #4446: compute the route's canonical install table BEFORE
            // resolving its next-hops, so a bare-gateway static route infers
            // its egress ifindex ONLY from a connected prefix in its OWN
            // table (mirrors the #2388 lookup-site connected filter, but at
            // BUILD time so the correct ifindex is baked into RouteEntryV4).
            let table = canonical_route_table(&route.table, false).into_owned();
            let next_hops = resolve_route_next_hops_v4(
                route,
                &iface_ctx.name_to_ifindex,
                &iface_ctx.linux_to_ifindex,
                state,
                &table,
            );
            let prefix = PrefixV4::from_net(prefix);
            if !route.next_table.is_empty() {
                state
                    .leak_rules_v4
                    .entry(table)
                    .or_default()
                    .push(LeakRuleV4 {
                        prefix,
                        next_table: canonical_next_table(&route.next_table, false).into_owned(),
                        rule_priority: route.rule_priority,
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
            // #4446: canonical install table computed before next-hop
            // resolution (see the v4 arm) so the connected-prefix inference
            // is scoped to the route's own table.
            let table = canonical_route_table(&route.table, true).into_owned();
            let next_hops = resolve_route_next_hops_v6(
                route,
                &iface_ctx.name_to_ifindex,
                &iface_ctx.linux_to_ifindex,
                state,
                &table,
            );
            let prefix = PrefixV6::from_net(prefix);
            if !route.next_table.is_empty() {
                state
                    .leak_rules_v6
                    .entry(table)
                    .or_default()
                    .push(LeakRuleV6 {
                        prefix,
                        next_table: canonical_next_table(&route.next_table, true).into_owned(),
                        rule_priority: route.rule_priority,
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
    // #2390: order each ordinary table by descending prefix length (longest-
    // match first), then ASCENDING preference (lower = more preferred per
    // Junos), so `routes.iter().find(prefix.contains)` returns the most-
    // specific and, among same-prefix routes, the operator-preferred one.
    // `sort_by` is stable, so same-prefix / same-preference routes keep their
    // relative (insertion) order.
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
    // #9955: leaks are ip rules, not FIB routes. Their priority is the only
    // ordering key in stage one; prefix length is deliberately ignored.
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
/// `RouteNextHopV4` candidate. A discard / next-table route has no
/// forwarding next-hop (returns empty). Each candidate resolves its egress
/// ifindex from an explicit `@interface` spec, else by inferring the
/// connected interface that contains the gateway IP — scoped to the
/// route's own canonical `table` (#4446) so a gateway is never resolved
/// against another routing-instance's overlapping connected prefix. This
/// mirrors the #2388 lookup-site connected filter, applied here at BUILD
/// time so the correct ifindex is baked into `RouteEntryV4.next_hops` (the
/// lookup consumes `nh.ifindex` verbatim, so a wrong build-time bind could
/// not be corrected at lookup). Candidates whose interface fails to resolve
/// are still retained with ifindex 0 (matching the pre-#2389 single-next-hop
/// fallback, which kept next_hop with ifindex 0).
pub(in crate::afxdp) fn resolve_route_next_hops_v4(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
) -> Vec<RouteNextHopV4> {
    if route.discard || !route.next_table.is_empty() {
        return Vec::new();
    }
    route
        .next_hops
        .iter()
        .map(|nh| {
            let (next_hop, interface) = parse_route_next_hop(nh.as_str());
            let (ifindex, tunnel_endpoint_id) = resolve_next_hop_target_v4(
                next_hop,
                interface.as_deref(),
                names,
                linux_names,
                state,
                table,
            );
            RouteNextHopV4 {
                next_hop,
                ifindex,
                tunnel_endpoint_id,
            }
        })
        .collect()
}

/// #2389/#4446: v6 twin of [`resolve_route_next_hops_v4`]. `table` is the
/// route's canonical install table; a bare-gateway static route infers its
/// egress ifindex only from a connected prefix in that table (never a
/// different routing-instance's overlapping prefix).
pub(in crate::afxdp) fn resolve_route_next_hops_v6(
    route: &RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
) -> Vec<RouteNextHopV6> {
    if route.discard || !route.next_table.is_empty() {
        return Vec::new();
    }
    route
        .next_hops
        .iter()
        .map(|nh| {
            let (next_hop, interface) = parse_route_next_hop_v6(nh.as_str());
            let (ifindex, tunnel_endpoint_id) = resolve_next_hop_target_v6(
                next_hop,
                interface.as_deref(),
                names,
                linux_names,
                state,
                table,
            );
            RouteNextHopV6 {
                next_hop,
                ifindex,
                tunnel_endpoint_id,
            }
        })
        .collect()
}

fn resolve_next_hop_target_v4(
    next_hop: Option<Ipv4Addr>,
    interface: Option<&str>,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
) -> (i32, u16) {
    interface
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .map(|ifindex| {
            (
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v4(state, ip, table)))
        .unwrap_or((0, 0))
}

fn resolve_next_hop_target_v6(
    next_hop: Option<Ipv6Addr>,
    interface: Option<&str>,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
    table: &str,
) -> (i32, u16) {
    interface
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .map(|ifindex| {
            (
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v6(state, ip, table)))
        .unwrap_or((0, 0))
}

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
    // #4446: table-scoped gateway inference — see
    // `infer_connected_route_target_v4` for the full rationale.
    state
        .connected_v6
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}
