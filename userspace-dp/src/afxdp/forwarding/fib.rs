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

/// #18560: `classify_metadata` plus the post-advance generation grace (see
/// `MetadataGenerationGrace`). Returns the disposition and whether the grace
/// admitted a packet the strict classifier would have dropped. The strict
/// path is unchanged and runs first, so a current-stamped packet pays nothing.
#[inline]
pub(in crate::afxdp) fn classify_metadata_with_grace(
    meta: UserspaceDpMeta,
    validation: ValidationState,
    grace: MetadataGenerationGrace,
    now_ns: u64,
) -> (PacketDisposition, bool) {
    let disposition = classify_metadata(meta, validation);
    match disposition {
        PacketDisposition::ConfigGenerationMismatch | PacketDisposition::FibGenerationMismatch
            if grace.admits(meta.config_generation, meta.fib_generation, validation, now_ns) =>
        {
            match meta.addr_family as i32 {
                libc::AF_INET | libc::AF_INET6 => (PacketDisposition::Valid, true),
                _ => (PacketDisposition::UnsupportedPacket, false),
            }
        }
        other => (other, false),
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
    if table == DEFAULT_V4_TABLE
        || table == DEFAULT_V6_TABLE
        || table.ends_with(".inet.0")
        || table.ends_with(".inet6.0")
    {
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
) -> ForwardingLookupResult {
    let Some(dst) = parse_packet_destination(area, desc, meta) else {
        return no_route_lookup_result(ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
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
        });
    };
    lookup_forwarding_resolution_with_dynamic(state, dynamic_neighbors, dst)
}

#[cfg(test)]
pub(in crate::afxdp) fn lookup_forwarding_for_ip(
    state: &ForwardingState,
    dst: IpAddr,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution(state, dst)
}

pub(in crate::afxdp) fn lookup_forwarding_resolution(
    state: &ForwardingState,
    dst: IpAddr,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_inner(state, None, dst, None)
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, None)
}

/// #2734/#11402: like `lookup_forwarding_resolution_with_dynamic`, but selects
/// a weighted ECMP next-hop by the per-FLOW 5-tuple hash (from the session
/// forward key), spreading flows across live members in proportion to weight.
/// Used by the session forwarding-resolution path.
pub(in crate::afxdp) fn lookup_forwarding_resolution_with_dynamic_for_flow(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
    flow_key: &crate::session::SessionKey,
) -> ForwardingLookupResult {
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
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_inner_ecmp(
        state,
        Some(dynamic_neighbors),
        dst,
        Some(table),
        Some(ecmp_hash_flow(flow_key)),
    )
}

/// #15118: decide whether `dst` is firewall-local *for this packet*.
///
/// `local_v*` mixes two sets: configured interface addresses (local for every
/// packet in their table) and NAT externals registered for proxy-ARP/ND and
/// ownership. A NAT external is local only when a translate rule could match
/// this packet's protocol, ports, source and ingress scope, or when every
/// translation targets a configured interface address (DNAT/static-to-self:
/// the translated packet is host-bound). Otherwise the address is a routed
/// host's address that merely shares an IP with a scoped NAT rule, and the
/// caller must fall through to the FIB instead of LocalDelivering it.
/// `icmp` carries the packet's ICMP type/code when known.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(in crate::afxdp) fn nat_destination_claims_local(
    state: &ForwardingState,
    dst: IpAddr,
    protocol: u8,
    src_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    ingress_zone: &str,
    ingress_ifname: &str,
    ingress_routing_instance: &str,
    icmp: Option<(u8, u8)>,
) -> bool {
    // A to-self translation is host-bound only for flows its rule matches:
    // DNAT 203.0.113.53 tcp/443 -> 10.0.61.1 does not make tcp/22 to the VIP
    // host-bound. The match check below is therefore not bypassed; to-self
    // only matters through the ordinary FIB on the translated target, which
    // the poll path resolves separately. Kept as a named binding so the
    // registration metadata stays visible at this decision point.
    let _to_self_registered = match dst {
        IpAddr::V4(v4) => state.local_nat_to_self_v4.contains_key(&v4),
        IpAddr::V6(v6) => state.local_nat_to_self_v6.contains_key(&v6),
    };
    state.dnat_table.nat_local_match_possible(
        protocol,
        src_ip,
        dst,
        src_port,
        dst_port,
        ingress_zone,
        ingress_ifname,
        ingress_routing_instance,
        icmp,
    ) || state.static_nat.nat_local_match_possible(
        protocol,
        src_ip,
        dst,
        dst_port,
        ingress_zone,
        ingress_ifname,
        ingress_routing_instance,
    )
}

/// #15118: scoped sibling of [`lookup_forwarding_resolution_with_dynamic_for_flow`]
/// for a packet whose destination was *not* translated. When the destination
/// is a NAT-registered address that no rule claims for this flow, the plain
/// FIB result is returned with the NAT local shortcut suppressed; every other
/// destination takes the ordinary lookup unchanged. Callers that already
/// translated the packet resolve the translated target and never reach this
/// helper with the wire destination.
///
/// #15768: `table` is the caller's PBR/native-VRF `route_table_override`
/// (its resolving table; `None` = default `inet.0`/`inet6.0`) and `icmp`
/// carries the packet's ICMP type/code when known, so the scoped claim check
/// sees the same ICMP-constrained rules the pre-routing DNAT lookup saw.
/// Both FIB arms resolve in `table` with the per-flow 5-tuple ECMP hash;
/// `ForwardingLookupResult::selected_route` carries that table's identity
/// (the caller in `poll_descriptor` stamps installing-table provenance from
/// it — pre-fix the helper discarded it and the miss arm hard-coded
/// `resolved_in_table = false`).
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(in crate::afxdp) fn lookup_forwarding_resolution_for_nat_flow(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    flow: &SessionFlow,
    ingress_zone: &str,
    ingress_ifname: &str,
    ingress_routing_instance: &str,
    table: Option<&str>,
    icmp: Option<(u8, u8)>,
) -> ForwardingLookupResult {
    let dst = flow.dst_ip;
    let is_nat_local = match dst {
        IpAddr::V4(v4) => state.local_nat_to_self_v4.contains_key(&v4),
        IpAddr::V6(v6) => state.local_nat_to_self_v6.contains_key(&v6),
    };
    if is_nat_local
        && !nat_destination_claims_local(
            state,
            dst,
            flow.forward_key.protocol,
            flow.src_ip,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
            ingress_zone,
            ingress_ifname,
            ingress_routing_instance,
            icmp,
        )
    {
        return lookup_forwarding_resolution_without_nat_local_inner(
            state,
            dynamic_neighbors,
            dst,
            table,
            Some(ecmp_hash_flow(&flow.forward_key)),
        );
    }
    match dynamic_neighbors {
        Some(neighbors) => match table {
            Some(table) => lookup_forwarding_resolution_with_dynamic_for_flow_in_table(
                state,
                neighbors,
                dst,
                &flow.forward_key,
                table,
            ),
            None => lookup_forwarding_resolution_with_dynamic_for_flow(
                state,
                neighbors,
                dst,
                &flow.forward_key,
            ),
        },
        None => lookup_forwarding_resolution_inner_ecmp(
            state,
            None,
            dst,
            table,
            Some(ecmp_hash_flow(&flow.forward_key)),
        ),
    }
}

/// #15118: FIB lookup with the NAT-external local shortcut suppressed for
/// `dst`. Interface addresses remain local; only the late NAT registration in
/// `local_nat_to_self_*` is bypassed.
///
/// #15768: this no longer deep-clones `ForwardingState`. The suppression is a
/// `Some(dst)` marker threaded through the inner walk into the per-table
/// local-ownership predicates (`local_*_owned_by_table`); the configured-
/// interface exception is evaluated inside those predicates, so an address
/// that is also a configured interface address stays local. The walk
/// allocates nothing beyond the canonical-table `Cow` the ordinary lookup
/// already produces.
pub(in crate::afxdp) fn lookup_forwarding_resolution_without_nat_local(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_without_nat_local_inner(state, dynamic_neighbors, dst, table, None)
}

fn lookup_forwarding_resolution_without_nat_local_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_inner_ecmp_suppressing(
        state,
        dynamic_neighbors,
        dst,
        table,
        ecmp_flow_hash,
        Some(dst),
    )
}

/// #9951: identify the first precedence-ordered leak incarnation that
/// owns this destination for ABA/revocation stamping (NOT necessarily
/// the leak that carried any given packet — see the #15934 note below).
/// This deliberately does not re-run neighbor/ECMP/HA resolution:
/// those mutable inputs can change between the session lookup and provenance
/// stamping, which must never turn a valid leak match into an unstamped one.
/// The first matching leak whose target table has a route is the same
/// precedence-ordered rule selected by the forwarding walk.
///
/// #15934 alignment note: since the #14319 recursive-NoRoute `continue`
/// was restored in the v4 walk (mirroring v6), the FORWARDING walk can
/// select a LATER leak than the one stamped here when an earlier
/// precheck-admitted target resolves `NoRoute` at lookup time (e.g.
/// tunnel-only longest prefix under `allow_tunnels == false`). This
/// provenance stamp intentionally remains the FIRST precheck-admitted
/// leak: the stamp answers "which leak incarnation owns this
/// destination for ABA/revocation purposes" (`leak_incarnation_is_live`
/// — a removed-and-re-added rule must fail closed), not "which leak
/// carried this packet". Re-stamping to the packet's eventual leak
/// would require re-running the mutable neighbor/ECMP/tunnel
/// resolution this function deliberately avoids, and a stamp mismatch
/// is fail-closed in `resolve.rs` (a differing current incarnation
/// yields NoRoute), never a permit. The same divergence pre-exists on
/// v6, whose walk has always continued past recursive NoRoute.
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
            // #16799: a deferred return owns the destination only when
            // the source table misses it; when the source owns it, the
            // return carries nothing and must not be stamped (a stamp
            // would let a later return removal kill a session the
            // source route legitimately carries — fail-closed but
            // wrong). Immediate leaks keep stage-1 ownership.
            // #17852: ownership is only consulted by deferred rows, so
            // the scan runs only when one covering `ip` exists — a
            // table without deferred returns does no ownership walk.
            let Some(rules) = state.leak_rules_v4.get(table.as_ref()) else {
                return None;
            };
            let source_owns = table_has_deferred_leak_v4(state, table.as_ref(), ip)
                && source_table_owns_v4(state, ip, table.as_ref(), true, None);
            rules
                .iter()
                .filter(|leak| leak.prefix.contains(ip))
                .filter(|leak| !leak.post_table || !source_owns)
                .find_map(|leak| {
                    let next_table = canonical_next_table(&leak.next_table, false);
                    table_has_v4_route(state, ip, next_table.as_ref(), true)
                        .then_some(leak.incarnation)
                })
        }
        IpAddr::V6(ip) => {
            let table = source_table
                .map(|name| canonical_route_table(name, true))
                .unwrap_or(Cow::Borrowed(DEFAULT_V6_TABLE));
            if local_v6_owned_by_table(state, ip, table.as_ref()) {
                return None;
            }
            // #17852 (v6 twin): the ownership scan runs only when a
            // deferred return covering `ip` exists; stage-1 leaks never
            // consult it.
            let Some(rules) = state.leak_rules_v6.get(table.as_ref()) else {
                return None;
            };
            let source_owns = table_has_deferred_leak_v6(state, table.as_ref(), ip)
                && source_table_owns_v6(state, ip, table.as_ref(), true, None);
            rules
                .iter()
                .filter(|leak| leak.prefix.contains(ip))
                .filter(|leak| !leak.post_table || !source_owns)
                .find_map(|leak| {
                    let next_table = canonical_next_table(&leak.next_table, true);
                    table_has_v6_route(state, ip, next_table.as_ref(), true)
                        .then_some(leak.incarnation)
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
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, table)
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_inner_ecmp(state, dynamic_neighbors, dst, table, None)
}

/// #2734/#11402: as `lookup_forwarding_resolution_inner`, plus an optional
/// per-flow ECMP spread key. `ecmp_flow_hash = Some(h)` selects a weighted
/// member by the 5-tuple flow hash; `None` falls back to the per-destination
/// hash (#2389 behavior) for callers without a flow context.
pub(in crate::afxdp) fn lookup_forwarding_resolution_inner_ecmp(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_inner_ecmp_suppressing(
        state,
        dynamic_neighbors,
        dst,
        table,
        ecmp_flow_hash,
        None,
    )
}

/// #15768: as `lookup_forwarding_resolution_inner_ecmp`, plus an optional
/// NAT-local suppression marker. `suppress_nat_local = Some(dst)` makes the
/// per-table local-ownership predicates ignore `dst`'s NAT registration
/// (unless `dst` is also a configured interface address) — the #15118
/// unclaimed-NAT walk without cloning `ForwardingState`.
fn lookup_forwarding_resolution_inner_ecmp_suppressing(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> ForwardingLookupResult {
    match dst {
        IpAddr::V4(ip) => {
            let table = table
                .map(|table| canonical_route_table(table, false))
                .unwrap_or(Cow::Borrowed(DEFAULT_V4_TABLE));
            lookup_forwarding_resolution_v4_suppressing(
                state,
                dynamic_neighbors,
                ip,
                &table,
                0,
                true,
                ecmp_flow_hash,
                suppress_nat_local,
            )
        }
        IpAddr::V6(ip) => {
            let table = table
                .map(|table| canonical_route_table(table, true))
                .unwrap_or(Cow::Borrowed(DEFAULT_V6_TABLE));
            lookup_forwarding_resolution_v6_suppressing(
                state,
                dynamic_neighbors,
                ip,
                &table,
                0,
                true,
                ecmp_flow_hash,
                suppress_nat_local,
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
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_v4_suppressing(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        allow_tunnels,
        ecmp_flow_hash,
        None,
    )
}

fn lookup_forwarding_resolution_v4_suppressing(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> ForwardingLookupResult {
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
        false,
        allow_tunnels,
        ecmp_flow_hash,
        suppress_nat_local,
    )
}

#[inline]
fn local_v4_owned_by_table(state: &ForwardingState, ip: Ipv4Addr, table: &str) -> bool {
    local_v4_owned_by_table_suppressing(state, ip, table, None)
}

/// #15768: `suppress_nat_local = Some(dst)` ignores `dst`'s NAT registration
/// for this ownership decision — mirroring the pre-fix clone-and-remove in
/// `lookup_forwarding_resolution_without_nat_local` (which also removed the
/// `local_nat_any_table_*` / `local_tables_*` attributions) — except that a
/// `dst` that is also a configured interface address stays local, exactly as
/// the clone's `configured_iface_*` guard preserved it.
#[inline]
fn local_v4_owned_by_table_suppressing(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
    suppress_nat_local: Option<IpAddr>,
) -> bool {
    if suppress_nat_local == Some(IpAddr::V4(ip))
        && state.local_nat_to_self_v4.contains_key(&ip)
        && !state.configured_iface_v4.contains(&ip)
    {
        return false;
    }
    state.local_v4.contains(&ip)
        && (state.local_nat_any_table_v4.contains(&ip)
            || state
                .local_tables_v4
                .get(&ip)
                .is_some_and(|tables| tables.contains(table)))
}

/// #14319: whether a route entry can serve a lookup. A route whose every
/// next-hop is a tunnel endpoint cannot serve a tunnel-forbidden lookup
/// (`allow_tunnels == false`); an entry with no next-hops (connected
/// marker) is backed by the connected scan below, not by this check.
#[inline]
fn route_entry_usable_v4(entry: &RouteEntryV4, allow_tunnels: bool) -> bool {
    allow_tunnels
        || entry.next_hops.is_empty()
        || entry.next_hops.iter().any(|nh| nh.tunnel_endpoint_id == 0)
}

#[inline]
fn route_entry_usable_v6(entry: &RouteEntryV6, allow_tunnels: bool) -> bool {
    allow_tunnels
        || entry.next_hops.is_empty()
        || entry.next_hops.iter().any(|nh| nh.tunnel_endpoint_id == 0)
}

/// #14319: IPv6 subnet-router anycast ownership (#10692): the network
/// address of a connected prefix in `table`, mirroring the else-arm of
/// `local_delivery_resolution_v6` so the precheck admits exactly what the
/// leak-target lookup would local-deliver.
#[inline]
fn subnet_router_anycast_v6_owned_by_table(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
) -> bool {
    state.connected_v6.iter().any(|entry| {
        entry.table == table
            && (1..127).contains(&entry.prefix.prefix_len())
            && entry.prefix.addr() == ip
    })
}

#[inline]
fn table_has_v4_route(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
    allow_tunnels: bool,
) -> bool {
    table_has_v4_route_suppressing(state, ip, table, allow_tunnels, None)
}

#[inline]
fn table_has_v4_route_suppressing(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
    allow_tunnels: bool,
    suppress_nat_local: Option<IpAddr>,
) -> bool {
    state.routes_v4.get(table).is_some_and(|routes| {
        routes.iter().any(|entry| {
            entry.next_table.is_empty()
                && entry.prefix.contains(ip)
                && route_entry_usable_v4(entry, allow_tunnels)
        })
    }) || state.connected_v4.iter().any(|entry| {
        entry.table == table
            && entry.prefix.contains(ip)
            && (allow_tunnels || entry.tunnel_endpoint_id == 0)
    }) || local_v4_owned_by_table_suppressing(state, ip, table, suppress_nat_local)
        || state
            .interface_nat_tables_v4
            .get(&ip)
            .is_some_and(|tables| tables.contains(table))
}

/// #16799: true when `table`'s own lookup owns `ip` — a usable ordinary
/// route entry, a connected prefix, or a per-table local/NAT/anycast
/// ownership — so a deferred (post-table) rib-group return must NOT
/// steal it. Discard/reject entries count: they are the source table's
/// own terminal answer, which the kernel's l3mdev lookup returns before
/// ever reaching the (1000, 2000) return rules. Entries whose only
/// next-hops are tunnels the caller forbade do not count (they resolve
/// to NoRoute, i.e. a miss).
#[inline]
fn source_table_owns_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
    allow_tunnels: bool,
    suppress_nat_local: Option<IpAddr>,
) -> bool {
    #[cfg(test)]
    record_source_ownership_scan_for_test();
    table_has_v4_route_suppressing(state, ip, table, allow_tunnels, suppress_nat_local)
}

#[inline]
fn source_table_owns_v6(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
    allow_tunnels: bool,
    suppress_nat_local: Option<IpAddr>,
) -> bool {
    #[cfg(test)]
    record_source_ownership_scan_for_test();
    table_has_v6_route_suppressing(state, ip, table, allow_tunnels, suppress_nat_local)
}

/// #17852: true when `table` holds at least one deferred (`post_table`)
/// return row covering `ip` — the exact rule set `try_deferred_leaks_v4`
/// walks. False means the deferred pass would find nothing, so the
/// #16799 source-ownership scan above can be skipped with no observable
/// difference: every consumer of that scan acts only on deferred rows.
#[inline]
fn table_has_deferred_leak_v4(state: &ForwardingState, table: &str, ip: Ipv4Addr) -> bool {
    state.leak_rules_v4.get(table).is_some_and(|leaks| {
        leaks
            .iter()
            .any(|leak| leak.post_table && leak.prefix.contains(ip))
    })
}

/// #17852: v6 twin of `table_has_deferred_leak_v4`.
#[inline]
fn table_has_deferred_leak_v6(state: &ForwardingState, table: &str, ip: Ipv6Addr) -> bool {
    state.leak_rules_v6.get(table).is_some_and(|leaks| {
        leaks
            .iter()
            .any(|leak| leak.post_table && leak.prefix.contains(ip))
    })
}

// #17852: test-only, thread-local count of source-ownership scans, so
// regression cells can prove lookups and incarnation checks in tables
// without deferred returns do no ownership walk. Zero cost in
// non-test builds (no counter exists there).
#[cfg(test)]
thread_local! {
    static SOURCE_OWNERSHIP_SCANS: std::cell::Cell<usize> = std::cell::Cell::new(0);
}

#[cfg(test)]
pub(in crate::afxdp) fn record_source_ownership_scan_for_test() {
    SOURCE_OWNERSHIP_SCANS.with(|scans| scans.set(scans.get() + 1));
}

#[cfg(test)]
pub(in crate::afxdp) fn source_ownership_scans_for_test() -> usize {
    SOURCE_OWNERSHIP_SCANS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(in crate::afxdp) fn reset_source_ownership_scans_for_test() {
    SOURCE_OWNERSHIP_SCANS.with(|scans| scans.set(0));
}

/// #16799: try the deferred (`post_table`) leaks of `table` in priority
/// order, with the same target-miss fall-through as stage 1 (#9955 /
/// #14319). Returns `Some` only when a deferred target actually
/// resolves (non-NoRoute); otherwise the caller keeps its source-miss
/// (NoRoute) outcome — never a fabricated result.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
fn try_deferred_leaks_v4(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> Option<ForwardingLookupResult> {
    let leaks = state.leak_rules_v4.get(table)?;
    for leak in leaks
        .iter()
        .filter(|leak| leak.post_table && leak.prefix.contains(ip))
    {
        let next_table_name = canonical_next_table(&leak.next_table, false);
        if !table_has_v4_route_suppressing(
            state,
            ip,
            next_table_name.as_ref(),
            allow_tunnels,
            suppress_nat_local,
        ) {
            continue;
        }
        let resolved = lookup_forwarding_resolution_v4_inner(
            state,
            dynamic_neighbors,
            ip,
            next_table_name.as_ref(),
            depth + 1,
            false,
            true,
            allow_tunnels,
            ecmp_flow_hash,
            suppress_nat_local,
        );
        if resolved.resolution.disposition == ForwardingDisposition::NoRoute {
            continue;
        }
        return Some(resolved);
    }
    None
}

#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
fn try_deferred_leaks_v6(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> Option<ForwardingLookupResult> {
    let leaks = state.leak_rules_v6.get(table)?;
    for leak in leaks
        .iter()
        .filter(|leak| leak.post_table && leak.prefix.contains(ip))
    {
        let next_table_name = canonical_next_table(&leak.next_table, true);
        if !table_has_v6_route_suppressing(
            state,
            ip,
            next_table_name.as_ref(),
            allow_tunnels,
            suppress_nat_local,
        ) {
            continue;
        }
        let resolved = lookup_forwarding_resolution_v6_inner(
            state,
            dynamic_neighbors,
            ip,
            next_table_name.as_ref(),
            depth + 1,
            false,
            true,
            allow_tunnels,
            ecmp_flow_hash,
            suppress_nat_local,
        );
        if resolved.resolution.disposition == ForwardingDisposition::NoRoute {
            continue;
        }
        return Some(resolved);
    }
    None
}

#[inline]
fn local_delivery_resolution_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
    include_interface_nat_owner: bool,
) -> Option<ForwardingResolution> {
    local_delivery_resolution_v4_suppressing(state, ip, table, include_interface_nat_owner, None)
}

#[inline]
fn local_delivery_resolution_v4_suppressing(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
    include_interface_nat_owner: bool,
    suppress_nat_local: Option<IpAddr>,
) -> Option<ForwardingResolution> {
    let interface_nat_owner = include_interface_nat_owner
        && state
            .interface_nat_tables_v4
            .get(&ip)
            .is_some_and(|tables| tables.contains(table));
    if !local_v4_owned_by_table_suppressing(state, ip, table, suppress_nat_local)
        && !interface_nat_owner
    {
        return None;
    }
    // #10645: match the row's unmasked HOST address, not the masked
    // `prefix.addr()` network (equal to the host only for a /32 — every
    // wider interface address previously fell through to ifindex 0,
    // collapsing owner-RG attribution and stripping fabric zone stamps).
    // Duplicate host addresses can be shared by interfaces in one table.
    // Pick the lowest ifindex explicitly so local-delivery ownership does not
    // depend on interface snapshot / connected-route insertion order.
    // #15950: peer-owned rows are suppressed from connected_v4 (transit
    // must not be attracted), but host attribution must still find them.
    // Fall back to the by-ifindex LPM (#15917) which retains them.
    let mut local_ifindex = state
        .connected_v4
        .iter()
        .filter(|entry| entry.table == table && entry.host == ip)
        .map(|entry| entry.ifindex)
        .min()
        .unwrap_or(0);
    if local_ifindex == 0 && state.configured_iface_v4.contains(&ip) {
        // Peer-owned interface host suppressed from connected_v4: attribute
        // via its by-ifindex prefix. NAT-only locals are not configured
        // interface addresses and must keep ifindex 0.
        local_ifindex = connected_lpm_ifindex_v4(state, ip, table);
    }
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
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    })
}

#[inline]
fn local_delivery_resolution_v6(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
    include_interface_nat_owner: bool,
) -> Option<ForwardingResolution> {
    local_delivery_resolution_v6_suppressing(state, ip, table, include_interface_nat_owner, None)
}

#[inline]
fn local_delivery_resolution_v6_suppressing(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
    include_interface_nat_owner: bool,
    suppress_nat_local: Option<IpAddr>,
) -> Option<ForwardingResolution> {
    let interface_nat_owner = include_interface_nat_owner
        && state
            .interface_nat_tables_v6
            .get(&ip)
            .is_some_and(|tables| tables.contains(table));
    let local_ifindex = if local_v6_owned_by_table_suppressing(state, ip, table, suppress_nat_local)
        || interface_nat_owner
    {
        // #15950: fall back to by-ifindex LPM for peer-owned hosts (see v4).
        let mut idx = state
            .connected_v6
            .iter()
            .filter(|entry| entry.table == table && entry.host == ip)
            .map(|entry| entry.ifindex)
            .min()
            .unwrap_or(0);
        if idx == 0 && state.configured_iface_v6.contains(&ip) {
            idx = connected_lpm_ifindex_v6(state, ip, table);
        }
        idx
    } else {
        // #10692: subnet-router anycast (see below); peer-owned prefixes
        // live only in the by-ifindex table, so consult it too.
        let mut found = state
            .connected_v6
            .iter()
            .find(|entry| {
                entry.table == table
                    && (1..127).contains(&entry.prefix.prefix_len())
                    && entry.prefix.addr() == ip
            })
            .map(|entry| entry.ifindex);
        if found.is_none() {
            // Anycast network address on a peer-owned prefix: accept only
            // when ip is exactly that prefix's network address.
            for (ifindex, prefixes) in &state.connected_v6_by_ifindex {
                let instance = state
                    .ifindex_to_routing_instance
                    .get(ifindex)
                    .map(String::as_str)
                    .unwrap_or("");
                if !instance_owns_table_v6(instance, table) {
                    continue;
                }
                if prefixes
                    .iter()
                    .any(|p| (1..127).contains(&p.prefix_len()) && p.addr() == ip)
                {
                    found = Some(*ifindex);
                    break;
                }
            }
        }
        found?
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
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    })
}

fn lookup_forwarding_resolution_v4_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    evaluate_leaks: bool,
    include_interface_nat_owner: bool,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> ForwardingLookupResult {
    // Per-table local entries retain their existing priority. Interface-NAT
    // ownership is admitted only for leak-target walks; it is independent of
    // whether this invocation evaluates the leak-rule stage.
    // Both outcomes precede the depth guard.
    if let Some(resolution) = local_delivery_resolution_v4_suppressing(
        state,
        ip,
        table,
        include_interface_nat_owner,
        suppress_nat_local,
    ) {
        return selected_route_lookup_result(state, table, resolution);
    }
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return no_route_lookup_result(ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        });
    }
    if evaluate_leaks {
        // #9955: kernel-model leaks and config-authored next-table routes
        // share the prefix-derived priority sequence. A kernel-model target
        // miss continues to the next rule; a winning config next-table miss
        // is terminal (Junos default reject).
        // #16799: deferred (post_table) rib-group returns remain after the
        // source-table lookup and run only on a source miss.
        let mut config_next_table = junos_next_table_winner_v4(state, ip, table);
        if let Some(leaks) = state.leak_rules_v4.get(table) {
            for leak in leaks
                .iter()
                .filter(|leak| !leak.post_table && leak.prefix.contains(ip))
            {
                if config_next_table
                    .as_ref()
                    .is_some_and(|(priority, winner)| match winner {
                        JunosNextTable::SourceTable { prefix_len } => {
                            *prefix_len >= leak.prefix.prefix_len()
                        }
                        _ => *priority <= leak.rule_priority,
                    })
                {
                    let (_, winner) = config_next_table
                        .take()
                        .expect("the next-table candidate was checked above");
                    return resolve_junos_next_table_v4(
                        state,
                        dynamic_neighbors,
                        ip,
                        table,
                        winner,
                        depth,
                        allow_tunnels,
                        ecmp_flow_hash,
                        suppress_nat_local,
                    );
                }
                let next_table_name = canonical_next_table(&leak.next_table, false);
                if !table_has_v4_route_suppressing(
                    state,
                    ip,
                    next_table_name.as_ref(),
                    allow_tunnels,
                    suppress_nat_local,
                ) {
                    continue;
                }
                // #14319: a recursive NoRoute is a miss, so continue to the
                // next leak and then to the next priority-ordered candidate.
                let resolved = lookup_forwarding_resolution_v4_inner(
                    state,
                    dynamic_neighbors,
                    ip,
                    next_table_name.as_ref(),
                    depth + 1,
                    false,
                    true,
                    allow_tunnels,
                    ecmp_flow_hash,
                    suppress_nat_local,
                );
                if resolved.resolution.disposition == ForwardingDisposition::NoRoute {
                    continue;
                }
                return resolved;
            }
        }
        if let Some((_, winner)) = config_next_table {
            return resolve_junos_next_table_v4(
                state,
                dynamic_neighbors,
                ip,
                table,
                winner,
                depth,
                allow_tunnels,
                ecmp_flow_hash,
                suppress_nat_local,
            );
        }
    }
    // #16799: deferred rib-group returns run only on a genuine source
    // miss, so any source-owned outcome (forward, discard/reject,
    // MissingNeighbor via a selected member) stays authoritative — as
    // the kernel's l3mdev lookup result is before the return rules.
    // #17852: the source-ownership scan is deferred to the miss tail
    // below and runs only when a deferred return covering `ip` exists,
    // so ordinary lookups in tables without deferred returns do no
    // ownership walk (the scan is a pure function of immutable state,
    // so evaluating it after the LPM cannot change any outcome).
    let result = match select_v4_route(state, dynamic_neighbors, ip, table, depth, ecmp_flow_hash) {
        Some(ResolvedRouteV4::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                if !allow_tunnels {
                    return no_route_lookup_result(no_route_resolution(Some(IpAddr::V4(ip))));
                }
                return selected_route_lookup_result(
                    state,
                    table,
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    ),
                );
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
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            selected_route_lookup_result(state, table, resolution)
        }
        Some(ResolvedRouteV4::Static { route, selected }) => {
            if route.discard || route.reject {
                // #16270 (option b; #16217 fold B3): a connected prefix
                // covering `ip` beats this non-cluster terminal ONLY
                // when republication debt is outstanding FOR THAT
                // COVERING PREFIX: a cluster-terminal exists in this
                // table AND the covering connected prefix is absent
                // from `connected_v4` transit (peer-owned suppression,
                // proven by `connected_*_by_ifindex` covering `ip`
                // with no same-prefix transit row). Pre-fold any
                // cluster-terminal ANYWHERE in the table let the win
                // override an operator discard for destinations whose
                // own connected prefix was settled locally. Mixed
                // tables (settled connected + owed elsewhere) keep the
                // operator discard bit-identically.
                let owed_ifindex = if !route.cluster_terminal
                    && table_has_cluster_terminal_v4(state, table)
                    && connected_win_republication_owed_v4(state, table, ip)
                {
                    // Transit row gone (suppressed): recover the egress
                    // from the by-ifindex ledger. Settled row present:
                    // no debt for this prefix, terminal stands.
                    Some(connected_lpm_ifindex_v4(state, ip, table))
                } else {
                    None
                };
                if let Some(ifindex) = owed_ifindex.filter(|i| *i > 0) {
                    {
                        let neighbor = lookup_neighbor_entry(
                            state,
                            dynamic_neighbors,
                            ifindex,
                            IpAddr::V4(ip),
                        );
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
                            source_ifindex: 0,
                            route_mtu: 0,
                            transport_route_mtu: 0,
                        };
                        populate_egress_resolution(state, ifindex, &mut resolution);
                        return selected_route_lookup_result(state, table, resolution);
                    }
                }
                let mut resolution = ForwardingResolution {
                    disposition: if route.cluster_terminal {
                        ForwardingDisposition::ClusterTerminalHAInactive
                    } else if route.reject {
                        ForwardingDisposition::RejectRoute
                    } else {
                        ForwardingDisposition::DiscardRoute
                    },
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
                };
                if route.cluster_terminal {
                    // #15742: stamp the selected forwarding default's
                    // gateway ifindex before the terminal zeroes the
                    // egress, so HA enforcement can attribute the
                    // would-be egress RG for this destination
                    resolution.source_ifindex = select_source_ifindex_v4(state, ip, table);
                }
                return selected_route_lookup_result(state, table, resolution);
            }
            // `select_v4_route` has already selected a member within the
            // preferred live tier, or the preferred drivable member if every
            // tier is unresolved (preserving the MissingNeighbor cold path).
            let (next_hop, ifindex, tunnel_endpoint_id) = match selected {
                Some(nh) => (nh.next_hop, nh.ifindex, nh.tunnel_endpoint_id),
                None => (None, 0, 0),
            };
            if tunnel_endpoint_id != 0 {
                if !allow_tunnels {
                    return no_route_lookup_result(no_route_resolution(
                        next_hop.map(IpAddr::V4).or(Some(IpAddr::V4(ip))),
                    ));
                }
                let mut resolution = resolve_tunnel_forwarding_resolution(
                    state,
                    dynamic_neighbors,
                    tunnel_endpoint_id,
                    depth,
                );
                resolution.route_mtu = route.mtu;
                return selected_route_lookup_result(state, table, resolution);
            }
            if ifindex <= 0 {
                return no_route_lookup_result(no_route_resolution(next_hop.map(IpAddr::V4)));
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
                source_ifindex: 0,
                route_mtu: route.mtu,
                transport_route_mtu: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            selected_route_lookup_result(state, table, resolution)
        }
        None => no_route_lookup_result(no_route_resolution(None)),
    };
    // #16799: deferred rib-group returns run only on a genuine source
    // miss: the LPM produced NoRoute AND the source table owns nothing
    // for `ip`. A source-owned outcome — including MissingNeighbor from
    // a selected-but-unresolved member — is returned bit-identically.
    // #17852: the ownership scan runs only when a deferred return
    // covering `ip` exists (otherwise the deferred pass below would
    // find nothing to try).
    if evaluate_leaks
        && result.resolution.disposition == ForwardingDisposition::NoRoute
        && table_has_deferred_leak_v4(state, table, ip)
        && !source_table_owns_v4(state, ip, table, allow_tunnels, suppress_nat_local)
    {
        if let Some(deferred) = try_deferred_leaks_v4(
            state,
            dynamic_neighbors,
            ip,
            table,
            depth,
            allow_tunnels,
            ecmp_flow_hash,
            suppress_nat_local,
        ) {
            return deferred;
        }
    }
    result
}

pub(in crate::afxdp) fn lookup_forwarding_resolution_v6(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_v6_suppressing(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        allow_tunnels,
        ecmp_flow_hash,
        None,
    )
}

fn lookup_forwarding_resolution_v6_suppressing(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> ForwardingLookupResult {
    lookup_forwarding_resolution_v6_inner(
        state,
        dynamic_neighbors,
        ip,
        table,
        depth,
        true,
        false,
        allow_tunnels,
        ecmp_flow_hash,
        suppress_nat_local,
    )
}

#[inline]
fn local_v6_owned_by_table(state: &ForwardingState, ip: Ipv6Addr, table: &str) -> bool {
    local_v6_owned_by_table_suppressing(state, ip, table, None)
}

/// #15768: v6 twin of `local_v4_owned_by_table_suppressing`.
#[inline]
fn local_v6_owned_by_table_suppressing(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
    suppress_nat_local: Option<IpAddr>,
) -> bool {
    if suppress_nat_local == Some(IpAddr::V6(ip))
        && state.local_nat_to_self_v6.contains_key(&ip)
        && !state.configured_iface_v6.contains(&ip)
    {
        return false;
    }
    state.local_v6.contains(&ip)
        && (state.local_nat_any_table_v6.contains(&ip)
            || state
                .local_tables_v6
                .get(&ip)
                .is_some_and(|tables| tables.contains(table)))
}

#[inline]
fn table_has_v6_route(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
    allow_tunnels: bool,
) -> bool {
    table_has_v6_route_suppressing(state, ip, table, allow_tunnels, None)
}

#[inline]
fn table_has_v6_route_suppressing(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
    allow_tunnels: bool,
    suppress_nat_local: Option<IpAddr>,
) -> bool {
    state.routes_v6.get(table).is_some_and(|routes| {
        routes.iter().any(|entry| {
            entry.next_table.is_empty()
                && entry.prefix.contains(ip)
                && route_entry_usable_v6(entry, allow_tunnels)
        })
    }) || state.connected_v6.iter().any(|entry| {
        entry.table == table
            && entry.prefix.contains(ip)
            && (allow_tunnels || entry.tunnel_endpoint_id == 0)
    }) || local_v6_owned_by_table_suppressing(state, ip, table, suppress_nat_local)
        || state
            .interface_nat_tables_v6
            .get(&ip)
            .is_some_and(|tables| tables.contains(table))
        || subnet_router_anycast_v6_owned_by_table(state, ip, table)
}
fn lookup_forwarding_resolution_v6_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    evaluate_leaks: bool,
    include_interface_nat_owner: bool,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> ForwardingLookupResult {
    if let Some(resolution) = local_delivery_resolution_v6_suppressing(
        state,
        ip,
        table,
        include_interface_nat_owner,
        suppress_nat_local,
    ) {
        return selected_route_lookup_result(state, table, resolution);
    }
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return no_route_lookup_result(ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        });
    }
    if evaluate_leaks {
        // #9955: merge kernel-model rules and config-authored next-table
        // routes by their shared priority. Kernel-model target misses
        // continue; a winning config next-table target miss is terminal.
        // #16799: deferred (post_table) returns remain after the source
        // lookup and run only on a source miss.
        let mut config_next_table = junos_next_table_winner_v6(state, ip, table);
        if let Some(leaks) = state.leak_rules_v6.get(table) {
            for leak in leaks
                .iter()
                .filter(|leak| !leak.post_table && leak.prefix.contains(ip))
            {
                if config_next_table
                    .as_ref()
                    .is_some_and(|(priority, winner)| match winner {
                        JunosNextTable::SourceTable { prefix_len } => {
                            *prefix_len >= leak.prefix.prefix_len()
                        }
                        _ => *priority <= leak.rule_priority,
                    })
                {
                    let (_, winner) = config_next_table
                        .take()
                        .expect("the next-table candidate was checked above");
                    return resolve_junos_next_table_v6(
                        state,
                        dynamic_neighbors,
                        ip,
                        table,
                        winner,
                        depth,
                        allow_tunnels,
                        ecmp_flow_hash,
                        suppress_nat_local,
                    );
                }
                let next_table_name = canonical_next_table(&leak.next_table, true);
                if !table_has_v6_route_suppressing(
                    state,
                    ip,
                    next_table_name.as_ref(),
                    allow_tunnels,
                    suppress_nat_local,
                ) {
                    continue;
                }
                let resolved = lookup_forwarding_resolution_v6_inner(
                    state,
                    dynamic_neighbors,
                    ip,
                    next_table_name.as_ref(),
                    depth + 1,
                    false,
                    true,
                    allow_tunnels,
                    ecmp_flow_hash,
                    suppress_nat_local,
                );
                if resolved.resolution.disposition == ForwardingDisposition::NoRoute {
                    continue;
                }
                return resolved;
            }
        }
        if let Some((_, winner)) = config_next_table {
            return resolve_junos_next_table_v6(
                state,
                dynamic_neighbors,
                ip,
                table,
                winner,
                depth,
                allow_tunnels,
                ecmp_flow_hash,
                suppress_nat_local,
            );
        }
    }
    // #16799/#17852 v6 twin: ownership gates only the deferred miss
    // tail below, and its scan runs only when a deferred return
    // covering `ip` exists.
    let result = match select_v6_route(state, dynamic_neighbors, ip, table, depth, ecmp_flow_hash) {
        Some(ResolvedRouteV6::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                if !allow_tunnels {
                    return no_route_lookup_result(no_route_resolution(Some(IpAddr::V6(ip))));
                }
                return selected_route_lookup_result(
                    state,
                    table,
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    ),
                );
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
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            selected_route_lookup_result(state, table, resolution)
        }
        Some(ResolvedRouteV6::Static { route, selected }) => {
            if route.discard || route.reject {
                // #16270 (option b; #16217 fold B3): v6 twin of the
                // v4 connected-win — only when republication debt is
                // outstanding for THIS covering prefix.
                let owed_ifindex = if !route.cluster_terminal
                    && table_has_cluster_terminal_v6(state, table)
                    && connected_win_republication_owed_v6(state, table, ip)
                {
                    Some(connected_lpm_ifindex_v6(state, ip, table))
                } else {
                    None
                };
                if let Some(ifindex) = owed_ifindex.filter(|i| *i > 0) {
                    {
                        let neighbor = lookup_neighbor_entry(
                            state,
                            dynamic_neighbors,
                            ifindex,
                            IpAddr::V6(ip),
                        );
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
                            source_ifindex: 0,
                            route_mtu: 0,
                            transport_route_mtu: 0,
                        };
                        populate_egress_resolution(state, ifindex, &mut resolution);
                        return selected_route_lookup_result(state, table, resolution);
                    }
                }
                let mut resolution = ForwardingResolution {
                    disposition: if route.cluster_terminal {
                        ForwardingDisposition::ClusterTerminalHAInactive
                    } else if route.reject {
                        ForwardingDisposition::RejectRoute
                    } else {
                        ForwardingDisposition::DiscardRoute
                    },
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
                };
                if route.cluster_terminal {
                    // #15742: see the v4 twin.
                    resolution.source_ifindex = select_source_ifindex_v6(state, ip, table);
                }
                return selected_route_lookup_result(state, table, resolution);
            }
            // See the v4 twin: preserve the preferred tier's cold-path
            // fallback only when no same-prefix tier has a live member.
            let (next_hop, ifindex, tunnel_endpoint_id) = match selected {
                Some(nh) => (nh.next_hop, nh.ifindex, nh.tunnel_endpoint_id),
                None => (None, 0, 0),
            };
            if tunnel_endpoint_id != 0 {
                if !allow_tunnels {
                    return no_route_lookup_result(no_route_resolution(
                        next_hop.map(IpAddr::V6).or(Some(IpAddr::V6(ip))),
                    ));
                }
                let mut resolution = resolve_tunnel_forwarding_resolution(
                    state,
                    dynamic_neighbors,
                    tunnel_endpoint_id,
                    depth,
                );
                resolution.route_mtu = route.mtu;
                return selected_route_lookup_result(state, table, resolution);
            }
            if ifindex <= 0 {
                return no_route_lookup_result(no_route_resolution(next_hop.map(IpAddr::V6)));
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
                source_ifindex: 0,
                route_mtu: route.mtu,
                transport_route_mtu: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            selected_route_lookup_result(state, table, resolution)
        }
        None => no_route_lookup_result(no_route_resolution(None)),
    };
    // #16799: v4 twin — deferred returns only on a genuine source miss.
    // #17852: the ownership scan runs only when a deferred return
    // covering `ip` exists (otherwise the deferred pass below would
    // find nothing to try).
    if evaluate_leaks
        && result.resolution.disposition == ForwardingDisposition::NoRoute
        && table_has_deferred_leak_v6(state, table, ip)
        && !source_table_owns_v6(state, ip, table, allow_tunnels, suppress_nat_local)
    {
        if let Some(deferred) = try_deferred_leaks_v6(
            state,
            dynamic_neighbors,
            ip,
            table,
            depth,
            allow_tunnels,
            ecmp_flow_hash,
            suppress_nat_local,
        ) {
            return deferred;
        }
    }
    result
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
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}
#[inline]
fn selected_route_lookup_result(
    state: &ForwardingState,
    table: &str,
    resolution: ForwardingResolution,
) -> ForwardingLookupResult {
    ForwardingLookupResult {
        resolution,
        selected_route: state.route_table_identities.get(table).copied(),
    }
}

#[inline]
fn no_route_lookup_result(resolution: ForwardingResolution) -> ForwardingLookupResult {
    ForwardingLookupResult {
        resolution,
        selected_route: None,
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
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}

enum JunosNextTable {
    /// Hand the lookup to this (canonical) table; a miss there is
    /// terminal (#16614).
    HandOff(String),
    /// The selected route is itself a next-table route whose target is
    /// unusable (empty): terminal, never a fall-through.
    Terminal,
    /// The main-table LPM selected a configured ordinary/terminal route
    /// more specific than this next-table candidate. Keep its prefix so it
    /// can compete with more-specific kernel leaks before source lookup.
    SourceTable { prefix_len: u8 },
}

/// #17684: merge configured next-table rules with the main-table LPM result.
/// A more-specific ordinary/discard/reject main row participates only when a
/// matching configured next-table route is broader—the same condition under
/// which Go emits its slot-0 static exception. Kernel-model rib-group-only
/// rules retain lookup-first behavior; their main-route parity is outside this
/// bounded exception mechanism.
fn junos_next_table_winner_v4(
    state: &ForwardingState,
    ip: Ipv4Addr,
    table: &str,
) -> Option<(u32, JunosNextTable)> {
    let routes = state.routes_v4.get(table)?;
    let mut best_len: Option<u8> = None;
    for route in routes {
        if !route.prefix.contains(ip) || (!route.next_table_route && !route.next_table.is_empty()) {
            continue;
        }
        let len = route.prefix.prefix_len();
        if best_len.is_some_and(|best| len < best) {
            break;
        }
        if best_len.is_none() {
            if state.connected_v4.iter().any(|connected| {
                connected.table == table
                    && connected.prefix.contains(ip)
                    && connected.prefix.prefix_len() >= len
            }) {
                return None;
            }
            best_len = Some(len);
        }
        if route.next_table_route {
            if route.next_table.is_empty() {
                return Some((route.rule_priority, JunosNextTable::Terminal));
            }
            return Some((
                route.rule_priority,
                JunosNextTable::HandOff(route.next_table.clone()),
            ));
        }
        let more_specific_than_config = routes.iter().any(|candidate| {
            candidate.next_table_route
                && candidate.prefix.contains(ip)
                && candidate.prefix.prefix_len() < len
        });
        if more_specific_than_config {
            return Some((
                route.rule_priority,
                JunosNextTable::SourceTable { prefix_len: len },
            ));
        }
    }
    None
}

fn junos_next_table_winner_v6(
    state: &ForwardingState,
    ip: Ipv6Addr,
    table: &str,
) -> Option<(u32, JunosNextTable)> {
    let routes = state.routes_v6.get(table)?;
    let mut best_len: Option<u8> = None;
    for route in routes {
        if !route.prefix.contains(ip) || (!route.next_table_route && !route.next_table.is_empty()) {
            continue;
        }
        let len = route.prefix.prefix_len();
        if best_len.is_some_and(|best| len < best) {
            break;
        }
        if best_len.is_none() {
            if state.connected_v6.iter().any(|connected| {
                connected.table == table
                    && connected.prefix.contains(ip)
                    && connected.prefix.prefix_len() >= len
            }) {
                return None;
            }
            best_len = Some(len);
        }
        if route.next_table_route {
            if route.next_table.is_empty() {
                return Some((route.rule_priority, JunosNextTable::Terminal));
            }
            return Some((
                route.rule_priority,
                JunosNextTable::HandOff(route.next_table.clone()),
            ));
        }
        let more_specific_than_config = routes.iter().any(|candidate| {
            candidate.next_table_route
                && candidate.prefix.contains(ip)
                && candidate.prefix.prefix_len() < len
        });
        if more_specific_than_config {
            return Some((
                route.rule_priority,
                JunosNextTable::SourceTable { prefix_len: len },
            ));
        }
    }
    None
}

fn resolve_junos_next_table_v4(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    winner: JunosNextTable,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> ForwardingLookupResult {
    match winner {
        JunosNextTable::Terminal => reject_route_lookup_result(),
        JunosNextTable::HandOff(next_table) => {
            let resolved = lookup_forwarding_resolution_v4_inner(
                state,
                dynamic_neighbors,
                ip,
                next_table.as_ref(),
                depth + 1,
                false,
                true,
                allow_tunnels,
                ecmp_flow_hash,
                suppress_nat_local,
            );
            if resolved.resolution.disposition == ForwardingDisposition::NoRoute {
                reject_route_lookup_result()
            } else {
                resolved
            }
        }
        JunosNextTable::SourceTable { .. } => lookup_forwarding_resolution_v4_inner(
            state,
            dynamic_neighbors,
            ip,
            table,
            depth,
            false,
            false,
            allow_tunnels,
            ecmp_flow_hash,
            suppress_nat_local,
        ),
    }
}

fn resolve_junos_next_table_v6(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    winner: JunosNextTable,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
    suppress_nat_local: Option<IpAddr>,
) -> ForwardingLookupResult {
    match winner {
        JunosNextTable::Terminal => reject_route_lookup_result(),
        JunosNextTable::HandOff(next_table) => {
            let resolved = lookup_forwarding_resolution_v6_inner(
                state,
                dynamic_neighbors,
                ip,
                next_table.as_ref(),
                depth + 1,
                false,
                true,
                allow_tunnels,
                ecmp_flow_hash,
                suppress_nat_local,
            );
            if resolved.resolution.disposition == ForwardingDisposition::NoRoute {
                reject_route_lookup_result()
            } else {
                resolved
            }
        }
        JunosNextTable::SourceTable { .. } => lookup_forwarding_resolution_v6_inner(
            state,
            dynamic_neighbors,
            ip,
            table,
            depth,
            false,
            false,
            allow_tunnels,
            ecmp_flow_hash,
            suppress_nat_local,
        ),
    }
}

fn reject_route_lookup_result() -> ForwardingLookupResult {
    no_route_lookup_result(ForwardingResolution {
        disposition: ForwardingDisposition::RejectRoute,
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

enum ResolvedRouteV4<'a> {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static {
        route: &'a RouteEntryV4,
        selected: Option<&'a RouteNextHopV4>,
    },
}

enum ResolvedRouteV6<'a> {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static {
        route: &'a RouteEntryV6,
        selected: Option<&'a RouteNextHopV6>,
    },
}

/// #15917: longest-prefix match over one family's connected
/// prefixes, restricted to interfaces whose routing instance owns
/// `table`. Returns the winning ifindex, or 0 when no in-table
/// interface prefix contains the address. Equal-length ties pick
/// the LOWEST ifindex — the #10645 local-delivery precedent
/// (`local_*_ifindex` uses `.min()`) — so the result never depends
/// on FastMap iteration (hash) order or snapshot insertion order.
///
/// This is the ONLY connected-prefix attribution the cluster-
/// terminal fallback may use. The pre-#15917 global scans of
/// `connected_*_by_ifindex` took the first prefix-containing
/// interface in FastMap (hash) order with no table check, so an
/// overlapping prefix in another VRF could steal the attribution:
/// the HA gate then saw the wrong RG (restoring DiscardRoute for
/// a peer-owned WAN) and the #15906 punt-seed consumers read the
/// wrong zone/owner from the same stamp. Deriving the owning
/// table from `ifindex_to_routing_instance` (compared via the
/// allocation-free `instance_owns_table_*` twins of
/// `connected_route_tables`) keeps this in lockstep with how
/// `populate_interfaces` scoped the transit `connected_v*` rows
/// (#2388) — one source of truth for an interface's table.
/// Interfaces absent from that map are the default instance (the
/// map's documented convention). Runs only on the terminal/miss
/// path, never per forwarded packet.
/// #17053: the session_glue connected attribution (owner RG and
/// connected ifindex for a destination) is built on this same
/// canonical LPM via `connected_lpm_ifindex`. `ConnectedSources`
/// selects which row sets participate; the tie rule, the per-family
/// table scoping (`instance_owns_table_*`) and the precedence
/// (transit rows before the ledger fallback) are defined HERE only,
/// so a scoping or tie fix lands in one place.
/// #15917: does `instance` ("" = default) own the v4 `table`?
/// Spells `connected_route_tables(instance).0 == table` without
/// allocating the canonical pair: the default instance owns only
/// `inet.0`; a named instance owns only `<instance>.inet.0`.
/// `connected_route_tables` remains the build-time spelling
/// authority; this is its allocation-free lookup-time twin, kept
/// next to its only consumers (Opus perf fold on PR #15926).
pub(in crate::afxdp) fn instance_owns_table_v4(instance: &str, table: &str) -> bool {
    if instance.is_empty() {
        table == DEFAULT_V4_TABLE
    } else {
        table.len() == instance.len() + ".inet.0".len()
            && table.starts_with(instance)
            && table[instance.len()..] == *".inet.0"
    }
}

/// #15917: v6 twin of `instance_owns_table_v4`.
pub(in crate::afxdp) fn instance_owns_table_v6(instance: &str, table: &str) -> bool {
    if instance.is_empty() {
        table == DEFAULT_V6_TABLE
    } else {
        table.len() == instance.len() + ".inet6.0".len()
            && table.starts_with(instance)
            && table[instance.len()..] == *".inet6.0"
    }
}

/// #15917: v4 connected-prefix LPM attribution for `table` (see
/// the note above). Longest prefix wins; equal lengths pick the
/// lowest ifindex (#10645 precedent).
pub(in crate::afxdp) fn connected_lpm_ifindex_v4(state: &ForwardingState, ip: Ipv4Addr, table: &str) -> i32 {
    connected_lpm_ifindex(state, IpAddr::V4(ip), Some(table), ConnectedSources::LedgerOnly).unwrap_or(0)
}

/// #15917: v6 twin of `connected_lpm_ifindex_v4`.
pub(in crate::afxdp) fn connected_lpm_ifindex_v6(state: &ForwardingState, ip: Ipv6Addr, table: &str) -> i32 {
    connected_lpm_ifindex(state, IpAddr::V6(ip), Some(table), ConnectedSources::LedgerOnly).unwrap_or(0)
}

/// #17053: which connected row sets `connected_lpm_ifindex` may
/// consult. The canonical LPM defines the longest-prefix / lowest-
/// ifindex tie rule and the per-family table scoping once; callers
/// differ only in which row sets participate.
///
/// * `LedgerOnly` — the #15917 cluster-terminal fallback: only the
///   `connected_*_by_ifindex` ledger (peer-owned prefixes live only
///   there). This is what `connected_lpm_ifindex_{v4,v6}` do.
/// * `RowsThenLedger` — the session_glue attribution: the FIB
///   `connected_v*` transit rows first; the ledger only when no
///   transit row contains the target. Mirrors the legacy
///   session_glue precedence, now with the canonical tie rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) enum ConnectedSources {
    LedgerOnly,
    RowsThenLedger,
}

/// #17053: canonical connected-prefix LPM dispatcher — the single
/// source of truth for connected attribution. Longest prefix wins;
/// equal-length ties pick the LOWEST ifindex (#10645 precedent), so
/// the result never depends on FastMap iteration order or Vec
/// insertion order. `table` is the session's installing table;
/// `None` resolves to the family default (`inet.0` / `inet6.0`),
/// mirroring the legacy wrappers.
///
/// #17053 fold (Rev18099 F1): returns `Option<i32>` — `Some(ifindex)`
/// when an in-scope connected prefix contains `ip` (the winning
/// ifindex itself may be 0 or negative in synthetic states), `None`
/// on no match. The legacy `i32` form returned 0 for BOTH, so a
/// matched winner whose owner RG is 0 was indistinguishable from
/// no-match and the session_glue scan fell through to the
/// interface-NAT tail while the build-time index returned `Hit(0)`.
/// Callers that only need the ifindex map `None` to 0 at the edge.
pub(in crate::afxdp) fn connected_lpm_ifindex(
    state: &ForwardingState,
    ip: IpAddr,
    table: Option<&str>,
    sources: ConnectedSources,
) -> Option<i32> {
    match ip {
        IpAddr::V4(v4) => {
            let want = table.unwrap_or(DEFAULT_V4_TABLE);
            if sources == ConnectedSources::RowsThenLedger {
                let mut best: Option<(u8, i32)> = None;
                for row in &state.connected_v4 {
                    if row.table != want && !row.table.is_empty() {
                        continue;
                    }
                    if row.prefix.contains(v4) {
                        let candidate = (row.prefix.prefix_len(), row.ifindex);
                        best = Some(match best {
                            None => candidate,
                            Some((best_len, best_ifindex))
                                if candidate.0 > best_len
                                    || (candidate.0 == best_len
                                        && candidate.1 < best_ifindex) =>
                            {
                                candidate
                            }
                            Some(current) => current,
                        });
                    }
                }
                if let Some((_, ifindex)) = best {
                    return Some(ifindex);
                }
            }
            connected_lpm_ifindex_ledger_v4(state, v4, want)
        }
        IpAddr::V6(v6) => {
            let want = table.unwrap_or(DEFAULT_V6_TABLE);
            if sources == ConnectedSources::RowsThenLedger {
                let mut best: Option<(u8, i32)> = None;
                for row in &state.connected_v6 {
                    if row.table != want && !row.table.is_empty() {
                        continue;
                    }
                    if row.prefix.contains(v6) {
                        let candidate = (row.prefix.prefix_len(), row.ifindex);
                        best = Some(match best {
                            None => candidate,
                            Some((best_len, best_ifindex))
                                if candidate.0 > best_len
                                    || (candidate.0 == best_len
                                        && candidate.1 < best_ifindex) =>
                            {
                                candidate
                            }
                            Some(current) => current,
                        });
                    }
                }
                if let Some((_, ifindex)) = best {
                    return Some(ifindex);
                }
            }
            connected_lpm_ifindex_ledger_v6(state, v6, want)
        }
    }
}

/// #17053: ledger-only kernel of `connected_lpm_ifindex` (v4).
/// `None` on no match (see the dispatcher note above).
fn connected_lpm_ifindex_ledger_v4(state: &ForwardingState, ip: Ipv4Addr, table: &str) -> Option<i32> {
    let mut best: Option<(u8, i32)> = None;
    for (ifindex, prefixes) in &state.connected_v4_by_ifindex {
        let instance = state
            .ifindex_to_routing_instance
            .get(ifindex)
            .map(String::as_str)
            .unwrap_or("");
        if !instance_owns_table_v4(instance, table) {
            continue;
        }
        for prefix in prefixes {
            if prefix.contains(ip) {
                let candidate = (prefix.prefix_len(), *ifindex);
                best = Some(match best {
                    None => candidate,
                    Some((best_len, best_ifindex))
                        if candidate.0 > best_len
                            || (candidate.0 == best_len && candidate.1 < best_ifindex) =>
                    {
                        candidate
                    }
                    Some(current) => current,
                });
            }
        }
    }
    best.map(|(_, ifindex)| ifindex)
}

/// #17053: ledger-only kernel of `connected_lpm_ifindex` (v6).
fn connected_lpm_ifindex_ledger_v6(state: &ForwardingState, ip: Ipv6Addr, table: &str) -> Option<i32> {
    let mut best: Option<(u8, i32)> = None;
    for (ifindex, prefixes) in &state.connected_v6_by_ifindex {
        let instance = state
            .ifindex_to_routing_instance
            .get(ifindex)
            .map(String::as_str)
            .unwrap_or("");
        if !instance_owns_table_v6(instance, table) {
            continue;
        }
        for prefix in prefixes {
            if prefix.contains(ip) {
                let candidate = (prefix.prefix_len(), *ifindex);
                best = Some(match best {
                    None => candidate,
                    Some((best_len, best_ifindex))
                        if candidate.0 > best_len
                            || (candidate.0 == best_len && candidate.1 < best_ifindex) =>
                    {
                        candidate
                    }
                    Some(current) => current,
                });
            }
        }
    }
    best.map(|(_, ifindex)| ifindex)
}

/// #15742: the gateway ifindex of the route that WOULD carry `ip`
/// absent any terminal row: the same live-tier selection
/// `select_v4_route` performs on non-terminal rows (first row with a
/// live member, else the preferred row's drivable member, else the
/// connected prefix at least as specific). Used to stamp a
/// cluster-terminal resolution's would-be egress before the terminal
/// zeroes it, so HA enforcement can attribute the destination's
/// would-be RG. Returns 0 when no forwarding row or connected prefix
/// matches.
fn select_source_ifindex_v4(state: &ForwardingState, ip: Ipv4Addr, table: &str) -> i32 {
    // #15917: table-scoped, longest-prefix attribution over the
    // by-ifindex connected prefixes (peer-owned prefixes live only
    // there). Replaces the global first-match scan.
    let by_ifindex_connected = connected_lpm_ifindex_v4(state, ip, table);
    let connected = state
        .connected_v4
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    if let Some(routes) = state.routes_v4.get(table) {
        let mut iter = routes.iter().filter(|r| {
            r.next_table.is_empty() && !r.discard && !r.reject && r.prefix.contains(ip)
        });
        if let Some(first) = iter.next() {
            if let Some(conn) = connected {
                if conn.prefix.prefix_len() >= first.prefix.prefix_len() {
                    return conn.ifindex;
                }
            }
            // Same live-tier rule as select_v4_route: first row with a
            // live member wins; otherwise remember the preferred row's
            // drivable member.
            let mut fallback_ifindex = 0;
            for route in std::iter::once(first).chain(iter) {
                let hash = ecmp_hash_v4(ip);
                match select_route_next_hop_with_status(
                    &route.next_hops,
                    hash,
                    ecmp_candidate_id_v4,
                    |nh| nh.weight,
                    |nh| {
                        nh.ifindex > 0
                            && state.egress.contains_key(&nh.ifindex)
                            && !state.egress_link_down.contains(&nh.ifindex)
                    },
                    |nh| nh.ifindex > 0,
                ) {
                    Some((nh, true)) => return nh.ifindex,
                    Some((nh, false)) if fallback_ifindex == 0 => fallback_ifindex = nh.ifindex,
                    _ => {}
                }
            }
            if fallback_ifindex > 0 {
                return fallback_ifindex;
            }
            if let Some(conn) = connected {
                return conn.ifindex;
            }
        }
    }
    // #15917: gateway-owner fallback, scoped to this table and
    // longest-prefix selected (was: first global map hit, so a
    // gateway covered in another VRF stole the attribution).
    if let Some(routes) = state.routes_v4.get(table) {
        for route in routes
            .iter()
            .filter(|r| r.next_table.is_empty() && !r.discard && !r.reject && r.prefix.contains(ip))
        {
            for nh in &route.next_hops {
                if let Some(gw) = nh.next_hop {
                    let owner = connected_lpm_ifindex_v4(state, gw, table);
                    if owner > 0 {
                        return owner;
                    }
                }
            }
        }
    }
    // #15742e live shape: no forwarding row survives HA filtering on
    // the split node, so the scan above finds nothing. The would-be
    // egress is still attributable: the destination's own connected
    // prefix (kept in connected_by_ifindex even when suppressed from
    // transit) names the peer-owned WAN unit. Return it so HA
    // enforcement can demote; 0 keeps the plain drop. #15917: both
    // candidates are table-scoped + LPM-selected; the transit-row
    // candidate keeps priority to preserve #15742e ordering.
    connected
        .map(|conn| conn.ifindex)
        .or(if by_ifindex_connected > 0 {
            Some(by_ifindex_connected)
        } else {
            None
        })
        .unwrap_or(0)
}

/// #15742: v6 twin of `select_source_ifindex_v4`.
fn select_source_ifindex_v6(state: &ForwardingState, ip: Ipv6Addr, table: &str) -> i32 {
    // #15917: see the v4 twin.
    let by_ifindex_connected = connected_lpm_ifindex_v6(state, ip, table);
    let connected = state
        .connected_v6
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    if let Some(routes) = state.routes_v6.get(table) {
        let mut iter = routes.iter().filter(|r| {
            r.next_table.is_empty() && !r.discard && !r.reject && r.prefix.contains(ip)
        });
        if let Some(first) = iter.next() {
            if let Some(conn) = connected {
                if conn.prefix.prefix_len() >= first.prefix.prefix_len() {
                    return conn.ifindex;
                }
            }
            let mut fallback_ifindex = 0;
            for route in std::iter::once(first).chain(iter) {
                let hash = ecmp_hash_v6(ip);
                match select_route_next_hop_with_status(
                    &route.next_hops,
                    hash,
                    ecmp_candidate_id_v6,
                    |nh| nh.weight,
                    |nh| {
                        nh.ifindex > 0
                            && state.egress.contains_key(&nh.ifindex)
                            && !state.egress_link_down.contains(&nh.ifindex)
                    },
                    |nh| nh.ifindex > 0,
                ) {
                    Some((nh, true)) => return nh.ifindex,
                    Some((nh, false)) if fallback_ifindex == 0 => fallback_ifindex = nh.ifindex,
                    _ => {}
                }
            }
            if fallback_ifindex > 0 {
                return fallback_ifindex;
            }
            if let Some(conn) = connected {
                return conn.ifindex;
            }
        }
    }
    // #15917: see the v4 twin.
    if let Some(routes) = state.routes_v6.get(table) {
        for route in routes
            .iter()
            .filter(|r| r.next_table.is_empty() && !r.discard && !r.reject && r.prefix.contains(ip))
        {
            for nh in &route.next_hops {
                if let Some(gw) = nh.next_hop {
                    let owner = connected_lpm_ifindex_v6(state, gw, table);
                    if owner > 0 {
                        return owner;
                    }
                }
            }
        }
    }
    // #15742e: see the v4 twin.
    connected
        .map(|conn| conn.ifindex)
        .or(if by_ifindex_connected > 0 {
            Some(by_ifindex_connected)
        } else {
            None
        })
        .unwrap_or(0)
}

/// Choose the most-specific route, then the first live preference/metric row.
/// Same-preference QNH rows stay ordered by the Go producer; each row is an
/// ECMP tier. If every row is unresolved, preserve the preferred row's
/// drivable member so the existing MissingNeighbor path can resolve it.
fn select_v4_route<'a>(
    state: &'a ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    ecmp_flow_hash: Option<u64>,
) -> Option<ResolvedRouteV4<'a>> {
    let connected_match = state
        .connected_v4
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    let mut matched_prefix_len = None;
    let mut fallback: Option<(&'a RouteEntryV4, Option<&'a RouteNextHopV4>)> = None;
    let mut spread_hash = ecmp_flow_hash;

    if let Some(routes) = state.routes_v4.get(table) {
        for route in routes {
            let prefix_len = route.prefix.prefix_len();
            if matched_prefix_len.is_some_and(|best| prefix_len < best) {
                break;
            }
            if !route.next_table.is_empty() || !route.prefix.contains(ip) {
                continue;
            }
            if matched_prefix_len.is_none() {
                matched_prefix_len = Some(prefix_len);
                if let Some(conn) = connected_match {
                    if conn.prefix.prefix_len() >= prefix_len {
                        return Some(ResolvedRouteV4::Connected {
                            ifindex: conn.ifindex,
                            tunnel_endpoint_id: conn.tunnel_endpoint_id,
                        });
                    }
                }
            }
            // Go emits same-preference QNH metric tiers as ordered rows. Each
            // row's next_hops remains ECMP; a later row is tried only when the
            // current tier has no live member.
            if route.discard || route.reject {
                // #15098: reject is a terminal row like discard — it must
                // not fall through to next-hop selection (which would
                // forward traffic the operator asked to reject). Preserve
                // an earlier gateway only when it has a drivable next-hop.
                // An empty/invalid fallback must not suppress this
                // terminal row.
                let fallback_drivable = fallback.is_some_and(|(_, selected)| {
                    selected.is_some_and(|nh| nh.ifindex > 0 || nh.tunnel_endpoint_id != 0)
                });
                if !fallback_drivable {
                    return Some(ResolvedRouteV4::Static {
                        route,
                        selected: None,
                    });
                }
                continue;
            }

            let hash = *spread_hash.get_or_insert_with(|| ecmp_hash_v4(ip));
            let selected = select_route_next_hop_with_status(
                &route.next_hops,
                hash,
                ecmp_candidate_id_v4,
                |nh| nh.weight,
                |nh| {
                    if nh.tunnel_endpoint_id != 0 {
                        return tunnel_next_hop_live(
                            state,
                            dynamic_neighbors,
                            nh.tunnel_endpoint_id,
                            depth,
                        );
                    }
                    // Interface-only members resolve the per-flow destination
                    // lazily; explicit gateways require an installed neighbor.
                    // #11404: a known-down or missing egress row is not live,
                    // but its destination neighbor remains lazy (#5161).
                    if nh.next_hop.is_none() {
                        return nh.ifindex > 0
                            && state.egress.contains_key(&nh.ifindex)
                            && !state.egress_link_down.contains(&nh.ifindex);
                    }
                    let target = nh.next_hop.unwrap_or(ip);
                    nh.ifindex > 0
                        && lookup_neighbor_entry(
                            state,
                            dynamic_neighbors,
                            nh.ifindex,
                            IpAddr::V4(target),
                        )
                        .is_some()
                },
                |nh| nh.ifindex > 0 || nh.tunnel_endpoint_id != 0,
            );
            match selected {
                Some((nh, true)) => {
                    return Some(ResolvedRouteV4::Static {
                        route,
                        selected: Some(nh),
                    });
                }
                selected if fallback.is_none() => {
                    fallback = Some((route, selected.map(|(nh, _)| nh)));
                }
                _ => {}
            }
        }
    }

    fallback
        .map(|(route, selected)| ResolvedRouteV4::Static { route, selected })
        .or_else(|| {
            connected_match.map(|conn| ResolvedRouteV4::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        })
}

/// #16270: with the connected-RG republication still owed (the post-
/// activation FIB lacks the /24 transit row), does `table` hold a
/// cluster-terminal? After a synchronous-with-activation republish
/// this is never true; the slow-path lookup consults it when the
/// republish is delayed so the terminal defers to HAInactive.
fn table_has_cluster_terminal_v4(state: &ForwardingState, table: &str) -> bool {
    state
        .routes_v4
        .get(table)
        .is_some_and(|routes| routes.iter().any(|r| r.cluster_terminal))
}

/// #16270: v6 twin of `table_has_cluster_terminal_v4`.
fn table_has_cluster_terminal_v6(state: &ForwardingState, table: &str) -> bool {
    state
        .routes_v6
        .get(table)
        .is_some_and(|routes| routes.iter().any(|r| r.cluster_terminal))
}

/// #16217 (fold B3): is republication debt outstanding for the
/// CONNECTED PREFIX covering `ip` in `table`? Debt means the
/// covering connected prefix is recorded in `connected_*_by_ifindex`
/// (the peer-owned-suppression ledger — every interface address,
/// owned or suppressed) but the SAME (ifindex, prefix) has no row
/// in `connected_v4`/`connected_v6` transit. The pre-fold guard
/// (`table_has_cluster_terminal_*`) tied the connected-win to ANY
/// cluster-terminal in the table, so a destination whose own
/// connected prefix was settled locally still overrode an operator
/// discard whenever some UNRELATED prefix in the table was owed.
/// "Same prefix" is exact (prefix + ifindex + table): a transit row
/// for the identical prefix proves that prefix was republished.
fn connected_win_republication_owed_v4(state: &ForwardingState, table: &str, ip: Ipv4Addr) -> bool {
    let ifindex = connected_lpm_ifindex_v4(state, ip, table);
    if ifindex <= 0 {
        return false;
    }
    !state
        .connected_v4
        .iter()
        .any(|entry| entry.table == table && entry.ifindex == ifindex && entry.prefix.contains(ip))
}

/// #16217 (fold B3): v6 twin of `connected_win_republication_owed_v4`.
fn connected_win_republication_owed_v6(state: &ForwardingState, table: &str, ip: Ipv6Addr) -> bool {
    let ifindex = connected_lpm_ifindex_v6(state, ip, table);
    if ifindex <= 0 {
        return false;
    }
    !state
        .connected_v6
        .iter()
        .any(|entry| entry.table == table && entry.ifindex == ifindex && entry.prefix.contains(ip))
}

fn select_v6_route<'a>(
    state: &'a ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    ecmp_flow_hash: Option<u64>,
) -> Option<ResolvedRouteV6<'a>> {
    let connected_match = state
        .connected_v6
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    let mut matched_prefix_len = None;
    let mut fallback: Option<(&'a RouteEntryV6, Option<&'a RouteNextHopV6>)> = None;
    let mut spread_hash = ecmp_flow_hash;

    if let Some(routes) = state.routes_v6.get(table) {
        for route in routes {
            let prefix_len = route.prefix.prefix_len();
            if matched_prefix_len.is_some_and(|best| prefix_len < best) {
                break;
            }
            if !route.next_table.is_empty() || !route.prefix.contains(ip) {
                continue;
            }
            if matched_prefix_len.is_none() {
                matched_prefix_len = Some(prefix_len);
                if let Some(conn) = connected_match {
                    if conn.prefix.prefix_len() >= prefix_len {
                        return Some(ResolvedRouteV6::Connected {
                            ifindex: conn.ifindex,
                            tunnel_endpoint_id: conn.tunnel_endpoint_id,
                        });
                    }
                }
            }
            // Preserve same-preference metric-tier row order as in v4: ECMP
            // within a row, fall through to the next row only if all members
            // in the current tier are unavailable.
            if route.discard || route.reject {
                // #15098: keep the v4 reject/discard terminal gate identical.
                let fallback_drivable = fallback.is_some_and(|(_, selected)| {
                    selected.is_some_and(|nh| nh.ifindex > 0 || nh.tunnel_endpoint_id != 0)
                });
                if !fallback_drivable {
                    return Some(ResolvedRouteV6::Static {
                        route,
                        selected: None,
                    });
                }
                continue;
            }

            let hash = *spread_hash.get_or_insert_with(|| ecmp_hash_v6(ip));
            let selected = select_route_next_hop_with_status(
                &route.next_hops,
                hash,
                ecmp_candidate_id_v6,
                |nh| nh.weight,
                |nh| {
                    if nh.tunnel_endpoint_id != 0 {
                        return tunnel_next_hop_live(
                            state,
                            dynamic_neighbors,
                            nh.tunnel_endpoint_id,
                            depth,
                        );
                    }
                    // Interface-only members resolve the per-flow destination
                    // lazily; explicit gateways require an installed neighbor.
                    // #11404: a known-down or missing egress row is not live,
                    // but its destination neighbor remains lazy (#5161).
                    if nh.next_hop.is_none() {
                        return nh.ifindex > 0
                            && state.egress.contains_key(&nh.ifindex)
                            && !state.egress_link_down.contains(&nh.ifindex);
                    }
                    let target = nh.next_hop.unwrap_or(ip);
                    nh.ifindex > 0
                        && lookup_neighbor_entry(
                            state,
                            dynamic_neighbors,
                            nh.ifindex,
                            IpAddr::V6(target),
                        )
                        .is_some()
                },
                |nh| nh.ifindex > 0 || nh.tunnel_endpoint_id != 0,
            );
            match selected {
                Some((nh, true)) => {
                    return Some(ResolvedRouteV6::Static {
                        route,
                        selected: Some(nh),
                    });
                }
                selected if fallback.is_none() => {
                    fallback = Some((route, selected.map(|(nh, _)| nh)));
                }
                _ => {}
            }
        }
    }

    fallback
        .map(|(route, selected)| ResolvedRouteV6::Static { route, selected })
        .or_else(|| {
            connected_match.map(|conn| ResolvedRouteV6::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        })
}

/// #2389/#2734/#11402: select one ECMP next-hop candidate for a forwarding
/// route. Prefers a candidate whose neighbor is resolved (skips a
/// dead/unresolved first next-hop — the load-bearing correctness fix); if
/// several resolve, distributes flows deterministically in proportion to their
/// configured weights; if none resolve, falls back to the same hashed pick so
/// the kernel slow-path can drive ARP/NDP.
///
/// #2734: the spread key is now per-FLOW. The session resolution path
/// threads the 5-tuple flow hash (`ecmp_hash_flow`, the same seeded
/// FxHasher the flow cache already feeds the session 5-tuple — see
/// `ecmp_hash_flow`) into `select_route_next_hop_with_status`; distinct flows
/// to the SAME destination spread across live ECMP members in proportion to
/// their weights, while every packet of one flow remains pinned to one member
/// (flow-consistent, with no intra-flow reordering). Callers without a flow
/// context (tunnel outer resolution, `inject`, bare-dst lookups) pass `None`,
/// which falls back to the per-DESTINATION hash (`ecmp_hash_v4`/`ecmp_hash_v6`)
/// — the #2389 behavior. The retained candidate vector (Vec<RouteNextHop>) is
/// what makes per-flow selection a localized runtime change.
/// Deterministic ECMP spread mixer. A fixed-seed splitmix64 finalizer over
/// the input word — used for the per-destination fallback. Stable across
/// reloads and workers so every worker maps the same input to the same
/// weighted path (a flow's packets never split across paths). Not a
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

fn ecmp_candidate_interface_id(identity: u64, interface_id: u64) -> u64 {
    ecmp_hash_bytes(identity ^ ecmp_hash_bytes(interface_id ^ 0x494e_0000_0000_0001))
}

/// Hash the complete family-specific next-hop tuple with explicit tags for
/// address presence and field boundaries. Logical interface name replaces
/// kernel ifindex so HA peers and renumbered nodes rank the same member.
fn ecmp_candidate_id_v4(candidate: &RouteNextHopV4) -> u64 {
    let mut identity = ecmp_hash_bytes(0x7634_0000_0000_0000);
    identity = match candidate.next_hop {
        Some(ip) => ecmp_hash_bytes(
            identity ^ ecmp_hash_bytes(u32::from(ip) as u64 ^ 0x4e48_0000_0000_0001),
        ),
        None => ecmp_hash_bytes(identity ^ 0x4e48_0000_0000_0000),
    };
    identity = ecmp_candidate_interface_id(identity, candidate.logical_interface_id);
    ecmp_hash_bytes(
        identity ^ ecmp_hash_bytes(candidate.tunnel_endpoint_id as u64 ^ 0x5445_0000_0000_0003),
    )
}

fn ecmp_candidate_id_v6(candidate: &RouteNextHopV6) -> u64 {
    let mut identity = ecmp_hash_bytes(0x7636_0000_0000_0000);
    identity = match candidate.next_hop {
        Some(ip) => {
            let bits = u128::from(ip);
            let identity = ecmp_hash_bytes(identity ^ 0x4e48_0000_0000_0001);
            let identity =
                ecmp_hash_bytes(identity ^ ecmp_hash_bytes(bits as u64 ^ 0x4c4f_0000_0000_0004));
            ecmp_hash_bytes(identity ^ ecmp_hash_bytes((bits >> 64) as u64 ^ 0x4849_0000_0000_0005))
        }
        None => ecmp_hash_bytes(identity ^ 0x4e48_0000_0000_0000),
    };
    identity = ecmp_candidate_interface_id(identity, candidate.logical_interface_id);
    ecmp_hash_bytes(
        identity ^ ecmp_hash_bytes(candidate.tunnel_endpoint_id as u64 ^ 0x5445_0000_0000_0003),
    )
}

/// #2734/#11405: stable per-FLOW ECMP spread key over the session 5-tuple.
///
/// Hashes (`addr_family`/`protocol`/`src_ip`/`dst_ip`/`src_port`/`dst_port`)
/// with a fixed, ECMP-domain-separated `FxHasher` seed. Unlike hot-path cache
/// placement, ECMP selection must remain stable across process restarts and HA
/// re-resolution: a per-process seed can change the selected route while the
/// stored SNAT rewrite remains unchanged. The hot-path secret remains in use
/// for attacker-amplifiable cache/map placement; this public fixed seed is
/// intentionally limited to stable route selection. With the same tuple,
/// candidate identities, and weights, selection is stable across processes.
/// Removing a nonselected candidate leaves surviving scores unchanged; adding
/// a candidate or changing an identity/weight can remap a flow.
pub(in crate::afxdp) const ECMP_FLOW_HASH_SEED: u64 = 0x4543_4d50_0000_0001;

pub(in crate::afxdp) fn ecmp_hash_flow(key: &crate::session::SessionKey) -> u64 {
    ecmp_hash_flow_seeded(ECMP_FLOW_HASH_SEED, key)
}

/// Seed-parameterized core of `ecmp_hash_flow`. Production supplies the fixed
/// `ECMP_FLOW_HASH_SEED`; explicit seeds remain available for reproducibility
/// and for tests of the core's hash behavior.
pub(in crate::afxdp) fn ecmp_hash_flow_seeded(seed: u64, key: &crate::session::SessionKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::with_seed(seed as usize);
    key.hash(&mut hasher);
    hasher.finish()
}

/// #2922/#11403: select one weighted ECMP next-hop in a SINGLE liveness pass.
///
/// The liveness predicate (`is_live`) is NOT pure — the IPv4/IPv6 callers
/// probe the shared dynamic-neighbor map, which the monitor thread mutates
/// concurrently. Evaluating it twice per candidate could observe different
/// states and adds duplicate neighbor-map probes to the hot path.
///
/// The selector snapshots liveness once and uses weighted rendezvous scoring:
/// each candidate's exponential-race score is `-ln(U) / weight`, and the
/// lowest score wins. Candidate identity, not authored position, seeds `U`, so
/// removing one member leaves every surviving member's score unchanged. If no
/// member is live, the same ranking chooses from the ARP-drivable subset, then
/// from the full authored slice.
///
/// #2923: ECMP candidate liveness for a TUNNEL next-hop.
///
/// A tunnel candidate (`tunnel_endpoint_id != 0`) is NOT a neighbor-resolved
/// L2 next-hop on the logical tunnel ifindex, so the direct-neighbor liveness
/// gate (`ifindex > 0 && lookup_neighbor_entry(...)`) always marks it dead.
/// In a MIXED direct+tunnel ECMP group a live direct member makes `live > 0`,
/// which restricts selection to direct candidates and starves the tunnel path
/// even when its underlay is fully up.
///
/// #11423: an endpoint explicitly marked link-down by keepalive is dead even
/// if its outer route remains forwardable. Older snapshots without link state
/// preserve the prior underlay-only liveness behavior.
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
    if state.tunnel_endpoints_down.contains(&tunnel_endpoint_id) {
        return false;
    }
    matches!(
        resolve_tunnel_outer(state, dynamic_neighbors, tunnel_endpoint_id, depth)
            .map(|outer| outer.resolution.disposition),
        Some(ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor)
    )
}

#[cfg(test)]
pub(in crate::afxdp) fn select_route_next_hop<'a, T: Copy>(
    candidates: &'a [T],
    flow_hash: u64,
    candidate_id: impl Fn(&T) -> u64,
    is_live: impl Fn(&T) -> bool,
    is_drivable: impl Fn(&T) -> bool,
) -> Option<&'a T> {
    select_route_next_hop_weighted(
        candidates,
        flow_hash,
        candidate_id,
        |_| 1,
        is_live,
        is_drivable,
    )
}

#[cfg(test)]
pub(in crate::afxdp) fn select_route_next_hop_weighted<'a, T: Copy>(
    candidates: &'a [T],
    flow_hash: u64,
    candidate_id: impl Fn(&T) -> u64,
    weight_of: impl Fn(&T) -> u32,
    is_live: impl Fn(&T) -> bool,
    is_drivable: impl Fn(&T) -> bool,
) -> Option<&'a T> {
    select_route_next_hop_with_status(
        candidates,
        flow_hash,
        candidate_id,
        weight_of,
        is_live,
        is_drivable,
    )
    .map(|(candidate, _)| candidate)
}

/// #2922/#11403: select one equal-cost next-hop in a single liveness pass
/// using weighted rendezvous. The minimum `-ln(U) / weight` wins; with every
/// weight equal to one, this is the original rendezvous ordering. Candidate
/// identity makes scores independent of authored order, so removing a member
/// cannot change the scores of survivors. If none are live, choose the best
/// drivable candidate, falling back to the best overall only when none is
/// drivable. The streaming scan uses constant stack space and never allocates.
fn select_route_next_hop_with_status<'a, T: Copy>(
    candidates: &'a [T],
    flow_hash: u64,
    candidate_id: impl Fn(&T) -> u64,
    weight_of: impl Fn(&T) -> u32,
    is_live: impl Fn(&T) -> bool,
    is_drivable: impl Fn(&T) -> bool,
) -> Option<(&'a T, bool)> {
    if candidates.is_empty() {
        return None;
    }

    #[inline]
    fn score(hash: u64, weight: u32) -> f64 {
        // Weighted rendezvous is an exponential race: choose the smallest
        // -ln(U)/weight. Map 52 high hash bits to open-interval U midpoints so
        // neither logarithm endpoint is reachable.
        const UNIT: f64 = 1.0 / ((1u64 << 52) as f64);
        let unit = ((hash >> 12) as f64 + 0.5) * UNIT;
        -unit.ln() / f64::from(weight.max(1))
    }

    #[inline]
    fn is_better(score: f64, hash: u64, id: u64, best: (f64, u64, u64)) -> bool {
        score < best.0 || (score == best.0 && (hash > best.1 || (hash == best.1 && id > best.2)))
    }

    let mut best_live: Option<(&'a T, f64, u64, u64)> = None;
    for candidate in candidates.iter() {
        if is_live(candidate) {
            let id = candidate_id(candidate);
            let hash = ecmp_hash_bytes(flow_hash ^ id);
            let candidate_score = score(hash, weight_of(candidate));
            if best_live.is_none_or(|(_, best_score, best_hash, best_id)| {
                is_better(candidate_score, hash, id, (best_score, best_hash, best_id))
            }) {
                best_live = Some((candidate, candidate_score, hash, id));
            }
        }
    }
    if let Some((candidate, _, _, _)) = best_live {
        return Some((candidate, true));
    }

    // #11318: when no candidate is live, preserve the drivable subset and
    // legacy all-candidate fallback, using the same stable weighted ranking.
    // A candidate's score is unchanged when the fallback set shrinks.
    let mut best_drivable: Option<(&'a T, f64, u64, u64)> = None;
    let mut best_any: Option<(&'a T, f64, u64, u64)> = None;
    for candidate in candidates.iter() {
        let id = candidate_id(candidate);
        let hash = ecmp_hash_bytes(flow_hash ^ id);
        let candidate_score = score(hash, weight_of(candidate));
        if best_any.is_none_or(|(_, best_score, best_hash, best_id)| {
            is_better(candidate_score, hash, id, (best_score, best_hash, best_id))
        }) {
            best_any = Some((candidate, candidate_score, hash, id));
        }
        if is_drivable(candidate)
            && best_drivable.is_none_or(|(_, best_score, best_hash, best_id)| {
                is_better(candidate_score, hash, id, (best_score, best_hash, best_id))
            })
        {
            best_drivable = Some((candidate, candidate_score, hash, id));
        }
    }
    best_drivable
        .or(best_any)
        .map(|(candidate, _, _, _)| (candidate, false))
}
