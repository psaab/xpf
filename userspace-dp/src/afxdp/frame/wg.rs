//! WireGuard transit-egress encap for the AF_XDP copy path (#1432 S2a).
//!
//! This is the SECOND of the two S2a egress encap sites; the primary is
//! the WG control thread's TUN-read loop (coordinator/wg_control/mod.rs).
//! This site fires only when an AF_XDP forwarding decision targets a
//! `mode == "wireguard"` tunnel endpoint id directly (a route/connected
//! entry carrying the WG endpoint id). In the canonical wgN-TUN topology
//! the kernel routes inner traffic to the wgN device and the control
//! thread owns egress, so this path is rarely hit; it exists so a
//! forwarding decision that does target the WG endpoint produces a valid
//! frame (and is correctly MTU-gated) rather than falling through to the
//! GRE builder.
//!
//! The non-WG fast path NEVER reaches here: `build_forwarded_frame_*`
//! only calls into the tunnel-encap branch when
//! `tunnel_endpoint_id != 0`, and a plain forward short-circuits long
//! before (tx/dispatch/mod.rs). The mode `match` in frame/mod.rs reads a
//! `&str` already loaded for the GRE lookup — no new branch on the
//! plain-forward path.

use super::super::wg::{EncapError, POLY1305_TAG_LEN, WG_DATA_HEADER_LEN, pad_to_16};
use super::super::*;
use super::checksum::checksum16_ipv6;
use super::headers::{write_eth_header_slice, write_ipv4_header, write_ipv6_header, write_udp_header};
use std::net::IpAddr;

/// The exact pad-aware encapped wire size for an `inner_len`-byte inner
/// packet plus the outer L3/L4 (IP + UDP). Used by the MTU guard so a
/// frame that would exceed the egress MTU is dropped rather than forcing
/// outer IP fragmentation (plan §7, Codex r3). Pulled out of
/// `wg_encap_frame` so the arithmetic is unit-testable in isolation.
#[inline]
fn wg_encapped_size(inner_len: usize, outer_v6: bool) -> usize {
    let outer_ip_len = if outer_v6 { 40 } else { 20 };
    let wg_record_len = WG_DATA_HEADER_LEN + pad_to_16(inner_len) + POLY1305_TAG_LEN;
    wg_record_len + outer_ip_len + 8
}

/// Test-only seam: counts every entry into `outer_physical_egress_resolution`
/// (each one performs exactly one outer-underlay FIB LPM). `wg_encap_frame`
/// resolves the outer route ONCE per packet (#3992); a test resets this to 0,
/// builds one frame, and asserts the count is exactly 1 (it was 2 before the
/// dedup).
///
/// #6294: this counter is THREAD-LOCAL, not a process-global atomic. The
/// default `cargo test` runs the suite in parallel, and every sibling
/// `wg_encap_frame` / `outer_*` test bumps this same counter. A process-global
/// value let a sibling's bump land between #6294's reset and read, corrupting
/// the exact `== 1` assertion (a load-sensitive flake, not a product bug). A
/// thread-local counter isolates each test thread's count: a test resets,
/// bumps, and reads entirely on its own thread, so no parallel sibling can
/// interfere — strictly stronger than serializing every bumper behind a lock,
/// and it needs no guard threaded through the ~14 outer-resolution tests. The
/// single-threaded test flow (reset -> one `wg_encap_frame` -> read) is
/// bit-identical to the former atomic. See `wg_tests.rs`'s
/// `outer_route_resolve_count_is_thread_local_isolated` for the fail-on-revert.
#[cfg(test)]
thread_local! {
    static OUTER_ROUTE_RESOLVE_COUNT: std::cell::Cell<usize> = std::cell::Cell::new(0);
}

/// Reset THIS thread's `OUTER_ROUTE_RESOLVE_COUNT` (see the counter doc). A
/// test calls this immediately before the single `wg_encap_frame` it measures.
#[cfg(test)]
pub(super) fn outer_route_resolve_count_reset() {
    OUTER_ROUTE_RESOLVE_COUNT.with(|c| c.set(0));
}

/// Read THIS thread's `OUTER_ROUTE_RESOLVE_COUNT` (see the counter doc).
#[cfg(test)]
pub(super) fn outer_route_resolve_count() -> usize {
    OUTER_ROUTE_RESOLVE_COUNT.with(std::cell::Cell::get)
}

/// Bump THIS thread's `OUTER_ROUTE_RESOLVE_COUNT` by one. Called from the
/// single outer-underlay FIB LPM site (`outer_physical_egress_resolution`)
/// and, directly, by the #6294 thread-local-isolation fail-on-revert test.
#[cfg(test)]
pub(super) fn outer_route_resolve_count_bump() {
    OUTER_ROUTE_RESOLVE_COUNT.with(|c| c.set(c.get().wrapping_add(1)));
}

/// Resolve the PHYSICAL underlay egress ifindex the OUTER (WG/UDP) datagram
/// actually leaves on, for a tunnel-resolved encap decision (#2680/#2701).
///
/// The interface that matters here is the PHYSICAL underlay egress — the one
/// the outer WG/UDP datagram leaves on — NOT
/// `decision.resolution.egress_ifindex`, which for a tunnel-resolved flow is
/// the tunnel LOGICAL ifindex (the WG interface, MTU ~1420, address a tunnel
/// address, used for zone/policy/CoS). BOTH the outer-MTU guard AND the outer
/// IP SOURCE address must follow this SAME physical egress:
///   - #2680: gating the outer size against the LOGICAL MTU is
///     apples-to-oranges and silently drops inner packets whose outer datagram
///     fits the 1500-byte underlay (broken PMTUD / tunnel transit).
///   - #2701: sourcing the outer IP from the LOGICAL ifindex reads a tunnel
///     address (or, when the logical WG iface carries no primary, `None` →
///     drop). The outer UDP must be sourced from the physical WAN primary.
///
/// For WireGuard the outer destination is the SELECTED peer endpoint
/// (`engine.peer_for_dest` LPM), NOT the endpoint-level `destination` (which
/// the build path zeroes to `0.0.0.0` for WG — the peer carries the real
/// outer hop). So the physical egress is the route to `outer_dst` in the
/// endpoint's transport table — exactly the interface the encapped datagram
/// egresses. `dynamic_neighbors` is `None`: the egress ifindex comes from
/// the ROUTE lookup, not from neighbor resolution, so the static forwarding
/// state suffices. (This is why `resolve_tunnel_outer`, which reads the
/// zeroed endpoint destination, cannot be reused here — it always NoRoutes
/// for WG.)
///
/// #2837 (NON-REPRODUCING — investigated, no fix applicable): the original
/// report was that this re-resolution "drops the known physical tx_ifindex and
/// falls back to the logical wg ifindex when the underlay neighbor was
/// dynamic-learned". It does not reproduce, for two independent reasons both
/// confirmed against the real resolver:
///
///  1. Passing `None` for the dynamic-neighbor map does NOT lose the physical
///     egress for a dynamic-learned underlay. The egress ifindex is
///     ROUTE-derived, not neighbor-derived: a route whose next-hop neighbor is
///     unresolved resolves to disposition `MissingNeighbor` (NOT `NoRoute`)
///     with the PHYSICAL `egress_ifindex` still populated, and the FIRST arm
///     below accepts `MissingNeighbor`. (Verified: the route to the real peer
///     endpoint with `dynamic_neighbors = None` yields
///     `MissingNeighbor`/`egress_ifindex = <physical>`.) So the dynamic map
///     would only change the disposition/`neighbor_mac` (neither read here),
///     never the returned ifindex — the first arm already returns the physical
///     underlay egress for the dynamic-learned case. The fallback is reached
///     ONLY on a genuine NoRoute to the peer endpoint, in which case there is
///     no underlay to deliver on regardless of which ifindex is chosen.
///
///  2. There is no admit-time physical `tx_ifindex` to fall back TO for a WG
///     session. `forwarding_build::tunnels` zeroes the WG endpoint destination
///     (`0.0.0.0`/`::` — the peer carries the real outer hop), so
///     `resolve_tunnel_forwarding_resolution` NoRoutes the outer and stores
///     `tx_ifindex = 0` (verified: the real resolver returns
///     `NoRoute`/`egress_ifindex = <logical>`/`tx_ifindex = 0` for the WG
///     endpoint). Even on a routable transport `populate_egress_resolution`
///     stores `tx_ifindex = egress.bind_ifindex` = the VLAN PARENT, which has
///     no `state.egress` row (rows are keyed by the L3 subif), so it could not
///     back the outer-source lookup anyway. A `tx_ifindex`-based fallback is
///     therefore dead code for WireGuard.
///
/// Fallback (conservative): if the outer route cannot be resolved (no FIB
/// entry / non-positive egress / the resolved egress is itself a tunnel
/// interface) fall back to the resolution's own `egress_ifindex` (the LOGICAL
/// ifindex). For the MTU guard this never makes it tighter than the pre-#2680
/// logical-MTU behaviour; for the source it preserves the pre-#2701 lookup, so
/// an unresolvable outer is no worse than before. This case is only reached
/// when the peer endpoint genuinely has no route (undeliverable), so the
/// choice of ifindex here cannot rescue the packet.
#[inline]
fn outer_physical_egress_ifindex(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    endpoint: &TunnelEndpoint,
    outer_dst: IpAddr,
) -> i32 {
    // #3992: the outer underlay route is resolved ONCE per encapped packet
    // (shared by the MTU guard, the outer source, AND — since #5292 — the
    // outer L2/VLAN). `outer_physical_egress_resolution` performs the single
    // FIB LPM and bumps the per-packet count; a second resolution per packet
    // is the redundant lookup #3992 removed.
    let outer = outer_physical_egress_resolution(forwarding, endpoint, outer_dst);
    outer_egress_ifindex_or_fallback(decision, forwarding, &outer)
}

/// #5292: resolve the FULL outer underlay `ForwardingResolution` for a WG
/// encap decision against its SELECTED peer endpoint. The WG endpoint-level
/// `destination` is zeroed (`0.0.0.0`/`::`) at build time — the peer carries
/// the real outer hop — so the outer egress, next-hop neighbor MAC, source,
/// and VLAN MUST all follow the peer route, NOT the placeholder (which
/// NoRoutes → blackhole, or matches the wrong default route). Returns the
/// resolution verbatim; callers derive the egress ifindex via
/// `outer_egress_ifindex_or_fallback` and read `neighbor_mac`/the egress row
/// (`src_mac`/`vlan_id`) from the SAME snapshot, so the outer L2/VLAN, source,
/// and MTU are all consistent with one physical egress.
///
/// Bumps `OUTER_ROUTE_RESOLVE_COUNT` exactly once — the #3992 single-FIB-LPM-
/// per-packet invariant. `dynamic_neighbors` is `None`: the egress ifindex is
/// ROUTE-derived (a missing underlay neighbor resolves to `MissingNeighbor`
/// with the physical egress still populated), so the static forwarding state
/// suffices to pick the egress; the neighbor MAC read by the encap path falls
/// back to the session's stored neighbor when the underlay next-hop is not
/// statically known (see `wg_encap_frame`).
#[inline]
fn outer_physical_egress_resolution(
    forwarding: &ForwardingState,
    endpoint: &TunnelEndpoint,
    outer_dst: IpAddr,
) -> ForwardingResolution {
    #[cfg(test)]
    outer_route_resolve_count_bump();
    // #2734: WG outer underlay resolution is per-tunnel-endpoint, not
    // per-inner-flow — pass None (per-destination ECMP spread).
    match outer_dst {
        IpAddr::V4(ip) => {
            lookup_forwarding_resolution_v4(forwarding, None, ip, &endpoint.transport_table, 1, false, None)
        }
        IpAddr::V6(ip) => {
            lookup_forwarding_resolution_v6(forwarding, None, ip, &endpoint.transport_table, 1, false, None)
        }
    }
}

/// The physical underlay egress ifindex from a resolved outer resolution,
/// with the conservative fallback to the decision's own `egress_ifindex` (the
/// tunnel LOGICAL ifindex) when the peer endpoint is genuinely unrouted /
/// non-positive / resolves onto a tunnel interface. See
/// `outer_physical_egress_ifindex`'s doc for the full #2837 analysis of why
/// the route-derived egress survives an unresolved (dynamic-learned) neighbor.
#[inline]
fn outer_egress_ifindex_or_fallback(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    outer: &ForwardingResolution,
) -> i32 {
    if outer.egress_ifindex > 0
        && outer.disposition != ForwardingDisposition::NoRoute
        && !forwarding.tunnel_interfaces.contains(&outer.egress_ifindex)
    {
        outer.egress_ifindex
    } else {
        decision.resolution.egress_ifindex
    }
}

/// The PHYSICAL underlay egress MTU the OUTER (WG/UDP) datagram must fit
/// (#2680). Thin wrapper over `outer_physical_egress_ifindex` so the MTU
/// guard and the outer-source lookup resolve the SAME physical egress.
///
/// The inner packet's own logical/PMTUD MTU is a SEPARATE concern handled
/// by the WG inner-MTU clamp / post-transform PMTUD on the TX dispatcher
/// (#2299/#2330/#2457); this helper is strictly outer-size-vs-physical-MTU.
/// Final fallback (egress row missing / MTU 0) is 1500.
#[inline]
fn outer_physical_egress_mtu(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    endpoint: &TunnelEndpoint,
    outer_dst: IpAddr,
) -> usize {
    let physical_ifindex =
        outer_physical_egress_ifindex(decision, forwarding, endpoint, outer_dst);
    forwarding
        .egress
        .get(&physical_ifindex)
        .map(|e| e.mtu)
        .filter(|m| *m > 0)
        .unwrap_or(1500)
}

/// The peer-endpoint outer destination whose underlay MTU the PTB must
/// derive from, for a given inner destination (#2845).
///
/// The encap path selects the egress peer by the inner destination's
/// longest-prefix match in the AllowedIPs trie
/// (`wg_encap_frame` → `engine.peer_for_dest`) and resolves the outer hop
/// from THAT peer's endpoint. Different peers of one wg interface can have
/// different endpoints / underlay paths / MTUs, so the PTB must select the
/// SAME peer rather than assuming one underlay per interface.
///
/// Resolution mirrors the encap path exactly: the live engine
/// (`forwarding.wg_engines`) owns the AllowedIPs LPM and the per-snapshot
/// endpoint binding (#2836), so the PTB and the encap agree on both the peer
/// and its (possibly roamed) endpoint.
///
/// Returns:
///   - `Some(ip)` — a covering peer was found with a known endpoint; resolve
///     the underlay via the route to `ip`.
///   - `None` — either no inner destination was available, no live engine is
///     present yet, or no peer covers the inner destination: fall back to the
///     pre-#2845 first-peer-with-endpoint behaviour (byte-identical in the
///     single-underlay common case, the only available answer with no inner
///     destination to select on).
///
/// NOTE: a covering peer found with NO endpoint (responder-only / unlearned)
/// resolves to that peer's `None` and is returned as `None` here — the caller
/// then uses the conservative logical-ifindex fallback rather than borrowing a
/// DIFFERENT peer's underlay (which would reintroduce the #2845 mismatch). The
/// encap path drops such a packet anyway, so the PTB value is moot.
#[inline]
fn wg_peer_outer_dst(
    forwarding: &ForwardingState,
    endpoint: &TunnelEndpoint,
    inner_dst: Option<IpAddr>,
) -> Option<IpAddr> {
    if let Some(dst) = inner_dst {
        if let Some(engine) = forwarding.wg_engines.get(&endpoint.id) {
            if let Some((_pubkey, peer_endpoint)) = engine.peer_for_dest(dst) {
                // A covering peer was found: use ITS endpoint (or None if the
                // peer has no learned/configured endpoint — see the doc note).
                return peer_endpoint.map(|ep| ep.ip());
            }
        }
    }
    // No inner dst, no live engine, or no covering peer: the pre-#2845
    // first-peer-with-endpoint behaviour. Byte-identical in the single-
    // underlay common case (one peer, or all peers on one underlay).
    endpoint
        .wg_peers
        .iter()
        .find_map(|peer| peer.endpoint.map(|ep| ep.ip()))
}

/// The PHYSICAL underlay egress MTU for a WireGuard endpoint, for the
/// post-transform PTB inner-MTU derivation (#2684, per-peer #2845).
///
/// This is the SAME physical-underlay SSOT (`outer_physical_egress_mtu`,
/// #2680) the encap drop guard uses, exposed so the TX dispatcher's
/// `post_transform_inner_mtu` advertises an inner MTU consistent with what
/// the encap guard actually admits.
///
/// #2845: the PTB path runs BEFORE the per-packet peer LPM in the builder, but
/// the dispatcher already holds the pre-encap inner frame and threads the inner
/// destination here. We select the SAME peer the encap path will
/// (`wg_peer_outer_dst` → `engine.peer_for_dest`) and resolve the underlay via
/// THAT peer's endpoint, so two peers of one wg interface with asymmetric
/// underlay MTUs each get the PTB derived from their OWN underlay — not an
/// arbitrary first peer's. When the inner destination is unavailable or no peer
/// covers it, this falls back to the first peer with an endpoint (the pre-#2845
/// per-interface behaviour, byte-identical when all peers share one underlay).
/// The fallback inside `outer_physical_egress_mtu` (route unresolvable → the
/// resolution's own `egress_ifindex` MTU = the tunnel LOGICAL MTU) preserves
/// the conservative pre-#2684 behaviour, never tighter.
///
/// Returns the logical-ifindex MTU fallback when the selected peer has no
/// learned/configured endpoint address (no outer hop to route to) — the same
/// value `tunnel_outer_mtu` would have produced, so the PTB is no worse than
/// before in that degenerate case.
///
/// # Why not `tunnel_outer_mtu`
/// For a WG transit flow `endpoint.destination` is `0.0.0.0`/`::`
/// (`forwarding_build::tunnels` zeroes it — the peer carries the real outer
/// hop), so `tunnel_outer_mtu`'s `tx_ifindex` resolution NoRoutes and the
/// chain falls through to the LOGICAL `egress_ifindex` MTU (~1420). Feeding
/// that to `wg_inner_mtu` subtracts the WG encap overhead a SECOND time
/// (the logical MTU is already underlay − encap), under-advertising the
/// inner PMTU by ~one encap (~75-95B). GRE is unaffected: its
/// `endpoint.destination` is the real outer hop, so `tunnel_outer_mtu`
/// resolves to the physical underlay correctly.
#[inline]
pub(in crate::afxdp) fn wg_endpoint_physical_outer_mtu(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    endpoint: &TunnelEndpoint,
    inner_dst: Option<IpAddr>,
) -> usize {
    // #2845: resolve the outer hop of the SAME peer the encap path selects
    // for this inner destination (per-peer underlay), with the pre-#2845
    // first-peer behaviour as the fallback.
    let outer_dst = wg_peer_outer_dst(forwarding, endpoint, inner_dst);
    match outer_dst {
        Some(dst) => outer_physical_egress_mtu(decision, forwarding, endpoint, dst),
        // No peer endpoint to route to: fall back to the resolution's own
        // egress (the logical ifindex), exactly what `tunnel_outer_mtu`
        // would have yielded — no regression in the degenerate case.
        None => forwarding
            .egress
            .get(&decision.resolution.egress_ifindex)
            .map(|e| e.mtu)
            .filter(|m| *m > 0)
            .unwrap_or(1500),
    }
}

/// #6308: the PHYSICAL underlay egress ifindex a WG transit-egress frame must
/// be DISPATCHED to — resolved against the SAME selected-peer route #5292 uses
/// for the frame BYTES, so the dispatch SSOT and the frame-bytes SSOT agree on
/// one physical NIC.
///
/// The TX dispatcher picks the egress binding from `decision.resolution`'s
/// `tx_ifindex` (the physical bind ifindex) or, when that is 0, from
/// `resolve_tx_binding_ifindex(egress_ifindex)`. For a WG transit-egress
/// decision the resolution SSOT (`resolve_tunnel_forwarding_resolution`) is
/// built against the endpoint's ZEROED destination (`0.0.0.0`/`::` — the peer
/// carries the real outer hop, #2837), so it stores `egress_ifindex =` the
/// tunnel LOGICAL wgN ifindex and:
///   * WG transport table HAS a default route → `tx_ifindex =` the default
///     egress bind ifindex (= the physical WAN parent). Dispatch already
///     egresses the correct NIC; this helper is not consulted (the caller
///     keeps the `tx_ifindex > 0` fast path — common case, UNCHANGED).
///   * WG transport table has ONLY a specific peer route, NO default →
///     `0.0.0.0`/`::` NoRoutes → `tx_ifindex = 0`; the fallback
///     `resolve_tx_binding_ifindex(logical wgN)` returns the logical ifindex
///     (which has no XSK binding) → the TX dispatcher NO_EGRESS_BINDING-DROPS a
///     frame #5292 built correctly. This is the #6308 bug.
///
/// This helper resolves the physical underlay egress the SAME way #5292 does
/// for the frame bytes: select the egress peer by the inner destination's
/// AllowedIPs LPM (`wg_peer_outer_dst` → `engine.peer_for_dest`) and resolve
/// that peer's endpoint through the endpoint transport table
/// (`outer_physical_egress_resolution` → `outer_egress_ifindex_or_fallback`).
/// The caller feeds the result to `resolve_tx_binding_ifindex`, so a specific
/// peer route egresses its physical NIC (which has a binding) instead of the
/// logical wgN fallback.
///
/// #6340: the peer selection is keyed on the POST-NAT inner dst
/// (`decision.nat.rewrite_dst` when a same-family DNAT applies, else the frame
/// dst) so DISPATCH resolves the SAME peer `wg_encap_frame` emits bytes for —
/// the encap builder applies DNAT into the outgoing frame before its own peer
/// LPM (`inner_dst_ip(&out)`), so a DNAT-across-AllowedIPs-peers flow on
/// distinct underlays must not split the dispatch NIC from the byte NIC. NAT64
/// is excluded (address-family change → returns `None`, the logical fallback).
///
/// Returns `None` — the caller keeps the pre-#6308 logical fallback — when the
/// decision is not a WG transit-egress (no tunnel id / a GRE or unknown mode),
/// or no covering peer with an endpoint exists. `Some(logical egress_ifindex)`
/// on a genuine NoRoute to the selected peer (via
/// `outer_egress_ifindex_or_fallback`'s conservative fallback): the packet is
/// undeliverable regardless, so dispatch still fails closed exactly as before.
///
/// #3992: this resolves the outer route once for DISPATCH; `wg_encap_frame`
/// resolves it once more for the BYTES. Both firings happen ONLY on the
/// tx_ifindex == 0 (no-default-route) path — the previously-DROPPED case — so
/// no working (default-route) traffic pays a second FIB LPM.
pub(in crate::afxdp) fn wg_transit_egress_physical_egress_ifindex(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    inner_frame: &[u8],
    inner_addr_family: u8,
    inner_l3_offset: u16,
) -> Option<i32> {
    let id = decision.resolution.tunnel_endpoint_id;
    if id == 0 {
        return None;
    }
    let endpoint = forwarding.tunnel_endpoints.get(&id)?;
    if !matches!(tunnel_mode_kind(&endpoint.mode), TunnelKind::WireGuard) {
        return None;
    }
    // #6340: DISPATCH must select the SAME peer `wg_encap_frame` emits bytes
    // for. The encap builder applies DNAT into the outgoing frame BEFORE
    // `wg_encap_frame` LPMs the AllowedIPs trie on the POST-NAT inner dst
    // (`build_forwarded_frame_into_from_frame` writes `nat.rewrite_dst` into
    // `out` via `apply_nat_ipv4/6`, then wg.rs reads `inner_dst_ip(&out)`).
    // Under a DNAT that rewrites the inner dst ACROSS AllowedIPs peers on
    // DISTINCT physical underlays, selecting the peer from the PRE-NAT frame dst
    // here would dispatch to the wrong peer's NIC while the encap bytes carry
    // the OTHER peer's L2 — a wire mismatch. Resolve the peer from the POST-NAT
    // dst so dispatch and bytes agree on ONE physical NIC.
    //
    // NAT64 (`nat.nat64`) is deliberately excluded: it changes the address
    // family, so `rewrite_dst` is a DIFFERENT-family address and the pre-NAT
    // frame dst is the pre-translation family — NEITHER is a valid same-family
    // AllowedIPs key for this WG endpoint's (same-family) peers, so reusing
    // either would mis-select. Fail closed to the caller's logical-ifindex
    // fallback (the pre-#6308 drop) rather than dispatch to a mis-selected NIC;
    // a NAT64→WG transit flow is undeliverable on this path regardless (the
    // pre-NAT frame parse already returned `None` here for that family
    // mismatch).
    if decision.nat.nat64 {
        return None;
    }
    // Same inner-destination peer selection the encap builder / PTB path use,
    // but keyed on the POST-DNAT dst (`nat.rewrite_dst`) when a same-family DNAT
    // applies, else the frame's parsed inner dst (with the `meta.l3_offset`
    // fallback) — which for a non-DNAT flow is byte-identical to the frame the
    // encap path reads. Then LPM the AllowedIPs trie to the covering peer's
    // endpoint.
    let inner_dst = decision.nat.rewrite_dst.or_else(|| {
        frame_l3_offset(inner_frame)
            .or_else(|| match inner_l3_offset {
                14 | 18 => Some(inner_l3_offset as usize),
                _ => None,
            })
            .and_then(|l3| inner_frame.get(l3..))
            .and_then(|pkt| crate::afxdp::gre::inner_dst_ip(pkt, inner_addr_family))
    });
    let outer_dst = wg_peer_outer_dst(forwarding, endpoint, inner_dst)?;
    let outer = outer_physical_egress_resolution(forwarding, endpoint, outer_dst);
    Some(outer_egress_ifindex_or_fallback(decision, forwarding, &outer))
}

pub(super) fn wg_encap_frame(
    inner_frame: &[u8],
    inner_meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let inner_meta = inner_meta.into();
    let id = decision.resolution.tunnel_endpoint_id;
    let endpoint = forwarding.tunnel_endpoints.get(&id)?;
    // #1873 (Codex code r2): refuse to encapsulate when the id's
    // owning netdev differs from the one recorded in the session's
    // stored resolution (egress_ifindex = logical_ifindex at resolve
    // time) — a re-owned id must fail the build (R-C gate drops the
    // frame), never encapsulate into the new owner.
    if decision.resolution.egress_ifindex > 0
        && endpoint.logical_ifindex != decision.resolution.egress_ifindex
    {
        return None;
    }
    let engine = forwarding.wg_engines.get(&id)?;

    // Extract the inner IP packet (strip L2).
    let inner_l3 = match frame_l3_offset(inner_frame) {
        Some(offset) => offset,
        None => inner_meta.l3_offset as usize,
    };
    let inner_packet = inner_frame.get(inner_l3..)?;
    let inner_len = crate::afxdp::gre::packet_trimmed_len(inner_packet, inner_meta.addr_family)?;
    let inner_packet = &inner_packet[..inner_len];

    // #1434 B1b cryptokey routing: select the egress peer by the inner
    // destination's longest-prefix match in the AllowedIPs trie (NOT a
    // single scalar peer). A packet with no covering peer is dropped —
    // there is no peer to encrypt it to.
    let inner_dst = crate::afxdp::gre::inner_dst_ip(inner_packet, inner_meta.addr_family)?;
    let (peer_pubkey, peer_endpoint) = engine.peer_for_dest(inner_dst)?;
    // A responder-only peer with no learned endpoint cannot be an encap
    // TARGET on this transit path (the control thread learns the
    // endpoint from inbound traffic; this AF_XDP transit site has no
    // such state). Drop rather than encap to a phantom destination.
    let peer_endpoint = peer_endpoint?;
    // #2303: copy the inner DSCP+ECN onto the outer header (uniform
    // DSCP model + RFC 6040 ECN ingress copy) instead of hardcoding 0.
    let outer_tos = crate::afxdp::gre::inner_tos_byte(inner_packet, inner_meta.addr_family);

    // Outer family follows the peer endpoint address.
    let outer_v6 = peer_endpoint.is_ipv6();
    let outer_ip_len = if outer_v6 { 40 } else { 20 };

    // Exact pad-aware MTU guard (plan §7, Codex r3). The WG record is
    // WG_DATA_HEADER_LEN + pad_to_16(inner) + POLY1305_TAG_LEN; the full
    // outer frame adds eth + outer IP + UDP(8). Drop oversize rather than
    // letting the kernel fragment the outer datagram.
    //
    // #2680/#2701/#3992/#5292: resolve the PHYSICAL underlay egress ONCE per
    // packet (a single FIB LPM to the SELECTED peer endpoint — the real outer
    // hop for WG) and derive the FULL outer identity from that ONE snapshot:
    // the outer-MTU guard, the outer IP SOURCE, AND (since #5292) the outer L2
    // header (dst MAC / src MAC / VLAN). The WG endpoint destination is zeroed
    // (`0.0.0.0`/`::`) at build time, so `decision.resolution` — resolved
    // against that placeholder BEFORE the AllowedIPs peer selection above — is
    // either NoRoute (no L2 → blackhole) or the WRONG default route's adjacency
    // (its neighbor MAC / src MAC / VLAN describe a different egress than the
    // selected peer needs). The OUTER datagram must fit the PHYSICAL underlay
    // MTU and carry the PHYSICAL egress L2/VLAN, NOT
    // `decision.resolution.egress_ifindex` (the tunnel LOGICAL ifindex, MTU
    // ~1420, tunnel-address L2); the logical/inner MTU is a separate concern
    // handled by the inner-MTU clamp.
    //
    // #3992: `outer_physical_egress_resolution` performs the single FIB LPM
    // (pre-#3992 the identical route was resolved twice — MTU guard + source).
    // `outer_physical_egress_mtu` remains the SSOT used by the PTB path
    // (`wg_endpoint_physical_outer_mtu`); here we read the MTU straight off the
    // single shared `egress` row so the guard MTU is byte-identical.
    let outer_resolution =
        outer_physical_egress_resolution(forwarding, endpoint, peer_endpoint.ip());
    let physical_egress_ifindex =
        outer_egress_ifindex_or_fallback(decision, forwarding, &outer_resolution);
    let egress = forwarding.egress.get(&physical_egress_ifindex);
    let outer_mtu = egress.map(|e| e.mtu).filter(|m| *m > 0).unwrap_or(1500);

    // #5292: the outer L2 header follows the resolved PHYSICAL egress —
    // internally consistent with the outer IP source (#2701) — NOT
    // `decision.resolution`. `src_mac` + VLAN come straight from the physical
    // egress row; the outer next-hop neighbor MAC comes from the peer route's
    // resolution, falling back to the session's stored neighbor ONLY when the
    // underlay next-hop is not yet statically resolved (e.g. a dynamic-learned
    // hop shared with the default route — the common single-underlay case).
    // Reverting any of these three to `decision.resolution` reintroduces the
    // zeroed-endpoint blackhole / wrong-adjacency bug.
    let src_mac = match egress {
        Some(e) => e.src_mac,
        None => decision.resolution.src_mac?,
    };
    let vlan_id = match egress {
        Some(e) => e.vlan_id,
        None => decision.resolution.tx_vlan_id,
    };
    let dst_mac = outer_resolution
        .neighbor_mac
        .or(decision.resolution.neighbor_mac)?;
    let outer_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let wg_record_len = WG_DATA_HEADER_LEN + pad_to_16(inner_packet.len()) + POLY1305_TAG_LEN;
    if wg_encapped_size(inner_packet.len(), outer_v6) > outer_mtu {
        // #1865: the promised "follow-up" counter store — same
        // `encap_mtu_drops` counter as the control thread's symmetric
        // guard (the plan's both-guards requirement).
        //
        // #2330: when a PTB is OWED (inner IPv4 DF or IPv6), the TX
        // dispatcher's pre-build `post_transform_inner_mtu` decision fires
        // BEFORE this builder is called (advertising the WG inner MTU =
        // `wg::mss::wg_inner_mtu`, the inverse of `wg_encapped_size`),
        // `mtu_signalled` skips the encap build, and this site is never
        // reached for that case — so the PTB and this drop counter never
        // both fire. This guard remains the backstop for a non-DF IPv4
        // inner (`ForwardOversizeNoDf`: no PTB, and no fragmentation before
        // encapsulation, #9758) whose padded encapsulation exceeds the MTU.
        crate::afxdp::wg::counters::WgCounters::bump(&engine.counters().encap_mtu_drops);
        return None;
    }

    // #2792 (agy-review-048 finding 048-11): eliminate the per-packet
    // heap churn. The pre-#2792 code allocated TWO Vecs per packet here —
    // an intermediate `wg_record` scratch for `try_encap`, then copied
    // that scratch into a second `out` frame Vec. Both are gone:
    //
    //   1. `wg_record` (removed): `try_encap` writes the WG transport
    //      record (data header + ciphertext + Poly1305 tag) starting at
    //      `out[0]` of whatever `&mut [u8]` it is handed. We hand it the
    //      UDP payload slot of `out` directly, so the encrypt lands in
    //      its final position — no intermediate buffer and no follow-up
    //      copy. The plaintext is staged on the stack inside `try_encap`
    //      (MaybeUninit), so the in-place encrypt is sound: snow's
    //      non-overlapping plaintext/ciphertext requirement is satisfied
    //      by that stack staging, not by a separate output buffer.
    //
    //   2. `out` is now sized ONCE to the pad-aware maximum record length
    //      (`wg_record_len`, the same arithmetic the MTU guard already
    //      validated above) and truncated to the actual encapped length
    //      after `try_encap` reports it. The single remaining `out`
    //      allocation is the function's owned return value (the
    //      `Vec<Vec<u8>>` TCP-segmentation caller needs an owned frame per
    //      segment) and is byte-for-byte identical to the GRE sibling's
    //      `encapsulate_native_gre_frame` output Vec — no WG-specific
    //      extra alloc remains.
    //
    // Wire output is unchanged: same header bytes, same ciphertext+tag,
    // same outer framing (proved byte-identical by
    // `wg_encap_in_place_matches_separate_buffer`).
    let outer_ip_start = outer_eth_len;
    let udp_start = outer_ip_start + outer_ip_len;
    let payload_start = udp_start + 8;
    // Size to the pad-aware maximum WG record; truncate to the real
    // length once `try_encap` reports `outcome.len`.
    let max_frame_len = payload_start + wg_record_len;
    let mut out = vec![0u8; max_frame_len];

    let outcome = match engine.try_encap(
        &peer_pubkey,
        inner_packet,
        out.get_mut(payload_start..payload_start + wg_record_len)?,
    ) {
        Ok(o) => o,
        Err(EncapError::NoSession) => {
            // Request a handshake for THIS peer (rate-limited relaxed atomic,
            // #5164) and drop.
            engine.request_handshake(&peer_pubkey, monotonic_nanos());
            return None;
        }
        Err(_) => return None,
    };
    let wg_record_actual = outcome.len;
    let udp_len = 8 + wg_record_actual;
    let frame_len = outer_eth_len + outer_ip_len + udp_len;
    out.truncate(frame_len);

    write_eth_header_slice(
        out.get_mut(..outer_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        if outer_v6 { 0x86dd } else { 0x0800 },
    )?;

    // Source IP/port: the firewall egress primary address + WG listen
    // port; destination: the peer endpoint.
    //
    // #2701: the outer IP SOURCE must be the PHYSICAL underlay egress
    // primary, resolved via the route to the SELECTED peer endpoint — the
    // SAME egress the #2680 MTU guard uses — NOT
    // `decision.resolution.egress_ifindex` (the tunnel LOGICAL ifindex,
    // whose primary is a tunnel address or absent → wrong source / None
    // drop). #3992: reuse the `physical_egress_ifindex` / `egress` row
    // resolved ONCE above (both the guard and this source share the single
    // `outer_physical_egress_ifindex` FIB LPM) rather than re-resolving.
    let src_port = endpoint.wg_listen_port;
    let dst_port = peer_endpoint.port();

    match (outer_v6, peer_endpoint.ip()) {
        (false, IpAddr::V4(dst)) => {
            let src = egress.and_then(|e| e.primary_v4)?;
            let total_len = u16::try_from(outer_ip_len + udp_len).ok()?;
            write_ipv4_header(
                out.get_mut(outer_ip_start..outer_ip_start + 20)?,
                src,
                dst,
                PROTO_UDP,
                outer_tos,
                endpoint.ttl,
                total_len,
            )?;
            // UDP checksum is optional over IPv4; leave 0 (disabled).
            write_udp_header(
                out.get_mut(udp_start..udp_start + 8)?,
                src_port,
                dst_port,
                u16::try_from(udp_len).ok()?,
                0,
            )?;
        }
        (true, IpAddr::V6(dst)) => {
            let src = egress.and_then(|e| e.primary_v6)?;
            let payload_len = u16::try_from(udp_len).ok()?;
            write_ipv6_header(
                out.get_mut(outer_ip_start..outer_ip_start + 40)?,
                src,
                dst,
                PROTO_UDP,
                outer_tos,
                /* flow_label */ 0,
                endpoint.ttl,
                payload_len,
            )?;
            // IPv6 mandates a non-zero UDP checksum. Compute over the
            // pseudo-header + UDP header + payload.
            write_udp_header(
                out.get_mut(udp_start..udp_start + 8)?,
                src_port,
                dst_port,
                payload_len,
                0,
            )?;
            // #2651: use the AVX2-backed `checksum16_ipv6` helper (the same
            // routine the inner TCP/UDP/ICMPv6 paths use) instead of the
            // scalar word-at-a-time loop that used to live in
            // `udp6_checksum`. The pseudo-header layout is identical (src,
            // dst, payload-len-as-u32-BE, [0,0,0,next-header], payload) so the
            // one's-complement sum is byte-for-byte the same; we re-apply the
            // IPv6 mandatory 0x0000 -> 0xFFFF canonicalization at the call
            // site (RFC 768 / RFC 8200 — the UDPv6 checksum MUST be non-zero
            // on the wire, unlike v4 where 0 means "disabled"). Proven
            // byte-identical to the prior scalar reference across sizes
            // (odd/even, all-zero-sum -> 0xFFFF, max) by
            // `udp6_checksum_matches_scalar_reference`.
            let csum = udp6_checksum_optimized(src, dst, &out[udp_start..udp_start + udp_len]);
            out[udp_start + 6..udp_start + 8].copy_from_slice(&csum.to_be_bytes());
        }
        _ => return None,
    }

    Some(out)
}

/// RFC 768 / RFC 8200 IPv6 UDP checksum over the pseudo-header + UDP
/// datagram, computed with a deliberately naive scalar word-at-a-time
/// one's-complement loop. `udp` is the full UDP header+payload (checksum
/// field 0).
///
/// #2651: this was the production routine on the WG IPv6 egress hot path;
/// it has been replaced at the call site by the AVX2-backed
/// `checksum16_ipv6` helper. It is retained ONLY as the independent
/// reference oracle for the parity test
/// (`udp6_checksum_matches_scalar_reference`), which proves the optimized
/// helper produces the byte-identical wire checksum across odd/even
/// lengths, the all-zero-sum -> 0xFFFF mandatory-v6 case, and max size.
#[cfg(test)]
fn udp6_checksum_scalar_reference(
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
    udp: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = udp.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += PROTO_UDP as u32; // next-header
    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if i < udp.len() {
        sum += (udp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    if csum == 0 { 0xffff } else { csum }
}

/// The production WG IPv6 outer UDP checksum: the AVX2-backed
/// `checksum16_ipv6` one's-complement sum over the pseudo-header + UDP
/// datagram, with the RFC 768 / RFC 8200 mandatory 0x0000 -> 0xFFFF
/// canonicalization applied. Mirrors the call site so tests exercise the
/// exact production formula. `udp` is the full UDP header+payload
/// (checksum field 0).
fn udp6_checksum_optimized(
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
    udp: &[u8],
) -> u16 {
    let csum = checksum16_ipv6(src, dst, PROTO_UDP, udp);
    if csum == 0 { 0xffff } else { csum }
}

#[cfg(test)]
#[path = "wg_tests.rs"]
mod tests;
