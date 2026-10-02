//! #5650: TCP MSS clamp and tunnel/GRE outer-MTU derivation helpers. Pure
//! code-motion split out of `forwarding/mod.rs` (behavior-identical).

use super::*;

/// Return the `security flow tcp-mss all-tcp` clamp value (0 = unset).
///
/// #2486: `all-tcp` is the context-agnostic clamp — it applies to every
/// forwarded TCP SYN regardless of tunnel context, and also serves as
/// the fallback for the per-context selectors (`gre-in`, tunnel egress)
/// below. `ipsec-vpn` is NOT read here: there is no IPsec context in the
/// userspace forward-build path (ESP/AH/IKE is local-delivered to the
/// kernel XFRM stack and the decrypted inner packets re-enter as plain
/// traffic with no IPsec marker), so `security flow tcp-mss ipsec-vpn`
/// is rejected at commit (pkg/config compiler) rather than carried as
/// dead config.
pub(in crate::afxdp) fn effective_tcp_mss(forwarding: &ForwardingState) -> u16 {
    forwarding.tcp_mss_all_tcp
}

/// Combine independently known MTU constraints without treating an unknown
/// leg (`0`) as a zero-byte budget. Returns zero only when both are unknown.
#[inline]
pub(in crate::afxdp) fn min_nonzero_mtu(a: usize, b: usize) -> usize {
    match (a, b) {
        (0, mtu) | (mtu, 0) => mtu,
        (a, b) => a.min(b),
    }
}

pub(in crate::afxdp) fn native_gre_inner_mtu(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
) -> usize {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    let Some(endpoint) = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
    else {
        return 0;
    };
    // #2517: resolve the outer/transport MTU through the SAME #2300 SSOT
    // helper the WireGuard MSS clamp uses (`tunnel_outer_mtu`) so the two
    // tunnel MSS paths cannot drift. That helper uses the standard 1500
    // underlay MTU as an interface fallback when EVERY egress lookup misses
    // (a transient egress-map miss during re-reconciliation / interface
    // bringup), instead of the old `unwrap_or_default()` → 0, which made
    // `native_gre_tcp_mss` return 0 and silently DISABLE a configured GRE
    // outbound TCP MSS clamp until the next reconcile. `tunnel_outer_mtu`
    // filters out an explicitly-zero stored egress MTU too, so it never
    // returns 0; the selected outer route can still constrain it below 1500.
    let transport_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
    let outer_ip_header_len = match endpoint.outer_family {
        libc::AF_INET => 20usize,
        libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let gre_header_len = 4usize + if endpoint.key != 0 { 4 } else { 0 };
    transport_mtu
        .checked_sub(outer_ip_header_len + gre_header_len)
        .unwrap_or_default()
}

pub(in crate::afxdp) fn native_gre_tcp_mss(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    addr_family: u8,
) -> u16 {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    let inner_mtu = native_gre_inner_mtu(forwarding, decision);
    if inner_mtu == 0 {
        return 0;
    }
    // The tunnel resolution carries two independent route constraints:
    // transport_route_mtu limits the encapsulated packet, while route_mtu
    // limits the inner packet. Keep a missing overlay MTU (0) non-limiting,
    // just as tcp_segmentation does, without turning an unknown inner budget
    // into a route-derived budget.
    let mtu = min_nonzero_mtu(inner_mtu, decision.resolution.route_mtu as usize);
    let ip_header_len = match addr_family as i32 {
        libc::AF_INET => 20usize,
        libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let Some(max_mss) = mtu.checked_sub(ip_header_len + 20) else {
        return 0;
    };
    if forwarding.tcp_mss_gre_out > 0 {
        // The configured gre-out value is a ceiling, not permission to
        // exceed either the outer- or overlay-derived inner budget.
        return forwarding
            .tcp_mss_gre_out
            .min(u16::try_from(max_mss).unwrap_or(u16::MAX));
    }
    u16::try_from(max_mss).unwrap_or_default()
}

/// Resolve the effective outer-link (transport) MTU for a tunnel endpoint —
/// the egress interface the OUTER encapped datagram leaves on, NOT the
/// tunnel device. The selected outer-route MTU constrains that physical-link
/// MTU before tunnel overhead is converted to an inner budget. This is the #2300
/// SSOT resolver shared by BOTH tunnel MSS-clamp paths: the WireGuard clamp
/// (#2299) and the native-GRE clamp (`native_gre_inner_mtu`, #2517).
/// Resolution chain: transport ifindex → stored resolution egress → endpoint
/// logical ifindex; `unwrap_or(1500)` only when every lookup misses (a
/// transient egress-map miss must NOT zero the clamp). An explicitly-zero
/// stored egress MTU is also coerced to that fallback, so this helper never
/// returns 0.
pub(in crate::afxdp) fn tunnel_outer_mtu(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    endpoint: &TunnelEndpoint,
) -> usize {
    let transport_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        decision.resolution.tx_ifindex,
        decision.resolution.tx_vlan_id,
    )
    .unwrap_or(decision.resolution.tx_ifindex);
    let interface_mtu = forwarding
        .egress
        .get(&transport_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.egress_ifindex))
        .or_else(|| forwarding.egress.get(&endpoint.logical_ifindex))
        .map(|egress| egress.mtu)
        .filter(|m| *m > 0)
        .unwrap_or(1500);
    min_nonzero_mtu(
        interface_mtu,
        decision.resolution.transport_route_mtu as usize,
    )
}

/// Dispatch the per-tunnel TCP MSS clamp by tunnel kind (#2299).
///
/// For a `mode == "wireguard"` endpoint the GRE MSS formula
/// (`native_gre_tcp_mss`) is ~36-60 bytes too high — it ignores
/// UDP(8) + WG data header(16) + Poly1305 tag(16) + §5.4.6 padding(≤15).
/// A SYN clamped with the GRE value lets the peer send full-MSS data
/// segments that the WG encap MTU guard then silently drops
/// (`encap_mtu_drops`). Route WG-bound SYNs through `wg::mss::wg_tcp_mss`
/// (#2299) instead, derived from `tunnel_outer_mtu` (resolve the transport
/// `tx_ifindex`/`tx_vlan` → egress, falling back to `egress_ifindex`
/// then the endpoint's `logical_ifindex`, with a 1500 interface fallback
/// followed by the selected-route MTU constraint).
///
/// NOTE (#2715): this is NOT the same path the encap MTU guard now
/// reads. Post-#2715 the encap guard route-resolves the physical egress
/// via the peer endpoint address; the MSS clamp still uses the
/// `tunnel_outer_mtu` (tx_ifindex→egress→logical) chain above. That
/// divergence is safe here, not a live bug: a route-resolved WG endpoint
/// returns NoRoute on this AF_XDP builder (no synthetic egress to read),
/// and the clamp errs toward a SMALLER MSS, so it can never advertise an
/// MSS larger than the encap guard tolerates — it cannot reintroduce
/// `encap_mtu_drops`.
///
/// Non-WG endpoints (and the plain-forward path, `tunnel_endpoint_id ==
/// 0`) keep the GRE formula bit-for-bit. No new branch on the
/// plain-forward fast path: the `tunnel_endpoint_id == 0` early-out
/// short-circuits before the endpoint lookup, exactly as
/// `native_gre_tcp_mss` does today.
pub(in crate::afxdp) fn tunnel_tcp_mss(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    addr_family: u8,
) -> u16 {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    let Some(endpoint) = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
    else {
        return 0;
    };
    if endpoint.mode == "wireguard" {
        // outer family from the endpoint; inner family from the packet
        // being forwarded; outer MTU from the real egress interface.
        let outer_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
        return crate::afxdp::wg::mss::wg_tcp_mss_with_route_mtu(
            endpoint.outer_family,
            addr_family as i32,
            outer_mtu,
            decision.resolution.route_mtu as usize,
        );
    }
    native_gre_tcp_mss(forwarding, decision, addr_family)
}

/// #2486: select the per-packet TCP MSS clamp value by forwarding
/// context. The three enforceable `security flow tcp-mss` contexts
/// (all-tcp, gre-in, gre-out/WG) are resolved here at frame-build time so
/// an accepted clamp is actually enforced; `ipsec-vpn` is rejected at
/// commit and never reaches this path
/// (previously only tunnel egress clamped — `all-tcp` / `gre-in` were
/// dead config and `gre-in` produced a silent full-MSS blackhole on the
/// GRE return path).
///
/// Priority (most specific wins, `all-tcp` is the universal fallback):
///   1. Tunnel egress (`tunnel_endpoint_id != 0`): the GRE/WG
///      overhead-aware value via `tunnel_tcp_mss` (gre-out, or the
///      MTU-derived formula). Falls back to `all-tcp` only when that
///      yields 0 (no gre-out and no MTU available).
///   2. GRE-decapped ingress (`GRE_DECAP_INGRESS_FLAG`): `gre-in`,
///      falling back to `all-tcp`.
///   3. Plain forwarded packet: `all-tcp`.
///
/// `ipsec-vpn` is intentionally absent — it is rejected at commit (no
/// IPsec context reaches this path; see `effective_tcp_mss`).
pub(in crate::afxdp) fn select_tcp_mss(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    meta: &ForwardPacketMeta,
) -> u16 {
    if decision.resolution.tunnel_endpoint_id != 0 {
        let tunnel = tunnel_tcp_mss(forwarding, decision, meta.addr_family);
        if tunnel > 0 {
            return tunnel;
        }
        return forwarding.tcp_mss_all_tcp;
    }
    if (meta.meta_flags & GRE_DECAP_INGRESS_FLAG) != 0 && forwarding.tcp_mss_gre_in > 0 {
        return forwarding.tcp_mss_gre_in;
    }
    effective_tcp_mss(forwarding)
}
