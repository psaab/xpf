// #2301: locally-generated Path-MTU-Discovery ICMP errors for the generic
// forwarder.
//
// The TX dispatcher only had a TCP-specific segmentation decision
// (`forwarded_tcp_may_need_segmentation`). Every other oversized forwarded
// L3 packet — UDP, ICMP, ESP, GRE, a TCP segmentation MISS, a tunnelled
// inner that grew past the egress MTU — was enqueued for TX past the egress
// MTU with no MTU signal to the sender. (What then happens to a DF-clear IPv4
// datagram is stated once, on `EgressMtuDecision::ForwardOversizeNoDf`.)
// PMTUD therefore never converged on a mixed-MTU /
// tunnel-underlay path (PPPoE 1492, cloud ~1450, VLAN stacks). For a
// routing/security appliance that is a forwarding-correctness gap, not a
// perf nicety.
//
// This module adds the egress-MTU decision and the matching ICMP error
// generators:
//   - ICMPv4 Destination Unreachable, type 3 code 4 (Fragmentation Needed
//     and DF Set) carrying the next-hop MTU in the low 16 bits of the
//     "unused" word (RFC 1191).
//   - ICMPv6 Packet Too Big, type 2 code 0, carrying the MTU in the 32-bit
//     field that replaces the "unused" word (RFC 4443 §3.2).
//
// The builders deliberately mirror `icmp::build_local_icmp_error_v4/v6`
// (L2 reflect + ingress-sourced outer IP + quoted inbound packet) rather
// than calling them, because those two functions hardcode the post-checksum
// word to zero and have no MTU parameter. icmp.rs is being edited in
// parallel (#2237/#2242), so keeping the PTB builders in their own module
// keeps the diff additive and conflict-free; the shared header/checksum
// helpers (`write_eth_header_tagged`, `write_ipv4_header`,
// `write_ipv6_header`, `checksum16`, `checksum16_ipv6`, `TxVlanTag`) and the
// RFC suppression gate (`icmp::reject_icmp_reply_suppressed`,
// `is_non_first_fragment`) are reused verbatim.

use super::*;

use super::icmp::reject_icmp_reply_suppressed;

/// Outcome of the per-forward egress-MTU decision. The fast path (the
/// forwarded L3 size fits the egress MTU) is `Forward` and adds a single
/// `usize` comparison to the dispatcher; everything else is a cold arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum EgressMtuDecision {
    /// The frame fits the egress MTU (or no egress MTU is known) — forward
    /// it unchanged. An OVERSIZED IPv4 frame without DF is
    /// [`Self::ForwardOversizeNoDf`] instead (#9328).
    Forward,
    /// The frame EXCEEDS the egress MTU, but the sender did not forbid
    /// fragmentation (IPv4 DF=0), so it is forwarded at full length anyway
    /// (#9328).
    ///
    /// Behaviourally identical to [`Self::Forward`] — that is deliberate and
    /// this variant changes no forwarding decision. It exists because the two
    /// were the SAME value, so nothing downstream could tell "it fits" from
    /// "it does not fit and we sent it anyway", and the second was booked as
    /// `enqueue_ok` + `tx_bytes_total` like any healthy forward. An operator
    /// investigating a downstream loss saw a HEALTHY counter — a wrong
    /// diagnostic, not a missing one.
    ///
    /// WHAT HAPPENS TO THE FRAME (#9395). There is no IPv4 transit fragmenter
    /// in this dataplane: a positive-controlled grep for MF/offset WRITERS finds
    /// only the three in `nat64.rs`, which copy MF/offset verbatim from an
    /// existing IPv6 Fragment Header. So the datagram leaves this decision
    /// WHOLE.
    ///
    /// POLICY (#9395): keep forwarding, and record this exception. It was
    /// decided from a PLAIN forward, where the wire size does not change: on
    /// the loss userspace cluster (mlx5 VF, 1500-byte L2 path), with `reth0.80`
    /// configured at MTU
    /// 1400, DF-clear 1450-byte UDP and ICMP datagrams reached the far host
    /// whole (no reassembly there, no NIC TX error). A drop there would break a
    /// path that delivered, and a downstream router that cannot carry the
    /// datagram may fragment it (RFC 791).
    ///
    /// NOT covered by that measurement, and not changed by the decision:
    ///   - a transformed path (NAT64, native GRE, WireGuard), where `mtu` is the
    ///     #2330 post-transform inner MTU and the translated or encapsulated
    ///     frame then meets that path's own handling;
    ///   - a plain datagram larger than the PHYSICAL egress link (#9758).
    ///
    /// The exception is SAMPLED (see `record_exception`), so it shows that such
    /// decisions happen, delivered or not, but is neither a count nor a loss
    /// counter. Every already-fragmented IPv4 datagram is DF-clear by
    /// construction, so forwarded non-first fragments are inside this
    /// population.
    ForwardOversizeNoDf,
    /// The frame exceeds the egress MTU and the sender asked us not to
    /// fragment (IPv4 DF=1) or cannot be fragmented in transit (IPv6) —
    /// generate an ICMP Frag-Needed / Packet-Too-Big advertising
    /// `next_hop_mtu` and drop the original.
    EmitPacketTooBig { next_hop_mtu: u16 },
}

/// Compute the egress-MTU decision for a forwarded L3 frame that the TCP
/// segmentation path did NOT handle.
///
/// `frame` is the frame as it will leave the egress interface (post-NAT /
/// post-header-rewrite). `l3_offset` is where the L3 header starts in that
/// frame. The decision compares the IP-DECLARED L3 datagram length (the same
/// length authority the PTB builders quote — IPv4 `total_len`, IPv6
/// `40 + payload_len`, each clamped to the buffer) against the resolved
/// egress MTU. It deliberately does NOT use the raw buffer length
/// (`frame.len() - l3_offset`): ethernet padding / trailing bytes beyond the
/// IP datagram would otherwise mis-fire or mis-size the PTB (#2783).
///
/// Returns `Forward` whenever:
///   - no egress MTU is known for the resolution (fail-open: never invent
///     an MTU smaller than the link),
///   - the IP header is unparseable / too short to read the declared length
///     (fail-open rather than over-read a truncated buffer),
///   - the L3 datagram fits the MTU, or
///   - the frame is otherwise unparseable for the MTU check.
///
/// An oversized IPv4 datagram without DF returns
/// [`EgressMtuDecision::ForwardOversizeNoDf`]: no PTB, because the sender did
/// not forbid fragmentation (#9328, #9395).
#[inline]
pub(in crate::afxdp) fn forwarded_egress_mtu_decision(
    frame: &[u8],
    l3_offset: usize,
    addr_family: u8,
    mtu: usize,
) -> EgressMtuDecision {
    if mtu == 0 || l3_offset >= frame.len() {
        return EgressMtuDecision::Forward;
    }
    let packet = &frame[l3_offset..];
    // #2783: size the decision off the IP-DECLARED L3 length — the exact
    // length authority the PTB builders quote — not the AF_XDP buffer
    // length. A buffer that carries ethernet padding / trailing bytes
    // beyond the IP datagram would otherwise fire (or drop) a PTB for a
    // datagram that actually fits the egress MTU, then quote the smaller
    // declared packet, hiding why the decision fired. An unparseable /
    // truncated header (declared length unreadable) fails open to Forward
    // rather than over-reading the buffer.
    let Some(l3_len) = ip_declared_l3_len(packet, addr_family) else {
        return EgressMtuDecision::Forward;
    };
    if l3_len <= mtu {
        return EgressMtuDecision::Forward;
    }
    // The next-hop MTU we advertise. Floor at the protocol minimum so a
    // misconfigured tiny MTU never tells the sender to use an illegal MSS.
    let floor = match addr_family as i32 {
        libc::AF_INET6 => 1280usize,
        _ => 68usize, // RFC 791 minimum IPv4 reassembly buffer / link MTU floor
    };
    let next_hop_mtu = mtu.max(floor).min(u16::MAX as usize) as u16;
    match addr_family as i32 {
        libc::AF_INET => {
            // Only signal PTB when the sender forbade fragmentation
            // (DF=1). A non-DF oversized datagram is the downstream's to
            // fragment; PTB-storming it would regress the prior behaviour.
            if ipv4_df_set(packet) {
                EgressMtuDecision::EmitPacketTooBig { next_hop_mtu }
            } else {
                // #9328 records it and #9395 decided to keep forwarding it. No
                // PTB: ICMP Fragmentation-Needed is meaningful only to a sender
                // that set DF, and this one did not. What happens next on each
                // path is stated once, on `ForwardOversizeNoDf`.
                EgressMtuDecision::ForwardOversizeNoDf
            }
        }
        // IPv6 routers never fragment in transit (RFC 8200 §4.5) — always
        // signal Packet-Too-Big.
        libc::AF_INET6 => EgressMtuDecision::EmitPacketTooBig { next_hop_mtu },
        _ => EgressMtuDecision::Forward,
    }
}

/// #2330: the inner-source post-transform MTU for a size-changing forward
/// path (NAT64 / native GRE / WireGuard).
///
/// #2301's `forwarded_egress_mtu_decision` compares the SOURCE frame against
/// the egress MTU, which is correct ONLY for a plain forward where the
/// on-wire size does not change. For a transformed path the on-wire frame
/// GROWS (GRE/WG encap) or its header SHRINKS/GROWS (NAT64 v6<->v4), so a
/// source-frame-vs-egress-MTU comparison is wrong and #2301 deliberately
/// SKIPS these paths (`if !is_nat64 && !uses_native_tunnel`). The result was
/// a silent blackhole: an inner source whose packet will not fit
/// post-transform got NO PMTUD signal.
///
/// This returns the largest INNER IP packet length (the L3 size of the
/// pre-transform `source_frame` the dispatcher already holds) whose
/// transformed frame is guaranteed to fit the egress/transport MTU. Feeding
/// it to `forwarded_egress_mtu_decision` as the `mtu` argument turns the
/// existing per-family DF/IPv6 decision + the existing PTB builders into the
/// correct INNER-source signal:
///   - GRE: the #2300 SSOT `native_gre_inner_mtu` (transport MTU minus the
///     outer IP + GRE[+key] header) — the SAME value the #2331 encap drop
///     guard enforces, so this site and that drop site agree.
///   - WireGuard: the pad-aware `wg::mss::wg_inner_mtu` derived from the
///     PHYSICAL underlay egress MTU (`frame::wg_endpoint_physical_outer_mtu`,
///     the #2680 SSOT) minus the WG outer overhead and worst-case §5.4.6
///     padding — the inverse of the `frame::wg::wg_encapped_size` drop guard,
///     so the advertised inner MTU matches the threshold the guard admits
///     (#2684). NOT `tunnel_outer_mtu`: for a WG flow `endpoint.destination`
///     is zeroed, so that helper falls back to the LOGICAL ifindex MTU
///     (already underlay − encap) and double-subtracts the encap overhead.
///   - NAT64: the egress MTU adjusted by the v6<->v4 header-size delta
///     (RFC 7915): a v6 inner translated to a v4 egress may be 20 bytes
///     LARGER on the inner side; a v4 inner translated to a v6 egress 20
///     bytes SMALLER. The advertised value is floored at the per-family
///     minimum by `forwarded_egress_mtu_decision`.
///
/// Returns 0 (fail-open — never invent a too-small MTU) when the endpoint
/// row is missing, the tunnel kind is unknown, or the computed inner MTU is
/// below the usable minimum (the per-kind inner-MTU helper returns 0). Note:
/// the outer/transport MTU itself always resolves — both `tunnel_outer_mtu`
/// (GRE) and `wg_endpoint_physical_outer_mtu` (WG) fall back to a non-zero
/// MTU — so a 0 return reflects a missing/unknown endpoint or an
/// unusably-small inner budget, never an unresolved outer MTU.
/// `egress_mtu` is the already-resolved physical egress-interface MTU
/// (`forwarded_egress_mtu`); used only for the NAT64 arm (the tunnel arms
/// re-resolve the transport MTU via the SSOT helpers).
pub(in crate::afxdp) fn post_transform_inner_mtu(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    is_nat64: bool,
    inner_addr_family: u8,
    egress_mtu: usize,
    inner_dst: Option<std::net::IpAddr>,
) -> usize {
    // §8896: NAT64 THROUGH A TUNNEL COMPOSES BOTH BUDGETS.
    //
    // Before #8896 the two transforms could not co-occur (§8890 dropped the
    // combination), and this function SELECTED rather than composed: the
    // `is_nat64` arm below returns before any tunnel arm can run, and the
    // `egress_mtu` it adjusts comes from `forwarded_egress_mtu`, which resolves
    // `decision.resolution.egress_ifindex` -- the tunnel LOGICAL ifindex, not
    // the physical underlay the outer header actually egresses.
    //
    // So a composed packet clamped by the `is_nat64` arm alone would advertise
    // an inner MTU too large by the whole GRE/WG encapsulation overhead:
    // packets that satisfy the clamp, encapsulate, and then exceed the
    // underlay. Measured: 1420 where 1396 is correct for an IPv4-outer GRE at
    // a 1400 transport MTU -- 24 bytes over, exactly the outer IP + GRE header.
    // That failure is worse than the black hole §8890 left, because it is
    // intermittent and looks like a path problem rather than a configuration
    // one.
    //
    // Resolve the TUNNEL inner budget first -- it already subtracts the encap
    // overhead from the physical underlay MTU via the §2680 SSOT -- then apply
    // the RFC 7915 header delta on top of that, in the same direction the
    // NAT64-only arm uses.
    if is_nat64 && decision.resolution.tunnel_endpoint_id != 0 {
        let tunnel_inner = tunnel_inner_mtu(decision, forwarding, inner_dst);
        if tunnel_inner == 0 {
            return 0;
        }
        return match inner_addr_family as i32 {
            libc::AF_INET6 => tunnel_inner.saturating_add(20),
            libc::AF_INET => tunnel_inner.saturating_sub(20),
            _ => 0,
        };
    }
    if is_nat64 {
        if egress_mtu == 0 {
            return 0;
        }
        // RFC 7915 §4 / §5: the translator changes the IP header size by 20
        // bytes (IPv6 40 vs IPv4 20). The inner source advertises a PTB in
        // ITS family, so the inner MTU is the egress MTU adjusted by the
        // header delta in the direction that keeps the TRANSLATED frame at
        // or under the egress MTU.
        return match inner_addr_family as i32 {
            // Inner v6 -> egress v4: translated v4 is 20 bytes SMALLER, so a
            // v6 inner up to egress_mtu + 20 still fits the v4 egress. Floor
            // at the IPv6 minimum is applied by the decision helper.
            libc::AF_INET6 => egress_mtu.saturating_add(20),
            // Inner v4 -> egress v6: translated v6 is 20 bytes LARGER, so the
            // v4 inner must be 20 bytes SMALLER than the v6 egress MTU.
            libc::AF_INET => egress_mtu.saturating_sub(20),
            _ => 0,
        };
    }
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    tunnel_inner_mtu(decision, forwarding, inner_dst)
}

/// The tunnel-only inner MTU: the physical underlay MTU less this tunnel
/// mode's encapsulation overhead.
///
/// Extracted from `post_transform_inner_mtu` by §8896 so the NAT64+tunnel arm
/// can compose the RFC 7915 header delta ON TOP of it rather than replacing
/// it. Returns 0 for a missing endpoint row or an unknown mode, matching the
/// §2327 fail-closed posture the frame builders use.
fn tunnel_inner_mtu(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    inner_dst: Option<std::net::IpAddr>,
) -> usize {
    let Some(endpoint) = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
    else {
        return 0;
    };
    match tunnel_mode_kind(&endpoint.mode) {
        // GRE's `endpoint.destination` is the real outer hop, so
        // `native_gre_inner_mtu`'s `tunnel_outer_mtu` resolves to the
        // physical underlay MTU correctly — leave it.
        TunnelKind::Gre => native_gre_inner_mtu(forwarding, decision),
        TunnelKind::WireGuard => {
            // #2684: resolve the outer MTU via the PHYSICAL underlay egress
            // (the #2680 SSOT), NOT `tunnel_outer_mtu`. For a WG transit flow
            // `endpoint.destination` is zeroed (the peer carries the outer
            // hop), so `tunnel_outer_mtu` falls back to the tunnel LOGICAL
            // ifindex MTU (~1420) — already underlay − encap. Feeding that to
            // `wg_inner_mtu` double-subtracts the WG encap overhead and
            // under-advertises the inner PMTU by ~one encap. Using the
            // physical underlay MTU (~1500) makes the advertised inner MTU
            // match the encap drop guard's admit threshold
            // (`wg_inner_mtu(physical)`), so DF-IPv4 / IPv6 inners get the
            // same PMTU the guard tolerates instead of ~100B too small.
            //
            // #2845: thread the inner destination so the underlay MTU is
            // derived from the SAME peer the encap path will select (per-peer
            // underlay), not an arbitrary first peer's. Two peers of one wg
            // interface can egress different underlays with different MTUs.
            let outer_mtu = crate::afxdp::frame::wg_endpoint_physical_outer_mtu(
                decision, forwarding, endpoint, inner_dst,
            );
            crate::afxdp::wg::mss::wg_inner_mtu(endpoint.outer_family, outer_mtu)
        }
        TunnelKind::Unknown => 0,
    }
}

/// Compute the IP-declared L3 datagram length (header + payload) for the
/// egress-MTU decision, mirroring exactly what the PTB builders quote.
///
/// `packet` is the L3 (IP-header-first) slice of the frame. Returns the
/// number of bytes the IP header *says* the datagram is, clamped to what is
/// actually present in the buffer:
///   - IPv4: `total_len` (bytes 2..4), `.min(packet.len())`
///     (`build_frag_needed_v4`).
///   - IPv6: `40 + payload_len` (bytes 4..6), `.min(packet.len())`
///     (`build_packet_too_big_v6`).
///
/// Returns `None` when the IP header is too short to read the declared
/// length (a truncated / malformed packet) so the decision can fail-open to
/// `Forward` rather than over-read or invent a length. This is the SINGLE
/// length authority shared by the decision and the builders (#2783): using
/// the on-wire buffer length (`frame.len() - l3_offset`) for the decision
/// while the builders quote the IP-declared length lets ethernet padding /
/// trailing bytes mis-fire a PTB (false positive) or, conversely, a
/// short-buffer-but-large-declared packet miss one.
#[inline]
fn ip_declared_l3_len(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            Some(total_len.min(packet.len()))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            Some((40 + payload_len).min(packet.len()))
        }
        _ => None,
    }
}

/// Read the IPv4 Don't-Fragment bit from an L3 (IP-header-first) slice.
#[inline]
fn ipv4_df_set(packet: &[u8]) -> bool {
    // Bytes 6..8 are flags+fragment-offset; DF is bit 14 (0x4000).
    packet
        .get(6)
        .map(|&b| (b & 0x40) != 0)
        .unwrap_or(false)
}

/// RFC error-suppression gate shared by the PTB path. Mirrors the reject
/// path: never reply to a non-first fragment (no transport header to quote
/// / key), to a trigger frame whose link-layer (L2) destination was
/// group/broadcast (RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e), #2325 — a
/// datagram delivered as an L2 broadcast/multicast must not generate an
/// error), to a trigger packet whose IP (L3) destination was
/// multicast/broadcast (#2314 — a multicast flood must not be amplified
/// into an ICMP-error backscatter storm), or to an inbound ICMP/ICMPv6
/// *error* message (avoid error loops and amplification). Returns true
/// when a PTB MUST be suppressed.
///
/// `forwarding` supplies the connected-route table for the #2411 IPv4
/// directed-broadcast check (RFC 1812 §4.3.2.7): a PTB to the all-ones
/// host of a connected subnet (e.g. `10.0.1.255` for `10.0.1.0/24`) is a
/// subnet-directed broadcast and must be suppressed. v4-only; the table
/// scan is a cold-path lookup that runs only when a PTB is about to be
/// generated.
#[inline]
pub(in crate::afxdp) fn ptb_reply_suppressed(
    frame: &[u8],
    meta: UserspaceDpMeta,
    l3_offset: usize,
    forwarding: &ForwardingState,
) -> bool {
    // #2325: never generate a PTB in reply to a datagram delivered as an
    // L2 broadcast/multicast frame. This gives the PTB path the same L2
    // suppression that the reject / Time-Exceeded path
    // (`can_generate_icmp_error_reply`) has. `frame` is the full trigger
    // ethernet frame (the same slice the PTB builders read the reflected
    // destination MAC from), so the L2 dst is the first 6 bytes.
    if let Some(eth_dst) = frame.get(0..6)
        && let Ok(eth_dst) = <&[u8; 6]>::try_from(eth_dst)
        && l2_dst_is_group_or_broadcast(eth_dst)
    {
        return true;
    }
    let Some(packet) = frame.get(l3_offset..) else {
        return true;
    };
    if is_non_first_fragment(packet, meta.addr_family) {
        return true;
    }
    // #2367: never generate a PTB in reply to a datagram whose IP SOURCE
    // is not a single unicast host (unspecified, loopback, multicast, or
    // — for IPv4 — broadcast). The PTB is addressed to the trigger's
    // source, so a forbidden source would produce spoofable ICMP
    // backscatter. Routes through the shared predicate so the PTB,
    // reject, and Time-Exceeded paths agree on the bad-source set
    // (RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e)).
    if source_is_invalid_for_icmp_error(meta.addr_family, packet) {
        return true;
    }
    // #2487: never generate a PTB in reply to an IPv4 subnet-directed
    // broadcast SOURCE (all-ones host of a connected prefix). The PTB is
    // addressed to the trigger's source, so a directed-broadcast source
    // would send the PTB to that directed broadcast (Smurf backscatter);
    // `source_is_invalid_for_icmp_error` only catches the limited
    // broadcast (255.255.255.255). v4-only — IPv6 has no broadcast and
    // `src_is_directed_broadcast` reads the v4 source octets, so it is
    // gated on AF_INET (matching the #2411 destination gate below).
    if meta.addr_family as i32 == libc::AF_INET && src_is_directed_broadcast(forwarding, packet) {
        return true;
    }
    // #2314: never generate a PTB in reply to a datagram whose IP
    // destination was multicast or broadcast.
    if dest_is_multicast_or_broadcast(meta.addr_family, packet) {
        return true;
    }
    // #2411: never generate a PTB in reply to an IPv4 subnet-directed
    // broadcast (all-ones host of a connected prefix). v4-only — IPv6
    // has no broadcast and `dest_is_directed_broadcast` reads the v4
    // destination octets, so it is gated on AF_INET.
    if meta.addr_family as i32 == libc::AF_INET && dest_is_directed_broadcast(forwarding, packet) {
        return true;
    }
    if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        let Some(&icmp_type) = frame.get(meta.l4_offset as usize) else {
            return true;
        };
        if reject_icmp_reply_suppressed(meta.protocol, icmp_type) {
            return true;
        }
    }
    false
}

/// Build a local-origin ICMPv4 Destination Unreachable (type 3, code 4 —
/// Fragmentation Needed and DF Set), reflecting L2 back to the sender and
/// sourcing the outer IP from the ingress interface primary v4. The
/// next-hop MTU is written into the low 16 bits of the otherwise-unused
/// word per RFC 1191. Quotes the inbound IP header plus the first 8 L4
/// bytes (RFC 792).
pub(in crate::afxdp) fn build_frag_needed_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    next_hop_mtu: u16,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_tag) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v4?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let dst_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let packet_len = total_len.min(packet.len());
    let quoted_len = packet_len.min(ihl.saturating_add(8));
    let tag = if ingress_tag.emits() {
        ingress_tag
    } else {
        TxVlanTag::from(egress.vlan_id)
    };
    let eth_len = tag.header_len();
    let total_len = 20usize.checked_add(8)?.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + total_len);
    write_eth_header_tagged(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        tag,
        0x0800,
    );
    let ip_start = out.len();
    out.resize(ip_start + 20, 0);
    write_ipv4_header(
        &mut out[ip_start..ip_start + 20],
        src_ip,
        dst_ip,
        PROTO_ICMP,
        /* tos */ 0,
        /* ttl */ 64,
        total_len as u16,
    )?;
    let icmp_start = out.len();
    // type=3 code=4; bytes 4..6 unused (0); bytes 6..8 = next-hop MTU.
    out.extend_from_slice(&[3, 4, 0, 0, 0, 0]);
    out.extend_from_slice(&next_hop_mtu.to_be_bytes());
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16(&out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

/// Build a local-origin ICMPv6 Packet Too Big (type 2, code 0), reflecting
/// L2 back to the sender and sourcing the outer IP from the ingress
/// interface primary v6. The MTU is written into the 32-bit field that
/// follows the checksum (RFC 4443 §3.2). Quotes as much of the inbound
/// packet as fits under the IPv6 minimum MTU (1280) so the reply itself is
/// never oversized.
pub(in crate::afxdp) fn build_packet_too_big_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
    mtu: u32,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_tag) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v6?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let packet_len = (40 + payload_len).min(packet.len());
    // RFC 4443 §3.2: the error must not exceed the IPv6 minimum MTU. Cap
    // the quote so eth + 40 (outer IP) + 8 (ICMPv6 header) + quote <= 1280.
    let tag = if ingress_tag.emits() {
        ingress_tag
    } else {
        TxVlanTag::from(egress.vlan_id)
    };
    let eth_len = tag.header_len();
    let max_quote = 1280usize.saturating_sub(40 + 8);
    let quoted_len = packet_len.min(max_quote);
    let outer_payload_len = 8usize.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + 40 + outer_payload_len);
    write_eth_header_tagged(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        tag,
        0x86dd,
    );
    let ip_start = out.len();
    out.resize(ip_start + 40, 0);
    write_ipv6_header(
        &mut out[ip_start..ip_start + 40],
        src_ip,
        dst_ip,
        PROTO_ICMPV6,
        /* traffic_class */ 0,
        /* flow_label */ 0,
        /* hop_limit */ 64,
        outer_payload_len as u16,
    )?;
    let icmp_start = out.len();
    // type=2 code=0; bytes 4..8 = MTU (replaces the "unused" word).
    out.extend_from_slice(&[2, 0, 0, 0]);
    out.extend_from_slice(&mtu.to_be_bytes());
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

/// Parse the inbound L2 header for a reflected local-origin reply: swapped
/// MACs plus the full ingress 802.1Q/802.1ad tag. Local copy of the
/// icmp.rs helper so this module does not depend on a `pub` widening of a
/// private icmp.rs function (icmp.rs is edited in parallel by #2237/#2242).
fn ingress_reply_l2(frame: &[u8]) -> Option<([u8; 6], [u8; 6], TxVlanTag)> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac = <[u8; 6]>::try_from(frame.get(0..6)?).ok()?;
    let src_mac = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    let ingress_tag = if matches!(eth_proto, TPID_8021Q | TPID_8021AD) {
        let tci = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
        TxVlanTag {
            tpid: eth_proto,
            tci,
            present: true,
        }
    } else {
        TxVlanTag::NONE
    };
    Some((src_mac, dst_mac, ingress_tag))
}

#[cfg(test)]
#[path = "icmp_ptb_tests.rs"]
mod tests;
