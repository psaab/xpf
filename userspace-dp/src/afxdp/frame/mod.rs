use super::*;

mod byte_writes;
pub(crate) mod checksum;
mod generated;
mod headers;
mod addr_class;
mod inspect;
mod tcp;
mod wg;

// #2238: parse a locally-generated reply frame back into its own egress
// classification key. Re-exported at `pub(in crate::afxdp)` so the shared
// classifier in `tx/cos_classify.rs` (a sibling afxdp module) can reach it.
pub(in crate::afxdp) use generated::generated_reply_session_key;

// #2684: the WG physical-underlay outer MTU SSOT, re-exported so the TX
// dispatcher's `post_transform_inner_mtu` (icmp_ptb.rs) derives the PTB
// inner MTU from the SAME physical underlay the encap drop guard admits
// against (the `mod wg` submodule itself is private to `frame`).
pub(in crate::afxdp) use wg::wg_endpoint_physical_outer_mtu;

// #6308: the WG transit-egress DISPATCH physical-egress SSOT, re-exported so
// the forward-request builder (`forward_request.rs`) selects the same physical
// underlay NIC (the peer route) for the egress binding that #5292 selects for
// the frame bytes — otherwise a specific-peer-route + no-default-route WG flow
// resolves the egress binding to the logical wgN ifindex (no XSK binding) and
// the TX dispatcher NO_EGRESS_BINDING-drops it.
pub(in crate::afxdp) use wg::wg_transit_egress_physical_egress_ifindex;

// #1440 consolidated outer-header serializers. Re-exported at
// `frame::write_eth_header`, `frame::write_eth_header_slice`, and
// `frame::headers::*` to keep existing call sites in icmp.rs,
// gre.rs, poll_stages.rs, tx/*, etc. importing from their current
// paths. The previous in-place definitions in this file were
// moved verbatim into headers.rs.
pub(in crate::afxdp) use headers::{
    TPID_8021AD, TPID_8021Q, TxVlanTag, eth_header_len, write_eth_header,
    write_eth_header_tagged, write_ipv4_header, write_ipv6_header, write_udp_header,
};
// #2844: re-exported `pub(crate)` so the top-level `crate::nat64`
// module (outside `crate::afxdp`) can use the one SSOT Ethernet writer.
pub(crate) use headers::write_eth_header_slice;

use byte_writes::{
    write_ipv4_dst, write_ipv4_src, write_ipv6_dst, write_ipv6_src, write_l4_dst_port,
    write_l4_src_port,
};

// Cross-module helpers reach into `frame::*` via the explicit list
// below. `adjust_l4_checksum_ipv6_addr_bytes` is file-private to
// `checksum.rs` (only the SNAT/DNAT rewrites here call it) and is
// pulled in via a non-pub `use` to avoid a glob re-export at a
// wider visibility than its own.
use checksum::{
    ChecksumFamily, adjust_l4_checksum_ipv6_addr_bytes, adjust_zero_checksum_illegal,
    checksum_family_of, l4_checksum_field_delta_v4, l4_checksum_field_delta_v6,
    l4_udp_checksum_optional,
};
pub(in crate::afxdp) use checksum::{
    adjust_ipv4_header_checksum, adjust_l4_checksum_ipv4, adjust_l4_checksum_ipv4_dst,
    adjust_l4_checksum_ipv4_src, adjust_l4_checksum_ipv4_words, adjust_l4_checksum_ipv6_words,
    checksum16, checksum16_add_bytes, checksum16_adjust, checksum16_finish, checksum16_ipv4,
    checksum16_ipv6, ipv6_words_from_octets, ipv6_words_from_slice,
    recompute_l4_checksum_ipv4, recompute_l4_checksum_ipv6, saturate_len16,
};

// Phase 2: header inspection / parsing helpers extracted to `inspect`.
// `frame_has_tcp_rst`, `decode_frame_summary`, `try_parse_metadata`,
// `authoritative_forward_ports`, and `forward_tuple_mismatch_reason` are
// reached for from afxdp.rs / tx/transmit.rs / tx/dispatch.rs /
// cos/queue_service.rs, so they go out at `pub(in crate::afxdp)`. The
// rest stay at `pub(super)` (afxdp-only callers in sibling files).
// #4435: re-exported `pub(crate)` (like `write_eth_header_slice` above)
// so `crate::nat64`'s private ext-header walkers share the single
// canonical bound instead of hardcoding a stale 6.
pub(crate) use inspect::MAX_IPV6_EXT_HEADERS;
// #6435: the single shared IPv6 extension-header walk and its verdict
// enum, re-exported `pub(crate)` (same channel as the bound above) so
// `crate::nat64`'s L4/fragment walkers fold the canonical walk instead of
// hand-mirroring it. The embedded-ICMP walker
// (`afxdp/icmp_embed/parse.rs`) reaches the same items through the
// `crate::afxdp` re-export + `use super::*` chain. The `ExtChainWalk` /
// `ExtChainFragment` container types stay inspect-local — callers read
// their fields, never name them.
pub(crate) use inspect::{ExtChainOutcome, ipv6_ext_header_is_traversable, walk_ipv6_ext_chain};
pub(super) use inspect::{
    frame_is_non_first_fragment, frame_l3_offset, frame_l4_offset,
    live_frame_ports, live_frame_ports_bytes, live_frame_ports_from_meta_bytes,
    metadata_tuple_complete, packet_rel_l4_offset, packet_rel_l4_offset_and_protocol,
    parse_flow_ports, parse_ipv4_session_flow_from_frame, parse_packet_destination_from_frame,
    parse_session_flow_from_bytes, parse_session_flow_from_frame, parse_session_flow_from_meta,
    parse_zone_encoded_fabric_ingress, parse_zone_encoded_fabric_ingress_from_frame,
};
pub(in crate::afxdp) use inspect::{
    authoritative_forward_ports, decode_frame_summary, declared_l3_end, dest_is_directed_broadcast,
    dest_is_multicast_or_broadcast, forward_tuple_mismatch_reason, ipv4_is_any_fragment,
    ipv4_is_non_first_fragment, ipv6_ext_chain_over_limit, ipv6_is_any_fragment,
    ipv6_is_non_first_fragment, is_any_fragment,
    L3_CTX_NONE_UNSPECIFIED_ADDR, is_non_first_fragment, l3_enforcement_flow_from_meta,
    l3_session_flow_from_meta,
    l2_dst_is_group_or_broadcast, meta_icmp_identifier_bearing, neighbor_ip_is_learnable,
    neighbor_mac_is_learnable,
    parse_session_flow,
    source_is_invalid_for_icmp_error,
    src_is_directed_broadcast, term_match_extra_from_frame,
    term_match_extra_from_meta,
    try_parse_metadata,
};

// #989: TCP-specific inspection + mutation kernels relocated from
// frame/inspect.rs and forwarding/mod.rs. Visibility split mirrors
// the inspect re-exports above:
//   - frame_has_tcp_rst: pub(in crate::afxdp) so afxdp.rs / tx
//     callers continue to see it via the wider re-export path.
//   - the remaining helpers stay at pub(super) (or fn-private for
//     the clamp helpers, which are only used inside frame/mod.rs).
#[allow(unused_imports)]
pub(in crate::afxdp) use tcp::{
    build_reject_rst_frame, build_syn_cookie_ack_rst_frame, build_syn_cookie_syn_ack_frame,
    frame_has_tcp_rst, tcp_payload_offset,
};
pub(super) use tcp::{extract_tcp_flags_and_window, extract_tcp_window, tcp_flags_str};
// #4074: the ICMP identifier-bearing query-type gate, reused by the NAT
// identifier rewriter (`apply_nat_icmp_identifier_rewrite`).
use inspect::icmp_identifier_bearing;
// #1352: clamp_tcp_mss_frame is now imported directly by the per-family
// helpers in frame/build/{ipv4,ipv6}.rs.

// #1046: TCP segmentation builders extracted into tcp_segmentation.rs
// to keep frame/mod.rs under the modularity-discipline LOC threshold.
// Re-exported at `pub(in crate::afxdp)` so afxdp.rs's `use self::frame::*;`
// continues to surface them at the same call sites in tx/dispatch.rs.
mod tcp_segmentation;
pub(in crate::afxdp) use tcp_segmentation::{
    finalize_tcp_segment_headers, segment_forwarded_tcp_frames,
    segment_forwarded_tcp_frames_from_frame,
};

// #1352 — extracted build orchestrator + per-address-family helpers.
// See docs/pr/1352-frame-build-rewrite-split/plan.md.
// Wrappers (build_forwarded_frame_from_frame, build_forwarded_frame_into)
// stay in this file and forward into the orchestrator after
// converting the meta type via .into().
mod build;
pub(in crate::afxdp) use build::build_forwarded_frame_into_from_frame;

// #1352 — extracted apply_rewrite_descriptor orchestrator + per-AF helpers.
mod rewrite;
pub(in crate::afxdp) use rewrite::apply_rewrite_descriptor;

/// IPv6 L4 offset relative to the L3 header: trust the metadata when it
/// is plausible (`meta_rel >= 40` and `l4 > l3`), else walk the
/// extension-header chain. SINGLE source of offset truth for both
/// rewrite paths (#1838) — the descriptor fast path
/// (`rewrite/ipv6.rs`), the generic in-place rewrite
/// (`rewrite_apply_v6`), the copy builder (`build/ipv6.rs`), the
/// slow-path NAT extract, and the ICMPv6-error NAT reversal builder
/// (`icmp_embed/builders.rs`) all derive the offset here, so the
/// meta-led precedence rule cannot drift between paths.
///
/// `packet` is the L3-relative slice; `l3_offset`/`l4_offset` are the
/// frame-relative metadata scalars (only their difference is used).
#[inline(always)]
pub(in crate::afxdp) fn v6_rel_l4_offset(
    packet: &[u8],
    l3_offset: u16,
    l4_offset: u16,
    addr_family: u8,
) -> Option<usize> {
    let meta_rel = l4_offset.wrapping_sub(l3_offset) as usize;
    if meta_rel >= 40 && l4_offset > l3_offset {
        Some(meta_rel)
    } else {
        packet_rel_l4_offset(packet, addr_family)
    }
}

/// Rewrite the DSCP (IPv4 TOS high 6 bits / IPv6 traffic-class high 6 bits) of
/// `frame` in place, incrementally fixing the IPv4 header checksum.
///
/// Returns `Some(())` when the DSCP was written (or already matched, a no-op
/// success). Returns `None` when the frame has no IPv4/IPv6 DSCP field to
/// rewrite: a non-IP frame (ARP and friends) or one too short to hold its L3
/// header. `None` is a benign "not applicable" outcome, NOT a forwarding error
/// — TX-path callers `let _` it because a per-CoS-queue DSCP rewrite is stamped
/// onto every queued item and non-IP frames legitimately co-reside in a
/// DSCP-rewrite queue. The frame is transmitted either way; see the "#4423
/// M3/M4" note in `afxdp/README.md`.
pub(in crate::afxdp) fn apply_dscp_rewrite_to_frame(frame: &mut [u8], dscp: u8) -> Option<()> {
    let dscp = dscp & 0x3f;
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get_mut(l3..)?;
    match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let new_tos = (dscp << 2) | (ip[1] & 0x03);
            if new_tos == ip[1] {
                return Some(());
            }
            let old_word = u16::from_be_bytes([ip[0], ip[1]]);
            let new_word = u16::from_be_bytes([ip[0], new_tos]);
            let current = u16::from_be_bytes([ip[10], ip[11]]);
            let updated = checksum16_adjust(current, &[old_word], &[new_word]);
            ip[1] = new_tos;
            ip[10] = (updated >> 8) as u8;
            ip[11] = updated as u8;
            Some(())
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let current_tc = ((ip[0] & 0x0f) << 4) | (ip[1] >> 4);
            let new_tc = (dscp << 2) | (current_tc & 0x03);
            if new_tc == current_tc {
                return Some(());
            }
            ip[0] = (ip[0] & 0xf0) | (new_tc >> 4);
            ip[1] = ((new_tc & 0x0f) << 4) | (ip[1] & 0x0f);
            Some(())
        }
        _ => None,
    }
}

pub(super) fn build_injected_packet(
    req: &InjectPacketRequest,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    resolution: ForwardingResolution,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let dst_mac = resolution
        .neighbor_mac
        .ok_or_else(|| "missing neighbor MAC".to_string())?;
    match (src, dst) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            build_injected_ipv4(req, dst_mac, src_v4, dst_v4, src_port, egress)
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            build_injected_ipv6(req, dst_mac, src_v6, dst_v6, src_port, egress)
        }
        _ => Err("injected packet source and destination address families differ".to_string()),
    }
}

/// Build a forwarded frame for NAT64 packets. NAT64 changes the IP address
/// family so the frame size changes (IPv6→IPv4 shrinks by 20, IPv4→IPv6 grows
/// by 20). This always uses a copy path — in-place rewrite is not possible.
///
/// # §8896: a tunnel-marked NAT64 decision is now ENCAPSULATED
///
/// §8890 made this combination fail closed. Before that gate, measured at
/// `c2e0a9ecb`, a tunnel-marked NAT64 decision emitted a frame **byte-identical
/// to the no-tunnel control** — plain IPv4 on the underlay for traffic an
/// operator had routed through WireGuard. The gate replaced that with a drop
/// and a `nat64_tunnel_encap_unsupported` counter: correct, but a black hole.
///
/// `build_nat64_forwarded_frame` below now composes the two transforms. The
/// two things §8890 recorded as unresolved were measured before this landed:
///
/// **What the encapsulators read from `meta`.** Exactly two fields, and both
/// encapsulators read the same two: `addr_family` at three sites each
/// (`packet_trimmed_len`, `inner_dst_ip` for WG AllowedIPs peer selection, and
/// `inner_tos_byte` for the §2303 DSCP copy) and `l3_offset` as a single
/// fallback. `l3_offset` is self-correcting — `frame_l3_offset(inner_frame)` is
/// consulted first and only falls back to meta — so `addr_family` is the field
/// that must be rebuilt. `nat64_translated_meta` rebuilds both anyway, and
/// `nat64_8896_encap_ignores_every_meta_field_but_family_and_l3` poisons every
/// OTHER field and asserts the emitted bytes do not change, so this claim reds
/// if a third field is ever read.
///
/// **Whether the outer identity survives a family change.** It does, and the
/// reason is that neither encapsulator derives the outer from the inner family.
/// Native GRE takes `endpoint.outer_family` and `endpoint.destination` for the
/// outer L3 and `decision.resolution.{neighbor_mac, src_mac, tx_vlan_id}` for
/// the outer L2. WireGuard selects the peer from `inner_dst` and then takes the
/// outer family from `peer_endpoint.is_ipv6()` and the outer MTU from the
/// PHYSICAL underlay egress (§2680/§3992/§5292 SSOT). The only inner-dependent
/// input in either is `inner_dst`/`inner_tos`, and both are correct once
/// `addr_family` is.
///
/// The §2327 fail-closed posture is preserved verbatim: an endpoint id that
/// resolves to no row, or to a row whose mode is neither GRE nor WireGuard, is
/// DROPPED rather than emitted. A fail-OPEN default in a security appliance is
/// the defect, and that has not changed — what changed is that a KNOWN mode is
/// no longer part of the unsupported set.
///
/// `nat64_tunnel_encap_unsupported` now counts only that genuine residue.
pub(super) fn build_nat64_forwarded_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    nat64_reverse: Option<&Nat64ReverseInfo>,
    no_v6_frag_header: bool,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let inner = build_nat64_inner_frame(frame, meta, decision, nat64_reverse, no_v6_frag_header)?;
    if decision.resolution.tunnel_endpoint_id == 0 {
        return Some(inner);
    }
    // §8896: the inner frame's family is the TRANSLATED one, not the ingress
    // family `meta` still describes. Passing `meta` through unchanged is the
    // defect §8890 refused to ship: an IPv4 frame parsed as IPv6 yields a wrong
    // length, a destination read past the header into the TCP payload, and
    // therefore the wrong WireGuard peer or none.
    let inner_meta = nat64_translated_meta(meta, decision)?;
    // §2327 preserved: dispatch on the TYPED kind and FAIL CLOSED on an
    // unknown or missing mode.
    let kind = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
        .map(|e| tunnel_mode_kind(&e.mode));
    match kind {
        Some(TunnelKind::WireGuard) => wg::wg_encap_frame(&inner, inner_meta, decision, forwarding),
        Some(TunnelKind::Gre) => {
            encapsulate_native_gre_frame(&inner, inner_meta, decision, forwarding)
        }
        Some(TunnelKind::Unknown) | None => None,
    }
}

/// §8896: rebuild the two `ForwardPacketMeta` fields the tunnel encapsulators
/// read, for a frame whose IP family NAT64 has just changed.
///
/// Returns `None` for an ingress family that is neither v4 nor v6 — the same
/// arm `build_nat64_inner_frame` rejects, so a frame that reached here always
/// has one of the two.
fn nat64_translated_meta(
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
) -> Option<ForwardPacketMeta> {
    let translated_family = match meta.addr_family as i32 {
        libc::AF_INET6 => libc::AF_INET as u8,
        libc::AF_INET => libc::AF_INET6 as u8,
        _ => return None,
    };
    let mut out = meta;
    out.addr_family = translated_family;
    // The built frame carries its own ethernet header, sized by the egress
    // VLAN rather than by the ingress one `meta.l3_offset` describes.
    out.l3_offset = if decision.resolution.tx_vlan_id > 0 { 18 } else { 14 };
    Some(out)
}

fn build_nat64_inner_frame(
    frame: &[u8],
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    nat64_reverse: Option<&Nat64ReverseInfo>,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;

    match meta.addr_family as i32 {
        libc::AF_INET6 => {
            // Forward direction: IPv6 → IPv4.
            let snat_v4 = match decision.nat.rewrite_src {
                Some(IpAddr::V4(v4)) => v4,
                _ => return None,
            };
            let dst_v4 = match decision.nat.rewrite_dst {
                Some(IpAddr::V4(v4)) => v4,
                _ => return None,
            };
            // #2562: a NON-first fragment has no L4 header — translate L3-only
            // (payload copied verbatim, no L4/port rewrite). `decision.nat`
            // (snat_v4/dst_v4) is the first fragment's translation, carried here
            // by the fragment-association cache consult. Reached only for a
            // non-first fragment whose first fragment installed an association;
            // an unassociated non-first fragment never gets a NAT64 decision and
            // is dropped fail-closed upstream (#4617).
            if let Some(l3) = frame_l3_offset(frame)
                && is_non_first_fragment(frame.get(l3..)?, libc::AF_INET6 as u8)
            {
                return crate::nat64::build_nat64_v6_to_v4_nonfirst_frame(
                    frame, snat_v4, dst_v4, dst_mac, src_mac, vlan_id,
                );
            }
            let mut out = crate::nat64::build_nat64_v6_to_v4_frame(
                frame,
                snat_v4,
                dst_v4,
                dst_mac,
                src_mac,
                vlan_id,
                no_v6_frag_header,
            )?;
            // #4381: rewrite the L4 SOURCE port / ICMP identifier to the unique
            // translated value the forward decision carries in `rewrite_src_port`
            // (RFC 6146 BIB). The output is IPv4; ICMPv6 mapped to ICMPv4.
            let out_protocol = if meta.protocol == PROTO_ICMPV6 {
                PROTO_ICMP
            } else {
                meta.protocol
            };
            apply_nat64_port_translation(&mut out, libc::AF_INET as u8, out_protocol, decision.nat)?;
            Some(out)
        }
        libc::AF_INET => {
            // Reverse direction: IPv4 → IPv6 (reply from server).
            let info = nat64_reverse?;
            // #2562: a NON-first reply fragment has no L4 header — translate
            // L3-only (payload verbatim, no L4/port rewrite) using the reverse
            // association (`orig_dst_v6`/`orig_src_v6`) the first reply fragment
            // installed. Reached only when the reverse fragment-association
            // consult supplies `nat64_reverse`; an unassociated non-first reply
            // fragment is dropped fail-closed upstream (#4617).
            if let Some(l3) = frame_l3_offset(frame)
                && is_non_first_fragment(frame.get(l3..)?, libc::AF_INET as u8)
            {
                return crate::nat64::build_nat64_v4_to_v6_nonfirst_frame(
                    frame,
                    info.orig_dst_v6,
                    info.orig_src_v6,
                    dst_mac,
                    src_mac,
                    vlan_id,
                );
            }
            // Reply: src_v6 = original dst (NAT64 prefix + server), dst_v6 = original client
            let mut out = crate::nat64::build_nat64_v4_to_v6_frame(
                frame,
                info.orig_dst_v6,
                info.orig_src_v6,
                dst_mac,
                src_mac,
                vlan_id,
            )?;
            // #4381: restore the ORIGINAL client L4 field. The reply arrived with
            // the translated source port/id as its DESTINATION (that is what the
            // server replied to), so the reverse session's decision — produced by
            // `NatDecision::reverse` — carries the original in `rewrite_dst_port`,
            // and the port/identifier rewriters map it back on the L4 DESTINATION.
            // The output is IPv6; ICMPv4 mapped to ICMPv6.
            let out_protocol = if meta.protocol == PROTO_ICMP {
                PROTO_ICMPV6
            } else {
                meta.protocol
            };
            apply_nat64_port_translation(&mut out, libc::AF_INET6 as u8, out_protocol, decision.nat)?;
            Some(out)
        }
        _ => None,
    }
}

/// #4381: apply the NAT64 translated L4 port / ICMP-identifier rewrite to an
/// already address-translated output frame, reusing the same-family
/// `apply_nat_port_rewrite` / `apply_nat_icmp_identifier_rewrite` (and their
/// incremental-checksum handling) rather than a NAT64-private port rewriter.
///
/// The port/identifier value is carried on `nat`: the FORWARD decision sets the
/// unique translated value in `rewrite_src_port` (rewrites the L4 SOURCE); the
/// REVERSE decision — produced by `NatDecision::reverse` — sets the original in
/// `rewrite_dst_port` (rewrites the L4 DESTINATION). Both rewriters no-op when
/// their field is unset or the protocol carries no port/identifier, so a NAT64
/// flow with no translatable L4 field (e.g. an ICMP error) is untouched. The
/// address delta was already folded into the L4 checksum by the translator; the
/// port/id delta is a further incremental fold, so the result is exact.
fn apply_nat64_port_translation(
    out: &mut [u8],
    out_addr_family: u8,
    out_protocol: u8,
    nat: NatDecision,
) -> Option<()> {
    let family = checksum_family_of(out_addr_family)?;
    let l4_off = frame_l4_offset(out, out_addr_family)?;
    apply_nat_port_rewrite(out, l4_off, out_protocol, family, nat)?;
    apply_nat_icmp_identifier_rewrite(out, l4_off, out_protocol, family, nat)?;
    Some(())
}

pub(super) fn build_forwarded_frame_from_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let mut out = vec![0u8; frame.len().saturating_add(4)];
    let written = build_forwarded_frame_into_from_frame(
        &mut out,
        frame,
        meta,
        decision,
        forwarding,
        apply_nat_on_fabric,
        expected_ports,
    )?;
    out.truncate(written);
    if decision.resolution.tunnel_endpoint_id != 0 {
        // The endpoint is already fetched for the GRE builder; the
        // `mode` match reads a &str already in hand — no new branch on
        // the plain-forward fast path (#1432 §4.4).
        //
        // #2327: dispatch on the TYPED kind and FAIL CLOSED on an
        // unknown/missing mode. The pre-#2327 `_ => GRE` arm silently
        // GRE-encapsulated any unrecognized or future tunnel mode (a
        // fail-OPEN default in a security appliance). An endpoint id
        // that resolves to no row, or to a row whose mode is neither
        // GRE nor WireGuard, is now DROPPED (`None`) rather than emitted
        // as GRE.
        let kind = forwarding
            .tunnel_endpoints
            .get(&decision.resolution.tunnel_endpoint_id)
            .map(|e| tunnel_mode_kind(&e.mode));
        return match kind {
            Some(TunnelKind::WireGuard) => wg::wg_encap_frame(&out, meta, decision, forwarding),
            Some(TunnelKind::Gre) => encapsulate_native_gre_frame(&out, meta, decision, forwarding),
            // Unknown mode or missing endpoint row: fail closed.
            Some(TunnelKind::Unknown) | None => None,
        };
    }
    Some(out)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_forwarded_frame(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_forwarded_frame_from_frame(frame, meta, decision, forwarding, false, expected_ports)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_forwarded_frame_into(
    out: &mut [u8],
    area: &MmapArea,
    desc: XdpDesc,
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    // v5: orchestrator takes concrete ForwardPacketMeta (#1352 plan).
    let meta = meta.into();
    build_forwarded_frame_into_from_frame(
        out,
        frame,
        meta,
        decision,
        forwarding,
        false,
        expected_ports,
    )
}

/// Common preamble for in-place rewrite: validate L3 offset, compute
/// payload length, pick the TX descriptor view, then write the Ethernet
/// header.
///
/// For VLAN push/pop we avoid moving the L3 payload. AF_XDP lets the TX
/// descriptor point at any byte inside the UMEM chunk; for a push we
/// transmit from `rx_addr - 4`, and for a pop from `rx_addr + 4`. The
/// payload remains at the same physical address, so the rewrite avoids a
/// 1500-byte `memmove` on the common cross-NIC VLAN-transition path.
///
/// If the shifted descriptor would leave the current UMEM frame, fall back
/// to the old copy-within path. That preserves correctness for malformed or
/// unusual descriptors while making the normal 256-byte-headroom path copy-free.
struct RewritePrep {
    #[cfg_attr(not(feature = "debug-log"), allow(dead_code))]
    eth_len: usize,
    ip_start: usize,
    frame_len: usize,
    tx_offset: u64,
    l2_rewrite: InPlaceL2Rewrite,
    apply_nat: bool,
    skip_ttl: bool,
    #[cfg_attr(not(feature = "debug-log"), allow(dead_code))]
    vlan_id: u16, // for the cfg-gated debug-log block
}

struct RewriteEthParams {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
    apply_nat: bool,
}

#[inline]
fn descriptor_view_in_same_umem_frame(rx_addr: u64, tx_addr: u64, len: usize) -> bool {
    let frame_mask = (UMEM_FRAME_SIZE as u64).saturating_sub(1);
    let frame_base = rx_addr & !frame_mask;
    let frame_end = frame_base.saturating_add(UMEM_FRAME_SIZE as u64);
    tx_addr >= frame_base
        && tx_addr
            .checked_add(len as u64)
            .is_some_and(|end| end <= frame_end)
}

#[inline]
fn classify_in_place_l2_rewrite(
    rx_addr: u64,
    current_l3: usize,
    target_eth_len: usize,
    frame_len: usize,
) -> Option<(u64, InPlaceL2Rewrite)> {
    if target_eth_len == current_l3 {
        return Some((rx_addr, InPlaceL2Rewrite::SameLength));
    }
    if current_l3 == 14 && target_eth_len == 18 {
        let Some(tx_addr) = rx_addr.checked_sub(4) else {
            return Some((rx_addr, InPlaceL2Rewrite::VlanPushMemmoveNoHeadroom));
        };
        if descriptor_view_in_same_umem_frame(rx_addr, tx_addr, frame_len) {
            return Some((tx_addr, InPlaceL2Rewrite::VlanPushDescriptor));
        }
        return Some((rx_addr, InPlaceL2Rewrite::VlanPushMemmoveNoHeadroom));
    }
    if current_l3 == 18 && target_eth_len == 14 {
        let tx_addr = rx_addr.checked_add(4)?;
        if descriptor_view_in_same_umem_frame(rx_addr, tx_addr, frame_len) {
            return Some((tx_addr, InPlaceL2Rewrite::VlanPopDescriptor));
        }
    }
    Some((rx_addr, InPlaceL2Rewrite::UnsupportedMemmove))
}

/// The read-only output of `rewrite_plan_eth_from_parts`: the descriptor
/// rewrite plan plus the ORIGINAL-frame geometry the descriptor fast path
/// needs to run its bail gates before mutating UMEM (#5466).
pub(in crate::afxdp::frame) struct EthRewritePlan {
    /// L3 offset within the ORIGINAL (RX) frame at `desc.addr`. Before the
    /// commit's VLAN-push memmove relocates the L3 payload, this is where
    /// the descriptor bail gates must read the IP/L4 header.
    pub(in crate::afxdp::frame) l3: usize,
    /// Trimmed L3 payload length (`== frame_len - eth_len`).
    pub(in crate::afxdp::frame) payload_len: usize,
    /// Post-commit descriptor result (offsets + L2 classification).
    pub(in crate::afxdp::frame) prep: RewritePrep,
}

/// Read-only half of the descriptor rewrite preamble (#5466). Computes the
/// L3 offset, trimmed payload length, target Ethernet length, TX descriptor
/// view, and L2-rewrite classification WITHOUT touching the UMEM frame.
///
/// Split out of `rewrite_prepare_eth_from_parts` so the descriptor fast path
/// can run every bail gate (non-first-fragment / header length / TTL / DMA-race
/// port mismatch) against the pristine frame BEFORE any mutation. A `None`
/// return from a gate then leaves the frame byte-identical, so the caller's
/// generic `.or_else(...)` fallback reprocesses an un-corrupted packet.
#[inline]
fn rewrite_plan_eth_from_parts(
    area: &MmapArea,
    desc: XdpDesc,
    meta: ForwardPacketMeta,
    params: &RewriteEthParams,
) -> Option<EthRewritePlan> {
    let current_len = desc.len as usize;
    let (l3, payload_len) = {
        let frame = area.slice(desc.addr as usize, current_len)?;
        let l3 = match meta.l3_offset {
            14 | 18 => meta.l3_offset as usize,
            _ => frame_l3_offset(frame)?,
        };
        if l3 >= current_len {
            return None;
        }
        (l3, trim_l3_payload(&frame[l3..current_len], meta).len())
    };
    let eth_len = if params.vlan_id > 0 { 18usize } else { 14usize };
    let frame_len = eth_len.checked_add(payload_len)?;
    let (tx_offset, l2_rewrite) = classify_in_place_l2_rewrite(desc.addr, l3, eth_len, frame_len)?;
    // Fabric-ingress packets already had TTL decremented by the
    // sending peer (FABRIC_INGRESS_FLAG = 0x80).
    let skip_ttl = (meta.meta_flags & 0x80) != 0;
    Some(EthRewritePlan {
        l3,
        payload_len,
        prep: RewritePrep {
            eth_len,
            ip_start: eth_len,
            frame_len,
            tx_offset,
            l2_rewrite,
            apply_nat: params.apply_nat,
            skip_ttl,
            vlan_id: params.vlan_id,
        },
    })
}

/// Mutating half of the descriptor rewrite preamble (#5466). Writes the new
/// Ethernet header and, on the VLAN-push-no-headroom / unsupported paths,
/// performs the payload `copy_within` memmove. Every write here mutates UMEM,
/// so this MUST be called only after all descriptor bail gates have passed.
///
/// Body is byte-identical to the mutation block of the pre-#5466
/// `rewrite_prepare_eth_from_parts`, so the generic path (which composes
/// plan + commit via `rewrite_prepare_eth_from_parts` below) is unchanged.
#[inline]
fn rewrite_commit_eth_from_plan(
    area: &MmapArea,
    desc: XdpDesc,
    plan: &EthRewritePlan,
    params: &RewriteEthParams,
) -> Option<()> {
    let l3 = plan.l3;
    let payload_len = plan.payload_len;
    let eth_len = plan.prep.eth_len;
    let frame_len = plan.prep.frame_len;
    let tx_offset = plan.prep.tx_offset;

    if matches!(
        plan.prep.l2_rewrite,
        InPlaceL2Rewrite::VlanPushMemmoveNoHeadroom | InPlaceL2Rewrite::UnsupportedMemmove
    ) {
        let frame_size = UMEM_FRAME_SIZE as u64;
        let frame_offset = desc.addr % frame_size;
        let frame_len_in_chunk = frame_size.checked_sub(frame_offset)?;
        let frame_len_in_chunk = usize::try_from(frame_len_in_chunk).ok()?;
        let frame = unsafe { area.slice_mut_unchecked(desc.addr as usize, frame_len_in_chunk)? };
        let source_end = l3.checked_add(payload_len)?;
        if frame_len > frame.len() || source_end > frame.len() {
            return None;
        }
        // NOTE: the two `?` below (get_mut, write_eth_header_slice) run AFTER
        // this copy_within, but they cannot fail: frame.len() >= frame_len >=
        // eth_len, and write_eth_header_slice only rejects a buffer shorter
        // than eth_len. All fallible geometry checks are above this line, so
        // the transactional guarantee (no mutation before a possible None)
        // holds — the sole mutation past a possible None is unreachable.
        frame.copy_within(l3..source_end, eth_len);
        write_eth_header_slice(
            frame.get_mut(..eth_len)?,
            params.dst_mac,
            params.src_mac,
            params.vlan_id,
            params.ether_type,
        )?;
    } else {
        let packet = unsafe { area.slice_mut_unchecked(tx_offset as usize, frame_len)? };
        write_eth_header_slice(
            packet.get_mut(..eth_len)?,
            params.dst_mac,
            params.src_mac,
            params.vlan_id,
            params.ether_type,
        )?;
    }
    Some(())
}

/// Read-only derivation of the Ethernet rewrite parameters (dst/src MAC,
/// tx VLAN, ether_type, whether NAT applies) from the forwarding decision.
///
/// #4965: split out of the old `rewrite_prepare_eth` so the generic in-place
/// rewrite can compute the eth plan and run its v4/v6 preflight WITHOUT
/// mutating UMEM — mirroring the #5466 descriptor fast path. Touches no
/// frame bytes; a `None` (missing neighbor/src MAC, or an unknown address
/// family) is a pure decline that leaves the frame byte-identical.
#[inline]
fn rewrite_eth_params(
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat_on_fabric: bool,
) -> Option<RewriteEthParams> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                apply_nat_on_fabric,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    Some(RewriteEthParams {
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
        apply_nat,
    })
}

/// Read-only preflight of the IPv4 generic in-place rewrite (#4965).
///
/// Returns `None` for EXACTLY the inputs on which `rewrite_apply_v4` would
/// return `None` — but here against the PRISTINE L3 payload, BEFORE
/// `rewrite_commit_eth_from_plan` mutates any UMEM byte. Gates, in the same
/// order the mutation half checks them:
///   1. L3 payload shorter than the minimum IPv4 header (20).
///   2. Malformed IHL (< 20, or longer than the payload).
///   3. TTL/hop-limit expiry (unless the sender already decremented — fabric
///      ingress, `skip_ttl`).
///   4. When NAT folds a change into the L4 checksum, the checksum field at
///      `ihl + {16 TCP, 6 UDP}` must be in bounds; otherwise the post-commit
///      `apply_nat_ipv4` adjust would decline. A non-first fragment carries no
///      L4 header (the bytes are payload) — the NAT leaf skips the L4 fold
///      there, so no bound is required and none is imposed.
///
/// `l3_payload` is `&frame[l3 .. l3 + payload_len]` at the ORIGINAL offset;
/// because the commit's VLAN-push memmove is a pure relocation, these
/// byte-for-byte reads decide identically to the post-commit checks they
/// replace. The success path is therefore unchanged; only the FAILING inputs
/// now decline before any mutation, leaving the frame byte-identical.
#[inline]
fn validate_generic_rewrite_v4(
    l3_payload: &[u8],
    meta: ForwardPacketMeta,
    nat: NatDecision,
    apply_nat: bool,
    skip_ttl: bool,
) -> Option<()> {
    if l3_payload.len() < 20 {
        return None;
    }
    let ihl = ((l3_payload[0] & 0x0f) as usize) * 4;
    if ihl < 20 || l3_payload.len() < ihl {
        return None;
    }
    if !skip_ttl && l3_payload[8] <= 1 {
        return None; // TTL expired
    }
    if apply_nat && nat != NatDecision::default() && !ipv4_is_non_first_fragment(l3_payload) {
        if let Some(delta) = l4_checksum_field_delta_v4(meta.protocol) {
            // `apply_nat_ipv4` reads/writes the L4 checksum at `ihl + delta`
            // (address-change fold and/or port rewrite). If the 2-byte field
            // is truncated the adjust returns None — hoist that decline here.
            if l3_payload.len() < ihl + delta + 2 {
                return None;
            }
        }
    }
    Some(())
}

/// Read-only preflight of the IPv6 generic in-place rewrite (#4965). Mirror
/// of `validate_generic_rewrite_v4` for IPv6:
///   1. L3 payload shorter than the fixed 40-byte IPv6 header.
///   2. Hop-limit expiry (unless `skip_ttl`).
///   3. Extension-chain L4 offset unresolvable (malformed/over-limit chain) —
///      `v6_rel_l4_offset` is the SAME SSOT the mutation half uses.
///   4. When NAT folds into the L4 checksum at `rel_l4 + {16 TCP, 6 UDP,
///      2 ICMPv6}`, that field must be in bounds; non-first fragments skip
///      the fold and impose no bound.
///
/// Returns the resolved `rel_l4` on success so the caller can prove the offset
/// was validated pre-commit; `rewrite_apply_v6` re-derives the identical value
/// (same bytes, same meta) after the commit.
#[inline]
fn validate_generic_rewrite_v6(
    l3_payload: &[u8],
    meta: ForwardPacketMeta,
    nat: NatDecision,
    apply_nat: bool,
    skip_ttl: bool,
) -> Option<usize> {
    if l3_payload.len() < 40 {
        return None;
    }
    if !skip_ttl && l3_payload[7] <= 1 {
        return None; // hop limit expired
    }
    let rel_l4 = v6_rel_l4_offset(
        l3_payload,
        meta.l3_offset,
        meta.l4_offset,
        meta.addr_family,
    )?;
    if apply_nat && nat != NatDecision::default() && !ipv6_is_non_first_fragment(l3_payload) {
        if let Some(delta) = l4_checksum_field_delta_v6(meta.protocol) {
            if l3_payload.len() < rel_l4 + delta + 2 {
                return None;
            }
        }
    }
    Some(rel_l4)
}

#[inline]
fn rewrite_apply_v4(
    packet: &mut [u8],
    ip_start: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    skip_ttl: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<()> {
    if packet.len() < ip_start + 20 {
        return None;
    }
    let ihl = ((packet[ip_start] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ip_start + ihl {
        return None;
    }
    if !skip_ttl && packet[ip_start + 8] <= 1 {
        return None;
    }
    let old_src = Ipv4Addr::new(
        packet[ip_start + 12],
        packet[ip_start + 13],
        packet[ip_start + 14],
        packet[ip_start + 15],
    );
    let old_dst = Ipv4Addr::new(
        packet[ip_start + 16],
        packet[ip_start + 17],
        packet[ip_start + 18],
        packet[ip_start + 19],
    );
    let old_ttl = packet[ip_start + 8];
    let rel_l4 = ihl;
    // #1852: compute the non-first-fragment predicate ONCE and thread it
    // into the L4 leaves (skip port/checksum/enforce/ICMP-ident work).
    let non_first_fragment = ipv4_is_non_first_fragment(&packet[ip_start..]);
    let repaired_ports =
        restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4, non_first_fragment)
            .unwrap_or(false);
    if apply_nat {
        apply_nat_ipv4(
            &mut packet[ip_start..],
            meta.protocol,
            decision.nat,
            non_first_fragment,
        )?;
    }
    if !skip_ttl {
        packet[ip_start + 8] -= 1;
    }
    adjust_ipv4_header_checksum(
        &mut packet[ip_start..ip_start + ihl],
        old_src,
        old_dst,
        old_ttl,
    )?;
    let enforced = enforce_expected_ports(
        packet,
        meta.addr_family,
        meta.protocol,
        expected_ports,
        non_first_fragment,
    )
    .unwrap_or(false);
    if repaired_ports && !enforced {
        recompute_l4_checksum_ipv4(&mut packet[ip_start..], ihl, meta.protocol, true)?;
    }
    Some(())
}

#[inline]
fn rewrite_apply_v6(
    packet: &mut [u8],
    ip_start: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    skip_ttl: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<()> {
    if packet.len() < ip_start + 40 {
        return None;
    }
    if !skip_ttl && packet[ip_start + 7] <= 1 {
        return None;
    }
    let rel_l4 = v6_rel_l4_offset(
        &packet[ip_start..],
        meta.l3_offset,
        meta.l4_offset,
        meta.addr_family,
    )?;
    // #1852: non-first-fragment predicate (walks for the v6 fragment
    // header), computed once and threaded into the L4 leaves.
    let non_first_fragment = ipv6_is_non_first_fragment(&packet[ip_start..]);
    let repaired_ports =
        restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4, non_first_fragment)
            .unwrap_or(false);
    if apply_nat {
        apply_nat_ipv6(
            &mut packet[ip_start..],
            rel_l4,
            meta.protocol,
            decision.nat,
            non_first_fragment,
        )?;
    }
    if !skip_ttl {
        packet[ip_start + 7] -= 1;
    }
    let enforced = enforce_expected_ports(
        packet,
        meta.addr_family,
        meta.protocol,
        expected_ports,
        non_first_fragment,
    )
    .unwrap_or(false);
    if repaired_ports && !enforced {
        recompute_l4_checksum_ipv6(&mut packet[ip_start..], rel_l4, meta.protocol)?;
    }
    Some(())
}

pub(super) fn rewrite_forwarded_frame_in_place(
    area: &MmapArea,
    desc: XdpDesc,
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<InPlaceRewriteResult> {
    let meta = meta.into();
    // #4965: preflight-then-commit, mirroring the #5466 descriptor fast path.
    // Compute the eth rewrite plan and run EVERY fallible v4/v6 gate against
    // the PRISTINE frame BEFORE `rewrite_commit_eth_from_plan` mutates any
    // UMEM byte (eth-header write + VLAN-push `copy_within` memmove). A `None`
    // from any gate then leaves the frame byte-identical, so the callers that
    // re-read the SAME UMEM after a decline — the flow-cache
    // `apply_rewrite_descriptor(...).or_else(generic)` fallback
    // (`poll_descriptor/flow_cache_hit.rs`) and the tx-dispatch
    // `build_forwarded_frame_from_frame(source_frame)` reinject
    // (`tx/dispatch/mod.rs`) — reprocess an un-corrupted packet, honoring the
    // zero-copy ownership contract.
    let eth_params = rewrite_eth_params(meta, decision, apply_nat_on_fabric)?;
    let plan = rewrite_plan_eth_from_parts(area, desc, meta, &eth_params)?;
    {
        // Read-only bail gates against the ORIGINAL L3 payload at `plan.l3`.
        // The commit's memmove is a pure relocation, so these byte reads
        // decide identically to `rewrite_apply_v4/v6`'s post-commit checks.
        let frame = area.slice(desc.addr as usize, desc.len as usize)?;
        let l3_end = plan.l3.checked_add(plan.payload_len)?;
        let l3_payload = frame.get(plan.l3..l3_end)?;
        match meta.addr_family as i32 {
            libc::AF_INET => validate_generic_rewrite_v4(
                l3_payload,
                meta,
                decision.nat,
                plan.prep.apply_nat,
                plan.prep.skip_ttl,
            )?,
            libc::AF_INET6 => {
                // Discard the resolved `rel_l4` — `rewrite_apply_v6` re-derives
                // the identical offset post-commit; the validator call is here
                // only to run (and possibly decline on) the ext-chain walk.
                validate_generic_rewrite_v6(
                    l3_payload,
                    meta,
                    decision.nat,
                    plan.prep.apply_nat,
                    plan.prep.skip_ttl,
                )?;
            }
            _ => return None,
        }
    }
    // All gates cleared: commit the eth rewrite (first UMEM mutation). From
    // here NO path returns None — the preflight proved the byte layout, so the
    // `rewrite_apply_v4/v6` `?` below can no longer fire (every remaining
    // fallible op — `apply_nat_ipv4/ipv6`, `adjust_ipv4_header_checksum`,
    // `recompute_l4_checksum_*`, `v6_rel_l4_offset` — was validated above).
    rewrite_commit_eth_from_plan(area, desc, &plan, &eth_params)?;
    let prep = plan.prep;
    let packet = unsafe { area.slice_mut_unchecked(prep.tx_offset as usize, prep.frame_len)? };
    match meta.addr_family as i32 {
        libc::AF_INET => rewrite_apply_v4(
            packet,
            prep.ip_start,
            meta,
            decision,
            prep.apply_nat,
            prep.skip_ttl,
            expected_ports,
        )?,
        libc::AF_INET6 => rewrite_apply_v6(
            packet,
            prep.ip_start,
            meta,
            decision,
            prep.apply_nat,
            prep.skip_ttl,
            expected_ports,
        )?,
        _ => return None,
    }
    // Debug: dump first N in-place rewritten frames' Ethernet headers
    #[cfg(feature = "debug-log")]
    {
        let eth_len = prep.eth_len;
        let ip_start = prep.ip_start;
        let frame_len = prep.frame_len;
        let vlan_id = prep.vlan_id;
        thread_local! {
            static INPLACE_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        INPLACE_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 10 {
                c.set(n + 1);
                let hdr_len = eth_len.min(packet.len()).min(22);
                let hdr_hex: String = packet[..hdr_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                let ip_info = if meta.addr_family as i32 == libc::AF_INET && packet.len() >= ip_start + 20 {
                    format!("src={}.{}.{}.{} dst={}.{}.{}.{}",
                        packet[ip_start+12], packet[ip_start+13], packet[ip_start+14], packet[ip_start+15],
                        packet[ip_start+16], packet[ip_start+17], packet[ip_start+18], packet[ip_start+19])
                } else if meta.addr_family as i32 == libc::AF_INET6 && packet.len() >= ip_start + 40 {
                    let s = &packet[ip_start+8..ip_start+24];
                    let d = &packet[ip_start+24..ip_start+40];
                    format!("src={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x} dst={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],s[11],s[12],s[13],s[14],s[15],
                        d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15])
                } else {
                    "unknown-af".to_string()
                };
                debug_log!("DBG INPLACE_ETH[{}]: eth=[{}] vlan={} frame_len={} proto={} {}",
                    n, hdr_hex, vlan_id, frame_len, meta.protocol, ip_info,
                );
            }
        });
    }
    // Checksum verification for in-place path.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..prep.frame_len]);
    }
    Some(InPlaceRewriteResult {
        offset: prep.tx_offset,
        len: prep.frame_len as u32,
        l2_rewrite: prep.l2_rewrite,
    })
}

#[inline(always)]
fn trim_l3_payload<'a>(raw_payload: &'a [u8], meta: impl Into<ForwardPacketMeta>) -> &'a [u8] {
    let meta = meta.into();
    // #5149: the IP-DECLARED datagram length is AUTHORITATIVE — NOT the
    // metadata `pkt_len`. `raw_payload` begins at the L3 header (l3 == 0
    // relative to this slice), so `declared_l3_end` returns the datagram-end
    // offset: IPv4 `total_len` / IPv6 `40 + payload_len`, clamped to
    // `[ihl/40, raw_payload.len()]`. This is the same SSOT the #5141
    // segmentation clamp and the #2361 fail-closed port bound use.
    //
    // The bug this closes: when `pkt_len` yielded a length equal to the full
    // backing slice (i.e. the metadata length INCLUDED trailing Ethernet
    // slack — NIC min-frame zero-pad or attacker-appended bytes), the old
    // metadata-led code returned that slack-inclusive suffix and never reached
    // the IP-header clamp. On the tunnel-forced L4 recompute path
    // (`force_tunnel_l4_recompute`, consumed by wg/gre encap), the L4 checksum
    // then covered the slack, but the encap transmits only the IP-declared
    // inner length, so the peer verified the checksum over bytes no longer
    // present and DROPPED the packet. The invariant (also enforced by
    // `verify_built_frame_checksums`): the L4 checksum must cover ONLY bytes
    // within IPv4 `total_len` / IPv6 `40 + payload_len`; Ethernet slack is
    // excluded.
    //
    // A declaration too short to cover the L4 header is handled downstream:
    // `declared_l3_end` clamps up to at least the IP header, and the L4
    // recompute helpers fail closed (`None` -> drop) when the trimmed segment
    // cannot hold the L4 header — never a checksum over garbage.
    //
    // Metadata is only a FALLBACK, reached when `declared_l3_end` is
    // unavailable/inconsistent: a truncated or malformed L3 header (bad
    // version/IHL, buffer shorter than the declared IHL) or an unknown
    // addr_family. A no-slack common frame is unaffected — its `total_len`
    // already equals the metadata-derived L3 length, so the trimmed extent is
    // byte-identical.
    if let Some(declared_end) = declared_l3_end(raw_payload, 0, meta.addr_family) {
        return &raw_payload[..declared_end];
    }
    let meta_len = meta.pkt_len as usize;
    if meta_len >= 20 && meta_len <= raw_payload.len() {
        return &raw_payload[..meta_len];
    }
    let meta_l3_len = match meta.l3_offset {
        14 | 18 if meta_len > meta.l3_offset as usize => Some(meta_len - meta.l3_offset as usize),
        _ => None,
    };
    if let Some(meta_l3_len) = meta_l3_len
        && meta_l3_len >= 20
        && meta_l3_len <= raw_payload.len()
    {
        return &raw_payload[..meta_l3_len];
    }
    // Last-resort: parse the IP header directly. Reached only when
    // `declared_l3_end` returned None (truncated/malformed L3 header) AND
    // metadata carries no usable payload length. Preserves the padding-trim
    // safety net for synthetic or incomplete metadata.
    if raw_payload.len() < 4 {
        return raw_payload;
    }
    match raw_payload[0] >> 4 {
        4 => {
            let ip_total_len = u16::from_be_bytes([raw_payload[2], raw_payload[3]]) as usize;
            if ip_total_len > 0 && ip_total_len < raw_payload.len() {
                &raw_payload[..ip_total_len]
            } else {
                raw_payload
            }
        }
        6 if raw_payload.len() >= 40 => {
            let ipv6_payload_len = u16::from_be_bytes([raw_payload[4], raw_payload[5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < raw_payload.len() {
                &raw_payload[..ip6_total]
            } else {
                raw_payload
            }
        }
        _ => raw_payload,
    }
}

/// `non_first_fragment` (#1852): when true, the L4-offset bytes are
/// PAYLOAD (a non-first fragment has no L4 header). The IP-address
/// rewrite still runs (every fragment carries the IP header and must be
/// rewritten consistently), but the L4-checksum adjustment for the
/// address change and the port rewrite are SKIPPED — the L4 checksum
/// lives only in the first fragment and is folded there.
pub(super) fn apply_nat_ipv4(
    packet: &mut [u8],
    protocol: u8,
    nat: NatDecision,
    non_first_fragment: bool,
) -> Option<()> {
    if nat == NatDecision::default() {
        return Some(());
    }
    if packet.len() < 20 {
        return None;
    }
    let old_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let old_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let new_src = nat.rewrite_src.and_then(|ip| match ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    });
    let new_dst = nat.rewrite_dst.and_then(|ip| match ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    });
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    // --- IP address rewriting (#963 PR-B helpers) ---
    // The line above (`if ihl < 20 || packet.len() < ihl { return None; }`)
    // guarantees `packet.len() >= 20`, so the unconditional byte-write
    // helpers are safe; no None-propagation needed here.
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        write_ipv4_src(packet, 0, new_src);
        if !non_first_fragment {
            adjust_l4_checksum_ipv4_src(packet, ihl, protocol, old_src, new_src)?;
        }
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        write_ipv4_dst(packet, 0, new_dst);
        if !non_first_fragment {
            adjust_l4_checksum_ipv4_dst(packet, ihl, protocol, old_dst, new_dst)?;
        }
    } else if new_src.is_some() || new_dst.is_some() {
        if let Some(ip) = new_src {
            write_ipv4_src(packet, 0, ip);
        }
        if let Some(ip) = new_dst {
            write_ipv4_dst(packet, 0, ip);
        }
        let new_src = new_src.unwrap_or(old_src);
        let new_dst = new_dst.unwrap_or(old_dst);
        // #1852: skip the L4-checksum adjust on a non-first fragment —
        // its "L4 checksum" bytes are payload. The address-change delta
        // is folded into the first fragment's L4 checksum.
        if !non_first_fragment {
            match protocol {
                PROTO_TCP => adjust_l4_checksum_ipv4(
                    packet, ihl, protocol, old_src, new_src, old_dst, new_dst,
                )?,
                PROTO_UDP => {
                    let checksum_offset = ihl.checked_add(6)?;
                    let keep_zero = packet
                        .get(checksum_offset..checksum_offset + 2)
                        .map(|bytes| bytes == [0, 0])
                        .unwrap_or(false);
                    if !keep_zero {
                        adjust_l4_checksum_ipv4(
                            packet, ihl, protocol, old_src, new_src, old_dst, new_dst,
                        )?;
                    }
                }
                _ => {}
            }
        }
    }

    // --- L4 port rewriting (after IP rewriting) ---
    // #1852: skip on a non-first fragment — the port bytes are payload.
    if !non_first_fragment {
        apply_nat_port_rewrite(packet, ihl, protocol, ChecksumFamily::V4, nat)?;
        // #4074: translate the ICMP Query Identifier (RFC 5508 §3.1). No-op
        // for TCP/UDP and for any ICMP decision without a translated id.
        apply_nat_icmp_identifier_rewrite(packet, ihl, protocol, ChecksumFamily::V4, nat)?;
    }

    Some(())
}

/// Apply a NAT decision to an IPv6 packet (L3-relative slice).
/// `rel_l4` is the caller-supplied ext-aware L4 offset (#1838) —
/// derived via `v6_rel_l4_offset` (or structurally, e.g. the
/// segmentation copy where the copied IP header length IS the parsed
/// offset). It mirrors `apply_nat_ipv4`'s IHL, which is derived
/// internally for v4 because the IHL lives in the header itself; the
/// v6 offset requires the extension-chain walk, so the caller
/// supplies it.
pub(super) fn apply_nat_ipv6(
    packet: &mut [u8],
    rel_l4: usize,
    protocol: u8,
    nat: NatDecision,
    non_first_fragment: bool,
) -> Option<()> {
    if nat == NatDecision::default() {
        return Some(());
    }
    if packet.len() < 40 {
        return None;
    }
    // #963 PR-B: keep `Ipv6Addr` here so the byte-write helpers fold
    // cleanly. `addr.octets()` returns `[u8; 16]` and the optimizer
    // elides the copy at the checksum call sites that need raw
    // bytes -- no layout guarantee is being relied on, just inlining.
    let new_src = nat.rewrite_src.and_then(|ip| match ip {
        IpAddr::V6(ip) => Some(ip),
        _ => None,
    });
    let new_dst = nat.rewrite_dst.and_then(|ip| match ip {
        IpAddr::V6(ip) => Some(ip),
        _ => None,
    });

    // NPTv6 (RFC 6296): prefix translation is checksum-neutral by design --
    // the adjustment word preserves the ones-complement sum of the full address.
    // Skip L4 checksum updates entirely for NPTv6 rewrites.
    // #1852: a non-first fragment has no L4 checksum at `rel_l4` (those
    // bytes are payload), so skip the address-change L4-checksum adjust
    // too. The IP address byte writes below still run.
    let skip_l4_csum = nat.nptv6 || non_first_fragment;
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        let old_src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
        write_ipv6_src(packet, 0, new_src);
        if !skip_l4_csum {
            adjust_l4_checksum_ipv6_addr_bytes(
                packet,
                rel_l4,
                protocol,
                &old_src,
                &new_src.octets(),
            )?;
        }
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        let old_dst: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
        write_ipv6_dst(packet, 0, new_dst);
        if !skip_l4_csum {
            adjust_l4_checksum_ipv6_addr_bytes(
                packet,
                rel_l4,
                protocol,
                &old_dst,
                &new_dst.octets(),
            )?;
        }
    } else if new_src.is_some() || new_dst.is_some() {
        // BOTH src and dst are rewritten -- a composed translation
        // (#3121: NPTv6 source + DNAT destination, or SNAT + DNAT). Unlike
        // the single-sided arms above, do NOT blanket-skip the L4 checksum
        // on `nat.nptv6` here: the NPTv6 side is checksum-neutral (its
        // incremental word adjustment nets zero by RFC 6296, in either
        // direction), but the composed DNAT side is NOT neutral and its
        // address change MUST be folded into the L4 checksum. Only a
        // non-first fragment (no L4 header at `rel_l4`) skips the adjust.
        let old_src_words = ipv6_words_from_slice(packet.get(8..24)?)?;
        let old_dst_words = ipv6_words_from_slice(packet.get(24..40)?)?;
        if let Some(ip) = new_src {
            write_ipv6_src(packet, 0, ip);
        }
        if let Some(ip) = new_dst {
            write_ipv6_dst(packet, 0, ip);
        }
        if !non_first_fragment {
            let new_src_words = new_src
                .map(|a| ipv6_words_from_octets(a.octets()))
                .unwrap_or(old_src_words);
            let new_dst_words = new_dst
                .map(|a| ipv6_words_from_octets(a.octets()))
                .unwrap_or(old_dst_words);
            match protocol {
                PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => {
                    adjust_l4_checksum_ipv6_words(
                        packet,
                        rel_l4,
                        protocol,
                        &old_src_words,
                        &new_src_words,
                    )?;
                    adjust_l4_checksum_ipv6_words(
                        packet,
                        rel_l4,
                        protocol,
                        &old_dst_words,
                        &new_dst_words,
                    )?;
                }
                _ => {}
            }
        }
    }

    // --- L4 port rewriting (after IP rewriting) ---
    // At the caller-supplied ext-aware L4 offset (#1838) — the fixed
    // 40 here used to land port writes inside the first extension
    // header of any ext-headered packet.
    // #1852: skip on a non-first fragment — the port bytes are payload.
    if !non_first_fragment {
        apply_nat_port_rewrite(packet, rel_l4, protocol, ChecksumFamily::V6, nat)?;
        // #4074: translate the ICMPv6 Query Identifier (RFC 5508 §3.1). The
        // pseudo-header address delta is already folded above; this adds only
        // the identifier delta.
        apply_nat_icmp_identifier_rewrite(packet, rel_l4, protocol, ChecksumFamily::V6, nat)?;
    }

    Some(())
}

/// Rewrite L4 source/destination ports and incrementally update the L4 checksum.
/// Port rewriting MUST happen AFTER IP address rewriting to avoid double-counting
/// in the checksum. Skips ICMP (no ports).
// Visibility narrowed from pub(super) in #1840: the `family`
// parameter's `ChecksumFamily` is `pub(in crate::afxdp::frame)` and
// every caller lives in this file (apply_nat_ipv4/ipv6), so the fn
// follows the type.
// #[inline(always)] is a structural guarantee, not a perf tweak: both
// callers pass `family` as a compile-time constant, so inlining folds
// the v6-only §5.5 branch out of the v4 NAT path entirely (Codex
// PR #1853 review — the v4 hot path must not pay for the v6 rule).
#[inline(always)]
pub(in crate::afxdp::frame) fn apply_nat_port_rewrite(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    family: ChecksumFamily,
    nat: NatDecision,
) -> Option<()> {
    // #3111: shared "has a rewritable L4 port" predicate (TCP/UDP) so the
    // generic and descriptor-fast-path rewriters cannot drift on which
    // protocols may have their first L4 bytes touched.
    if !crate::ip_proto::has_l4_ports(protocol) {
        return Some(());
    }
    if packet.len() < l4_offset + 4 {
        return Some(());
    }

    // #963 PR-B: byte-write kernel + caller-side checksum delta. The
    // helper only writes the port bytes; the surrounding `if old !=
    // new` short-circuit and incremental-checksum call stay here,
    // preserving the existing semantics (no checksum work when the
    // port doesn't actually change).
    if let Some(new_src_port) = nat.rewrite_src_port {
        let port_offset = l4_offset; // TCP/UDP src port at offset +0
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_src_port {
            write_l4_src_port(packet, l4_offset, new_src_port);
            adjust_l4_checksum_port(packet, l4_offset, protocol, family, old_port, new_src_port)?;
        }
    }

    if let Some(new_dst_port) = nat.rewrite_dst_port {
        let port_offset = l4_offset + 2; // TCP/UDP dst port at offset +2
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_dst_port {
            write_l4_dst_port(packet, l4_offset, new_dst_port);
            adjust_l4_checksum_port(packet, l4_offset, protocol, family, old_port, new_dst_port)?;
        }
    }

    // #1840 §5.5 no-op-port parity rule: v6 UDP with a port-NAT
    // decision present (even value-identity) mirrors the descriptor's
    // ≡0-delta application, which canonicalizes a stored 0x0000 to
    // 0xFFFF. If an old != new adjust already ran above, the stored
    // value is no longer literal 0x0000 (the adjusters canonicalize
    // their own computed zeros), so this only fires on the
    // short-circuited identity case. v4 UDP stored-0 keeps the
    // RFC 768 skip.
    if family == ChecksumFamily::V6
        && protocol == PROTO_UDP
        && (nat.rewrite_src_port.is_some() || nat.rewrite_dst_port.is_some())
    {
        let csum_off = l4_offset.checked_add(6)?;
        if let Some(stored) = packet.get(csum_off..csum_off + 2)
            && stored == [0, 0]
        {
            packet
                .get_mut(csum_off..csum_off + 2)?
                .copy_from_slice(&0xFFFFu16.to_be_bytes());
        }
    }

    Some(())
}

/// #4074 (RFC 5508 §3.1 "ICMP Query Mappings"): rewrite the ICMP / ICMPv6
/// Query Identifier and repair the ICMP checksum incrementally.
///
/// The identifier is a single 16-bit field at `l4_offset + 4` — the same
/// offset in BOTH families and BOTH directions (`type[0] code[1]
/// checksum[2..4] identifier[4..6] sequence[6..8]`) — and it is the ICMP
/// demux key that pool-mode SNAT translates so two internal hosts pinging the
/// same target with the same id, both hidden behind one pool address, do not
/// collide on the reverse tuple `(pool_addr, id)`. Because the field is
/// symmetric, the forward NAT decision carries the translated id in
/// `rewrite_src_port` while the reverse (reply) decision — produced by
/// `NatDecision::reverse` — carries the ORIGINAL id in `rewrite_dst_port`. At
/// most one of the two is set for an ICMP flow, so the new identifier is
/// `rewrite_src_port.or(rewrite_dst_port)`.
///
/// Gated on the ICMP type being an identifier-bearing query (echo / timestamp
/// / information for ICMPv4, echo for ICMPv6): an error or control message's
/// `l4+4` bytes are a gateway address / next-hop MTU / pointer / reserved
/// field, NOT an identifier, and must never be touched — the same query-type
/// gate `parse_flow_ports` applies when it lifts the id into the session tuple.
///
/// For ICMPv6 the pseudo-header address change is already folded into the
/// checksum by the caller's IP-rewrite section (`adjust_l4_checksum_ipv6_*`,
/// which handles `PROTO_ICMPV6`); here only the identifier delta is applied.
/// ICMPv4 has no pseudo-header, so the SNAT address change never affects the
/// ICMPv4 checksum and only the identifier delta matters.
// #[inline(always)]: `family` and the protocol match are constants at both
// call sites, so the whole body folds out of the TCP/UDP NAT path.
#[inline(always)]
pub(in crate::afxdp::frame) fn apply_nat_icmp_identifier_rewrite(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    family: ChecksumFamily,
    nat: NatDecision,
) -> Option<()> {
    if !matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return Some(());
    }
    let Some(new_ident) = nat.rewrite_src_port.or(nat.rewrite_dst_port) else {
        return Some(());
    };
    write_icmp_identifier(packet, l4_offset, protocol, family, new_ident)?;
    Some(())
}

/// #5191: the SINGLE writer of the ICMP / ICMPv6 Query Identifier at
/// `l4_offset + 4`. Both producers of that write — the NAT identifier
/// translation (`apply_nat_icmp_identifier_rewrite`, #4074) and the metadata
/// restore (`restore_l4_tuple_from_meta`) — route through here so the
/// query-type gate and the checksum repair cannot drift between them. Before
/// #5191 only the NAT writer carried either: the restore wrote the field for
/// ANY ICMP type and left the checksum stale, so a repaired ICMPv4 message left
/// the box with a checksum the receiver discards, and a non-query message
/// (Redirect gateway / Parameter-Problem pointer / RA fields / MLD maximum
/// response delay) had two semantic bytes overwritten with a pseudo-port.
///
/// Returns `Some(true)` when the field actually changed, `Some(false)` when it
/// did not (already equal, not an identifier-bearing query type, not ICMP, or a
/// header too short to hold type + checksum + identifier). Never `None` on a
/// short header — a truncated message is left byte-identical, matching the
/// fail-closed disposition the NAT writer already had.
///
/// Gate: the `l4+4` bytes are an Identifier ONLY for query types (ICMPv4 echo /
/// timestamp / information, ICMPv6 echo). For an error or control message they
/// are a gateway address, a next-hop MTU, a pointer, or a reserved field — the
/// same gate `parse_flow_ports` applies when it lifts the id into the session
/// tuple, which is why the metadata pseudo-port for such a packet is 0 in the
/// first place (`parse_flow_ports` declines, so the GRE-decap meta synthesis in
/// `gre.rs` falls back to `unwrap_or_default()`).
///
/// Checksum: repaired INCREMENTALLY (RFC 1624) over the single changed 16-bit
/// word, never by a full recompute. The in-place rewrite path hands this
/// function a slice bounded by the RX descriptor length, which includes any
/// Ethernet min-frame zero-pad; a full recompute would fold that pad into the
/// checksum. The incremental delta is immune to trailing slack.
#[inline(always)]
pub(in crate::afxdp::frame) fn write_icmp_identifier(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    family: ChecksumFamily,
    new_ident: u16,
) -> Option<bool> {
    if !matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return Some(false);
    }
    // Need type[0], checksum[2..4], and identifier[4..6].
    if packet.len() < l4_offset + 6 {
        return Some(false);
    }
    if !icmp_identifier_bearing(protocol, packet[l4_offset]) {
        return Some(false);
    }
    let old_ident = u16::from_be_bytes([packet[l4_offset + 4], packet[l4_offset + 5]]);
    if old_ident == new_ident {
        return Some(false);
    }
    packet
        .get_mut(l4_offset + 4..l4_offset + 6)?
        .copy_from_slice(&new_ident.to_be_bytes());
    // ICMP checksum field is at l4+2 in both families.
    let csum_off = l4_offset + 2;
    let current = u16::from_be_bytes([*packet.get(csum_off)?, *packet.get(csum_off + 1)?]);
    let mut updated = checksum16_adjust(current, &[old_ident], &[new_ident]);
    // ICMPv6 forbids a transmitted 0x0000 checksum (RFC 8200 §8.1); a v4 ICMP
    // 0x0000 is a legal checksum value. `adjust_zero_checksum_illegal` is the
    // shared SSOT for this rule (ICMPv6 canonicalizes, ICMPv4 does not).
    if adjust_zero_checksum_illegal(protocol, family) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(csum_off..csum_off + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(true)
}

/// Incremental L4 checksum update for a single 16-bit port change.
/// `family` gates the two zero-checksum rules through the shared
/// predicates (#1840): the RFC 768 received-0 skip is IPv4-UDP-only
/// (a v6 UDP 0x0000 is malformed per RFC 8200 §8.1 and gets adjusted
/// like any other value), and the computed-0 canonicalization follows
/// `adjust_zero_checksum_illegal` (UDP both families; ICMPv6 has no
/// ports so only UDP is reachable here — identical output to the old
/// unconditional UDP match, routed through the predicate for
/// one-source-of-truth uniformity).
// Visibility narrowed from pub(super) in #1840 (same rationale as
// apply_nat_port_rewrite — callers are all in frame/).
// #[inline(always)]: same structural constant-family fold as
// apply_nat_port_rewrite (the RFC 768 skip predicate becomes a
// compile-time constant per call site).
#[inline(always)]
pub(in crate::afxdp::frame) fn adjust_l4_checksum_port(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    family: ChecksumFamily,
    old_port: u16,
    new_port: u16,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => l4_offset.checked_add(16)?,
        PROTO_UDP => l4_offset.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    if l4_udp_checksum_optional(protocol, family) && current == 0 {
        return Some(());
    }
    let mut updated = checksum16_adjust(current, &[old_port], &[new_port]);
    if adjust_zero_checksum_illegal(protocol, family) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(super) fn enforce_expected_ports(
    frame: &mut [u8],
    addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
    non_first_fragment: bool,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
    // #1852: a non-first fragment has no L4 ports at the post-IP offset —
    // do not "enforce" payload bytes (and do not touch a fake checksum).
    if non_first_fragment {
        return Some(false);
    }
    // #1840: family for the zero-checksum predicates. None (other
    // family) => nothing to enforce — unreachable in practice because
    // frame_l4_offset below already fails other families.
    let Some(family) = checksum_family_of(addr_family) else {
        return Some(false);
    };
    let l3 = frame_l3_offset(frame)?;
    let l4 = frame_l4_offset(frame, addr_family)?;
    let ports = frame.get(l4..l4 + 4)?;
    let current_src = u16::from_be_bytes([ports[0], ports[1]]);
    let current_dst = u16::from_be_bytes([ports[2], ports[3]]);
    if current_src == expected_src && current_dst == expected_dst {
        return Some(false);
    }
    let packet = frame.get_mut(l3..)?;
    let rel_l4 = l4.checked_sub(l3)?;
    // #963 PR-B: byte-write helpers replace the inline copy_from_slice.
    // The earlier `frame.get(l4..l4 + 4)?` upstream guarantees
    // `packet.len() >= rel_l4 + 4`, so the helper's internal length
    // guard is redundant-but-correct.
    if current_src != expected_src {
        write_l4_src_port(packet, rel_l4, expected_src);
        adjust_l4_checksum_port(packet, rel_l4, protocol, family, current_src, expected_src)?;
    }
    if current_dst != expected_dst {
        write_l4_dst_port(packet, rel_l4, expected_dst);
        adjust_l4_checksum_port(packet, rel_l4, protocol, family, current_dst, expected_dst)?;
    }
    Some(true)
}

/// Like enforce_expected_ports, but takes pre-computed L3/L4 offsets to avoid
/// redundant header parsing in the hot path.
#[inline]
pub(super) fn enforce_expected_ports_at(
    frame: &mut [u8],
    l3: usize,
    l4: usize,
    addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
    non_first_fragment: bool,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
    // #1852: skip port enforcement on a non-first fragment (payload at l4).
    if non_first_fragment {
        return Some(false);
    }
    // #1840: the previously-unused addr_family parameter now selects
    // the zero-checksum predicate family.
    let Some(family) = checksum_family_of(addr_family) else {
        return Some(false);
    };
    let ports = frame.get(l4..l4 + 4)?;
    let current_src = u16::from_be_bytes([ports[0], ports[1]]);
    let current_dst = u16::from_be_bytes([ports[2], ports[3]]);
    if current_src == expected_src && current_dst == expected_dst {
        return Some(false);
    }
    let packet = frame.get_mut(l3..)?;
    let rel_l4 = l4.checked_sub(l3)?;
    // #963 PR-B: byte-write helpers replace the inline copy_from_slice.
    // The earlier `frame.get(l4..l4 + 4)?` upstream guarantees
    // `packet.len() >= rel_l4 + 4`, so the helper's internal length
    // guard is redundant-but-correct.
    if current_src != expected_src {
        write_l4_src_port(packet, rel_l4, expected_src);
        adjust_l4_checksum_port(packet, rel_l4, protocol, family, current_src, expected_src)?;
    }
    if current_dst != expected_dst {
        write_l4_dst_port(packet, rel_l4, expected_dst);
        adjust_l4_checksum_port(packet, rel_l4, protocol, family, current_dst, expected_dst)?;
    }
    Some(true)
}

pub(super) fn restore_l4_tuple_from_meta(
    packet: &mut [u8],
    meta: impl Into<ForwardPacketMeta>,
    rel_l4: usize,
    non_first_fragment: bool,
) -> Option<bool> {
    let meta = meta.into();
    // #1852: a non-first fragment has no L4 header — the ICMP "ident"
    // bytes at rel_l4+4 are payload; do not restore into them.
    if non_first_fragment {
        return Some(false);
    }
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => Some(false),
        PROTO_ICMP | PROTO_ICMPV6 => {
            // #5191: route the write through the shared identifier writer so
            // the query-type gate AND the incremental checksum repair apply
            // here exactly as they do on the NAT translation path. Before
            // #5191 this arm wrote `meta.flow_src_port` into [rel_l4+4,
            // rel_l4+6) for EVERY ICMP type with no gate and no checksum fix.
            //
            // Both halves were reachable together: `gre.rs`'s inner-meta
            // synthesis derives `flow_src_port` from `parse_session_flow_from_
            // frame`, which declines (0) for every non-query ICMP type — so a
            // GRE-decapped Redirect / Parameter-Problem / RA / MLD message had
            // its gateway-address, pointer, or max-response-delay bytes zeroed.
            // On IPv4 the stale checksum then had the receiver drop it; on IPv6
            // the trailing full recompute made the CORRUPTED message verify,
            // which is the worse of the two outcomes.
            //
            // An unknown address family yields no checksum family, so nothing
            // is written at all (fail closed) rather than written unrepaired.
            let Some(family) = checksum_family_of(meta.addr_family) else {
                return Some(false);
            };
            write_icmp_identifier(packet, rel_l4, meta.protocol, family, meta.flow_src_port)
        }
        _ => Some(false),
    }
}

pub(super) fn build_injected_ipv4(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 20 + 8 + 16;
    // #2443: clamp target_len to the inject maximum so a bypassed length
    // bound cannot pre-allocate a huge buffer here. The reject path in
    // `inject_test_packet` rejects an over-max request before reaching
    // this builder; this clamp is defense in depth.
    let target_len = req
        .packet_length
        .max(min_total as u32)
        .min(crate::afxdp::MAX_INJECT_PACKET_LENGTH) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 20 + 8);

    // #2443: never emit a wrapped wire length. The IPv4 total-length
    // field is u16; if 20 + 8 + payload_len cannot be represented, REJECT
    // the build rather than truncating to a wrong on-wire length.
    let total_len = u16::try_from(20 + 8 + payload_len).map_err(|_| {
        format!(
            "injected IPv4 total length {} exceeds u16",
            20 + 8 + payload_len
        )
    })?;

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x0800);

    let ip_start = frame.len();
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        1,
        0,
        0,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    let ip_sum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10] = (ip_sum >> 8) as u8;
    frame[ip_start + 11] = ip_sum as u8;

    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0, 0]);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

pub(super) fn build_injected_ipv6(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 40 + 8 + 16;
    // #2443: clamp target_len to the inject maximum (defense in depth;
    // the request is rejected up front in `inject_test_packet`).
    let target_len = req
        .packet_length
        .max(min_total as u32)
        .min(crate::afxdp::MAX_INJECT_PACKET_LENGTH) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 40 + 8);

    // #2443: the IPv6 payload-length field is u16; REJECT rather than
    // emit a wrapped on-wire length.
    let plen = u16::try_from(8 + payload_len)
        .map_err(|_| format!("injected IPv6 payload length {} exceeds u16", 8 + payload_len))?;

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x86dd);
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        58,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());

    let icmp_start = frame.len();
    frame.extend_from_slice(&[128, 0, 0, 0]);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

// `write_eth_header` and `write_eth_header_slice` moved to
// `frame/headers.rs` in #1440. Re-exported at the same path above so
// existing call sites continue to work unchanged.

/// Verify IP + TCP/UDP checksums on a fully-built forwarded frame.
/// Returns (ip_ok, l4_ok). Logs mismatches for the first N frames.
pub(super) static CSUM_VERIFIED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(super) static CSUM_BAD_IP_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(super) static CSUM_BAD_L4_TOTAL: AtomicU64 = AtomicU64::new(0);

pub(super) fn verify_built_frame_checksums(frame: &[u8]) -> (bool, bool) {
    let l3 = match frame_l3_offset(frame) {
        Some(o) => o,
        None => return (true, true),
    };
    let packet = match frame.get(l3..) {
        Some(p) if p.len() >= 20 => p,
        _ => return (true, true),
    };
    // Only handle IPv4 TCP for now (main traffic under test).
    if (packet[0] >> 4) != 4 {
        return (true, true);
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return (true, true);
    }
    let protocol = packet[9];
    // --- IP header checksum verification ---
    let ip_header = match packet.get(..ihl) {
        Some(h) => h,
        None => return (true, true),
    };
    let ip_csum_in_frame = u16::from_be_bytes([ip_header[10], ip_header[11]]);
    // Compute from scratch: zero out checksum field, compute, compare.
    let mut ip_scratch = [0u8; 60]; // max IHL = 60
    let scratch = &mut ip_scratch[..ihl];
    scratch.copy_from_slice(ip_header);
    scratch[10] = 0;
    scratch[11] = 0;
    let expected_ip_csum = checksum16(scratch);
    let ip_ok = ip_csum_in_frame == expected_ip_csum;

    // --- IP total length consistency ---
    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let actual_l3_len = packet.len();
    if ip_total_len != actual_l3_len {
        thread_local! {
            static IP_LEN_MISMATCH_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        IP_LEN_MISMATCH_LOG.with(|c| {
            let n = c.get();
            if n < 20 {
                c.set(n + 1);
                #[cfg(feature = "debug-log")]
                {
                    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    debug_log!(
                        "IP_LEN_MISMATCH[{}]: ip_total_len={} actual_l3_len={} frame_len={} l3={} src={} dst={} proto={}",
                        n, ip_total_len, actual_l3_len, frame.len(), l3, src, dst, protocol,
                    );
                }
            }
        });
    }

    // --- L4 checksum verification (TCP or UDP) ---
    // Use ip_total_len to bound the L4 segment — Ethernet padding bytes beyond
    // ip_total_len must NOT be included in the checksum pseudo-header or payload.
    let l4_len = if ip_total_len > ihl {
        ip_total_len - ihl
    } else {
        0
    };
    let l4_ok = if protocol == PROTO_TCP {
        let segment = match packet.get(ihl..ihl + l4_len) {
            Some(s) if s.len() >= 20 => s,
            _ => return (ip_ok, true),
        };
        let tcp_csum_in_frame = u16::from_be_bytes([segment[16], segment[17]]);
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        // Build pseudo-header + TCP with checksum zeroed.
        let mut pseudo = Vec::with_capacity(12 + segment.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(PROTO_TCP);
        pseudo.extend_from_slice(&saturate_len16(segment.len()).to_be_bytes());
        pseudo.extend_from_slice(segment);
        // Zero the checksum field in pseudo buffer (offset 12 + 16 = 28..30).
        let csum_off = 12 + 16;
        if pseudo.len() > csum_off + 1 {
            pseudo[csum_off] = 0;
            pseudo[csum_off + 1] = 0;
        }
        let expected_tcp_csum = checksum16(&pseudo);
        tcp_csum_in_frame == expected_tcp_csum
    } else if protocol == PROTO_UDP {
        let segment = match packet.get(ihl..ihl + l4_len) {
            Some(s) if s.len() >= 8 => s,
            _ => return (ip_ok, true),
        };
        let udp_csum_in_frame = u16::from_be_bytes([segment[6], segment[7]]);
        if udp_csum_in_frame == 0 {
            true // zero = no checksum
        } else {
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let mut pseudo = Vec::with_capacity(12 + segment.len());
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.push(0);
            pseudo.push(PROTO_UDP);
            pseudo.extend_from_slice(&saturate_len16(segment.len()).to_be_bytes());
            pseudo.extend_from_slice(segment);
            let csum_off = 12 + 6;
            if pseudo.len() > csum_off + 1 {
                pseudo[csum_off] = 0;
                pseudo[csum_off + 1] = 0;
            }
            let expected_udp_csum = checksum16(&pseudo);
            let expected_udp_csum = if expected_udp_csum == 0 {
                0xffff
            } else {
                expected_udp_csum
            };
            udp_csum_in_frame == expected_udp_csum
        }
    } else {
        true
    };

    CSUM_VERIFIED_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !ip_ok {
        CSUM_BAD_IP_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if !l4_ok {
        CSUM_BAD_L4_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    thread_local! {
        static CSUM_VERIFY_COUNT: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
    }
    if !ip_ok || !l4_ok {
        CSUM_VERIFY_COUNT.with(|c| {
            let (total_bad, logged) = c.get();
            c.set((total_bad + 1, logged));
            if logged < 30 {
                c.set((total_bad + 1, logged + 1));
                let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                eprintln!("CSUM_BAD[{}]: ip_ok={} l4_ok={} proto={} ip_in={:#06x} ip_exp={:#06x} \
                     src={} dst={} frame_len={} l3={} ihl={}",
                    total_bad, ip_ok, l4_ok, protocol,
                    ip_csum_in_frame, expected_ip_csum,
                    src, dst, frame.len(), l3, ihl,
                );
                if !l4_ok && protocol == PROTO_TCP {
                    let segment = &packet[ihl..];
                    let tcp_csum = u16::from_be_bytes([segment[16], segment[17]]);
                    let tcp_src = u16::from_be_bytes([segment[0], segment[1]]);
                    let tcp_dst = u16::from_be_bytes([segment[2], segment[3]]);
                    // Recompute to show expected
                    let mut pseudo = Vec::with_capacity(12 + segment.len());
                    pseudo.extend_from_slice(&src.octets());
                    pseudo.extend_from_slice(&dst.octets());
                    pseudo.push(0);
                    pseudo.push(PROTO_TCP);
                    pseudo.extend_from_slice(&saturate_len16(segment.len()).to_be_bytes());
                    pseudo.extend_from_slice(segment);
                    pseudo[12 + 16] = 0;
                    pseudo[12 + 17] = 0;
                    let expected = checksum16(&pseudo);
                    eprintln!("CSUM_BAD_TCP[{}]: sport={} dport={} csum_in={:#06x} csum_exp={:#06x} seg_len={}",
                        total_bad, tcp_src, tcp_dst, tcp_csum, expected, segment.len(),
                    );
                    // Hex dump of first 60 bytes of frame for deep debug
                    if logged < 5 {
                        let hex_len = frame.len().min(80);
                        let hex: String = frame[..hex_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        eprintln!("CSUM_BAD_HEX[{}]: {}", total_bad, hex);
                    }
                }
            }
        });
    }
    (ip_ok, l4_ok)
}

// frame/tests.rs (8.3k-LOC catch-all) was split into cohesive per-subsystem
// sibling test modules plus a shared support module in #4840. Pure test
// code-motion; each file reaches production items through `super::*` and
// shared fixtures through `super::super::test_fixtures::*`, identical to the
// pre-split single module.
#[cfg(test)]
#[path = "tests_support.rs"]
mod tests_support;
#[cfg(test)]
#[path = "tests_parse_forward_pbr.rs"]
mod tests_parse_forward_pbr;
#[cfg(test)]
#[path = "tests_native_gre_ecn.rs"]
mod tests_native_gre_ecn;
#[cfg(test)]
#[path = "tests_nat_rewrite.rs"]
mod tests_nat_rewrite;
#[cfg(test)]
#[path = "tests_ports_live_forward.rs"]
mod tests_ports_live_forward;
#[cfg(test)]
#[path = "tests_segment_tcp.rs"]
mod tests_segment_tcp;
#[cfg(test)]
#[path = "tests_ttl_descriptor_dscp.rs"]
mod tests_ttl_descriptor_dscp;
#[cfg(test)]
#[path = "tests_fragment_term_extra.rs"]
mod tests_fragment_term_extra;
#[cfg(test)]
#[path = "tests_ipv6_ext_walk.rs"]
mod tests_ipv6_ext_walk;
#[cfg(test)]
#[path = "tests_mss_inject_inspect.rs"]
mod tests_mss_inject_inspect;
// #4555: parity guard between the AF_XDP shim's parse_ipv6 extension-header
// walk (userspace-xdp/src/lib.rs) and walk_ipv6_ext_chain above.
#[cfg(test)]
#[path = "tests_shim_ext_parity.rs"]
mod tests_shim_ext_parity;
// #8274: the shim's WireGuard record classification, executed rather than
// modelled — same reason and same shape as the parity guard above.
#[cfg(test)]
#[path = "tests_shim_wg_classify_8274.rs"]
mod tests_shim_wg_classify_8274;

// #1824: proptest property harness (parse no-panic/bounds, NAT
// round-trip + descriptor-vs-generic differential, TSO reassembly).
// `not(miri)` because proptest case loops are intractable under the
// targeted `cargo +nightly miri test --bin` passes (#1755 lesson).
//
// #9499: this comment used to end "the deterministic example tests keep
// miri coverage of the same fns". That was true of the tests' SHAPE and
// false about the world -- no make target ran Miri at all, so the
// exclusion was gating against a pass that never happened, and a reader
// took a protection to exist. `make test-miri` now runs a REGISTERED
// subset (userspace-dp/MIRI.registry) and `afxdp::frame::` is NOT in it:
// measured at 16df7c8c7 the module ran 1021 s under Miri and then stopped
// on an `unsupported operation` from a test that reads a file. This file
// is therefore declared in userspace-dp/MIRI.unregistered with that
// reason, and scripts/miri-census.sh fails if that declaration is
// dropped. The deterministic pins remain the RIGHT shape for Miri; they
// are simply not run under it today.
#[cfg(all(test, not(miri)))]
mod prop_tests;
