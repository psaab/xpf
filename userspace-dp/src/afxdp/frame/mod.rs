use super::*;

mod byte_writes;
mod checksum;
mod inspect;
mod tcp;

use byte_writes::{
    write_ipv4_dst, write_ipv4_src, write_ipv6_dst, write_ipv6_src, write_l4_dst_port,
    write_l4_src_port,
};

// Cross-module helpers reach into `frame::*` via the explicit list
// below. `adjust_l4_checksum_ipv6_addr_bytes` is file-private to
// `checksum.rs` (only the SNAT/DNAT rewrites here call it) and is
// pulled in via a non-pub `use` to avoid a glob re-export at a
// wider visibility than its own.
use checksum::adjust_l4_checksum_ipv6_addr_bytes;
pub(in crate::afxdp) use checksum::{
    adjust_ipv4_header_checksum, adjust_l4_checksum_ipv4, adjust_l4_checksum_ipv4_dst,
    adjust_l4_checksum_ipv4_src, adjust_l4_checksum_ipv4_words, adjust_l4_checksum_ipv6,
    adjust_l4_checksum_ipv6_dst, adjust_l4_checksum_ipv6_src, adjust_l4_checksum_ipv6_words,
    checksum16, checksum16_add_bytes, checksum16_adjust, checksum16_finish, checksum16_ipv4,
    checksum16_ipv6, ipv4_words, ipv6_words, ipv6_words_from_octets, ipv6_words_from_slice,
    recompute_l4_checksum_ipv4, recompute_l4_checksum_ipv6,
};

// Phase 2: header inspection / parsing helpers extracted to `inspect`.
// `frame_has_tcp_rst`, `decode_frame_summary`, `try_parse_metadata`,
// `authoritative_forward_ports`, and `forward_tuple_mismatch_reason` are
// reached for from afxdp.rs / tx/transmit.rs / tx/dispatch.rs /
// cos/queue_service.rs, so they go out at `pub(in crate::afxdp)`. The
// rest stay at `pub(super)` (afxdp-only callers in sibling files).
pub(in crate::afxdp) use inspect::{
    authoritative_forward_ports, decode_frame_summary, forward_tuple_mismatch_reason,
    parse_session_flow, try_parse_metadata,
};
pub(super) use inspect::{
    frame_l3_offset, frame_l4_offset, live_frame_ports, live_frame_ports_bytes,
    live_frame_ports_from_meta_bytes, metadata_tuple_complete, packet_rel_l4_offset,
    packet_rel_l4_offset_and_protocol, parse_flow_ports, parse_ipv4_session_flow_from_frame,
    parse_packet_destination_from_frame, parse_session_flow_from_bytes,
    parse_session_flow_from_frame, parse_session_flow_from_meta,
    parse_zone_encoded_fabric_ingress, parse_zone_encoded_fabric_ingress_from_frame,
};

// #989: TCP-specific inspection + mutation kernels relocated from
// frame/inspect.rs and forwarding/mod.rs. Visibility split mirrors
// the inspect re-exports above:
//   - frame_has_tcp_rst: pub(in crate::afxdp) so afxdp.rs / tx
//     callers continue to see it via the wider re-export path.
//   - the remaining helpers stay at pub(super) (or fn-private for
//     the clamp helpers, which are only used inside frame/mod.rs).
pub(in crate::afxdp) use tcp::frame_has_tcp_rst;
pub(super) use tcp::{extract_tcp_flags_and_window, extract_tcp_window, tcp_flags_str};
use tcp::clamp_tcp_mss_frame;

// #1046: TCP segmentation builders extracted into tcp_segmentation.rs
// to keep frame/mod.rs under the modularity-discipline LOC threshold.
// Re-exported at `pub(in crate::afxdp)` so afxdp.rs's `use self::frame::*;`
// continues to surface them at the same call sites in tx/dispatch.rs.
mod tcp_segmentation;
pub(in crate::afxdp) use tcp_segmentation::{
    segment_forwarded_tcp_frames, segment_forwarded_tcp_frames_from_frame,
};








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
    dst: IpAddr,
    resolution: ForwardingResolution,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let dst_mac = resolution
        .neighbor_mac
        .ok_or_else(|| "missing neighbor MAC".to_string())?;
    match dst {
        IpAddr::V4(dst_v4) => build_injected_ipv4(req, dst_mac, dst_v4, egress),
        IpAddr::V6(dst_v6) => build_injected_ipv6(req, dst_mac, dst_v6, egress),
    }
}

/// Build a forwarded frame for NAT64 packets. NAT64 changes the IP address
/// family so the frame size changes (IPv6→IPv4 shrinks by 20, IPv4→IPv6 grows
/// by 20). This always uses a copy path — in-place rewrite is not possible.
pub(super) fn build_nat64_forwarded_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    nat64_reverse: Option<&Nat64ReverseInfo>,
) -> Option<Vec<u8>> {
    let meta = meta.into();
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
            crate::nat64::build_nat64_v6_to_v4_frame(
                frame, snat_v4, dst_v4, dst_mac, src_mac, vlan_id,
            )
        }
        libc::AF_INET => {
            // Reverse direction: IPv4 → IPv6 (reply from server).
            let info = nat64_reverse?;
            // Reply: src_v6 = original dst (NAT64 prefix + server), dst_v6 = original client
            crate::nat64::build_nat64_v4_to_v6_frame(
                frame,
                info.orig_dst_v6,
                info.orig_src_v6,
                dst_mac,
                src_mac,
                vlan_id,
            )
        }
        _ => None,
    }
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
        return encapsulate_native_gre_frame(&out, meta, decision, forwarding);
    }
    Some(out)
}


pub(super) fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let meta = meta.into();
    let dst_mac = decision.resolution.neighbor_mac?;
    let enforced_ports = expected_ports;
    // Use meta L3 offset when it's a valid Ethernet header size (14 or 18),
    // otherwise re-derive from the frame's ethertype.
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    if l3 >= frame.len() {
        return None;
    }
    let raw_payload = &frame[l3..];
    let payload = trim_l3_payload(raw_payload, meta);
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
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let frame_len = eth_len + payload.len();
    if frame_len > out.len() {
        return None;
    }
    write_eth_header_slice(
        out.get_mut(..eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
    )?;
    let payload_out = out.get_mut(eth_len..frame_len)?;
    // SAFETY: source (payload) and destination (payload_out) are distinct
    // buffers — payload is from the ingress UMEM, payload_out is in the
    // egress UMEM. Lengths are equal because both span eth_len..frame_len.
    debug_assert_eq!(payload_out.len(), payload.len());
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), payload_out.as_mut_ptr(), payload.len());
    }
    let out = &mut out[..frame_len];
    let force_tunnel_l4_recompute = decision.resolution.tunnel_endpoint_id != 0;
    let tunnel_tcp_mss = native_gre_tcp_mss(forwarding, decision, meta.addr_family);
    let ip_start = eth_len;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if out.len() < ip_start + 20 {
                return None;
            }
            let ihl = ((out[ip_start] & 0x0f) as usize) * 4;
            if ihl < 20 || out.len() < ip_start + ihl {
                return None;
            }
            if (meta.meta_flags & 0x80) == 0 && out[ip_start + 8] <= 1 {
                return None;
            }
            let old_src = Ipv4Addr::new(
                out[ip_start + 12],
                out[ip_start + 13],
                out[ip_start + 14],
                out[ip_start + 15],
            );
            let old_dst = Ipv4Addr::new(
                out[ip_start + 16],
                out[ip_start + 17],
                out[ip_start + 18],
                out[ip_start + 19],
            );
            let old_ttl = out[ip_start + 8];
            // IHL already computed above — use directly instead of re-parsing.
            let rel_l4 = ihl;
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv4(&mut out[ip_start..], meta.protocol, decision.nat)?;
            }
            let skip_ttl = (meta.meta_flags & 0x80) != 0;
            if !skip_ttl {
                out[ip_start + 8] -= 1;
            }
            let enforced = enforce_expected_ports_at(
                out,
                ip_start,
                ip_start + rel_l4,
                meta.addr_family,
                meta.protocol,
                enforced_ports,
            )
            .unwrap_or(false);
            adjust_ipv4_header_checksum(
                &mut out[ip_start..ip_start + ihl],
                old_src,
                old_dst,
                old_ttl,
            )?;
            if tunnel_tcp_mss > 0 {
                let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
            }
            if force_tunnel_l4_recompute || (repaired_ports && !enforced) {
                recompute_l4_checksum_ipv4(&mut out[ip_start..], ihl, meta.protocol, true)?;
            }
        }
        libc::AF_INET6 => {
            if out.len() < ip_start + 40 {
                return None;
            }
            if (meta.meta_flags & 0x80) == 0 && out[ip_start + 7] <= 1 {
                return None;
            }
            // Use meta-derived L4 offset when valid (>= 40 for IPv6 base header,
            // avoids walking extension headers). Fall back to parsing otherwise.
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&out[ip_start..], meta.addr_family)?
            };
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv6(&mut out[ip_start..], meta.protocol, decision.nat)?;
            }
            if (meta.meta_flags & 0x80) == 0 {
                out[ip_start + 7] -= 1;
            }
            let enforced = enforce_expected_ports_at(
                out,
                ip_start,
                ip_start + rel_l4,
                meta.addr_family,
                meta.protocol,
                enforced_ports,
            )
            .unwrap_or(false);
            if tunnel_tcp_mss > 0 {
                let _ = clamp_tcp_mss_frame(out, ip_start, tunnel_tcp_mss);
            }
            if force_tunnel_l4_recompute || (repaired_ports && !enforced) {
                recompute_l4_checksum_ipv6(&mut out[ip_start..], meta.protocol)?;
            }
        }
        _ => return None,
    }
    // Debug: dump first N built frames' Ethernet + IP headers to see post-NAT on wire
    if cfg!(feature = "debug-log") {
        thread_local! {
            static BUILD_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        BUILD_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 30 {
                c.set(n + 1);
                let pkt_detail = decode_frame_summary(out);
                eprintln!(
                    "DBG BUILT_ETH[{}]: vlan={} frame_len={} proto={} {}",
                    n, vlan_id, frame_len, meta.protocol, pkt_detail,
                );
                // For the first 3 frames, also dump the full IP+TCP header hex
                if n < 3 {
                    let dump_len = frame_len.min(out.len()).min(eth_len + 60);
                    let hex: String = out[..dump_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("DBG BUILT_HEX[{n}]: {hex}");
                }
            }
        });
    }
    // Checksum verification: recompute from scratch and compare to incremental update.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&out[..frame_len]);
    }

    // RST corruption check: detect if frame building introduced a TCP RST
    // that wasn't in the source frame.
    if cfg!(feature = "debug-log") {
        let out_has_rst = frame_has_tcp_rst(&out[..frame_len]);
        let in_has_rst = frame_has_tcp_rst(frame);
        if out_has_rst && !in_has_rst {
            thread_local! {
                static BUILD_RST_CORRUPT_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
            }
            BUILD_RST_CORRUPT_COUNT.with(|c| {
                let n = c.get();
                if n < 20 {
                    c.set(n + 1);
                    let in_summary = decode_frame_summary(frame);
                    let out_summary = decode_frame_summary(&out[..frame_len]);
                    eprintln!(
                        "RST_CORRUPT BUILD[{}]: frame build INTRODUCED RST! in=[{}] out=[{}]",
                        n, in_summary, out_summary,
                    );
                    let in_hex_len = frame.len().min(80);
                    let in_hex: String = frame[..in_hex_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let out_hex_len = frame_len.min(out.len()).min(80);
                    let out_hex: String = out[..out_hex_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("RST_CORRUPT IN_HEX[{n}]: {in_hex}");
                    eprintln!("RST_CORRUPT OUT_HEX[{n}]: {out_hex}");
                }
            });
        }
    }
    Some(frame_len)
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

#[inline]
fn rewrite_prepare_eth_from_parts(
    area: &MmapArea,
    desc: XdpDesc,
    meta: ForwardPacketMeta,
    params: RewriteEthParams,
) -> Option<RewritePrep> {
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
    let (tx_offset, l2_rewrite) =
        classify_in_place_l2_rewrite(desc.addr, l3, eth_len, frame_len)?;

    if matches!(
        l2_rewrite,
        InPlaceL2Rewrite::VlanPushMemmoveNoHeadroom | InPlaceL2Rewrite::UnsupportedMemmove
    ) {
        let frame =
            unsafe { area.slice_mut_unchecked(desc.addr as usize, UMEM_FRAME_SIZE as usize)? };
        let source_end = l3.checked_add(payload_len)?;
        if frame_len > frame.len() || source_end > frame.len() {
            return None;
        }
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
    // Fabric-ingress packets already had TTL decremented by the
    // sending peer (FABRIC_INGRESS_FLAG = 0x80).
    let skip_ttl = (meta.meta_flags & 0x80) != 0;
    Some(RewritePrep {
        eth_len,
        ip_start: eth_len,
        frame_len,
        tx_offset,
        l2_rewrite,
        apply_nat: params.apply_nat,
        skip_ttl,
        vlan_id: params.vlan_id,
    })
}

#[inline]
fn rewrite_prepare_eth(
    area: &MmapArea,
    desc: XdpDesc,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat_on_fabric: bool,
) -> Option<RewritePrep> {
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
    rewrite_prepare_eth_from_parts(
        area,
        desc,
        meta,
        RewriteEthParams {
            dst_mac,
            src_mac,
            vlan_id,
            ether_type,
            apply_nat,
        },
    )
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
    let repaired_ports =
        restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4).unwrap_or(false);
    if apply_nat {
        apply_nat_ipv4(&mut packet[ip_start..], meta.protocol, decision.nat)?;
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
    let enforced = enforce_expected_ports(packet, meta.addr_family, meta.protocol, expected_ports)
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
    let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
    let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
        meta_rel
    } else {
        packet_rel_l4_offset(&packet[ip_start..], meta.addr_family)?
    };
    let repaired_ports =
        restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4).unwrap_or(false);
    if apply_nat {
        apply_nat_ipv6(&mut packet[ip_start..], meta.protocol, decision.nat)?;
    }
    if !skip_ttl {
        packet[ip_start + 7] -= 1;
    }
    let enforced = enforce_expected_ports(packet, meta.addr_family, meta.protocol, expected_ports)
        .unwrap_or(false);
    if repaired_ports && !enforced {
        recompute_l4_checksum_ipv6(&mut packet[ip_start..], meta.protocol)?;
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
    let prep = rewrite_prepare_eth(area, desc, meta, decision, apply_nat_on_fabric)?;
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
    // Fall back to parsing the IP header only when metadata does not carry a
    // usable payload length. This preserves the padding-trim safety net for
    // synthetic or incomplete metadata while keeping the hot path metadata-led.
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

/// Straight-line frame rewrite using a precomputed `RewriteDescriptor`.
///
/// Eliminates per-packet branches for address family, VLAN presence, NAT type,
/// and checksum recomputation — all decisions are baked into the descriptor at
/// session / flow-cache insertion time.
///
/// Returns the new frame length on success, or `None` if the frame is corrupt,
/// too short, or has a port mismatch (caller falls back to generic rewrite).
///
/// **Scope**: IPv4/IPv6 TCP and UDP only (flow cache gates on ACK-only TCP + UDP).
/// Does NOT handle: ICMP identifier repair, NAT64 (header-size change), NPTv6
/// (checksum-neutral — no L4 csum adjust needed, but address rewrite differs).
#[inline]
pub(super) fn apply_rewrite_descriptor(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    rd: &super::RewriteDescriptor,
    expected_ports: Option<(u16, u16)>,
) -> Option<InPlaceRewriteResult> {
    // NAT64 and NPTv6 use the generic path — they need special handling.
    if rd.nat64 || rd.nptv6 {
        return None;
    }

    let prep = rewrite_prepare_eth_from_parts(
        area,
        desc,
        meta.into(),
        RewriteEthParams {
            dst_mac: rd.dst_mac,
            src_mac: rd.src_mac,
            vlan_id: rd.tx_vlan_id,
            ether_type: rd.ether_type,
            apply_nat: !rd.fabric_redirect || rd.apply_nat_on_fabric,
        },
    )?;
    let packet = unsafe { area.slice_mut_unchecked(prep.tx_offset as usize, prep.frame_len)? };
    let frame_len = prep.frame_len;
    let ip = prep.ip_start;
    let skip_ttl = prep.skip_ttl;
    let apply_nat = prep.apply_nat;

    match rd.ether_type {
        0x0800 => {
            // ── IPv4 straight-line rewrite ──
            if packet.len() < ip + 20 {
                return None;
            }
            let ihl = ((packet[ip] & 0x0f) as usize) * 4;
            if ihl < 20 || packet.len() < ip + ihl {
                return None;
            }
            if !skip_ttl && packet[ip + 8] <= 1 {
                return None; // TTL expired
            }
            let l4 = ip + ihl;

            // Port validation (DMA race guard).
            // If ports don't match, fall back to generic path for repair.
            if let Some((exp_src, exp_dst)) = expected_ports {
                if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && packet.len() >= l4 + 4 {
                    let cur_src = u16::from_be_bytes([packet[l4], packet[l4 + 1]]);
                    let cur_dst = u16::from_be_bytes([packet[l4 + 2], packet[l4 + 3]]);
                    if cur_src != exp_src || cur_dst != exp_dst {
                        return None;
                    }
                }
            }

            // NAT: direct byte writes for IP addresses (#963 PR-B
            // helpers). Caller-side `if let Some(IpAddr::V4(_))`
            // matching keeps conditional logic visible at the call
            // site and lets the `#[inline(always)]` helpers fold
            // into a single MOV/MOVB instruction.
            if apply_nat {
                if let Some(IpAddr::V4(new_src)) = rd.rewrite_src_ip {
                    write_ipv4_src(packet, ip, new_src);
                }
                if let Some(IpAddr::V4(new_dst)) = rd.rewrite_dst_ip {
                    write_ipv4_dst(packet, ip, new_dst);
                }
            }

            // NAT: direct byte writes for L4 ports.
            if apply_nat {
                if let Some(new_sport) = rd.rewrite_src_port {
                    write_l4_src_port(packet, l4, new_sport);
                }
                if let Some(new_dport) = rd.rewrite_dst_port {
                    write_l4_dst_port(packet, l4, new_dport);
                }
            }

            // TTL decrement (skip for fabric-ingress — peer already decremented).
            if !skip_ttl {
                packet[ip + 8] -= 1;
            }

            // IP header checksum: precomputed NAT delta + TTL-1 delta.
            let old_csum = u16::from_be_bytes([packet[ip + 10], packet[ip + 11]]);
            let mut sum = (!old_csum as u32) & 0xffff;
            if apply_nat {
                sum += rd.ip_csum_delta as u32;
            }
            if !skip_ttl {
                // TTL-1 delta is always 0xFEFF in one's complement arithmetic
                sum += 0xFEFF;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let new_csum = !(sum as u16);
            packet[ip + 10..ip + 12].copy_from_slice(&new_csum.to_be_bytes());

            // L4 checksum: precomputed delta covers IP + port changes.
            if apply_nat && rd.l4_csum_delta != 0 {
                let l4_csum_off = match meta.protocol {
                    PROTO_TCP => l4 + 16,
                    PROTO_UDP => l4 + 6,
                    _ => 0,
                };
                if l4_csum_off > 0 && packet.len() >= l4_csum_off + 2 {
                    let old_l4_csum =
                        u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
                    // Skip UDP checksum update if zero (no checksum, RFC 768).
                    if meta.protocol != PROTO_UDP || old_l4_csum != 0 {
                        let mut l4sum = (!old_l4_csum as u32) & 0xffff;
                        l4sum += rd.l4_csum_delta as u32;
                        while (l4sum >> 16) != 0 {
                            l4sum = (l4sum & 0xffff) + (l4sum >> 16);
                        }
                        let new_l4 = !(l4sum as u16);
                        // UDP: 0x0000 means "no checksum" — use 0xFFFF (RFC 768).
                        let final_csum = if meta.protocol == PROTO_UDP && new_l4 == 0 {
                            0xFFFFu16
                        } else {
                            new_l4
                        };
                        packet[l4_csum_off..l4_csum_off + 2]
                            .copy_from_slice(&final_csum.to_be_bytes());
                    }
                }
            }
        }
        0x86dd => {
            // ── IPv6 straight-line rewrite ──
            // No IP header checksum; only L4 pseudo-header changes matter.
            if packet.len() < ip + 40 {
                return None;
            }
            if !skip_ttl && packet[ip + 7] <= 1 {
                return None; // Hop limit expired
            }

            // L4 offset from metadata or by parsing extension headers.
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&packet[ip..], meta.addr_family)?
            };
            let l4 = ip + rel_l4;

            // Port validation (DMA race guard).
            if let Some((exp_src, exp_dst)) = expected_ports {
                if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && packet.len() >= l4 + 4 {
                    let cur_src = u16::from_be_bytes([packet[l4], packet[l4 + 1]]);
                    let cur_dst = u16::from_be_bytes([packet[l4 + 2], packet[l4 + 3]]);
                    if cur_src != exp_src || cur_dst != exp_dst {
                        return None;
                    }
                }
            }

            // NAT: direct byte writes for IPv6 addresses (#963 PR-B).
            if apply_nat {
                if let Some(IpAddr::V6(new_src)) = rd.rewrite_src_ip {
                    write_ipv6_src(packet, ip, new_src);
                }
                if let Some(IpAddr::V6(new_dst)) = rd.rewrite_dst_ip {
                    write_ipv6_dst(packet, ip, new_dst);
                }
            }

            // NAT: direct byte writes for L4 ports (#963 PR-B).
            if apply_nat {
                if let Some(new_sport) = rd.rewrite_src_port {
                    write_l4_src_port(packet, l4, new_sport);
                }
                if let Some(new_dport) = rd.rewrite_dst_port {
                    write_l4_dst_port(packet, l4, new_dport);
                }
            }

            // Hop limit decrement (skip for fabric-ingress).
            if !skip_ttl {
                packet[ip + 7] -= 1;
            }

            // L4 checksum: precomputed delta covers IPv6 address + port changes.
            if apply_nat && rd.l4_csum_delta != 0 {
                let l4_csum_off = match meta.protocol {
                    PROTO_TCP => l4 + 16,
                    PROTO_UDP => l4 + 6,
                    PROTO_ICMPV6 => l4 + 2,
                    _ => 0,
                };
                if l4_csum_off > 0 && packet.len() >= l4_csum_off + 2 {
                    let old_l4_csum =
                        u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
                    let mut l4sum = (!old_l4_csum as u32) & 0xffff;
                    l4sum += rd.l4_csum_delta as u32;
                    while (l4sum >> 16) != 0 {
                        l4sum = (l4sum & 0xffff) + (l4sum >> 16);
                    }
                    let new_l4 = !(l4sum as u16);
                    // IPv6 UDP must have non-zero checksum; use 0xFFFF for all.
                    let final_csum = if new_l4 == 0 { 0xFFFFu16 } else { new_l4 };
                    packet[l4_csum_off..l4_csum_off + 2].copy_from_slice(&final_csum.to_be_bytes());
                }
            }
        }
        _ => return None,
    }

    // Checksum verification for descriptor path (debug only).
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(InPlaceRewriteResult {
        offset: prep.tx_offset,
        len: frame_len as u32,
        l2_rewrite: prep.l2_rewrite,
    })
}

pub(super) fn apply_nat_ipv4(packet: &mut [u8], protocol: u8, nat: NatDecision) -> Option<()> {
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
        adjust_l4_checksum_ipv4_src(packet, ihl, protocol, old_src, new_src)?;
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        write_ipv4_dst(packet, 0, new_dst);
        adjust_l4_checksum_ipv4_dst(packet, ihl, protocol, old_dst, new_dst)?;
    } else if new_src.is_some() || new_dst.is_some() {
        if let Some(ip) = new_src {
            write_ipv4_src(packet, 0, ip);
        }
        if let Some(ip) = new_dst {
            write_ipv4_dst(packet, 0, ip);
        }
        let new_src = new_src.unwrap_or(old_src);
        let new_dst = new_dst.unwrap_or(old_dst);
        match protocol {
            PROTO_TCP => {
                adjust_l4_checksum_ipv4(packet, ihl, protocol, old_src, new_src, old_dst, new_dst)?
            }
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

    // --- L4 port rewriting (after IP rewriting) ---
    apply_nat_port_rewrite(packet, ihl, protocol, nat)?;

    Some(())
}

pub(super) fn apply_nat_ipv6(packet: &mut [u8], protocol: u8, nat: NatDecision) -> Option<()> {
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
    let skip_l4_csum = nat.nptv6;
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        let old_src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
        write_ipv6_src(packet, 0, new_src);
        if !skip_l4_csum {
            adjust_l4_checksum_ipv6_addr_bytes(packet, protocol, &old_src, &new_src.octets())?;
        }
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        let old_dst: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
        write_ipv6_dst(packet, 0, new_dst);
        if !skip_l4_csum {
            adjust_l4_checksum_ipv6_addr_bytes(packet, protocol, &old_dst, &new_dst.octets())?;
        }
    } else if new_src.is_some() || new_dst.is_some() {
        let old_src_words = ipv6_words_from_slice(packet.get(8..24)?)?;
        let old_dst_words = ipv6_words_from_slice(packet.get(24..40)?)?;
        if let Some(ip) = new_src {
            write_ipv6_src(packet, 0, ip);
        }
        if let Some(ip) = new_dst {
            write_ipv6_dst(packet, 0, ip);
        }
        if !skip_l4_csum {
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
                        protocol,
                        &old_src_words,
                        &new_src_words,
                    )?;
                    adjust_l4_checksum_ipv6_words(
                        packet,
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
    // IPv6 header is always 40 bytes (no IHL).
    apply_nat_port_rewrite(packet, 40, protocol, nat)?;

    Some(())
}

/// Rewrite L4 source/destination ports and incrementally update the L4 checksum.
/// Port rewriting MUST happen AFTER IP address rewriting to avoid double-counting
/// in the checksum. Skips ICMP (no ports).
pub(super) fn apply_nat_port_rewrite(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    nat: NatDecision,
) -> Option<()> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
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
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_src_port)?;
        }
    }

    if let Some(new_dst_port) = nat.rewrite_dst_port {
        let port_offset = l4_offset + 2; // TCP/UDP dst port at offset +2
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_dst_port {
            write_l4_dst_port(packet, l4_offset, new_dst_port);
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_dst_port)?;
        }
    }

    Some(())
}

/// Incremental L4 checksum update for a single 16-bit port change.
pub(super) fn adjust_l4_checksum_port(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
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
    // Skip UDP IPv4 checksum update when checksum is 0 (optional for IPv4 UDP)
    if matches!(protocol, PROTO_UDP) && current == 0 {
        return Some(());
    }
    let mut updated = checksum16_adjust(current, &[old_port], &[new_port]);
    if matches!(protocol, PROTO_UDP) && updated == 0 {
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
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
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
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_src, expected_src)?;
    }
    if current_dst != expected_dst {
        write_l4_dst_port(packet, rel_l4, expected_dst);
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_dst, expected_dst)?;
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
    _addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
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
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_src, expected_src)?;
    }
    if current_dst != expected_dst {
        write_l4_dst_port(packet, rel_l4, expected_dst);
        adjust_l4_checksum_port(packet, rel_l4, protocol, current_dst, expected_dst)?;
    }
    Some(true)
}

pub(super) fn restore_l4_tuple_from_meta(
    packet: &mut [u8],
    meta: impl Into<ForwardPacketMeta>,
    rel_l4: usize,
) -> Option<bool> {
    let meta = meta.into();
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => Some(false),
        PROTO_ICMP | PROTO_ICMPV6 => {
            let ident = packet.get_mut(rel_l4 + 4..rel_l4 + 6)?;
            let expected = meta.flow_src_port.to_be_bytes();
            let repaired = *ident != expected;
            if repaired {
                ident.copy_from_slice(&expected);
            }
            Some(repaired)
        }
        _ => Some(false),
    }
}

pub(super) fn build_injected_ipv4(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let src_ip = egress
        .primary_v4
        .ok_or_else(|| "egress interface has no IPv4 source address".to_string())?;
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 20 + 8 + 16;
    let target_len = req.packet_length.max(min_total as u32) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 20 + 8);

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x0800);

    let total_len = (20 + 8 + payload_len) as u16;
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
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
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
    dst_ip: Ipv6Addr,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let src_ip = egress
        .primary_v6
        .ok_or_else(|| "egress interface has no IPv6 source address".to_string())?;
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 40 + 8 + 16;
    let target_len = req.packet_length.max(min_total as u32) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 40 + 8);

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x86dd);
    let plen = (8 + payload_len) as u16;
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
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

pub(super) fn write_eth_header(
    buf: &mut Vec<u8>,
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) {
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    if vlan_id > 0 {
        buf.extend_from_slice(&0x8100u16.to_be_bytes());
        buf.extend_from_slice(&(vlan_id & 0x0fff).to_be_bytes());
    }
    buf.extend_from_slice(&ether_type.to_be_bytes());
}

pub(super) fn write_eth_header_slice(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) -> Option<()> {
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    if buf.len() < eth_len {
        return None;
    }
    let ether_type_bytes = ether_type.to_be_bytes();
    // SAFETY: buf.len() >= eth_len is guaranteed by the guard above.
    // eth_len is 14 (no VLAN) or 18 (VLAN), so all writes are in-bounds.
    debug_assert!(buf.len() >= eth_len);
    unsafe {
        let ptr = buf.as_mut_ptr();
        core::ptr::copy_nonoverlapping(dst.as_ptr(), ptr, 6);
        core::ptr::copy_nonoverlapping(src.as_ptr(), ptr.add(6), 6);
        if vlan_id > 0 {
            core::ptr::copy_nonoverlapping(0x8100u16.to_be_bytes().as_ptr(), ptr.add(12), 2);
            core::ptr::copy_nonoverlapping(
                (vlan_id & 0x0fff).to_be_bytes().as_ptr(),
                ptr.add(14),
                2,
            );
            core::ptr::copy_nonoverlapping(ether_type_bytes.as_ptr(), ptr.add(16), 2);
        } else {
            core::ptr::copy_nonoverlapping(ether_type_bytes.as_ptr(), ptr.add(12), 2);
        }
    }
    Some(())
}

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
        pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
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
            pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
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
                    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
