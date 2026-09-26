//! IPv6 arm of `apply_rewrite_descriptor`.
//!
//! Split into a read-only `validate_rewrite_descriptor_ipv6` (all
//! None-returning bail gates, including the `v6_rel_l4_offset`
//! extension-header walk) and an infallible
//! `apply_rewrite_descriptor_ipv6` (mutation only). #5466 requires the
//! gates to run against the PRISTINE frame BEFORE the eth-header write /
//! VLAN-push memmove commit. The apply body is byte-identical to the
//! pre-split mutation block, so success-path output is unchanged.

use super::super::byte_writes::{
    write_ipv6_dst, write_ipv6_src, write_l4_dst_port, write_l4_src_port,
};
use super::super::checksum::{adjust_zero_checksum_illegal, ChecksumFamily};
use super::super::v6_rel_l4_offset;
use crate::afxdp::{
    RewriteDescriptor, UserspaceDpMeta, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP,
};
use crate::ip_proto::has_l4_ports;
use std::net::IpAddr;

/// Read-only bail gates for the IPv6 descriptor rewrite. `l3_payload` is
/// the frame from the L3 offset onward (`&frame[ip..ip + payload_len]`),
/// so every check is relative to offset 0 and yields identical decisions
/// whether run on the ORIGINAL frame (pre-commit) or the committed TX
/// frame (the commit's memmove is a pure relocation). Returns the L4
/// offset relative to the IP header on success; `None` on any bail (header
/// too short, hop-limit expired, unparseable L4 offset, DMA-race port
/// mismatch).
#[inline(always)]
pub(in crate::afxdp::frame) fn validate_rewrite_descriptor_ipv6(
    l3_payload: &[u8],
    skip_ttl: bool,
    meta: UserspaceDpMeta,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    // No IP header checksum; only L4 pseudo-header changes matter.
    if l3_payload.len() < 40 {
        return None;
    }
    if !skip_ttl && l3_payload[7] <= 1 {
        return None; // Hop limit expired
    }
    // #10729 X2-F6: decline chains sighting AH — the descriptor's
    // precomputed checksum delta covers port writes the generic path now
    // strips through AH (ICV break), so the paths cannot agree here. The
    // generic fallback applies full AH semantics. AH is rare; slow is fine.
    if crate::afxdp::frame::ipv6_ah_sighted(l3_payload, libc::AF_INET6 as u8, 0) {
        return None;
    }

    // L4 offset from metadata or by parsing extension headers — the
    // shared `v6_rel_l4_offset` helper (#1838) keeps this precedence
    // rule structurally identical to the generic path's.
    let rel_l4 =
        v6_rel_l4_offset(l3_payload, meta.l3_offset, meta.l4_offset, meta.addr_family)?;

    // Port validation (DMA race guard).
    if let Some((exp_src, exp_dst)) = expected_ports {
        if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && l3_payload.len() >= rel_l4 + 4 {
            let cur_src = u16::from_be_bytes([l3_payload[rel_l4], l3_payload[rel_l4 + 1]]);
            let cur_dst = u16::from_be_bytes([l3_payload[rel_l4 + 2], l3_payload[rel_l4 + 3]]);
            if cur_src != exp_src || cur_dst != exp_dst {
                return None;
            }
        }
    }
    Some(rel_l4)
}

/// Infallible mutation half of the IPv6 descriptor rewrite. MUST be called
/// only after `validate_rewrite_descriptor_ipv6` cleared the gates; `rel_l4`
/// is that call's return. No path returns `None` — every write is bounds-safe
/// given the validated `packet.len() >= ip + 40` / `>= ip + rel_l4` layout.
#[inline(always)]
pub(in crate::afxdp::frame) fn apply_rewrite_descriptor_ipv6(
    packet: &mut [u8],
    ip: usize,
    rel_l4: usize,
    skip_ttl: bool,
    apply_nat: bool,
    meta: UserspaceDpMeta,
    rd: &RewriteDescriptor,
) {
    let l4 = ip + rel_l4;

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
    //
    // #3111: gate on TCP/UDP — a port-less protocol (GRE/ESP/AH/OSPF/...)
    // has no port field, so writing offset +0/+2 would corrupt the L4
    // header (ESP SPI / GRE flags). Mirrors the generic rewriter's gate.
    if apply_nat && has_l4_ports(meta.protocol) {
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
            // #1839: computed-zero canonicalization scoped to the
            // shared predicate (UDP + ICMPv6 for v6 — RFC 8200 §8.1
            // mandates the 0 → 0xFFFF substitution for UDP only; a
            // computed TCP 0x0000 is valid on the wire and now matches
            // both the generic adjusters and v4 TCP behavior).
            let final_csum =
                if new_l4 == 0 && adjust_zero_checksum_illegal(meta.protocol, ChecksumFamily::V6) {
                    0xFFFFu16
                } else {
                    new_l4
                };
            packet[l4_csum_off..l4_csum_off + 2].copy_from_slice(&final_csum.to_be_bytes());
        }
    }
}
