//! IPv6 arm of `apply_rewrite_descriptor`.
//!
//! Split into a read-only `validate_rewrite_descriptor_ipv6` (all
//! None-returning bail gates, including the `v6_rel_l4_offset`
//! extension-header walk) and an infallible
//! `apply_rewrite_descriptor_ipv6` (mutation only). #5466 requires the
//! gates to run against the PRISTINE frame BEFORE the eth-header write /
//! VLAN-push memmove commit. The apply half preserves the pre-split
//! success-path behavior; the validator checks any folding L4 checksum
//! field before commit.

use super::super::byte_writes::{
    write_ipv6_dst, write_ipv6_src, write_l4_dst_port, write_l4_src_port,
};
use super::super::checksum::{
    adjust_zero_checksum_illegal, l4_checksum_field_delta_v6, ChecksumFamily,
};
use super::super::v6_rel_l4_offset;
use crate::afxdp::{RewriteDescriptor, UserspaceDpMeta, PROTO_TCP, PROTO_UDP};
use crate::ip_proto::has_l4_ports;
use std::net::IpAddr;

/// Read-only bail gates for the IPv6 descriptor rewrite. `l3_payload` is
/// the frame from the L3 offset onward (`&frame[ip..ip + payload_len]`),
/// so every check is relative to offset 0 and yields identical decisions
/// whether run on the ORIGINAL frame (pre-commit) or the committed TX
/// frame (the commit's memmove is a pure relocation). Returns the L4 offset
/// relative to the IP header and, when the fold gate applies, its validated
/// checksum-field offset relative to the IP header; `None` on any bail (header
/// too short, hop-limit expired, unparseable L4 offset, DMA-race port mismatch,
/// or a truncated checksum field when the descriptor will fold).
#[inline(always)]
pub(in crate::afxdp::frame) fn validate_rewrite_descriptor_ipv6(
    l3_payload: &[u8],
    skip_ttl: bool,
    meta: UserspaceDpMeta,
    expected_ports: Option<(u16, u16)>,
    fold_l4_csum: bool,
) -> Option<(usize, Option<usize>)> {
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
    // #4965: match the apply half's exact fold gate. A short packet with a
    // truncated field must decline before commit instead of rewriting addresses
    // and then silently skipping the out-of-bounds checksum fold.
    let l4_checksum_field_offset = if fold_l4_csum {
        if let Some(delta) = l4_checksum_field_delta_v6(meta.protocol) {
            let field_offset = rel_l4 + delta;
            if l3_payload.len() < field_offset + 2 {
                return None;
            }
            Some(field_offset)
        } else {
            None
        }
    } else {
        None
    };

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
    Some((rel_l4, l4_checksum_field_offset))
}

/// only after `validate_rewrite_descriptor_ipv6` cleared the gates; `rel_l4`
/// and the optional L4 checksum-field offset relative to the IP header are
/// that call's returns. No path returns `None` — every write is bounds-safe
/// given the validated header/rel_l4 layout and fold-gated checksum field bound.
#[inline(always)]
pub(in crate::afxdp::frame) fn apply_rewrite_descriptor_ipv6(
    packet: &mut [u8],
    ip: usize,
    rel_l4: usize,
    l4_checksum_field_offset: Option<usize>,
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
        if let Some(field_offset) = l4_checksum_field_offset {
            let l4_csum_off = ip + field_offset;
            debug_assert!(packet.len() >= l4_csum_off + 2);
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
