//! IPv4 arm of `apply_rewrite_descriptor`.
//!
//! Split into a read-only `validate_rewrite_descriptor_ipv4` (all
//! None-returning bail gates) and an infallible
//! `apply_rewrite_descriptor_ipv4` (mutation only). #5466 requires the
//! gates to run against the PRISTINE frame BEFORE the eth-header write /
//! VLAN-push memmove commit, so the orchestrator calls `validate_*` on
//! the original L3 payload and only calls `apply_*` after the commit —
//! keeping the rewrite transactional (no UMEM mutation before a possible
//! `None`). The apply half preserves the pre-split success-path behavior,
//! while the validator now checks a folding L4 checksum field before commit.

use super::super::byte_writes::{
    write_ipv4_dst, write_ipv4_src, write_l4_dst_port, write_l4_src_port,
};
use super::super::checksum::{
    adjust_zero_checksum_illegal, l4_checksum_field_delta_v4, l4_udp_checksum_optional,
    ChecksumFamily,
};
use crate::afxdp::{RewriteDescriptor, UserspaceDpMeta, PROTO_TCP, PROTO_UDP};
use crate::ip_proto::has_l4_ports;
use std::net::IpAddr;

/// Read-only bail gates for the IPv4 descriptor rewrite. `l3_payload` is
/// the frame from the L3 offset onward (`&frame[ip..ip + payload_len]`),
/// so all length checks and byte reads are relative to offset 0 — this
/// makes the gate decisions identical whether run on the ORIGINAL frame
/// (pre-commit, at `plan.l3`) or the committed TX frame (at `eth_len`),
/// because the commit's memmove is a pure relocation. Returns the L4
/// offset relative to the IP header (the IHL) and, when the fold gate
/// applies, its validated checksum-field offset relative to the IP header;
/// `None` on any bail (header too short, TTL expired, DMA-race port mismatch,
/// or a truncated L4 checksum field when the descriptor will fold its delta).
#[inline(always)]
pub(in crate::afxdp::frame) fn validate_rewrite_descriptor_ipv4(
    l3_payload: &[u8],
    skip_ttl: bool,
    meta: UserspaceDpMeta,
    expected_ports: Option<(u16, u16)>,
    fold_l4_csum: bool,
) -> Option<(usize, Option<usize>)> {
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
    // #4965: the apply half folds into the L4 checksum only when both
    // `apply_nat` and the descriptor delta are non-zero. Validate the
    // checksum field before the eth commit so a short packet cannot half-apply
    // its address/port and IPv4-header rewrites.
    let l4_checksum_field_offset = if fold_l4_csum {
        if let Some(delta) = l4_checksum_field_delta_v4(meta.protocol) {
            let field_offset = ihl + delta;
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
    // If ports don't match, fall back to generic path for repair.
    if let Some((exp_src, exp_dst)) = expected_ports {
        if matches!(meta.protocol, PROTO_TCP | PROTO_UDP) && l3_payload.len() >= ihl + 4 {
            let cur_src = u16::from_be_bytes([l3_payload[ihl], l3_payload[ihl + 1]]);
            let cur_dst = u16::from_be_bytes([l3_payload[ihl + 2], l3_payload[ihl + 3]]);
            if cur_src != exp_src || cur_dst != exp_dst {
                return None;
            }
        }
    }
    Some((ihl, l4_checksum_field_offset))
}

/// Infallible mutation half of the IPv4 descriptor rewrite. MUST be called
/// only after `validate_rewrite_descriptor_ipv4` cleared the gates; `rel_l4`
/// and the optional L4 checksum-field offset relative to the IP header are
/// that call's returns. No path returns `None` — every write is bounds-safe
/// given the validated header layout and, for L4 folds, field bound.
#[inline(always)]
pub(in crate::afxdp::frame) fn apply_rewrite_descriptor_ipv4(
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
    //
    // #3111: only rewrite ports for protocols that actually carry a
    // 16-bit port pair at offset +0/+2 (TCP/UDP). A port-less protocol
    // (GRE/ESP/AH/OSPF/...) has no port field; writing here would clobber
    // the first two L4 bytes (ESP SPI / GRE flags). The allocator already
    // leaves `rewrite_src_port` unset for these, but this guard mirrors
    // the generic rewriter's TCP|UDP gate so neither path can corrupt a
    // tunnel header even if a stale descriptor still carries a port.
    if apply_nat && has_l4_ports(meta.protocol) {
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
        if let Some(field_offset) = l4_checksum_field_offset {
            let l4_csum_off = ip + field_offset;
            debug_assert!(packet.len() >= l4_csum_off + 2);
            let old_l4_csum =
                u16::from_be_bytes([packet[l4_csum_off], packet[l4_csum_off + 1]]);
            // Skip IPv4 UDP checksum update if zero (no checksum, RFC 768).
            if !l4_udp_checksum_optional(meta.protocol, ChecksumFamily::V4) || old_l4_csum != 0 {
                let mut l4sum = (!old_l4_csum as u32) & 0xffff;
                l4sum += rd.l4_csum_delta as u32;
                while (l4sum >> 16) != 0 {
                    l4sum = (l4sum & 0xffff) + (l4sum >> 16);
                }
                let new_l4 = !(l4sum as u16);
                let final_csum =
                    if new_l4 == 0 && adjust_zero_checksum_illegal(meta.protocol, ChecksumFamily::V4) {
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
