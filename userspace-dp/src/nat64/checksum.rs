//! NAT64 checksum helpers.
//!
//! The deliberate `checksum16*` one-line forwards to
//! `crate::afxdp::frame::checksum` (kept post-#13086), the streamed
//! pseudo-header checksums, and the RFC 1624 incremental adjusters.
//!
//! #16188 PURE CODE MOTION: every line below was moved verbatim from
//! `nat64.rs` lines 4687-4844. The only edits are the visibility
//! widenings enumerated in `nat64/mod.rs`; no logic, no ordering and
//! no signature changed.

use super::*;

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

// #13086 (D6-13): the scalar duplicates of afxdp::frame::checksum are
// gone — delegate to the shared (vectorized) implementation. Bit-
// identical by the frame module's own differential tests.
pub(super) fn checksum16(data: &[u8]) -> u16 {
    crate::afxdp::frame::checksum::checksum16(data)
}

#[inline]
pub(super) fn checksum16_add(sum: u32, bytes: &[u8]) -> u32 {
    crate::afxdp::frame::checksum::checksum16_add_bytes(sum, bytes)
}

#[inline]
pub(super) fn checksum16_fold(sum: u32) -> u16 {
    crate::afxdp::frame::checksum::checksum16_finish(sum)
}

/// IPv4 pseudo-header + L4 checksum, streamed (no per-packet `Vec`, #2211).
pub(super) fn checksum16_ipv4_pseudo(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add(sum, &src.octets());
    sum = checksum16_add(sum, &dst.octets());
    sum = checksum16_add(sum, &[0, protocol]);
    sum = checksum16_add(sum, &(payload.len() as u16).to_be_bytes());
    sum = checksum16_add(sum, payload);
    checksum16_fold(sum)
}

/// IPv6 pseudo-header + L4 checksum, streamed (no per-packet `Vec`, #2211).
pub(super) fn checksum16_ipv6_pseudo(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add(sum, &src.octets());
    sum = checksum16_add(sum, &dst.octets());
    sum = checksum16_add(sum, &(payload.len() as u32).to_be_bytes());
    sum = checksum16_add(sum, &[0, 0, 0, next_header]);
    sum = checksum16_add(sum, payload);
    checksum16_fold(sum)
}

/// Incremental one's-complement checksum update (RFC 1624 eqn 3): given an
/// existing checksum `old_cksum` and a set of 16-bit words that changed from
/// `old_bytes` to `new_bytes`, return the new checksum WITHOUT re-summing the
/// rest of the protected data. Used for translated TCP/UDP FRAGMENTs (#2488)
/// where the transport payload is incomplete and only the IP pseudo-header
/// addresses differ between the v4 and v6 forms. `old_bytes` / `new_bytes` are
/// big-endian and may be any (even) length; a trailing odd byte is padded with
/// zero, matching the standard checksum word split.
pub(super) fn checksum16_incremental(old_cksum: u16, old_bytes: &[u8], new_bytes: &[u8]) -> u16 {
    // HC' = ~( ~HC + sum(~m_i) + sum(m'_i) )
    let mut sum: u32 = u32::from(!old_cksum);
    for w in old_bytes.chunks(2) {
        let val = u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]);
        sum += u32::from(!val);
    }
    for w in new_bytes.chunks(2) {
        let val = u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]);
        sum += u32::from(val);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Adjust a translated v6→v4 TCP/UDP L4 checksum for the pseudo-header address
/// change only (RFC 1624 incremental). The L4 header at `out[20..]` was copied
/// verbatim and still holds the IPv6-pseudo-header checksum; fold the 32-byte v6
/// address pair out and the 8-byte v4 address pair in. The L4 length and
/// protocol number are identical across the translation so they cancel.
///
/// Used for BOTH the #2488 FRAGMENT path (where the transport payload is
/// incomplete and a full recompute is impossible) AND the #3025 non-fragment
/// fast path (where the payload IS present but only the pseudo-header changed, so
/// the O(1) adjustment is byte-identical to a full recompute over the whole
/// payload — one's-complement addition is exact, RFC 1624 §3). The caller must
/// only invoke this when the verbatim L4 checksum is a trustworthy baseline: for
/// non-fragment UDP a zero baseline means "no checksum present" on the v6 input
/// (illegal, but defended against) and must take the full recompute instead.
pub(super) fn adjust_l4_checksum_v6_to_v4_incremental(
    out: &mut [u8],
    protocol: u8,
    v6_src_dst: &[u8; 32],
    v4_src: Ipv4Addr,
    v4_dst: Ipv4Addr,
) -> Option<()> {
    let field = match protocol {
        PROTO_TCP => 16usize,
        PROTO_UDP => 6,
        _ => return Some(()),
    };
    let l4 = out.get_mut(20..)?;
    let cksum = l4.get(field..field + 2)?;
    let old = u16::from_be_bytes([cksum[0], cksum[1]]);
    let mut v4_addrs = [0u8; 8];
    v4_addrs[..4].copy_from_slice(&v4_src.octets());
    v4_addrs[4..].copy_from_slice(&v4_dst.octets());
    let updated = checksum16_incremental(old, v6_src_dst, &v4_addrs);
    // RFC 768: a computed UDP checksum of 0x0000 is transmitted as 0xFFFF.
    let final_sum = if protocol == PROTO_UDP && updated == 0 {
        0xFFFF
    } else {
        updated
    };
    l4[field..field + 2].copy_from_slice(&final_sum.to_be_bytes());
    Some(())
}

/// Adjust a translated v4→v6 TCP/UDP L4 checksum for the pseudo-header address
/// change only (RFC 1624 incremental). The L4 header sits at `dst[l4_off..]`
/// (past any inserted IPv6 Fragment Header) and still holds the
/// IPv4-pseudo-header checksum; fold the 8-byte v4 address pair out and the
/// 32-byte v6 address pair in.
///
/// Used for BOTH the #2488 FRAGMENT path AND the #3025 non-fragment fast path
/// (byte-identical to a full recompute; see the v6→v4 twin). The caller must
/// only invoke this when the verbatim IPv4 L4 checksum is a trustworthy
/// baseline: an IPv4 UDP checksum of 0 means "no checksum present" (RFC 768), so
/// there is no baseline to adjust and — because IPv6 UDP mandates a checksum —
/// that case MUST take the full recompute to GENERATE one. (A zero IPv4 UDP
/// checksum was already rejected upstream for a fragment, so on the fragment
/// path `old` is non-zero here.)
pub(super) fn adjust_l4_checksum_v4_to_v6_incremental(
    dst: &mut [u8],
    next_header: u8,
    l4_off: usize,
    v4_src_dst: &[u8; 8],
    v6_src_dst: &[u8; 32],
) -> Option<()> {
    let field = match next_header {
        PROTO_TCP => 16usize,
        PROTO_UDP => 6,
        _ => return Some(()),
    };
    let l4 = dst.get_mut(l4_off..)?;
    let cksum = l4.get(field..field + 2)?;
    let old = u16::from_be_bytes([cksum[0], cksum[1]]);
    let updated = checksum16_incremental(old, v4_src_dst, v6_src_dst);
    // UDP over IPv6: a zero checksum is illegal, so a computed 0x0000 is written
    // as 0xFFFF. (Both callers guarantee a non-zero `old`: the fragment path
    // rejects a zero IPv4 UDP checksum upstream, and the #3025 non-fragment path
    // routes a zero baseline to the full recompute instead.)
    let final_sum = if next_header == PROTO_UDP && updated == 0 {
        0xFFFF
    } else {
        updated
    };
    l4[field..field + 2].copy_from_slice(&final_sum.to_be_bytes());
    Some(())
}

// ---------------------------------------------------------------------------
// Frame building helpers for NAT64
// ---------------------------------------------------------------------------

