// Pure 16-bit one's-complement checksum arithmetic for IPv4/IPv6
// header + L4 (TCP/UDP/ICMP) updates.
//
// Issue #74 / GH issue #967 SIMD path: `checksum16_add_bytes` (and
// `checksum16` which delegates to it) take an x86_64 AVX2 fast path
// when the host CPU advertises AVX2 support. The fast path processes
// 32 bytes (16 u16 words) per AVX2 iteration vs 2 bytes per scalar
// iteration. Byte-swap is done with `_mm256_shuffle_epi8` so the
// intermediate u32 partial sum is bit-identical to the scalar BE
// accumulation — callers can chain SIMD and scalar partial sums
// without semantic drift.
//
// Runtime detection via `is_x86_feature_detected!` happens on every
// call but is cached internally by the standard library; the branch
// is well-predicted. For builds compiled with `-C target-feature=+avx2`
// or `-C target-cpu=native`, the optimizer can usually fold the check
// to a constant.

use crate::afxdp::{PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(in crate::afxdp) fn checksum16(bytes: &[u8]) -> u16 {
    checksum16_finish(checksum16_add_bytes(0, bytes))
}

pub(in crate::afxdp) fn checksum16_add_bytes(sum: u32, bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: target-feature gate above guarantees AVX2.
            return unsafe { x86_avx2::checksum16_add_bytes_avx2(sum, bytes) };
        }
    }
    checksum16_add_bytes_scalar(sum, bytes)
}

/// Scalar fallback — also the reference implementation for the SIMD
/// differential tests. Kept as a free function (not just a closure)
/// so the SIMD path can call it for the trailing remainder bytes.
fn checksum16_add_bytes_scalar(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(last) = chunks.remainder().first() {
        sum = sum.wrapping_add((*last as u32) << 8);
    }
    sum
}

#[cfg(target_arch = "x86_64")]
mod x86_avx2 {
    use std::arch::x86_64::*;

    /// AVX2 one's-complement-additive byte sum producing a u32 partial
    /// sum whose value is bit-identical to
    /// `checksum16_add_bytes_scalar` for the same inputs.
    ///
    /// Strategy:
    /// 1. Load 32 bytes (`_mm256_loadu_si256`).
    /// 2. Byte-swap each of the 16 u16 lanes (`_mm256_shuffle_epi8` with
    ///    a per-pair-swap mask). Now each u16 lane holds the BE
    ///    interpretation of its bytes — matches scalar
    ///    `u16::from_be_bytes` exactly.
    /// 3. Zero-extend low 8 lanes and high 8 lanes into 32-bit lanes
    ///    (`_mm256_unpacklo_epi16` / `_mm256_unpackhi_epi16` against
    ///    a zero vector).
    /// 4. Accumulate into two YMM accumulators (lo + hi).
    /// 5. After the chunk loop, horizontally sum the eight 32-bit
    ///    lanes of `acc_lo + acc_hi` into one u32, add to caller's
    ///    `sum`, then call back into the scalar path for the trailing
    ///    < 32 bytes (which already correctly handles odd-length
    ///    remainders).
    ///
    /// Overflow note: per chunk, each of the 8 final-merged lanes
    /// (after `acc_lo + acc_hi`) absorbs the sum of two u16 values,
    /// max `2 * 0xFFFF = 0x1_FFFE`. For a 64 KiB input (2048 chunks)
    /// the per-lane max is `2048 * 0x1_FFFE = 0x0FFF_F000` — about
    /// `2^28`, well below `u32::MAX`. Realistic packet sizes
    /// (≤ 9 KiB jumbo) are far below this bound.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn checksum16_add_bytes_avx2(sum: u32, bytes: &[u8]) -> u32 {
        // SAFETY: every intrinsic below is gated by the target_feature
        // attribute, which the caller proves with `is_x86_feature_detected`.
        unsafe {
            // Per-pair byte-swap mask: within each 128-bit lane, swap
            // the bytes of every u16. AVX2 shuffle_epi8 operates per-
            // 128-bit lane, so we duplicate the mask in both halves.
            let bswap = _mm256_setr_epi8(
                1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, // low half
                1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, // high half
            );
            let zero = _mm256_setzero_si256();
            let mut acc_lo = zero;
            let mut acc_hi = zero;
            let mut chunks = bytes.chunks_exact(32);
            for chunk in &mut chunks {
                let v = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
                let v_be = _mm256_shuffle_epi8(v, bswap);
                let lo = _mm256_unpacklo_epi16(v_be, zero);
                let hi = _mm256_unpackhi_epi16(v_be, zero);
                acc_lo = _mm256_add_epi32(acc_lo, lo);
                acc_hi = _mm256_add_epi32(acc_hi, hi);
            }
            let acc = _mm256_add_epi32(acc_lo, acc_hi);
            let simd_sum = horizontal_sum_u32_avx2(acc);
            // Combine via u32 wrapping_add so the bit-32 carry is
            // discarded the same way the scalar path silently wraps.
            // The downstream `checksum16_finish` folds bit 16+ carries
            // identically in both paths, so silent wrap here is the
            // only behavior that keeps SIMD and scalar bit-for-bit
            // congruent at the u32 partial-sum interface.
            let combined = sum.wrapping_add(simd_sum);
            super::checksum16_add_bytes_scalar(combined, chunks.remainder())
        }
    }

    /// Horizontal sum of 8x u32 lanes in a 256-bit register.
    #[target_feature(enable = "avx2")]
    unsafe fn horizontal_sum_u32_avx2(v: __m256i) -> u32 {
        // SAFETY: AVX2 intrinsics; gated by target_feature on the
        // function and proved by the calling pathway.
        unsafe {
            // Reduce 256 → 128: low half + high half.
            let hi128 = _mm256_extracti128_si256(v, 1);
            let lo128 = _mm256_castsi256_si128(v);
            let sum128 = _mm_add_epi32(lo128, hi128);
            // Reduce 128 → 64: shuffle high u64 down and add.
            let shuf = _mm_shuffle_epi32(sum128, 0b1110); // [hi64, _]
            let sum64 = _mm_add_epi32(sum128, shuf);
            // Reduce 64 → 32: shuffle high u32 down and add.
            let shuf2 = _mm_shuffle_epi32(sum64, 0b0001); // [u32_1, _]
            let sum32 = _mm_add_epi32(sum64, shuf2);
            _mm_cvtsi128_si32(sum32) as u32
        }
    }
}

pub(in crate::afxdp) fn checksum16_finish(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(in crate::afxdp) fn checksum16_adjust(checksum: u16, old_words: &[u16], new_words: &[u16]) -> u16 {
    let mut sum = (!checksum as u32) & 0xffff;
    for word in old_words {
        sum += (!u32::from(*word)) & 0xffff;
    }
    for word in new_words {
        sum += u32::from(*word);
    }
    checksum16_finish(sum)
}

#[inline(always)]
fn checksum16_adjust_ipv6_addr_bytes(
    checksum: u16,
    old_addr: &[u8; 16],
    new_addr: &[u8; 16],
) -> u16 {
    let mut sum = (!checksum as u32) & 0xffff;
    let mut idx = 0usize;
    while idx < 16 {
        let old_word = u16::from_be_bytes([old_addr[idx], old_addr[idx + 1]]);
        let new_word = u16::from_be_bytes([new_addr[idx], new_addr[idx + 1]]);
        sum += (!u32::from(old_word)) & 0xffff;
        sum += u32::from(new_word);
        idx += 2;
    }
    checksum16_finish(sum)
}

pub(in crate::afxdp) fn ipv4_words(ip: Ipv4Addr) -> [u16; 2] {
    let octets = ip.octets();
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
    ]
}

#[allow(dead_code)]
pub(in crate::afxdp) fn ipv6_words(ip: Ipv6Addr) -> [u16; 8] {
    ipv6_words_from_octets(ip.octets())
}

pub(in crate::afxdp) fn ipv6_words_from_octets(octets: [u8; 16]) -> [u16; 8] {
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
        u16::from_be_bytes([octets[4], octets[5]]),
        u16::from_be_bytes([octets[6], octets[7]]),
        u16::from_be_bytes([octets[8], octets[9]]),
        u16::from_be_bytes([octets[10], octets[11]]),
        u16::from_be_bytes([octets[12], octets[13]]),
        u16::from_be_bytes([octets[14], octets[15]]),
    ]
}

pub(in crate::afxdp) fn ipv6_words_from_slice(bytes: &[u8]) -> Option<[u16; 8]> {
    let octets: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
    Some(ipv6_words_from_octets(octets))
}

pub(in crate::afxdp) fn adjust_ipv4_header_checksum(
    packet: &mut [u8],
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    old_ttl: u8,
) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    let current = u16::from_be_bytes([packet[10], packet[11]]);
    let new_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let new_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let old_ttl_word = u16::from_be_bytes([old_ttl, packet[9]]);
    let new_ttl_word = u16::from_be_bytes([packet[8], packet[9]]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    updated = checksum16_adjust(updated, &[old_ttl_word], &[new_ttl_word]);
    packet
        .get_mut(10..12)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(in crate::afxdp) fn checksum16_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add_bytes(sum, &src.octets());
    sum = checksum16_add_bytes(sum, &dst.octets());
    sum = checksum16_add_bytes(sum, &(payload.len() as u32).to_be_bytes());
    sum = checksum16_add_bytes(sum, &[0, 0, 0, next_header]);
    sum = checksum16_add_bytes(sum, payload);
    checksum16_finish(sum)
}

pub(in crate::afxdp) fn checksum16_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add_bytes(sum, &src.octets());
    sum = checksum16_add_bytes(sum, &dst.octets());
    sum = checksum16_add_bytes(sum, &[0, protocol]);
    sum = checksum16_add_bytes(sum, &(payload.len() as u16).to_be_bytes());
    sum = checksum16_add_bytes(sum, payload);
    checksum16_finish(sum)
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv4(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    new_dst: Ipv4Addr,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => ihl.checked_add(16)?,
        PROTO_UDP => ihl.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    if matches!(protocol, PROTO_UDP) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

#[allow(dead_code)]
pub(in crate::afxdp) fn adjust_l4_checksum_ipv6(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 40usize.checked_add(16)?,
        PROTO_UDP => 40usize.checked_add(6)?,
        PROTO_ICMPV6 => 40usize.checked_add(2)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv6_words(old_src), &ipv6_words(new_src));
    updated = checksum16_adjust(updated, &ipv6_words(old_dst), &ipv6_words(new_dst));
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv4_src(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv4_words(
        packet,
        ihl,
        protocol,
        &ipv4_words(old_src),
        &ipv4_words(new_src),
    )
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv4_dst(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_dst: Ipv4Addr,
    new_dst: Ipv4Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv4_words(
        packet,
        ihl,
        protocol,
        &ipv4_words(old_dst),
        &ipv4_words(new_dst),
    )
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv4_words(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => ihl.checked_add(16)?,
        PROTO_UDP => ihl.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    if matches!(protocol, PROTO_UDP) && current == 0 {
        return Some(());
    }
    let updated = checksum16_adjust(current, old_words, new_words);
    let updated = if matches!(protocol, PROTO_UDP) && updated == 0 {
        0xffff
    } else {
        updated
    };
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

#[allow(dead_code)]
pub(in crate::afxdp) fn adjust_l4_checksum_ipv6_src(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_src), &ipv6_words(new_src))
}

#[allow(dead_code)]
pub(in crate::afxdp) fn adjust_l4_checksum_ipv6_dst(
    packet: &mut [u8],
    protocol: u8,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_dst), &ipv6_words(new_dst))
}

pub(in crate::afxdp) fn adjust_l4_checksum_ipv6_words(
    packet: &mut [u8],
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 40usize.checked_add(16)?,
        PROTO_UDP => 40usize.checked_add(6)?,
        PROTO_ICMPV6 => 40usize.checked_add(2)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, old_words, new_words);
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

#[inline(always)]
pub(super) fn adjust_l4_checksum_ipv6_addr_bytes(
    packet: &mut [u8],
    protocol: u8,
    old_addr: &[u8; 16],
    new_addr: &[u8; 16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 56usize,
        PROTO_UDP => 46usize,
        PROTO_ICMPV6 => 42usize,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust_ipv6_addr_bytes(current, old_addr, new_addr);
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

pub(in crate::afxdp) fn recompute_l4_checksum_ipv4(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    zero_offset: bool,
) -> Option<()> {
    let segment = packet.get(ihl..)?;
    match protocol {
        PROTO_TCP => {
            if segment.len() < 20 {
                return None;
            }
            packet.get_mut(ihl + 16..ihl + 18)?.copy_from_slice(&[0, 0]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let sum = checksum16_ipv4(src, dst, protocol, packet.get(ihl..)?);
            packet
                .get_mut(ihl + 16..ihl + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if segment.len() < 8 {
                return None;
            }
            packet.get_mut(ihl + 6..ihl + 8)?.copy_from_slice(&[0, 0]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let sum = checksum16_ipv4(src, dst, protocol, packet.get(ihl..)?);
            let sum = if zero_offset && sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(ihl + 6..ihl + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

pub(in crate::afxdp) fn recompute_l4_checksum_ipv6(packet: &mut [u8], protocol: u8) -> Option<()> {
    let payload = packet.get(40..)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    match protocol {
        PROTO_TCP => {
            if payload.len() < 20 {
                return None;
            }
            packet.get_mut(40 + 16..40 + 18)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_TCP, packet.get(40..)?);
            packet
                .get_mut(40 + 16..40 + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if payload.len() < 8 {
                return None;
            }
            packet.get_mut(40 + 6..40 + 8)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_UDP, packet.get(40..)?);
            let sum = if sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(40 + 6..40 + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if payload.len() < 4 {
                return None;
            }
            packet.get_mut(40 + 2..40 + 4)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_ICMPV6, packet.get(40..)?);
            packet
                .get_mut(40 + 2..40 + 4)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

#[cfg(test)]
mod simd_checksum_tests {
    use super::*;

    /// Reference scalar implementation for differential testing — bypasses
    /// the runtime AVX2 detection in `checksum16_add_bytes` and goes straight
    /// to the scalar path. Without this helper the tests would only verify
    /// `simd == simd` on AVX2 hosts (the SIMD path is the live one).
    fn add_bytes_scalar_only(sum: u32, bytes: &[u8]) -> u32 {
        super::checksum16_add_bytes_scalar(sum, bytes)
    }

    fn check_eq_for(label: &str, bytes: &[u8]) {
        // Differential: live `checksum16_add_bytes` (which may take the
        // AVX2 path) MUST agree with the scalar reference for BOTH the
        // raw u32 partial sum AND the folded 16-bit checksum. Comparing
        // only the folded value would miss a class of accumulator bugs
        // where SIMD and scalar differ by a value invariant under
        // 16-bit fold (e.g. an extra 0x1_0000 that gets absorbed).
        for &start_sum in &[0u32, 0x1234, 0xffff, 0x1_0000, 0xffff_0000] {
            let live = checksum16_add_bytes(start_sum, bytes);
            let scalar = add_bytes_scalar_only(start_sum, bytes);
            assert_eq!(
                live, scalar,
                "label={label} len={} start={:#x}: raw partial live=0x{:08x} scalar=0x{:08x}",
                bytes.len(),
                start_sum,
                live,
                scalar,
            );
            assert_eq!(
                checksum16_finish(live),
                checksum16_finish(scalar),
                "label={label} len={} start={:#x}: folded live=0x{:04x} scalar=0x{:04x}",
                bytes.len(),
                start_sum,
                checksum16_finish(live),
                checksum16_finish(scalar),
            );
        }
    }

    #[test]
    fn simd_matches_scalar_at_chunk_boundary_sizes() {
        // Sizes around AVX2 32-byte chunk boundaries: 0, 1, 2, 31, 32,
        // 33, 63, 64, 65 — covers no-chunk, exact-chunk, chunk+remainder,
        // and odd-byte tail.
        for len in [0, 1, 2, 16, 31, 32, 33, 63, 64, 65, 128, 129] {
            let pattern: Vec<u8> = (0..len).map(|i| ((i * 31 + 17) & 0xff) as u8).collect();
            check_eq_for("pattern", &pattern);
        }
    }

    #[test]
    fn simd_matches_scalar_for_realistic_packet_sizes() {
        // 1500 (typical Ethernet MTU), 9000 (jumbo), 64000 (max u16-ish).
        for len in [1500usize, 9000, 64000] {
            let pattern: Vec<u8> = (0..len)
                .map(|i| ((i.wrapping_mul(2654435761)) & 0xff) as u8)
                .collect();
            check_eq_for("realistic", &pattern);
        }
    }

    #[test]
    fn simd_matches_scalar_for_pathological_byte_patterns() {
        // All-zero, all-0xff, alternating, and a pattern that maximizes
        // u16 carry propagation (every word is 0xffff).
        let zeros = vec![0u8; 1024];
        check_eq_for("zeros", &zeros);
        let ones = vec![0xffu8; 1024];
        check_eq_for("ones", &ones);
        let alt: Vec<u8> = (0..1024).map(|i| if i & 1 == 0 { 0xaa } else { 0x55 }).collect();
        check_eq_for("alt", &alt);
        // Every u16 = 0xffff: maximally stressful for carry folding.
        let max_u16 = vec![0xffu8; 256];
        check_eq_for("max_u16", &max_u16);
    }

    #[test]
    fn checksum16_complement_is_invariant() {
        // Sanity: checksum16(bytes) is the one's-complement of
        // checksum16_finish(checksum16_add_bytes(0, bytes)).
        let bytes: Vec<u8> = (0..200u8).collect();
        let direct = checksum16(&bytes);
        let composed = checksum16_finish(checksum16_add_bytes(0, &bytes));
        assert_eq!(direct, composed);
    }
}
