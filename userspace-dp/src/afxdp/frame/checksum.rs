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

/// Address family for the L4 checksum-offset / zero-checksum helpers.
/// Only ever passed as a compile-time-literal at the call sites, so the
/// `#[inline(always)]` helpers fold the match to a constant. Visible to
/// the rest of `frame/` (#1839/#1840): the descriptor v6 arm
/// (`rewrite/ipv6.rs`) and the port-rewrite path (`frame/mod.rs`)
/// route their zero-checksum decisions through the same predicates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// #9069: crate-visible so the NAT64 translator can consult THE rule rather
// than re-implementing the matrix. It was frame-private, which is why a second
// implementation grew outside this module and then diverged.
pub(crate) enum ChecksumFamily {
    V4,
    V6,
}

/// Per-protocol delta of the L4 checksum field from the start of the IPv4
/// L4 header (add the IPv4 IHL to get the packet offset). `None` => the
/// protocol carries no L4 checksum field this module adjusts (IPv4 ICMP,
/// IPv4 protocol 58, unknown) → the caller no-ops with `Some(())`.
///
/// NOTE: there is deliberately NO `PROTO_ICMPV6` arm here. IPv4 packets
/// never carry ICMPv6, and the IPv4 NAT adjust paths call the v4 helpers
/// without protocol filtering, so a stray ICMPv6 arm would adjust at
/// `ihl + 2` for protocol 58 instead of no-op'ing — a live behavior change.
// #4965: re-exported to `frame::mod` so the generic-rewrite preflight
// validator (`validate_generic_rewrite_v4`) derives the L4-checksum-field
// bound from the SAME per-protocol SSOT the mutation half uses — the
// preflight's "is the L4 checksum in bounds" gate can never drift from
// where the checksum adjust actually writes.
#[inline(always)]
pub(in crate::afxdp::frame) fn l4_checksum_field_delta_v4(protocol: u8) -> Option<usize> {
    match protocol {
        PROTO_TCP => Some(16),
        PROTO_UDP => Some(6),
        _ => None,
    }
}

/// Per-protocol delta of the L4 checksum field from the start of the IPv6
/// L4 header (add the fixed 40-byte IPv6 header to get the packet offset).
/// `None` => no adjusted L4 checksum field (unknown) → caller no-ops.
// #4965: re-exported alongside the v4 helper (same SSOT rationale) for the
// generic-rewrite preflight's v6 L4-checksum bound.
#[inline(always)]
pub(in crate::afxdp::frame) fn l4_checksum_field_delta_v6(protocol: u8) -> Option<usize> {
    match protocol {
        PROTO_TCP => Some(16),
        PROTO_UDP => Some(6),
        PROTO_ICMPV6 => Some(2),
        _ => None,
    }
}

/// Whether a received UDP datagram carries an OPTIONAL checksum that
/// may legitimately be 0x0000 (RFC 768 — the checksum is optional for
/// IPv4 UDP and 0x0000 means "no checksum was computed"). The
/// incremental-adjust path must NOT fabricate a checksum for such a
/// packet, so it skips. The skip is IPv4-only (#1840): RFC 8200 §8.1
/// makes the UDP checksum mandatory for IPv6, so a v6 UDP 0x0000 is
/// malformed input and the adjusters update it like any other value.
///
/// This is a DISTINCT concept from `adjust_zero_checksum_illegal` (which
/// canonicalizes a freshly-computed 0x0000 to 0xFFFF). It is intentionally
/// kept as its own predicate so the two RFC concepts are not conflated.
#[inline(always)]
pub(in crate::afxdp::frame) fn l4_udp_checksum_optional(
    protocol: u8,
    family: ChecksumFamily,
) -> bool {
    family == ChecksumFamily::V4 && protocol == PROTO_UDP
}

/// Map the metadata `addr_family` byte onto a `ChecksumFamily`. `None`
/// for any other family — callers treat that as "nothing to adjust"
/// (unreachable in practice: `frame_l4_offset` already fails other
/// families before any port work happens).
#[inline(always)]
pub(in crate::afxdp::frame) fn checksum_family_of(addr_family: u8) -> Option<ChecksumFamily> {
    match addr_family as i32 {
        libc::AF_INET => Some(ChecksumFamily::V4),
        libc::AF_INET6 => Some(ChecksumFamily::V6),
        _ => None,
    }
}

/// Whether a freshly-computed L4 checksum of 0x0000 must be canonicalized
/// to 0xFFFF. IPv4: UDP only. IPv6: UDP and ICMPv6 (RFC 2460 §8.1 /
/// RFC 8200 forbid a transmitted 0x0000 for both, since 0x0000 has the
/// "no checksum" meaning for IPv4 UDP).
///
/// SCOPE (#1839): this is the single source of truth for the
/// computed-zero rule across the incremental `adjust_l4_checksum_*`
/// sites, the descriptor fast path (`rewrite/ipv6.rs`), the port
/// adjust (`adjust_l4_checksum_port`), and — by matching arithmetic —
/// `recompute_l4_checksum_ipv6` (UDP and ICMPv6 arms canonicalize; TCP
/// does not: a computed TCP 0x0000 is valid on the wire and matches v4
/// TCP behavior).
#[inline(always)]
pub(crate) fn adjust_zero_checksum_illegal(
    protocol: u8,
    family: ChecksumFamily,
) -> bool {
    match family {
        ChecksumFamily::V4 => protocol == PROTO_UDP,
        ChecksumFamily::V6 => matches!(protocol, PROTO_UDP | PROTO_ICMPV6),
    }
}

pub(crate) fn checksum16(bytes: &[u8]) -> u16 {
    checksum16_finish(checksum16_add_bytes(0, bytes))
}

pub(crate) fn checksum16_add_bytes(sum: u32, bytes: &[u8]) -> u32 {
    // #1440: short-circuit for sub-chunk inputs. The AVX2 path
    // below uses `chunks_exact(32)`; for slices < 32 bytes (e.g.
    // 20-byte IPv4 headers, 8-byte UDP headers, 8-byte TCP option
    // fragments) the chunked loop iterates zero times and the input
    // would go through the scalar remainder anyway — but the SIMD
    // entry still pays the `is_x86_feature_detected!` query, the
    // YMM accumulator init, the per-pair-swap mask materialization,
    // and the horizontal sum. Bypass for known-small inputs.
    // Bit-identical to the unguarded path because both paths
    // ultimately fall through to `checksum16_add_bytes_scalar` for
    // sub-32-byte inputs; the differential SIMD-vs-scalar test in
    // this file already proves bit-identity of the two paths.
    if bytes.len() < 32 {
        return checksum16_add_bytes_scalar(sum, bytes);
    }
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

pub(crate) fn checksum16_finish(mut sum: u32) -> u16 {
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

/// Narrow a byte length into a 16-bit on-the-wire length field — an
/// IPv4/TCP/UDP pseudo-header length, an IPv4 `total_length`, or an IPv6
/// `payload_length`. Saturates at `u16::MAX` instead of the historical bare
/// `as u16`, which silently WRAPPED (65536 → 0), forging a plausible but
/// wrong length.
///
/// Defense-in-depth (#5765). Every frame the AF_XDP dataplane touches comes
/// from a single UMEM frame (a few KiB), and an IPv4 `total_length` is itself
/// a 16-bit field, so `len` is always ≤ `u16::MAX` today and the result is
/// byte-identical to the old cast — a legitimate packet checksums the same.
/// Only a future frame-size increase / GRO super-frame / IPv6-jumbogram
/// reassembly that presented a >64 KiB length would differ, and there
/// saturating keeps the value deterministic and non-wrapping (the checksum is
/// still "wrong" for such a frame — the field is 16-bit on the wire — but can
/// never masquerade as a small valid length). Mirrors the validated-narrowing
/// newtype idiom in `afxdp/forwarding_build/validated.rs`
/// (`VlanId`/`TunnelTtl`/`QueueId`).
#[inline]
pub(in crate::afxdp) fn saturate_len16(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

pub(in crate::afxdp) fn checksum16_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum16_add_bytes(sum, &src.octets());
    sum = checksum16_add_bytes(sum, &dst.octets());
    sum = checksum16_add_bytes(sum, &[0, protocol]);
    sum = checksum16_add_bytes(sum, &saturate_len16(payload.len()).to_be_bytes());
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
    let delta = match l4_checksum_field_delta_v4(protocol) {
        Some(d) => d,
        None => return Some(()),
    };
    let checksum_offset = ihl.checked_add(delta)?;
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    if adjust_zero_checksum_illegal(protocol, ChecksumFamily::V4) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

// The IPv6 dead trio (`adjust_l4_checksum_ipv6`, `_src`, `_dst`) was
// deleted in #1838: all were `#[allow(dead_code)]` with zero non-test
// callers, and threading the ext-aware `rel_l4` offset through helpers
// nobody calls would have been pure noise. `ipv6_words` went with them
// (its only remaining caller was the deleted trio). The live v6
// adjusters are `adjust_l4_checksum_ipv6_words` and
// `adjust_l4_checksum_ipv6_addr_bytes` below.

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
    let delta = match l4_checksum_field_delta_v4(protocol) {
        Some(d) => d,
        None => return Some(()),
    };
    let checksum_offset = ihl.checked_add(delta)?;
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    if l4_udp_checksum_optional(protocol, ChecksumFamily::V4) && current == 0 {
        return Some(());
    }
    let updated = checksum16_adjust(current, old_words, new_words);
    let updated = if adjust_zero_checksum_illegal(protocol, ChecksumFamily::V4) && updated == 0 {
        0xffff
    } else {
        updated
    };
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

/// Incremental v6 L4 checksum adjust for a word-list delta. `rel_l4`
/// is the L4 offset relative to the IPv6 header start (40 for the
/// ext-free common case; the caller's ext-aware walk result otherwise
/// — #1838). The checksum field sits at `rel_l4 + {16,6,2}`.
pub(in crate::afxdp) fn adjust_l4_checksum_ipv6_words(
    packet: &mut [u8],
    rel_l4: usize,
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let delta = match l4_checksum_field_delta_v6(protocol) {
        Some(d) => d,
        None => return Some(()),
    };
    let checksum_offset = rel_l4.checked_add(delta)?;
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, old_words, new_words);
    if adjust_zero_checksum_illegal(protocol, ChecksumFamily::V6) && updated == 0 {
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
    rel_l4: usize,
    protocol: u8,
    old_addr: &[u8; 16],
    new_addr: &[u8; 16],
) -> Option<()> {
    let delta = match l4_checksum_field_delta_v6(protocol) {
        Some(d) => d,
        None => return Some(()),
    };
    // rel_l4 + {16,6,2}; with rel_l4 == 40 (no ext headers) this
    // reproduces the previous absolute constants 56/46/42 (#1838).
    let checksum_offset = rel_l4.checked_add(delta)?;
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust_ipv6_addr_bytes(current, old_addr, new_addr);
    if adjust_zero_checksum_illegal(protocol, ChecksumFamily::V6) && updated == 0 {
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

/// Full L4 checksum recompute for an IPv6 packet. `rel_l4` is the L4
/// offset relative to the IPv6 header start (40 when no extension
/// headers; the caller's ext-aware walk result otherwise — #1838).
/// The pseudo-header upper-layer length is `packet.len() - rel_l4`
/// and the Next Header value is `protocol` (the final L4 protocol) —
/// exactly what RFC 8200 §8.1 prescribes when extension headers are
/// present.
pub(in crate::afxdp) fn recompute_l4_checksum_ipv6(
    packet: &mut [u8],
    rel_l4: usize,
    protocol: u8,
) -> Option<()> {
    let payload = packet.get(rel_l4..)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    match protocol {
        PROTO_TCP => {
            if payload.len() < 20 {
                return None;
            }
            packet
                .get_mut(rel_l4 + 16..rel_l4 + 18)?
                .copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_TCP, packet.get(rel_l4..)?);
            packet
                .get_mut(rel_l4 + 16..rel_l4 + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if payload.len() < 8 {
                return None;
            }
            packet
                .get_mut(rel_l4 + 6..rel_l4 + 8)?
                .copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_UDP, packet.get(rel_l4..)?);
            let sum = if sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(rel_l4 + 6..rel_l4 + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if payload.len() < 4 {
                return None;
            }
            packet
                .get_mut(rel_l4 + 2..rel_l4 + 4)?
                .copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_ICMPV6, packet.get(rel_l4..)?);
            // #1839: canonicalize computed 0x0000 → 0xFFFF, completing
            // the single coherent v6 matrix with the incremental
            // adjusters (`adjust_zero_checksum_illegal` includes
            // ICMPv6 for V6).
            let sum = if sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(rel_l4 + 2..rel_l4 + 4)?
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

#[cfg(test)]
mod l4_offset_helper_tests {
    use super::*;
    use crate::afxdp::PROTO_ICMP;

    #[test]
    fn v4_field_delta_table() {
        // IPv4: TCP +16, UDP +6. No ICMPv6 arm — IPv4 packets never carry
        // ICMPv6 and the IPv4 NAT adjust paths call the v4 helper without
        // protocol filtering, so PROTO_ICMPV6 MUST fall through to None
        // (no-op), not produce ihl+2.
        assert_eq!(l4_checksum_field_delta_v4(PROTO_TCP), Some(16));
        assert_eq!(l4_checksum_field_delta_v4(PROTO_UDP), Some(6));
        assert_eq!(l4_checksum_field_delta_v4(PROTO_ICMP), None);
        assert_eq!(l4_checksum_field_delta_v4(PROTO_ICMPV6), None);
        assert_eq!(l4_checksum_field_delta_v4(0), None);
    }

    #[test]
    fn v6_field_delta_table() {
        // IPv6: TCP +16, UDP +6, ICMPv6 +2.
        assert_eq!(l4_checksum_field_delta_v6(PROTO_TCP), Some(16));
        assert_eq!(l4_checksum_field_delta_v6(PROTO_UDP), Some(6));
        assert_eq!(l4_checksum_field_delta_v6(PROTO_ICMPV6), Some(2));
        assert_eq!(l4_checksum_field_delta_v6(PROTO_ICMP), None);
        assert_eq!(l4_checksum_field_delta_v6(0), None);
    }

    #[test]
    fn v6_addr_bytes_offsets_match_old_constants() {
        // adjust_l4_checksum_ipv6_addr_bytes previously hard-coded
        // 56/46/42; now derived as 40 + delta. Confirm bit-identical.
        for (proto, want) in [(PROTO_TCP, 56usize), (PROTO_UDP, 46), (PROTO_ICMPV6, 42)] {
            let delta = l4_checksum_field_delta_v6(proto).expect("v6 proto has delta");
            assert_eq!(40usize + delta, want, "proto {proto}");
        }
    }

    #[test]
    fn udp_checksum_optional_is_v4_udp_only() {
        // #1840 family table: the RFC 768 "no checksum" skip exists
        // for IPv4 UDP ONLY. RFC 8200 §8.1 makes the checksum
        // mandatory for IPv6 UDP, so no v6 protocol may skip.
        assert!(l4_udp_checksum_optional(PROTO_UDP, ChecksumFamily::V4));
        assert!(!l4_udp_checksum_optional(PROTO_TCP, ChecksumFamily::V4));
        assert!(!l4_udp_checksum_optional(PROTO_ICMPV6, ChecksumFamily::V4));
        assert!(!l4_udp_checksum_optional(PROTO_ICMP, ChecksumFamily::V4));
        assert!(!l4_udp_checksum_optional(PROTO_UDP, ChecksumFamily::V6));
        assert!(!l4_udp_checksum_optional(PROTO_TCP, ChecksumFamily::V6));
        assert!(!l4_udp_checksum_optional(PROTO_ICMPV6, ChecksumFamily::V6));
    }

    #[test]
    fn checksum_family_of_maps_af_constants() {
        assert_eq!(
            checksum_family_of(libc::AF_INET as u8),
            Some(ChecksumFamily::V4)
        );
        assert_eq!(
            checksum_family_of(libc::AF_INET6 as u8),
            Some(ChecksumFamily::V6)
        );
        assert_eq!(checksum_family_of(0), None);
        assert_eq!(checksum_family_of(255), None);
    }

    #[test]
    fn zero_checksum_illegal_preserves_v4_v6_asymmetry() {
        // The #1669 trap: IPv4 canonicalizes UDP zero only; IPv6
        // canonicalizes BOTH UDP and ICMPv6 zero. A blind unify would
        // break ICMPv6.
        // IPv4: UDP only.
        assert!(adjust_zero_checksum_illegal(PROTO_UDP, ChecksumFamily::V4));
        assert!(!adjust_zero_checksum_illegal(PROTO_TCP, ChecksumFamily::V4));
        assert!(!adjust_zero_checksum_illegal(
            PROTO_ICMPV6,
            ChecksumFamily::V4
        ));
        assert!(!adjust_zero_checksum_illegal(
            PROTO_ICMP,
            ChecksumFamily::V4
        ));
        // IPv6: UDP and ICMPv6.
        assert!(adjust_zero_checksum_illegal(PROTO_UDP, ChecksumFamily::V6));
        assert!(adjust_zero_checksum_illegal(
            PROTO_ICMPV6,
            ChecksumFamily::V6
        ));
        assert!(!adjust_zero_checksum_illegal(PROTO_TCP, ChecksumFamily::V6));
        assert!(!adjust_zero_checksum_illegal(
            PROTO_ICMP,
            ChecksumFamily::V6
        ));
    }

    /// Build a minimal IPv4 + L4 frame (no Ethernet) for adjust tests.
    /// `proto` goes in the IPv4 protocol byte; src/dst at the usual
    /// offsets. Returns a 60-byte buffer (20 IHL + 40 payload room).
    fn ipv4_frame(proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; 60];
        p[0] = 0x45; // version 4, IHL 5
        p[9] = proto;
        // src 10.0.0.1, dst 10.0.0.2
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p
    }

    #[test]
    fn ipv4_proto_58_is_noop_not_adjusted() {
        // Regression guard (Codex r2 #2): an IPv4 packet with protocol 58
        // (ICMPv6 number) must hit the helper's None arm and no-op via
        // Some(()), NOT adjust the bytes at ihl+2. Verify the packet is
        // untouched.
        let mut p = ipv4_frame(PROTO_ICMPV6);
        let before = p.clone();
        let r = adjust_l4_checksum_ipv4(
            &mut p,
            20,
            PROTO_ICMPV6,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 1, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 2, 2, 2),
        );
        assert_eq!(r, Some(()));
        assert_eq!(p, before, "IPv4 proto-58 must not be adjusted");

        // Same for the *_words and *_src/_dst entry points.
        let mut p = ipv4_frame(PROTO_ICMPV6);
        let before = p.clone();
        assert_eq!(
            adjust_l4_checksum_ipv4_src(
                &mut p,
                20,
                PROTO_ICMPV6,
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 1, 1, 1),
            ),
            Some(())
        );
        assert_eq!(p, before, "IPv4 proto-58 (_src) must not be adjusted");
    }

    #[test]
    fn ipv4_recognized_proto_overflow_returns_none() {
        // Regression guard (Codex r2 #1): a recognized protocol (TCP/UDP)
        // with an IHL so large that ihl.checked_add(delta) overflows usize
        // must return None (failure), NOT Some(()) (no-op success). The
        // helper returns Some(delta) for the recognized proto; the
        // overflow is caught by the call-site `?` on checked_add.
        let mut p = ipv4_frame(PROTO_TCP);
        assert_eq!(
            adjust_l4_checksum_ipv4(
                &mut p,
                usize::MAX,
                PROTO_TCP,
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 1, 1, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 2, 2, 2),
            ),
            None,
            "recognized-proto overflow must propagate as None failure"
        );
        // Unsupported proto with the same overflowing ihl must still no-op
        // (it returns Some(()) before ever touching checked_add).
        let mut p = ipv4_frame(PROTO_ICMP);
        assert_eq!(
            adjust_l4_checksum_ipv4(
                &mut p,
                usize::MAX,
                PROTO_ICMP,
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 1, 1, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 2, 2, 2),
            ),
            Some(()),
            "unsupported proto must no-op regardless of ihl"
        );
    }

    #[test]
    fn ipv6_icmpv6_zero_canonicalizes_to_ffff() {
        // The #1669-trap end-to-end check: an ICMPv6 packet whose adjusted
        // checksum computes to 0 must be written as 0xFFFF, not 0x0000.
        // Construct an IPv6 frame and choose the stored checksum + address
        // delta so the incremental adjust lands on 0.
        //
        // adjust_l4_checksum_ipv6_words computes:
        //   updated = checksum16_adjust(current, old_words, new_words)
        // We want updated == 0. Pick old_words == new_words so the adjust
        // is identity: updated = current. Then set the stored checksum so
        // that the "current" read at offset 42 is 0 — but a stored 0 read
        // would already be 0 and identity-adjust keeps it 0, triggering
        // the canonicalization to 0xFFFF.
        let mut p = vec![0u8; 60];
        p[6] = PROTO_ICMPV6; // next-header
        // ICMPv6 checksum field is at 40 + 2 = 42. Start it at 0.
        p[42] = 0;
        p[43] = 0;
        let same = ipv6_words_from_octets(Ipv6Addr::LOCALHOST.octets());
        let r = adjust_l4_checksum_ipv6_words(&mut p, 40, PROTO_ICMPV6, &same, &same);
        assert_eq!(r, Some(()));
        // current=0, identity adjust -> 0, canonicalized -> 0xffff.
        assert_eq!(
            u16::from_be_bytes([p[42], p[43]]),
            0xffff,
            "ICMPv6 computed-zero must canonicalize to 0xffff"
        );
    }

    #[test]
    fn recompute_ipv6_icmpv6_computed_zero_canonicalizes_to_ffff() {
        // #1839 rider: recompute_l4_checksum_ipv6's ICMPv6 arm
        // canonicalizes a computed 0x0000 to 0xFFFF, completing the
        // v6 matrix with the incremental adjusters. Two-pass balancing:
        // stored C1 = !fold(S), so a balancing word of C1 makes
        // fold(S + C1) = 0xFFFF → raw computed checksum 0.
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&8u16.to_be_bytes()); // payload len
        p[6] = PROTO_ICMPV6;
        p[7] = 64;
        // src/dst stay all-zero; ICMPv6 echo header at 40..48 with the
        // balancing word in the last two bytes.
        p[40] = 128;
        assert_eq!(recompute_l4_checksum_ipv6(&mut p, 40, PROTO_ICMPV6), Some(()));
        let c1 = u16::from_be_bytes([p[42], p[43]]);
        p[46..48].copy_from_slice(&c1.to_be_bytes());
        assert_eq!(recompute_l4_checksum_ipv6(&mut p, 40, PROTO_ICMPV6), Some(()));
        // Raw sum is genuinely zero (receiver-style verify with the
        // field zeroed)…
        let mut zeroed = p[40..].to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        assert_eq!(
            checksum16_ipv6(
                Ipv6Addr::UNSPECIFIED,
                Ipv6Addr::UNSPECIFIED,
                PROTO_ICMPV6,
                &zeroed
            ),
            0,
            "balancing word must force the raw computed checksum to zero"
        );
        // …and the stored field is the canonical 0xFFFF encoding.
        assert_eq!(
            u16::from_be_bytes([p[42], p[43]]),
            0xffff,
            "ICMPv6 recompute must canonicalize computed-zero to 0xFFFF"
        );
    }

    #[test]
    fn ipv4_tcp_zero_not_canonicalized() {
        // Counterpart: IPv4 TCP computing to 0 is left as 0 (only IPv4 UDP
        // canonicalizes on v4). Identity-adjust a stored-0 TCP checksum.
        let mut p = ipv4_frame(PROTO_TCP);
        // TCP checksum at ihl + 16 = 36. Start at 0.
        p[36] = 0;
        p[37] = 0;
        let same = ipv4_words(Ipv4Addr::new(10, 0, 0, 1));
        let r = adjust_l4_checksum_ipv4_words(&mut p, 20, PROTO_TCP, &same, &same);
        assert_eq!(r, Some(()));
        assert_eq!(
            u16::from_be_bytes([p[36], p[37]]),
            0,
            "IPv4 TCP computed-zero must NOT canonicalize"
        );
    }
}

// #5765: defense-in-depth for the 16-bit on-the-wire length narrowing.
// These sites are unreachable-for-wrap in production (an AF_XDP frame is
// bounded by the UMEM frame size and an IPv4 total_length is itself a
// 16-bit field), so the tests construct a synthetic >64 KiB length
// DIRECTLY at the function boundary — bypassing that upstream bound — to
// prove the hardened path SATURATES rather than silently WRAPS.
#[cfg(test)]
mod len16_hardening_tests {
    use super::*;

    #[test]
    fn saturate_len16_passes_through_in_range_and_saturates_above() {
        // The valid path is byte-identical to the old `as u16` cast.
        assert_eq!(saturate_len16(0), 0);
        assert_eq!(saturate_len16(1000), 1000);
        assert_eq!(saturate_len16(u16::MAX as usize), u16::MAX);
        // The >64K path SATURATES to u16::MAX — NOT the wrapped value the
        // bare `as u16` would produce. Neutralizing the helper body to
        // `len as u16` makes each of these observe the wrap and go RED:
        //   65536 -> 0, 65540 -> 4, 131072 -> 0.
        assert_eq!(saturate_len16(65536), u16::MAX, "65536 must saturate, not wrap to 0");
        assert_eq!(saturate_len16(65540), u16::MAX, "65540 must saturate, not wrap to 4");
        assert_eq!(saturate_len16(131072), u16::MAX, "131072 must saturate, not wrap to 0");
    }

    // Reference pseudo-header checksum for `checksum16_ipv4`, computed with
    // an explicit 16-bit length field so the test controls wrap vs saturate
    // independently of the function under test.
    fn ipv4_pseudo_checksum_with_len(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        len_field: u16,
        payload: &[u8],
    ) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + payload.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(&len_field.to_be_bytes());
        pseudo.extend_from_slice(payload);
        checksum16(&pseudo)
    }

    #[test]
    fn checksum16_ipv4_in_range_is_byte_identical() {
        // Regression guard: a legitimate (<64K) L4 segment must checksum
        // exactly as before — the pseudo-header carries the true length.
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 2);
        let payload: Vec<u8> = (0..1400u32).map(|i| (i.wrapping_mul(31) & 0xff) as u8).collect();
        let got = checksum16_ipv4(src, dst, PROTO_TCP, &payload);
        let want =
            ipv4_pseudo_checksum_with_len(src, dst, PROTO_TCP, payload.len() as u16, &payload);
        assert_eq!(got, want, "in-range checksum must be byte-identical to the true-length reference");
    }

    #[test]
    fn checksum16_ipv4_saturates_length_above_u16() {
        // A 65540-byte payload: the true length overflows the 16-bit
        // pseudo-header field. The hardened code narrows via saturate_len16
        // -> 0xffff; the pre-fix `payload.len() as u16` wrapped 65540 -> 4.
        // All-zero payload keeps the payload's own checksum contribution 0,
        // so the two computations differ ONLY in the length word — making
        // the wrap-vs-saturate divergence sharp and unambiguous. (65540 not
        // 65536: a 65536 wrap yields the length word 0x0000, which is the
        // one's-complement negative-zero of the saturated 0xffff and would
        // fold to the SAME checksum — hiding the very difference under test.)
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 2);
        let payload = vec![0u8; 65540];
        let got = checksum16_ipv4(src, dst, PROTO_TCP, &payload);

        // saturate_len16(65540) == 0xffff; the pre-fix `65540 as u16` == 4.
        let saturated =
            ipv4_pseudo_checksum_with_len(src, dst, PROTO_TCP, u16::MAX, &payload);
        let wrapped =
            ipv4_pseudo_checksum_with_len(src, dst, PROTO_TCP, payload.len() as u16, &payload);

        assert_ne!(
            saturated, wrapped,
            "test setup invariant: saturated(0xffff) and wrapped(4) length words must diverge"
        );
        assert_eq!(
            got, saturated,
            "checksum16_ipv4 must use a SATURATED 16-bit pseudo-header length for a >64K payload"
        );
        assert_ne!(
            got, wrapped,
            "checksum16_ipv4 must NOT silently wrap the length (65540 -> 4)"
        );
    }
}
