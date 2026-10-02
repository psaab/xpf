//! WireGuard MSS-clamp arithmetic.
//!
//! Lives separately from `forwarding/mod.rs::native_gre_tcp_mss`
//! because the byte overhead differs from GRE and because reusing
//! the GRE function (as PR #1492 did) was a 48-byte error.
//!
//! Per-packet overhead, end-to-end, from inner-TCP payload back
//! out to the wire:
//!
//! ```text
//!   inner TCP header      20
//!   inner IPv4 header     20    (or 40 for v6)
//!   ----------------
//!   inner IP packet       40 (v4) / 60 (v6)
//!
//!   WG data record:
//!     type+reserved        4
//!     receiver_index       4
//!     counter              8
//!     §5.4.6 padding       0..15  (round inner up to 16-byte multiple)
//!     Poly1305 tag        16
//!   ----------------
//!   WG transport         32..47
//!
//!   outer UDP             8
//!   outer IP             20 (v4) / 40 (v6)
//!   ----------------
//!   outer encap          28 (v4) / 48 (v6)
//! ```
//!
//! Maximum permitted inner-TCP MSS at MTU `M` for an IPv4 outer
//! tunnel carrying an IPv4 inner TCP segment, accounting for the
//! worst-case 15 bytes of WG §5.4.6 padding that the encap side
//! will add to a non-16-aligned inner length:
//!
//! ```text
//!   max_inner_tcp_payload = M - outer_encap_v4 - wg_transport
//!                             - max_padding
//!                             - inner_ip_v4 - inner_tcp_header
//!                         = M - 28 - 32 - 15 - 20 - 20
//!                         = M - 115
//! ```
//!
//! For a 1500-byte outer link MTU, this gives MSS = 1385. (Compare
//! to vanilla TCP-over-Ethernet at MSS = 1460 — the 75-byte delta
//! is the WG + padding + outer-IP+UDP overhead.)
//!
//! The 15-byte subtraction is conservative: a real inner segment
//! of MSS bytes will need padding only if the resulting inner IP
//! packet length is not a multiple of 16. Subtracting the worst
//! case keeps the outer frame at or under MTU regardless of how
//! the inner payload length lands, which is the property a sender
//! MUST be able to advertise. Carrying tight per-packet math here
//! would require knowing the exact inner-IP+TCP+payload length at
//! TCP-option-rewrite time, which we don't.

use super::{WG_OVERHEAD_V4, WG_OVERHEAD_V6};

/// Worst-case bytes of WG §5.4.6 padding (round inner-IP packet up
/// to a 16-byte multiple before AEAD).
const WG_MAX_PADDING: usize = 15;

/// Inner-TCP MSS for the given outer-link MTU and inner+outer IP
/// families. Returns 0 if `mtu` is too small to accommodate any
/// inner TCP payload (in which case the caller MUST NOT advertise
/// the MSS — leave the TCP option as-is).
///
/// `outer_family` is one of `libc::AF_INET` or `libc::AF_INET6`;
/// `inner_family` ditto. The cross-family combos (v4-inner in
/// v6-outer, etc.) are valid: the WG inner payload is an IP packet
/// of whichever family the originator chose.
///
/// The returned MSS accounts for the worst-case 15 bytes of WG
/// §5.4.6 transport-padding that the encap side may add to align
/// the inner-IP packet length to a 16-byte multiple — see the
/// module-level doc for the byte-by-byte derivation. The sender
/// advertising this MSS will never produce an outer frame that
/// exceeds `mtu`, regardless of how the inner segment's total
/// length aligns modulo 16.
pub(crate) fn wg_tcp_mss(outer_family: i32, inner_family: i32, mtu: usize) -> u16 {
    let outer_overhead = match outer_family {
        x if x == libc::AF_INET => WG_OVERHEAD_V4,
        x if x == libc::AF_INET6 => WG_OVERHEAD_V6,
        _ => return 0,
    };
    let inner_ip_header = match inner_family {
        x if x == libc::AF_INET => 20usize,
        x if x == libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let inner_tcp_header = 20usize;
    mtu.checked_sub(outer_overhead + WG_MAX_PADDING + inner_ip_header + inner_tcp_header)
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0)
}

/// Clamp the outer-derived MSS by an independently selected overlay route MTU.
/// A zero route MTU leaves the existing value untouched; a zero WG inner
/// budget remains zero instead of being replaced by the route budget.
pub(crate) fn wg_tcp_mss_with_route_mtu(
    outer_family: i32,
    inner_family: i32,
    outer_mtu: usize,
    route_mtu: usize,
) -> u16 {
    let mss = wg_tcp_mss(outer_family, inner_family, outer_mtu);
    if route_mtu == 0 {
        return mss;
    }
    let inner_mtu = wg_inner_mtu(outer_family, outer_mtu);
    if inner_mtu == 0 {
        return 0;
    }
    let capped_inner_mtu = inner_mtu.min(route_mtu);
    let inner_ip_header = match inner_family {
        x if x == libc::AF_INET => 20usize,
        x if x == libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let route_max_mss = capped_inner_mtu
        .checked_sub(inner_ip_header + 20)
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0);
    mss.min(route_max_mss)
}

/// #2330: the pad-aware WireGuard INNER-IP MTU for the given outer-link MTU
/// and outer IP family — the largest inner IP packet length whose encapped
/// outer frame is guaranteed to fit `outer_mtu`, accounting for the
/// worst-case 15 bytes of WG §5.4.6 transport-padding the encap side may
/// add. This is the inverse of the encap MTU guard
/// (`frame::wg::wg_encapped_size`): `wg_encapped_size(inner, outer_v6) <=
/// outer_mtu` iff `inner <= wg_inner_mtu(outer_family, outer_mtu)` for a
/// 16-aligned inner (the conservative `WG_MAX_PADDING` subtraction makes the
/// bound hold for ANY inner length).
///
/// The advertised value is what a post-transform Packet-Too-Big / Frag-
/// Needed back to the INNER source must carry so the inner sender shrinks
/// its packets below the WG encap drop threshold (`encap_mtu_drops`).
/// Returns 0 when `outer_mtu` is too small to carry any inner payload
/// (fail-open: never advertise a nonsensical inner MTU).
///
/// `outer_family` is the family of the WG transport (the peer endpoint
/// address), one of `libc::AF_INET` / `libc::AF_INET6`. The inner family is
/// irrelevant to the encap overhead (the WG record wraps the raw inner IP
/// packet whole), so unlike `wg_tcp_mss` no inner-family argument is needed.
///
/// #2457: the result is additionally clamped to the engine's hard ceiling
/// `engine::WG_ENGINE_MAX_INNER_MTU` (= `PADDED_PLAINTEXT_MAX` = 4096) — the
/// largest inner IP packet the WG engine can encrypt in one transport
/// message. On a jumbo outer link the outer-derived budget
/// (`outer_mtu - overhead - pad`) exceeds what the engine can encap, so a
/// sender that honored an UNCLAMPED advertised inner MTU would still have
/// its oversized packets dropped at the encap `padded_len >
/// PADDED_PLAINTEXT_MAX` guard (`encap_mtu_drops`). Clamping here keeps the
/// advertised / segmentation inner MTU at or below the encryptable maximum,
/// so what we advertise is what the engine actually accepts.
pub(crate) fn wg_inner_mtu(outer_family: i32, outer_mtu: usize) -> usize {
    let outer_overhead = match outer_family {
        x if x == libc::AF_INET => WG_OVERHEAD_V4,
        x if x == libc::AF_INET6 => WG_OVERHEAD_V6,
        _ => return 0,
    };
    let outer_derived = outer_mtu
        .checked_sub(outer_overhead + WG_MAX_PADDING)
        .unwrap_or(0);
    outer_derived.min(super::engine::WG_ENGINE_MAX_INNER_MTU)
}

#[cfg(test)]
mod mss_tests {
    use super::*;

    // The numbers below come from the table at the top of this file.
    // If they change, the table is the source of truth — update it
    // first.

    #[test]
    fn v4_outer_v4_inner_1500_mtu() {
        // 1500 - 60 (outer encap+WG) - 15 (worst-case padding)
        //      - 20 (inner IPv4) - 20 (TCP) = 1385.
        assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET, 1500), 1385);
    }

    #[test]
    fn v6_outer_v4_inner_1500_mtu() {
        // 1500 - 80 (outer encap+WG) - 15 (worst-case padding)
        //      - 20 (inner IPv4) - 20 (TCP) = 1365.
        assert_eq!(wg_tcp_mss(libc::AF_INET6, libc::AF_INET, 1500), 1365);
    }

    #[test]
    fn route_mtu_caps_the_pad_aware_wg_inner_budget_11687() {
        assert_eq!(
            wg_tcp_mss_with_route_mtu(libc::AF_INET6, libc::AF_INET, 1500, 1400),
            1360
        );
    }

    #[test]
    fn zero_route_mtu_preserves_the_outer_derived_wg_mss_11687() {
        assert_eq!(
            wg_tcp_mss_with_route_mtu(libc::AF_INET6, libc::AF_INET, 1500, 0),
            1365
        );
    }

    #[test]
    fn route_mtu_does_not_replace_a_zero_wg_inner_budget_11687() {
        assert_eq!(
            wg_tcp_mss_with_route_mtu(libc::AF_INET, libc::AF_INET, 50, 1400),
            0
        );
    }

    #[test]
    fn v4_outer_v6_inner_1500_mtu() {
        // 1500 - 60 - 15 (worst-case padding) - 40 (inner IPv6) - 20 (TCP) = 1365.
        assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET6, 1500), 1365);
    }

    #[test]
    fn padded_inner_never_exceeds_mtu() {
        // Property check: at MSS, the worst-case padded inner IP
        // packet plus WG transport plus outer encap must fit in
        // the MTU. This is the contract that justifies the
        // WG_MAX_PADDING subtraction in the MSS formula.
        for mtu in [576usize, 1280, 1500, 9000] {
            for (outer, inner, outer_enc, inner_ip) in [
                (libc::AF_INET, libc::AF_INET, WG_OVERHEAD_V4, 20),
                (libc::AF_INET, libc::AF_INET6, WG_OVERHEAD_V4, 40),
                (libc::AF_INET6, libc::AF_INET, WG_OVERHEAD_V6, 20),
                (libc::AF_INET6, libc::AF_INET6, WG_OVERHEAD_V6, 40),
            ] {
                let mss = wg_tcp_mss(outer, inner, mtu) as usize;
                if mss == 0 {
                    continue;
                }
                // Worst-case inner IP packet at MSS, with the padding
                // rounded up to a 16-byte multiple.
                let inner_total = inner_ip + 20 + mss;
                let padded = (inner_total + 15) & !15;
                // padded inner + WG transport overhead (data header
                // 16 + tag 16 = 32 already inside outer_enc - outer IP
                // and UDP, so we add 0) — outer_enc already includes
                // WG_DATA_HEADER_LEN + POLY1305_TAG_LEN per mod.rs.
                let outer_total = outer_enc + (padded - inner_total) + inner_total;
                // The above simplifies to outer_enc + padded; assert
                // it directly to be unambiguous.
                assert_eq!(outer_total, outer_enc + padded);
                assert!(
                    outer_enc + padded <= mtu,
                    "MTU {mtu} outer={outer} inner={inner}: outer_enc {outer_enc} + padded {padded} = {} > MTU",
                    outer_enc + padded
                );
            }
        }
    }

    #[test]
    fn under_minimum_mtu_returns_zero() {
        // 60-byte outer + 15-byte padding + 40-byte inner IP+TCP =
        // 115 bytes minimum. An MTU of 50 cannot carry any inner
        // TCP payload.
        assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET, 50), 0);
    }

    #[test]
    fn unknown_family_returns_zero() {
        assert_eq!(wg_tcp_mss(99, libc::AF_INET, 1500), 0);
        assert_eq!(wg_tcp_mss(libc::AF_INET, 99, 1500), 0);
    }

    #[test]
    fn matches_byte_breakdown_constant() {
        // Cross-check: the IPv4-outer overhead must equal the
        // constants used by the framing code.
        assert_eq!(WG_OVERHEAD_V4, 60);
        assert_eq!(WG_OVERHEAD_V6, 80);
    }

    #[test]
    fn wg_inner_mtu_v4_outer_pad_aware() {
        // #2330: inner MTU = outer_mtu - WG_OVERHEAD_V4(60) - max_pad(15).
        assert_eq!(wg_inner_mtu(libc::AF_INET, 1500), 1425);
        assert_eq!(wg_inner_mtu(libc::AF_INET, 1400), 1325);
    }

    #[test]
    fn wg_inner_mtu_v6_outer_pad_aware() {
        // WG_OVERHEAD_V6 = 80. 1500 - 80 - 15 = 1405.
        assert_eq!(wg_inner_mtu(libc::AF_INET6, 1500), 1405);
    }

    #[test]
    fn wg_inner_mtu_under_minimum_returns_zero() {
        // Too small to carry any inner payload -> 0 (fail-open).
        assert_eq!(wg_inner_mtu(libc::AF_INET, 50), 0);
    }

    #[test]
    fn wg_inner_mtu_unknown_family_returns_zero() {
        assert_eq!(wg_inner_mtu(99, 1500), 0);
    }

    // #2457 fail-on-revert: the outer-derived inner MTU MUST be clamped to
    // the engine's hard ceiling (PADDED_PLAINTEXT_MAX = 4096), the largest
    // inner IP packet the engine can encrypt. Remove the `.min(...)` clamp
    // in `wg_inner_mtu` and these go RED (the jumbo cases return the
    // unclamped 8925 / 8905).
    #[test]
    fn wg_inner_mtu_jumbo_clamped_to_engine_max() {
        // 9000 - 60 - 15 = 8925 outer-derived, but the engine caps the
        // encryptable inner at 4096 → clamp to 4096.
        assert_eq!(
            wg_inner_mtu(libc::AF_INET, 9000),
            super::super::engine::WG_ENGINE_MAX_INNER_MTU
        );
        assert_eq!(
            super::super::engine::WG_ENGINE_MAX_INNER_MTU,
            4096,
            "engine ceiling drifted — update the #2457 clamp expectations"
        );
        // 9000 - 80 - 15 = 8905 outer-derived (v6 outer), still clamped.
        assert_eq!(
            wg_inner_mtu(libc::AF_INET6, 9000),
            super::super::engine::WG_ENGINE_MAX_INNER_MTU
        );
    }

    #[test]
    fn wg_inner_mtu_below_ceiling_passes_unchanged() {
        // A standard 1500 outer link is well under the engine ceiling, so
        // the clamp is a no-op and the pad-aware derivation is returned
        // unchanged (proves the clamp does not over-clamp the common case).
        assert_eq!(wg_inner_mtu(libc::AF_INET, 1500), 1425);
        // The exact MTU whose derived inner sits AT the engine ceiling:
        // inner = outer - 60 - 15 = 4096 → outer = 4171. At-ceiling passes
        // unchanged; one byte more is clamped back to the ceiling.
        assert_eq!(
            wg_inner_mtu(libc::AF_INET, 4171),
            super::super::engine::WG_ENGINE_MAX_INNER_MTU
        );
        assert_eq!(
            wg_inner_mtu(libc::AF_INET, 4170),
            super::super::engine::WG_ENGINE_MAX_INNER_MTU - 1
        );
        assert_eq!(
            wg_inner_mtu(libc::AF_INET, 4172),
            super::super::engine::WG_ENGINE_MAX_INNER_MTU
        );
    }
}
