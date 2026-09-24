//! Header inspection / parsing helpers — read-only fns over
//! Ethernet/IPv4/IPv6/TCP/UDP/ICMP byte buffers. No mutation.
//!
//! Phase 2 split out of `frame.rs` per #988. The inspect cluster
//! covers raw header parsing (frame_l3_offset, parse_session_flow_*,
//! decode_frame_summary, etc.) plus session-key / fabric-tag readers
//! that operate on a frame slice without mutating it.

use crate::afxdp::types::ForwardPacketMeta;
use crate::nat::NatDecision;
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

// #989: TCP-specific inspection helpers (frame_has_tcp_rst,
// extract_tcp_flags_and_window, extract_tcp_window) and tcp_flags_str
// were relocated to `frame/tcp.rs`.

/// #2292: maximum IPv6 extension headers the forwarding walkers will
/// chase before giving up. Kept equal to the screen path's bound in
/// `screen/extract.rs` (`for _ in 0..8`) so screen and forwarding agree
/// on what "valid enough IPv6" means — a chain that is still on an
/// extension header at the bound is treated identically (fail-closed)
/// by both paths. Before #2292 the forwarding walkers used 6 and
/// surrendered open at the bound (returned `Some(offset)` with the
/// unconsumed ext-header type as a bogus "L4 protocol"), so a 7th ext
/// header was classified one way by screen and another by forwarding.
///
/// #4435: exposed `pub(crate)` (re-exported at `crate::afxdp` level,
/// like `write_eth_header_slice`) so the NAT64 translator's own private
/// ext-header walkers in `crate::nat64` share this exact bound instead
/// of hardcoding a stale 6. Keeping one const removes the 6-vs-8 skew
/// where a 7-ext-header packet was NAT64-dropped but accepted by the
/// forwarding/screen paths.
pub(crate) const MAX_IPV6_EXT_HEADERS: usize = 8;

// #4517: the IPv6 extension-header types every walker in this file treats
// as a generic length-prefixed header (byte 0 = next header, byte 1 =
// HdrExtLen in 8-octet units excluding the first 8, advance
// `(HdrExtLen + 1) * 8`). The match arms below spell them as
// `0 | 43 | 60 | 135 | 139 | 140 | 253 | 254`:
//   0   Hop-by-Hop Options  (RFC 8200 §4.3)
//   43  Routing             (RFC 8200 §4.4)
//   60  Destination Options (RFC 8200 §4.6)
//   135 Mobility            (RFC 6275 §6.1)
//   139 HIP                 (RFC 7401 §5.1)
//   140 Shim6               (RFC 5533 §5.1)
//   253/254 experimental/testing (RFC 3692 / RFC 4727)
// AH (51) keeps its own arm (RFC 4302 `(len + 2) * 4` arithmetic) and
// Fragment (44) its fixed 8-byte arm. ESP (50) is deliberately NOT
// walked: the payload is encrypted and the inner next-header is
// unreadable, so stopping there is correct. Before #4517 the exotic
// types (135/139/140/253/254) fell to the terminal `_` arm, so a chain
// like `HOP → MOBILITY → FRAGMENT → TCP` was classified proto=135 with
// no L4/fragment status — hiding the SYN from the screens and the flow
// from forwarding (an ext-header IDS evasion). All walkers here MUST
// keep the same set so the screen, meta, and fragment paths agree.
// #6435: they now share one WALKER too — `walk_ipv6_ext_chain` below is
// the single loop every L4 resolver / fragment predicate in this file
// (and, via the `crate::afxdp` re-export, the NAT64 and embedded-ICMP
// walkers) folds into its own verdict, so the set above can never drift
// between copies again. `screen/extract.rs` keeps its own walk: it
// extracts screen-specific state (routing-header type, fragment info)
// into its parse struct and fails with a screen-specific `Err`, a
// different contract than L4 resolution.

/// #6435: terminal verdict of the one shared IPv6 extension-header walk
/// ([`walk_ipv6_ext_chain`]). Every wrapper folds this into its own
/// return type (`Option<usize>` L4 offset, `Option<(usize, u8)>`, or a
/// fail-closed `bool`); the walk itself exists exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtChainOutcome {
    /// Resolved to a non-extension terminal header within the bound:
    /// `(l4_offset, l4_protocol)`, with `l4_offset` relative to the
    /// start of the walked buffer (the IPv6 header start when `l3 == 0`).
    L4(usize, u8),
    /// No-Next-Header (59) reached: a valid terminal with no L4 header.
    NoNextHeader,
    /// The walk stopped before any terminal: a short read, a declared
    /// length overrunning the buffer, or an offset overflow. The
    /// pre-#6435 hand-written walkers returned their fail-closed value
    /// (`None` / `false`) on each of these; the wrappers keep folding
    /// them to the same verdict.
    Truncated,
    /// Still on an extension header after `MAX_IPV6_EXT_HEADERS`
    /// iterations — the over-limit, uninspectable chain the #2292
    /// walkers fail closed on and #4743's `ipv6_ext_chain_over_limit`
    /// reports. #10665: the 8th header's DECLARATION is over-limit even
    /// when its bytes overrun the buffer (`OverLimit`, not `Truncated`).
    OverLimit,
}

/// The FIRST Fragment (44) header a walked chain declared, recorded by
/// [`walk_ipv6_ext_chain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExtChainFragment {
    /// The raw 8 header bytes when they lay within the buffer; `None`
    /// when the buffer truncates the header, so the offset/M/ident bits
    /// are unreadable. The distinction preserves the pre-#6435
    /// predicates: `ipv6_is_non_first_fragment` / NAT64's
    /// `ipv6_fragment_header` fail closed on unreadable bytes, while
    /// `ipv6_is_any_fragment` reports the DECLARED header even then
    /// (that predicate matched on the declared type without reading the
    /// header).
    pub bytes: Option<[u8; 8]>,
    /// #9950: absolute buffer offset of the Fragment header start (the `offset`
    /// the walker held when it declared the header). Needed to size this
    /// fragment's data contribution (`frag_data_off` + wire clamp) without a
    /// second walk. `Some` whenever `fragment` is `Some` (declared), even when
    /// `bytes` is `None` (truncated).
    pub header_offset: usize,
}

/// Result of [`walk_ipv6_ext_chain`]: the terminal verdict plus the
/// first Fragment header sighted along the way, when the chain declared
/// one. Only the FIRST Fragment header is recorded in
/// [`ExtChainWalk::fragment`] — a (hostile) chain with a second Fragment
/// header keeps the first sighting, matching the stop-at-first-fragment
/// pre-#6435 declares-match consumers (`ipv6_is_any_fragment`, the NDP
/// NA refusal); consumers that judge EVERY sighting (the #1838
/// embedded-ICMP resolver, and since #10661 every fragment-status
/// predicate) read [`ExtChainWalk::non_first_fragment_offset_seen`] and
/// [`ExtChainWalk::first_non_atomic_fragment`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExtChainWalk {
    pub outcome: ExtChainOutcome,
    pub fragment: Option<ExtChainFragment>,
    /// Set when ANY Fragment header sighted along the walk (first OR a
    /// later, RFC 8200-non-conformant repeat) carried non-zero
    /// fragment-offset bits in readable bytes. The embedded-ICMP L4
    /// resolver (#1838) judges EVERY sighted Fragment header, not just
    /// the first recorded one — this flag is what preserves that
    /// every-header judgement on top of the single recorded sighting.
    /// Since #10661 the forwarding non-first predicates fold this too,
    /// matching the shim's every-sighting verdict.
    pub non_first_fragment_offset_seen: bool,
    /// #10661: the FIRST readably non-ATOMIC Fragment header sighted
    /// along the walk — offset != 0 or M != 0 in readable bytes — with
    /// its header offset, so the overlap tracker keys its range off the
    /// header the plain single-header control carries. `None` when the
    /// chain declared no Fragment header or every sighting was ATOMIC
    /// (offset 0, M 0). A declared-but-truncated sighting is never
    /// recorded here (its bits are unreadable); it sets
    /// [`ExtChainWalk::fragment_truncated`] instead.
    pub first_non_atomic_fragment: Option<ExtChainFragment>,
    /// #10661: set when ANY declared Fragment header's 8 bytes lay past
    /// the buffer end. Bit-reading verdicts (the overlap tracker, the
    /// non-atomic predicate) fail closed on this rather than judging
    /// the chain from a readable ATOMIC sighting alone.
    pub fragment_truncated: bool,
}

/// #6435: the single IPv6 extension-header chain walk shared by every
/// forwarding / NAT64 / embedded-ICMP L4 resolver, chain classifier, and
/// fragment predicate. `buf` is the buffer to walk and `l3` the offset
/// of the IPv6 header inside it (`0` for an L3-relative packet slice,
/// `frame_l3_offset(frame)` for a full frame). The walk starts at the
/// fixed header's Next Header byte (`buf[l3 + 6]`) and the first
/// extension header (`l3 + 40`); a buffer too short for the fixed
/// 40-byte header yields [`ExtChainOutcome::Truncated`].
///
/// The loop body is the exact shape every pre-#6435 copy hand-mirrored:
/// the #4517 generic length-prefixed set advances `(HdrExtLen + 1) * 8`,
/// AH (51) advances `(len + 2) * 4` (RFC 4302), Fragment (44) advances a
/// fixed 8 bytes, ESP (50) is deliberately NOT walked (encrypted payload,
/// unreadable inner next-header — it falls to the terminal `L4` verdict
/// like any real upper-layer protocol), No-Next-Header (59) is its own
/// verdict, every advance re-validates against `buf.len()`, and a chain
/// still on an extension header after `MAX_IPV6_EXT_HEADERS` iterations
/// is [`ExtChainOutcome::OverLimit`] (#2292/#4743 fail-closed). #10665:
/// the 8th header's DECLARATION is over-limit even when its bytes overrun
/// the buffer — `OverLimit` takes precedence over `Truncated` at the bound
/// (checked before any length byte of header 8 is touched), matching the
/// shim's 7-iteration walk, which never reads header 8 at all.
///
/// The walk ALWAYS runs to a terminal (or the bound), even past a
/// Fragment header: the first Fragment header is RECORDED in
/// [`ExtChainWalk::fragment`] instead of stopping the walk, so one loop
/// serves both the L4 resolvers (which walk past first/atomic fragments)
/// and the fragment predicates (which read only the recorded sighting —
/// see the type's doc for the verdict-equivalence argument).
/// `#[inline(always)]` keeps the shared body folded into each caller per
/// the repo hot-path convention (in-crate, LTO off, codegen-units 16 —
/// explicit attrs are required for cross-CGU inlining); the common
/// no-extension-header packet still exits on the first match arm.
#[inline(always)]
pub(crate) fn walk_ipv6_ext_chain(buf: &[u8], l3: usize) -> ExtChainWalk {
    let mut fragment = None;
    let mut non_first_fragment_offset_seen = false;
    let mut first_non_atomic_fragment = None;
    let mut fragment_truncated = false;
    if buf.len() < l3 + 40 {
        return ExtChainWalk {
            outcome: ExtChainOutcome::Truncated,
            fragment,
            non_first_fragment_offset_seen,
            first_non_atomic_fragment,
            fragment_truncated,
        };
    }
    let mut protocol = buf[l3 + 6];
    let mut offset = l3 + 40;
    for i in 0..MAX_IPV6_EXT_HEADERS {
        // #10665: at the bound the DECLARATION of an 8th extension header is
        // over-limit even when its bytes overrun the frame — `OverLimit` takes
        // precedence over `Truncated`. Resolving the chain would need a 9th
        // iteration even with the bytes present, and the shim's 7-iteration
        // walk never reads header 8 at all, so neither do we: no length byte
        // is touched on this path. A terminal (L4/59/ESP) at this iteration
        // still resolves below — only a TRAVERSABLE protocol is over-limit.
        // The declared Fragment sighting is still recorded (bytes `None` when
        // truncated) so `ipv6_is_any_fragment` keeps its declares-match
        // semantics at the bound.
        if i + 1 == MAX_IPV6_EXT_HEADERS && ipv6_ext_header_is_traversable(protocol) {
            if protocol == 44 {
                record_fragment_sighting(buf, offset, &mut fragment, &mut non_first_fragment_offset_seen);
            }
            return ExtChainWalk {
                outcome: ExtChainOutcome::OverLimit,
                fragment,
                non_first_fragment_offset_seen,
            };
        }
        match protocol {
            // #4517: generic length-prefixed EHs (see the set at
            // MAX_IPV6_EXT_HEADERS): HbH/Routing/DestOpt +
            // Mobility/HIP/Shim6/experimental.
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                let Some(opt) = buf.get(offset..offset + 2) else {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                };
                protocol = opt[0];
                let Some(next) = offset.checked_add((usize::from(opt[1]) + 1) * 8) else {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                };
                offset = next;
                if buf.len() < offset {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                }
            }
            51 => {
                let Some(opt) = buf.get(offset..offset + 2) else {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                };
                protocol = opt[0];
                let Some(next) = offset.checked_add((usize::from(opt[1]) + 2) * 4) else {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                };
                offset = next;
                if buf.len() < offset {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                }
            }
            44 => {
                let header = buf.get(offset..offset + 8);
                // The shared recorder preserves the first declaration and updates the every-sighting non-first verdict; it is also used by the #10665 bound early-return.
                record_fragment_sighting(buf, offset, &mut fragment, &mut non_first_fragment_offset_seen);
                if let Some(f) = header {
                    // #10661: record the FIRST readably non-ATOMIC header
                    // (offset != 0 or M != 0), so an `[ATOMIC][real]`
                    // chain tracks like its plain single-header control.
                    // `f` is the 8 walked bytes, so copying is in-bounds.
                    if first_non_atomic_fragment.is_none()
                        && (u16::from_be_bytes([f[2], f[3]]) & 0xFFF9) != 0
                    {
                        first_non_atomic_fragment = Some(ExtChainFragment {
                            bytes: Some([
                                f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
                            ]),
                            header_offset: offset,
                        });
                    }
                } else {
                    // A declared-but-unreadable Fragment header — first or
                    // repeat — poisons bit-reading verdicts.
                    fragment_truncated = true;
                }
                let Some(frag) = header else {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                };
                protocol = frag[0];
                let Some(next) = offset.checked_add(8) else {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                };
                offset = next;
                if buf.len() < offset {
                    return ExtChainWalk {
                        outcome: ExtChainOutcome::Truncated,
                        fragment,
                        non_first_fragment_offset_seen,
                        first_non_atomic_fragment,
                        fragment_truncated,
                    };
                }
            }
            59 => {
                return ExtChainWalk {
                    outcome: ExtChainOutcome::NoNextHeader,
                    fragment,
                    non_first_fragment_offset_seen,
                };
                first_non_atomic_fragment,
                fragment_truncated,
            }
            _ => {
                return ExtChainWalk {
                    outcome: ExtChainOutcome::L4(offset, protocol),
                    fragment,
                    non_first_fragment_offset_seen,
                };
                first_non_atomic_fragment,
                fragment_truncated,
            }
        }
    }
    ExtChainWalk {
        outcome: ExtChainOutcome::OverLimit,
        fragment,
        non_first_fragment_offset_seen,
        first_non_atomic_fragment,
        fragment_truncated,
    }
}

/// #10665: record one declared Fragment (44) header sighting at `offset`.
/// Shared by the in-loop Fragment arm and the bound early-return so the
/// two can never drift apart. Records the FIRST declaration only
/// (`bytes: None` when the buffer truncates the header, preserving
/// `ipv6_is_any_fragment`'s declares-match semantics) while the #1838
/// every-sighting non-first-offset judgement runs on every call. Never
/// panics: the header is read through `buf.get`.
#[inline(always)]
fn record_fragment_sighting(
    buf: &[u8],
    offset: usize,
    fragment: &mut Option<ExtChainFragment>,
    non_first_fragment_offset_seen: &mut bool,
) {
    let header = buf.get(offset..offset + 8);
    if fragment.is_none() {
        *fragment = Some(ExtChainFragment {
            bytes: header.and_then(|h| <[u8; 8]>::try_from(h).ok()),
            header_offset: offset,
        });
    }
    if let Some(f) = header {
        // #1838 every-sighting judgement: a non-zero offset in ANY
        // sighted Fragment header (not just the recorded first) is a
        // quoted/forwarded non-first fragment.
        if (u16::from_be_bytes([f[2], f[3]]) & 0xFFF8) != 0 {
            *non_first_fragment_offset_seen = true;
        }
    }
}

/// #4555/#6923: `true` iff `protocol` is an IPv6 next-header value the walk
/// above TRAVERSES rather than terminates on — the GENERIC length-prefixed set
/// (`0 | 43 | 60 | 135 | 139 | 140 | 253 | 254`), AH (51) and Fragment (44).
/// No-Next-Header (59) is deliberately NOT a member: it is a TERMINAL verdict
/// (`NoNextHeader`) both walkers resolve to, not a header either one steps past.
///
/// This is the set a resolved walk can NEVER hand out as an upper-layer
/// protocol, on either side of the shim boundary — the shim's
/// `walk_ipv6_ext_headers` yields one of these only by EXHAUSTING
/// `MAX_EXT_HDRS`, and `walk_ipv6_ext_chain` folds that same exhaustion into
/// `OverLimit`. So a `meta.protocol` in this set means "the shim gave up
/// mid-chain", never "the shim resolved this upper-layer protocol", which is
/// what [`metadata_tuple_complete`] keys off. ESP (50) is deliberately absent
/// on both sides (encrypted payload, unreadable inner next-header): it IS a
/// resolved terminal and must keep flowing.
///
/// Kept next to `walk_ipv6_ext_chain` and pinned to it BEHAVIOURALLY rather
/// than by a second copy of the arm list — `inspect_tests.rs` sweeps all 256
/// values and asserts this predicate agrees with what the walker measurably
/// does with a one-header chain of that type, and `tests_shim_ext_parity.rs`
/// asserts it also agrees with the SHIM's `eh_class`. Adding a type to either
/// walker without adding it here reds both.
///
/// #9901 (F-072): the GENERIC length-prefixed subset as a shared const, so the
/// screen extractor (`screen/extract.rs`) guards on this single source instead
/// of a second hand-mirrored arm list. The predicate below delegates to it —
/// the set is stated once, here.
pub(crate) const IPV6_GENERIC_EXT_HEADERS: [u8; 8] = [0, 43, 60, 135, 139, 140, 253, 254];
#[inline]
pub(crate) fn ipv6_ext_header_is_traversable(protocol: u8) -> bool {
    IPV6_GENERIC_EXT_HEADERS.contains(&protocol) || matches!(protocol, 44 | 51)
}

pub(in crate::afxdp) fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(eth_proto, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return None;
        }
        return Some(18);
    }
    Some(14)
}

/// A nibble-checked L3 resolution: the offset plus whether the STAMP was
/// trusted. When `stamp_trusted` is false the shim's whole offset pair is
/// suspect (both stamps come from one parse) — the caller must ALSO distrust
/// `meta.l4_offset` (neutralize it so downstream derivation falls back to
/// the wire) instead of mixing a corrected L3 with a stale L4 (GPT-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct CheckedL3 {
    pub(in crate::afxdp) l3: usize,
    pub(in crate::afxdp) stamp_trusted: bool,
}

/// The stamp half of [`nibble_checked_l3`] without the wire fallback:
/// `Some(stamp)` iff the stamp is 14/18 AND the nibble at it matches
/// `addr_family`. For wire-FIRST callers whose ethertype parse already
/// failed — there is no wire L2 length left to prefer, but an unverified
/// stamp must still not index the frame (SPARK-m3).
#[inline]
pub(in crate::afxdp) fn nibble_trusted_stamp(
    frame: &[u8],
    l3_offset: u16,
    addr_family: u8,
) -> Option<usize> {
    let expected_version = match addr_family as i32 {
        libc::AF_INET => 4u8,
        libc::AF_INET6 => 6u8,
        _ => return None,
    };
    match l3_offset {
        14 | 18
            if frame
                .get(l3_offset as usize)
                .is_some_and(|byte| (byte >> 4) == expected_version) =>
        {
            Some(l3_offset as usize)
        }
        _ => None,
    }
}

/// Resolve the L3 offset, trusting the stamped `l3_offset` ONLY when the byte
/// it points at carries the IP-version nibble matching `addr_family (#9900
/// F-095). A wrong-but-plausible stamp (14 on a tagged frame, 18 on an
/// untagged one) falls back to [`frame_l3_offset`], as does any non-14/18
/// stamp and any unknown family; `None` means neither the stamp nor the wire
/// yields an offset and the caller fails closed. The answer carries
/// `stamp_trusted`: when false the caller must ALSO distrust `meta.l4_offset`
/// (see [`CheckedL3`]) instead of mixing a corrected L3 with a stale L4.
/// The gate is the #2344 idiom (`frame_is_non_first_fragment` below), factored
/// out so the stamp consumers share one spelling instead of hand-mirrored
/// matches. Converted callers and their fallback judgments:
///
/// - `frame/mod.rs` `rewrite_plan_eth_from_parts` — `?` (fail closed): the
///   plan drives TTL decrement, checksum recompute and NAT at `plan.l3`.
///   Carries `stamp_trusted` so callers neutralize `meta.l4_offset` when the
///   stamp was distrusted (GPT-5: a corrected L3 with a stale L4 mis-drives
///   the v6 transport rewrites).
/// - `frame/build/mod.rs` `build_forwarded_frame_into_from_frame` — `?` plus
///   the same L4 neutralization.
/// - `forwarding/fib.rs` `parse_packet_destination` — `.unwrap_or(stamp)`:
///   a read-only dst parse, so double-garbage keeps the old stamp-indexed
///   behavior instead of growing a new NoRoute cliff.
/// - `inspect.rs` `parse_packet_destination_from_frame` — same `.unwrap_or`
///   judgment (SPARK-M4: DNAT/NAT64 dst parse, the converted twin's twin).
/// - `wg/decap.rs` `outer_source_ip` — `?` (fail closed): the read feeds
///   PERSISTENT roam/endpoint learning, so double-garbage must skip the
///   observation, never learn a garbage endpoint (SPARK-M6).
/// - `live_frame_ports_from_meta_bytes` — the meta fast arm derives its
///   declared end from the nibble-checked L3 (SPARK-M5).
/// - Declared-end readers `term_match_extra_from_frame` and
///   `meta_icmp_identifier_bearing` — same treatment (filter/icmp verdict
///   inputs; SPARK-m4).
/// - Wire-first sites (`tx/dispatch/mod.rs` x3, `frame/wg.rs` x2,
///   `gre.rs` inner, `forward_request.rs` hint chain) — stamp fallback
///   nibble-gated via [`nibble_trusted_stamp`] (SPARK-m3).
/// - `poll_descriptor` fragment predicates/slices + `nat64_icmp_error.rs` —
///   `.unwrap_or(stamp)` (SPARK-m6: a wrong stamp previously flipped the
///   SNAT-gate and NAT64-association verdicts).
///
/// No post-fallback nibble re-check: the fallback IS the wire parse, and the
/// downstream TTL/checksum/NAT arms already version-gate (e.g.
/// `frame/mod.rs` `validate_generic_rewrite_v4/v6`). `frame_is_non_first_fragment`
/// keeps its own inline copy WITH the extra post-check (meta-led fixtures
/// carry the tuple in metadata with no IP byte at the derived offset at all),
/// so it is NOT refactored onto this helper — same deliberate-twin rationale
/// as the `lock_recover` shapes.
///
/// #9900 audit: every other production `l3_offset` reader, dispositioned.
///
/// - Length-math ONLY (no wire indexing): `frame/mod.rs` `trim_l3_payload`
///   meta fallback (`pkt_len - l3_offset` extent math, clamped to the payload;
///   callers now pass the CORRECTED offset, which is the true L3 length).
/// - Difference-only HINT (`l4 - l3`, never an index): `v6_rel_l4_offset`
///   (neutralized `l4 == l3` input yields a 0 difference, forcing the wire
///   parse — the GPT-5 convention, stated on the helper).
/// - Bounded read-only cold/error-path readers with the same blind-trust SHAPE
///   but fail-soft outcomes (a mis verdict or misaligned quote on one packet,
///   no UMEM mutation, no forwarding corruption, no persistent learning):
///   `icmp.rs` x4, `icmp_ptb.rs` x2, `gre.rs` OUTER readers x3
///   (`parse_outer_addresses`, `outer_datagram_end`, `outer_ecn_bits` — the
///   outer IP header of a decap candidate; worst case a misread outer addr
///   on one error/quote path), `icmp_embed/*`, `icmp_embed/nat64_match.rs`.
///   Converting them is follow-up scope, recorded in `docs/log/9900.md` —
///   each needs its own `?`-vs-`unwrap_or` judgment and repro cell.
/// - No production callers (re-exported, test-only): the
///   `tx/dispatch/slow_path.rs` extract family.
/// - Producers, not readers (stamp WRITES): `coordinator/inject.rs`,
///   `tunnel.rs`, `frame/mod.rs` egress stamping.
#[inline]
pub(in crate::afxdp) fn nibble_checked_l3(
    frame: &[u8],
    l3_offset: u16,
    addr_family: u8,
) -> Option<CheckedL3> {
    if let Some(l3) = nibble_trusted_stamp(frame, l3_offset, addr_family) {
        return Some(CheckedL3 {
            l3,
            stamp_trusted: true,
        });
    }
    // Unknown family, non-14/18 stamp, or nibble mismatch: the stamp is
    // unverifiable, hence unusable — derive from the wire (operational)
    // or fail closed.
    frame_l3_offset(frame).map(|l3| CheckedL3 {
        l3,
        stamp_trusted: false,
    })
}

/// Verified L3 with stamp fallback: [`nibble_checked_l3`] resolved, or the
/// raw stamp when NEITHER verifies (double-garbage). For read-only callers
/// whose old stamp-indexed behavior on double-garbage must be preserved
/// (FIB/NAT64 dst parses, declared-end gates, poll predicates) — mutating
/// callers use `?` on [`nibble_checked_l3`] instead, and L4-coherent callers
/// read `stamp_trusted` off it.
#[inline]
pub(in crate::afxdp) fn verified_l3_or_stamp(
    frame: &[u8],
    l3_offset: u16,
    addr_family: u8,
) -> usize {
    nibble_checked_l3(frame, l3_offset, addr_family)
        .map(|checked| checked.l3)
        .unwrap_or(l3_offset as usize)
}

// #989: tcp_flags_str moved to `frame/tcp.rs`.

pub(in crate::afxdp) fn frame_l4_offset(frame: &[u8], addr_family: u8) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    match addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 {
                return None;
            }
            let ihl = usize::from(frame[l3] & 0x0f) * 4;
            if ihl < 20 || frame.len() < l3 + ihl {
                return None;
            }
            Some(l3 + ihl)
        }
        libc::AF_INET6 => {
            // #2292: only a resolved terminal L4 within the bound yields
            // an offset — every other verdict fails CLOSED (None → caller
            // drops). In particular an OverLimit chain (still on an
            // extension header at the MAX_IPV6_EXT_HEADERS bound) no
            // longer surrenders the unconsumed ext-header offset as a
            // fake L4 offset; this matches the screen path
            // (`screen/extract.rs`), which returns
            // `Err(TruncatedIpv6ExtChain)` on the same over-bound chain.
            // #6435: the walk itself is the shared `walk_ipv6_ext_chain`.
            match walk_ipv6_ext_chain(frame, l3).outcome {
                ExtChainOutcome::L4(offset, _) => Some(offset),
                _ => None,
            }
        }
        _ => None,
    }
}

/// #4743: return `true` iff `frame`'s IPv6 extension-header chain is still on
/// an extension header after `MAX_IPV6_EXT_HEADERS` iterations — the OVER-LIMIT,
/// uninspectable chain that `frame_l4_offset` fails closed on (the post-loop
/// `None` at the bound). Deliberately distinguishes over-limit from TRUNCATION:
/// any in-loop short read / declared-length overrun returns `false` (a truncated
/// chain stays on the existing flowless path, unchanged) — EXCEPT a short read /
/// overrun OF the 8th header's own bytes: its declaration is over-limit even
/// when its bytes overrun the buffer (#10665), so the gate fires there. A chain
/// terminates on a real L4 within the bound or a non-IPv6 packet. This is the
/// gate for the explicit fail-closed drop: before #4743 an over-limit chain was
/// forwarded flowless (`l4_present = false`), an ext-header IDS-evasion; now it
/// is dropped and counted (`ipv6_ext_header_dropped`). #6435: folds the shared
/// `walk_ipv6_ext_chain` — only its `OverLimit` verdict is "over-limit", so this
/// gate and `frame_l4_offset` agree by construction on what "over-limit" means.
pub(in crate::afxdp) fn ipv6_ext_chain_over_limit(frame: &[u8], addr_family: u8) -> bool {
    if addr_family as i32 != libc::AF_INET6 {
        return false;
    }
    let Some(l3) = frame_l3_offset(frame) else {
        return false;
    };
    // A truncated base header (frame shorter than l3 + 40) walks to
    // `Truncated`, not `OverLimit` — preserved from the pre-#6435 gate's
    // explicit "truncated base header — not over-limit" early return.
    matches!(
        walk_ipv6_ext_chain(frame, l3).outcome,
        ExtChainOutcome::OverLimit
    )
}

pub(in crate::afxdp) fn packet_rel_l4_offset(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some(ihl)
        }
        libc::AF_INET6 => {
            // #2292: fail-CLOSED on every non-L4 verdict, including
            // OverLimit at the bound (see frame_l4_offset). #6435: the
            // walk is the shared `walk_ipv6_ext_chain` over the
            // L3-relative slice.
            match walk_ipv6_ext_chain(packet, 0).outcome {
                ExtChainOutcome::L4(offset, _) => Some(offset),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Like `packet_rel_l4_offset` but also returns the final L4 protocol
/// after walking IPv6 extension headers. For IPv4, returns the protocol
/// byte from the IP header. Needed for GRE inner packet parsing where
/// the initial next-header (packet[6]) may be an extension header, not
/// the actual L4 protocol.
pub(in crate::afxdp) fn packet_rel_l4_offset_and_protocol(
    packet: &[u8],
    addr_family: u8,
) -> Option<(usize, u8)> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some((ihl, packet[9]))
        }
        libc::AF_INET6 => {
            // #2292: fail-CLOSED on every non-L4 verdict. Before #2292 the
            // at-bound fall-through returned `Some((offset, protocol))`
            // where `protocol` was the unconsumed extension-header type
            // (0/43/51/60), which callers (GRE inner-parse, tunnel
            // local-origin metadata, NDP/TCP-flag helpers) then trusted as
            // a real L4 protocol. #6435: the walk is the shared
            // `walk_ipv6_ext_chain` over the L3-relative slice.
            match walk_ipv6_ext_chain(packet, 0).outcome {
                ExtChainOutcome::L4(offset, protocol) => Some((offset, protocol)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// #1852: is this L3-relative IPv4 packet a NON-first fragment?
///
/// A non-first fragment has a non-zero fragment offset (the low 13 bits
/// of the `frag_off` field at IPv4 header bytes 6-7) and therefore has NO
/// L4 header at the post-IP-header offset — its "L4" bytes are payload.
/// First and atomic fragments (offset 0, MF=0 or 1) carry the real L4
/// header and return `false`. A too-short slice returns `false` (the
/// length guards in the rewrite leaves reject it separately).
#[inline]
pub(in crate::afxdp) fn ipv4_is_non_first_fragment(packet: &[u8]) -> bool {
    packet.len() >= 8 && (u16::from_be_bytes([packet[6], packet[7]]) & 0x1FFF) != 0
}

/// #1852: is this L3-relative IPv6 packet a NON-first fragment?
///
/// Walks the extension-header chain (bounded, same iteration limit as
/// `packet_rel_l4_offset` — `MAX_IPV6_EXT_HEADERS`) looking for a
/// fragment header (44). Returns
/// `true` iff a fragment header is present AND its fragment-offset bits
/// (upper 13 bits of bytes 2-3, mask `0xFFF8`, RFC 8200 §4.5) are
/// non-zero. First/atomic fragments (offset 0) and packets without a
/// fragment header return `false`. Mirrors `screen/extract.rs` /
/// `parse_embedded_v6_l4` fragment semantics. Read-only, no mutation;
/// unlike the defect-2 fix this is a separate predicate so the shared
/// `packet_rel_l4_offset_and_protocol` (read by GRE decap / tunnel
/// local-origin to FORWARD fragments) stays unchanged.
/// #6435: folds the shared `walk_ipv6_ext_chain`'s recorded first
/// Fragment-header sighting. A declared-but-truncated Fragment header
/// (bytes unreadable) fails closed (`false`), exactly like the pre-#6435
/// walker's `packet.get(offset..offset + 8)` else-return. The shared walk
/// continues past the Fragment header to the chain terminal, but this
/// predicate reads only the recorded FIRST sighting, so a (hostile)
/// double-Fragment chain still judges by the first header — identical to
/// the pre-#6435 stop-at-first-fragment walk.
#[inline]
pub(in crate::afxdp) fn ipv6_is_non_first_fragment(packet: &[u8]) -> bool {
    walk_ipv6_ext_chain(packet, 0)
        .fragment
        .and_then(|frag| frag.bytes)
        .is_some_and(|b| (u16::from_be_bytes([b[2], b[3]]) & 0xFFF8) != 0)
}

/// #1852: family-dispatched non-first-fragment predicate over the
/// L3-relative packet slice. Computed ONCE per packet by the rewrite
/// orchestrators and threaded into the NAT leaves so the L4 byte
/// operations (port rewrite, L4-checksum adjust, port enforcement, ICMP
/// ident restore) are skipped on non-first fragments while the IP
/// address rewrite still runs (the IP header is present on every
/// fragment; the L4 checksum lives only in the first fragment).
#[inline]
pub(in crate::afxdp) fn is_non_first_fragment(packet: &[u8], addr_family: u8) -> bool {
    match addr_family as i32 {
        libc::AF_INET => ipv4_is_non_first_fragment(packet),
        libc::AF_INET6 => ipv6_is_non_first_fragment(packet),
        _ => false,
    }
}

/// #2362: is this L3-relative IPv4 packet ANY fragment? Junos `is-fragment`
/// matches a datagram that is part of a fragmented packet — the FIRST fragment
/// (MF=1, offset=0), a MIDDLE/LAST fragment (offset != 0), but NOT an
/// unfragmented datagram (MF=0, offset=0). The MF bit is 0x2000 and the
/// fragment-offset field is the low 13 bits, so the combined test on the
/// `frag_off` field (IPv4 header bytes 6-7) is `(value & 0x3FFF) != 0`. The DF
/// bit (0x4000) and the reserved bit (0x8000) are intentionally excluded. A
/// too-short slice returns `false`.
#[inline]
pub(in crate::afxdp) fn ipv4_is_any_fragment(packet: &[u8]) -> bool {
    packet.len() >= 8 && (u16::from_be_bytes([packet[6], packet[7]]) & 0x3FFF) != 0
}

/// #2362: is this L3-relative IPv6 packet ANY fragment? IPv6 carries
/// fragmentation in a Fragment extension header (next-header 44). Junos
/// `is-fragment` matches any datagram that carries a fragment header, including
/// the first fragment (offset 0, M=1). Walks the extension-header chain
/// (bounded by `MAX_IPV6_EXT_HEADERS`) and returns `true` as soon as a fragment
/// header is found. Packets with no fragment header return `false`.
/// #6435: folds the shared `walk_ipv6_ext_chain`'s recorded first
/// Fragment-header sighting. The DECLARATION alone matches — a chain that
/// declares a Fragment header whose 8 bytes are then truncated still
/// returns `true`, exactly like the pre-#6435 predicate's `44 => return
/// true` arm, which matched on the declared type without reading the
/// header bytes. Only the FIRST sighting is consulted, matching the
/// pre-#6435 stop-at-first-fragment walk on a double-Fragment chain.
#[inline]
pub(in crate::afxdp) fn ipv6_is_any_fragment(packet: &[u8]) -> bool {
    walk_ipv6_ext_chain(packet, 0).fragment.is_some()
}

/// #9901 (F-077): is this L3-relative IPv6 packet NON-ATOMICALLY fragmented —
/// i.e. could a LATER fragment explain a short quote? A Fragment header with
/// offset == 0 AND M == 0 (an ATOMIC fragment, RFC 8200 §4.5) carries the
/// whole datagram: no later fragment exists, so it must NOT disable the
/// quoted-L4 adequacy floor the way a genuine first fragment (M == 1) or a
/// non-first fragment (offset != 0) does. A declaration with UNREADABLE
/// bytes (truncated header) conservatively counts as fragmenting — the bits
/// cannot be inspected, so the old declares-match behavior is kept there.
#[inline]
pub(in crate::afxdp) fn ipv6_is_nonatomically_fragmented(packet: &[u8]) -> bool {
    match walk_ipv6_ext_chain(packet, 0).fragment {
        None => false,
        Some(f) => match f.bytes {
            // Fragment-header bytes 2-3: 13-bit offset (high bits) + 2
            // reserved bits + M. Non-atomic iff offset != 0 or M != 0.
            Some(b) => (u16::from_be_bytes([b[2], b[3]]) & 0xFFF9) != 0,
            None => true,
        },
    }
}

/// #2362: family-dispatched ANY-fragment predicate over the L3-relative packet
/// slice. Used by the firewall-filter `is-fragment` match condition.
#[inline]
pub(in crate::afxdp) fn is_any_fragment(packet: &[u8], addr_family: u8) -> bool {
    match addr_family as i32 {
        libc::AF_INET => ipv4_is_any_fragment(packet),
        libc::AF_INET6 => ipv6_is_any_fragment(packet),
        _ => false,
    }
}

/// #2362: build the per-packet L4 match inputs (tcp-flags / is-fragment /
/// icmp-type / icmp-code) consumed by the firewall-filter term predicate, from
/// the live frame + metadata. The fragment bit is read from the L3-relative
/// packet slice (`meta.l3_offset`); `tcp_flags` comes from `meta`, and the
/// ICMP/ICMPv6 type/code bytes from `meta.l4_offset`. Only the cold
/// filter-evaluation path calls this, and only when an interface carries a
/// per-packet-L4 (or DSCP) match filter, so the parse cost stays off the hot
/// path. A non-ICMP protocol yields (0, 0) for type/code — the matcher already
/// guards those against the protocol, so the values are never consulted.
///
/// #2362 fold A (the #2344 non-first-fragment class): a NON-FIRST fragment
/// carries NO L4 header at `l4_offset` — those bytes are payload, and
/// `meta.protocol` / `meta.tcp_flags` are derived from the IP header / shim
/// stamping, not a real L4 header. Reading them would let a crafted fragment
/// whose payload byte equals a filter's `icmp-type` (or whose payload-derived
/// `tcp_flags` carries the masked bits) spuriously match. So when the packet is
/// a non-first fragment, force `tcp_flags = icmp_type = icmp_code = 0` — those
/// L4 terms must NOT match (matching the `per_packet_l4_matches` doc contract).
/// `is_fragment` is KEPT true (a non-first fragment IS a fragment; the
/// `is-fragment` term reads only the L3 header, which is present on every
/// fragment). Reuses the existing `is_non_first_fragment` predicate (#2344).
///
/// #2449 (the truncation class): a NON-FRAGMENTED ICMP/ICMPv6 frame may still
/// be shorter than `l4_offset + 2`, so the type/code bytes are absent. Reading
/// them with `unwrap_or(0)` would yield `icmp_type = icmp_code = 0` while
/// `l4_present` stayed true — a crafted short ICMP packet would spuriously
/// match `icmp-type 0 / icmp-code 0` (Echo Reply). So when the type/code bytes
/// are not present in the frame, force `(0, 0, 0)` AND drop `l4_present`, so the
/// L4 matcher fails closed (treats it as no-match). The #2344/#2362 gate only
/// covered the non-first-fragment case, not pure truncation.
/// #5150: end offset (into `frame`) of the IP-DECLARED datagram, i.e.
/// `l3_offset + IP total length`, CLAMPED to `frame.len()`. Backs the
/// flexible-match-range byte slices (`flex_l3`/`flex_l4`) so a firewall filter
/// byte-match is bounded by the LOGICAL IP datagram (IP total-length) and never
/// by the physical Ethernet backing frame.
///
/// Two clamps, both security-relevant:
///   - Upper clamp to `frame.len()`: a LYING (too-large) IP length field can
///     never widen the slice past the physical frame (no over-read).
///   - The slice end is this value, NOT `frame.len()`: attacker-controlled bytes
///     in Ethernet SLACK (padding beyond the declared IP length — e.g. the 60-
///     octet minimum-frame pad after a short datagram) are EXCLUDED, closing the
///     match-on-padding / filter-evasion hole.
///
/// Returns `None` when the frame is too short to even hold the IP length field
/// (IPv4 total-length at l3+2..4, IPv6 payload-length at l3+4..6) — the caller
/// then has no declared bound and fails the flex slice closed (the same
/// fail-closed posture as a frame shorter than `l3_offset`). A non-IP
/// `addr_family` also yields `None` (no IP datagram to bound).
///
/// For a well-formed packet with no Ethernet slack, `declared_end == frame.len()`
/// so `flex_l3`/`flex_l4` see the exact same bytes as before this change.
#[inline]
fn ip_declared_end(frame: &[u8], l3_offset: usize, addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            // IPv4 total length (header + payload), bytes 2..4 of the IP header.
            let total = u16::from_be_bytes([
                *frame.get(l3_offset + 2)?,
                *frame.get(l3_offset + 3)?,
            ]) as usize;
            Some(l3_offset.checked_add(total)?.min(frame.len()))
        }
        libc::AF_INET6 => {
            // IPv6 payload length (ext headers + L4 + payload), bytes 4..6 of the
            // fixed 40-byte IPv6 header. Declared datagram end = l3 + 40 + payload.
            let payload = u16::from_be_bytes([
                *frame.get(l3_offset + 4)?,
                *frame.get(l3_offset + 5)?,
            ]) as usize;
            Some(
                l3_offset
                    .checked_add(40)?
                    .checked_add(payload)?
                    .min(frame.len()),
            )
        }
        _ => None,
    }
}

/// #5568: the number of L4 (TCP) header bytes that must lie within the
/// IP-DECLARED datagram before the shim-stamped `tcp_flags` may be trusted for
/// a `tcp-flags` match. The TCP flags byte is at TCP header offset 13 (RFC
/// 9293 §3.1), so the declared datagram must reach `l4_offset + 14`. A shorter
/// declared length means the shim read the flags out of Ethernet slack /
/// padding, so the tcp-flags terms must fail closed (`l4_present = false`). A
/// well-formed TCP packet always declares at least a 20-byte L4 header, so this
/// bound never rejects legitimate traffic.
const TCP_FLAGS_DECLARED_MIN: usize = 14;

/// #2362 fold A + fold B unified (#6435): the ONE per-packet match-input
/// builder for both metadata flavors. The input-filter path
/// (`poll_descriptor/filter.rs`, `host_inbound_policy.rs`, `pbr.rs`,
/// `forward_request.rs`, `neighbor_dispatch.rs`, `coordinator/inject.rs`)
/// carries a `UserspaceDpMeta`; the TX-selection / CoS classification path
/// (`tx/cos_classify.rs`, #2362 fold B) carries a `ForwardPacketMeta`. Both
/// used to have byte-identical private copies (`term_match_extra_from_frame`
/// vs `..._fwd`, kept in sync by a "MUST stay identical" comment on a
/// fail-closed security gate); #6435 collapses them onto this single generic
/// builder via the same `impl Into<ForwardPacketMeta>` channel
/// `live_frame_ports_from_meta_bytes` already uses, so the #5568
/// declared-datagram derivation below can never drift between copies again.
/// The `From<UserspaceDpMeta> for ForwardPacketMeta` conversion is lossless
/// for every field this builder reads (`l3_offset`, `l4_offset`,
/// `addr_family`, `protocol`, `tcp_flags`).
///
/// Same fragment-safe contract on both paths: a non-first fragment forces
/// the L4-derived fields to 0 (its bytes are payload) while keeping the
/// L3-only `is_fragment` bit. The CoS path already routes a non-first
/// fragment to the default queue with no flow_key (#2357), so in practice
/// this builder is invoked on first/atomic packets there — the gate is
/// defense-in-depth and identical for both callers.
#[inline]
pub(in crate::afxdp) fn term_match_extra_from_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
) -> crate::filter::TermMatchExtra<'_> {
    use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP};
    let meta = meta.into();
    // #5568: derive EVERY scalar L4/fragment input from the IP-DECLARED datagram
    // end, not the physical frame. The shim stamps `l3_offset`/`l4_offset` from
    // the raw frame, so attacker-controlled Ethernet padding beyond the declared
    // IP length would otherwise manufacture fragment status, ICMP type/code, TCP
    // flags, and `l4_present` out of slack. Compute `declared_end` FIRST (the
    // #5150 `ip_declared_end` SSOT — also backing the flex slices below), so a
    // single declared bound governs the whole builder. On the common no-slack
    // path `declared_end == frame.len()`, so classification is byte-identical.
    // SPARK-m4: the declared end (and every verdict input below it) derives
    // from a VERIFIED L3 — a wrong stamp previously mis-sized the datagram
    // and flipped filter inputs. Double-garbage keeps the stamp (old shape).
    let l3 = verified_l3_or_stamp(frame, meta.l3_offset, meta.addr_family);
    let l4 = meta.l4_offset as usize;
    let declared_end = ip_declared_end(frame, l3, meta.addr_family);
    // The fragment walkers see ONLY the declared datagram (`l3..declared_end`),
    // so an IPv6 fragment/extension header lurking in padding beyond the declared
    // `payload_len` — or an IPv4 `frag_off` in slack — cannot manufacture
    // fragment state. `frame.get(l3..declared_end)` is None when the frame is too
    // short to even hold the IP length field (`declared_end == None`), which
    // fails the fragment bits closed (false) — the same posture the L4 gates take.
    let l3_declared = declared_end.and_then(|end| frame.get(l3..end));
    let is_fragment = l3_declared.is_some_and(|packet| is_any_fragment(packet, meta.addr_family));
    // A non-first fragment has no L4 header at `l4_offset` (its bytes are
    // payload) — suppress every L4-derived match input so those terms fail
    // closed. The is-fragment bit above stays as-is (L3-only).
    let non_first_fragment =
        l3_declared.is_some_and(|packet| is_non_first_fragment(packet, meta.addr_family));
    // #2449 + #5568: ICMP/ICMPv6 type+code occupy the first 2 L4 bytes; they are
    // present ONLY if the DECLARED datagram reaches `l4 + 2`. The pre-#5568 gate
    // used the physical `frame.len()`, so Ethernet padding beyond a short declared
    // length (e.g. an IPv4 total-length of 20 with no declared ICMP body) could
    // read `type/code` — turning a non-match into a spurious `icmp-type 8`
    // (echo-request) PERMIT or false DENY. `declared_end == None` (frame too short
    // to hold the IP length field) fails closed.
    let icmp_type_code_present = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !non_first_fragment
        && declared_end.is_some_and(|end| l4.saturating_add(2) <= end);
    let l4_truncated_icmp = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !non_first_fragment
        && !icmp_type_code_present;
    // #5568: the shim-stamped `tcp_flags` is trustworthy only if the DECLARED
    // datagram reaches the TCP flags byte (`l4 + TCP_FLAGS_DECLARED_MIN`). A short
    // / padded TCP frame whose declared length stops before the flags byte had
    // those flags read from slack, so the tcp-flags terms must fail closed. A
    // legitimate TCP packet always declares >= 20 L4 bytes, so this never rejects
    // real traffic. `declared_end == None` fails closed.
    let tcp_flags_present = meta.protocol == PROTO_TCP
        && !non_first_fragment
        && declared_end.is_some_and(|end| l4.saturating_add(TCP_FLAGS_DECLARED_MIN) <= end);
    let l4_truncated_tcp =
        meta.protocol == PROTO_TCP && !non_first_fragment && !tcp_flags_present;
    let (tcp_flags, icmp_type, icmp_code) = if non_first_fragment {
        (0, 0, 0)
    } else if icmp_type_code_present {
        // Safe: `l4 + 2 <= declared_end <= frame.len()`, so both bytes lie in the
        // frame AND within the declared datagram (never slack).
        (
            meta.tcp_flags,
            frame.get(l4).copied().unwrap_or(0),
            frame.get(l4.wrapping_add(1)).copied().unwrap_or(0),
        )
    } else if l4_truncated_tcp {
        // TCP flags byte lies beyond the declared datagram — the shim read them
        // from slack. Fail closed (0 flags; `l4_present` dropped below).
        (0, 0, 0)
    } else if l4_truncated_icmp {
        // Truncated/padded ICMP — no real type/code bytes. Fail closed.
        (0, 0, 0)
    } else {
        (meta.tcp_flags, 0, 0)
    };
    // #9894 (GPT-2): `ports_unknown` stays `false` HERE, by design. This
    // builder sees (frame, meta) but never the flow, so it cannot know
    // whether the evaluated ports are real: a session-miss/flow-cache flow
    // carries real key ports even when this frame's L4 is unreadable (a
    // DMA-mutated slice on a cache hit must NOT veto the cached tuple it
    // was parsed from). The sites that KNOW their ports are synthetic —
    // the flowless input-filter/PBR evaluations running on an L3-only
    // enforcement context (ports 0-substituted by construction, #3291) —
    // set the bit themselves (`poll_descriptor/mod.rs`, `forwarding/pbr.rs`).
    // Deriving it here would over-gate real flows and under-gate L3 contexts
    // evaluated against frames with present-but-unevaluated L4 bytes.
    crate::filter::TermMatchExtra {
        tcp_flags,
        is_fragment,
        icmp_type,
        icmp_code,
        // The L4 header is absent on a non-first fragment, a truncated/padded ICMP
        // (type/code past the declared end, #2449/#5568), or a truncated/padded
        // TCP (flags byte past the declared end, #5568). The matcher gates
        // tcp-flags / icmp-type / icmp-code on this (a zeroed icmp byte is
        // otherwise a valid icmp-type 0 / icmp-code 0 match).
        l4_present: !non_first_fragment && !l4_truncated_icmp && !l4_truncated_tcp,
        // #3077: the L3 header slice (match-start layer-3) backs the
        // flexible-match-range byte-offset match. The byte offset is relative to
        // the start of the IP header. #5150: the slice ends at the IP-declared
        // datagram end, not frame.len(), so Ethernet slack cannot be matched.
        // `frame.get(l3..declared_end)` is None if the frame is shorter than
        // l3_offset (declared_end < l3 → invalid range) OR `declared_end` is
        // None, in which case the matcher's bounds check fails the flex term
        // closed.
        flex_l3: l3_declared,
        // #3232: the L4 header slice (match-start layer-4) backs a layer-4
        // flexible-match-range. The byte offset is relative to the start of the
        // transport header (`meta.l4_offset`). A NON-FIRST fragment carries no
        // L4 header there (its post-IP bytes are payload), so it gets None and a
        // layer-4 flex term fails closed. #5150: the slice ends at the
        // IP-declared datagram end (Ethernet slack excluded); if l4_offset is at
        // or past that end (e.g. a lying tiny IP length) the range is invalid and
        // yields None → fail closed. `frame.get` is also None if the frame is
        // shorter than l4_offset, in which case the matcher's bounds check fails
        // closed too.
        flex_l4: if non_first_fragment {
            None
        } else {
            declared_end.and_then(|end| frame.get(l4..end))
        },
        // #7992: these callers DO have real ports (flowless sites that do not
        // set the bit themselves — see above).
        ports_unknown: false,
    }
}

/// #2362 fold B: build the per-packet match inputs from metadata ALONE, for the
/// rare TX-selection callers that have no contiguous ingress frame slice
/// (locally-generated replies whose tuple is re-derived, ARP/NDP-deferred
/// forwards, control-plane injects). `tcp_flags` is taken from the
/// shim-stamped `meta` (authoritative on the forwarding path); `is_fragment`
/// and `icmp_type`/`icmp_code` cannot be read without the frame, so they are
/// 0/false — a CoS-action filter term keyed on is-fragment or icmp-type on one
/// of these non-transit paths under-matches rather than mis-matches. The common
/// `tcp-flags` CoS term is fully covered.
///
/// #3008 (meta sibling of #2449): the real ICMP type/code bytes are NOT
/// available on this meta-only path — there is no frame to read them from. The
/// pre-#3008 code stamped `icmp_type = icmp_code = 0` while leaving
/// `l4_present = true`, so any term keyed on `icmp-type 0` (echo-reply) or
/// `icmp-code 0` (a *valid*, common value) FALSE-MATCHED every ICMP-family
/// packet whose type/code was never parsed. The matcher gates the
/// icmp-type / icmp-code terms on `l4_present`, so for an ICMP/ICMPv6 packet on
/// this path we MUST drop `l4_present` to make those terms fail closed — the
/// type/code is genuinely unknown, so an `icmp-type N` / `icmp-code N` term must
/// NOT match. For non-ICMP protocols `l4_present` stays true so the
/// authoritative shim-stamped `tcp_flags` keeps matching (tcp-flags terms only
/// apply to TCP anyway). `icmp_type` / `icmp_code` are left 0 but are now inert
/// on the ICMP path because the `l4_present` gate rejects the term first.
#[inline]
pub(in crate::afxdp) fn term_match_extra_from_meta(
    meta: ForwardPacketMeta,
) -> crate::filter::TermMatchExtra<'static> {
    use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6};
    // #3008: the ICMP type/code bytes are unknown on the meta-only path (no
    // frame). A 0 byte is a real `icmp-type 0` / `icmp-code 0` value, so we must
    // signal "L4 type/code not parsed" to fail those terms closed. The matcher
    // shares one `l4_present` bit across tcp-flags and icmp-type/code; for an
    // ICMP-family packet there are no tcp-flags terms to preserve, so dropping
    // `l4_present` is safe and fails the icmp-type/code terms closed. For TCP/
    // UDP it stays true so authoritative `tcp_flags` matching is preserved.
    let is_icmp = matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6);
    crate::filter::TermMatchExtra {
        tcp_flags: meta.tcp_flags,
        is_fragment: false,
        icmp_type: 0,
        icmp_code: 0,
        // FALSE for ICMP/ICMPv6 (type/code genuinely unknown — fail
        // icmp-type/code terms closed); TRUE otherwise so the shim-stamped
        // tcp_flags still drives tcp-flags matching on synthetic/local TX.
        l4_present: !is_icmp,
        // #3077: no contiguous frame on this meta-only path, so there are no L3
        // bytes to read. A flex-constrained term fails closed here (the
        // flow-cache declines for such filters, so this path never carries one).
        flex_l3: None,
        // #3232: likewise no L4 bytes on the meta-only path — a layer-4 flex
        // term fails closed.
        flex_l4: None,
        // #7992: these callers DO have real ports.
        ports_unknown: false,
    }
}

// #6926: the address-classification group moved to `addr_class.rs` when this
// file crossed the 2000-LOC [REFACTOR] tier. Re-exported here rather than
// leaving callers to be rewritten: the tree reaches these by BOTH a bare `use`
// and a fully-qualified `crate::afxdp::frame::inspect::...` path, and the second
// would break on a move. See `addr_class.rs` for why this group was the seam.
pub(in crate::afxdp) use super::addr_class::{
    dest_is_directed_broadcast, dest_is_multicast_or_broadcast, l2_dst_is_group_or_broadcast,
    neighbor_ip_is_learnable, neighbor_mac_is_learnable, source_is_invalid_for_icmp_error,
    src_is_directed_broadcast,
};

/// Is the shim-stamped metadata tuple a RESOLVED flow identity, or only the
/// state the shim was in when it stopped parsing?
///
/// #4555/#6923 — the second question is why the `_ => true` arm is not the
/// whole answer. For IPv6 the shim's walk exits by EXHAUSTING `MAX_EXT_HDRS`
/// on an over-limit chain, and exhaustion is not an error there: it returns the
/// last declared next-header value, so `ParsedPacket::protocol` holds an
/// EXTENSION-HEADER type and `parse_l4`'s catch-all stamps ports 0/0. That
/// tuple has real addresses and a plausible-looking protocol, so the blanket
/// `_ => true` accepted it, `parse_session_flow_from_bytes` returned the
/// metadata flow, and every downstream consumer treated an uninspectable
/// packet as a resolved L4 flow. Concretely: `flow.is_none()` went false, so
/// the #4743 over-limit drop in the poll loop was SKIPPED; an
/// `application any` permit matched (no ports to fail on); and the session was
/// installed AND published to `USERSPACE_SESSIONS` under
/// `(AF_INET6, <ext-header type>, src, dst, 0, 0)` — which is EXACTLY the key
/// the shim probes for the next packet of that chain. The over-limit refusal
/// the shim documents as unconditional was in fact conditional on policy, and
/// after the first packet the chain had a fast path.
///
/// So an IPv6 metadata tuple whose protocol is one the walk TRAVERSES
/// ([`ipv6_ext_header_is_traversable`]) is NOT complete: it names where the
/// shim gave up, not an upper-layer protocol. Refusing it here makes the
/// metadata arm decline, the frame arm already declines (`parse_flow_ports`
/// has no case for an extension-header protocol), the meta-offset fallback
/// declines for the same reason, and `parse_session_flow_from_bytes` returns
/// `None` — which is the input the #4743 gate needs to fire and drop the
/// packet. IPv4 is untouched: 0/43/44/51/60/... are ordinary IPv4 protocol
/// numbers there, with no extension-header meaning.
pub(in crate::afxdp) fn metadata_tuple_complete(meta: UserspaceDpMeta, flow: &SessionFlow) -> bool {
    if flow.src_ip.is_unspecified() || flow.dst_ip.is_unspecified() {
        return false;
    }
    if meta.addr_family as i32 == libc::AF_INET6 && ipv6_ext_header_is_traversable(meta.protocol) {
        return false;
    }
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0,
        // ICMP/ICMPv6 keep their metadata tuple: the shim resolves a REAL
        // identifier for them (`parse_l4`'s ICMP arm reads bytes [l4+4, l4+6)),
        // and the meta-side gate in `parse_session_flow_from_bytes` has already
        // nulled `meta_flow` for every non-identifier-bearing type. An
        // identifier of 0 is legal, so this is deliberately not a non-zero
        // check like the TCP/UDP arm above.
        PROTO_ICMP | PROTO_ICMPV6 => true,
        // #6837: every other protocol is NOT complete.
        //
        // The question this function's NAME asks is "did the shim resolve an
        // L4 identity?". The `_ => true` this replaces answered a different
        // one — "are both addresses set?" — and that gap is the whole defect.
        // The shim resolves L4 for exactly TCP, UDP, ICMP and ICMPv6; its
        // `parse_l4` catch-all (`userspace-xdp/src/lib.rs`) returns
        // `Some((l4_offset, 0, 0, 0, 0))` for everything else. Those zeros are
        // a PLACEHOLDER, not a parse, and treating them as a resolved tuple is
        // what let GRE (47), ESP (50), AH (51), OSPF (89) and friends past.
        //
        // The consequence was not merely cosmetic. The frame side had already
        // refused these protocols (`parse_flow_ports` has no arm for them), so
        // the two sides disagreed and `parse_session_flow_from_bytes` resolved
        // the disagreement in favour of the side that had not parsed anything.
        // The packet then took the flow-backed arm and, on permit, installed
        // `SessionKey { protocol, src_port: 0, dst_port: 0, .. }` plus its
        // reverse companion — measured at two entries per transit flow, and
        // aliasing every distinct flow between one endpoint pair onto one key.
        //
        // Declining here makes the metadata arm agree with the frame arm, so
        // the packet stays flowless and takes the route-based, session-less
        // forward path (`frame/README.md`). Flowless is NOT a drop and NOT a
        // bypass: it still FORWARDS (measured), and since #3291 the flowless
        // transit arm applies zone policy, interface input filters and PBR.
        //
        // What is genuinely given up is STATEFUL RETURN ADMISSION for these
        // protocols, and their appearance in `show security flow session`.
        // Restoring a session for them requires a discriminator that is the
        // SAME in both directions — the RFC 2890 GRE Key qualifies, an RFC 2637
        // PPTP Call ID and an ESP SPI do not (they are allocated per-direction;
        // see `docs/userspace-native-gre-plan.md` §6e). That is #7188's typed
        // discriminator, on the PARSE side. It must not come back as a
        // metadata-side default.
        _ => false,
    }
}

/// The frame-relative byte offset at which the IPv4 datagram ENDS, as
/// declared by the IP header `total_len` (bytes [l3+2..l3+4]), clamped to
/// `[l3 + ihl, frame.len()]`.
///
/// #2361 fail-CLOSED: the L4 port read MUST be bounded by the IP-DECLARED
/// packet end, not merely the backing slice. A frame whose `total_len`
/// declares a short datagram but carries trailing slack (NIC zero-pad on a
/// sub-60-byte frame, or attacker-supplied bytes) would otherwise have its
/// "ports" read from out-of-datagram bytes. We clamp to the slice so a
/// truncated capture (slice shorter than `total_len`) also fails closed
/// (the read still cannot exceed what is present). Mirrors the
/// `total_len.clamp(ihl, packet.len())` bound the sibling generated-reply
/// parser enforces (`generated.rs::parse_generated_v4`).
///
/// Returns `None` when the IPv4 header itself is truncated/malformed
/// (caller already validated `frame.len() >= l3 + 20` and `ihl >= 20`, so
/// this is belt-and-suspenders for stray callers).
pub(in crate::afxdp) fn ipv4_declared_l3_end(frame: &[u8], l3: usize) -> Option<usize> {
    if frame.len() < l3 + 20 {
        return None;
    }
    let ihl = usize::from(frame[l3] & 0x0f) * 4;
    // Fail closed when the buffer does not even hold the declared IHL
    // header (ihl can be 21..=60 with IPv4 options, but the meta-driven
    // callers do NOT validate ihl against the slice). This guard is also a
    // PANIC SAFETY invariant: the `clamp` below requires `min <= max`, i.e.
    // `l3 + ihl <= frame.len()`. Without this guard a crafted frame with
    // IHL nibble = 15 (60 bytes) in a buffer truncated to l3+20 would give
    // `clamp(min = l3+60, max = l3+20)` -> `min > max` -> panic (DoS).
    if ihl < 20 || frame.len() < l3 + ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]) as usize;
    Some(l3.saturating_add(total_len).clamp(l3 + ihl, frame.len()))
}

/// The frame-relative byte offset at which the IPv6 datagram ENDS, as
/// declared by the fixed-header `payload_len` (bytes [l3+4..l3+6]), clamped
/// to `[l3 + 40, frame.len()]`.
///
/// #2361 fail-CLOSED counterpart of [`ipv4_declared_l3_end`]: the IPv6
/// packet end is `l3 + 40 + payload_len`. Mirrors the
/// `(40 + payload_len).clamp(40, packet.len())` bound in
/// `generated.rs::parse_generated_v6`.
pub(in crate::afxdp) fn ipv6_declared_l3_end(frame: &[u8], l3: usize) -> Option<usize> {
    if frame.len() < l3 + 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
    Some(
        l3.saturating_add(40)
            .saturating_add(payload_len)
            .clamp(l3 + 40, frame.len()),
    )
}

/// IP-declared datagram end for either family, given the L3 offset and the
/// address family. `None` for an unknown family or a truncated L3 header.
pub(in crate::afxdp) fn declared_l3_end(frame: &[u8], l3: usize, addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => ipv4_declared_l3_end(frame, l3),
        libc::AF_INET6 => ipv6_declared_l3_end(frame, l3),
        _ => None,
    }
}

/// Read the L4 ports at `l4`, bounded by BOTH the backing slice AND the
/// IP-DECLARED packet end (`declared_end`, the slice-clamped
/// `ipv4_declared_l3_end` / `ipv6_declared_l3_end`).
///
/// #2361 fail-CLOSED: TCP/UDP need 4 port bytes at `[l4, l4+4)`; ICMP/ICMPv6
/// read the 2 identifier bytes at `[l4+4, l4+6)`. The read MUST lie entirely
/// within `declared_end`. When the IP header declares a datagram that ends
/// BEFORE the L4 ports — even though the backing buffer still holds trailing
/// slack/padding bytes — this returns `None` rather than synthesizing ports
/// from out-of-datagram bytes. The caller treats `None` as flowless (the
/// packet follows the route-based, session-less forward path, consistent with
/// the #2344 non-first-fragment handling), so out-of-packet bytes never drive
/// policy / firewall-filter / CoS / session installation. This is the same
/// invariant the sibling generated-reply parser enforces via
/// `generated.rs::generated_l4_ports`.
/// #3067/#3290: the ICMP/ICMPv6 types whose 3rd/4th header bytes
/// (`[l4+4..l4+6]`) are a genuine Identifier usable as a stateful
/// pseudo source port. Echo Request/Reply carry one in both families;
/// ICMPv4 additionally has the Timestamp and Information query+reply
/// pairs (same offset per RFC 792). For every error/control type
/// (Dest-Unreachable, Packet-Too-Big, Time-Exceeded, Parameter-Problem,
/// Redirect, ND/MLD, ...) those bytes are part of a gateway address /
/// next-hop MTU / pointer / unused word — NOT a port.
///
/// This is the single predicate shared by the frame port parser
/// (`parse_flow_ports`) and the metadata-fallback gate in
/// `parse_session_flow_from_bytes` (#3290), so both arms honor the SAME
/// query-type rule and the shim's ungated pseudo-port can never install a
/// fake session for a non-query ICMP packet.
#[inline]
pub(in crate::afxdp) fn icmp_identifier_bearing(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        // Echo Reply (0) / Echo Request (8), Timestamp Request (13) /
        // Reply (14), Information Request (15) / Reply (16).
        PROTO_ICMP => matches!(icmp_type, 0 | 8 | 13 | 14 | 15 | 16),
        // Echo Request (128) / Echo Reply (129).
        PROTO_ICMPV6 => matches!(icmp_type, 128 | 129),
        _ => false,
    }
}

/// #10637: is this ICMP/ICMPv6 type a query ANSWER (vs a query itself)?
///
/// Echo Reply (0), Timestamp Reply (14), Information Reply (16); ICMPv6
/// Echo Reply (129). A reverse-direction packet of one of these types is
/// return traffic for the live query session it hits — Junos permits it
/// because the session exists, not because a policy admits the reverse
/// pair — so the owner-hit type gate coasts. Any other type in the
/// reverse direction originates a NEW query that merely shares the
/// typeless session key, and must face reverse-direction policy exactly
/// as the miss path would judge it. Non-identifier types (errors,
/// ND/MLD, ...) can never hit a session companion (#3290 gates them
/// flowless), so answering "not a reply" for them is unreachable
/// fail-closed, never a behavior change.
#[inline]
pub(in crate::afxdp) fn icmp_reply_type(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        PROTO_ICMP => matches!(icmp_type, 0 | 14 | 16),
        PROTO_ICMPV6 => matches!(icmp_type, 129),
        _ => false,
    }
}

/// #3290: report whether the metadata-stamped ICMP/ICMPv6 pseudo-port may be
/// trusted as a stateful identifier — frame-EQUIVALENT to the
/// `parse_flow_ports` gate. Two conditions must hold, both bounded by the
/// IP-declared datagram end (the #2361 fail-closed invariant, since trailing
/// slack is not authoritative):
///
/// 1. the ICMP type byte at `l4` lies inside the declared datagram AND is an
///    identifier-bearing query type, and
/// 2. the full 2-byte Identifier at `[l4+4..l4+6)` ALSO lies inside the
///    declared datagram.
///
/// Condition 2 is what `parse_flow_ports` enforces with its `ident_end >
/// declared_end` check: a query packet truncated between the type byte and the
/// identifier yields `None` there, so the meta gate must agree or the shim's
/// pseudo-port (read from bytes outside the declared datagram) would still
/// install a metadata-keyed session. Returns `false` (fail closed -> suppress
/// the metadata pseudo-port fallback) on any malformed/truncated input. Only
/// gates the metadata fallback; the frame parsers re-derive the type
/// independently.
pub(in crate::afxdp) fn meta_icmp_identifier_bearing(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    // SPARK-m4: verify L3 before deriving the declared end (see above).
    let l3 = verified_l3_or_stamp(frame, meta.l3_offset, meta.addr_family);
    let l4 = meta.l4_offset as usize;
    let declared_end = match meta.addr_family as i32 {
        libc::AF_INET => ipv4_declared_l3_end(frame, l3),
        libc::AF_INET6 => ipv6_declared_l3_end(frame, l3),
        _ => None,
    };
    let Some(declared_end) = declared_end else {
        return false;
    };
    if l4 >= declared_end {
        return false;
    }
    // Frame-equivalent to parse_flow_ports: the identifier bytes [l4+4..l4+6)
    // must lie within the IP-declared datagram, not merely the type byte.
    match l4.checked_add(6) {
        Some(ident_end) if ident_end <= declared_end => {}
        _ => return false,
    }
    match frame.get(l4) {
        Some(&icmp_type) => icmp_identifier_bearing(meta.protocol, icmp_type),
        None => false,
    }
}

/// #9894: report whether the 4 TCP/UDP port bytes the shim stamped into
/// metadata lie inside the IP-declared datagram — the #2361 fail-closed
/// invariant, applied to the metadata fast path.
///
/// The shim bounds its L4 read by the frame end INCLUDING trailing slack
/// (`parse_l4` in `userspace-xdp/src/lib.rs` reads against `data_end` and
/// never consults IPv4 `total_len`), so a short declared length with trailing
/// slack arrives with a metadata tuple spelled from out-of-datagram bytes.
/// `metadata_tuple_complete` carries no length dimension, so both
/// metadata-return sites in `parse_session_flow_from_bytes` (the TCP/UDP fast
/// path and the agreement arm) must consult this gate: `[l4, l4+4)` MUST lie
/// within `declared_l3_end`, the same bound `parse_flow_ports` enforces for
/// the frame-led read. Returns `false` (fail closed -> fall through to the
/// frame parse, which re-derives and re-bounds everything from bytes) on any
/// malformed/truncated input. One comparison, no re-parse, so the hot-path
/// cost argument for the fast path is preserved.
#[inline]
pub(in crate::afxdp) fn meta_l4_ports_in_declared_end(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    // SPARK-m4: verify L3 before deriving the declared end (see above).
    let l3 = verified_l3_or_stamp(frame, meta.l3_offset, meta.addr_family);
    let l4 = meta.l4_offset as usize;
    let Some(declared_end) = declared_l3_end(frame, l3, meta.addr_family) else {
        return false;
    };
    match l4.checked_add(4) {
        Some(end) if end <= declared_end => true,
        _ => false,
    }
}

pub(in crate::afxdp) fn parse_flow_ports(
    frame: &[u8],
    l4: usize,
    protocol: u8,
    declared_end: usize,
) -> Option<(u16, u16)> {
    match protocol {
        PROTO_TCP | PROTO_UDP => {
            let end = l4.checked_add(4)?;
            if end > declared_end {
                return None;
            }
            let bytes = frame.get(l4..end)?;
            Some((
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            // #3067: bytes [l4+4, l4+6) are the ICMP/ICMPv6 Identifier ONLY for
            // the identifier-bearing query types. For ICMPv4 those are Echo
            // Request/Reply and the Timestamp/Information query+reply pairs (the
            // Identifier sits at the same offset for all of them, per RFC 792);
            // for ICMPv6 only Echo Request/Reply (RFC 4443). For error and
            // control messages — Dest-Unreachable, Packet-Too-Big,
            // Time-Exceeded, Parameter-Problem, Redirect, and the ND/MLD types —
            // those two bytes are NOT a port: they are part of a gateway
            // address, the next-hop MTU, a pointer, or an unused/reserved field.
            // Treating them as a pseudo source port installed bogus
            // identifier-keyed stateful sessions for transit ICMP control
            // traffic, polluting the session table and risking spurious
            // collisions. Return `None` (the caller's "flowless" sentinel) for
            // every non-query type so the packet takes the session-less,
            // route-based forward path instead of installing a fake session.
            //
            // The type byte at `l4` must itself lie within the IP-declared
            // datagram (the #2361 fail-closed invariant); a type byte read from
            // trailing slack past `declared_end` is not authoritative.
            if l4 >= declared_end {
                return None;
            }
            let icmp_type = *frame.get(l4)?;
            if !icmp_identifier_bearing(protocol, icmp_type) {
                return None;
            }
            let ident_start = l4.checked_add(4)?;
            let ident_end = l4.checked_add(6)?;
            if ident_end > declared_end {
                return None;
            }
            let bytes = frame.get(ident_start..ident_end)?;
            let ident = u16::from_be_bytes([bytes[0], bytes[1]]);
            Some((ident, 0))
        }
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn authoritative_forward_ports(
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    if let Some(flow_ports) = flow.and_then(|flow| {
        if flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0 {
            Some((flow.forward_key.src_port, flow.forward_key.dst_port))
        } else {
            None
        }
    }) {
        return Some(flow_ports);
    }
    // #9894 (GPT-3): the metadata last resort is trusted ONLY when the 4
    // port bytes lie inside the IP-declared datagram. Without this, a short
    // total_len + slack-ports frame (flowless after the fast-path gate, and
    // frame-portless after the #2361 bound) would still emit the phantom
    // stamped tuple as `expected_ports` — and `enforce_expected_ports`
    // would write it into the frame. `None` means "no authoritative ports":
    // enforcement is skipped and TX hashing falls back port-less.
    let meta_ports = if meta.flow_src_port != 0
        && meta.flow_dst_port != 0
        && meta_l4_ports_in_declared_end(frame, meta)
    {
        Some((meta.flow_src_port, meta.flow_dst_port))
    } else {
        None
    };
    let frame_ports = live_frame_ports_from_meta_bytes(frame, meta);
    frame_ports.or(meta_ports)
}

#[allow(dead_code)]
pub(in crate::afxdp) fn live_frame_ports(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    live_frame_ports_from_meta_bytes(frame, meta)
}

#[inline(always)]
pub(in crate::afxdp) fn live_frame_ports_from_meta_bytes(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
) -> Option<(u16, u16)> {
    let meta = meta.into();
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    // SPARK-M5: the meta fast arm may only fire on a VERIFIED L3 — derive
    // the declared end from the nibble-checked offset, and distrust the L4
    // stamp with a distrusted L3 (`l4 = 0` forces the wire fallback below).
    // A wrong-but-plausible stamp pair otherwise returns WRONG ports with no
    // fallback, and these ports feed `enforce_expected_ports*` frame writes.
    // Double-garbage keeps the old stamp-indexed attempt (bounded as before).
    let (l3, l4) = match nibble_checked_l3(frame, meta.l3_offset, meta.addr_family) {
        Some(checked) if checked.stamp_trusted => (checked.l3, meta.l4_offset as usize),
        Some(checked) => (checked.l3, 0),
        None => (meta.l3_offset as usize, meta.l4_offset as usize),
    };
    // #2361: bound the meta-stamped L4 read by the IP-declared packet end,
    // not just the slice. The XDP shim stamps `meta.l4_offset` but does NOT
    // enforce that the L4 header lies inside the IP-declared datagram, so a
    // frame with a short total_len/payload_len + trailing slack could have
    // its ports read past the datagram. We re-derive the declared end from
    // the L3 header in the frame (using the checked `l3`). If the meta
    // offsets are unusable, fall through to the byte-led parser, which
    // re-derives both L3 and the declared end from the frame.
    if l4 != 0
        && let Some(declared_end) = declared_l3_end(frame, l3, meta.addr_family)
        && let Some(ports) = parse_flow_ports(frame, l4, meta.protocol, declared_end)
    {
        return Some(ports);
    }
    live_frame_ports_bytes(frame, meta.addr_family, meta.protocol)
}

pub(in crate::afxdp) fn live_frame_ports_bytes(
    frame: &[u8],
    addr_family: u8,
    protocol: u8,
) -> Option<(u16, u16)> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let l3 = frame_l3_offset(frame)?;
    let l4 = frame_l4_offset(frame, addr_family)?;
    // #2361: bound by the IP-declared packet end (re-derived from the frame),
    // not just the backing slice.
    let declared_end = declared_l3_end(frame, l3, addr_family)?;
    parse_flow_ports(frame, l4, protocol, declared_end)
}

pub(in crate::afxdp) fn forward_tuple_mismatch_reason(
    source_ports: Option<(u16, u16)>,
    expected_ports: Option<(u16, u16)>,
    built_ports: Option<(u16, u16)>,
) -> Option<String> {
    let expected = expected_ports.or(source_ports)?;
    let built = built_ports?;
    if built == expected {
        return None;
    }
    let source = source_ports.unwrap_or((0, 0));
    Some(format!(
        "forward_tuple_mismatch:src={}:{} expected={}:{} built={}:{}",
        source.0, source.1, expected.0, expected.1, built.0, built.1
    ))
}

/// #9782: translate a pre-NAT port expectation into the post-NAT tuple a
/// correct builder must have emitted, for the debug-only post-build
/// mismatch check (`forward_tuple_mismatch_reason`).
///
/// `expected_ports`/`source_ports` are the arrival-tuple authorities
/// (session-flow/frame bytes). The translation applies to the EFFECTIVE
/// expectation (`expected_ports.or(source_ports)`, mirroring the reason
/// function); callers keep passing the ORIGINAL `source_ports` through so
/// the diagnostic still shows the arrival tuple. Both `None` stays `None`
/// (no authority — the reason function skips, as before).
///
/// `nat_applied == false` (FabricRedirect with `apply_nat_on_fabric ==
/// false`, where builders suppress NAT) is the identity: the arrival
/// tuple stands. Callers derive it from the same gate the builders use.
///
/// Layer bound: ports only. Outputs whose parsers yield no TCP/UDP tuple
/// (`built == None` — NAT64 cross-family frames, tunnel encap) still skip
/// exactly as before; this never fabricates an authority where none
/// exists. Only same-family TCP/UDP translated output changes verdict.
pub(in crate::afxdp) fn post_nat_expected_ports(
    expected_ports: Option<(u16, u16)>,
    source_ports: Option<(u16, u16)>,
    nat: NatDecision,
    nat_applied: bool,
) -> Option<(u16, u16)> {
    let (src, dst) = expected_ports.or(source_ports)?;
    if !nat_applied {
        return Some((src, dst));
    }
    Some((
        nat.rewrite_src_port.unwrap_or(src),
        nat.rewrite_dst_port.unwrap_or(dst),
    ))
}

/// #2344: resolve the L3-relative slice the way the SessionFlow frame
/// parsers do (prefer `meta.l3_offset` when it points at a frame byte
/// whose IP-version nibble matches `addr_family`, else fall back to
/// `frame_l3_offset`) and run the family-aware non-first-fragment
/// predicate over it. Returns `true` only when the packet is positively
/// identified as a non-first fragment; an unresolvable/too-short frame
/// returns `false` (the downstream parser length guards reject it).
pub(in crate::afxdp) fn frame_is_non_first_fragment(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    let expected_version = match meta.addr_family as i32 {
        libc::AF_INET => 4u8,
        libc::AF_INET6 => 6u8,
        _ => return false,
    };
    let l3 = match meta.l3_offset {
        14 | 18
            if frame
                .get(meta.l3_offset as usize)
                .is_some_and(|byte| (byte >> 4) == expected_version) =>
        {
            meta.l3_offset as usize
        }
        _ => match frame_l3_offset(frame) {
            Some(off) => off,
            None => return false,
        },
    };
    // Only flag a fragment when the byte at the resolved L3 offset is a
    // real IP header whose version matches the metadata family. Without
    // this the predicate would read the fragment-offset bytes out of a
    // garbage/non-IP frame whose flow tuple is carried entirely in
    // metadata (e.g. the meta-led ICMP fixtures), spuriously suppressing
    // a legitimate flow. The downstream parsers already re-derive L3,
    // so this only guards the early-exit decision.
    if frame
        .get(l3)
        .is_none_or(|byte| (byte >> 4) != expected_version)
    {
        return false;
    }
    match frame.get(l3..) {
        Some(slice) => is_non_first_fragment(slice, meta.addr_family),
        None => false,
    }
}

pub(in crate::afxdp) fn parse_session_flow_from_bytes(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    // #2344: a non-first IP fragment carries no L4 header. Refuse to build
    // any ported SessionFlow for it — this is the single chokepoint that
    // also defeats the meta fast path below (the XDP shim does NOT gate
    // non-first fragments, so `meta.flow_*_port` may hold payload bytes
    // read at the post-IP-header offset). Returning `None` makes the
    // fragment flowless: it follows the route-based, session-less forward
    // path instead of polluting policy / flow-cache / session indexes.
    // Composes with #1852 (NAT leaves gated on the same predicate) and
    // #2293-era screen fragment classification.
    if frame_is_non_first_fragment(frame, meta) {
        return None;
    }
    let meta_flow = parse_session_flow_from_meta(meta);
    // #3290: the metadata fallback below copies `meta.flow_src_port` verbatim
    // into the SessionKey, but the XDP shim stamps bytes [l4+4..l4+6] as
    // `flow_src_port` for EVERY ICMP/ICMPv6 type with NO query-type gate. An
    // ICMP error/control packet (Dest-Unreachable, Packet-Too-Big,
    // Time-Exceeded, Parameter-Problem, Redirect, ND/MLD, ...) would otherwise
    // install a stateful session keyed on a non-port control word, bypassing
    // the #3067 invariant the frame parser (`parse_flow_ports`) enforces.
    // Discard the metadata flow for a non-query ICMP type so the packet stays
    // flowless: `frame_flow` is already `None` for it (the frame parser gates),
    // and the offset fallback re-runs the same `parse_flow_ports` gate, so the
    // packet follows the session-less, route-based forward path. Only
    // identifier-bearing query types keep their metadata tuple (where it equals
    // the frame-derived identifier anyway).
    let meta_flow = match meta.protocol {
        PROTO_ICMP | PROTO_ICMPV6 if !meta_icmp_identifier_bearing(frame, meta) => None,
        _ => meta_flow,
    };
    // Fast path: for TCP/UDP with complete metadata tuple, use meta directly
    // without parsing the frame. This avoids extra L3/L4 parsing for the
    // common established-flow case.
    // #9894: a complete tuple is NOT sufficient — the shim reads L4 against
    // the frame end INCLUDING slack, so the 4 port bytes must ALSO lie inside
    // the IP-declared datagram (#2361). On failure fall through to the frame
    // parse (authoritative, declared-bounded), not to None.
    if matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
        && let Some(meta_flow) = meta_flow.as_ref()
        && metadata_tuple_complete(meta, meta_flow)
        && meta_l4_ports_in_declared_end(frame, meta)
    {
        return Some(meta_flow.clone());
    }

    let frame_flow = if matches!(meta.addr_family as i32, libc::AF_INET) {
        parse_ipv4_session_flow_from_frame(frame, meta)
    } else {
        parse_session_flow_from_frame(frame, meta)
    };

    // #9894: same declared-end gate as the fast path (defense-in-depth here:
    // TCP/UDP with a complete tuple already returned above, so this arm is
    // reachable only for ICMP, whose meta tuple passed the #3290 gate above).
    // Agreement stays IPs-ONLY (#3290 arbitration retained): the session key
    // must equal the key the shim probes (`live_userspace_session_action`
    // keys USERSPACE_SESSIONS on the STAMPED tuple) and the identifier the
    // forward path restores (`restore_l4_tuple_from_meta` writes
    // `meta.flow_src_port`). Preferring the frame identifier on disagreement
    // would key the session on an ident the shim never probes while emitting
    // another — a session/wire split. TCP/UDP never reach this arm with a
    // complete tuple (the fast path returns first), so the length fix for
    // them lives entirely in the fast-path gate above.
    if let Some(meta_flow) = meta_flow
        && metadata_tuple_complete(meta, &meta_flow)
        && meta_l4_ports_in_declared_end(frame, meta)
    {
        if let Some(ref frame_flow) = frame_flow {
            if frame_flow.src_ip == meta_flow.src_ip && frame_flow.dst_ip == meta_flow.dst_ip {
                return Some(meta_flow);
            }
            return Some(frame_flow.clone());
        }
        return Some(meta_flow);
    }

    if let Some(flow) = frame_flow {
        return Some(flow);
    }

    // #9900 F-095 (SPARK-m4+): last-resort meta-offset fallback — verify the
    // stamp before fabricating a session key from it. A distrusted stamp
    // derives L3 from the wire and L4 along with it (GPT-5 coherence: a
    // corrected L3 with a stale L4 mis-keys the flow); if neither resolves,
    // decline rather than keying a session on garbage bytes.
    let checked = nibble_checked_l3(frame, meta.l3_offset, meta.addr_family)?;
    let l3 = checked.l3;
    let l4 = if checked.stamp_trusted {
        meta.l4_offset as usize
    } else {
        frame_l4_offset(frame, meta.addr_family)?
    };
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 || frame.len() < l4 {
                return None;
            }
            // #2344: same non-first-fragment gate as the frame parsers —
            // this meta-offset fallback must not fabricate ports either.
            if ipv4_is_non_first_fragment(&frame[l3..]) {
                return None;
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 12],
                frame[l3 + 13],
                frame[l3 + 14],
                frame[l3 + 15],
            ));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            ));
            // #2361: bound by the IP-declared packet end, not just the slice.
            let declared_end = ipv4_declared_l3_end(frame, l3)?;
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol, declared_end)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                                    discriminator: Default::default(),
                                    routing_domain: 0,
                },
            })
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            // #2344: same non-first-fragment gate as the frame parsers.
            if ipv6_is_non_first_fragment(&frame[l3..]) {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            // #2361: bound by the IP-declared packet end, not just the slice.
            let declared_end = ipv6_declared_l3_end(frame, l3)?;
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol, declared_end)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                                    discriminator: Default::default(),
                                    routing_domain: 0,
                },
            })
        }
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn parse_session_flow(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_session_flow_from_bytes(frame, meta)
}

/// Decode an Ethernet frame into a human-readable summary showing IP src/dst,
/// TCP/UDP ports, TCP flags, and checksums. For debugging packet forwarding.
pub(in crate::afxdp) fn decode_frame_summary(frame: &[u8]) -> String {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return String::new(),
    };
    let ip = &frame[l3..];
    if ip.len() < 20 {
        return String::new();
    }
    let version = ip[0] >> 4;
    if version == 4 {
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let total_len = u16::from_be_bytes([ip[2], ip[3]]);
        let protocol = ip[9];
        let ip_csum = u16::from_be_bytes([ip[10], ip[11]]);
        let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
        let ttl = ip[8];
        if matches!(protocol, PROTO_TCP | PROTO_UDP) && ip.len() >= ihl + 8 {
            let l4 = &ip[ihl..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if protocol == PROTO_TCP && ip.len() >= ihl + 20 {
                let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
                let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
                let flags = l4[13];
                let tcp_csum = u16::from_be_bytes([l4[16], l4[17]]);
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv4 {}:{} -> {}:{} TCP [{flag_str}] seq={seq} ack={ack} ttl={ttl} ip_csum={ip_csum:#06x} tcp_csum={tcp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else if protocol == PROTO_UDP {
                let udp_csum = u16::from_be_bytes([l4[6], l4[7]]);
                format!(
                    "IPv4 {}:{} -> {}:{} UDP ttl={ttl} ip_csum={ip_csum:#06x} udp_csum={udp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else {
                format!(
                    "IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}",
                    src, dst
                )
            }
        } else {
            format!(
                "IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}",
                src, dst
            )
        }
    } else if version == 6 && ip.len() >= 40 {
        let payload_len = u16::from_be_bytes([ip[4], ip[5]]);
        let next_header = ip[6];
        let hop_limit = ip[7];
        let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap_or([0; 16]));
        let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap_or([0; 16]));
        if matches!(next_header, PROTO_TCP | PROTO_UDP) && ip.len() >= 48 {
            let l4 = &ip[40..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if next_header == PROTO_TCP && ip.len() >= 60 {
                let flags = l4[13];
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv6 [{src}]:{sport} -> [{dst}]:{dport} TCP [{flag_str}] hop={hop_limit} pl={payload_len}"
                )
            } else {
                format!(
                    "IPv6 [{src}]:{sport} -> [{dst}]:{dport} proto={next_header} hop={hop_limit} pl={payload_len}"
                )
            }
        } else {
            format!("IPv6 [{src}] -> [{dst}] proto={next_header} hop={hop_limit} pl={payload_len}")
        }
    } else {
        String::new()
    }
}

pub(in crate::afxdp) fn parse_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    match meta.addr_family as i32 {
        libc::AF_INET => parse_ipv4_session_flow_from_frame(frame, meta),
        libc::AF_INET6 => {
            let l3 = match meta.l3_offset {
                14 | 18
                    if frame
                        .get(meta.l3_offset as usize)
                        .is_some_and(|byte| (byte >> 4) == 6) =>
                {
                    meta.l3_offset as usize
                }
                _ => frame_l3_offset(frame)?,
            };
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                l3.checked_add(meta_rel)?
            } else {
                frame_l4_offset(frame, meta.addr_family)?
            };
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            // #2344: a non-first IPv6 fragment (Fragment Header type 44
            // with a non-zero offset) carries NO L4 header. Refuse to
            // synthesize a ported SessionFlow for it; return `None` so the
            // fragment is flowless and follows the route-based forward
            // path. Same predicate #1852 uses for the NAT leaves, walked
            // over the L3-relative slice.
            if ipv6_is_non_first_fragment(&frame[l3..]) {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            // #2361: bound the L4 port read by the IP-declared packet end
            // (l3 + 40 + payload_len, slice-clamped), not just the slice.
            let declared_end = ipv6_declared_l3_end(frame, l3)?;
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol, declared_end)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                                    discriminator: Default::default(),
                                    routing_domain: 0,
                },
            })
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn parse_session_flow_from_meta(meta: UserspaceDpMeta) -> Option<SessionFlow> {
    let (src_ip, dst_ip) = match meta.addr_family as i32 {
        libc::AF_INET => {
            let src = meta.flow_src_addr.get(..4)?;
            let dst = meta.flow_dst_addr.get(..4)?;
            (
                IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
                IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
            )
        }
        libc::AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(meta.flow_src_addr)),
            IpAddr::V6(Ipv6Addr::from(meta.flow_dst_addr)),
        ),
        _ => return None,
    };
    if src_ip.is_unspecified() || dst_ip.is_unspecified() {
        return None;
    }
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip,
            dst_ip,
            src_port: meta.flow_src_port,
            dst_port: meta.flow_dst_port,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    })
}

/// #3291: build an L3-only [`SessionFlow`] (ports forced to 0) from the
/// shim-stamped `meta` L3 addresses, for the flowless transit enforcement gate.
///
/// A non-first fragment / no-L4 transit packet carries L3 identity
/// (src/dst/protocol) but NO L4 header (#2344: its post-IP bytes are payload,
/// never ports). The returned flow therefore has `src_port = dst_port = 0`;
/// callers MUST treat it as L4-absent (`l4_present = false`) so port-bearing
/// policy / filter terms fail CLOSED, and MUST NEVER insert it into any session
/// index — it exists only to drive zone-policy / input-filter / PBR evaluation
/// and the deny/log records. Returns `None` when the meta carries no usable L3
/// address (unspecified or non-IP family), in which case the caller leaves the
/// packet's existing (resolve-only) flowless behavior unchanged.
/// #7055: how many times a per-packet enforcement site was skipped because no
/// L3 identity could be derived from the metadata, split by WHICH leg fired.
///
/// The name says the leg deliberately. A single "no L3 identity" counter would
/// tell a future reader nothing about what to do, because the two legs have
/// opposite meanings:
///
///   - `L3_CTX_NONE_UNKNOWN_FAMILY` should stay at ZERO in production. The shim
///     writes `addr_family: parsed.addr_family` and `parsed` only ever comes
///     from `parse_ipv4`/`parse_ipv6`, which hard-code AF_INET/AF_INET6; a
///     packet whose parse fails never receives metadata at all. A non-zero value
///     here means that invariant broke — a metadata-layout or shim change — and
///     is a bug report, not a traffic observation.
///   - `L3_CTX_NONE_UNSPECIFIED_ADDR` is REACHABLE with ordinary (if unusual)
///     packets: the shim stamps `flow_{src,dst}_addr` faithfully, so an IP
///     header carrying `0.0.0.0`/`::` produces `None` from a fully parsed
///     packet. A dst-unspecified packet dies at NoRoute, but a SRC-unspecified
///     one with a valid destination routes normally. A non-zero value here is a
///     traffic observation, and on the fragment-association arms it means an
///     operator-configured control (`from is-fragment then discard`, the PBR
///     `then { routing-instance X; discard; }` term) was not evaluated.
///
/// Cumulative and process-global, like `INTERFACE_SNAT_PAT_COLLISIONS`, so tests
/// read them as a delta.
///
/// **`L3_CTX_NONE_UNKNOWN_FAMILY` counts without changing disposition.** An
/// unparseable family has no addresses to enforce against, so every site still
/// refuses and falls through. It is unreachable in production anyway.
///
/// **`L3_CTX_NONE_UNSPECIFIED_ADDR` no longer describes a bypass (#7890).**
/// This paragraph used to say the callers "still forward, and deliberately so",
/// because the same `if let Some(l3_flow)` gate sat on the association-HIT arm,
/// the session-MISS arm, the MissingNeighbor policy arm and — since #7480 — the
/// NoRoute policy arm, and diverging on one would have broken the hit/miss
/// parity invariant. #7890 changed all of them together, which is what that
/// invariant actually required: the four arms and the two flowless filter-log
/// sites now resolve through `l3_enforcement_flow_from_meta`, which answers the
/// ADDRESS question rather than the identity one and does not refuse an
/// unspecified address. The operator's configured verdict decides the packet.
///
/// The counter is kept, with its meaning restated on that function: "an
/// unspecified address was SEEN here", not "a lookup was refused". A test
/// asserts it MOVED before asserting what enforcement did, so a fixture that
/// misses a conjunct cannot pass proving nothing.
///
/// Each site is bound by a named cell, and the binding was measured by
/// site-local mutation against the full suite rather than assumed:
///
///   - `poll_descriptor` association-HIT arm —
///     `unspecified_source_association_hit_still_runs_the_input_filter_7890`
///   - `poll_descriptor` session-MISS arm —
///     `unspecified_source_still_runs_the_is_fragment_input_filter_7890`
///     (paired with `..._honours_a_non_discard_filter_verdict_7890`, which is
///     what distinguishes evaluating the filter from dropping on `None`)
///   - `poll_descriptor` NoRoute arm —
///     `unspecified_source_noroute_fragment_still_policy_denied_7890`
///   - `poll_descriptor` MissingNeighbor arm —
///     `unspecified_source_missing_neighbor_fragment_still_policy_denied_7890`
///   - the two `forward_request` flowless filter-log sites —
///     `unspecified_source_flowless_egress_filter_log_is_still_emitted_7890`,
///     which binds them as a PAIR: they form a fallback chain, so reverting
///     either alone leaves the suite green while reverting both reds that cell.
///
/// Two of those bindings are not the obvious ones, and both were found by
/// mutation rather than by reading:
///
///   - On the NoRoute arm, `forward == 0` does NOT bind anything — a NoRoute
///     packet does not forward either way. `policy_deny == 1` does.
///   - On the filter-log sites the failure is a MISSING LOG on a packet that
///     forwards correctly, so no packet-side observable can see it; the cell
///     has to read the event stream and assert the record's addresses.
///
/// The counters stay so the seam cannot be silently reopened by a future
/// metadata or resolver change.
pub(in crate::afxdp) static L3_CTX_NONE_UNKNOWN_FAMILY: AtomicU64 = AtomicU64::new(0);

/// See `L3_CTX_NONE_UNKNOWN_FAMILY`. This is the leg that is reachable in
/// production (#7055).
pub(in crate::afxdp) static L3_CTX_NONE_UNSPECIFIED_ADDR: AtomicU64 = AtomicU64::new(0);

pub(in crate::afxdp) fn l3_session_flow_from_meta(meta: UserspaceDpMeta) -> Option<SessionFlow> {
    let (src_ip, dst_ip) = match meta.addr_family as i32 {
        libc::AF_INET => {
            let src = meta.flow_src_addr.get(..4)?;
            let dst = meta.flow_dst_addr.get(..4)?;
            (
                IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
                IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
            )
        }
        libc::AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(meta.flow_src_addr)),
            IpAddr::V6(Ipv6Addr::from(meta.flow_dst_addr)),
        ),
        _ => {
            // #7055: the UNREACHABLE leg — see the counter's doc block.
            L3_CTX_NONE_UNKNOWN_FAMILY.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    if src_ip.is_unspecified() || dst_ip.is_unspecified() {
        // #7055: the REACHABLE leg — an IP header carrying 0.0.0.0/:: from a
        // fully parsed packet.
        //
        // #7890: refusing here is CORRECT for session identity — a session keyed
        // on `0.0.0.0` aliases every other unspecified-source flow — and it is
        // why this function keeps the refusal. It is NOT correct for the
        // enforcement sites, which need the packet's ADDRESSES rather than a
        // session; they use `l3_enforcement_flow_from_meta` below. One resolver
        // was answering both questions, and six call sites read a refusal of the
        // first as "nothing to enforce" for the second.
        L3_CTX_NONE_UNSPECIFIED_ADDR.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip,
            dst_ip,
            // #3291: NO L4 ports — a flowless packet's L4 header is absent.
            src_port: 0,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    })
}

/// The L3 context for ENFORCEMENT — interface filters, PBR and policy (#7890).
///
/// Identical to [`l3_session_flow_from_meta`] except that it does **not** refuse
/// an unspecified address.
///
/// **Why the two are different functions rather than one.** A session keyed on
/// `0.0.0.0` aliases every other unspecified-source flow, so refusing is right
/// for identity. But a per-packet interface filter, a PBR
/// `then { routing-instance X; discard; }` term and a zone policy do not need a
/// session — they need the packet's **addresses**, and those parsed fine. The
/// header carried `0.0.0.0`, which is a perfectly well-defined value to evaluate
/// a `from`-clause against.
///
/// So the enforcement sites get their own accessor and the operator's configured
/// verdict decides the packet's fate — rather than a session-identity refusal
/// silently substituting "forward" for whatever was configured.
///
/// **Still refuses an unparseable family**, which is the genuinely unusable case
/// (and unreachable in production: the shim only ever writes `AF_INET`/
/// `AF_INET6`).
///
/// It bumps the same `L3_CTX_NONE_UNSPECIFIED_ADDR` counter, which therefore now
/// means "an unspecified address was SEEN here", not "a lookup was refused".
/// That keeps it usable as the witness a test asserts to prove the arm was
/// entered before asserting what enforcement did.
pub(in crate::afxdp) fn l3_enforcement_flow_from_meta(
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    if let Some(flow) = l3_session_flow_from_meta(meta) {
        return Some(flow);
    }
    // Refused. Distinguish the two legs: an unparseable family has no addresses
    // to enforce against, an unspecified one does.
    let (src_ip, dst_ip) = ForwardPacketMeta::from(meta).l3_addrs_unfiltered()?;
    if !src_ip.is_unspecified() && !dst_ip.is_unspecified() {
        // Refused for some other reason; do not invent a context.
        return None;
    }
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip,
            dst_ip,
            // #3291: NO L4 ports — a flowless packet's L4 header is absent.
            src_port: 0,
            dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    })
}

pub(in crate::afxdp) fn parse_ipv4_session_flow_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    let l3 = match meta.l3_offset {
        14 | 18
            if frame
                .get(meta.l3_offset as usize)
                .is_some_and(|byte| (byte >> 4) == 4) =>
        {
            meta.l3_offset as usize
        }
        _ => frame_l3_offset(frame)?,
    };
    if frame.len() < l3 + 20 {
        return None;
    }
    let ihl = usize::from(frame[l3] & 0x0f) * 4;
    if ihl < 20 || frame.len() < l3 + ihl {
        return None;
    }
    let protocol = frame[l3 + 9];
    // #2344: a non-first IPv4 fragment carries NO L4 header — its
    // post-IP-header bytes are payload, not TCP/UDP ports. Refuse to
    // synthesize a ported SessionFlow for it. Returning `None` makes the
    // fragment flowless: it follows the route-based, session-less forward
    // path (the existing pre-#1913 "no flow tuple" behavior) instead of
    // polluting policy / flow-cache / session indexes with fake ports.
    // Mirrors #1852, which gates the NAT rewrite leaves on the same
    // `ipv4_is_non_first_fragment` predicate over the L3-relative slice.
    if ipv4_is_non_first_fragment(&frame[l3..]) {
        return None;
    }
    let parsed_l4 = l3 + ihl;
    let l4 = if meta.l4_offset > meta.l3_offset && meta.l4_offset as usize == parsed_l4 {
        meta.l4_offset as usize
    } else {
        parsed_l4
    };
    if frame.len() < l4 {
        return None;
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 12],
        frame[l3 + 13],
        frame[l3 + 14],
        frame[l3 + 15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 16],
        frame[l3 + 17],
        frame[l3 + 18],
        frame[l3 + 19],
    ));
    // #2361: bound the L4 port read by the IP-declared packet end
    // (l3 + total_len, slice-clamped), not just the slice. A short total_len
    // with trailing slack/padding must NOT yield ports from out-of-datagram
    // bytes.
    let declared_end = ipv4_declared_l3_end(frame, l3)?;
    let (src_port, dst_port) = parse_flow_ports(frame, l4, protocol, declared_end)?;
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn parse_zone_encoded_fabric_ingress(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
) -> Option<u16> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    parse_zone_encoded_fabric_ingress_from_frame(frame, meta, forwarding, ha_state, now_secs)
}

/// #919/#922: returns the encoded zone ID directly, no `zone_id_to_name`
/// lookup or `String` clone. Callers that need a name resolve via
/// `forwarding.zone_id_to_name` on the slow path. #3075: the id is a u16
/// carried big-endian across frame[10]/frame[11] of the synthetic fabric MAC.
///
/// #6458: the magic + zone-existence decode is necessary but NOT
/// sufficient — an L2-adjacent host on the fabric segment can forge both
/// (`StableZoneID` is a public name hash). The decoded zone is returned
/// only when `zone_encoded_fabric_stamp_valid` ALSO accepts the frame
/// (unicast dst == our fabric link MAC + the claimed zone is RG-bound and
/// not locally forwarding-active); otherwise the stamp is ignored and the
/// frame is treated as an ordinary unstamped fabric-ingress packet.
pub(in crate::afxdp) fn parse_zone_encoded_fabric_ingress_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
) -> Option<u16> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    if frame.len() < 12 {
        return None;
    }
    if frame[6] != 0x02
        || frame[7] != 0xbf
        || frame[8] != 0x72
        || frame[9] != FABRIC_ZONE_MAC_MAGIC
    {
        return None;
    }
    // #3075: zone id is a u16 carried big-endian in frame[10] (high) /
    // frame[11] (low). The old u8 scheme hardcoded frame[10]=0x00, which still
    // decodes correctly here (id < 256 has a 0 high byte).
    let id = u16::from_be_bytes([frame[10], frame[11]]);
    if id == 0 {
        return None;
    }
    // Validate the encoded ID exists in the configured zone map; an
    // unknown id is a stale or hostile frame. Single hash lookup —
    // the value isn't needed, just presence.
    if !forwarding.zone_id_to_name.contains_key(&id) {
        return None;
    }
    // #6458: fabric-link identity + RG-ownership validation (V1a/V1b).
    zone_encoded_fabric_stamp_valid(
        forwarding,
        ha_state,
        now_secs,
        &frame[0..6],
        meta.ingress_ifindex as i32,
        id,
    )
    .then_some(id)
}

pub(in crate::afxdp) fn parse_packet_destination_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    // #9900 F-095 (SPARK-M4): same judgment as the FIB twin — nibble-gate
    // the stamp, keep it as the fallback (read-only dst parse; double-garbage
    // keeps the old behavior instead of a new cliff).
    let l3 = verified_l3_or_stamp(frame, meta.l3_offset, meta.addr_family);
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            )))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            )))
        }
        _ => None,
    }
}

pub(in crate::afxdp) fn try_parse_metadata(
    area: &MmapArea,
    desc: XdpDesc,
) -> Option<UserspaceDpMeta> {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    if (desc.addr as usize) < meta_len {
        return None;
    }
    let meta_offset = (desc.addr as usize).checked_sub(meta_len)?;
    let bytes = area.slice(meta_offset, meta_len)?;
    // ptr::read_unaligned: bytes is &[u8] with no alignment guarantee;
    // dereferencing as *const UserspaceDpMeta directly would be UB on
    // architectures that fault on misaligned loads (the x86 host happens
    // to tolerate it but it's still UB and a portability footgun).
    //
    // #7176 (C179-019): this read stays unaligned and is correct as written.
    // The PRODUCER side (userspace-xdp/src/lib.rs) does a plain aligned store
    // to the same bytes, which reads as a contradiction with this comment. It
    // is not one: that store's alignment was measured on the shipped target
    // (5,989,142 samples, zero misaligned) and the producer carries the
    // invariant, the measurement, and the cost of making it explicit. Do not
    // "reconcile" the two by weakening this side to a plain deref — this side
    // is the one with no alignment guarantee to lose.
    let meta = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const UserspaceDpMeta) };
    if meta.magic != USERSPACE_META_MAGIC || meta.version != USERSPACE_META_VERSION {
        return None;
    }
    if meta.length as usize != meta_len {
        return None;
    }
    Some(meta)
}

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod inspect_iplen_tests;
