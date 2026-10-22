//! NAT64 stateless IPv6<->IPv4 packet translation cores.
//!
//! Extension-header/fragment eligibility, the `write_*_into` cores,
//! and the shared translate routines both frame builders call.
//!
//! #16188 PURE CODE MOTION: every line below was moved verbatim from
//! `nat64.rs` lines 2684-3869. The only edits are the visibility
//! widenings enumerated in `nat64/mod.rs`; no logic, no ordering and
//! no signature changed. The deliberate `checksum16*` one-line
//! forwards live in the sibling `checksum` submodule, untouched.

use super::*;

// ---------------------------------------------------------------------------
// Packet translation functions
// ---------------------------------------------------------------------------

pub(super) const ICMPV6_ECHO_REQUEST: u8 = 128;
pub(super) const ICMPV6_ECHO_REPLY: u8 = 129;
pub(super) const ICMP_ECHO_REQUEST: u8 = 8;
pub(super) const ICMP_ECHO_REPLY: u8 = 0;

// ICMPv6 error message types (RFC 4443).
pub(super) const ICMPV6_DEST_UNREACHABLE: u8 = 1;
pub(super) const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub(super) const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub(super) const ICMPV6_PARAMETER_PROBLEM: u8 = 4;

// ICMPv4 error message types (RFC 792).
pub(super) const ICMP_DEST_UNREACHABLE: u8 = 3;
pub(super) const ICMP_TIME_EXCEEDED: u8 = 11;
pub(super) const ICMP_PARAMETER_PROBLEM: u8 = 12;

/// Lower bound a Packet-Too-Big MTU is clamped to when it crosses the NAT64
/// boundary. The IPv6 minimum link MTU (RFC 8200) — a translated v6 client
/// must never be told to use a path MTU below this.
pub(super) const IPV6_MIN_MTU: u32 = 1280;

/// Upper bound an IPv6 Packet-Too-Big MTU is clamped to when translated to an
/// IPv4 Fragmentation-Needed Next-Hop-MTU. The v4 datagram is 20 bytes smaller
/// than the v6 one it was translated from (40-byte v6 header vs 20-byte v4
/// header), so a v6 path-MTU `M` corresponds to a v4 next-hop MTU of `M - 20`
/// (RFC 7915 5.2). Subtracting 20 keeps the advertised v4 MTU consistent with
/// the smaller translated datagram.
pub(super) const NAT64_HEADER_DELTA: u32 = 20;

/// RFC 1191 Table 7-1 plateaus (lowest MTU of each group), descending.
/// Used only when a pre-RFC 1191 router reports Next-Hop MTU 0 in a
/// Fragmentation-Needed message: RFC 7915 §4.2 requires the greatest
/// plateau below the quoted datagram's Total Length (floored at 1280).
const RFC1191_PLATEAUS: [u32; 11] = [
    65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
];

/// Greatest RFC 1191 plateau strictly below `quoted_total_len`, floored
/// at the IPv6 minimum MTU (1280). Values at or below 1280 therefore all
/// yield 1280; a length with no plateau >= 1280 below it also yields 1280.
pub(super) fn rfc1191_plateau_mtu(quoted_total_len: u32) -> u32 {
    RFC1191_PLATEAUS
        .iter()
        .copied()
        .find(|&p| p < quoted_total_len && p >= IPV6_MIN_MTU)
        .unwrap_or(IPV6_MIN_MTU)
}


/// Maximum embedded (quoted) original-packet bytes the ICMP-error translator
/// processes. RFC 4443 lets an ICMPv6 error quote "as much of the invoking
/// packet as possible" up to the IPv6 minimum MTU (1280). The translated
/// embedded packet is built into a fixed stack scratch buffer — NO per-packet
/// heap allocation (#2211) — sized for the v6 worst case; v4→v6 embedded
/// translation grows the header by 20 bytes, so the scratch headroom must cover
/// `1280 + 20`.
pub(super) const MAX_EMBEDDED_LEN: usize = 1280 + NAT64_HEADER_DELTA as usize;

/// Process-global IPv4 Identification generator for header-less translated
/// datagrams that leave DF clear. RFC 7915 §5.1 requires it for translated
/// IPv4 packets up to 1260 bytes; the local no-v6-frag-header option also uses
/// it when explicitly keeping larger packets fragmentable.
///
/// RFC 6864 §4.1 requires a source emitting non-atomic datagrams (DF=0) not
/// to repeat IDs for a given source/destination/protocol tuple within one
/// Maximum Datagram Lifetime. A monotonically incrementing counter is a cheap
/// generator; atomic datagrams (DF=1) are exempt and keep ID=0.
static NAT64_FRAG_ID: AtomicU32 = AtomicU32::new(0);

/// Return the next non-zero 16-bit Fragment Identification value for a
/// fragmentable translated datagram. The value cycles over the full non-zero
/// 16-bit space `1..=65535` with no two consecutive values equal WITHIN the
/// 65535-value cycle (the value after 65535 is 1, a jump, not a repeat).
/// Skipping 0 keeps the all-zero ID reserved (by convention) for the atomic
/// DF=1 path.
///
/// CAVEAT: at the outer `AtomicU32` counter wrap — once per 2^32 fragmentable
/// translations — two ADJACENT values do collide: `(2^32 - 1) % 65535 == 0`
/// and the wrapped `0 % 65535 == 0` both map to ID 1. This is deliberately
/// accepted (#2014 r3, Codex+AGY): IPv4's 16-bit Identification inherently
/// repeats every 65535 packets regardless, so one extra adjacent duplicate per
/// ~4.3e9 translations is operationally negligible and not worth replacing the
/// lock-free `fetch_add` with a CAS/modulo-65535 counter that would bounce a
/// cache line on this path.
pub(super) fn next_frag_id() -> u16 {
    // Relaxed is sufficient: we only need a distinct, non-repeating sequence,
    // not ordering against other memory. Map the monotonic 32-bit counter onto
    // 1..=65535 via `(raw % 65535) + 1`. This is what makes the sequence
    // collision-free for RFC 6864 4.1: a naive `truncate-to-u16 then remap 0->1`
    // maps BOTH raw=0 and raw=1 to 1, so two back-to-back DF=0 translations
    // would share an Identification (and the same dup recurs at every 16-bit
    // wrap). `% 65535 + 1` instead yields 1,2,...,65535,1,2,... — every adjacent
    // pair differs.
    let raw = NAT64_FRAG_ID.fetch_add(1, Ordering::Relaxed);
    map_frag_id(raw)
}

/// Pure mapping from a monotonic 32-bit counter value to the 1..=65535
/// Identification space. Factored out of `next_frag_id` so the cycle invariant
/// (non-zero, in-range, no consecutive duplicates within the 65535-value cycle
/// — see the `next_frag_id` caveat for the accepted 2^32-boundary edge) can be
/// unit-tested deterministically without touching the process-global counter.
#[inline]
pub(super) fn map_frag_id(raw: u32) -> u16 {
    (raw % 65535) as u16 + 1
}

/// Translate an IPv6 packet to IPv4 (forward direction: client→server).
///
/// Input: `packet` starts at L3 (IPv6 header), not Ethernet.
/// `snat_v4` = pool IPv4 source, `dst_v4` = extracted destination.
///
/// `no_v6_frag_header` mirrors the `security nat natv6v4 no-v6-frag-header`
/// option. It is an explicit local override: when true, header-less
/// IPv6→IPv4 output stays fragmentable regardless of size. Otherwise RFC 7915
/// §5.1 selects DF from the translated IPv4 total length: DF is clear through
/// 1260 bytes (with a generated non-zero Identification) and set above 1260
/// (with Identification 0). If an IPv6 Fragment Header is present, its
/// Identification and fragment geometry are preserved regardless of the option.
///
/// Whichever path clears DF, the Identification MUST be consistent with it: a
/// DF=0 datagram is non-atomic, so RFC 6864 §4.1 forbids a constant/repeated ID;
/// header-less outputs use the per-translator generator so downstream fragments
/// remain reassemblable rather than colliding on a constant ID.
///
/// Returns the translated IPv4 packet (L3 only, no Ethernet header).
///
/// Allocating convenience wrapper over [`write_v6_to_v4_into`]. Hot-path
/// callers (the frame builders) write straight into a reserved output buffer
/// with the `_into` core to avoid this per-packet `Vec` (#2211); this wrapper
/// is `#[cfg(test)]`-only — the differential tests use it to assert the `_into`
/// core is byte-identical to an owned-`Vec` translation. No production caller
/// allocates an owned NAT64 packet, so gating it on test keeps the release
/// build free of a dead-code path.
#[cfg(test)]
pub(crate) fn translate_v6_to_v4(
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    // Worst case (no shrink relative to input): 20-byte IPv4 header + the IPv6
    // L4 payload. The IPv6 input is `40 + payload_len`, so `20 + payload_len`
    // never exceeds the input length; sizing to the input length is a safe
    // upper bound, then we truncate to the exact written length.
    let mut out = vec![0u8; packet.len()];
    let written = write_v6_to_v4_into(&mut out, packet, snat_v4, dst_v4, no_v6_frag_header)?;
    out.truncate(written);
    Some(out)
}

/// Walk the IPv6 extension-header chain of an L3-relative IPv6 packet to find
/// the terminal transport header (#2290).
///
/// Returns `(l4_offset, l4_protocol)` where `l4_offset` is the byte offset of
/// the real transport header (TCP/UDP/ICMPv6/...) measured from the start of
/// the IPv6 header, and `l4_protocol` is its protocol number. Walks
/// Hop-by-Hop (0), Routing (43), Destination Options (60), AH (51), and
/// Fragment (44) headers, bounded to `MAX_IPV6_EXT_HEADERS` iterations
/// (RFC 8200 §4.1 — a fixed-order chain rarely exceeds a handful).
/// No-Next-Header (59) and a chain that runs off the end of the packet
/// return `None`.
///
/// #6435: this is now a thin fold over the ONE canonical walker,
/// `crate::afxdp::walk_ipv6_ext_chain` (`afxdp::frame::inspect`) — the same
/// walk the forwarding path's `packet_rel_l4_offset_and_protocol` folds, so
/// NAT64 and forwarding resolve the same L4 BY CONSTRUCTION (the #4435
/// bound-share made the bounds agree; this makes the loop itself agree).
/// Every non-`L4` verdict fails CLOSED (`None`), exactly like the canonical
/// walker (#2292): a chain still on an extension header at the
/// `MAX_IPV6_EXT_HEADERS` bound is `OverLimit`, NOT a terminal — before
/// #4435 the post-loop fall-through resolved one header deeper than the
/// canonical walker, a one-level parity skew at the bound.
///
/// The returned offset is only the START of the L4 header; the caller is
/// responsible for the non-first-fragment check (a non-first fragment carries
/// NO L4 header at this offset — its bytes are payload).
pub(super) fn ipv6_l4_offset_and_protocol(packet: &[u8]) -> Option<(usize, u8)> {
    let walk = walk_ipv6_ext_chain(packet, 0);
    match walk.outcome {
        ExtChainOutcome::L4(offset, protocol) => Some((offset, protocol)),
        // #14116: a non-first fragment carries no L4, but NAT64's L3-only
        // non-first translator needs the payload offset (first byte past
        // the Fragment header) and the Fragment header's Next Header —
        // exactly what the pre-#14116 walk surrendered by walking payload
        // to a terminal. The fragment sighting is already recorded; fail
        // closed if it is unreadable.
        ExtChainOutcome::NonFirstFragment => {
            let fragment = walk.fragment?;
            let bytes = fragment.bytes?;
            if walk.non_first_fragment_offset_seen {
                Some((fragment.header_offset + 8, bytes[0]))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// RFC 7915 §5.1 translation-eligibility gate (#5625).
///
/// Walk the IPv6 extension-header chain of an L3-relative IPv6 packet and
/// return `true` iff the packet carries an extension header that a stateless
/// NAT64 v6→v4 translation MUST NOT silently strip/translate. The forward
/// translator (`write_v6_to_v4_into` / `write_v6_to_v4_nonfirst_into`) calls
/// this BEFORE resolving the terminal L4 and rejects (fail-closed drop) when it
/// returns `true`, instead of letting `ipv6_l4_offset_and_protocol` walk PAST
/// the header and translate the deeper transport — which silently drops the
/// extension semantics (there is no IPv4 equivalent) or, for AH, emits an
/// IPv4 packet whose authentication no longer covers the rewritten header.
///
/// INELIGIBLE (returns `true` → drop):
///   * **Any extension header named by a Fragment Header's Next Header field**
///     — its bytes belong to the fragmentable part, so stripping it while
///     copying fragment offsets verbatim breaks reassembly geometry. RFC 7915
///     §5.1.1 says to drop this case (except ESP); applies to both first and
///     non-first fragments before the normal L4 walker can consume payload as
///     an extension header.
///   * **Authentication Header (51)** — AH's ICV covers IP header fields NAT64
///     rewrites (source/destination address), so a translated packet carries a
///     stale/broken ICV the receiver rejects. We extend the fragmented §5.1.1
///     drop to non-fragmented packets too, where the literal §5.1 "copy the Next
///     Header value" rule would otherwise strip AH and emit a broken protocol-51
///     IPv4 packet.
///   * **Routing header (43) with Segments Left > 0** — an ACTIVE source route
///     that has NOT reached its final destination. RFC 7915 §5.1: "If a Routing
///     header with a non-zero Segments Left field is present, then the packet
///     MUST NOT be translated". (Segments Left == 0 is inert and handled below.)
///   * **Mobility (135) / HIP (139) / Shim6 (140)** — active end-to-end
///     extension semantics with NO IPv4 equivalent. The parity walker
///     (`ipv6_l4_offset_and_protocol`, #4517) walks PAST them to resolve the
///     inner L4, so translating would silently strip them and break the
///     protocol (Mobility binding updates, HIP handshakes, Shim6 locator
///     management). Reject rather than translate-and-strip.
///
/// ELIGIBLE (returns `false` → translate normally, no over-reject):
///   * **Hop-by-Hop Options (0) / Destination Options (60) / Routing with
///     Segments Left == 0 (43)** before any Fragment header — RFC 7915 §5.1:
///     "those IPv6 extension headers MUST be ignored ... and the packet
///     translated normally." A header after Fragment is rejected above.
///   * **Fragment (44)** with a real upper-layer Next Header — NAT64's fragment
///     logic owns it.
///   * **ESP (50)** — not flagged here; it falls through to the translator's
///     protocol match, which already drops it (not TCP/UDP/ICMPv6). Unchanged.
///   * **No Next Header (59)** and a real upper-layer protocol — eligible.
///   * A **malformed/truncated** chain is NOT flagged ineligible here; it is
///     dropped fail-closed by the translator's own length guards /
///     `ipv6_l4_offset_and_protocol` returning `None`.
///
/// This gate is NAT64-translate-path specific: it does NOT change the L4
/// resolution the forwarding/screen parity walkers perform (#4435). Bounded to
/// `MAX_IPV6_EXT_HEADERS` like the sibling walkers. For ordinary traffic (the
/// first Next Header is TCP/UDP/ICMPv6) this returns on the first iteration
/// with zero extension-header reads, so the fast path is unaffected.
pub(super) fn nat64_v6_translation_ineligible(packet: &[u8]) -> bool {
    if packet.len() < 40 {
        return false; // too short → the translator's length guard drops it
    }
    let mut protocol = packet[6];
    let mut offset = 40usize;
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        match protocol {
            // Authentication Header (51): ICV covers rewritten IP fields —
            // MUST NOT translate. RFC 7915 §5.1.1.
            51 => return true,
            // Mobility (135) / HIP (139) / Shim6 (140): active end-to-end
            // semantics with no IPv4 equivalent — reject rather than strip.
            135 | 139 | 140 => return true,
            // Routing header (43): ineligible ONLY when Segments Left > 0 (an
            // active, not-yet-delivered source route — RFC 7915 §5.1). A
            // Routing header with Segments Left == 0 is inert; skip it.
            43 => {
                let hdr = match packet.get(offset..offset + 4) {
                    Some(h) => h,
                    None => return false, // truncated → translator drops it
                };
                if hdr[3] > 0 {
                    return true; // Segments Left > 0 → active source route
                }
                protocol = hdr[0];
                offset = match offset.checked_add((usize::from(hdr[1]) + 1) * 8) {
                    Some(o) => o,
                    None => return false,
                };
                if packet.len() < offset {
                    return false;
                }
            }
            // Hop-by-Hop (0) / Destination Options (60) / experimental
            // (253/254): "MUST be ignored ... translated normally" (RFC 7915
            // §5.1). Length in 8-byte units, not counting the first 8 bytes.
            0 | 60 | 253 | 254 => {
                let hdr = match packet.get(offset..offset + 2) {
                    Some(h) => h,
                    None => return false,
                };
                protocol = hdr[0];
                offset = match offset.checked_add((usize::from(hdr[1]) + 1) * 8) {
                    Some(o) => o,
                    None => return false,
                };
                if packet.len() < offset {
                    return false;
                }
            }
            // Fragment header (44): fixed 8 bytes; NAT64 fragment logic owns it.
            44 => {
                let frag = match packet.get(offset..offset + 8) {
                    Some(f) => f,
                    None => return false,
                };
                // #10860: fragmentable-part extension headers are stripped by
                // NAT64 but their bytes are included in sender fragment offsets.
                // Copying those offsets verbatim would leave a reassembly hole;
                // it also makes the L4 walker mistake non-first payload for an
                // extension header. RFC 7915 §5.1.1 says SHOULD drop this case,
                // except ESP (not traversed by the shared extension walker).
                if ipv6_ext_header_is_traversable(frag[0]) {
                    return true;
                }
                protocol = frag[0];
                offset = match offset.checked_add(8) {
                    Some(o) => o,
                    None => return false,
                };
                if packet.len() < offset {
                    return false;
                }
            }
            // No Next Header (59) or a real upper-layer protocol → eligible.
            _ => return false,
        }
    }
    // Chain still on an extension header after the bound: not classified as an
    // eligibility reject here — the translator's `ipv6_l4_offset_and_protocol`
    // fails CLOSED (`None`) at the same bound (#4435), so the packet is dropped
    // regardless. Do not double-attribute it to the ext-header counter.
    false
}

/// #5625: does this L2 frame trigger a NAT64 RFC 7915 §5.1 translation-
/// eligibility drop for the given ingress address family? Only the forward
/// (`AF_INET6` → v6→v4) direction can carry IPv6 extension headers; IPv4 has no
/// extension headers, so the reverse (`AF_INET`) direction is always `false`.
///
/// Used by the TX dispatcher to attribute a NAT64 build-returned-`None` to the
/// `nat64_exthdr_ineligible` counter without re-deriving the reason inline,
/// mirroring `frame_is_nat64_fragment_drop` (#2562). Returns false for a
/// malformed/short frame or an unrecognized family.
pub(crate) fn frame_is_nat64_exthdr_ineligible(frame: &[u8], addr_family: i32) -> bool {
    if addr_family != libc::AF_INET6 {
        return false;
    }
    let Some(l3) = frame_l3_offset(frame) else {
        return false;
    };
    let Some(packet) = frame.get(l3..) else {
        return false;
    };
    nat64_v6_translation_ineligible(packet)
}

/// Is this L3-relative IPv6 packet a NON-first fragment (#2290)?
///
/// Uses the shared walk's every-sighting non-zero-offset verdict, so an
/// ATOMIC header cannot mask a later real non-first header. An unreadable
/// Fragment header contributes no readable offset and returns false, as
/// before; paths that require valid L4 or overlap bounds fail closed elsewhere.
pub(super) fn ipv6_is_non_first_fragment(packet: &[u8]) -> bool {
    walk_ipv6_ext_chain(packet, 0).non_first_fragment_offset_seen
}

/// Parsed IPv6 Fragment Header (next-header 44) fields, RFC 8200 §4.5.
#[derive(Clone, Copy, Debug)]
// #7899: `pub(crate)` for the extracted `fragment_assoc` component, which
// derives its key from the same parsed fragment header. Stays HERE rather
// than moving with the cache because nat64.rs still has four other uses.
pub(crate) struct Ipv6FragInfo {
    /// 13-bit fragment offset in 8-byte units (same unit as the IPv4
    /// fragment-offset field, so it is copied verbatim across NAT64).
    pub(crate) offset_units: u16,
    /// The M (More Fragments) flag.
    pub(crate) more: bool,
    /// The 32-bit Identification value.
    pub(crate) ident: u32,
    /// #5798: the Fragment Header's Next Header byte — the upper-layer protocol
    /// (or the next extension-header type). It is a field OF the Fragment
    /// Header, so it is present and identical in EVERY fragment of a datagram,
    /// including non-first ones that carry no L4 header at all.
    pub(crate) next_header: u8,
}

/// Parse an IPv6 Fragment header (next-header 44) if present (#2488).
///
/// Uses the first readable non-ATOMIC header when any exists, so preceding
/// ATOMIC headers do not hide real fragmentation. For an all-ATOMIC chain,
/// retains the first declared header to preserve RFC 6946 translation
/// behavior. Returns `None` for no readable header or a truncated chain.
pub(crate) fn ipv6_fragment_header(packet: &[u8]) -> Option<Ipv6FragInfo> {
    let walk = walk_ipv6_ext_chain(packet, 0);
    if walk.fragment_truncated {
        return None;
    }
    let bytes = walk
        .first_non_atomic_fragment
        .or(walk.fragment)?
        .bytes?;
    // bytes 2-3: FragmentOffset[15:3] | Res[2:1] | M[0].
    let word = u16::from_be_bytes([bytes[2], bytes[3]]);
    Some(Ipv6FragInfo {
        offset_units: word >> 3,
        more: (word & 0x0001) != 0,
        ident: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        // byte 0: Next Header (#5798 protocol scoping).
        next_header: bytes[0],
    })
}

/// #2562: does this L3-relative IPv6 packet trigger the NAT64 v6→v4
/// fail-closed FRAGMENT drop in [`write_v6_to_v4_into`]?
///
/// Any readable non-zero offset in the chain drops, regardless of preceding
/// Any readable non-zero offset in the chain drops, regardless of preceding
/// ATOMIC sightings. Real first fragments drop for ICMPv6, and for UDP with
/// the illegal zero checksum. All-ATOMIC or non-fragment chains return false.
pub(crate) fn v6_to_v4_is_fragment_drop(packet: &[u8]) -> bool {
    if ipv6_is_non_first_fragment(packet) {
        return true;
    }
    let Some(info) = ipv6_fragment_header(packet) else {
        return false;
    };
    if info.offset_units != 0 {
        return true;
    }
    if !info.more {
        return false; // atomic fragment (MF=0, offset 0) — complete datagram
    }
    let Some((l4_offset, protocol)) = ipv6_l4_offset_and_protocol(packet) else {
        return false;
    };
    protocol == PROTO_ICMPV6
        || (protocol == PROTO_UDP
            && packet.get(l4_offset + 6..l4_offset + 8) == Some(&[0, 0][..]))
}
/// #2562: v4→v6 twin of [`v6_to_v4_is_fragment_drop`] for the reverse NAT64
/// direction, mirroring the drop conditions of [`write_v4_to_v6_into`].
///
/// True for a non-first IPv4 fragment (offset > 0, ANY protocol) or a real
/// fragment (MF=1 or offset > 0) carrying ICMP. An atomic fragment
/// (MF=0, offset 0) and a non-fragmented datagram return false.
pub(crate) fn v4_to_v6_is_fragment_drop(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return false;
    }
    let frag_word = u16::from_be_bytes([packet[6], packet[7]]);
    let more = (frag_word & 0x2000) != 0;
    let offset = frag_word & 0x1FFF;
    if offset != 0 {
        return true; // non-first fragment, any protocol
    }
    if !more {
        return false; // atomic or non-fragmented
    }
    // First fragment (MF=1, offset 0): dropped only when it carries ICMP.
    packet[9] == PROTO_ICMP
}

/// #2562: does this L2 frame trigger a NAT64 fail-closed fragment drop for the
/// given ingress address family (`AF_INET6` → forward v6→v4, `AF_INET` →
/// reverse v4→v6)?
///
/// Used by the TX dispatcher to attribute a NAT64 build-returned-`None` to the
/// `nat64_frag_dropped` counter without re-deriving the drop reason inline.
/// Returns false for a malformed/short frame or an unrecognized family.
pub(crate) fn frame_is_nat64_fragment_drop(frame: &[u8], addr_family: i32) -> bool {
    let Some(l3) = frame_l3_offset(frame) else {
        return false;
    };
    let Some(packet) = frame.get(l3..) else {
        return false;
    };
    match addr_family {
        libc::AF_INET6 => v6_to_v4_is_fragment_drop(packet),
        libc::AF_INET => v4_to_v6_is_fragment_drop(packet),
        _ => false,
    }
}

/// Allocation-free IPv6→IPv4 translation: write the translated IPv4 L3 packet
/// directly into `dst` and return the number of bytes written (#2211).
///
/// `dst` must be at least `20 + ipv6_payload_len` bytes; on a too-small buffer
/// the function returns `None` without writing a partial frame. Behavior is
/// byte-identical to the previous `Vec`-allocating translator: same header
/// fields, same DF/Identification policy, same checksums — the only change is
/// the output destination and the elimination of the intermediate L3 `Vec`
/// plus the pseudo-header `Vec`.
pub(crate) fn write_v6_to_v4_into(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
) -> Option<usize> {
    write_v6_to_v4_translate(dst, packet, snat_v4, dst_v4, no_v6_frag_header, None, false)
}

/// #11066: NoRoute slow-path entry point (v6→v4). Byte-identical to
/// [`write_v6_to_v4_into`] except the ingress Hop Limit is PRESERVED instead
/// of decremented, and a Hop Limit of 1 (or 0) is accepted instead of dropped
/// as expired. The delegated TUN hands the packet to the kernel FIB, which
/// performs the single forwarding decrement (or its normal ICMP Time Exceeded)
/// itself; decrementing here would cost an extra hop versus the same-family
/// NoRoute handoff (which copies L3 bytes verbatim) and would drop TTL-1
/// packets the kernel owns. Forwarding callers keep `write_v6_to_v4_into`.
pub(crate) fn write_v6_to_v4_into_preserve_ttl(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
) -> Option<usize> {
    write_v6_to_v4_translate(dst, packet, snat_v4, dst_v4, no_v6_frag_header, None, true)
}

/// #6472: flowless ICMP-error translation entry point (v6→v4). Identical to
/// [`write_v6_to_v4_into`] except the embedded quote's L4 destination port /
/// echo identifier is restored to the session's TRANSLATED (pool) value —
/// the tuple the v4 server actually carries — so the server can associate
/// the error (RFC 7915 §5.2 quote fidelity; the translators previously
/// copied the quoted L4 verbatim, leaving the original v6 client port,
/// which no v4 socket matches). `embedded_dst_port = None` reproduces
/// [`write_v6_to_v4_into`] byte-for-byte.
pub(crate) fn write_v6_to_v4_icmp_error_into(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
    embedded_dst_port: Option<u16>,
) -> Option<usize> {
    write_v6_to_v4_translate(
        dst,
        packet,
        snat_v4,
        dst_v4,
        no_v6_frag_header,
        embedded_dst_port,
        false,
    )
}

/// Shared core of [`write_v6_to_v4_into`], [`write_v6_to_v4_into_preserve_ttl`],
/// and [`write_v6_to_v4_icmp_error_into`]. `embedded_dst_port` rides
/// [`EmbeddedV6ToV4::mapped_embedded_dst_port`] into quote translation;
/// `preserve_ttl` is enabled only for kernel slow-path handoff.
pub(super) fn write_v6_to_v4_translate(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    no_v6_frag_header: bool,
    embedded_dst_port: Option<u16>,
    preserve_ttl: bool,
) -> Option<usize> {
    if packet.len() < 40 {
        return None;
    }
    // #5625/#10860: reject Authentication Header (51), active Routing (43,
    // Segments Left > 0), Mobility (135) / HIP (139) / Shim6 (140), and any
    // extension header named by a Fragment Header's Next Header field before
    // resolving L4. The latter headers are in the fragmentable part; stripping
    // them while copying offsets verbatim breaks reassembly geometry.
    // Hop-by-Hop / Destination Options / Routing-with-SL0 before Fragment, and
    // Fragment with a real upper-layer Next Header, remain eligible.
    if nat64_v6_translation_ineligible(packet) {
        return None;
    }
    // IPv6 header fields.
    // Full 8-bit traffic class (DSCP[7:2] | ECN[1:0]) straddling bytes 0-1 of
    // the IPv6 header. Copied verbatim into the IPv4 TOS byte below per the
    // RFC 7915 §5 default (DSCP copied, ECN copied verbatim — NAT64 is
    // stateless translation, not RFC 6040 tunnel encapsulation).
    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let hop_limit = packet[7];

    if !preserve_ttl && hop_limit <= 1 {
        return None; // TTL expired for forwarding; NoRoute handoff preserves it for the kernel
    }

    // #2290: walk the IPv6 extension-header chain to learn the terminal L4
    // offset and protocol instead of assuming L4 at byte 40 / reading the
    // raw next-header. A packet carrying Hop-by-Hop / Routing / Dest-Opts /
    // AH / Fragment before its transport header was previously dropped as
    // "unsupported protocol" even though it is legal RFC 8200 input.
    let (l4_offset, l4_protocol) = ipv6_l4_offset_and_protocol(packet)?;

    // A non-first fragment has NO L4 header at `l4_offset` — its bytes are
    // payload. Reading them as a transport header (and translating) would
    // corrupt the datagram, so fail closed (drop).
    if ipv6_is_non_first_fragment(packet) {
        return None;
    }

    // Map protocol from the terminal L4, not the raw next-header.
    let ipv4_protocol = match l4_protocol {
        PROTO_ICMPV6 => PROTO_ICMP,
        PROTO_TCP | PROTO_UDP => l4_protocol,
        _ => return None, // Unsupported protocol
    };

    // #2562 fail-closed: a REAL fragment (Fragment Header present with MF=1 OR
    // a non-zero offset) carrying ICMPv6 CANNOT be translated. The ICMPv4
    // checksum covers the WHOLE ICMP message, but a single fragment holds only
    // a slice of it, so `translate_icmpv6_message_to_icmpv4` below would
    // recompute the checksum over just this fragment's bytes and emit a FIRST
    // fragment with a wrong checksum that the receiver discards. A non-first
    // fragment (offset > 0, any protocol) is already dropped above; this
    // additionally drops the FIRST fragment (MF=1, offset 0) of an ICMPv6
    // datagram. An ATOMIC fragment (Fragment Header present, MF=0, offset 0 —
    // RFC 6946) is NOT a real fragment: it carries the complete ICMP message
    // and still translates normally. The stateful frag-association cache that
    // would let real ICMP fragments traverse end-to-end via reassembly is the
    // deferred principled fix (#2562 / #3291 stage 4).
    if l4_protocol == PROTO_ICMPV6 {
        if let Some(info) = ipv6_fragment_header(packet) {
            if info.more || info.offset_units != 0 {
                return None;
            }
        }
    }

    // #13696 / RFC 8200 §8.1: IPv6 UDP requires a checksum. A zero field in a
    // REAL first fragment is an illegal input and has no trustworthy
    // incremental baseline; the full datagram is unavailable to recompute it.
    // Drop before touching the caller's output buffer, matching the v4→v6
    // sibling's zero-checksum fragment gate below. Atomic fragments have the
    // complete datagram and remain eligible for a full checksum recompute.
    if l4_protocol == PROTO_UDP
        && ipv6_fragment_header(packet).is_some_and(|info| info.more && info.offset_units == 0)
        && packet.get(l4_offset + 6..l4_offset + 8) == Some(&[0, 0][..])
    {
        return None;
    }

    // The L4 region starts at the walked offset and ends at the IPv6
    // payload boundary (`40 + payload_len`). The ext-header bytes between
    // byte 40 and `l4_offset` are stripped by NAT64: RFC 7915 §5.1 maps the
    // IPv6 packet to an IPv4 packet carrying only the transport payload,
    // dropping the (non-translatable) IPv6 extension headers.
    let l4_end = 40usize.checked_add(payload_len)?;
    if l4_offset > l4_end {
        return None; // ext-header chain overran the advertised payload
    }
    let l4_payload = packet.get(l4_offset..l4_end)?;
    let new_ttl = if preserve_ttl {
        hop_limit
    } else {
        hop_limit - 1
    };

    // The L4 length is normally unchanged, but an ICMP *error* message embeds
    // the original (return-direction) packet, which is itself NAT64-translated
    // v6->v4 and so SHRINKS by 20 bytes. The translated L4 therefore never
    // exceeds the input L4, so reserving `20 + l4_payload.len()` is a safe upper
    // bound; the exact written length is computed below.
    let max_total_len = 20usize + l4_payload.len();
    let out = dst.get_mut(..max_total_len)?;

    // Build IPv4 header (total length + checksum patched after the L4 length is
    // known, since an ICMP-error translation can shrink the L4).
    out[0] = 0x45; // version=4, IHL=5
    out[1] = traffic_class; // DSCP/ECN copied from IPv6 traffic class (RFC 7915 §5)
    // #2488: preserve the IPv6 Fragment Header's fragment geometry and
    // Identification. Without one, RFC 7915 §5.1 keys DF on the translated
    // IPv4 packet length: packets up to 1260 bytes stay fragmentable, while
    // larger packets are atomic. The local no-v6-frag-header option remains
    // an explicit override that keeps header-less packets fragmentable.
    let frag_info = ipv6_fragment_header(packet);
    out[8] = new_ttl;
    out[9] = ipv4_protocol;
    out[10..12].copy_from_slice(&[0, 0]); // header checksum = 0 (computed below)
    out[12..16].copy_from_slice(&snat_v4.octets());
    out[16..20].copy_from_slice(&dst_v4.octets());

    // Translate the L4 region into the output and learn its final length.
    let l4_len = if l4_protocol == PROTO_ICMPV6 {
        // The embedded (quoted) original packet is the RETURN-direction packet:
        // its addresses are the outer error's addresses swapped, so v6->v4 the
        // embedded src maps to `dst_v4` and the embedded dst maps to `snat_v4`.
        let embedded = EmbeddedV6ToV4 {
            mapped_embedded_src: dst_v4,
            mapped_embedded_dst: snat_v4,
            mapped_embedded_dst_port: embedded_dst_port,
        };
        translate_icmpv6_message_to_icmpv4(&mut out[20..], l4_payload, &embedded)?
    } else {
        // Non-ICMP: copy L4 payload verbatim (single copy).
        out[20..max_total_len].copy_from_slice(l4_payload);
        l4_payload.len()
    };

    let ipv4_total_len = 20usize.checked_add(l4_len)?;
    // #10191: IPv4 Total Length is a 16-bit field. Fail closed rather than
    // narrowing 20 + l4_len above 65535 and emitting a wrapped datagram.
    if ipv4_total_len > u16::MAX as usize {
        return None;
    }
    out[2..4].copy_from_slice(&(ipv4_total_len as u16).to_be_bytes());
    let (frag_word, identification): (u16, u16) = match frag_info {
        Some(info) => {
            let mf = if info.more { 0x2000u16 } else { 0 };
            (mf | (info.offset_units & 0x1FFF), (info.ident & 0xFFFF) as u16)
        }
        None if no_v6_frag_header || ipv4_total_len <= 1260 => (0x0000, next_frag_id()),
        None => (0x4000, 0),
    };
    out[4..6].copy_from_slice(&identification.to_be_bytes());
    out[6..8].copy_from_slice(&frag_word.to_be_bytes());

    // L4 checksum after the IPv6→IPv4 pseudo-header change. The L4 payload is
    // byte-identical across NAT64 translation (verbatim copy for TCP/UDP), and
    // the transport length + protocol number are unchanged, so ONLY the
    // pseudo-header addresses differ between the v6 and v4 forms. That makes an
    // O(1) RFC 1624 incremental adjustment of the verbatim-copied L4 checksum
    // BYTE-IDENTICAL to a full recompute over the whole payload (one's-complement
    // addition is exact), but without re-summing every byte:
    //
    //   * #2488 FRAGMENT (TCP, or UDP with a non-zero baseline): a full
    //     recompute is IMPOSSIBLE — the first fragment's checksum covers the
    //     whole reassembled payload that is not present here — so incremental
    //     adjustment is mandatory. A real first fragment with zero IPv6 UDP
    //     checksum is dropped before output writes (#13696); an atomic UDP
    //     fragment has all bytes and takes the full recompute.
    //   * #3025 NON-fragment (TCP, or UDP with a non-zero baseline checksum):
    //     a full recompute is possible but wasteful; the incremental adjustment
    //     produces the identical wire result at O(changed-words) cost.
    //   * ICMP: ICMPv6→ICMPv4 genuinely rewrites the message and ICMPv4 carries
    //     no pseudo-header, so `translate_icmpv6_message_to_icmpv4` already set
    //     the correct checksum and the generic recompute re-affirms it.
    //   * Complete UDP datagrams with a zero v6 checksum: no trustworthy
    //     baseline exists, so the full recompute generates a valid checksum.
    // #15956: bound both checksum-field reads by the written prefix
    // (`out[..ipv4_total_len]`: header + verbatim L4 copy) explicitly,
    // twin of the v4->v6 read in `write_v4_to_v6_translate`.
    let (nonfrag_incremental, frag_incremental) = {
        let written_out = &out[..ipv4_total_len];
        (
            frag_info.is_none()
                && (ipv4_protocol == PROTO_TCP
                    || (ipv4_protocol == PROTO_UDP && written_out.get(26..28) != Some(&[0, 0][..]))),
            frag_info.is_some()
                && (ipv4_protocol == PROTO_TCP
                    || (ipv4_protocol == PROTO_UDP && written_out.get(26..28) != Some(&[0, 0][..]))),
        )
    };
    if frag_incremental || nonfrag_incremental {
        let mut v6_addrs = [0u8; 32];
        v6_addrs.copy_from_slice(&packet[8..40]);
        adjust_l4_checksum_v6_to_v4_incremental(
            &mut out[..ipv4_total_len],
            ipv4_protocol,
            &v6_addrs,
            snat_v4,
            dst_v4,
        )?;
    } else {
        recompute_l4_checksum_after_nat64_v6_to_v4(&mut out[..ipv4_total_len], ipv4_protocol)?;
    }

    // Compute IPv4 header checksum.
    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());

    Some(ipv4_total_len)
}
/// Length-only mirror of the v6→v4 translator for its pre-build MTU decision.
/// It shares extension-header, non-first-fragment payload, and ICMP quote
/// conversion rules without copying payload bytes.
pub(crate) fn v6_to_v4_output_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 40 || nat64_v6_translation_ineligible(packet) || packet[7] <= 1 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let (l4_offset, l4_protocol) = ipv6_l4_offset_and_protocol(packet)?;
    let l4_end = 40usize.checked_add(payload_len)?;
    if l4_offset > l4_end {
        return None;
    }
    // Keep the preflight length consistent with the builder: a declared
    // IPv6 payload that is not present in the captured packet is not
    // translatable, including on the non-first-fragment fast return below.
    let l4_payload = packet.get(l4_offset..l4_end)?;
    if ipv6_is_non_first_fragment(packet) {
        let fragment = ipv6_fragment_header(packet)?;
        // `write_v6_to_v4_nonfirst_into` accepts only TCP/UDP. Fragmented
        // ICMPv6 cannot be translated because its checksum covers the whole
        // datagram, so it must fail the same MTU preflight gate.
        if fragment.offset_units == 0 || !matches!(l4_protocol, PROTO_TCP | PROTO_UDP) {
            return None;
        }
        let total_len = 20usize.checked_add(l4_payload.len())?;
        return (total_len <= u16::MAX as usize).then_some(total_len);
    }
    if l4_protocol == PROTO_UDP
        && ipv6_fragment_header(packet).is_some_and(|info| info.more && info.offset_units == 0)
        && l4_payload.get(6..8) == Some(&[0, 0][..])
    {
        return None;
    }
    let l4_len = match l4_protocol {
        PROTO_TCP | PROTO_UDP => l4_payload.len(),
        PROTO_ICMPV6 => {
            if ipv6_fragment_header(packet)
                .is_some_and(|info| info.more || info.offset_units != 0)
            {
                return None;
            }
            match l4_payload.first().copied()? {
                ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY if l4_payload.len() >= 4 => {
                    l4_payload.len()
                }
                ICMPV6_PACKET_TOO_BIG
                | ICMPV6_DEST_UNREACHABLE
                | ICMPV6_TIME_EXCEEDED
                | ICMPV6_PARAMETER_PROBLEM => {
                    translated_icmpv6_error_l4_len(l4_payload)?
                }
                _ => return None,
            }
        }
        _ => return None,
    };
    let total_len = 20usize.checked_add(l4_len)?;
    (total_len <= u16::MAX as usize).then_some(total_len)
}


/// Translate an IPv4 packet to IPv6 (reverse direction: server→client reply).
///
/// Input: `packet` starts at L3 (IPv4 header), not Ethernet.
/// `dst_v6` is the original IPv6 client source, `src_v6` is the NAT64 prefix
/// + original IPv4 server address (i.e. orig_dst_v6 for the reply src).
///
/// Returns the translated IPv6 packet (L3 only, no Ethernet header).
///
/// Allocating convenience wrapper over [`write_v4_to_v6_into`]; see the
/// `_into` core for the hot-path, allocation-free entry point (#2211).
/// `#[cfg(test)]`-only (the differential byte-identity tests), like its
/// v6->v4 twin — no production caller allocates an owned NAT64 packet.
#[cfg(test)]
pub(crate) fn translate_v4_to_v6(
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<Vec<u8>> {
    // IPv4→IPv6 grows the outer header by 20 bytes (40-byte v6 header vs the
    // 20-byte v4 header). An ICMP-error message ALSO grows its embedded quoted
    // packet by another 20 bytes (the embedded v4 header expands to a v6
    // header). The worst-case output is therefore `packet.len() + 40`. Allocate
    // that upper bound, then truncate to the exact written length.
    let mut out = vec![0u8; packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    let written = write_v4_to_v6_into(&mut out, packet, src_v6, dst_v6)?;
    out.truncate(written);
    Some(out)
}

/// Allocation-free IPv4→IPv6 translation: write the translated IPv6 L3 packet
/// directly into `dst` and return the number of bytes written (#2211).
///
/// `dst` must be at least `40 + 8 + (ipv4_total_len - ihl)` bytes for a
/// fragmented input (the extra 8 bytes are the inserted IPv6 Fragment Header,
/// #2488) and `40 + (ipv4_total_len - ihl)` otherwise; on a too-small buffer
/// the function returns `None` without writing a partial frame. Behavior on a
/// non-fragmented input is byte-identical to the previous `Vec`-allocating
/// translator.
pub(crate) fn write_v4_to_v6_into(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<usize> {
    write_v4_to_v6_translate(dst, packet, src_v6, dst_v6, None, false)
}

/// #11066: NoRoute slow-path entry point (v4→v6), preserving ingress TTL.
/// The delegated TUN kernel performs the single forwarding decrement (or
/// generates its normal Time Exceeded response) after route lookup.
pub(crate) fn write_v4_to_v6_into_preserve_ttl(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<usize> {
    write_v4_to_v6_translate(dst, packet, src_v6, dst_v6, None, true)
}

/// #6472: flowless ICMP-error translation entry point (v4→v6). Identical to
/// [`write_v4_to_v6_into`] except the embedded quote's L4 source port /
/// echo identifier is restored to the ORIGINAL v6 client value — the tuple
/// the client actually sent — so the client can associate the error with
/// its session (RFC 7915 §4.2 quote fidelity; the translators previously
/// copied the quoted L4 verbatim, leaving the TRANSLATED pool port no
/// client socket matches). `embedded_src_port = None` reproduces
/// [`write_v4_to_v6_into`] byte-for-byte.
pub(crate) fn write_v4_to_v6_icmp_error_into(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    embedded_src_port: Option<u16>,
) -> Option<usize> {
    write_v4_to_v6_translate(dst, packet, src_v6, dst_v6, embedded_src_port, false)
}

/// #10720 (N2): checked IPv6 Payload Length narrowing for the v4→v6 direction.
///
/// The v6→v4 twin guards every `as u16` length narrowing with an explicit
/// `u16::MAX` fail-closed check (#10191); the two v4→v6 sites below narrowed
/// unchecked. Both call sites sum a fragment-header allowance (0 or 8) with a
/// length already bounded by the IPv4 16-bit Total Length field (at most
/// 65515 + 8 = 65523), so the guard cannot fire on any input the translators
/// accept today — it is defence-in-depth against a future input widening, and
/// the single choke point both v4→v6 payload-length narrowings route through
/// so that such a widening fails closed instead of wrapping the wire field.
#[inline]
pub(super) fn checked_ipv6_payload_len(frag_hdr_len: usize, l4_len: usize) -> Option<u16> {
    let total = frag_hdr_len.checked_add(l4_len)?;
    if total > u16::MAX as usize {
        return None;
    }
    Some(total as u16)
}

/// Shared core of [`write_v4_to_v6_into`], [`write_v4_to_v6_into_preserve_ttl`],
/// and [`write_v4_to_v6_icmp_error_into`]. `embedded_src_port` rides
/// [`EmbeddedV4ToV6::mapped_embedded_src_port`] into quote translation;
/// `preserve_ttl` is enabled only for kernel slow-path handoff.
pub(super) fn write_v4_to_v6_translate(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    embedded_src_port: Option<u16>,
    preserve_ttl: bool,
) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    // IPv4 TOS byte (DSCP[7:2] | ECN[1:0]) — copied verbatim into the IPv6
    // traffic class below per the RFC 7915 §4 default (DSCP copied, ECN copied
    // verbatim — NAT64 is stateless translation, not RFC 6040 encapsulation).
    let tos = packet[1];
    let ttl = packet[8];
    if !preserve_ttl && ttl <= 1 {
        return None; // TTL expired for forwarding; NoRoute handoff preserves it for the kernel
    }
    let protocol = packet[9];
    // Trim the L4 payload to the IPv4 Total Length field rather than the end
    // of the slice. The caller passes the whole L3-onward frame, which may
    // include Ethernet padding appended to reach the 60/64-byte minimum frame
    // size (common for TCP ACKs, DNS replies, short HTTP). Copying that padding
    // into the IPv6 packet inflates payload_len and poisons the recomputed L4
    // checksum, so the receiver drops the reply. This mirrors the forward path
    // (translate_v6_to_v4) which trims to the IPv6 payload_len field.
    //
    // total_len is attacker/driver-controlled, so clamp safely: a malformed
    // header could advertise a length shorter than the IPv4 header or longer
    // than the bytes we actually received.
    let ipv4_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ipv4_total_len < ihl || ipv4_total_len > packet.len() {
        return None;
    }
    let l4_payload = packet.get(ihl..ipv4_total_len)?;

    // Map protocol.
    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };

    // #2488: a FIRST IPv4 fragment (MF=1, offset 0) MUST become an IPv6 packet
    // carrying a Fragment Header (next-header 44), per RFC 7915 §4. Without it
    // the receiver treats a truncated first fragment as a complete datagram.
    // Bytes 6-7 are [Res(1) | DF(1) | MF(1) | FragOffset(13)] in 8-byte units
    // (the same unit as the IPv6 Fragment Header offset). Non-first fragments
    // are dropped below.
    let v4_frag_word = u16::from_be_bytes([packet[6], packet[7]]);
    let v4_more = (v4_frag_word & 0x2000) != 0;
    let v4_offset_units = v4_frag_word & 0x1FFF;
    // A NON-first fragment (offset > 0) carries no L4 header — its bytes are
    // payload, not a transport header. It never reaches the reverse NAT64
    // translator anyway (no L4 ports to match the session), but fail closed
    // here, symmetric with the v6→v4 non-first-fragment drop. Only first
    // (offset 0, MF=1) and atomic (offset 0, MF=0) datagrams translate.
    if v4_offset_units != 0 {
        return None;
    }
    let is_fragment = v4_more;
    // #2562 fail-closed: a REAL fragment (MF=1 or offset > 0) carrying ICMP
    // cannot be translated — the ICMPv6 checksum covers the WHOLE datagram, so
    // `translate_icmpv4_message_to_icmpv6` over a single fragment's bytes would
    // emit a FIRST fragment with a wrong checksum the receiver discards. A
    // non-first fragment (offset > 0) is dropped above; this drops the FIRST
    // fragment (MF=1, offset 0) of an ICMP datagram. An ATOMIC fragment
    // (MF=0, offset 0) still translates. Symmetric with the v6→v4 ICMP-fragment
    // guard; the stateful frag-association cache remains deferred (#2562 /
    // #3291 stage 4).
    if protocol == PROTO_ICMP && is_fragment {
        return None;
    }
    let v4_ident = u16::from_be_bytes([packet[4], packet[5]]);
    // RFC 7915 §4.5: a UDP fragment with a zero IPv4 checksum cannot be
    // translated — the IPv6 UDP checksum is mandatory and cannot be computed
    // from a single fragment (the full payload is unavailable). Drop it rather
    // than emit an illegal zero-checksum IPv6 UDP datagram.
    if is_fragment
        && protocol == PROTO_UDP
        && packet.get(ihl + 6..ihl + 8) == Some(&[0, 0][..])
    {
        return None;
    }
    let frag_hdr_len = if is_fragment { 8usize } else { 0 };

    let new_hop_limit = if preserve_ttl { ttl } else { ttl - 1 };

    // Build the 40-byte IPv6 header. The 8-bit traffic class straddles bytes
    // 0-1: TC[7:4] in the low nibble of byte 0 (alongside the version=6 nibble)
    // and TC[3:0] in the high nibble of byte 1 (alongside the flow-label high
    // nibble, left at 0). Mirrors apply_dscp_rewrite_to_frame in
    // afxdp/frame/mod.rs:133-134. The caller's buffer may be reused (a TX UMEM
    // frame), so write every byte of the IPv6 header explicitly rather than
    // relying on a zero-initialized destination: zero byte 1's low nibble +
    // bytes 2-3 (the flow label). The payload-length field (bytes 4-5) is
    // patched after the L4 length is known — an ICMP-error translation grows
    // the embedded packet by 20 bytes.
    let hdr = dst.get_mut(..40)?;
    hdr[0] = 0x60 | (tos >> 4); // version=6 | TC[7:4]
    hdr[1] = (tos & 0x0f) << 4; // TC[3:0] | flow-label high nibble (0)
    hdr[2] = 0; // flow label
    hdr[3] = 0; // flow label
    // A fragmented datagram chains a Fragment Header (44) after the base
    // header; the base next-header points at it and the Fragment Header carries
    // the real upper-layer protocol.
    hdr[6] = if is_fragment { 44 } else { next_header };
    hdr[7] = new_hop_limit;
    hdr[8..24].copy_from_slice(&src_v6.octets());
    hdr[24..40].copy_from_slice(&dst_v6.octets());

    // #2488: emit the 8-byte IPv6 Fragment Header (RFC 8200 §4.5) when the
    // input was an IPv4 fragment. The fragment offset is copied verbatim (both
    // count 8-byte units), the M flag mirrors IPv4 MF, and the Identification
    // is the IPv4 16-bit Identification zero-extended to 32 bits (RFC 7915 §4).
    if is_fragment {
        let frag = dst.get_mut(40..48)?;
        frag[0] = next_header;
        frag[1] = 0; // reserved
        let frag_word = (v4_offset_units << 3) | u16::from(v4_more);
        frag[2..4].copy_from_slice(&frag_word.to_be_bytes());
        frag[4..8].copy_from_slice(&u32::from(v4_ident).to_be_bytes());
    }

    // Translate the L4 region into the output tail and learn its final length.
    // `get_mut(l4_off..)` only borrows the space actually present in `dst`; the
    // ICMP-error path may need up to 20 bytes more than the input L4 (embedded
    // packet growth), so the frame builder over-allocates by 20. A Fragment
    // Header shifts the L4 region 8 bytes further into the buffer.
    let l4_off = 40 + frag_hdr_len;
    let l4_dst = dst.get_mut(l4_off..)?;
    let l4_len = if protocol == PROTO_ICMP {
        // The embedded (quoted) original packet is the RETURN-direction packet:
        // its addresses are the outer error's addresses swapped. v4->v6 the
        // embedded src (our SNAT pool v4) maps to the original v6 client
        // (`dst_v6`), and the embedded dst (the v4 server) maps to the NAT64
        // prefix + server address — the prefix being the top 96 bits of the
        // outer translated source (`src_v6` = prefix::server).
        let mut prefix_bytes = [0u8; 12];
        prefix_bytes.copy_from_slice(&src_v6.octets()[..12]);
        let embedded = EmbeddedV4ToV6 {
            mapped_embedded_src: dst_v6,
            prefix_bytes,
            mapped_embedded_src_port: embedded_src_port,
        };
        translate_icmpv4_message_to_icmpv6(l4_dst, l4_payload, &embedded)?
    } else {
        // Non-ICMP: copy L4 payload verbatim (single copy).
        l4_dst.get_mut(..l4_payload.len())?.copy_from_slice(l4_payload);
        l4_payload.len()
    };

    // #10720 (N2): checked narrowing — the #10191 twin for this direction.
    let ipv6_payload_len = checked_ipv6_payload_len(frag_hdr_len, l4_len)?;
    let ipv6_total_len = 40usize + usize::from(ipv6_payload_len);
    dst[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());

    // L4 checksum after the IPv4→IPv6 pseudo-header change. The L4 payload is
    // byte-identical across translation and the transport length + protocol
    // number are unchanged, so ONLY the pseudo-header addresses differ — making
    // an O(1) RFC 1624 incremental adjustment BYTE-IDENTICAL to a full recompute
    // (see the v6→v4 twin for the full rationale).
    //
    //   * #2488 FRAGMENT (TCP/UDP): incremental adjustment is mandatory (the
    //     transport payload is incomplete). Fragmented ICMP keeps whatever
    //     `translate_icmpv4_message_to_icmpv6` produced — a degenerate edge that
    //     is moot because non-first fragments never reach this translator (no L4
    //     ports to match the reverse NAT64 session), so a fragmented datagram
    //     never reassembles regardless.
    //   * #3025 NON-fragment (TCP, or UDP with a non-zero IPv4 checksum): the
    //     incremental adjustment replaces the previous full recompute at no
    //     change to the wire result.
    //   * ICMP: ICMPv4→ICMPv6 rewrites the message AND ICMPv6 (unlike ICMPv4)
    //     uses a pseudo-header, so the checksum genuinely changes — full
    //     recompute.
    //   * Non-fragment UDP with a 0x0000 IPv4 checksum: RFC 768 "no checksum
    //     present". There is no baseline to adjust and IPv6 UDP REQUIRES a
    //     checksum, so a full recompute GENERATES one.
    if is_fragment {
        if matches!(next_header, PROTO_TCP | PROTO_UDP) {
            let mut v6_addrs = [0u8; 32];
            v6_addrs[..16].copy_from_slice(&src_v6.octets());
            v6_addrs[16..].copy_from_slice(&dst_v6.octets());
            let mut v4_addrs = [0u8; 8];
            v4_addrs[..4].copy_from_slice(&packet[12..16]);
            v4_addrs[4..].copy_from_slice(&packet[16..20]);
            adjust_l4_checksum_v4_to_v6_incremental(
                &mut dst[..ipv6_total_len],
                next_header,
                l4_off,
                &v4_addrs,
                &v6_addrs,
            )?;
        }
    } else {
        // #15956: bound the checksum-field read by the WRITTEN prefix
        // explicitly. `dst[..l4_written]` is exactly what the header
        // writes plus the verbatim L4 copy above initialized; a UDP
        // datagram too short to contain the field (copied < 8 bytes)
        // yields no baseline here and falls to the full recompute,
        // which itself fails closed on the short L4 — the read never
        // consults bytes past the copy.
        let l4_written = l4_off + l4_len;
        let udp_no_baseline = next_header == PROTO_UDP
            && dst
                .get(..l4_written)
                .and_then(|written| written.get(l4_off + 6..l4_off + 8))
                == Some(&[0, 0][..]);
        if matches!(next_header, PROTO_TCP | PROTO_UDP) && !udp_no_baseline {
            let mut v6_addrs = [0u8; 32];
            v6_addrs[..16].copy_from_slice(&src_v6.octets());
            v6_addrs[16..].copy_from_slice(&dst_v6.octets());
            let mut v4_addrs = [0u8; 8];
            v4_addrs[..4].copy_from_slice(&packet[12..16]);
            v4_addrs[4..].copy_from_slice(&packet[16..20]);
            adjust_l4_checksum_v4_to_v6_incremental(
                &mut dst[..ipv6_total_len],
                next_header,
                l4_off,
                &v4_addrs,
                &v6_addrs,
            )?;
        } else {
            recompute_l4_checksum_after_nat64_v4_to_v6(&mut dst[..ipv6_total_len], next_header)?;
        }
    }

    Some(ipv6_total_len)
}

