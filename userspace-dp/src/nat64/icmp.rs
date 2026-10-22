//! NAT64 ICMP error translation and embedded-quote translation.
//!
//! ICMPv4<->ICMPv6 error type/code maps, embedded (quoted) packet
//! translation, and the L4 checksum recompute arms.
//!
//! #16188 PURE CODE MOTION: every line below was moved verbatim from
//! `nat64.rs` lines 3870-4685 (doc block included; it moved with its fn). The only edits are the visibility
//! widenings enumerated in `nat64/mod.rs`; no logic, no ordering and
//! no signature changed.

use super::*;

/// Map an ICMPv6 error type/code to its ICMPv4 equivalent per RFC 7915 §5.2.
/// Returns `None` for ICMPv6 types that have no IPv4 mapping (e.g. NDP, MLD —
/// which are link-local and never cross the translator) so the caller drops
/// them rather than emitting a malformed ICMPv4 error.
///
/// Packet-Too-Big (type 2) is handled separately by the caller because it also
/// rewrites the MTU field, so it is intentionally absent here.
pub(super) fn map_icmpv6_error_to_icmpv4(icmpv6_type: u8, icmpv6_code: u8) -> Option<(u8, u8)> {
    match icmpv6_type {
        ICMPV6_DEST_UNREACHABLE => {
            // RFC 7915 5.2: ICMPv6 Destination Unreachable codes map onto the
            // ICMPv4 Destination Unreachable code space.
            let v4_code = match icmpv6_code {
                0 => 1, // no route to destination       -> host unreachable
                1 => 10, // communication administratively prohibited
                //          -> communication with destination host
                //             administratively prohibited
                2 => 1, // beyond scope of source address -> host unreachable
                3 => 1, // address unreachable            -> host unreachable
                4 => 3, // port unreachable               -> port unreachable
                _ => return None,
            };
            Some((ICMP_DEST_UNREACHABLE, v4_code))
        }
        ICMPV6_TIME_EXCEEDED => {
            // RFC 7915 5.2: Time Exceeded (3) maps 1:1 with its code preserved
            // (0 = hop limit exceeded, 1 = fragment reassembly time exceeded).
            Some((ICMP_TIME_EXCEEDED, icmpv6_code))
        }
        ICMPV6_PARAMETER_PROBLEM => {
            // RFC 7915 5.2: Parameter Problem.
            match icmpv6_code {
                // code 0 (erroneous header field) -> ICMPv4 Parameter Problem
                // code 0 (pointer indicates the error). The embedded-pointer
                // remap (RFC 7915 Figure 6) is not performed; the pointer is a
                // best-effort hint, and Junos/vSRX parity does not depend on it.
                0 => Some((ICMP_PARAMETER_PROBLEM, 0)),
                // code 1 (unrecognized Next Header) -> ICMPv4 Destination
                // Unreachable / Protocol Unreachable.
                1 => Some((ICMP_DEST_UNREACHABLE, 2)),
                // code 2 (unrecognized IPv6 option) is silently dropped per
                // RFC 7915 — it has no IPv4 analogue.
                _ => None,
            }
        }
        _ => None,
    }
}

/// Map an ICMPv4 error type/code to its ICMPv6 equivalent per RFC 7915 §4.2.
/// Returns `None` for ICMPv4 types/codes that have no IPv6 mapping so the
/// caller drops them. Fragmentation-Needed (type 3 code 4) is handled
/// separately by the caller because it rewrites the MTU field.
pub(super) fn map_icmpv4_error_to_icmpv6(icmpv4_type: u8, icmpv4_code: u8) -> Option<(u8, u8)> {
    match icmpv4_type {
        ICMP_DEST_UNREACHABLE => {
            // RFC 7915 4.2: ICMPv4 Destination Unreachable codes map onto the
            // ICMPv6 Destination Unreachable / Packet Too Big code space.
            // (code 4, Fragmentation Needed, is handled by the caller — it
            // becomes Packet Too Big with an MTU rewrite.)
            let mapped = match icmpv4_code {
                0 => (ICMPV6_DEST_UNREACHABLE, 0), // net unreachable -> no route
                1 => (ICMPV6_DEST_UNREACHABLE, 0), // host unreachable -> no route
                2 => (ICMPV6_PARAMETER_PROBLEM, 1), // protocol unreachable ->
                //  parameter problem, unrecognized Next Header
                3 => (ICMPV6_DEST_UNREACHABLE, 4), // port unreachable -> port unreachable
                5 => (ICMPV6_DEST_UNREACHABLE, 0), // source route failed -> no route
                6 => (ICMPV6_DEST_UNREACHABLE, 0), // dest network unknown -> no route
                7 => (ICMPV6_DEST_UNREACHABLE, 0), // dest host unknown -> no route
                8 => (ICMPV6_DEST_UNREACHABLE, 0), // src host isolated -> no route
                11 => (ICMPV6_DEST_UNREACHABLE, 0), // net unreachable for TOS -> no route
                12 => (ICMPV6_DEST_UNREACHABLE, 0), // host unreachable for TOS -> no route
                9 | 10 | 13 | 15 => (ICMPV6_DEST_UNREACHABLE, 1), // admin prohibited
                _ => return None,
            };
            Some(mapped)
        }
        ICMP_TIME_EXCEEDED => {
            // RFC 7915 4.2: Time Exceeded (11) maps 1:1 with its code preserved.
            Some((ICMPV6_TIME_EXCEEDED, icmpv4_code))
        }
        ICMP_PARAMETER_PROBLEM => {
            // RFC 7915 4.2: Parameter Problem (12).
            match icmpv4_code {
                // code 0 (pointer indicates error) and code 2 (bad length) ->
                // ICMPv6 Parameter Problem, erroneous header field.
                0 | 2 => Some((ICMPV6_PARAMETER_PROBLEM, 0)),
                // code 1 (missing required option) has no IPv6 analogue.
                _ => None,
            }
        }
        _ => return None,
    }
}

/// Address mapping for the embedded (quoted) packet of an ICMPv6 error being
/// translated v6->v4. The embedded packet is the RETURN-direction original
/// packet whose addresses are the outer error's addresses swapped, so both
/// embedded addresses are known constants derived from the outer translation —
/// no NAT64 prefix arithmetic is needed in this direction (the outer src/dst v4
/// already carry the fully-mapped values).
pub(super) struct EmbeddedV6ToV4 {
    /// IPv4 the embedded IPv6 source maps to.
    pub(super) mapped_embedded_src: Ipv4Addr,
    /// IPv4 the embedded IPv6 destination maps to.
    pub(super) mapped_embedded_dst: Ipv4Addr,
    /// #6472: optional L4 destination-port / ICMP-identifier rewrite for the
    /// quoted packet, applied before the outer ICMP checksum is computed.
    /// The NAT64 flowless ICMP-error path (v6→v4) translates an error about
    /// the session's RETURN-direction wire packet: the quote's destination
    /// port / echo id is the ORIGINAL v6 client value, which the v4 server
    /// can only associate when it reads back as the TRANSLATED (pool) value
    /// the server actually replied to. `None` leaves the quoted L4 verbatim
    /// (the data-packet callers — byte-identical to pre-#6472).
    pub(super) mapped_embedded_dst_port: Option<u16>,
}

/// Borrowed translated-header view shared by the ICMP quote writer and its
/// allocation-free MTU length preflight.
pub(super) struct EmbeddedV6ToV4Layout<'a> {
    pub(super) l4: &'a [u8],
    pub(super) traffic_class: u8,
    pub(super) hop_limit: u8,
    pub(super) ipv4_protocol: u8,
    pub(super) advertised_total: usize,
    pub(super) fragment_word: u16,
    pub(super) identification: u16,
    pub(super) l4_protocol: u8,
}

pub(super) fn embedded_v6_to_v4_layout<'a>(embedded: &'a [u8]) -> Option<EmbeddedV6ToV4Layout<'a>> {
    if embedded.len() < 40 || nat64_v6_translation_ineligible(embedded) {
        return None;
    }
    // Clamp hostile or large quotes to the fixed stack-scratch contract. A
    // shorter ICMP quote is always legal.
    let quote_in = &embedded[..embedded.len().min(MAX_EMBEDDED_LEN)];
    let payload_len = u16::from_be_bytes([quote_in[4], quote_in[5]]) as usize;
    let hop_limit = quote_in[7];
    let traffic_class = ((quote_in[0] & 0x0f) << 4) | (quote_in[1] >> 4);
    let (l4_offset, l4_protocol) = ipv6_l4_offset_and_protocol(quote_in)?;
    if ipv6_is_non_first_fragment(quote_in) {
        return None;
    }
    let ipv4_protocol = match l4_protocol {
        PROTO_ICMPV6 => PROTO_ICMP,
        PROTO_TCP | PROTO_UDP => l4_protocol,
        _ => return None,
    };

    let stripped_ext_len = l4_offset.checked_sub(40)?;
    let translated_payload_len = payload_len.checked_sub(stripped_ext_len)?;
    let advertised_total = 20usize.checked_add(translated_payload_len)?;
    if advertised_total > u16::MAX as usize {
        return None;
    }
    let payload_end = 40usize.checked_add(payload_len)?;
    let quoted_end = payload_end.min(quote_in.len());
    if l4_offset > quoted_end {
        return None;
    }
    let l4 = quote_in.get(l4_offset..quoted_end)?;

    // RFC 7915 §5.2 defers to §5.1 for embedded fragmentation fields. A
    // non-first fragment was rejected above; copy the available first/atomic
    // fragment geometry or keep header-less quote behavior unchanged.
    let (fragment_word, identification) = match ipv6_fragment_header(quote_in) {
        Some(info) => {
            let more = if info.more { 0x2000u16 } else { 0 };
            (more | (info.offset_units & 0x1FFF), (info.ident & 0xFFFF) as u16)
        }
        None => (0x4000, 0),
    };
    Some(EmbeddedV6ToV4Layout {
        l4,
        traffic_class,
        hop_limit,
        ipv4_protocol,
        advertised_total,
        fragment_word,
        identification,
        l4_protocol,
    })
}

/// Address mapping for the embedded (quoted) packet of an ICMPv4 error being
/// translated v4->v6. The embedded packet is the RETURN-direction original
/// packet: its IPv4 source (our SNAT pool) maps to the original v6 client
/// (`mapped_embedded_src`); its IPv4 destination (the v4 server) maps to the
/// NAT64 prefix + that destination (`prefix_bytes` :: dst-v4).
pub(super) struct EmbeddedV4ToV6 {
    /// IPv6 the embedded IPv4 source maps to (the original v6 client).
    pub(super) mapped_embedded_src: Ipv6Addr,
    /// NAT64 /96 prefix the embedded IPv4 destination is composed onto.
    pub(super) prefix_bytes: [u8; 12],
    /// #6472: optional L4 source-port / ICMP-identifier rewrite for the
    /// quoted packet, applied before the outer ICMPv6 checksum is computed.
    /// The NAT64 flowless ICMP-error path (v4→v6) translates an error about
    /// the session's FORWARD wire packet: the quote's source port / echo id
    /// is the TRANSLATED (pool) value, which the v6 client can only
    /// associate when it reads back as its ORIGINAL value. `None` leaves
    /// the quoted L4 verbatim (the data-packet callers — byte-identical to
    /// pre-#6472).
    pub(super) mapped_embedded_src_port: Option<u16>,
}


pub(super) fn translated_icmpv6_error_l4_len(src: &[u8]) -> Option<usize> {
    let icmpv6_type = *src.first()?;
    let icmpv6_code = *src.get(1)?;
    if src.len() < 8 {
        return None;
    }
    if icmpv6_type != ICMPV6_PACKET_TOO_BIG {
        map_icmpv6_error_to_icmpv4(icmpv6_type, icmpv6_code)?;
    }
    let quote = embedded_v6_to_v4_layout(src.get(8..)?)?;
    8usize
        .checked_add(20)?
        .checked_add(quote.l4.len())
}
/// Translate a complete ICMPv6 message (`src`, starting at the ICMPv6 type
/// byte) into ICMPv4 in `dst`, returning the written ICMPv4 message length.
///
/// Handles echo request/reply (length unchanged) AND error messages
/// (Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem)
/// per RFC 7915 §5.2 — for an error the leading 8-byte ICMP header is followed
/// by the quoted original packet, whose embedded IPv6 header is NAT64-translated
/// to IPv4 (addresses mapped, lengths/checksums fixed). The ICMPv4 checksum is
/// computed here (ICMPv4 has no pseudo-header), so the caller's generic
/// recompute is a consistent no-op over the already-correct value.
///
/// Allocation-free: the embedded packet is translated through a fixed stack
/// scratch buffer (`MAX_EMBEDDED_LEN`), never the heap (#2211). `None` aborts
/// the frame (drop) for an untranslatable type/code or a malformed/oversized
/// embedded packet.
pub(super) fn translate_icmpv6_message_to_icmpv4(
    dst: &mut [u8],
    src: &[u8],
    embedded: &EmbeddedV6ToV4,
) -> Option<usize> {
    if src.len() < 4 {
        return None;
    }
    let icmpv6_type = src[0];
    let icmpv6_code = src[1];

    match icmpv6_type {
        ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY => {
            // Echo: length preserved, only type/code change.
            let out = dst.get_mut(..src.len())?;
            out.copy_from_slice(src);
            out[0] = if icmpv6_type == ICMPV6_ECHO_REQUEST {
                ICMP_ECHO_REQUEST
            } else {
                ICMP_ECHO_REPLY
            };
            out[1] = 0;
            finalize_icmpv4_checksum(out);
            Some(out.len())
        }
        ICMPV6_PACKET_TOO_BIG => {
            // An ICMP error always carries the full 8-byte header (type/code/
            // checksum + the 4-byte rest-of-header). `src` is packet data, so
            // reject a truncated header before indexing the MTU word.
            if src.len() < 8 {
                return None;
            }
            // RFC 7915 5.2: ICMPv6 Packet Too Big (type 2) -> ICMPv4
            // Destination Unreachable / Fragmentation Needed (type 3 code 4).
            // The 4-byte "unused" word of an ICMPv6 PTB carries the MTU; the
            // ICMPv4 Fragmentation-Needed instead carries the Next-Hop MTU in
            // its low 16 bits (bytes 6-7), with bytes 4-5 unused (RFC 1191).
            let mtu = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
            // The translated v4 datagram is 20 bytes smaller than the v6 one, so
            // advertise an MTU 20 bytes smaller (clamped to a sane 16-bit range
            // and never below the v4 minimum). RFC 7915 5.2.
            let v4_mtu = mtu.saturating_sub(NAT64_HEADER_DELTA).clamp(68, 0xffff) as u16;
            write_icmpv4_error_with_embedded(
                dst,
                src,
                ICMP_DEST_UNREACHABLE,
                4,
                [0, 0, (v4_mtu >> 8) as u8, v4_mtu as u8],
                embedded,
            )
        }
        ICMPV6_DEST_UNREACHABLE | ICMPV6_TIME_EXCEEDED | ICMPV6_PARAMETER_PROBLEM => {
            let (v4_type, v4_code) = map_icmpv6_error_to_icmpv4(icmpv6_type, icmpv6_code)?;
            // RFC 7915 5.2: the 4-byte rest-of-header is ZEROED for these
            // types. Time-Exceeded / Dest-Unreach carry an unused word (zero
            // is correct on the wire). The ICMPv6 Parameter-Problem pointer is
            // intentionally NOT remapped to an ICMPv4 pointer (see
            // map_icmpv6_error_to_icmpv4), so it is dropped to zero rather than
            // translated.
            write_icmpv4_error_with_embedded(
                dst, src, v4_type, v4_code, [0, 0, 0, 0], embedded,
            )
        }
        _ => None, // NDP, MLD, etc. — never crosses the translator.
    }
}

/// Translate a complete ICMPv4 message (`src`, starting at the ICMPv4 type
/// byte) into ICMPv6 in `dst`, returning the written ICMPv6 message length.
///
/// The v6->v4 twin of [`translate_icmpv6_message_to_icmpv4`]; same contract.
/// The ICMPv6 checksum is NOT computed here (it needs the IPv6 pseudo-header):
/// the caller's `recompute_l4_checksum_after_nat64_v4_to_v6` finishes it over
/// the full message, so this leaves the checksum field zeroed.
pub(super) fn translate_icmpv4_message_to_icmpv6(
    dst: &mut [u8],
    src: &[u8],
    embedded: &EmbeddedV4ToV6,
) -> Option<usize> {
    if src.len() < 4 {
        return None;
    }
    let icmpv4_type = src[0];
    let icmpv4_code = src[1];

    match icmpv4_type {
        ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY => {
            let out = dst.get_mut(..src.len())?;
            out.copy_from_slice(src);
            out[0] = if icmpv4_type == ICMP_ECHO_REQUEST {
                ICMPV6_ECHO_REQUEST
            } else {
                ICMPV6_ECHO_REPLY
            };
            out[1] = 0;
            // Checksum is recomputed by the caller (needs the v6 pseudo-header).
            out[2..4].copy_from_slice(&[0, 0]);
            Some(out.len())
        }
        ICMP_DEST_UNREACHABLE if icmpv4_code == 4 => {
            // An ICMP error always carries the full 8-byte header; reject a
            // truncated header before indexing the Next-Hop MTU word.
            if src.len() < 8 {
                return None;
            }
            // RFC 7915 4.2: ICMPv4 Fragmentation Needed (type 3 code 4) ->
            // ICMPv6 Packet Too Big (type 2). The Next-Hop MTU is in the low
            // 16 bits (bytes 6-7) of the ICMPv4 rest-of-header (RFC 1191); the
            // ICMPv6 PTB carries the MTU as a full 32-bit word (bytes 4-7).
            let v4_mtu = u16::from_be_bytes([src[6], src[7]]) as u32;
            // RFC 7915 §4.2: a zero Next-Hop MTU means the v4 router predates
            // RFC 1191 and reports no MTU. Recover a likely path MTU from the
            // quoted datagram's Total Length via the RFC 1191 plateau table
            // (greatest plateau below that length, floored at 1280) instead of
            // pinning every such client to 1280. The quoted header is src[8..];
            // a truncated or malformed quote has no usable Total Length and
            // keeps the 1280 floor rather than dropping the error. Non-zero
            // MTUs keep the plain +20 translation below.
            // The translated v6 datagram is 20 bytes larger than the v4 one, so
            // the v6 path MTU is 20 bytes larger; clamp to the v6 minimum link
            // MTU (1280) so a v6 client is never told to go below it.
            let v6_mtu = if v4_mtu == 0 {
                let quoted_total_len = src
                    .get(8..)
                    .filter(|q| q.len() >= 20 && (q[0] >> 4) == 4)
                    .map(|q| u16::from_be_bytes([q[2], q[3]]) as u32)
                    .unwrap_or(0);
                rfc1191_plateau_mtu(quoted_total_len)
            } else {
                v4_mtu.saturating_add(NAT64_HEADER_DELTA).max(IPV6_MIN_MTU)
            };
            write_icmpv6_error_with_embedded(
                dst,
                src,
                ICMPV6_PACKET_TOO_BIG,
                0,
                v6_mtu.to_be_bytes(),
                embedded,
            )
        }
        ICMP_DEST_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM => {
            let (v6_type, v6_code) = map_icmpv4_error_to_icmpv6(icmpv4_type, icmpv4_code)?;
            write_icmpv6_error_with_embedded(
                dst, src, v6_type, v6_code, [0, 0, 0, 0], embedded,
            )
        }
        _ => None,
    }
}

/// Build an ICMPv4 error message (8-byte header + translated embedded packet)
/// in `dst` from the ICMPv6 error `src`. `rest_of_header` is the 4-byte word
/// after type/code/checksum. Returns the written length, or `None` on a
/// malformed/oversized embedded packet.
pub(super) fn write_icmpv4_error_with_embedded(
    dst: &mut [u8],
    src: &[u8],
    v4_type: u8,
    v4_code: u8,
    rest_of_header: [u8; 4],
    embedded: &EmbeddedV6ToV4,
) -> Option<usize> {
    // The quoted original packet starts after the 8-byte ICMPv6 error header.
    let embedded_in = src.get(8..)?;
    // Translate the embedded IPv6 header (+leading L4) into a stack scratch
    // buffer — no heap alloc on the hot path (#2211).
    let mut scratch = [0u8; MAX_EMBEDDED_LEN];
    let embedded_len = translate_embedded_v6_to_v4(&mut scratch, embedded_in, embedded)?;

    let total = 8 + embedded_len;
    let out = dst.get_mut(..total)?;
    out[0] = v4_type;
    out[1] = v4_code;
    out[2..4].copy_from_slice(&[0, 0]); // checksum (computed below)
    out[4..8].copy_from_slice(&rest_of_header);
    out[8..total].copy_from_slice(&scratch[..embedded_len]);
    finalize_icmpv4_checksum(out);
    Some(total)
}

/// Build an ICMPv6 error message (8-byte header + translated embedded packet)
/// in `dst` from the ICMPv4 error `src`. The ICMPv6 checksum is left zeroed —
/// the caller recomputes it with the IPv6 pseudo-header.
pub(super) fn write_icmpv6_error_with_embedded(
    dst: &mut [u8],
    src: &[u8],
    v6_type: u8,
    v6_code: u8,
    rest_of_header: [u8; 4],
    embedded: &EmbeddedV4ToV6,
) -> Option<usize> {
    let embedded_in = src.get(8..)?;
    let mut scratch = [0u8; MAX_EMBEDDED_LEN];
    let embedded_len = translate_embedded_v4_to_v6(&mut scratch, embedded_in, embedded)?;

    let total = 8 + embedded_len;
    let out = dst.get_mut(..total)?;
    out[0] = v6_type;
    out[1] = v6_code;
    out[2..4].copy_from_slice(&[0, 0]); // checksum recomputed by caller
    out[4..8].copy_from_slice(&rest_of_header);
    out[8..total].copy_from_slice(&scratch[..embedded_len]);
    Some(total)
}

/// Translate the embedded (quoted) IPv6 header + leading L4 bytes of an ICMPv6
/// error into IPv4, writing into `dst` and returning the written length.
///
/// RFC 7915 §5.2: the embedded packet is translated like a normal v6->v4 packet
/// but with the embedded addresses' pre-computed mappings. The embedded L4 is
/// quoted (often truncated to 8 bytes), so its own checksum is left unchanged —
/// it is informational and a receiver does not validate the quoted L4 checksum.
/// The embedded packet is bounded to `MAX_EMBEDDED_LEN`; an oversized or
/// truncated-below-the-IPv6-header quote returns `None`.
pub(super) fn translate_embedded_v6_to_v4(
    dst: &mut [u8],
    embedded: &[u8],
    map: &EmbeddedV6ToV4,
) -> Option<usize> {
    let layout = embedded_v6_to_v4_layout(embedded)?;
    let l4_len = layout.l4.len();

    // `total` is the bytes physically emitted into the fixed scratch buffer,
    // not the advertised length above. Never size this slice from a truncated
    // quote's original datagram length.
    let total = 20usize.checked_add(l4_len)?;
    let out = dst.get_mut(..total)?;
    out[0] = 0x45;
    out[1] = layout.traffic_class;
    out[2..4].copy_from_slice(&(layout.advertised_total as u16).to_be_bytes());
    // #9128: carry the quoted packet's fragmentation fields instead of pinning
    // ID=0 / DF=1 unconditionally. RFC 7915 §5.2 defers to §5.1 for the
    // embedded header, and §5.1 requires -- when a Fragment Header is present
    // -- the Identification from its low 16 bits, DF cleared, and the M flag
    // and fragment offset copied. The OUTER v6->v4 translator has always done
    // this (see the `frag_word` computation in write_v6_to_v4_translate); only
    // the embedded twin pinned the fields.
    //
    // Non-first fragments are rejected by the shared layout; first and atomic
    // Fragment Header geometry reaches the copy below.
    //
    // The unfragmented case is byte-identical to before (0x4000, ID 0), and
    // deliberately does NOT borrow the outer translator's `next_frag_id()`
    // arm: that mints a fresh Identification for a datagram this box is about
    // to send, whereas a quote describes a packet that already exists on the
    // wire. Inventing an ID for it would be a fabrication, not a translation.
    let embedded_frag_word = layout.fragment_word;
    let embedded_ident = layout.identification;
    out[4..6].copy_from_slice(&embedded_ident.to_be_bytes()); // identification
    out[6..8].copy_from_slice(&embedded_frag_word.to_be_bytes()); // flags+offset
    out[8] = layout.hop_limit; // embedded hop limit copied verbatim (NOT decremented)
    out[9] = layout.ipv4_protocol;
    out[10..12].copy_from_slice(&[0, 0]); // header checksum (computed below)
    out[12..16].copy_from_slice(&map.mapped_embedded_src.octets());
    out[16..20].copy_from_slice(&map.mapped_embedded_dst.octets());
    out[20..total].copy_from_slice(layout.l4);

    // #6472: restore the quoted L4 destination port / echo identifier to the
    // TRANSLATED (pool) value the v4 server replied to. The quoted L4
    // checksum is intentionally left unchanged — it is informational and a
    // receiver does not validate it (the outer ICMP checksum below covers
    // these bytes). A truncated quote (< the port/id bytes) skips the
    // rewrite, exactly like the non-matching-protocol case.
    if let Some(port) = map.mapped_embedded_dst_port {
        if matches!(layout.l4_protocol, PROTO_TCP | PROTO_UDP) && l4_len >= 4 {
            out[22..24].copy_from_slice(&port.to_be_bytes());
        } else if layout.l4_protocol == PROTO_ICMPV6 && l4_len >= 6 {
            out[24..26].copy_from_slice(&port.to_be_bytes());
        }
    }

    // If the embedded protocol is ICMPv6, fix the embedded ICMP type byte so the
    // quoted v4 packet is internally consistent (the quoted L4 checksum is left
    // as-is — it is not validated by a receiver). Only the leading type/code are
    // touched; a fuller embedded-ICMP translation is unnecessary for the quote.
    if layout.l4_protocol == PROTO_ICMPV6 && l4_len >= 2 {
        if let Some((t, c)) = embedded_icmpv6_type_to_icmpv4(out[20]) {
            out[20] = t;
            out[21] = c;
        }
    }

    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    Some(total)
}

/// Translate the embedded (quoted) IPv4 header + leading L4 bytes of an ICMPv4
/// error into IPv6, writing into `dst` and returning the written length. The
/// v6->v4 twin of [`translate_embedded_v6_to_v4`]; same quote/checksum policy.
pub(super) fn translate_embedded_v4_to_v6(
    dst: &mut [u8],
    embedded: &[u8],
    map: &EmbeddedV4ToV6,
) -> Option<usize> {
    if embedded.len() < 20 {
        return None;
    }
    let ihl = ((embedded[0] & 0x0f) as usize) * 4;
    if ihl < 20 || embedded.len() < ihl {
        return None;
    }
    let quote_in = &embedded[..embedded.len().min(MAX_EMBEDDED_LEN - NAT64_HEADER_DELTA as usize)];
    let tos = quote_in[1];
    let ttl = quote_in[8];
    let protocol = quote_in[9];
    let total_len_field = u16::from_be_bytes([quote_in[2], quote_in[3]]) as usize;
    if total_len_field < ihl {
        return None;
    }

    let next_header = match protocol {
        PROTO_ICMP => PROTO_ICMPV6,
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };

    // #9129 Half B: a fragmented quote needs an IPv6 Fragment Header, or its
    // Identification and M flag are simply lost -- this function never read
    // quote_in[4..8] and set `out[6] = next_header` unconditionally, so the
    // translated quote described an unfragmented datagram that was never sent.
    // The OUTER v4->v6 translator already emits the header (#2488); this is the
    // embedded twin of that code, and RFC 7915 §5.2 asks for the same thing.
    //
    // Only a FIRST fragment reaches here: `parse_embedded_v4` (#1852) refuses a
    // quote whose offset is non-zero, because it has no L4 header to read. It
    // filters on OFFSET ONLY, so an `MF=1, offset=0` quote passes -- which is
    // exactly the case that was losing its fields. The offset is copied anyway
    // so this arm does not depend on that upstream guard for its correctness.
    let v4_frag_word = u16::from_be_bytes([quote_in[6], quote_in[7]]);
    let v4_more = (v4_frag_word & 0x2000) != 0;
    let v4_offset_units = v4_frag_word & 0x1FFF;
    let v4_ident = u16::from_be_bytes([quote_in[4], quote_in[5]]);
    let is_fragment = v4_more || v4_offset_units != 0;
    let frag_hdr_len = if is_fragment { 8 } else { 0 };
    // RFC 7915 §4.2 preserves the original IPv4 payload length and adds only
    // the generated Fragment Header, if this quoted packet needs one. This is
    // independent of how many quoted L4 bytes are physically available.
    let advertised_payload_len = total_len_field
        .checked_sub(ihl)?
        .checked_add(frag_hdr_len)?;
    if advertised_payload_len > u16::MAX as usize {
        return None;
    }

    // Quoted L4 bytes after the IPv4 header, capped by the advertised total
    // length and what was actually quoted. The advertised IPv6 Payload Length
    // is computed separately from the original IPv4 Total Length below.
    let end = total_len_field.min(quote_in.len());
    let mut l4 = quote_in.get(ihl..end)?;

    // The Fragment Header costs 8 bytes the caller's scratch was not sized
    // for: quote_in is already clamped to MAX_EMBEDDED_LEN - NAT64_HEADER_DELTA
    // so that `40 + l4_len` lands exactly on MAX_EMBEDDED_LEN at the maximum.
    // Growing past that would make `dst.get_mut(..total)` return None and turn
    // an unfaithful translation into a DROPPED ICMP error, which is a worse
    // outcome than the defect. Shorten the quote instead -- truncating a quote
    // is always legal for an ICMP error, and the receiver's demux keys on the
    // leading tuple, which is retained.
    let max_l4 = dst.len().saturating_sub(40 + frag_hdr_len);
    if l4.len() > max_l4 {
        l4 = &l4[..max_l4];
    }
    let l4_len = l4.len();

    let total = 40 + frag_hdr_len + l4_len;
    let out = dst.get_mut(..total)?;
    out[0] = 0x60 | (tos >> 4);
    out[1] = (tos & 0x0f) << 4;
    out[2] = 0;
    out[3] = 0;
    // Payload length advertises the original IPv4 payload plus any generated
    // Fragment Header, while `total` remains the physically emitted quote size.
    out[4..6].copy_from_slice(&(advertised_payload_len as u16).to_be_bytes());
    // A fragmented datagram chains a Fragment Header (44) after the base
    // header; the base next-header points at it and the Fragment Header carries
    // the real upper-layer protocol.
    out[6] = if is_fragment { 44 } else { next_header };
    out[7] = ttl; // embedded hop limit copied verbatim (NOT decremented)
    // Embedded src (our SNAT pool v4) -> original v6 client.
    out[8..24].copy_from_slice(&map.mapped_embedded_src.octets());
    // Embedded dst (the v4 server) -> NAT64 prefix :: dst-v4.
    out[24..36].copy_from_slice(&map.prefix_bytes);
    out[36..40].copy_from_slice(&quote_in[16..20]);
    // #9129: the 8-byte Fragment Header (RFC 8200 §4.5). Offset is copied
    // verbatim (both fields count 8-byte units), M mirrors IPv4 MF, and the
    // Identification is the IPv4 16-bit value zero-extended to 32 bits
    // (RFC 7915 §4) -- identical to the outer translator's #2488 emission.
    if is_fragment {
        out[40] = next_header;
        out[41] = 0; // reserved
        let frag_word = (v4_offset_units << 3) | u16::from(v4_more);
        out[42..44].copy_from_slice(&frag_word.to_be_bytes());
        out[44..48].copy_from_slice(&u32::from(v4_ident).to_be_bytes());
    }
    let l4_start = 40 + frag_hdr_len;
    out[l4_start..total].copy_from_slice(l4);

    // #6472: restore the quoted L4 source port / echo identifier to the
    // ORIGINAL v6 client value. The quote carries the TRANSLATED (pool)
    // source value; the client only associates the error with its session
    // when the quote reads back as the original tuple it sent. The quoted
    // L4 checksum is left unchanged (informational — same policy as the
    // address rewrite above); the outer ICMPv6 checksum recompute covers
    // these bytes. A truncated quote skips the rewrite.
    //
    // #9129: these offsets are relative to the L4 region, which a Fragment
    // Header shifts by 8. They were absolute before, because the L4 always
    // began at 40.
    if let Some(port) = map.mapped_embedded_src_port {
        if matches!(protocol, PROTO_TCP | PROTO_UDP) && l4_len >= 2 {
            out[l4_start..l4_start + 2].copy_from_slice(&port.to_be_bytes());
        } else if protocol == PROTO_ICMP && l4_len >= 6 {
            out[l4_start + 4..l4_start + 6].copy_from_slice(&port.to_be_bytes());
        }
    }

    if protocol == PROTO_ICMP && l4_len >= 2 {
        if let Some((t, c)) = embedded_icmpv4_type_to_icmpv6(out[l4_start]) {
            out[l4_start] = t;
            out[l4_start + 1] = c;
        }
    }
    Some(total)
}

/// Best-effort embedded ICMPv6->ICMPv4 type/code remap for the quoted L4 of an
/// embedded packet (echo only, which is the realistic embedded-ICMP case for a
/// PMTUD/traceroute error quoting a ping). Returns `None` to leave the byte
/// untouched for anything else — the quoted L4 is informational.
pub(super) fn embedded_icmpv6_type_to_icmpv4(t: u8) -> Option<(u8, u8)> {
    match t {
        ICMPV6_ECHO_REQUEST => Some((ICMP_ECHO_REQUEST, 0)),
        ICMPV6_ECHO_REPLY => Some((ICMP_ECHO_REPLY, 0)),
        _ => None,
    }
}

/// Best-effort embedded ICMPv4->ICMPv6 type/code remap (echo only); twin of
/// [`embedded_icmpv6_type_to_icmpv4`].
pub(super) fn embedded_icmpv4_type_to_icmpv6(t: u8) -> Option<(u8, u8)> {
    match t {
        ICMP_ECHO_REQUEST => Some((ICMPV6_ECHO_REQUEST, 0)),
        ICMP_ECHO_REPLY => Some((ICMPV6_ECHO_REPLY, 0)),
        _ => None,
    }
}

/// Zero then recompute the ICMPv4 checksum (no pseudo-header) over `icmp`.
pub(super) fn finalize_icmpv4_checksum(icmp: &mut [u8]) {
    if icmp.len() < 4 {
        return;
    }
    icmp[2..4].copy_from_slice(&[0, 0]);
    let sum = checksum16(icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
}

/// Recompute L4 checksum after IPv6→IPv4 translation.
pub(super) fn recompute_l4_checksum_after_nat64_v6_to_v4(packet: &mut [u8], protocol: u8) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    // Read IP addresses before taking mutable borrow of L4 portion.
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let l4 = &mut packet[20..];
    match protocol {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv4_pseudo(src, dst, protocol, l4);
            // RFC 768 / RFC 1624: in IPv4 UDP a checksum field of 0x0000 is the
            // reserved "no checksum present" sentinel. A genuinely computed
            // checksum of zero MUST be transmitted as 0xFFFF (all-ones) so the
            // receiver still validates it. `checksum16_ipv4_pseudo` returns the
            // final one's-complement value, so a 0x0000 here is a real computed
            // checksum, not an internal sentinel. Mirrors the v4->v6 UDP arm.
            let sum = canonicalize_zero_checksum(sum, protocol, ChecksumFamily::V4);
            l4[6..8].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMP => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv4 does NOT use pseudo-header — checksum over ICMP message only.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16(l4);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

/// Recompute L4 checksum after IPv4→IPv6 translation.
/// Apply the codebase's ONE zero-checksum rule to a freshly computed sum
/// (#9069).
///
/// `adjust_zero_checksum_illegal` (afxdp/frame/checksum.rs, #1839) is the
/// declared single source of truth for which (protocol, family) pairs may not
/// carry 0x0000: V4 UDP, and V6 UDP or ICMPv6. Every NAT64 recompute arm now
/// consults it instead of hand-rolling `if sum == 0 { 0xFFFF }` per arm.
///
/// THE DEFECT THIS CLOSES. The `PROTO_ICMPV6` arm of the v4->v6 recompute wrote
/// `sum` raw while its own UDP sibling ten lines above canonicalised — so a
/// translated ICMPv6 message whose checksum folded to zero was emitted as
/// 0x0000, which the SSOT says is illegal and which the afxdp-side
/// `recompute_l4_checksum_ipv6` canonicalises. The zero is PRODUCIBLE, not
/// theoretical: an Echo Reply payload ending (0xa1, 0x2a) folds to it.
///
/// WHAT THIS IS AND IS NOT. It is an internal consistency fix against a declared
/// SSOT. It is NOT a wire-correctness fix: the originating report cited RFC 4443
/// §2.3 and RFC 8200 §8.1 for a mandatory all-ones substitution on ICMPv6, and
/// that rule is UDP-SPECIFIC in RFC 8200 §8.1 while RFC 4443 §2.3 contains no
/// such sentence. A 0x0000 ICMPv6 checksum verifies correctly at a compliant
/// receiver — there is no "no checksum" sentinel for ICMPv6 — so the claimed
/// drop does not follow and is not claimed here.
///
/// The rule must NOT over-apply. A computed TCP 0x0000 is legal on the wire in
/// both families, and V4 ICMP has no pseudo-header and no sentinel; both fall
/// out of `adjust_zero_checksum_illegal` returning false, which is exactly why
/// consulting it beats writing the condition again.
pub(super) fn canonicalize_zero_checksum(sum: u16, protocol: u8, family: ChecksumFamily) -> u16 {
    if sum == 0 && adjust_zero_checksum_illegal(protocol, family) {
        return 0xFFFF;
    }
    sum
}

pub(super) fn recompute_l4_checksum_after_nat64_v4_to_v6(packet: &mut [u8], next_header: u8) -> Option<()> {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    let l4 = &mut packet[40..];
    match next_header {
        PROTO_TCP => {
            if l4.len() < 20 {
                return None;
            }
            l4[16..18].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            let sum = canonicalize_zero_checksum(sum, next_header, ChecksumFamily::V6);
            l4[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            l4[6..8].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            // UDP over IPv6: zero is illegal; the SSOT says so, and #9069 routes
            // this through it rather than restating it.
            let sum = canonicalize_zero_checksum(sum, next_header, ChecksumFamily::V6);
            l4[6..8].copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if l4.len() < 4 {
                return None;
            }
            // ICMPv6 DOES use pseudo-header.
            l4[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6_pseudo(src, dst, next_header, l4);
            // #9069: THE arm that was missing the canonicalisation.
            let sum = canonicalize_zero_checksum(sum, next_header, ChecksumFamily::V6);
            l4[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}
