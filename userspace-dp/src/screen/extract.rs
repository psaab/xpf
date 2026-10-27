//! Allocation-free extraction of screen-relevant fields from raw
//! packet bytes plus the upstream parser's metadata. Parses just
//! enough of IPv4/IPv6 + TCP options to populate `ScreenPacketInfo`.

use std::net::IpAddr;

use super::packet::{PROTO_TCP, ScreenPacketInfo, ScreenParseError};
use crate::afxdp::frame::{ExtChainOutcome, walk_ipv6_ext_chain};

/// Extract screen-relevant fields from raw packet bytes and metadata.
/// This avoids full packet parsing — just reads the fields needed for checks.
///
/// Returns `Err(ScreenParseError)` when the L3 header cannot be parsed
/// far enough to evaluate the fragment/TCP screens (#2146). The caller
/// MUST treat an `Err` as FAIL-CLOSED (drop). A truncated IPv6
/// extension-header chain used to `break` out of the walk silently and
/// leave `is_first_fragment=false`, which let a SYN-bearing frame with
/// a truncated FRAGMENT header bypass the `syn-frag` screen — the exact
/// IDS-evasion the screen claims to defend against now that the BPF
/// screen path (#1373/#1476) that masked it is gone.
///
/// #4167 (fable-review-164 L-11): the IPv4 arm is now SYMMETRIC with the
/// IPv6 fail-closed contract. A too-short IPv4 base header (fewer than
/// the fixed 20 bytes captured at `l3_offset`) or an IHL that claims a
/// header longer than the captured frame (`l3_offset + ihl*4 >
/// frame.len()`) returns `Err(TruncatedIpv4Header)` instead of falling
/// through to `Ok(defaults)`. The old fall-through left `is_fragment=
/// false`/`ip_ihl=5`/`saw_ipv4_source_route=false`, so a malformed IPv4
/// frame bypassed `check_ping_of_death`/`check_teardrop`/
/// `check_icmp_fragment`/`check_source_route` — the IPv4 mirror of the
/// IPv6 fail-open the #2146 hardening closed.
///
/// #4543: the IPv4 options TLV walk is now fail-closed on a MALFORMED
/// option too, not only on a truncated header. A length-prefixed option
/// whose length byte is missing, is `< 2`, or runs past the options
/// region returns `Err(TruncatedIpv4Header)` instead of `break`ing. The
/// LSRR/SSRR kind test precedes the length check, so the old `break`
/// aborted the scan before a source-route option placed AFTER a bad
/// option could be seen — a `source-route` screen bypass. This completes
/// #4167's fail-closed contract for the option region and matches vSRX,
/// which drops malformed IP options / source-route regardless of order.
///
/// #3120: the IPv6 walk CONTINUES past the Fragment header for a
/// FIRST fragment (fragment offset == 0) instead of stopping at it, so a
/// `Fragment → Destination-Options → TCP` chain (RFC 8200 permits an
/// extension header after the fragment header) still reaches the real L4
/// header and exposes the TCP seq/ack/flags/MSS to the TCP-flag screens
/// and the SYN-cookie flood challenge. A NON-FIRST fragment (offset > 0)
/// genuinely carries no L4 header in this packet, so the walk stops
/// there (the #2344/#3064 flowless handling). The continuation is the
/// shared walker's, bounded by `MAX_IPV6_EXT_HEADERS` (#17106).
/// The protocol value the SHIM substitutes for a non-first fragment, which has
/// no L4 header to read a real protocol from (#9114).
///
/// KEEP IN SYNC with `userspace-xdp/src/ipv6_ext_walk.rs`'s
/// `PROTO_FRAGMENT_NO_L4`. The shim crate is not a dependency of this one — the
/// only place userspace-dp reaches it is a `#[path]` include inside a parity
/// test — so the literal is mirrored rather than shared. 255 is reserved
/// (IANA "Reserved"), so it can never collide with a real protocol number.
const SHIM_PROTO_FRAGMENT_NO_L4: u8 = 255;

pub(crate) fn extract_screen_info(
    frame: &[u8],
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    pkt_len: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    l3_offset: usize,
) -> Result<ScreenPacketInfo, ScreenParseError> {
    // #10729 X2-F6 / #17106: a v6 chain sighting AH screens as AH (proto
    // 51, no L4), symmetric with v4 where AH is terminal. Applied below
    // from the single shared walk's `ah_present`, not a second walk.
    let mut info = ScreenPacketInfo {
        addr_family,
        protocol,
        tcp_flags,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags_unknown: false,
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_mss: 0,
        pkt_len,
        is_fragment: false,
        is_first_fragment: false,
        ip_ihl: 5,
        ip_frag_off: 0,
        ip_total_len: 0,
        ip_payload_len: 0,
        frag_data_off: 0,
        saw_ipv4_source_route: false,
        saw_ipv6_routing_header: false,
    };

    let mut tcp_offset: Option<usize> = None;

    if addr_family == libc::AF_INET as u8 {
        // FAIL-CLOSED (#4167 / fable-review-164 L-11): a too-short IPv4
        // base header — fewer than the mandatory 20 bytes captured at
        // `l3_offset` — cannot be parsed to evaluate the fragment /
        // source-route / ICMP screens. Return an `Err` so the caller
        // fail-closes (drop), MIRRORING the IPv6 `l3_offset + 40 >
        // frame.len()` arm below. Before this, the too-short IPv4 case
        // fell through to the terminal `Ok(info)` with defaults
        // (`is_fragment=false`, `ip_ihl=5`, `saw_ipv4_source_route=
        // false`), which made `check_ping_of_death` / `check_teardrop` /
        // `check_icmp_fragment` / `check_source_route` all early-return
        // and let a truncated frame pass UNSCREENED — a fail-open
        // asymmetry vs the IPv6 #2146 fail-closed contract. A valid
        // minimal 20-byte IPv4 header (IHL=5, no options) is NOT
        // dropped; only a runt/malformed capture shorter than the base
        // header its own layout requires.
        if l3_offset + 20 > frame.len() {
            return Err(ScreenParseError::TruncatedIpv4Header);
        }
        // IPv4: extract IHL, total_len, frag_off from the fixed 20-byte
        // base header. frag_off is bytes 6-7, big-endian.
        let ip_hdr = &frame[l3_offset..];
        info.ip_ihl = ip_hdr[0] & 0x0F;
        info.ip_total_len = u16::from_be_bytes([ip_hdr[2], ip_hdr[3]]);
        info.ip_frag_off = u16::from_be_bytes([ip_hdr[6], ip_hdr[7]]);
        // Fragment if MF bit (0x2000) set OR fragment offset (0x1FFF) > 0.
        // First fragment: MF=1 AND offset==0 (#1137, mirrors BPF #866).
        info.is_fragment = (info.ip_frag_off & 0x3FFF) != 0;
        info.is_first_fragment =
            (info.ip_frag_off & 0x2000) != 0 && (info.ip_frag_off & 0x1FFF) == 0;
        // #9114: RECOVER the real protocol when the caller handed us the shim's
        // non-first-fragment sentinel.
        //
        // `userspace-xdp` substitutes `PROTO_FRAGMENT_NO_L4` for a non-first
        // fragment's protocol BEFORE `parse_l4`, and that value rides
        // `meta.protocol` through `stage_screen_check` into here unchanged. The
        // screens are then keyed on a protocol that is not the packet's, so
        // `check_icmp_fragment`, `icmp-flood` and `udp-flood` — all of which
        // test `protocol == PROTO_ICMP/ICMPV6/UDP` — never fire on the exact
        // packets they exist to police. It is a MISS, not an over-match: every
        // other protocol-keyed screen tests `== PROTO_TCP` or `!= PROTO_TCP`
        // and DECLINES on the sentinel, which is correct for a fragment with no
        // L4 header (`check_tcp_flag_screens` carries its own explicit
        // non-first-fragment guard immediately below its protocol test).
        //
        // The IPv4 protocol byte is at header offset 9 and is present: the
        // 20-byte base header was length-validated above. Gated on the sentinel
        // so an ordinary packet's protocol is passed through untouched.
        if info.protocol == SHIM_PROTO_FRAGMENT_NO_L4 {
            info.protocol = ip_hdr[9];
        }
        // FAIL-CLOSED (#4167): the header's own IHL claims a header
        // (`ihl*4`) longer than the captured frame, so the options
        // region — and thus any LSRR/SSRR source-route option — cannot
        // be parsed. Drop rather than silently skip the scan below,
        // which would leave `saw_ipv4_source_route=false` for a route
        // the extractor was UNABLE to read (a fail-open on the
        // `source-route` screen). Mirrors the IPv6 extension-header
        // overshoot fail-closed check. A minimal IHL=5 header always
        // survives — `l3_offset + 20 <= frame.len()` was just asserted.
        let ihl_bytes = (info.ip_ihl as usize) * 4;
        // FAIL-CLOSED (#8298): RFC 791 makes IHL >= 5 mandatory, and the two
        // checks around this one cannot catch a SHORTER-than-legal header —
        // both guard the header being LONGER than the capture, and
        // `ihl_bytes` of 0..16 is smaller than the 20 bytes already asserted
        // present, so both pass. The declared length is then believed by every
        // downstream consumer.
        //
        // `check_teardrop` is the consumer that matters: it computes
        // `hdr_len = ip_ihl * 4` and subtracts it from `ip_total_len`, so an
        // IHL of 0 makes the payload read as the WHOLE total length. The
        // canonical teardrop — a non-first fragment whose real payload is
        // under 8 bytes — then clears the `< 8` test it exists to fail, and
        // the attacker picks IHL, total_len and frag_off independently.
        //
        // REACHABLE, measured rather than assumed. A non-first fragment is
        // classified FLOWLESS by `parse_session_flow_from_bytes` (#2344) — a
        // classification, not a drop — before any header-length validation,
        // and neither `poll_descriptor/mod.rs` nor `poll_stages.rs` checks
        // `ihl` at all. So the frames that skip flow parsing are exactly the
        // non-first fragments this screen is for. Bound end-to-end by
        // `flowless_teardrop_fragment_with_ihl_zero_is_still_dropped_8298`,
        // whose sibling `flowless_teardrop_fragment_dropped_3064` is the
        // control: the same frame without the IHL mutation.
        //
        // Rejecting here rather than clamping in `check_teardrop` because this
        // is the documented fail-closed boundary — "a runt/malformed capture
        // shorter than the base header its own layout requires" is exactly an
        // IHL below 5, declared rather than measured — and a clamp would leave
        // every other consumer of `ip_ihl` believing the bogus value.
        if info.ip_ihl < 5 {
            return Err(ScreenParseError::TruncatedIpv4Header);
        }
        if l3_offset + ihl_bytes > frame.len() {
            return Err(ScreenParseError::TruncatedIpv4Header);
        }
        // FAIL-CLOSED (#9901, F-075): the declared total length cannot cover
        // the header it counts — an impossible datagram. The shim refuses the
        // same shape before classification (`ipv4_declared_len_covers_header`,
        // one gate shared by source, parity-pinned in
        // `screen/tests_9901_len_gate.rs`); refusing here as well keeps a
        // frame that bypasses the shim (slow path, injected, replayed) from
        // reaching the option scan and the length-arithmetic screens below
        // with a header no consumer can bound. A bare-header datagram
        // (total == ihl*4) is possible and still passes — only the impossible
        // shorter-than-header shape is refused.
        if (info.ip_total_len as usize) < ihl_bytes {
            return Err(ScreenParseError::TruncatedIpv4Header);
        }
        // #2973: scan the IPv4 options region (bytes 20..ihl*4) for an
        // actual source-route option. The `source-route` screen used to
        // drop on ANY IHL>5 (any options present), which also dropped
        // benign router-alert/record-route/timestamp/security packets.
        // Detect only LSRR (option type 131 = copied|control|9) and
        // SSRR (137 = copied|control|11). Bounded TLV walk; EOOL(0) ends,
        // NOP(1) is one byte, every other option is length-prefixed.
        // The options region is guaranteed captured by the fail-closed
        // `l3_offset + ihl_bytes > frame.len()` check above.
        //
        // FAIL-CLOSED (#4543): a MALFORMED length-prefixed option (a
        // length byte at the very end of the options region with no room
        // for the length field, or a declared length < 2, or one that
        // runs past the options end) returns `Err(TruncatedIpv4Header)`
        // instead of `break`. The kind==LSRR/SSRR test necessarily
        // precedes the length check, so a `break` on a malformed option
        // ABORTED the walk before a source-route option placed AFTER it
        // could be seen — leaving `saw_ipv4_source_route=false` so
        // `check_source_route` passed a packet the extractor could not
        // fully parse. An attacker could prepend `[type=0x44,len=0x01]`
        // to an LSRR and evade the `source-route` screen the operator
        // enabled. Dropping the malformed frame mirrors #4167's
        // truncation fail-closed contract and vSRX, which drops malformed
        // IP options / source-route regardless of option ordering. A
        // WELL-FORMED options list (including a well-formed LSRR/SSRR the
        // screen must catch) is unaffected: every option's length is
        // consistent, so the walk advances normally and the LSRR/SSRR arm
        // still fires.
        if info.ip_ihl > 5 {
            const IPOPT_EOOL: u8 = 0;
            const IPOPT_NOP: u8 = 1;
            const IPOPT_LSRR: u8 = 131;
            const IPOPT_SSRR: u8 = 137;
            let opt_end = l3_offset + ihl_bytes;
            let mut pos = l3_offset + 20;
            while pos < opt_end {
                let kind = frame[pos];
                if kind == IPOPT_EOOL {
                    break;
                }
                if kind == IPOPT_NOP {
                    pos += 1;
                    continue;
                }
                if kind == IPOPT_LSRR || kind == IPOPT_SSRR {
                    info.saw_ipv4_source_route = true;
                    // #15947 (H28-02): validate the source-route option's
                    // own length and keep walking instead of breaking:
                    // the pre-fix break returned Ok for a truncated LSRR
                    // (no length byte), an LSRR with opt_len < 3 or
                    // overrunning opt_end, and never walked a malformed
                    // TLV placed after a well-formed LSRR — so with the
                    // source-route screen disabled the malformed header
                    // forwarded unscreened, breaking the #4543 contract
                    // that ip-malformed drops regardless of that setting.
                    // LSRR/SSRR are length-prefixed (kind, len, pointer,
                    // route data), so the minimum well-formed length is 3.
                    if pos + 1 >= opt_end {
                        return Err(ScreenParseError::TruncatedIpv4Header);
                    }
                    let opt_len = frame[pos + 1] as usize;
                    if opt_len < 3 || pos + opt_len > opt_end {
                        return Err(ScreenParseError::TruncatedIpv4Header);
                    }
                    pos += opt_len;
                    continue;
                }
                // Length-prefixed option: byte at pos+1 is the total
                // option length (including the kind/length bytes). A
                // length byte at the very end of the options region (no
                // room to read it) is a MALFORMED option — fail closed
                // (#4543) rather than `break`, which would let an LSRR/
                // SSRR placed AFTER the bad option evade the source-route
                // screen.
                if pos + 1 >= opt_end {
                    return Err(ScreenParseError::TruncatedIpv4Header);
                }
                let opt_len = frame[pos + 1] as usize;
                // A declared length < 2 (impossible for a length-prefixed
                // option) or one running past the options end is MALFORMED
                // — fail closed (#4543), same reasoning as above.
                if opt_len < 2 || pos + opt_len > opt_end {
                    return Err(ScreenParseError::TruncatedIpv4Header);
                }
                pos += opt_len;
            }
        }
        tcp_offset = Some(l3_offset + ihl_bytes);
    } else if addr_family == libc::AF_INET6 as u8 {
        // IPv6: ONE shared walk (#17106). Fixed IPv6 base header is 40 bytes.
        //
        // #6885: the shared walk resolves chains of 0..=7 extension headers
        // and reports `OverLimit` at 8 or more. Measured, not asserted:
        // `screen_ext_header_depth_agrees_with_the_forwarding_walker_6885`
        // drives chains of 0..=10 headers through this extractor AND through
        // `walk_ipv6_ext_chain` and requires the two to agree at every length.
        // The shim's parity condition is stated once, authoritatively, at
        // `userspace-xdp/src/ipv6_ext_walk.rs` (`MAX_EXT_HDRS ==
        // MAX_IPV6_EXT_HEADERS - 1`); #4555 moved it from 6 to 7 to reach it.
        //
        // FAIL-CLOSED (#2146): every place the walk runs out of bytes
        // (the base header is short, or an extension header's declared
        // length runs past the captured frame) returns
        // `Err(TruncatedIpv6ExtChain)`. Returning defaults here would
        // leave `is_first_fragment=false` and let a SYN-bearing frame
        // with a truncated FRAGMENT header bypass the `syn-frag`
        // screen. The legacy BPF `parse_ipv6hdr` returned -1 (drop)
        // on the same condition; with the BPF screen path retired
        // (#1373/#1476) the extractor is the only enforcement point.
        //
        // OverLimit decision (#17106, explicit): the old private walk fell
        // out of its `0..8` loop and returned `Ok` with `tcp_offset = None`
        // on an 8+ chain. The shared walk reports `OverLimit` for the same
        // chain, and the forwarding path already fails closed on it
        // (`frame_l4_offset` -> None, `ipv6_ext_chain_over_limit` -> drop).
        // The screen now maps `OverLimit` to `Err(TruncatedIpv6ExtChain)`
        // ("ip-malformed") as well: an uninspectable chain must not pass
        // unscreened merely because it is long rather than short. The
        // #6885 depth cell is updated to pin this Err explicitly.
        if l3_offset + 40 > frame.len() {
            return Err(ScreenParseError::TruncatedIpv6ExtChain);
        }
        // #2293: IPv6 payload-length field (bytes 4-5 of the 40-byte base
        // header) — the length of everything after the base header
        // (extension headers + L4 + data). The ping-of-death check uses
        // it with `frag_data_off` to size a fragment's contribution to
        // the reassembled datagram.
        info.ip_payload_len = u16::from_be_bytes([frame[l3_offset + 4], frame[l3_offset + 5]]);
        let walk = walk_ipv6_ext_chain(frame, l3_offset);
        // Outcome mapping first: Truncated and OverLimit fail closed
        // before any sighting is folded, so a truncated second Fragment
        // header reports Truncated (not Multiple), matching #14325's
        // "checked after the truncation guard" ordering.
        match walk.outcome {
            ExtChainOutcome::Truncated | ExtChainOutcome::OverLimit => {
                return Err(ScreenParseError::TruncatedIpv6ExtChain);
            }
            ExtChainOutcome::L4(off, 6) => {
                tcp_offset = Some(off);
            }
            ExtChainOutcome::L4(_, _)
            | ExtChainOutcome::NoNextHeader
            | ExtChainOutcome::NonFirstFragment => {}
        }
        // #14325: a SECOND readable non-ATOMIC Fragment header is rejected
        // outright. RFC 8200 allows each extension-header type at most
        // once, and there is no defined screening meaning to choose
        // between two non-ATOMIC headers — receivers key reassembly on
        // the first and treat the second as payload. Pure-ATOMIC repeats
        // stay ignored; a lone ATOMIC followed by a real header is still
        // governed by the real header (#10661).
        if walk.second_non_atomic_seen {
            return Err(ScreenParseError::MultipleIpv6FragmentHeaders);
        }
        info.saw_ipv6_routing_header = walk.rh_source_route_seen;
        // #14129/#10661: the FIRST readable non-ATOMIC sighting governs.
        // An ATOMIC header (offset 0, M 0) is a no-op (RFC 8200 4.5) and
        // never sets these fields, nor clears a real sighting.
        if let Some(frag) = walk.first_non_atomic_fragment {
            // Readable by construction (`first_non_atomic_fragment` only
            // records readable headers); the fallback keeps this total.
            let frag_off = frag
                .bytes
                .map(|b| u16::from_be_bytes([b[2], b[3]]))
                .unwrap_or(0);
            info.ip_frag_off = frag_off;
            info.is_fragment = true;
            info.is_first_fragment = (frag_off & 0x1) != 0 && (frag_off & 0xFFF8) == 0;
            // #2293: payload-region bytes that precede THIS (governing)
            // fragment's data.
            info.frag_data_off = ((frag.header_offset + 8).saturating_sub(l3_offset + 40)) as u16;
            // #9114: a NON-FIRST fragment carries no L4 header here, so
            // recover the real protocol from the governing Fragment
            // header's own NextHdr byte (present on every fragment).
            // Gated on the sentinel so a caller that already knew the
            // protocol keeps it. Only the governing (first non-ATOMIC)
            // header names it — for [ATOMIC][real-non-first] that is the
            // real header, exactly as the old walk's break did.
            if (frag_off & 0xFFF8) != 0 && info.protocol == SHIM_PROTO_FRAGMENT_NO_L4 {
                if let Some(b) = frag.bytes {
                    info.protocol = b[0];
                }
            }
        }
        // #10729 X2-F6: AH sighted anywhere readable screens as AH
        // (proto 51, no L4) — applied after the fragment protocol
        // recovery above so AH wins exactly as the old pre-walk did
        // (it rewrote protocol/flags/ports before any fragment logic).
        if walk.ah_present {
            info.protocol = crate::ip_proto::PROTO_AH;
            info.tcp_flags = 0;
            info.src_port = 0;
            info.dst_port = 0;
            tcp_offset = None;
        }
    }

    // #16007: a TCP first fragment whose DECLARED datagram ends before
    // the flags byte (L4+14) has UNKNOWN flags. The caller-supplied
    // `tcp_flags` for such a packet is the shim's 0 stamp (or a slow-path
    // equivalent), which `check_tcp_flag_screens` would otherwise read
    // as a proven no-flag packet and `strict_syn_check` as a proven
    // non-SYN. Fail closed here — the one place every screened path
    // crosses — with the `syn-frag` reason. Declared end is computed
    // from the IP header itself (total_len / payload_len), never from
    // capture length, so Ethernet slack cannot manufacture or hide it.
    // A zero declared length means no declared bound was supplied
    // (synthetic metas) and manufactures no verdict.
    if protocol == PROTO_TCP && info.is_first_fragment {
        let declared_end = if addr_family == libc::AF_INET as u8 {
            if info.ip_total_len == 0 {
                usize::MAX
            } else {
                l3_offset.saturating_add(info.ip_total_len as usize)
            }
        } else if info.ip_payload_len == 0 {
            usize::MAX
        } else {
            l3_offset
                .saturating_add(40)
                .saturating_add(info.ip_payload_len as usize)
        };
        if let Some(tcp_start) = tcp_offset
            && declared_end < tcp_start.saturating_add(14)
        {
            return Err(ScreenParseError::TinyFirstFragmentFlagsUnknown);
        }
    }

    if protocol == PROTO_TCP
        && (!info.is_fragment || info.is_first_fragment)
        && let Some(tcp_start) = tcp_offset
        && tcp_start + 20 <= frame.len()
    {
        let tcp = &frame[tcp_start..];
        info.tcp_seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        info.tcp_ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        if data_offset >= 20 && tcp.len() >= data_offset {
            let mut pos = 20;
            while pos < data_offset {
                let kind = tcp[pos];
                if kind == 0 {
                    break;
                }
                if kind == 1 {
                    pos += 1;
                    continue;
                }
                if pos + 2 > data_offset {
                    break;
                }
                let opt_len = tcp[pos + 1] as usize;
                if opt_len < 2 || pos + opt_len > data_offset {
                    break;
                }
                if kind == 2 && opt_len == 4 {
                    info.tcp_mss = u16::from_be_bytes([tcp[pos + 2], tcp[pos + 3]]);
                    break;
                }
                pos += opt_len;
            }
        }
    }

    Ok(info)
}
