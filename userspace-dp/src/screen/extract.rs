//! Allocation-free extraction of screen-relevant fields from raw
//! packet bytes plus the upstream parser's metadata. Parses just
//! enough of IPv4/IPv6 + TCP options to populate `ScreenPacketInfo`.

use std::net::IpAddr;

use crate::afxdp::frame::{IPV6_GENERIC_EXT_HEADERS, ipv6_ext_header_is_traversable};
use super::packet::{PROTO_TCP, ScreenPacketInfo, ScreenParseError};

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
/// #3120: the IPv6 walk now CONTINUES past the Fragment header for a
/// FIRST fragment (fragment offset == 0) instead of stopping at it, so a
/// `Fragment → Destination-Options → TCP` chain (RFC 8200 permits an
/// extension header after the fragment header) still reaches the real L4
/// header and exposes the TCP seq/ack/flags/MSS to the TCP-flag screens
/// and the SYN-cookie flood challenge. A NON-FIRST fragment (offset > 0)
/// genuinely carries no L4 header in this packet, so the walk still stops
/// there (the #2344/#3064 flowless handling). The continuation stays
/// bounded by the `for _ in 0..8` extension-header cap and the
/// top-of-loop `offset > frame.len()` fail-closed check (#2361).
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
    let mut info = ScreenPacketInfo {
        addr_family,
        protocol,
        tcp_flags,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
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
        // `afxdp/tests_ipv4_len_gate_9901.rs`); refusing here as well keeps a
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
                    break;
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
        // IPv6: walk the extension header chain looking for
        // NEXTHDR_FRAGMENT (44). Fixed IPv6 base header is 40 bytes.
        //
        // #6885: the bound below is `0..8` ITERATIONS, and one iteration is
        // spent on the terminal (the arm that sets `tcp_offset` and breaks),
        // so this walk resolves chains of **0..=7 extension headers** and
        // refuses 8 or more. Measured, not asserted:
        // `screen_ext_header_depth_agrees_with_the_forwarding_walker_6885`
        // drives chains of 0..=10 headers through this extractor AND through
        // `walk_ipv6_ext_chain` and requires the two to agree at every length.
        //
        // That depth is shared by all three IPv6 ext-header walkers in the
        // tree, which reach it by DIFFERENT mechanisms and therefore carry
        // three different numbers — which is why the number alone was never
        // safe to state here:
        //
        //   this extractor            `0..8` iterations, terminal costs one
        //   `walk_ipv6_ext_chain`     MAX_IPV6_EXT_HEADERS = 8, ditto, and
        //                             folds exhaustion into `OverLimit`
        //   the AF_XDP shim           MAX_EXT_HDRS = 7, exits by EXHAUSTION
        //                             carrying the next-header, so it needs
        //                             no terminal iteration
        //
        // The shim's parity condition is stated once, authoritatively, at
        // `userspace-xdp/src/ipv6_ext_walk.rs` (`MAX_EXT_HDRS ==
        // MAX_IPV6_EXT_HEADERS - 1`); #4555 moved it from 6 to 7 to reach it.
        // #9901 (F-072): the DEPTH still differs by mechanism, but the
        // TRAVERSED SET no longer does — the generic arm below guards on the
        // shared `IPV6_GENERIC_EXT_HEADERS` const, the same source the
        // forwarding verdict delegates to.
        //
        // The comment this replaces read "We bound the walk to
        // MAX_EXT_HDRS=8 like the BPF parser", and both halves were false: no
        // constant named `MAX_EXT_HDRS` has ever been 8 (it is 7 in the live
        // shim and 6 in the retired BPF header), and the BPF parser bounded
        // at 6 — so it was never in parity with this walk at all. The parity
        // is real; the number and the peer named for it were not.
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
        if l3_offset + 40 > frame.len() {
            return Err(ScreenParseError::TruncatedIpv6ExtChain);
        }
        // #2293: IPv6 payload-length field (bytes 4-5 of the 40-byte base
        // header) — the length of everything after the base header
        // (extension headers + L4 + data). The ping-of-death check uses
        // it with `frag_data_off` to size a fragment's contribution to
        // the reassembled datagram.
        info.ip_payload_len = u16::from_be_bytes([frame[l3_offset + 4], frame[l3_offset + 5]]);
        const NEXTHDR_HOP: u8 = 0;
        const NEXTHDR_ROUTING: u8 = 43;
        const NEXTHDR_FRAGMENT: u8 = 44;
        const NEXTHDR_DEST: u8 = 60;
        const NEXTHDR_AUTH: u8 = 51;
        // #4517: the remaining IANA-assigned IPv6 extension headers that
        // share the generic length-prefixed layout (byte 0 = next header,
        // byte 1 = HdrExtLen in 8-octet units excluding the first 8) —
        // Mobility (135, RFC 6275 §6.1), HIP (139, RFC 7401 §5.1), Shim6
        // (140, RFC 5533 §5.1), and the two experimental/testing values
        // (253/254, RFC 3692 / RFC 4727). Before #4517 these fell to the
        // terminal `_ => break` arm, so a chain such as
        // `HOP → MOBILITY → FRAGMENT → TCP(SYN)` STOPPED at the Mobility
        // header: `is_fragment`/`is_first_fragment` stayed false and the
        // SYN was never reached, so the `syn-frag`/teardrop/ping-of-death
        // fragment screens could not fire — an ext-header IDS evasion. ESP
        // (50) is deliberately NOT walked: its payload is encrypted and the
        // inner next-header is unreadable, so stopping there is correct.
        const NEXTHDR_MOBILITY: u8 = 135;
        const NEXTHDR_HIP: u8 = 139;
        const NEXTHDR_SHIM6: u8 = 140;
        const NEXTHDR_EXP1: u8 = 253;
        const NEXTHDR_EXP2: u8 = 254;
        let mut nexthdr = frame[l3_offset + 6];
        let mut offset = l3_offset + 40;
        for _ in 0..8 {
            // FAIL-CLOSED (#2146/#2189): an intermediate extension header
            // can advance `offset` past the captured frame using its own
            // DECLARED length (HOP/ROUTING/DEST `hdr_ext_len`, AUTH
            // `payload_len`). The terminal arms below (`NEXTHDR_FRAGMENT`,
            // `PROTO_TCP`, `_`) read or trust `offset`, so re-validate it
            // at the TOP of every iteration before any arm runs. Without
            // this, a base NextHdr=HOP-BY-HOP with HdrExtLen=200 jumps
            // `offset` far past `frame.len()`, then an inner NextHdr=TCP
            // hits `PROTO_TCP`, sets `tcp_offset=Some(offset)` and breaks
            // with `Ok{is_first_fragment:false}` — a SYN bypasses the
            // `syn-frag` screen (the IDS evasion #2146 set out to close).
            if offset > frame.len() {
                return Err(ScreenParseError::TruncatedIpv6ExtChain);
            }
            // #9901 (F-072): the local arm decision must agree with the SHARED
            // traversed-set verdict on every iteration. The generic arm below
            // guards on the shared const directly; this assert pins the FULL
            // local set (routing + generic + AH + Fragment, terminally
            // excluding 59/ESP like the predicate) to it, so editing either
            // side without the other reds every extractor test in debug builds.
            // Zero release cost.
            debug_assert_eq!(
                matches!(
                    nexthdr,
                    NEXTHDR_ROUTING
                        | NEXTHDR_HOP
                        | NEXTHDR_DEST
                        | NEXTHDR_MOBILITY
                        | NEXTHDR_HIP
                        | NEXTHDR_SHIM6
                        | NEXTHDR_EXP1
                        | NEXTHDR_EXP2
                        | NEXTHDR_AUTH
                        | NEXTHDR_FRAGMENT
                ),
                ipv6_ext_header_is_traversable(nexthdr),
                "#9901: screen extractor arm set drifted from the shared IPv6 \
                 ext-header verdict",
            );
            match nexthdr {
                NEXTHDR_ROUTING => {
                    // #2973: an IPv6 Routing Header. Byte at offset+2 is
                    // the routing type. Type 0 (RH0, the deprecated
                    // source-route routing header, RFC 5095) and the
                    // legacy/experimental type 1 are source routing;
                    // type 2 (Mobile IPv6) and other types are not. We
                    // need offset+4 to safely read the type byte (the
                    // generic HOP/DEST arm only needs offset+2). Mirror
                    // the IPv4 LSRR/SSRR `source-route` screen for parity.
                    if offset + 4 > frame.len() {
                        return Err(ScreenParseError::TruncatedIpv6ExtChain);
                    }
                    let routing_type = frame[offset + 2];
                    if routing_type == 0 || routing_type == 1 {
                        info.saw_ipv6_routing_header = true;
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 1) * 8;
                }
                // #9901 (F-072): the generic length-prefixed set is the SHARED
                // `IPV6_GENERIC_EXT_HEADERS` const — the same source the
                // forwarding walker's `ipv6_ext_header_is_traversable` verdict
                // delegates to — not a second hand-mirrored arm list. ROUTING
                // (43) is a member of that set but keeps its own arm above
                // (it additionally checks the routing type for the
                // `source-route` screen); arm order keeps it there. AH (51)
                // and Fragment (44) keep their literal arms (distinct advance
                // math, single values, covered by the debug_assert above).
                n if IPV6_GENERIC_EXT_HEADERS.contains(&n) => {
                    if offset + 2 > frame.len() {
                        return Err(ScreenParseError::TruncatedIpv6ExtChain);
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 1) * 8;
                }
                NEXTHDR_AUTH => {
                    if offset + 2 > frame.len() {
                        return Err(ScreenParseError::TruncatedIpv6ExtChain);
                    }
                    nexthdr = frame[offset];
                    offset += (frame[offset + 1] as usize + 2) * 4;
                }
                NEXTHDR_FRAGMENT => {
                    if offset + 8 > frame.len() {
                        return Err(ScreenParseError::TruncatedIpv6ExtChain);
                    }
                    // IPv6 frag_off layout (big-endian u16 at offset+2):
                    //   offset (13 bits, top) | reserved (2 bits) | M (1 bit, lowest)
                    // Mirrors BPF #866: MF=0x1, offset=0xFFF8.
                    let frag_off = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                    info.ip_frag_off = frag_off;
                    info.is_fragment = (frag_off & 0x1) != 0 || (frag_off & 0xFFF8) != 0;
                    info.is_first_fragment = (frag_off & 0x1) != 0 && (frag_off & 0xFFF8) == 0;
                    // #2293: payload-region bytes that precede THIS
                    // fragment's data — every extension header up to and
                    // including this 8-byte fragment header. `offset + 8`
                    // is the frame position of the fragment payload;
                    // subtract the base-header end (`l3_offset + 40`) to
                    // get the payload-region offset of the fragment data.
                    // `ip_payload_len - frag_data_off` is then the L4/data
                    // bytes this fragment carries. Saturating: a hostile
                    // chain whose declared payload_len is smaller than the
                    // headers we walked yields 0 contribution, never an
                    // underflow.
                    info.frag_data_off =
                        ((offset + 8).saturating_sub(l3_offset + 40)) as u16;
                    // #3120: a NON-FIRST fragment (fragment offset > 0)
                    // genuinely carries no L4 header in THIS packet — the
                    // TCP header lives in the first fragment — so stopping
                    // the walk is correct (the downstream gate
                    // `(!is_fragment || is_first_fragment)` then keeps any
                    // `tcp_offset` unused for it; see #2344/#3064). But for
                    // the FIRST fragment (offset == 0) the real L4 header
                    // DOES follow the extension-header chain, and RFC 8200
                    // permits another extension header (e.g.
                    // destination-options) AFTER the fragment header. The
                    // pre-fix code only checked whether the IMMEDIATELY
                    // following header was TCP and then unconditionally
                    // `break`d, so a `frag → dest-opts → TCP` chain left
                    // `tcp_offset = None` and hid the TCP seq/ack/flags/MSS
                    // from the TCP-flag screens and the SYN-cookie flood
                    // challenge — an extension-chain IDS evasion. CONTINUE
                    // the walk past this fixed 8-byte fragment header (set
                    // `nexthdr` from the fragment header's own NextHdr field
                    // and advance `offset` by 8) so the trailing ext-header
                    // chain is traversed to the real L4 header. The walk
                    // stays bounded by the enclosing `for _ in 0..8` cap and
                    // the top-of-loop `offset > frame.len()` fail-closed
                    // check (#2146/#2189/#2361), so a malicious chain can
                    // neither loop forever nor over-read.
                    if (frag_off & 0xFFF8) != 0 {
                        // Non-first fragment: no L4 header is present here.
                        //
                        // #9114: recover the real upper-layer protocol before
                        // giving up on the walk. The FRAGMENT HEADER's own
                        // NextHdr field (its byte 0, at `offset`) names the
                        // protocol this datagram carries, and it is present on
                        // EVERY fragment including this one — that is the whole
                        // point of the field. Without this the screens see the
                        // shim's `PROTO_FRAGMENT_NO_L4` sentinel and
                        // `check_icmp_fragment` / `icmp-flood` / `udp-flood`,
                        // all keyed on the real protocol, never fire on the
                        // packets they exist to police.
                        //
                        // `offset + 2` and `offset + 3` were just read for
                        // `frag_off`, so `offset` is in bounds. Gated on the
                        // sentinel so a caller that already knew the protocol
                        // keeps it.
                        if info.protocol == SHIM_PROTO_FRAGMENT_NO_L4 {
                            info.protocol = frame[offset];
                        }
                        break;
                    }
                    nexthdr = frame[offset];
                    offset += 8;
                }
                PROTO_TCP => {
                    tcp_offset = Some(offset);
                    break;
                }
                _ => break,
            }
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
