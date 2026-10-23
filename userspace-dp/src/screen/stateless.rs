//! Side-effect-free stateless screen checks. Each helper takes
//! immutable borrows of the per-zone `ScreenProfile` and the parsed
//! `ScreenPacketInfo` and returns `Some(reason)` if the packet
//! should be dropped. The orchestrator in `mod.rs` calls these in
//! the same order the monolithic implementation did so drop
//! precedence is preserved byte-for-byte.
//!
//! Hot-path discipline: every helper is `#[inline]` so LLVM inlines
//! the bodies back into the caller. No allocations.

use super::packet::{
    PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, ScreenPacketInfo, ScreenProfile, TCP_ACK, TCP_FIN,
    TCP_SYN, TCP_URG,
};

/// LAND attack: `src_ip == dst_ip`.
///
/// Mirrors the authoritative BPF screen (#2215, see
/// `git show 13fa1009e^:bpf/xdp/xdp_screen.c` ~lines 715-723), which
/// dropped on `src_ip == dst_ip` ALONE for both IPv4 and IPv6, with NO
/// port comparison. The classic named LAND attack does use equal ports,
/// but the source==destination IP match is the LAND signature and an
/// unconditional anti-spoofing invariant — a spoofed frame whose source
/// equals its destination is illegal regardless of L4 ports (and need
/// not even be TCP/UDP). The pre-#2215 userspace port added a
/// `src_port == dst_port` requirement that silently admitted such frames
/// when the ports differed; that narrowing is removed here for BPF
/// parity.
#[inline]
pub(super) fn check_land(profile: &ScreenProfile, pkt: &ScreenPacketInfo) -> Option<&'static str> {
    if profile.land && pkt.src_ip == pkt.dst_ip {
        return Some("land-attack");
    }
    None
}

/// TCP flag-bit screens (SYN+FIN, no-flag, FIN-no-ACK, WinNuke,
/// syn_frag). Outer guard `!is_fragment || is_first_fragment`
/// mirrors the BPF #853 defense (#1137): subsequent fragments
/// don't carry the L4 header so `tcp_flags` is unreliable for them.
#[inline]
pub(super) fn check_tcp_flag_screens(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if pkt.protocol != PROTO_TCP {
        return None;
    }
    if pkt.is_fragment && !pkt.is_first_fragment {
        return None;
    }
    // #16007 defense in depth: flags UNKNOWN (tiny first fragment) must
    // never be read as a proven flag set — neither to fire `syn-frag`
    // on a SYN nobody saw, nor to false-fire `no-flag` on tf==0. The
    // extractor already fails closed on this shape, so this only binds
    // hand-built packets (and any future extractor caller that forgets).
    if pkt.tcp_flags_unknown && pkt.is_first_fragment {
        return Some("syn-frag");
    }
    let tf = pkt.tcp_flags;

    if profile.syn_fin && (tf & TCP_SYN) != 0 && (tf & TCP_FIN) != 0 {
        return Some("tcp-syn-fin");
    }

    if profile.no_flag && tf == 0 {
        return Some("tcp-no-flag");
    }

    if profile.fin_no_ack && (tf & TCP_FIN) != 0 && (tf & TCP_ACK) == 0 {
        return Some("tcp-fin-no-ack");
    }

    if profile.winnuke && (tf & TCP_URG) != 0 && pkt.dst_port == 139 {
        return Some("winnuke");
    }

    // #1137: SYN-fragment — TCP SYN on a first-fragment is the
    // fragmentation-based attack pattern.
    if profile.syn_frag && (tf & TCP_SYN) != 0 && pkt.is_first_fragment {
        return Some("syn-frag");
    }

    None
}

/// Ping of Death: an IPv4 fragment whose contribution to the
/// reassembled datagram would exceed the 65535-byte IP length limit.
///
/// Ports the authoritative BPF screen `SCREEN_PING_OF_DEATH` formula
/// (#2215, restored from #893 / `git show
/// 13fa1009e^:bpf/xdp/xdp_screen.c`). The dataplane does not reassemble
/// fragments, so the classic ping-of-death (many small fragments that
/// reassemble to >65535 bytes) is detected per-fragment from the
/// fragment offset plus this fragment's total length:
///
/// ```text
///   offset_bytes = (frag_off & 0x1FFF) << 3   // 8-byte fragment units
///   if offset_bytes + ip_total_len > 65535 -> drop
/// ```
///
/// Applies to ANY IPv4 protocol (not just ICMP) and only to fragmented
/// packets, exactly matching the BPF reference. The pre-#2215 userspace
/// port reverted to the original pre-#893 dead-code shape (an
/// ICMP-only `pkt.pkt_len as u32 > 65535` predicate that is structurally
/// unsatisfiable because `pkt_len` is a u16), so fragment-based
/// ping-of-death went entirely undetected.
///
/// Limitation (inherited from #893): a first fragment carrying IP
/// options combined with non-first fragments without them can craft
/// `offset_bytes + ip_total_len <= 65535` while the reassembled total
/// overflows by up to 40 bytes. (Note: the `ip-source-route` screen now
/// only drops actual LSRR/SSRR options after #2973, so it no longer
/// blanket-drops every IHL>5 packet as a side defense here.)
///
/// #2293: the IPv6 path applies the same per-fragment oversize formula.
/// The dataplane does not reassemble, so for an IPv6 fragment we size
/// the reassembled end-byte this fragment implies:
///
/// ```text
///   offset_bytes = (frag_off & 0xFFF8) >> 3 << 3 == frag_off & 0xFFF8
///   frag_data    = ip_payload_len - frag_data_off   // L4/data bytes
///   if offset_bytes + frag_data > 65535 -> drop
/// ```
///
/// `frag_off & 0xFFF8` is already the byte offset (the IPv6 fragment
/// offset field is the upper 13 bits and counts 8-byte units, so masking
/// the low 3 bits yields the offset directly in bytes). `frag_data_off`
/// is the payload-region bytes consumed by extension headers up to and
/// including the fragment header (captured in `extract.rs`), so
/// `ip_payload_len - frag_data_off` is this fragment's data contribution.
/// A maximal-offset last fragment that pushes the reassembled datagram
/// past the 65535 IPv6-payload ceiling is dropped — the IPv6 analogue of
/// the classic ping-of-death. Like the IPv4 path this fires on ANY IPv6
/// protocol, only for fragments, and inherits the same per-fragment
/// (non-reassembling) approximation limit.
#[inline]
pub(super) fn check_ping_of_death(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if !profile.ping_death || !pkt.is_fragment {
        return None;
    }
    if pkt.addr_family == libc::AF_INET as u8 {
        let offset_bytes = ((pkt.ip_frag_off & 0x1FFF) as u32) << 3;
        if offset_bytes + pkt.ip_total_len as u32 > 65535 {
            return Some("ping-of-death");
        }
    } else if pkt.addr_family == libc::AF_INET6 as u8 {
        // IPv6 fragment offset is the upper 13 bits (8-byte units) of the
        // fragment header's frag_off field; `& 0xFFF8` is the byte offset.
        let offset_bytes = (pkt.ip_frag_off & 0xFFF8) as u32;
        // This fragment's data bytes = payload_len minus the ext-header
        // bytes preceding the fragment data. saturating_sub guards a
        // hostile payload_len shorter than the headers actually walked.
        let frag_data = pkt.ip_payload_len.saturating_sub(pkt.frag_data_off) as u32;
        if offset_bytes + frag_data > 65535 {
            return Some("ping-of-death");
        }
    }
    None
}

/// Teardrop: a non-last fragment whose payload is not a multiple of 8
/// bytes (including a payload below 8), at ANY fragment offset — plus a
/// zero/under-length payload on any fragment.
///
/// #9426: the doc used to call `< 8` on any non-first fragment "the classic
/// overlapping-fragment signature". That was factually wrong twice over, and
/// the second error cost legal traffic. A tiny tail is not an overlapping
/// fragment — no overlap is computed anywhere here — and the tiny-fragment
/// heuristic it resembles is RFC 1858's, which applies to the FIRST fragment
/// (to stop an attacker pushing the TCP flags into fragment 2), not to tails.
///
/// Every IP fragment except the LAST must be a multiple of 8 bytes; the last
/// one may be any size. So an IPv4 datagram whose length mod 1480 lands in 1-7
/// produces a perfectly legal 1-7 byte last fragment, which this check dropped
/// — and because the receiver's reassembly then times out, the WHOLE datagram
/// is lost. No attacker is required: any UDP application that fragments (DNS
/// with large responses, IKE, RADIUS, NFS, VXLAN, GTP) emits one for about
/// 0.5% of datagram sizes, deterministically per size, so an application with a
/// fixed message size is either always broken or never affected. Juniper
/// specifies `tear-drop` as OVERLAP detection ("when the sum of the offset and
/// size of one fragmented packet differs from that of the next") and says
/// nothing about tiny tails, so xpf was dropping traffic SRX does not.
///
/// The discriminator was already in the struct and unused: `ip_frag_off` is the
/// raw field, so the More-Fragments bit is in hand at this check (IPv4 0x2000;
/// IPv6 the Fragment header's low bit). MF = 0 IS the last fragment and is the
/// one that may legally carry 1-7 bytes; MF = 1 with a sub-8-byte payload
/// really is malformed. The check now tests it.
///
/// What did NOT change: a fragment with ZERO or under-length payload is
/// malformed whatever MF says — a last fragment that contributes no data is
/// not a legal tail, it is a fragment with nothing in it — so the #3027 arm and
/// its IPv6 analogue stay ungated.
///
/// This does NOT make the check an overlap detector. Detecting a real teardrop
/// needs offset/length state across fragments, and the only fragment-state
/// module in the tree (`fragment_assoc`) states in its own doc that it
/// ASSOCIATES rather than RFC-reassembles. That gap is a design limitation of a
/// stateless screen and is deliberately out of scope here; what is fixed is the
/// FALSE POSITIVE, which costs legal traffic on its own.
///
/// #3027: a fragment whose `ip_total_len <= hdr_len` carries
/// zero (or, by the field's claimed length, "negative") payload. That is
/// even more clearly malformed than the classic tiny-but-positive
/// teardrop signature — exactly the kind of crafted fragment that
/// confuses downstream reassembly — yet the pre-#3027 code only entered
/// the payload-size branch when `ip_total_len > hdr_len`, so the
/// zero/under-length case slipped through as a PASS. Treat it as a
/// teardrop drop.
///
/// #3119: this check was IPv4-only while the sibling `check_ping_of_death`
/// already screened both families. An IPv6 teardrop (a Fragment
/// extension-header fragment with a tiny data contribution) therefore
/// bypassed the screen entirely. The IPv6 arm mirrors the
/// `check_ping_of_death` IPv6 sizing: the Fragment header's offset field
/// is the upper 13 bits (8-byte units), so `ip_frag_off & 0xFFF8` is the
/// byte offset, and this fragment's data bytes are
/// `ip_payload_len - frag_data_off` (the L4/data region after the
/// extension headers up to and including the 8-byte fragment header).
/// `saturating_sub` collapses a hostile under-length (`frag_data_off`
/// larger than the declared `ip_payload_len`) to 0, which is treated as the
/// malformed zero/under-length teardrop case — the IPv6
/// analogue of the #3027 IPv4 fix. Junos vSRX applies teardrop screening
/// to both families.
///
/// #16030: the pre-fix check gated BOTH arms on `frag_offset > 0`, so a
/// non-last FIRST fragment (offset 0, MF/M=1) with a payload that is not a
/// multiple of 8 — e.g. 4 bytes, or 12 bytes — was never dropped, even
/// though RFC 791 / RFC 8200 require every non-last fragment's payload to
/// be a multiple of 8. Only the offset gate is removed: the MF-gated
/// `payload % 8 != 0` test now runs at offset 0 too, which subsumes the old
/// `payload < 8` case (any positive payload < 8 is a non-multiple of 8).
/// The zero/under-length arm likewise no longer needs the offset gate:
/// a non-last fragment with no data is malformed at offset 0 as well.
/// Legal short LAST fragments (MF/M=0, 1-7 bytes, #9426) stay admitted
/// because the `% 8` test remains MF-gated; a legal 8-byte (or any
/// multiple-of-8) first fragment also passes.
#[inline]
pub(super) fn check_teardrop(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if !profile.teardrop || !pkt.is_fragment {
        return None;
    }
    if pkt.addr_family == libc::AF_INET as u8 {
        let hdr_len = (pkt.ip_ihl as u16) * 4;
        if pkt.ip_total_len <= hdr_len {
            // No / negative payload — malformed whatever MF says (#3027,
            // #16030: also at offset 0). A last fragment contributing zero
            // data is not a legal tail.
            return Some("teardrop");
        }
        let payload = pkt.ip_total_len - hdr_len;
        // #9426 + #16030: only a NON-LAST fragment must carry a multiple
        // of 8 bytes, at ANY offset including the first fragment. MF=0
        // is the last fragment and may legally carry 1-7 bytes.
        let more_fragments = (pkt.ip_frag_off & 0x2000) != 0;
        if more_fragments && payload % 8 != 0 {
            return Some("teardrop");
        }
    } else if pkt.addr_family == libc::AF_INET6 as u8 {
        // This fragment's data bytes = payload_len minus the ext-header
        // bytes preceding the fragment data. saturating_sub collapses a
        // hostile under-length to 0, the IPv6 analogue of the #3027
        // zero/negative-payload case.
        let frag_data = pkt.ip_payload_len.saturating_sub(pkt.frag_data_off);
        if frag_data == 0 {
            // Zero / under-length contribution — malformed whatever M says
            // (#3119's IPv6 analogue of the #3027 case, #16030: also at
            // offset 0). The v4 arm above reaches the same state through
            // `ip_total_len <= hdr_len`.
            return Some("teardrop");
        }
        // #9426 + #16030: as in the v4 arm, only a NON-LAST fragment must
        // carry a multiple of 8 bytes, at ANY offset including the first
        // fragment. The Fragment header's M bit is the low bit.
        let more_fragments = (pkt.ip_frag_off & 0x1) != 0;
        if more_fragments && frag_data % 8 != 0 {
            return Some("teardrop");
        }
    }
    None
}

/// ICMP fragment: any fragmented ICMP/ICMPv6 packet.
#[inline]
pub(super) fn check_icmp_fragment(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if profile.icmp_fragment
        && pkt.is_fragment
        && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
    {
        return Some("icmp-fragment");
    }
    None
}

/// IP source-route screen.
///
/// #2973: drop ONLY when an actual source-route option/header is present
/// — IPv4 LSRR (option 131) / SSRR (option 137), or an IPv6 Routing
/// Header (next-header 43) carrying a source-route routing type (RH0 /
/// type 1). The extractor (`extract.rs`) decodes the IPv4 options TLVs
/// and the IPv6 extension-header chain to set `saw_ipv4_source_route` /
/// `saw_ipv6_routing_header`.
///
/// The pre-#2973 implementation dropped on ANY IPv4 IHL>5 (any options
/// present), which false-dropped benign router-alert / record-route /
/// timestamp / security packets, and it ignored IPv6 Routing Headers
/// entirely — a vSRX/SRX feature-parity gap (the screen is expected to
/// catch the source-route security intent on both families).
#[inline]
pub(super) fn check_source_route(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if profile.source_route && (pkt.saw_ipv4_source_route || pkt.saw_ipv6_routing_header) {
        return Some("ip-source-route");
    }
    None
}

/// #6238: the ALREADY-CONTIGUOUS common stateless tail shared by the
/// flow-present (`check_packet_with_zone_id_opts`) and flowless
/// (`check_flowless_screens_opts`) paths: ping-of-death → teardrop →
/// icmp-fragment → source-route, in the exact order and with the exact
/// reason strings both paths already run them.
///
/// Extracting this run single-sources the fragment/source-route family so a
/// future addition covers BOTH entry points by construction — the fail-open
/// class that bit #3902 (the flowless path once ran only the three fragment
/// screens and BYPASSED source-route + LAND + the flood counters). Because
/// the four checks were already adjacent, identically ordered, and identically
/// guarded on both paths, this extraction is behavior-preserving by
/// construction: it reorders nothing.
///
/// Deliberately does NOT include:
///   - **LAND** — it is `addrs_known`-gated on the flowless path and
///     UNCONDITIONAL on the full path, and on the full path it runs BEFORE the
///     TCP-flag screens. Folding it in would either drop the flowless guard or
///     reorder it across the TCP-flag screens (an observable drop-reason /
///     per-reason-counter flip). LAND stays a per-call at each site.
///   - **TCP-flag screens** (`check_tcp_flag_screens`) — full-path only, and
///     INTERPOSED between LAND and this tail. They stay in place immediately
///     before this helper on the full path.
///
/// Side-effect-free: reads only `&profile` / `&pkt`, mutates nothing,
/// allocates nothing. `#[inline]` so LLVM folds the bodies back into each
/// caller exactly as the pre-#6238 open-coded run did.
#[inline]
pub(super) fn check_fragment_and_route(
    profile: &ScreenProfile,
    pkt: &ScreenPacketInfo,
) -> Option<&'static str> {
    if let Some(reason) = check_ping_of_death(profile, pkt) {
        return Some(reason);
    }
    if let Some(reason) = check_teardrop(profile, pkt) {
        return Some(reason);
    }
    if let Some(reason) = check_icmp_fragment(profile, pkt) {
        return Some(reason);
    }
    if let Some(reason) = check_source_route(profile, pkt) {
        return Some(reason);
    }
    None
}
