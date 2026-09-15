//! #947: pure parsers for ARP and IPv6 NDP packets, extracted from
//! `poll_binding_process_descriptor` to make them testable in
//! isolation and to declutter the main poll loop.
//!
//! These functions intentionally do NOT use trait objects (`dyn
//! ProtocolParser`) — they are `#[inline]`-able free functions so the
//! compiler can fold them into the caller. The original issue
//! proposed a Strategy trait pattern, but trait-object dispatch on a
//! per-packet path would regress IPC; generics with monomorphization
//! (or, as here, simple `#[inline]` functions) are the correct shape.
//!
//! IPv4/IPv6/TCP/GRE parsing already lives in `frame.rs` and
//! `gre.rs`; this module covers the two control-plane shapes (ARP
//! reply and IPv6 neighbor advertisement) that were still inline in
//! `afxdp.rs`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use super::ethernet::{
    ETH_HDR_LEN, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN, ETHERTYPE_VLAN_8021AD, VLAN_TAG_LEN,
};

const ARP_BODY_LEN: usize = 28;
const IPV6_HDR_LEN: usize = 40;
const ICMPV6_NA_HDR_LEN: usize = 24;
const NEXT_HEADER_ICMPV6: u8 = 58;
const ICMPV6_TYPE_NA: u8 = 136;
const ARP_OP_REPLY: u16 = 2;
/// ARP hardware type for Ethernet (RFC 826 / IANA). The fixed-offset
/// read of the sender hardware address is only meaningful when the
/// hardware type is Ethernet.
const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP protocol type for IPv4 (EtherType 0x0800). The fixed-offset read
/// of the sender protocol address is only meaningful for IPv4.
const ARP_PTYPE_IPV4: u16 = 0x0800;
/// ARP hardware address length for Ethernet (6-byte MAC).
const ARP_HLEN_ETHERNET: u8 = 6;
/// ARP protocol address length for IPv4 (4-byte address).
const ARP_PLEN_IPV4: u8 = 4;
const NDP_OPT_TARGET_LL: u8 = 2;
/// RFC 4861 §7.1.2: every NDP message MUST be sent with an IPv6 Hop
/// Limit of 255 so a receiver can reject any NDP packet whose hop
/// limit is lower — such a packet was necessarily forwarded by a
/// router and therefore did not originate on-link. An off-link or
/// spoofed-but-routed NA cannot satisfy this without a router
/// decrementing the field.
const NDP_REQUIRED_HOP_LIMIT: u8 = 255;
/// #9893: NA learns refused because the IPv6 chain carried a Fragment header
/// (RFC 6980 §5 MUST-discards). Bumped only for NA-shaped frames (proto 58 +
/// type 136 confirmed) so ordinary fragmented transit does not pollute the
/// series — this probe runs per-packet. Test-visible; Prometheus export is
/// #10097 (deferred to keep #9893 SMALL per the
/// `SHARED_SESSION_POISON_RECOVERIES` precedent).
pub(crate) static NDP_NA_FRAG_REFUSED: AtomicU64 = AtomicU64::new(0);
/// #9893: NA learns refused because the IPv6 source was not a valid on-link
/// unicast (unspecified/loopback/multicast). Same NA-shape gating and
/// test-visible status as `NDP_NA_FRAG_REFUSED`; Prometheus export likewise
/// #10097.
pub(crate) static NDP_NA_BAD_SOURCE_REFUSED: AtomicU64 = AtomicU64::new(0);
/// #9893: serializes tests sampling the two refusal counters above.
/// The counters are process-wide statics and every `#9893` sampling test
/// holds this across its before/after window so a parallel sibling cannot
/// move the count inside it (mirrors
/// `gre::gre_checksum_counter_test_lock`).
#[cfg(test)]
pub(super) fn ndp_na_refusal_counter_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Resolve the L3-header offset and the EtherType. Handles untagged
/// and single-tagged frames carrying either an 802.1Q (0x8100) or an
/// 802.1ad (0x88a8) VLAN tag.
///
/// Returns `(l3_start, ethertype)` if the frame is large enough to
/// contain the L2 header, otherwise `None`.
///
/// #2150: 0x88a8 was previously treated as the inner ethertype (l3=14),
/// which made a single-0x88a8-tagged ARP/NDP frame parse as a non-IP /
/// non-ARP frame and silently skip neighbor learning. Both forwarding
/// L2 parsers (`frame/inspect.rs::frame_l3_offset`,
/// `cos/ecn.rs::ethernet_l3`) already treat 0x88a8 as a single tag with
/// l3 at 18; this learning parser must agree. A QinQ DOUBLE tag (a tag
/// whose inner ethertype is itself a VLAN TPID) is NOT unwound here —
/// for frames with a complete L2 header, the upstream XDP shim drops
/// double-tagged frames (and legacy-0x9100 outers) before they reach
/// userspace: after its single unwrap, a still-VLAN ethertype takes an
/// explicit XDP_DROP with the `qinq_drop` degraded-path counter
/// (`userspace-xdp/src/lib.rs::is_vlan_tpid`, #9888) on both the armed
/// and the degraded non-IP arms, never the XDP_PASS handoff. (A runt
/// truncating inside the tag takes `parse_l2`'s `None` path instead —
/// `cpumap_or_pass` on the armed path — and carries no L3 payload, so
/// no transit rides that shape.) The DISPOSITION is enforced by the Go
/// BPF cells (`pkg/dataplane/userspace/qinq_disposition_9888_test.go`),
/// which run the real program; what the QinQ section of the L2 canary
/// in parser_tests.rs pins is only this parser's contract — "single
/// tag → l3=18; the inner (possibly still-VLAN) ethertype is returned
/// as-is" — so a future edit to the parser reds there rather than
/// silently reinterpreting the inner tag.
#[inline(always)]
pub(super) fn parse_eth_offsets(raw_frame: &[u8]) -> Option<(usize, u16)> {
    if raw_frame.len() < ETH_HDR_LEN {
        return None;
    }
    let outer_ethertype = u16::from_be_bytes([raw_frame[12], raw_frame[13]]);
    if matches!(outer_ethertype, ETHERTYPE_VLAN | ETHERTYPE_VLAN_8021AD) {
        if raw_frame.len() < ETH_HDR_LEN + VLAN_TAG_LEN {
            return None;
        }
        let inner = u16::from_be_bytes([raw_frame[16], raw_frame[17]]);
        Some((ETH_HDR_LEN + VLAN_TAG_LEN, inner))
    } else {
        Some((ETH_HDR_LEN, outer_ethertype))
    }
}

/// Parsed ARP reply (sender MAC + sender IP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ArpReply {
    pub sender_mac: [u8; 6],
    pub sender_ip: IpAddr,
}

/// Classification of an Ethernet frame as ARP-or-not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ArpClassification {
    /// Frame is not ARP (or is too short to classify).
    NotArp,
    /// Frame is ARP but not a learnable Ethernet/IPv4 reply (e.g. a
    /// request, RARP, gratuitous announcement, or — per #2369 — an
    /// opcode-2 ARP whose fixed header is not Ethernet/IPv4:
    /// htype!=1, ptype!=0x0800, hlen!=6, or plen!=4). Caller should
    /// recycle the frame — ARP does not transit the firewall — but skip
    /// neighbor learning.
    OtherArp,
    /// Frame is an ARP reply with a parsed `(sender_mac, sender_ip)`.
    Reply(ArpReply),
}

/// Classify an Ethernet frame as ARP / non-ARP / ARP reply. Handles
/// untagged and VLAN-tagged frames.
///
/// Replaces the inline parser at `afxdp.rs:893-947` (pre-#947). The
/// caller's contract was: if it's any kind of ARP, recycle the frame
/// (ARP does not transit); if it's specifically an ARP reply, also
/// learn the neighbor entry. The enum captures both branches without
/// re-parsing.
#[inline(always)]
pub(super) fn classify_arp(raw_frame: &[u8]) -> ArpClassification {
    let Some((l3_start, ethertype)) = parse_eth_offsets(raw_frame) else {
        return ArpClassification::NotArp;
    };
    if ethertype != ETHERTYPE_ARP {
        return ArpClassification::NotArp;
    }
    if raw_frame.len() < l3_start + ARP_BODY_LEN {
        return ArpClassification::NotArp;
    }
    // #2369: validate the ARP fixed header BEFORE reading the sender
    // hardware/protocol addresses. The sender MAC (l3+8..14) and sender IP
    // (l3+14..18) sit at offsets that are only correct for Ethernet/IPv4
    // ARP — i.e. when htype==1, ptype==0x0800, hlen==6, plen==4. A crafted
    // opcode-2 ARP declaring a different hardware/protocol type or length
    // would otherwise be parsed at these fixed offsets and the resulting
    // attacker-chosen bytes learned as a MAC->IP binding into both the
    // userspace `dynamic_neighbors` cache and the kernel neighbor table
    // (RFC 826: an ARP packet MUST be interpreted per its type/length
    // fields). Fail closed: any mismatch is treated as a non-learnable ARP
    // (recycled, never learned), mirroring the #2368 NDP fail-closed style.
    let htype = u16::from_be_bytes([raw_frame[l3_start], raw_frame[l3_start + 1]]);
    let ptype = u16::from_be_bytes([raw_frame[l3_start + 2], raw_frame[l3_start + 3]]);
    let hlen = raw_frame[l3_start + 4];
    let plen = raw_frame[l3_start + 5];
    if htype != ARP_HTYPE_ETHERNET
        || ptype != ARP_PTYPE_IPV4
        || hlen != ARP_HLEN_ETHERNET
        || plen != ARP_PLEN_IPV4
    {
        return ArpClassification::OtherArp;
    }
    let opcode = u16::from_be_bytes([raw_frame[l3_start + 6], raw_frame[l3_start + 7]]);
    if opcode != ARP_OP_REPLY {
        return ArpClassification::OtherArp;
    }
    let sender_mac = [
        raw_frame[l3_start + 8],
        raw_frame[l3_start + 9],
        raw_frame[l3_start + 10],
        raw_frame[l3_start + 11],
        raw_frame[l3_start + 12],
        raw_frame[l3_start + 13],
    ];
    let sender_ip = IpAddr::V4(Ipv4Addr::new(
        raw_frame[l3_start + 14],
        raw_frame[l3_start + 15],
        raw_frame[l3_start + 16],
        raw_frame[l3_start + 17],
    ));
    ArpClassification::Reply(ArpReply {
        sender_mac,
        sender_ip,
    })
}

/// Parsed ICMPv6 Neighbor Advertisement (type 136).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NdpNeighborAdvert {
    pub target_ip: IpAddr,
    /// Some(mac) iff the NA carries a Target Link-Layer Address option
    /// (option type 2). NA without TLLA is valid (e.g. unsolicited NA
    /// from a host whose router knows the LLA already), but we can't
    /// learn a MAC from those.
    pub target_mac: Option<[u8; 6]>,
    /// RFC 4861 §4.4 Override (O) flag from the NA flags byte. When 0, the
    /// advertisement MUST NOT overwrite a cached neighbor entry that maps
    /// to a DIFFERENT link-layer address (§7.2.5) — that is exactly the
    /// unsolicited-NA next-hop hijack primitive. The learn site
    /// (`poll_stages::stage_link_layer_classify`) honors this (#4475): a
    /// legitimate host announcing a link-layer-address change sets
    /// Override=1 (§7.2.6), so an Override=0 NA is only allowed to create a
    /// first-time entry or refresh the same LLA, never to replace a live
    /// differing one.
    pub override_flag: bool,
}

/// Parse an IPv6 Neighbor Advertisement. Returns `None` if the frame
/// is not an NA or is too short. Handles VLAN-tagged frames.
///
/// Replaces the inline parser at `afxdp.rs:948-1014` (pre-#947).
///
/// #2150: previously this assumed ICMPv6 sat at a fixed `l3 + 40` and
/// read the base `next_header` (`raw[l3 + 6]`) directly, so an NA that
/// arrived behind an IPv6 extension header (hop-by-hop, dest-options,
/// routing, fragment) was missed — the exact asymmetry the
/// forwarding/screen walkers (#2148/#2189) were written to avoid. It now
/// reuses the shared #2148 walker over the L3-relative slice to locate the
/// real L4 offset and confirm the terminal protocol is ICMPv6 (58) —
/// `walk_ipv6_ext_chain` directly since #9893 (same one-walk cost as the
/// `packet_rel_l4_offset_and_protocol` wrapper, plus the recorded Fragment
/// sighting the RFC 6980 gate needs). The walker keeps its existing
/// 6-iteration bound, so behavior is byte-identical for the no-ext-header
/// case (offset == l3 + 40, protocol == 58). The parser-agreement canary
/// in parser_tests.rs pins this against the forwarding walker.
#[inline(always)]
pub(super) fn parse_ndp_neighbor_advert(raw_frame: &[u8]) -> Option<NdpNeighborAdvert> {
    let (l3_start, ethertype) = parse_eth_offsets(raw_frame)?;
    if ethertype != ETHERTYPE_IPV6 {
        return None;
    }
    if raw_frame.len() < l3_start + IPV6_HDR_LEN {
        return None;
    }
    // Walk the IPv6 extension-header chain (shared #2148 engine) to find
    // the real L4 offset + terminal protocol. The walker operates on the
    // L3-relative slice; translate its relative offset back to a
    // frame-absolute offset.
    //
    // #9893: walk `walk_ipv6_ext_chain` directly (same one-walk cost as the
    // `packet_rel_l4_offset_and_protocol` wrapper) so the recorded Fragment
    // sighting survives for the RFC 6980 gate below. The `L4`-only match
    // preserves the wrapper's #2292 fail-closed verdict folding.
    let l3_slice = raw_frame.get(l3_start..)?;
    let walk = super::frame::walk_ipv6_ext_chain(l3_slice, 0);
    let (rel_l4, protocol) = match walk.outcome {
        super::frame::ExtChainOutcome::L4(offset, proto) => (offset, proto),
        // Truncated/OverLimit/NoNextHeader: fail closed WITHOUT counting —
        // the shape is unconfirmable as NA (accepted residual: uncounted
        // but refused, never learned).
        _ => return None,
    };
    let l4_start = l3_start.checked_add(rel_l4)?;
    if protocol != NEXT_HEADER_ICMPV6
        || raw_frame.len() < l4_start + ICMPV6_NA_HDR_LEN
        || raw_frame[l4_start] != ICMPV6_TYPE_NA
    {
        return None;
    }
    // #9893 (RFC 6980 §5): Neighbor Discovery messages MUST NOT be
    // fragmented — discard any NA whose chain sighted a Fragment header.
    // Gated on the NA-shape confirmation above so this per-packet probe
    // counts only genuine NA learn attempts, never ordinary fragmented
    // transit. Counted (`NDP_NA_FRAG_REFUSED`) for the fail-closed audit.
    // First-defect attribution: this gate precedes the source gate, so a
    // doubly-defective NA (fragmented AND bad source) counts once, here.
    if walk.fragment.is_some() {
        NDP_NA_FRAG_REFUSED.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    // #2368 (B): bound the whole NDP parse — header AND option walk — by
    // the IPv6-declared packet end, not the raw frame length. A
    // minimum-size Ethernet frame can declare a payload covering only
    // the fixed NA header and then place a forged TLLA option in the
    // L2 padding/trailer beyond `40 + payload_len`. Reading that trailer
    // as an option would learn an attacker-chosen MAC from bytes the
    // sender never accounted for in the IP length. Compute the declared
    // end (mirrors the #2361 declared-end discipline) and reject if it
    // overruns the frame or is too short to even hold the NA header.
    let payload_len = u16::from_be_bytes([raw_frame[l3_start + 4], raw_frame[l3_start + 5]]) as usize;
    let packet_end = l3_start.checked_add(IPV6_HDR_LEN)?.checked_add(payload_len)?;
    if packet_end > raw_frame.len() || packet_end < l4_start + ICMPV6_NA_HDR_LEN {
        return None;
    }

    // #2368 (A): RFC 4861 §7.1.2 NA validity MUSTs. Without these an
    // off-link/spoofed NA poisons the dynamic-neighbor cache and the
    // kernel neighbor table (this is a control-plane MAC->IP learning
    // path). Fail-closed: any failed check learns nothing.
    //
    //  - Hop Limit MUST be 255 (the off-link-impersonation gate).
    //  - ICMPv6 Code MUST be 0.
    //  - ICMP length (here `packet_end - l4_start`) MUST be >= 24, which
    //    `packet_end` already guarantees above.
    //  - Target Address MUST NOT be multicast (a multicast target is
    //    never a unicast neighbor to learn).
    //  - The ICMPv6 checksum (RFC 4443, computed over the IPv6
    //    pseudo-header + the ICMPv6 message) MUST be valid.
    if raw_frame[l3_start + 7] != NDP_REQUIRED_HOP_LIMIT {
        return None;
    }
    if raw_frame[l4_start + 1] != 0 {
        return None;
    }
    let target_bytes: [u8; 16] =
        <[u8; 16]>::try_from(&raw_frame[l4_start + 8..l4_start + 24]).ok()?;
    if target_bytes[0] == 0xff {
        // ff00::/8 is the IPv6 multicast range.
        return None;
    }
    let target_ip = IpAddr::V6(Ipv6Addr::from(target_bytes));
    // #9893: the IPv6 SOURCE must be a valid on-link unicast. An NA from
    // unspecified/loopback/multicast source is never a legitimate neighbor
    // advertisement — without this an L2-adjacent sender teaches us a TLLA
    // under a spoofed source identity the checksum alone cannot bind (the
    // pseudo-header only proves the sender knew the bytes, not that they
    // name a real on-link peer). Reuses the exact `neighbor_ip_is_learnable`
    // predicate the learn site applies to targets so the two cannot drift.
    // `l3_start + 8..24` is in bounds — the `l3_start + 40` length gate at
    // function top already guaranteed the full base header. Counted.
    // Accepted residual: on-link here means hop-limit 255 (checked above)
    // plus this unicast predicate — no FIB connected-prefix check.
    let src_bytes: [u8; 16] = <[u8; 16]>::try_from(&raw_frame[l3_start + 8..l3_start + 24]).ok()?;
    if !super::frame::neighbor_ip_is_learnable(IpAddr::V6(Ipv6Addr::from(src_bytes))) {
        NDP_NA_BAD_SOURCE_REFUSED.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    // RFC 4861 §4.4: the NA flags byte sits immediately after the 4-byte
    // ICMPv6 header (type/code/checksum), i.e. at `l4_start + 4`. Bit 0x20
    // is the Override (O) flag. `l4_start + 4` is in bounds — the header
    // length check above already required `raw_frame.len() >= l4_start +
    // ICMPV6_NA_HDR_LEN` (24). Read it so the learn site can honor §7.2.5
    // (#4475: do not let an Override=0 NA overwrite a live differing LLA).
    let override_flag = raw_frame[l4_start + 4] & 0x20 != 0;

    // ICMPv6 checksum over the IPv6 pseudo-header + the ICMPv6 message
    // (`l4_start..packet_end`). A valid packet sums (including its own
    // checksum field) to zero in 16-bit one's complement, i.e. the
    // recomputed value is 0x0000. Reuse the shared one's-complement
    // accumulator (#2211) so this matches every other checksum site.
    if !icmpv6_checksum_valid(raw_frame, l3_start, l4_start, packet_end) {
        return None;
    }

    // Walk the NDP options for a Target Link-Layer Address (type 2),
    // strictly within the IPv6-declared packet end (#2368 B). An option
    // whose declared length overruns `packet_end` is rejected (stop the
    // walk) rather than read out of the declared packet.
    let mut target_mac: Option<[u8; 6]> = None;
    let mut opt_off = l4_start + ICMPV6_NA_HDR_LEN;
    while opt_off + 2 <= packet_end {
        let opt_type = raw_frame[opt_off];
        let opt_len = raw_frame[opt_off + 1] as usize * 8;
        if opt_len == 0 || opt_off + opt_len > packet_end {
            break;
        }
        if opt_type == NDP_OPT_TARGET_LL && opt_len >= 8 {
            target_mac = Some([
                raw_frame[opt_off + 2],
                raw_frame[opt_off + 3],
                raw_frame[opt_off + 4],
                raw_frame[opt_off + 5],
                raw_frame[opt_off + 6],
                raw_frame[opt_off + 7],
            ]);
            break;
        }
        opt_off += opt_len;
    }
    Some(NdpNeighborAdvert {
        target_ip,
        target_mac,
        override_flag,
    })
}

/// Validate the ICMPv6 checksum (RFC 4443 §2.3) of a Neighbor
/// Advertisement. The checksum is computed over the IPv6 pseudo-header
/// (source + destination address from the IPv6 header, the upper-layer
/// packet length, and the next-header value 58) followed by the entire
/// ICMPv6 message (`l4_start..packet_end`, which includes the checksum
/// field itself). For a valid packet the one's-complement sum folds to
/// zero, so the recomputed checksum is 0x0000.
///
/// Reuses the shared `frame` one's-complement accumulator (#2211) so the
/// arithmetic is bit-identical to the NAT64 / forwarding checksum paths
/// and benefits from the same AVX2 fast path.
#[inline(always)]
fn icmpv6_checksum_valid(
    raw_frame: &[u8],
    l3_start: usize,
    l4_start: usize,
    packet_end: usize,
) -> bool {
    let icmp = &raw_frame[l4_start..packet_end];
    let mut sum: u32 = 0;
    // IPv6 pseudo-header: src (16) + dst (16).
    sum = super::frame::checksum16_add_bytes(sum, &raw_frame[l3_start + 8..l3_start + 24]);
    sum = super::frame::checksum16_add_bytes(sum, &raw_frame[l3_start + 24..l3_start + 40]);
    // Upper-layer packet length (32-bit) — the ICMPv6 message length.
    sum = super::frame::checksum16_add_bytes(sum, &(icmp.len() as u32).to_be_bytes());
    // Three zero bytes + next-header (58).
    sum = super::frame::checksum16_add_bytes(sum, &[0, 0, 0, NEXT_HEADER_ICMPV6]);
    // The ICMPv6 message itself (the on-wire checksum field included).
    sum = super::frame::checksum16_add_bytes(sum, icmp);
    super::frame::checksum16_finish(sum) == 0
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;

