//! TCP-specific inspection + mutation kernels (#989).
//!
//! Per the design doc (docs/pr/989-l4-specializations/design.md
//! rev-3), this module owns:
//!
//!  - TCP-flag/window/RST inspection helpers (read-only, no side
//!    effects), previously scattered in `frame/inspect.rs`.
//!  - TCP MSS-clamping byte-mutation kernels, previously in
//!    `forwarding/mod.rs`. These walk TCP options, rewrite the MSS
//!    field for SYN/SYN+ACK only, and incrementally update the TCP
//!    checksum.
//!
//! Pure relocation: bodies are byte-for-byte identical to the
//! pre-move sources. Visibility is preserved
//! (`pub(in crate::afxdp)` for the inspection helpers that were
//! previously crate-internal; `pub(super)` for the clamp helpers
//! that were previously `forwarding/mod.rs`-internal).
//!
//! `#[inline]` is applied to every fn so the move does not regress
//! cross-codegen-unit inlining at the hot call sites in
//! `frame/mod.rs`. With the default `codegen-units > 1`, an
//! un-annotated cross-module call cannot be guaranteed to inline
//! without LTO; `#[inline]` emits the body into every CGU that
//! references it.

use super::*;

#[cfg_attr(not(test), allow(dead_code))]
const SYN_COOKIE_REPLY_TTL: u8 = 64;
#[cfg_attr(not(test), allow(dead_code))]
const SYN_COOKIE_REPLY_HOP_LIMIT: u8 = 64;
#[cfg_attr(not(test), allow(dead_code))]
const SYN_COOKIE_TCP_WINDOW: u16 = 64240;
#[cfg_attr(not(test), allow(dead_code))]
const ETHERNET_MIN_FRAME_LEN: usize = 60;
// #2151: TCP flag bits come from the shared crate::tcp_flags SSOT.
// Re-aliased to the historical TCP_FLAG_* spellings used in this module's
// reply builders; values are bit-identical.
use crate::tcp_flags::{TCP_ACK as TCP_FLAG_ACK, TCP_RST as TCP_FLAG_RST, TCP_SYN as TCP_FLAG_SYN};
#[cfg_attr(not(test), allow(dead_code))]
const TCP_MIN_HEADER_LEN: usize = 20;
#[cfg_attr(not(test), allow(dead_code))]
const TCP_MSS_OPTION_LEN: usize = 4;

/// Check if a frame contains a TCP RST flag.
///
/// #2148: the L4 offset is derived via the shared ext-aware
/// `packet_rel_l4_offset_and_protocol` walker, NOT a fixed L3+40 for
/// IPv6. The previous fixed offset read inside an IPv6 extension header
/// (hop-by-hop / routing / fragment / dest-opts) on flows that carry
/// one, reporting a false RST verdict to the diagnostics path. The
/// walker is bounded (≤6 iterations), allocation-free, and fails safe
/// (returns `false`) on a truncated/malformed chain.
#[inline(always)]
pub(in crate::afxdp) fn frame_has_tcp_rst(frame: &[u8]) -> bool {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return false,
    };
    let ip = match frame.get(l3..) {
        Some(ip) if ip.len() >= 20 => ip,
        _ => return false,
    };
    let addr_family = match ip[0] >> 4 {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return false,
    };
    let (l4_offset, protocol) = match packet_rel_l4_offset_and_protocol(ip, addr_family) {
        Some(t) => t,
        None => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match ip.get(l4_offset..) {
        Some(t) if t.len() >= 14 => t,
        _ => return false,
    };
    // TCP flags at offset 13 (#2151: shared RST predicate).
    crate::tcp_flags::has_rst(tcp[13])
}

/// Extract TCP flags and window from raw frame, auto-detecting L3 from Ethernet header.
/// Returns (tcp_flags, tcp_window) or None.
///
/// #2148: routes the L4 offset through the ext-aware
/// `packet_rel_l4_offset_and_protocol` walker rather than a fixed L3+40
/// for IPv6, so flags/window are read from the real TCP header on flows
/// that carry IPv6 extension headers. Fails safe (returns `None`) on a
/// truncated/malformed chain.
#[inline]
pub(in crate::afxdp) fn extract_tcp_flags_and_window(frame: &[u8]) -> Option<(u8, u16)> {
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get(l3..)?;
    let addr_family = match ip.first()? >> 4 {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return None,
    };
    let (l4_offset, protocol) = packet_rel_l4_offset_and_protocol(ip, addr_family)?;
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    let flags = tcp[13];
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    Some((flags, window))
}

/// Offset into `frame` of the first TCP PAYLOAD byte (#7699).
///
/// `None` unless the frame really is TCP and its declared data offset fits
/// inside the bytes present — the length is attacker-controlled, so it is
/// checked against the slice rather than trusted.
///
/// This exists because the payload start is NOT free: recognising a control
/// channel is two port comparisons on a tuple already parsed, but COPYING the
/// segment additionally requires locating the payload, which means reading the
/// TCP data-offset nibble. Stating it accurately matters — "off the hot path"
/// buys the parse, not the test for whether to parse, and not this read.
///
/// The address family is derived from the IP version in the frame rather than
/// taken as a parameter, matching [`extract_tcp_flags_and_window`] above, so a
/// caller cannot pass one that disagrees with the packet.
#[inline]
pub(in crate::afxdp) fn tcp_payload_offset(frame: &[u8]) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get(l3..)?;
    let addr_family = match ip.first()? >> 4 {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return None,
    };
    let (l4_offset, protocol) = packet_rel_l4_offset_and_protocol(ip, addr_family)?;
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < TCP_MIN_HEADER_LEN {
        return None;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    // A data offset below the minimum header is malformed; one past the bytes
    // present is a truncated or lying packet. Both mean "no payload here".
    if data_offset < TCP_MIN_HEADER_LEN || tcp.len() < data_offset {
        return None;
    }
    Some(l3 + l4_offset + data_offset)
}

/// Extract TCP window size from raw frame data.
/// Returns None if not a TCP frame or if frame is too short.
///
/// #2148: derives the L4 offset via the shared ext-aware
/// `packet_rel_l4_offset_and_protocol` walker instead of a fixed L3+40
/// for IPv6, so the window is read from the real TCP header even when
/// the IPv6 packet carries extension headers. Fails safe (returns
/// `None`) on a truncated/malformed chain.
#[inline]
#[allow(dead_code)]
pub(in crate::afxdp) fn extract_tcp_window(frame: &[u8], addr_family: u8) -> Option<u16> {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return None,
    };
    let ip = frame.get(l3..)?;
    let (l4_offset, protocol) = packet_rel_l4_offset_and_protocol(ip, addr_family)?;
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    // TCP window is at offset 14-15 (big-endian)
    Some(u16::from_be_bytes([tcp[14], tcp[15]]))
}

#[inline]
pub(in crate::afxdp) fn tcp_flags_str(flags: u8) -> String {
    use crate::tcp_flags::{has_ack, has_fin, has_psh, has_rst, has_syn, has_urg};
    let mut s = String::with_capacity(12);
    if has_syn(flags) {
        s.push_str("SYN ");
    }
    if has_ack(flags) {
        s.push_str("ACK ");
    }
    if has_fin(flags) {
        s.push_str("FIN ");
    }
    if has_rst(flags) {
        s.push_str("RST ");
    }
    if has_psh(flags) {
        s.push_str("PSH ");
    }
    if has_urg(flags) {
        s.push_str("URG ");
    }
    if s.ends_with(' ') {
        s.truncate(s.len() - 1);
    }
    if s.is_empty() {
        s.push_str("none");
    }
    s
}

/// Clamp the TCP MSS option of a SYN / SYN+ACK packet to `max_mss`.
/// `packet` is the L3+L4 view (no Ethernet header); `max_mss` is
/// the maximum allowed MSS value. Returns `true` iff the MSS was
/// rewritten (and the TCP checksum incrementally updated).
///
/// No-ops on:
///   - non-TCP packets
///   - packets shorter than the IPv4/IPv6 header
///   - non-SYN packets (ACK-only, FIN-only, etc.)
///   - frames where the MSS option is absent or already <= max_mss
///   - malformed TCP options (length=0, length=1, or option past
///     data_offset boundary)
#[inline]
#[allow(dead_code)]
pub(super) fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    if max_mss == 0 {
        return false;
    }
    // Determine L3 header length and protocol.
    if packet.is_empty() {
        return false;
    }
    let version = packet[0] >> 4;
    // #1852: a non-first fragment has no TCP header at the post-IP
    // offset — never clamp it (the "TCP" bytes are payload). Gate the
    // clamp itself here rather than making the shared offset helper
    // fragment-aware: that helper is read by GRE decap / tunnel
    // local-origin to FORWARD legitimately-fragmented inner packets, so
    // it must keep returning the offset.
    match version {
        4 => {
            if ipv4_is_non_first_fragment(packet) {
                return false;
            }
        }
        6 => {
            if ipv6_is_non_first_fragment(packet) {
                return false;
            }
        }
        _ => return false,
    }
    let (l4_offset, protocol) = match version {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let ihl = (packet[0] & 0x0F) as usize * 4;
            (ihl, packet[9])
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            // #1852: ext-aware L4 offset. The previous fixed
            // `(40, packet[6])` silently no-opped on ext-headered v6
            // SYNs (packet[6] was an ext-header type, so the
            // `protocol != TCP` check below bailed). Walk the chain so
            // the MSS clamp reaches the real TCP header.
            match packet_rel_l4_offset_and_protocol(packet, libc::AF_INET6 as u8) {
                Some((off, proto)) => (off, proto),
                None => return false,
            }
        }
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match packet.get_mut(l4_offset..) {
        Some(s) if s.len() >= 20 => s,
        _ => return false,
    };
    let flags = tcp[13];
    // Only clamp on SYN or SYN+ACK (#2151: shared SYN predicate).
    if !crate::tcp_flags::has_syn(flags) {
        return false;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return false;
    }
    // Walk TCP options looking for MSS (kind=2, len=4)
    let mut pos = 20;
    while pos + 4 <= data_offset {
        let kind = tcp[pos];
        if kind == 0 {
            break; // end of options
        }
        if kind == 1 {
            pos += 1; // NOP
            continue;
        }
        let opt_len = tcp[pos + 1] as usize;
        if opt_len < 2 || pos + opt_len > data_offset {
            break;
        }
        if kind == 2 && opt_len == 4 {
            let current_mss = u16::from_be_bytes([tcp[pos + 2], tcp[pos + 3]]);
            if current_mss > max_mss {
                // Clamp MSS and adjust TCP checksum
                let old_bytes = [tcp[pos + 2], tcp[pos + 3]];
                tcp[pos + 2..pos + 4].copy_from_slice(&max_mss.to_be_bytes());
                // Incremental TCP checksum update per RFC 1624:
                //   HC' = HC + m + ~m'  (ones-complement, end-around carry)
                // The result is stored directly; no further negation.
                let old_val = if pos & 1 == 0 {
                    u16::from_be_bytes(old_bytes)
                } else {
                    u16::from_be_bytes(old_bytes).swap_bytes()
                } as u32;
                let new_val = if pos & 1 == 0 {
                    max_mss
                } else {
                    max_mss.swap_bytes()
                } as u32;
                let old_csum = u16::from_be_bytes([tcp[16], tcp[17]]) as u32;
                let mut sum = old_csum + old_val + (!new_val & 0xFFFF);
                sum = (sum & 0xFFFF) + (sum >> 16);
                sum = (sum & 0xFFFF) + (sum >> 16);
                tcp[16..18].copy_from_slice(&(sum as u16).to_be_bytes());
                return true;
            }
            return false;
        }
        pos += opt_len;
    }
    false
}

/// Build the SYN-cookie challenge reply for a threshold-exceeded SYN.
///
/// The caller still owns admission and TX-frame budgeting. This builder is a
/// pure byte-construction primitive: it swaps L2/L3/L4 identity, emits a
/// minimal SYN+ACK with the encoded cookie as the sequence number, advertises
/// the selected MSS when present, and recomputes checksums from scratch.
#[inline]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn build_syn_cookie_syn_ack_frame(
    frame: &[u8],
    cookie_isn: u32,
    advertised_mss: u16,
) -> Option<Vec<u8>> {
    let parsed = parse_tcp_reply_source(frame)?;
    if (parsed.flags & TCP_FLAG_SYN) == 0 || (parsed.flags & TCP_FLAG_ACK) != 0 {
        return None;
    }
    let tcp_len = if advertised_mss > 0 {
        TCP_MIN_HEADER_LEN + TCP_MSS_OPTION_LEN
    } else {
        TCP_MIN_HEADER_LEN
    };
    build_syn_cookie_tcp_reply(
        frame,
        parsed,
        tcp_len,
        cookie_isn,
        parsed.seq.wrapping_add(1),
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        advertised_mss,
    )
}

/// Build a TCP RST reply rejecting a transit segment (#2089 policy
/// `reject` action). Mirrors the retired eBPF `send_tcp_rst_v{4,6}`
/// behavior and RFC 9293 §3.5.2 / RFC 793 §3.4 "Reset Generation":
///
///   - Never reply to an inbound RST (`frame` already carries RST) — a
///     RST about a RST would storm.
///   - If the inbound segment has **no ACK** (e.g. a bare SYN), the RST
///     carries `seq = 0`, `ack = inbound_seq + seg_len`, flags `RST|ACK`.
///     `seg_len` counts the SYN and FIN control bits (1 each) plus any
///     TCP payload bytes (IP total length minus L3 and TCP header
///     lengths). For a bare SYN this is `ack = inbound_seq + 1`.
///   - If the inbound segment has an ACK, the RST carries
///     `seq = inbound_ack`, **no ACK flag**, flags `RST` only. This is
///     deliberately different from `build_syn_cookie_ack_rst_frame`,
///     whose `RST|ACK` form is the validated-cookie special case.
///
/// The L2/L3/L4 assembly (identity swap, checksums, window-0-on-RST) is
/// shared with the SYN-cookie path via `build_syn_cookie_tcp_reply_v{4,6}`.
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn build_reject_rst_frame(frame: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_tcp_reply_source(frame)?;
    // #3204's L2 group/broadcast refusal now lives in `parse_tcp_reply_source`
    // above, which this function has already called — #9111 moved it there
    // after finding the other two reply builders were never given it. The
    // rationale is recorded at the new site; this note exists so the #3204
    // history is not lost from the leg it was written for.
    // Never RST-storm: do not reply to an inbound RST.
    if (parsed.flags & TCP_FLAG_RST) != 0 {
        return None;
    }
    let (seq, ack, flags) = if (parsed.flags & TCP_FLAG_ACK) == 0 {
        // No ACK in the inbound segment: RST carries seq 0 and
        // acknowledges the consumed sequence space (SYN/FIN + payload).
        let seg_len = tcp_segment_consumed_len(frame, parsed)?;
        (
            0u32,
            parsed.seq.wrapping_add(seg_len),
            TCP_FLAG_RST | TCP_FLAG_ACK,
        )
    } else {
        // Inbound carries an ACK: RST takes its sequence from that ACK
        // and omits the ACK flag (canonical RFC reset to a closed port).
        (parsed.ack, 0u32, TCP_FLAG_RST)
    };
    build_syn_cookie_tcp_reply(frame, parsed, TCP_MIN_HEADER_LEN, seq, ack, flags, 0)
}

/// Sequence space consumed by an inbound TCP segment: 1 for each of the
/// SYN and FIN control bits, plus the TCP payload byte count derived
/// from the IP total/payload length minus the L3 and TCP header lengths.
/// Used to compute the RST `ack` for a no-ACK inbound segment.
#[cfg_attr(not(test), allow(dead_code))]
fn tcp_segment_consumed_len(frame: &[u8], parsed: TcpReplySource) -> Option<u32> {
    let mut len: u32 = 0;
    if (parsed.flags & TCP_FLAG_SYN) != 0 {
        len = len.wrapping_add(1);
    }
    // FIN consumes one sequence number too (#2151: shared FIN predicate).
    if crate::tcp_flags::has_fin(parsed.flags) {
        len = len.wrapping_add(1);
    }
    let ip = frame.get(parsed.l3..)?;
    // Offset (from frame start) of the end of the IP datagram, derived
    // from the IP length field. For IPv6, payload_len covers everything
    // after the 40-byte base header — INCLUDING any extension headers —
    // so the TCP payload must be measured from the real TCP header start
    // (frame_l4_offset walks the ext-header chain), not by subtracting a
    // fixed 40 bytes. Doing the latter over-counts the segment length by
    // the ext-header span and inflates the RST ack (a no-ACK v6 segment
    // with ext headers would then carry an unacceptable ack → the client
    // discards the RST → the reject silently degrades to a drop).
    let ip_datagram_end = match parsed.addr_family as i32 {
        libc::AF_INET => {
            if ip.len() < 20 {
                return None;
            }
            let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            parsed.l3.checked_add(total)?
        }
        libc::AF_INET6 => {
            if ip.len() < 40 {
                return None;
            }
            let payload = u16::from_be_bytes([ip[4], ip[5]]) as usize;
            parsed.l3.checked_add(40)?.checked_add(payload)?
        }
        _ => return None,
    };
    // Clamp the datagram end to the captured frame length. The IP length
    // field (v4 total_len / v6 payload_len) is attacker-controlled: a
    // crafted or corrupted packet can advertise a length that runs past
    // the actual frame. Left unclamped, `ip_datagram_end` overshoots the
    // frame, `payload_len` below over-counts by the overshoot, and the
    // no-ACK RST then carries `ack = seq + inflated_seg_len` — an
    // unacceptable ack the peer discards, degrading the `reject`/RST leg
    // to a silent drop (a fail-closed self-DoS on the reject path). For a
    // well-formed packet the datagram end is already within the frame, so
    // this is a no-op (v4 #4484 L-3; also bounds the v6 path).
    let ip_datagram_end = ip_datagram_end.min(frame.len());
    // TCP header start (after IPv6 ext headers, if any) and length from
    // the inbound segment's data-offset field.
    let l4 = frame_l4_offset(frame, parsed.addr_family)?;
    let tcp = frame.get(l4..l4 + TCP_MIN_HEADER_LEN)?;
    let tcp_hdr_len = ((tcp[12] >> 4) as usize) * 4;
    if tcp_hdr_len < TCP_MIN_HEADER_LEN {
        return None;
    }
    let tcp_data_start = l4.checked_add(tcp_hdr_len)?;
    // saturating_sub guards a truncated/malformed length field; a normal
    // segment has ip_datagram_end >= tcp_data_start.
    let payload_len = ip_datagram_end.saturating_sub(tcp_data_start);
    Some(len.wrapping_add(payload_len as u32))
}

/// Build the RST reply for a validated SYN-cookie ACK.
///
/// The userspace contract mirrors the eBPF behavior: a valid cookie ACK is
/// consumed, a RST is sent, and the client's NEXT CONNECTION takes the normal
/// policy/NAT/session path via the validated-client whitelist. For ACK-bearing
/// segments RFC 793 sets the RST sequence number from the received ACK and does
/// not include an ACK field.
///
/// #9419 — read "next connection", not "next SYN". This RST is addressed to
/// the client with `seq = parsed.ack`, i.e. exactly the client's `RCV.NXT`, so
/// RFC 5961 accepts it without a challenge ACK and the just-ESTABLISHED socket
/// is aborted with `ECONNRESET`. Nothing retransmits a SYN from there; the
/// application `connect()`s again on a NEW ephemeral port. That is why the
/// whitelist this path relies on must be keyed on the client and service and
/// must NOT include the source port — the equivalence this comment asserts
/// held only once the key matched the eBPF `struct validated_client_key`.
/// See `screen::SynCookieClientKey` and
/// `docs/syn-cookie-flood-protection.md`, "Whitelist scope and lifetime".
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn build_syn_cookie_ack_rst_frame(frame: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_tcp_reply_source(frame)?;
    if (parsed.flags & TCP_FLAG_ACK) == 0 || (parsed.flags & TCP_FLAG_SYN) != 0 {
        return None;
    }
    build_syn_cookie_tcp_reply(
        frame,
        parsed,
        TCP_MIN_HEADER_LEN,
        parsed.ack,
        parsed.seq.wrapping_add(1),
        TCP_FLAG_RST | TCP_FLAG_ACK,
        0,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy)]
struct TcpReplySource {
    l3: usize,
    addr_family: u8,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_tcp_reply_source(frame: &[u8]) -> Option<TcpReplySource> {
    let l3 = frame_l3_offset(frame)?;
    // #9111 (#3204 completed): NEVER build a reply to an L2 group/broadcast
    // frame, on ANY of the three reply legs.
    //
    // `write_reply_eth_header` copies the inbound L2 DESTINATION into the
    // reply's own L2 SOURCE (`out[6..12] = frame[0..6]`), so a reply built for
    // a frame addressed to a multicast/broadcast MAC egresses with a
    // group/broadcast SOURCE MAC. That is an IEEE 802.3 violation: switches
    // learn the group address against this port, or raise MAC-flap alarms and
    // err-disable it — a broadcast-domain-wide availability event rather than a
    // firewall-local one. Any unauthenticated host on an attached segment can
    // drive it.
    //
    // #3204 established this and guarded ONE of the three builders
    // (`build_reject_rst_frame`); `build_syn_cookie_syn_ack_frame` and
    // `build_syn_cookie_ack_rst_frame` were left reachable, which is exactly
    // when the SYN-cookie path is armed and under attack.
    //
    // The check lives HERE, at the single function all three builders call
    // first, rather than being repeated at each — a fourth reply builder
    // inherits it instead of having to remember it, which is the property the
    // per-site version did not have. Fails closed to the silent drop every
    // caller already performs on None.
    if let Some(eth_dst) = frame.get(0..6)
        && let Ok(eth_dst) = <&[u8; 6]>::try_from(eth_dst)
        && crate::afxdp::frame::inspect::l2_dst_is_group_or_broadcast(eth_dst)
    {
        return None;
    }
    let ip = frame.get(l3..)?;
    let addr_family = match ip.first()? >> 4 {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return None,
    };
    // #8597 K37: DECLINE a non-first fragment, the same gate `clamp_tcp_mss`
    // takes 250 lines above.
    //
    // On a non-first fragment the bytes at `l4` are PAYLOAD, not a TCP header,
    // so every field below — ports, seq, ack, flags — would be read from
    // attacker-chosen data and then reflected into a SYN-ACK or an RST by the
    // three builders that call this.
    //
    // The protocol check further down does NOT cover this, and that is the
    // subtle part: it reads the protocol byte out of the FRAME's IP header,
    // where a fragmented TCP datagram still says TCP (6) in every fragment.
    // Fragmentation does not change that field.
    //
    // NOT REACHABLE TODAY, and the defence is remote enough to be worth naming
    // rather than relying on. The shim substitutes `PROTO_FRAGMENT_NO_L4` for a
    // non-first fragment's protocol BEFORE `parse_l4` (`userspace-xdp/src/lib.rs`
    // `parse_ipv4`), so `meta.protocol` is not `PROTO_TCP` and `meta.tcp_flags`
    // is 0 — which is what actually stops all three callers: the two syn-cookie
    // builders need SYN flags from screen, and `reject_reply.rs` branches on
    // `meta.protocol == PROTO_TCP` and takes the ICMP arm instead.
    //
    // So the invariant protecting this function lives in a different crate, is
    // keyed on `meta` while this function reads the FRAME, and no test here can
    // red without it. That is precisely the kind of guard worth making local.
    match addr_family as i32 {
        libc::AF_INET => {
            if ipv4_is_non_first_fragment(ip) {
                return None;
            }
        }
        libc::AF_INET6 => {
            if ipv6_is_non_first_fragment(ip) {
                return None;
            }
        }
        _ => return None,
    }
    let l4 = frame_l4_offset(frame, addr_family)?;
    let tcp = frame.get(l4..l4 + TCP_MIN_HEADER_LEN)?;
    let protocol = match addr_family as i32 {
        libc::AF_INET => *ip.get(9)?,
        libc::AF_INET6 => {
            let (_, protocol) = packet_rel_l4_offset_and_protocol(ip, addr_family)?;
            protocol
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    Some(TcpReplySource {
        l3,
        addr_family,
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_syn_cookie_tcp_reply(
    frame: &[u8],
    parsed: TcpReplySource,
    tcp_len: usize,
    seq: u32,
    ack: u32,
    flags: u8,
    advertised_mss: u16,
) -> Option<Vec<u8>> {
    match parsed.addr_family as i32 {
        libc::AF_INET => build_syn_cookie_tcp_reply_v4(
            frame,
            parsed,
            tcp_len,
            seq,
            ack,
            flags,
            advertised_mss,
        ),
        libc::AF_INET6 => build_syn_cookie_tcp_reply_v6(
            frame,
            parsed,
            tcp_len,
            seq,
            ack,
            flags,
            advertised_mss,
        ),
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_syn_cookie_tcp_reply_v4(
    frame: &[u8],
    parsed: TcpReplySource,
    tcp_len: usize,
    seq: u32,
    ack: u32,
    flags: u8,
    advertised_mss: u16,
) -> Option<Vec<u8>> {
    let ip = frame.get(parsed.l3..parsed.l3 + 20)?;
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let total_len = 20usize.checked_add(tcp_len)?;
    let frame_len = parsed
        .l3
        .checked_add(total_len)?
        .max(ETHERNET_MIN_FRAME_LEN);
    let mut out = vec![0u8; frame_len];
    write_reply_eth_header(frame, &mut out, parsed.l3)?;
    let ip_out = out.get_mut(parsed.l3..parsed.l3 + total_len)?;
    ip_out[0] = 0x45;
    ip_out[2..4].copy_from_slice(&saturate_len16(total_len).to_be_bytes());
    ip_out[8] = SYN_COOKIE_REPLY_TTL;
    ip_out[9] = PROTO_TCP;
    ip_out[12..16].copy_from_slice(&dst.octets());
    ip_out[16..20].copy_from_slice(&src.octets());
    let ip_sum = checksum16(&ip_out[..20]);
    ip_out[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    write_syn_cookie_tcp_header(
        &mut ip_out[20..20 + tcp_len],
        parsed,
        seq,
        ack,
        flags,
        advertised_mss,
    )?;
    recompute_l4_checksum_ipv4(ip_out, 20, PROTO_TCP, false)?;
    Some(out)
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_syn_cookie_tcp_reply_v6(
    frame: &[u8],
    parsed: TcpReplySource,
    tcp_len: usize,
    seq: u32,
    ack: u32,
    flags: u8,
    advertised_mss: u16,
) -> Option<Vec<u8>> {
    let ip = frame.get(parsed.l3..parsed.l3 + 40)?;
    let src = ip.get(8..24)?;
    let dst = ip.get(24..40)?;
    let frame_len = parsed.l3.checked_add(40)?.checked_add(tcp_len)?;
    let mut out = vec![0u8; frame_len];
    write_reply_eth_header(frame, &mut out, parsed.l3)?;
    let ip_out = out.get_mut(parsed.l3..frame_len)?;
    ip_out[0] = 0x60;
    ip_out[4..6].copy_from_slice(&saturate_len16(tcp_len).to_be_bytes());
    ip_out[6] = PROTO_TCP;
    ip_out[7] = SYN_COOKIE_REPLY_HOP_LIMIT;
    ip_out[8..24].copy_from_slice(dst);
    ip_out[24..40].copy_from_slice(src);
    write_syn_cookie_tcp_header(
        &mut ip_out[40..40 + tcp_len],
        parsed,
        seq,
        ack,
        flags,
        advertised_mss,
    )?;
    recompute_l4_checksum_ipv6(ip_out, 40, PROTO_TCP)?;
    Some(out)
}

#[cfg_attr(not(test), allow(dead_code))]
fn write_reply_eth_header(frame: &[u8], out: &mut [u8], l3: usize) -> Option<()> {
    if l3 != 14 && l3 != 18 {
        return None;
    }
    out.get_mut(0..6)?.copy_from_slice(frame.get(6..12)?);
    out.get_mut(6..12)?.copy_from_slice(frame.get(0..6)?);
    if l3 == 18 {
        out.get_mut(12..18)?.copy_from_slice(frame.get(12..18)?);
    } else {
        out.get_mut(12..14)?.copy_from_slice(frame.get(12..14)?);
    }
    Some(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn write_syn_cookie_tcp_header(
    tcp: &mut [u8],
    parsed: TcpReplySource,
    seq: u32,
    ack: u32,
    flags: u8,
    advertised_mss: u16,
) -> Option<()> {
    if tcp.len() != TCP_MIN_HEADER_LEN && tcp.len() != TCP_MIN_HEADER_LEN + TCP_MSS_OPTION_LEN {
        return None;
    }
    tcp[0..2].copy_from_slice(&parsed.dst_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&parsed.src_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((tcp.len() / 4) as u8) << 4;
    tcp[13] = flags;
    let window: u16 = if flags & TCP_FLAG_RST != 0 {
        0
    } else {
        SYN_COOKIE_TCP_WINDOW
    };
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    if tcp.len() == TCP_MIN_HEADER_LEN + TCP_MSS_OPTION_LEN {
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22..24].copy_from_slice(&advertised_mss.to_be_bytes());
    }
    Some(())
}

/// Clamp TCP MSS in a full Ethernet frame starting at `l3_offset`.
#[inline(always)]
#[allow(dead_code)]
pub(super) fn clamp_tcp_mss_frame(frame: &mut [u8], l3_offset: usize, max_mss: u16) -> bool {
    if max_mss == 0 || l3_offset >= frame.len() {
        return false;
    }
    clamp_tcp_mss(&mut frame[l3_offset..], max_mss)
}

#[cfg(test)]
#[path = "tcp_tests.rs"]
mod tests;
