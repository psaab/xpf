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
#[cfg_attr(not(test), allow(dead_code))]
const TCP_FLAG_ACK: u8 = 0x10;
#[cfg_attr(not(test), allow(dead_code))]
const TCP_FLAG_RST: u8 = 0x04;
#[cfg_attr(not(test), allow(dead_code))]
const TCP_FLAG_SYN: u8 = 0x02;
#[cfg_attr(not(test), allow(dead_code))]
const TCP_MIN_HEADER_LEN: usize = 20;
#[cfg_attr(not(test), allow(dead_code))]
const TCP_MSS_OPTION_LEN: usize = 4;

/// Check if a frame contains a TCP RST flag.
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
    let (protocol, l4_offset) = match ip[0] >> 4 {
        4 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 if ip.len() >= 40 => (ip[6], 40usize),
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match ip.get(l4_offset..) {
        Some(t) if t.len() >= 14 => t,
        _ => return false,
    };
    // TCP flags at offset 13: RST = 0x04
    (tcp[13] & 0x04) != 0
}

/// Extract TCP flags and window from raw frame, auto-detecting L3 from Ethernet header.
/// Returns (tcp_flags, tcp_window) or None.
#[inline]
pub(in crate::afxdp) fn extract_tcp_flags_and_window(frame: &[u8]) -> Option<(u8, u16)> {
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            (ip[6], 40usize)
        }
        _ => return None,
    };
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

/// Extract TCP window size from raw frame data.
/// Returns None if not a TCP frame or if frame is too short.
#[inline]
#[allow(dead_code)]
pub(in crate::afxdp) fn extract_tcp_window(frame: &[u8], addr_family: u8) -> Option<u16> {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return None,
    };
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match addr_family as i32 {
        libc::AF_INET => {
            if ip.len() < 20 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        libc::AF_INET6 => {
            if ip.len() < 40 {
                return None;
            }
            (ip[6], 40usize)
        }
        _ => return None,
    };
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
    let mut s = String::with_capacity(12);
    if flags & 0x02 != 0 {
        s.push_str("SYN ");
    }
    if flags & 0x10 != 0 {
        s.push_str("ACK ");
    }
    if flags & 0x01 != 0 {
        s.push_str("FIN ");
    }
    if flags & 0x04 != 0 {
        s.push_str("RST ");
    }
    if flags & 0x08 != 0 {
        s.push_str("PSH ");
    }
    if flags & 0x20 != 0 {
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
            (40, packet[6])
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
    // Only clamp on SYN or SYN+ACK
    if (flags & 0x02) == 0 {
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
                let old_val = u16::from_be_bytes(old_bytes) as u32;
                let new_val = max_mss as u32;
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

/// Build the RST reply for a validated SYN-cookie ACK.
///
/// The current userspace contract mirrors the eBPF behavior: a valid cookie ACK
/// is consumed, a RST is sent, and the client's next SYN takes the normal
/// policy/NAT/session path. For ACK-bearing segments RFC 793 sets the RST
/// sequence number from the received ACK and does not include an ACK field.
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
        0,
        TCP_FLAG_RST,
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
    let ip = frame.get(l3..)?;
    let addr_family = match ip.first()? >> 4 {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return None,
    };
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
    ip_out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
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
    ip_out[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
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
    recompute_l4_checksum_ipv6(ip_out, PROTO_TCP)?;
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
    tcp[14..16].copy_from_slice(&SYN_COOKIE_TCP_WINDOW.to_be_bytes());
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
