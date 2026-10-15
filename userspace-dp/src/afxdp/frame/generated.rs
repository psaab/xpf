//! #2238: parse a LOCALLY-GENERATED reply frame (the bytes the dataplane
//! built in response to an inbound packet) back into a classification key.
//!
//! Locally-generated control frames — ICMP/ICMPv6 Time Exceeded, the
//! policy-`reject` TCP RST / ICMP-unreachable, and SYN-cookie SYN-ACK /
//! ACK-RST — are *reflections* of the inbound packet (MAC swap, IP swap,
//! frequently a protocol change). Their true egress 5-tuple is the reverse
//! of the trigger, with ICMP/ICMPv6 as the protocol for the error cases.
//! Classifying them by the *trigger* tuple (what the pre-#2238 code did)
//! means an output firewall filter / CoS forwarding-class / DSCP rewrite
//! keyed on the GENERATED packet never fires (or the wrong term fires).
//!
//! [`generated_reply_session_key`] walks the BUILT bytes (the same byte
//! layout the `build_*` reflectors emit) and returns the generated frame's
//! own `(SessionKey, ForwardPacketMeta)` so the shared classifier
//! ([`crate::afxdp::tx::classify_generated_reply`]) can evaluate the egress
//! output filter + CoS against the reply's real tuple.
//!
//! This reuses [`super::frame_l3_offset`] (the single L2/VLAN walker) so
//! there is ONE parser of wire bytes, not a second hand-rolled one. ICMP /
//! ICMPv6 carry no L4 ports; ports are reported as 0 — the output filter's
//! ICMP terms key on protocol (+ optionally addresses), never on L4 ports
//! (Junos has no `port` match for ICMP), and the TX-selection evaluator
//! takes ports as `u16` with 0 the natural "no port" sentinel (same as how
//! ICMP is keyed everywhere else in the dataplane).
//!
//! Cold path only — every caller is on a generator's exception arm
//! (`#[cold]` reject/cookie bodies, or the TTL<=1 Time Exceeded path). No
//! hot-path cost.

use super::frame_l3_offset;
use super::*;

/// Parse a locally-generated reply frame into its own egress
/// `(SessionKey, ForwardPacketMeta)`.
///
/// Returns `None` on any parse failure (truncated header, unknown family,
/// over-bound IPv6 extension chain, or a TCP/UDP reply truncated before its 4
/// L4 port bytes). The caller MUST fail CLOSED on `None`
/// (#2238 §6.2): an output-filter terminal `discard`/`reject` is a security
/// boundary, so a reply whose own bytes cannot be classified is DROPPED, not
/// leaked past the filter. The bytes are our own, so `None` is a logic bug —
/// the caller attributes it on a dedicated parse-error counter.
///
///   - `tcp_flags` is read from the generated TCP header, and TCP packets whose
///     IP-declared length ends before that byte fail closed;
///   - `pkt_len` is the L3-onwards length of the generated frame (what the
///     output-filter byte counter should be charged);
///   - `ingress_*` fields are left neutral/zero: the reply is host-
///     originated, so it has no meaningful ingress PCP/VLAN for an IEEE-802.1
///     classifier. The egress output filter + DSCP classifier are the
///     relevant inputs, and both key off the fields populated above.
pub(in crate::afxdp) fn generated_reply_session_key(
    frame: &[u8],
) -> Option<(SessionKey, ForwardPacketMeta)> {
    let l3 = frame_l3_offset(frame)?;
    let packet = frame.get(l3..)?;
    let version = (packet.first()? >> 4) & 0x0f;
    match version {
        4 => parse_generated_v4(packet, l3),
        6 => parse_generated_v6(packet, l3),
        _ => None,
    }
}

fn parse_generated_v4(packet: &[u8], l3_offset: usize) -> Option<(SessionKey, ForwardPacketMeta)> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    // ToS byte: DSCP is the top 6 bits.
    let dscp = packet[1] >> 2;
    let protocol = packet[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
    // IPv4 total length bounds the L3-onward byte count; clamp to the slice
    // so a built frame with trailing slack does not over-charge the filter
    // byte counter.
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let pkt_len = total_len.clamp(ihl, packet.len());
    // §6.2 fail-CLOSED: a TCP/UDP generated reply MUST carry its 4 port bytes
    // at the L4 offset (`ihl`) within the IP-DECLARED packet end (`pkt_len`).
    // A frame truncated before the ports — or whose total_len ends short of
    // the L4 header while the buffer has trailing slack — yields `None` here,
    // so the caller drops the reply (and bumps
    // `generated_reply_classify_parse_errors`) rather than misclassifying it
    // with substituted (0,0) ports past an output `discard`.
    let (src_port, dst_port) = generated_l4_ports(packet, ihl, protocol, pkt_len)?;
    let tcp_flags = generated_tcp_flags(packet, ihl, protocol, pkt_len)?;
    finish_generated_key(
        libc::AF_INET as u8,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        dscp,
        pkt_len,
        l3_offset,
        ihl,
        tcp_flags,
    )
}

fn parse_generated_v6(packet: &[u8], l3_offset: usize) -> Option<(SessionKey, ForwardPacketMeta)> {
    if packet.len() < 40 {
        return None;
    }
    // Traffic class spans the low nibble of byte 0 and the high nibble of
    // byte 1: tc[7:0] = (byte0[3:0] << 4) | (byte1[7:4]); DSCP is tc[7:2].
    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let dscp = traffic_class >> 2;
    let src_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?));
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let pkt_len = (40usize.saturating_add(payload_len)).clamp(40, packet.len());
    // Walk the extension-header chain to the L4 protocol + offset (bounded,
    // fail-closed at the bound — same contract as the forwarding walkers).
    let (rel_l4, protocol) = packet_rel_l4_offset_and_protocol(packet, libc::AF_INET6 as u8)?;
    // §6.2 fail-CLOSED: see parse_generated_v4 — a TCP/UDP reply truncated
    // before its 4 port bytes, or whose payload_len ends short of the L4
    // header (bounded by `pkt_len`, not the backing slice), drops rather than
    // misclassifies with (0,0).
    let (src_port, dst_port) = generated_l4_ports(packet, rel_l4, protocol, pkt_len)?;
    let tcp_flags = generated_tcp_flags(packet, rel_l4, protocol, pkt_len)?;
    finish_generated_key(
        libc::AF_INET6 as u8,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        dscp,
        pkt_len,
        l3_offset,
        rel_l4,
        tcp_flags,
    )
}

/// L4 ports for the generated frame: real ports for TCP/UDP, 0/0 for
/// ICMP/ICMPv6 (no transport ports) and anything else.
///
/// §6.2 fail-CLOSED: for TCP/UDP this returns `None` when the 4 port bytes
/// at `rel_l4` cannot be read inside the IP-DECLARED packet end. `pkt_len`
/// is the slice-clamped IP-declared length (IPv4 total_len / IPv6
/// 40+payload_len, each clamped to the backing slice), so the read is bounded
/// by `min(pkt_len, packet.len())` — i.e. `pkt_len`, since `pkt_len <=
/// packet.len()` by construction. This means a corrupted or short total_len /
/// payload_len that ends BEFORE the L4 header fails closed even when the
/// backing buffer still has trailing slack bytes (reading those would yield
/// bogus ports). The callers propagate that `None` so a generated reply whose
/// ports cannot be read is DROPPED, never misclassified with substituted (0,0)
/// ports past an output-filter `discard`. ICMP/ICMPv6 (and anything else)
/// legitimately have no transport ports and return `(0, 0)` unchanged.
fn generated_l4_ports(
    packet: &[u8],
    rel_l4: usize,
    protocol: u8,
    pkt_len: usize,
) -> Option<(u16, u16)> {
    match protocol {
        PROTO_TCP | PROTO_UDP => {
            // Bound the port read by the IP-declared end, not the backing
            // slice. `end > pkt_len` => declared packet stops before the ports.
            let end = rel_l4.checked_add(4)?;
            if end > pkt_len {
                return None;
            }
            packet.get(rel_l4..end).map(|b| {
                (
                    u16::from_be_bytes([b[0], b[1]]),
                    u16::from_be_bytes([b[2], b[3]]),
                )
            })
        }
        _ => Some((0, 0)),
    }
}

/// TCP flag byte for the generated reply, bounded by the IP-declared packet.
/// A TCP packet whose declared datagram ends before the flag byte is not
/// classifiable for a `tcp-flags` output-filter term, so fail closed just as
/// for missing ports. Non-TCP protocols carry no TCP flags.
fn generated_tcp_flags(packet: &[u8], rel_l4: usize, protocol: u8, pkt_len: usize) -> Option<u8> {
    if protocol != PROTO_TCP {
        return Some(0);
    }
    let end = rel_l4.checked_add(14)?;
    if end > pkt_len {
        return None;
    }
    packet.get(rel_l4.checked_add(13)?).copied()
}


#[allow(clippy::too_many_arguments)]
fn finish_generated_key(
    addr_family: u8,
    protocol: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    dscp: u8,
    pkt_len: usize,
    l3_offset: usize,
    rel_l4: usize,
    tcp_flags: u8,
) -> Option<(SessionKey, ForwardPacketMeta)> {
    let key = SessionKey {
        addr_family,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let meta = ForwardPacketMeta {
        addr_family,
        protocol,
        dscp,
        l3_offset: u16::try_from(l3_offset).unwrap_or(0),
        l4_offset: u16::try_from(l3_offset.saturating_add(rel_l4)).unwrap_or(0),
        pkt_len: u16::try_from(pkt_len).unwrap_or(u16::MAX),
        tcp_flags,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..ForwardPacketMeta::default()
    };
    Some((key, meta))
}

#[cfg(test)]
#[path = "generated_tests.rs"]
mod tests;
