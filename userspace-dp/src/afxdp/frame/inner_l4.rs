//! #17164: the single tunnel-inner L4 parser shared by GRE, WireGuard,
//! and the IPsec-inner descriptor path.
//!
//! Moved verbatim (modulo the TCP arm, see below) from `gre.rs`, where
//! `parse_inner_protocol_and_offsets` and `packet_trimmed_len` lived
//! `pub(in crate::afxdp)`. The IPsec path never called it: `slowpath.rs`
//! kept a private copy over `packet_rel_l4_offset_and_protocol`, which
//! diverged on short UDP (admitted with `payload == l4` instead of
//! failing closed), on ICMP (`payload == l4` instead of `l4 + 8`), and
//! carried a rustc-flagged unreachable `6 => None` arm (#13713's copy
//! shipped the TCP divergence the shared parser already handled).
//! Every inner-L4 fix (#2376, #13713, #15787) had to find both copies;
//! now there is one.
//!
//! The TCP arm resolves the payload end via
//! `frame::tcp::tcp_payload_offset_from_l3` instead of open-coding the
//! data-offset nibble read a third time. That helper re-walks the
//! L3-relative chain and requires the walked L4 offset to equal the
//! caller's, which holds here by construction (the caller just walked
//! the same packet), so the verdicts are identical to the open-coded
//! arm: `None` on a sub-20-byte or past-end TCP header, `l4 + tcp_len`
//! otherwise.

use super::super::*;
use super::packet_rel_l4_offset_and_protocol;
use super::tcp::tcp_payload_offset_from_l3;

pub(crate) fn packet_trimmed_len(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total_len == 0 || total_len > packet.len() {
                return None;
            }
            Some(total_len)
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let total_len = 40usize.checked_add(payload_len)?;
            if total_len > packet.len() {
                return None;
            }
            Some(total_len)
        }
        _ => None,
    }
}

// #8274: widened from private for the WireGuard worker decap stage — the inner
// packet it hands to `build_logical_ingress_packet` needs exactly these three
// values, derived exactly this way.
pub(crate) fn parse_inner_protocol_and_offsets(
    packet: &[u8],
    addr_family: u8,
) -> Option<(u8, u16, u16)> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            // #15787: a non-first fragment's bytes at `ihl` are payload,
            // not an L4 header. Admit it as fragment-no-L4 (the XDP
            // shim's `PROTO_FRAGMENT_NO_L4` substitution, ported via
            // `packet_rel_l4_offset_and_protocol`) instead of parsing
            // the payload as a TCP/UDP/ICMP header.
            if crate::afxdp::frame::ipv4_is_non_first_fragment(packet) {
                return Some((
                    crate::session::SHIM_PROTO_FRAGMENT_NO_L4,
                    ihl as u16,
                    ihl as u16,
                ));
            }
            let protocol = packet[9];
            let l4_offset = ihl as u16;
            let payload_offset = match protocol {
                PROTO_TCP => {
                    // #17164: payload end via the shared TCP helper; it
                    // fails closed exactly like the open-coded arm did
                    // (sub-20-byte or past-end data offset -> None).
                    tcp_payload_offset_from_l3(packet, addr_family, ihl)? as u16
                }
                // #2376: UDP (RFC 768) and ICMP (RFC 792) both have an
                // 8-byte minimum header. The inner packet was already
                // trimmed to its IP-declared total length
                // (`packet_trimmed_len`), so a short inner (e.g.
                // total_len = ihl + 2) survives to here. Unlike TCP
                // above, these arms previously advanced the payload
                // offset by 8 with NO bounds check, stamping
                // `l4_offset`/`payload_offset` from bytes that are not a
                // real L4 header and pointing `payload_offset` past the
                // packet end. Fail CLOSED (drop / no decap) when the
                // inner cannot contain the claimed L4 header.
                PROTO_UDP | PROTO_ICMP => {
                    if packet.len() < ihl + 8 {
                        return None;
                    }
                    l4_offset + 8
                }
                _ => l4_offset,
            };
            Some((protocol, l4_offset, payload_offset))
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            // Use the extension-header-aware helper to get both the final L4
            // protocol and the correct offset. packet[6] may be an extension
            // header type, not the actual L4 protocol.
            //
            // #2292: `packet_rel_l4_offset_and_protocol` now fails CLOSED
            // (returns `None`) when the ext-header chain is still on an
            // extension header at the `MAX_IPV6_EXT_HEADERS` bound, so a
            // surrendered `protocol == 0` (unconsumed Hop-by-Hop) can no
            // longer reach this match. The `_` arm below additionally
            // DROPS any leftover ext-header / no-next-header sentinel
            // (Hop-by-Hop 0, Routing 43, AH 51, No-Next 59, Dest-Opts 60)
            // rather than forwarding it with the ext-header offset used as
            // a fake L4/payload offset — defense in depth so this caller
            // never forwards a packet whose L4 protocol it could not
            // resolve.
            let (l4_off, protocol) = packet_rel_l4_offset_and_protocol(packet, addr_family)?;
            let rel_l4 = l4_off as u16;
            // #15787: an inner IPv6 non-first fragment resolves to the
            // fragment-no-L4 sentinel at the payload offset (first byte
            // past the Fragment header). Admit it flowless — payload
            // offset == L4 offset, no L4 header is read — instead of
            // dropping 100% of such decapsulated fragments.
            if protocol == crate::session::SHIM_PROTO_FRAGMENT_NO_L4 {
                return Some((protocol, rel_l4, rel_l4));
            }
            let payload_offset = match protocol {
                PROTO_TCP => {
                    // #17164: payload end via the shared TCP helper (see
                    // the IPv4 arm); same fail-closed verdicts.
                    tcp_payload_offset_from_l3(packet, addr_family, l4_off)? as u16
                }
                // #2376: mirror the IPv4 UDP/ICMP guard for the IPv6
                // inner. UDP (RFC 768) and ICMPv6 (RFC 4443) both have
                // an 8-byte minimum header. `rel_l4` is the offset of
                // the resolved L4 header within the (already
                // IP-declared-length-trimmed) inner packet; if the
                // packet ends before that header is complete, the
                // previous `rel_l4 + 8` stamped a payload offset past
                // the packet end from non-L4 bytes. Fail CLOSED.
                PROTO_UDP | PROTO_ICMPV6 => {
                    let l4 = rel_l4 as usize;
                    if packet.len() < l4 + 8 {
                        return None;
                    }
                    rel_l4 + 8
                }
                // #2292: an unresolved/extension-header protocol is a drop,
                // not a forward. 0/43/51/59/60 are IPv6 ext-header or
                // no-next-header sentinels, never a real inner L4.
                0 | 43 | 51 | 59 | 60 => return None,
                _ => rel_l4,
            };
            Some((protocol, rel_l4, payload_offset))
        }
        _ => None,
    }
}
