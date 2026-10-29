//! #7899: fragment-association KEY derivation -- the packet-parsing half of
//! the component. Split from the cache mechanics in `mod.rs` because parsing
//! L3 headers and running a sharded LRU are different responsibilities.

use super::*;

/// Parse the port-free fragment fields from an L3-relative packet: the
/// `(key, more, offset_units)` triple. `addr_family` selects the family. Shared
/// by [`first_fragment_key`] and [`nonfirst_fragment_key`] so the
/// install and consult key derivations are byte-identical.
///
/// #5798: `authority` is the ingress security domain the caller resolved for
/// THIS packet (see [`FragAuthority`]). It is stamped verbatim into the key so
/// install and consult agree by construction; this ONE builder is the SSOT for
/// both derivations, so the two can never drift into keying on different
/// dimensions. Every other field is read from the packet's L3 headers only —
/// no payload byte is interpreted as L4.
fn fragment_fields(
    packet: &[u8],
    addr_family: i32,
    authority: FragAuthority,
) -> Option<(FragKey, bool, u16)> {
    match addr_family {
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let frag = ipv6_fragment_header(packet)?;
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            let key = FragKey {
                addr_family: libc::AF_INET6 as u8,
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                ident: frag.ident,
                // The Fragment Header's Next Header — present in every
                // fragment, so first and non-first derive the same protocol.
                protocol: frag.next_header,
                authority,
            };
            Some((key, frag.more, frag.offset_units))
        }
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let frag_word = u16::from_be_bytes([packet[6], packet[7]]);
            let more = (frag_word & 0x2000) != 0;
            let offset_units = frag_word & 0x1FFF;
            let ident = u16::from_be_bytes([packet[4], packet[5]]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let key = FragKey {
                addr_family: libc::AF_INET as u8,
                src: IpAddr::V4(src),
                dst: IpAddr::V4(dst),
                ident: u32::from(ident),
                // IPv4 header byte 9 — the Protocol field, present in every
                // fragment (unlike the L4 header, which only the first carries).
                protocol: packet[9],
                authority,
            };
            Some((key, more, offset_units))
        }
        _ => None,
    }
}

/// Association key for a FIRST fragment (offset 0, MF=1) — the fragment that
/// INSTALLS the entry. Returns `None` for a non-first fragment, an atomic
/// fragment (MF=0, offset 0), or a non-fragmented packet.
///
/// #5798: `authority` is the ingress security domain that admitted this first
/// fragment; a non-first fragment can only inherit the entry by presenting the
/// SAME authority.
pub(crate) fn first_fragment_key(
    packet: &[u8],
    addr_family: i32,
    authority: FragAuthority,
) -> Option<FragKey> {
    let (key, more, offset_units) = fragment_fields(packet, addr_family, authority)?;
    if more && offset_units == 0 {
        Some(key)
    } else {
        None
    }
}

/// Association key for a NON-first fragment (offset > 0) — the fragment that
/// CONSULTS the entry. Returns `None` for a first / atomic / non-fragmented
/// packet.
///
/// #5798: `authority` is THIS fragment's own ingress domain. A fragment from a
/// different domain therefore builds a different key and MISSES, falling
/// through to full flowless enforcement under its real identity instead of
/// inheriting the first fragment's permit.
pub(crate) fn nonfirst_fragment_key(
    packet: &[u8],
    addr_family: i32,
    authority: FragAuthority,
) -> Option<FragKey> {
    let (key, _more, offset_units) = fragment_fields(packet, addr_family, authority)?;
    if offset_units != 0 { Some(key) } else { None }
}
/// #17720: derive a fragment's byte-range contribution from its network-layer
/// length, not the receive-buffer extent (which may include padding). Unknown,
/// truncated, or malformed geometry is deliberately not accumulated, so it can
/// never make the association appear complete.
pub(crate) fn fragment_range(
    packet: &[u8],
    addr_family: i32,
    authority: FragAuthority,
) -> Option<FragmentRange> {
    let (_key, more, offset_units) = fragment_fields(packet, addr_family, authority)?;
    if offset_units == 0 && !more {
        return None;
    }
    let start = u32::from(offset_units) * 8;
    let payload_len = match addr_family {
        libc::AF_INET => {
            let ihl = u32::from(*packet.first()? & 0x0F) * 4;
            let total_len = u32::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            if ihl < 20 || total_len < ihl || total_len as usize > packet.len() {
                return None;
            }
            total_len - ihl
        }
        libc::AF_INET6 => {
            let total_len = 40u32
                .checked_add(u32::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?])))?;
            let walk = crate::afxdp::frame::walk_ipv6_ext_chain(packet, 0);
            let fragment = walk.fragment?;
            let fragment_end = fragment.header_offset.checked_add(8)?;
            if fragment_end > total_len as usize || total_len as usize > packet.len() {
                return None;
            }
            total_len - fragment_end as u32
        }
        _ => return None,
    };
    // RFC 791 / RFC 8200 require non-final fragment data lengths to be a
    // multiple of eight. Treat malformed geometry as unknown rather than
    // rounding it into coverage.
    if more && payload_len % 8 != 0 {
        return None;
    }
    let end = start.checked_add(payload_len)?;
    if end > u32::from(u16::MAX) {
        return None;
    }
    Some(FragmentRange { start, end, more })
}


