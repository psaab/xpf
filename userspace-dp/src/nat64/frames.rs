//! NAT64 non-first-fragment translation and Ethernet frame builders.
//!
//! The `build_nat64_*_frame*` family and `frame_l3_offset`.
//!
//! #16188 PURE CODE MOTION: every line below was moved verbatim from
//! `nat64.rs` lines 4845-5371 (doc block included; it moved with its fn). The only edits are the visibility
//! widenings enumerated in `nat64/mod.rs`; no logic, no ordering and
//! no signature changed.

use super::*;

/// #2562: translate a NON-first IPv6 fragment to IPv4, L3-only.
///
/// A non-first fragment (Fragment Header present, offset > 0) has NO L4 header —
/// every byte after the Fragment Header is opaque payload. This is the sibling
/// of [`write_v6_to_v4_into`] for that case: it does NOT parse or checksum an L4
/// header (there is none). It strips the IPv6 base + extension + Fragment
/// headers, emits a 20-byte IPv4 header whose fragmentation fields are copied
/// from the IPv6 Fragment Header (DF=0, MF from the M flag, the 13-bit offset
/// verbatim in 8-byte units, and **IPv4 Identification = the low 16 bits of the
/// IPv6 32-bit Identification** — the SAME truncation the first fragment used,
/// which is load-bearing for reassembly at the receiver), copies the payload
/// verbatim, and recomputes ONLY the IPv4 header checksum.
///
/// The `snat_v4`/`dst_v4` come from the FIRST fragment's cached association
/// (`FragAssoc`), so all fragments translate to the same source and
/// reassemble. Fragmented ICMPv6 is NOT handled here (the ICMP checksum covers
/// the whole datagram and cannot be recomputed from a fragment) — it stays the
/// #4617 fail-closed drop, so only TCP/UDP are accepted.
pub(super) fn write_v6_to_v4_nonfirst_translate(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    preserve_ttl: bool,
) -> Option<usize> {
    if packet.len() < 40 {
        return None;
    }
    // #5625/#10860: same eligibility gate as the first-fragment translator.
    // Drop a fragmented datagram whose unfragmentable part carries an ACTIVE
    // Routing header (SL > 0), or whose Fragment Header names any traversable
    // extension header; otherwise post-Fragment bytes would be stripped /
    // mistaken for a header while the fragment offset is copied verbatim.
    if nat64_v6_translation_ineligible(packet) {
        return None;
    }
    let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let hop_limit = packet[7];
    if !preserve_ttl && hop_limit <= 1 {
        return None; // TTL expired for forwarding; slow path preserves it for the kernel
    }
    // `ipv6_l4_offset_and_protocol` walks the chain and, for a non-first
    // fragment, returns the offset of the byte AFTER the Fragment Header (where
    // the opaque payload starts) and the Fragment Header's Next Header (the real
    // upper-layer protocol) — exactly what we need.
    let (payload_off, l4_protocol) = ipv6_l4_offset_and_protocol(packet)?;
    let frag = ipv6_fragment_header(packet)?;
    if frag.offset_units == 0 {
        return None; // not a non-first fragment — caller must use the first path
    }
    // TCP/UDP only. ICMPv6 fragments stay the #4617 fail-closed drop.
    let ipv4_protocol = match l4_protocol {
        PROTO_TCP | PROTO_UDP => l4_protocol,
        _ => return None,
    };
    let l4_end = 40usize.checked_add(payload_len)?;
    if payload_off > l4_end {
        return None; // ext-header chain overran the advertised payload
    }
    let payload = packet.get(payload_off..l4_end)?;
    let total_len = 20usize.checked_add(payload.len())?;
    // #10191: IPv4 Total Length is a 16-bit field. Fail closed rather than
    // narrowing 20 + payload.len() above 65535 and emitting a wrapped datagram.
    if total_len > u16::MAX as usize {
        return None;
    }
    let out = dst.get_mut(..total_len)?;
    out[0] = 0x45; // version=4, IHL=5
    out[1] = traffic_class;
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    let ident = (frag.ident & 0xFFFF) as u16;
    out[4..6].copy_from_slice(&ident.to_be_bytes());
    let mf = if frag.more { 0x2000u16 } else { 0 };
    let frag_word = mf | (frag.offset_units & 0x1FFF);
    out[6..8].copy_from_slice(&frag_word.to_be_bytes());
    out[8] = if preserve_ttl {
        hop_limit
    } else {
        hop_limit - 1
    };
    out[9] = ipv4_protocol;
    out[10..12].copy_from_slice(&[0, 0]); // header checksum (computed below)
    out[12..16].copy_from_slice(&snat_v4.octets());
    out[16..20].copy_from_slice(&dst_v4.octets());
    out[20..total_len].copy_from_slice(payload);
    let hdr_sum = checksum16(&out[..20]);
    out[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    Some(total_len)
}

/// Allocation-free entry point for the decrementing translator.
pub(crate) fn write_v6_to_v4_nonfirst_into(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
) -> Option<usize> {
    write_v6_to_v4_nonfirst_translate(dst, packet, snat_v4, dst_v4, false)
}

/// #14114: slow-path twin of [`write_v6_to_v4_nonfirst_into`] that preserves
/// the ingress Hop Limit. The delegated kernel FIB performs the single
/// forwarding decrement (or emits Time Exceeded), so the translator must
/// not decrement first — the same contract as
/// [`write_v6_to_v4_into_preserve_ttl`] for whole packets.
pub(crate) fn write_v6_to_v4_nonfirst_into_preserve_ttl(
    dst: &mut [u8],
    packet: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
) -> Option<usize> {
    write_v6_to_v4_nonfirst_translate(dst, packet, snat_v4, dst_v4, true)
}

/// #2562: translate a NON-first IPv4 fragment to IPv6, L3-only.
///
/// Sibling of [`write_v4_to_v6_into`] for a non-first IPv4 fragment (offset > 0,
/// no L4 header). Emits a 40-byte IPv6 header + an 8-byte Fragment Header whose
/// M flag / 13-bit offset are copied from the IPv4 fragmentation word and whose
/// **32-bit Identification is the IPv4 16-bit Identification zero-extended** (the
/// SAME extension the first fragment used), copies the payload verbatim, and
/// touches NO L4 checksum (there is no L4 header). `src_v6`/`dst_v6` come from
/// the first fragment's cached reverse association. TCP/UDP only — a fragmented
/// ICMP stays the #4617 fail-closed drop.
pub(super) fn write_v4_to_v6_nonfirst_translate(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    preserve_ttl: bool,
) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let tos = packet[1];
    let ttl = packet[8];
    if !preserve_ttl && ttl <= 1 {
        return None; // TTL expired for forwarding; slow path preserves it for the kernel
    }
    let protocol = packet[9];
    let ipv4_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ipv4_total_len < ihl || ipv4_total_len > packet.len() {
        return None;
    }
    let payload = packet.get(ihl..ipv4_total_len)?;
    let frag_word = u16::from_be_bytes([packet[6], packet[7]]);
    let more = (frag_word & 0x2000) != 0;
    let offset_units = frag_word & 0x1FFF;
    if offset_units == 0 {
        return None; // not a non-first fragment — caller must use the first path
    }
    // TCP/UDP only. ICMP fragments stay the #4617 fail-closed drop.
    let next_header = match protocol {
        PROTO_TCP | PROTO_UDP => protocol,
        _ => return None,
    };
    let v4_ident = u16::from_be_bytes([packet[4], packet[5]]);
    // #10720 (N2): checked narrowing — same choke point as the first-fragment path.
    let ipv6_payload_len = checked_ipv6_payload_len(8, payload.len())?;
    let total_len = 40usize.checked_add(usize::from(ipv6_payload_len))?;
    let out = dst.get_mut(..total_len)?;
    out[0] = 0x60 | (tos >> 4); // version=6 | TC[7:4]
    out[1] = (tos & 0x0f) << 4; // TC[3:0] | flow-label high nibble (0)
    out[2] = 0; // flow label
    out[3] = 0; // flow label
    out[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());
    out[6] = 44; // next header = Fragment
    out[7] = if preserve_ttl { ttl } else { ttl - 1 };
    out[8..24].copy_from_slice(&src_v6.octets());
    out[24..40].copy_from_slice(&dst_v6.octets());
    // 8-byte IPv6 Fragment Header (RFC 8200 §4.5).
    out[40] = next_header;
    out[41] = 0; // reserved
    let v6_frag_word = (offset_units << 3) | u16::from(more);
    out[42..44].copy_from_slice(&v6_frag_word.to_be_bytes());
    out[44..48].copy_from_slice(&u32::from(v4_ident).to_be_bytes());
    out[48..total_len].copy_from_slice(payload);
    Some(total_len)
}

/// Allocation-free entry point for the decrementing translator.
pub(crate) fn write_v4_to_v6_nonfirst_into(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<usize> {
    write_v4_to_v6_nonfirst_translate(dst, packet, src_v6, dst_v6, false)
}

/// #14114: slow-path twin of [`write_v4_to_v6_nonfirst_into`] that preserves
/// the ingress TTL for the delegated kernel FIB, mirroring
/// [`write_v4_to_v6_into_preserve_ttl`] for whole packets.
pub(crate) fn write_v4_to_v6_nonfirst_into_preserve_ttl(
    dst: &mut [u8],
    packet: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
) -> Option<usize> {
    write_v4_to_v6_nonfirst_translate(dst, packet, src_v6, dst_v6, true)
}

/// #2562: Ethernet + IPv4 frame for a NON-first IPv6 fragment (forward NAT64).
/// Mirrors [`build_nat64_v6_to_v4_frame`] but calls the L3-only non-first
/// translator (no L4 header, no `no_v6_frag_header` policy — the fragmentation
/// fields come from the packet's Fragment Header).
/// Write a non-first IPv6 fragment's translated Ethernet frame into a caller
/// buffer. `out` must hold the input frame length (the translation shrinks).
pub(crate) fn build_nat64_v6_to_v4_nonfirst_frame_into(
    out: &mut [u8],
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let eth_len: usize = if vlan_id > 0 { 18 } else { 14 };
    let out = out.get_mut(..eth_len.checked_add(ipv6_packet.len())?)?;
    write_eth_header_slice(out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written = write_v6_to_v4_nonfirst_into(&mut out[eth_len..], ipv6_packet, snat_v4, dst_v4)?;
    Some(eth_len + written)
}

#[cfg(test)]

pub(crate) fn build_nat64_v6_to_v4_nonfirst_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; eth_len + ipv6_packet.len()];
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written = write_v6_to_v4_nonfirst_into(&mut out[eth_len..], ipv6_packet, snat_v4, dst_v4)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// #2562: Ethernet + IPv6 frame for a NON-first IPv4 fragment (reverse NAT64).
/// Mirrors [`build_nat64_v4_to_v6_frame`] but calls the L3-only non-first
/// translator. The IPv4->IPv6 non-first output grows by 28 bytes (40+8 IPv6
/// header vs 20 IPv4 header); the `2 * NAT64_HEADER_DELTA` over-allocation is a
/// safe upper bound (there is no ICMP-error embedded-packet growth on a
/// TCP/UDP fragment) and the result is truncated to the exact length.
pub(crate) fn build_nat64_v4_to_v6_nonfirst_frame_into(
    out: &mut [u8], frame: &[u8], src_v6: Ipv6Addr, dst_v6: Ipv6Addr,
    eth_dst: [u8; 6], eth_src: [u8; 6], vlan_id: u16,
) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    let packet = frame.get(l3..)?;
    let eth_len: usize = if vlan_id > 0 { 18 } else { 14 };
    let l3_capacity = packet.len().checked_add(2 * NAT64_HEADER_DELTA as usize)?;
    let out = out.get_mut(..eth_len.checked_add(l3_capacity)?)?;
    write_eth_header_slice(out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_nonfirst_into(&mut out[eth_len..], packet, src_v6, dst_v6)?;
    Some(eth_len + written)
}

#[cfg(test)]

pub(crate) fn build_nat64_v4_to_v6_nonfirst_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out =
        vec![0u8; eth_len + ipv4_packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_nonfirst_into(&mut out[eth_len..], ipv4_packet, src_v6, dst_v6)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// Build a complete Ethernet + IPv4 frame from an Ethernet + IPv6 frame.
/// Used for forward NAT64 (IPv6→IPv4): frame shrinks by 20 bytes.
///
/// `eth_dst`, `eth_src` are the new L2 addresses for the forwarded frame.
/// `vlan_id` is inserted if > 0.
pub(crate) fn build_nat64_v6_to_v4_frame_into(
    out: &mut [u8], frame: &[u8], snat_v4: Ipv4Addr, dst_v4: Ipv4Addr,
    eth_dst: [u8; 6], eth_src: [u8; 6], vlan_id: u16, no_v6_frag_header: bool,
) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    let packet = frame.get(l3..)?;
    let eth_len: usize = if vlan_id > 0 { 18 } else { 14 };
    let out = out.get_mut(..eth_len.checked_add(packet.len())?)?;
    write_eth_header_slice(out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written = write_v6_to_v4_into(
        &mut out[eth_len..], packet, snat_v4, dst_v4, no_v6_frag_header,
    )?;
    Some(eth_len + written)
}

#[cfg(test)]

pub(crate) fn build_nat64_v6_to_v4_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    // Find L3 offset.
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    // Single output allocation (the unavoidable `TxRequest.bytes`): IPv6→IPv4
    // shrinks the L3 by 20 bytes, so the IPv4 frame can never exceed
    // `eth_len + ipv6_packet.len()`. Allocate that upper bound, write the
    // translated IPv4 L3 directly into the tail with the allocation-free
    // `_into` core (no intermediate L3 `Vec`, no second copy — #2211), then
    // truncate to the exact length.
    let mut out = vec![0u8; eth_len + ipv6_packet.len()];
    // #2844: use the SSOT in-place Ethernet writer shared with gre.rs,
    // icmp.rs, and the TX segmentation path instead of a private copy,
    // so VLAN/TPID/PCP/ethertype changes propagate to NAT64 too.
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written =
        write_v6_to_v4_into(&mut out[eth_len..], ipv6_packet, snat_v4, dst_v4, no_v6_frag_header)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// Build a complete Ethernet + IPv6 frame from an Ethernet + IPv4 frame.
/// Used for reverse NAT64 (IPv4→IPv6): frame grows by 20 bytes.
///
/// `src_v6` and `dst_v6` are the restored IPv6 addresses.
pub(crate) fn build_nat64_v4_to_v6_frame_into(
    out: &mut [u8], frame: &[u8], src_v6: Ipv6Addr, dst_v6: Ipv6Addr,
    eth_dst: [u8; 6], eth_src: [u8; 6], vlan_id: u16,
) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    let packet = frame.get(l3..)?;
    let eth_len: usize = if vlan_id > 0 { 18 } else { 14 };
    let capacity = packet.len().checked_add(2 * NAT64_HEADER_DELTA as usize)?;
    let out = out.get_mut(..eth_len.checked_add(capacity)?)?;
    write_eth_header_slice(out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_into(&mut out[eth_len..], packet, src_v6, dst_v6)?;
    Some(eth_len + written)
}

#[cfg(test)]

pub(crate) fn build_nat64_v4_to_v6_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    // Single output allocation (the unavoidable `TxRequest.bytes`): IPv4→IPv6
    // grows the outer L3 header by 20 bytes (40-byte IPv6 header vs 20-byte IPv4
    // header). An ICMP-error message ALSO grows its embedded quoted packet by
    // another 20 bytes (#2219), so the worst-case IPv6 frame is
    // `eth_len + ipv4_packet.len() + 40`. Allocate that upper bound, write the
    // translated IPv6 L3 directly into the tail with the allocation-free `_into`
    // core (no intermediate L3 `Vec`, no second copy — #2211), then truncate to
    // the exact length.
    let mut out = vec![0u8; eth_len + ipv4_packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    // #2844: SSOT Ethernet writer (see build_nat64_v6_to_v4_frame).
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_into(&mut out[eth_len..], ipv4_packet, src_v6, dst_v6)?;
    out.truncate(eth_len + written);
    Some(out)
}

/// #6472: Ethernet + IPv4 frame for a flowless NAT64 ICMPv6 error (an error
/// about the session's translated REPLY packet, v6→v4). Mirrors
/// [`build_nat64_v6_to_v4_frame`] but drives
/// [`write_v6_to_v4_icmp_error_into`] so the embedded quote's L4 destination
/// port / echo id is restored to the session's translated (pool) value —
/// the tuple the v4 server associates the error with.
pub(crate) fn build_nat64_v6_to_v4_icmp_error_frame_into(
    out: &mut [u8], frame: &[u8], snat_v4: Ipv4Addr, dst_v4: Ipv4Addr,
    embedded_dst_port: Option<u16>, eth_dst: [u8; 6], eth_src: [u8; 6],
    vlan_id: u16, no_v6_frag_header: bool,
) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    let packet = frame.get(l3..)?;
    let eth_len: usize = if vlan_id > 0 { 18 } else { 14 };
    let out = out.get_mut(..eth_len.checked_add(packet.len())?)?;
    write_eth_header_slice(out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written = write_v6_to_v4_icmp_error_into(
        &mut out[eth_len..], packet, snat_v4, dst_v4, no_v6_frag_header, embedded_dst_port,
    )?;
    Some(eth_len + written)
}

#[cfg(test)]

pub(crate) fn build_nat64_v6_to_v4_icmp_error_frame(
    frame: &[u8],
    snat_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    embedded_dst_port: Option<u16>,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
    no_v6_frag_header: bool,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv6_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    // IPv6→IPv4 shrinks the L3 by 20 bytes, so `eth_len + ipv6_packet.len()`
    // is a safe upper bound even with the embedded-packet shrink.
    let mut out = vec![0u8; eth_len + ipv6_packet.len()];
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x0800)?;
    let written = write_v6_to_v4_icmp_error_into(
        &mut out[eth_len..],
        ipv6_packet,
        snat_v4,
        dst_v4,
        no_v6_frag_header,
        embedded_dst_port,
    )?;
    out.truncate(eth_len + written);
    Some(out)
}

/// #6472: Ethernet + IPv6 frame for a flowless NAT64 ICMPv4 error (an error
/// about the session's FORWARD wire packet, v4→v6). Mirrors
/// [`build_nat64_v4_to_v6_frame`] but drives
/// [`write_v4_to_v6_icmp_error_into`] so the embedded quote's L4 source
/// port / echo id is restored to the ORIGINAL v6 client value — the tuple
/// the client associates the error with.
pub(crate) fn build_nat64_v4_to_v6_icmp_error_frame_into(
    out: &mut [u8], frame: &[u8], src_v6: Ipv6Addr, dst_v6: Ipv6Addr,
    embedded_src_port: Option<u16>, eth_dst: [u8; 6], eth_src: [u8; 6], vlan_id: u16,
) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    let packet = frame.get(l3..)?;
    let eth_len: usize = if vlan_id > 0 { 18 } else { 14 };
    let capacity = packet.len().checked_add(2 * NAT64_HEADER_DELTA as usize)?;
    let out = out.get_mut(..eth_len.checked_add(capacity)?)?;
    write_eth_header_slice(out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_icmp_error_into(
        &mut out[eth_len..], packet, src_v6, dst_v6, embedded_src_port,
    )?;
    Some(eth_len + written)
}

#[cfg(test)]

pub(crate) fn build_nat64_v4_to_v6_icmp_error_frame(
    frame: &[u8],
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    embedded_src_port: Option<u16>,
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    vlan_id: u16,
) -> Option<Vec<u8>> {
    let l3 = frame_l3_offset(frame)?;
    let ipv4_packet = frame.get(l3..)?;
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; eth_len + ipv4_packet.len().saturating_add(2 * NAT64_HEADER_DELTA as usize)];
    write_eth_header_slice(&mut out, eth_dst, eth_src, vlan_id, 0x86dd)?;
    let written = write_v4_to_v6_icmp_error_into(
        &mut out[eth_len..],
        ipv4_packet,
        src_v6,
        dst_v6,
        embedded_src_port,
    )?;
    out.truncate(eth_len + written);
    Some(out)
}

/// Find the L3 offset by checking Ethernet type/VLAN.
///
/// #2150: a single 0x88a8 (802.1ad) tag carries the same 4-byte
/// TPID+TCI layout as 0x8100, so the L3 header sits at offset 18, not
/// 14. The previous `== 0x8100` check treated a 0x88a8-tagged frame as
/// untagged (l3=14) and read the IP header 4 bytes into the VLAN tag,
/// corrupting any NAT64 translation of a provider-tagged frame. This
/// now matches the canonical L2 contract
/// (`afxdp/frame/inspect.rs::frame_l3_offset`,
/// `afxdp/cos/ecn.rs::ethernet_l3`, `afxdp/parser.rs::parse_eth_offsets`).
pub(super) fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(ethertype, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return None;
        }
        Some(18)
    } else {
        Some(14)
    }
}

// #2844: NAT64's private `write_eth_header` (hardcoded 0x8100 TPID,
// bare-VID semantics) was deleted. The frame builders above now call
// the shared SSOT `crate::afxdp::write_eth_header_slice`, the same
// in-place writer used by gre.rs, icmp.rs, and the TX segmentation
// path. The SSOT writer's `From<u16>` VLAN semantics (tag present iff
// `vlan_id > 0`, TPID 0x8100, PCP/DEI 0) reproduce the deleted copy's
// behavior byte-for-byte, so output is identical for every NAT64
// frame the dataplane currently emits — while a future TPID/PCP/DEI/
// 802.1ad/ethertype change in the shared module now reaches NAT64.
