use super::parse::parse_embedded_v6_l4;
use super::*;

/// Rewrite an IPv4 ICMP error packet so it appears to originate from
/// (and be addressed to) the original pre-NAT client. Mirrors
/// `icmp_embed.rs:531-643` literally.
pub(in crate::afxdp::icmp_embed) fn build_nat_reversed_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    if l3 >= frame.len() || l4 >= frame.len() || l3 >= l4 {
        return None;
    }
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ttl = packet[8];
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) == 0 && ttl <= 1 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }

    let original_client = match icmp_match.original_src {
        IpAddr::V4(v4) => v4,
        _ => return None,
    };
    // #3112: pre-DNAT public destination. Only rewritten when the flow
    // actually had destination NAT (DNAT/static); otherwise the writes
    // below are gated off and the output stays byte-identical.
    let original_dst = match icmp_match.original_dst {
        IpAddr::V4(v4) => v4,
        _ => return None,
    };
    let had_dst_nat = icmp_match.nat.rewrite_dst.is_some();

    #[cfg(feature = "debug-log")]
    let _eth_len = l3;
    let dst_mac = icmp_match.resolution.neighbor_mac?;
    let src_mac = icmp_match.resolution.src_mac?;
    let vlan_id = icmp_match.resolution.tx_vlan_id;

    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let payload = if ip_total_len > 0 && ip_total_len < packet.len() {
        &packet[..ip_total_len]
    } else {
        packet
    };

    let out_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; out_eth_len + payload.len()];
    write_eth_header_slice(
        out.get_mut(..out_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        0x0800,
    )?;
    out.get_mut(out_eth_len..)?.copy_from_slice(payload);

    let pkt = &mut out[out_eth_len..];
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) == 0 {
        pkt[8] = ttl - 1;
    }

    pkt.get_mut(16..20)?
        .copy_from_slice(&original_client.octets());

    // #3112: when destination NAT was applied, rewrite the outer SOURCE
    // so the error appears to originate from the public address the
    // client sent to (mirrors the unconditional outer-dst rewrite above,
    // but gated on dst-NAT to leave transit/intermediate-router errors
    // and SNAT-only flows untouched).
    if had_dst_nat {
        pkt.get_mut(12..16)?.copy_from_slice(&original_dst.octets());
    }

    let icmp_offset = ihl;
    let emb_ip_offset = icmp_offset + 8;
    if pkt.len() < emb_ip_offset + 20 {
        return None;
    }
    let emb_ihl = ((pkt[emb_ip_offset] & 0x0f) as usize) * 4;
    if emb_ihl < 20 || pkt.len() < emb_ip_offset + emb_ihl {
        return None;
    }

    pkt.get_mut(emb_ip_offset + 12..emb_ip_offset + 16)?
        .copy_from_slice(&original_client.octets());

    // #3112: un-DNAT the embedded (quoted) destination so the client's
    // stack can match the error to the session it opened to the public
    // dst. Done before the embedded IP-header checksum recompute below.
    if had_dst_nat {
        pkt.get_mut(emb_ip_offset + 16..emb_ip_offset + 20)?
            .copy_from_slice(&original_dst.octets());
    }

    {
        pkt.get_mut(emb_ip_offset + 10..emb_ip_offset + 12)?
            .copy_from_slice(&[0, 0]);
        let emb_ip_header = pkt.get(emb_ip_offset..emb_ip_offset + emb_ihl)?;
        let csum = checksum16(emb_ip_header);
        pkt.get_mut(emb_ip_offset + 10..emb_ip_offset + 12)?
            .copy_from_slice(&csum.to_be_bytes());
    }

    let emb_l4_offset = emb_ip_offset + emb_ihl;
    // #1852: skip the embedded L4 port/ident restore when the QUOTED v4
    // packet is a non-first fragment — `emb_l4_offset` then points at
    // payload, not an L4 header. The embedded IP-address rewrite above
    // (emb_ip_offset+12) is correct for every fragment and stays. This
    // reads the embedded IPv4 fragment-offset field directly because the
    // builder derives `emb_l4_offset` itself rather than via
    // `parse_embedded_v4` (so it does not inherit that guard).
    let emb_frag_off =
        u16::from_be_bytes([pkt[emb_ip_offset + 6], pkt[emb_ip_offset + 7]]);
    let emb_non_first_fragment = (emb_frag_off & 0x1FFF) != 0;
    if !emb_non_first_fragment
        && (icmp_match.nat.rewrite_src_port.is_some() || icmp_match.nat.rewrite_src.is_some())
    {
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 2 {
            pkt.get_mut(emb_l4_offset..emb_l4_offset + 2)?
                .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
        } else if emb_proto == PROTO_ICMP && pkt.len() >= emb_l4_offset + 6 {
            let old_id_bytes = pkt.get(emb_l4_offset + 4..emb_l4_offset + 6)?;
            let old_id = u16::from_be_bytes([old_id_bytes[0], old_id_bytes[1]]);
            if old_id != icmp_match.original_src_port {
                pkt.get_mut(emb_l4_offset + 4..emb_l4_offset + 6)?
                    .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
                if pkt.len() >= emb_l4_offset + 4 {
                    let old_csum =
                        u16::from_be_bytes([pkt[emb_l4_offset + 2], pkt[emb_l4_offset + 3]]);
                    let new_csum =
                        checksum16_adjust(old_csum, &[old_id], &[icmp_match.original_src_port]);
                    pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                        .copy_from_slice(&new_csum.to_be_bytes());
                }
            }
        }
    }

    // #3112: un-DNAT the embedded transport DESTINATION port (TCP/UDP).
    // Same fragment gate as the source restore above. The embedded L4
    // checksum is intentionally NOT adjusted here — exactly as the
    // source-port restore omits it: the quoted L4 header is truncated and
    // unverifiable, and only the outer ICMP checksum (recomputed below
    // over the whole payload) covers these bytes. ICMP echo (no dst port)
    // is excluded — its dst_port is 0 and original_dst_port a no-op.
    if !emb_non_first_fragment
        && (icmp_match.nat.rewrite_dst_port.is_some() || icmp_match.nat.rewrite_dst.is_some())
    {
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 4 {
            pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                .copy_from_slice(&icmp_match.original_dst_port.to_be_bytes());
        }
    }

    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let icmp_data = pkt.get(icmp_offset..)?;
    let icmp_csum = checksum16(icmp_data);
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp_csum.to_be_bytes());

    pkt.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let ip_header = pkt.get(..ihl)?;
    let ip_csum = checksum16(ip_header);
    pkt.get_mut(10..12)?.copy_from_slice(&ip_csum.to_be_bytes());

    Some(out)
}

/// Rewrite an IPv6 ICMPv6 error packet so it appears to originate
/// from (and be addressed to) the original pre-NAT client. Mirrors
/// `icmp_embed.rs:645-734` literally.
pub(in crate::afxdp::icmp_embed) fn build_nat_reversed_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    if l3 >= frame.len() || l4 >= frame.len() || l3 >= l4 {
        return None;
    }
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }
    let hop_limit = packet[7];
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) == 0 && hop_limit <= 1 {
        return None;
    }

    let original_client_bytes = match icmp_match.original_src {
        IpAddr::V6(v6) => v6.octets(),
        _ => return None,
    };
    // #3112: pre-DNAT public destination (DNAT66/static). Only applied
    // when the flow had destination NAT; otherwise gated off so the
    // output is byte-identical to the SNAT-only / no-NAT path.
    let original_dst_bytes = match icmp_match.original_dst {
        IpAddr::V6(v6) => v6.octets(),
        _ => return None,
    };
    let had_dst_nat = icmp_match.nat.rewrite_dst.is_some();

    let dst_mac = icmp_match.resolution.neighbor_mac?;
    let src_mac = icmp_match.resolution.src_mac?;
    let vlan_id = icmp_match.resolution.tx_vlan_id;

    let ipv6_payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ip6_total = 40 + ipv6_payload_len;
    let payload = if ip6_total > 0 && ip6_total < packet.len() {
        &packet[..ip6_total]
    } else {
        packet
    };

    let out_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; out_eth_len + payload.len()];
    write_eth_header_slice(
        out.get_mut(..out_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        0x86dd,
    )?;
    out.get_mut(out_eth_len..)?.copy_from_slice(payload);

    let pkt = &mut out[out_eth_len..];
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) == 0 {
        pkt[7] = hop_limit - 1;
    }

    pkt.get_mut(24..40)?.copy_from_slice(&original_client_bytes);

    // #3112: rewrite the outer SOURCE to the public dst on dst-NAT flows
    // so the error appears to come from the address the client used. The
    // ICMPv6 checksum recompute below reads the (rewritten) outer src/dst
    // for its pseudo-header, so the order is correct.
    if had_dst_nat {
        pkt.get_mut(8..24)?.copy_from_slice(&original_dst_bytes);
    }

    // Outer ICMPv6 offset: ext-aware via the shared #1838 helper (the
    // outer NAT match in icmp_embed/mod.rs reads the ICMP type at
    // meta.l4_offset, so an outer-ext error MATCHES — a fixed 40 here
    // then corrupted it by writing the embedded un-NAT and the
    // checksum recompute inside the outer extension chain).
    let icmp_offset = v6_rel_l4_offset(pkt, meta.l3_offset, meta.l4_offset, meta.addr_family)?;
    let emb_ip_offset = icmp_offset.checked_add(8)?;
    if pkt.len() < emb_ip_offset + 40 {
        return None;
    }
    pkt.get_mut(emb_ip_offset + 8..emb_ip_offset + 24)?
        .copy_from_slice(&original_client_bytes);

    // #3112: un-DNAT the embedded (quoted) destination so the client can
    // match the error to its session. v6 has no IP-header checksum, so no
    // recompute is needed for this rewrite (the outer ICMPv6 checksum
    // below covers the whole quoted payload).
    if had_dst_nat {
        pkt.get_mut(emb_ip_offset + 24..emb_ip_offset + 40)?
            .copy_from_slice(&original_dst_bytes);
    }

    // Embedded L4 offset: fragment-aware walk over the quoted packet
    // (plan §5.7). None — e.g. a quoted non-first fragment, which has
    // no L4 header — skips the embedded port/ident restore exactly
    // like today's non-matching protocols do.
    let emb_l4 = parse_embedded_v6_l4(pkt.get(emb_ip_offset..)?);
    if (icmp_match.nat.rewrite_src_port.is_some() || icmp_match.nat.rewrite_src.is_some())
        && let Some((emb_rel_l4, _)) = emb_l4
    {
        let emb_l4_offset = emb_ip_offset.checked_add(emb_rel_l4)?;
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 2 {
            pkt.get_mut(emb_l4_offset..emb_l4_offset + 2)?
                .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
        } else if emb_proto == PROTO_ICMPV6 && pkt.len() >= emb_l4_offset + 6 {
            let old_id_bytes = pkt.get(emb_l4_offset + 4..emb_l4_offset + 6)?;
            let old_id = u16::from_be_bytes([old_id_bytes[0], old_id_bytes[1]]);
            if old_id != icmp_match.original_src_port {
                pkt.get_mut(emb_l4_offset + 4..emb_l4_offset + 6)?
                    .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
                if pkt.len() >= emb_l4_offset + 4 {
                    let old_csum =
                        u16::from_be_bytes([pkt[emb_l4_offset + 2], pkt[emb_l4_offset + 3]]);
                    let new_csum =
                        checksum16_adjust(old_csum, &[old_id], &[icmp_match.original_src_port]);
                    pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                        .copy_from_slice(&new_csum.to_be_bytes());
                }
            }
        }
    }

    // #3112: un-DNAT the embedded transport DESTINATION port (TCP/UDP),
    // mirroring the source-port restore above. Same fragment-aware gate
    // (skip when the quoted packet has no L4 header). The embedded L4
    // checksum is left as-is — the outer ICMPv6 checksum recompute below
    // covers the quoted bytes. ICMPv6 echo carries no dst port.
    if (icmp_match.nat.rewrite_dst_port.is_some() || icmp_match.nat.rewrite_dst.is_some())
        && let Some((emb_rel_l4, _)) = emb_l4
    {
        let emb_l4_offset = emb_ip_offset.checked_add(emb_rel_l4)?;
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 4 {
            pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                .copy_from_slice(&icmp_match.original_dst_port.to_be_bytes());
        }
    }

    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let src_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(8..24)?).ok()?);
    let dst_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(24..40)?).ok()?);
    let icmp6_data = pkt.get(icmp_offset..)?;
    // With an ext-aware icmp_offset the recompute coverage (upper-layer
    // length = len - icmp_offset, Next Header = ICMPv6) is correct per
    // RFC 8200 §8.1. Canonicalize a computed 0x0000 to 0xFFFF — the v6
    // ICMPv6 rule the incremental adjusters and
    // recompute_l4_checksum_ipv6 follow (plan §5.7 / Codex r2).
    let icmp6_csum = checksum16_ipv6(src_v6, dst_v6, PROTO_ICMPV6, icmp6_data);
    let icmp6_csum = if icmp6_csum == 0 { 0xffff } else { icmp6_csum };
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp6_csum.to_be_bytes());

    Some(out)
}

/// #6474: rewrite an OUTBOUND IPv4 ICMP error through source NAT so the
/// wire carries the session's EXTERNAL identity (RFC 5508 §4). The
/// internal host emitted the error about the session's reply, so the
/// frame arrives with the PRE-NAT source and a quote the remote cannot
/// associate. Rewrites (everything else preserved):
///   * outer source → the SNAT address (`nat.rewrite_src`), outer IPv4
///     header checksum recomputed;
///   * embedded (quoted) destination address → the SNAT address, embedded
///     IPv4 header checksum recomputed;
///   * embedded L4 destination port / echo identifier → the translated
///     value (`nat.rewrite_src_port`), the tuple the remote replied to;
///   * outer ICMP checksum recomputed over the whole message.
/// The quoted L4 checksum is left unchanged (informational — a receiver
/// does not validate it). For TCP/UDP quotes this mirrors the #5690
/// reversed builders' policy exactly; an ICMP-echo quote through an
/// echo-id-translating SNAT is the one nuance — the rewritten echo id is
/// covered by the quoted echo's ORIGINAL checksum (the #5690 builders
/// adjust that layer with `checksum16_adjust`; this builder deliberately
/// does not, matching the no-mainstream-stack-validates-quoted-checksums
/// posture; the outer ICMP checksum receivers DO validate IS recomputed).
/// The outer destination and the quote's source are untouched — the
/// error is addressed to the remote server, which is exactly who must
/// associate it.
pub(in crate::afxdp::icmp_embed) fn build_snat_outbound_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    if l3 >= frame.len() || l4 >= frame.len() || l3 >= l4 {
        return None;
    }
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ttl = packet[8];
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) == 0 && ttl <= 1 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }
    let snat_ip = match icmp_match.nat.rewrite_src {
        Some(IpAddr::V4(v4)) => v4,
        _ => return None,
    };
    let dst_mac = icmp_match.resolution.neighbor_mac?;
    let src_mac = icmp_match.resolution.src_mac?;
    let vlan_id = icmp_match.resolution.tx_vlan_id;

    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let payload = if ip_total_len > 0 && ip_total_len < packet.len() {
        &packet[..ip_total_len]
    } else {
        packet
    };

    let out_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; out_eth_len + payload.len()];
    write_eth_header_slice(
        out.get_mut(..out_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        0x0800,
    )?;
    out.get_mut(out_eth_len..)?.copy_from_slice(payload);

    let pkt = &mut out[out_eth_len..];
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) == 0 {
        pkt[8] = ttl - 1;
    }

    // Outer source → the SNAT (external) address.
    pkt.get_mut(12..16)?.copy_from_slice(&snat_ip.octets());

    let icmp_offset = ihl;
    let emb_ip_offset = icmp_offset + 8;
    if pkt.len() < emb_ip_offset + 20 {
        return None;
    }
    let emb_ihl = ((pkt[emb_ip_offset] & 0x0f) as usize) * 4;
    if emb_ihl < 20 || pkt.len() < emb_ip_offset + emb_ihl {
        return None;
    }

    // Embedded destination → the SNAT address (the quote's destination is
    // the pre-NAT internal host; the remote only knows the pool identity).
    pkt.get_mut(emb_ip_offset + 16..emb_ip_offset + 20)?
        .copy_from_slice(&snat_ip.octets());

    {
        pkt.get_mut(emb_ip_offset + 10..emb_ip_offset + 12)?
            .copy_from_slice(&[0, 0]);
        let emb_ip_header = pkt.get(emb_ip_offset..emb_ip_offset + emb_ihl)?;
        let csum = checksum16(emb_ip_header);
        pkt.get_mut(emb_ip_offset + 10..emb_ip_offset + 12)?
            .copy_from_slice(&csum.to_be_bytes());
    }

    // Embedded L4 destination port / echo identifier → the translated
    // value. Same non-first-fragment guard as the #5690 builder (#1852):
    // a quoted non-first fragment has no L4 header to rewrite.
    let emb_l4_offset = emb_ip_offset + emb_ihl;
    let emb_frag_off =
        u16::from_be_bytes([pkt[emb_ip_offset + 6], pkt[emb_ip_offset + 7]]);
    let emb_non_first_fragment = (emb_frag_off & 0x1FFF) != 0;
    if !emb_non_first_fragment && icmp_match.nat.rewrite_src_port.is_some() {
        let xlated = icmp_match.nat.rewrite_src_port?;
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 4 {
            pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                .copy_from_slice(&xlated.to_be_bytes());
        } else if emb_proto == PROTO_ICMP && pkt.len() >= emb_l4_offset + 6 {
            pkt.get_mut(emb_l4_offset + 4..emb_l4_offset + 6)?
                .copy_from_slice(&xlated.to_be_bytes());
        }
    }

    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let icmp_data = pkt.get(icmp_offset..)?;
    let icmp_csum = checksum16(icmp_data);
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp_csum.to_be_bytes());

    pkt.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let ip_header = pkt.get(..ihl)?;
    let ip_csum = checksum16(ip_header);
    pkt.get_mut(10..12)?.copy_from_slice(&ip_csum.to_be_bytes());

    Some(out)
}

/// #6474: IPv6 twin of [`build_snat_outbound_icmp_error_v4`] — an OUTBOUND
/// ICMPv6 error through SNAT66/NPTv6 leaves with the session's external
/// identity: outer source → the translated source, embedded destination →
/// the translated source, embedded L4 destination port / echo identifier →
/// `nat.rewrite_src_port`, outer ICMPv6 checksum recomputed with the
/// pseudo-header (canonicalizing a computed 0x0000 to 0xFFFF, same as the
/// #5690 v6 builder).
pub(in crate::afxdp::icmp_embed) fn build_snat_outbound_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    if l3 >= frame.len() || l4 >= frame.len() || l3 >= l4 {
        return None;
    }
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }
    let hop_limit = packet[7];
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) == 0 && hop_limit <= 1 {
        return None;
    }
    let snat_bytes = match icmp_match.nat.rewrite_src {
        Some(IpAddr::V6(v6)) => v6.octets(),
        _ => return None,
    };
    let dst_mac = icmp_match.resolution.neighbor_mac?;
    let src_mac = icmp_match.resolution.src_mac?;
    let vlan_id = icmp_match.resolution.tx_vlan_id;

    let ipv6_payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ip6_total = 40 + ipv6_payload_len;
    let payload = if ip6_total > 0 && ip6_total < packet.len() {
        &packet[..ip6_total]
    } else {
        packet
    };

    let out_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; out_eth_len + payload.len()];
    write_eth_header_slice(
        out.get_mut(..out_eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        0x86dd,
    )?;
    out.get_mut(out_eth_len..)?.copy_from_slice(payload);

    let pkt = &mut out[out_eth_len..];
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) == 0 {
        pkt[7] = hop_limit - 1;
    }

    // Outer source → the translated (external) source.
    pkt.get_mut(8..24)?.copy_from_slice(&snat_bytes);

    // Outer ICMPv6 offset: ext-aware via the shared #1838 helper (same
    // reasoning as the #5690 v6 builder).
    let icmp_offset = v6_rel_l4_offset(pkt, meta.l3_offset, meta.l4_offset, meta.addr_family)?;
    let emb_ip_offset = icmp_offset.checked_add(8)?;
    if pkt.len() < emb_ip_offset + 40 {
        return None;
    }

    // Embedded destination → the translated source.
    pkt.get_mut(emb_ip_offset + 24..emb_ip_offset + 40)?
        .copy_from_slice(&snat_bytes);

    // Embedded L4 destination port / echo identifier → the translated
    // value; fragment-aware via the shared walker (a quoted non-first
    // fragment has no L4 header).
    let emb_l4 = parse_embedded_v6_l4(pkt.get(emb_ip_offset..)?);
    if icmp_match.nat.rewrite_src_port.is_some()
        && let Some((emb_rel_l4, _)) = emb_l4
    {
        let xlated = icmp_match.nat.rewrite_src_port?;
        let emb_l4_offset = emb_ip_offset.checked_add(emb_rel_l4)?;
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 4 {
            pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                .copy_from_slice(&xlated.to_be_bytes());
        } else if emb_proto == PROTO_ICMPV6 && pkt.len() >= emb_l4_offset + 6 {
            pkt.get_mut(emb_l4_offset + 4..emb_l4_offset + 6)?
                .copy_from_slice(&xlated.to_be_bytes());
        }
    }

    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let src_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(8..24)?).ok()?);
    let dst_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(24..40)?).ok()?);
    let icmp6_data = pkt.get(icmp_offset..)?;
    let icmp6_csum = checksum16_ipv6(src_v6, dst_v6, PROTO_ICMPV6, icmp6_data);
    let icmp6_csum = if icmp6_csum == 0 { 0xffff } else { icmp6_csum };
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp6_csum.to_be_bytes());

    Some(out)
}

/// Finalize the forwarding resolution attached to an embedded ICMP
/// match — enforce HA disposition, then re-redirect via fabric if the
/// local resolution turned into HAInactive/NoRoute/DiscardRoute.
/// Mirrors `icmp_embed.rs:736-761` literally.
pub(in crate::afxdp::icmp_embed) fn finalize_embedded_icmp_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    icmp_match: &EmbeddedIcmpMatch,
) -> ForwardingResolution {
    finalize_embedded_icmp_resolution_parts(
        forwarding,
        ha_state,
        now_secs,
        ingress_ifindex,
        icmp_match.resolution,
        icmp_match.metadata.ingress_zone,
    )
}

/// #6472: the (resolution, ingress-zone) core of
/// [`finalize_embedded_icmp_resolution`], shared with the NAT64 flowless
/// ICMP-error arm whose match carries the two fields directly instead of
/// an [`EmbeddedIcmpMatch`]. Identical semantics: HA-enforce the cached
/// resolution, then re-redirect via fabric when the local outcome is
/// HAInactive/NoRoute/DiscardRoute (non-fabric ingress only).
pub(in crate::afxdp::icmp_embed) fn finalize_embedded_icmp_resolution_parts(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    resolution: ForwardingResolution,
    ingress_zone: u16,
) -> ForwardingResolution {
    let enforced = enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution);
    if !ingress_is_fabric(forwarding, ingress_ifindex)
        && matches!(
            enforced.disposition,
            ForwardingDisposition::HAInactive
                | ForwardingDisposition::NoRoute
                | ForwardingDisposition::DiscardRoute
        )
    {
        if let Some(redirect) =
            resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone)
        {
            return redirect;
        }
    }
    redirect_via_fabric_if_needed(forwarding, enforced, ingress_ifindex)
}
