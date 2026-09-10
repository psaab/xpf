use super::*;
use crate::afxdp::gre_discriminator::{gre_transit_discriminator, pptp_call_id};
use crate::session::TunnelDiscriminator;

/// Parsed embedded inner IPv4 header + first 8 bytes of L4 (enough to
/// recover ports / icmp echo id). IP address octets are recovered
/// directly from the frame; L4 port fields are decoded from
/// big-endian wire bytes into host-order `u16` for convenient
/// comparison and key construction.
pub(in crate::afxdp::icmp_embed) struct EmbeddedV4Header {
    pub proto: u8,
    /// #9031: the QUOTED packet's GRE discriminator.
    ///
    /// `SessionKey` derives Hash/Eq INCLUDING the discriminator (#7188), and a
    /// live accelerated GRE session carries `Unkeyed`/`Keyed(k)`/`Pptp(handle)`.
    /// Every embedded lookup key used to hard-code `Default::default()` —
    /// `None` — so every exact index probe for a GRE quote missed, and an ICMP
    /// error for a translated accelerated tunnel found no NAT state: the outer
    /// destination and quoted source could not be restored and no usable signal
    /// reached the endpoint. GRE carries bulk payload, so small probes stay
    /// healthy while large traffic stalls after an MTU reduction.
    ///
    /// `None` for every non-GRE protocol, which is exactly what those sessions
    /// carry — so this field leaves every other protocol's identity unchanged.
    pub discriminator: TunnelDiscriminator,
    /// #9298: the QUOTED PPTP Call ID, when the quote is a version-1 (PPTP
    /// enhanced) GRE header.
    ///
    /// Extraction only -- this stays a PURE byte read, which is why it is a
    /// call id and not a discriminator. `TunnelDiscriminator::Pptp` carries a
    /// LOCALLY DERIVED handle, not the wire value: RFC 2637 s4.1 has each side
    /// allocate its own Call ID naming the peer it sends to, so the two
    /// directions of one call carry DIFFERENT wire values and a discriminator
    /// built from the wire would never match its reverse companion. Turning
    /// this id into a handle needs the per-worker association table, which the
    /// parser deliberately does not take; `session_match` does that, where
    /// `sessions` is already in scope.
    ///
    /// `None` for every non-GRE protocol and for a version-0 GRE quote, whose
    /// identity `discriminator` above already carries.
    pub pptp_call_id: Option<u16>,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub l4_off: usize,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Parsed embedded inner IPv6 header + first 8 bytes of L4.
///
/// `src_wire` is the on-the-wire (untranslated) source address —
/// NPTv6 inbound translation, if any, MUST be applied at the call
/// site (see `nat_match_v6.rs`, mirroring `icmp_embed.rs:358-360`).
/// The parser does not translate. L4 port fields are decoded from
/// big-endian wire bytes into host-order `u16` like
/// `EmbeddedV4Header`.
pub(in crate::afxdp::icmp_embed) struct EmbeddedV6Header {
    pub proto: u8,
    /// #9031: see EmbeddedV4Header::discriminator.
    pub discriminator: TunnelDiscriminator,
    /// #9298: see EmbeddedV4Header::pptp_call_id.
    pub pptp_call_id: Option<u16>,
    pub src_wire: Ipv6Addr,
    pub dst: IpAddr,
    pub l4_off: usize,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Parse the embedded IPv4 header starting at `embedded_ip_start`.
/// Returns None on truncated frame, malformed IHL, or when the QUOTED
/// packet is a non-first fragment.
///
/// #1852: a quoted non-first fragment (IPv4 fragment-offset field, low
/// 13 bits of bytes 6-7, non-zero) has no L4 header — reading "ports" at
/// `ihl` would interpret payload bytes as ports and could enable a false
/// embedded-session match. This is the IPv4 twin of the #1853
/// fragment-aware `parse_embedded_v6_l4` guard (it was deferred to this
/// follow-up). First/atomic fragments (offset 0) carry the real L4
/// header and parse normally.
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v4(
    frame: &[u8],
    embedded_ip_start: usize,
) -> Option<EmbeddedV4Header> {
    if frame.len() < embedded_ip_start + 28 {
        return None;
    }
    let ihl = ((frame[embedded_ip_start] & 0x0F) as usize) * 4;
    if ihl < 20 || frame.len() < embedded_ip_start + ihl + 4 {
        return None;
    }
    // #1852: refuse a quoted non-first fragment (no L4 header to read).
    let frag_off =
        u16::from_be_bytes([frame[embedded_ip_start + 6], frame[embedded_ip_start + 7]]);
    if (frag_off & 0x1FFF) != 0 {
        return None;
    }
    let proto = frame[embedded_ip_start + 9];
    let src = Ipv4Addr::new(
        frame[embedded_ip_start + 12],
        frame[embedded_ip_start + 13],
        frame[embedded_ip_start + 14],
        frame[embedded_ip_start + 15],
    );
    let dst = Ipv4Addr::new(
        frame[embedded_ip_start + 16],
        frame[embedded_ip_start + 17],
        frame[embedded_ip_start + 18],
        frame[embedded_ip_start + 19],
    );
    let l4_off = embedded_ip_start + ihl;
    // #5568: bound the quoted-inner L4 read by the QUOTED IPv4 datagram's
    // declared total-length, not merely the outer backing frame. An ICMP error
    // whose outer frame carries slack/padding beyond the quoted datagram's
    // declared length would otherwise have those bytes read as inner ports — a
    // manufactured embedded-session tuple that could touch an existing session.
    // The quoted datagram ends at `embedded_ip_start + total_len`; the port read
    // must lie within it. A quote whose declared length legitimately EXCEEDS the
    // available bytes (an RFC-792 minimum, intentionally truncated quote) is NOT
    // rejected: `total_len` is large, so the window check passes and `frame.get`
    // then bounds the read to what is actually present.
    let inner_total =
        u16::from_be_bytes([frame[embedded_ip_start + 2], frame[embedded_ip_start + 3]]) as usize;
    let inner_declared_end = embedded_ip_start.saturating_add(inner_total);
    let (src_port, dst_port) = if matches!(proto, PROTO_TCP | PROTO_UDP) {
        if l4_off.saturating_add(4) > inner_declared_end {
            return None;
        }
        let bytes = frame.get(l4_off..l4_off + 4)?;
        (
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        )
    } else if matches!(proto, PROTO_ICMP) {
        if l4_off.saturating_add(6) > inner_declared_end {
            return None;
        }
        let bytes = frame.get(l4_off + 4..l4_off + 6)?;
        (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
    } else {
        (0, 0)
    };
    // #9031: the QUOTED GRE discriminator. `gre_transit_discriminator` is the
    // SAME extractor the transit path uses, reused rather than re-spelled — a
    // second parser for one wire format is where two readings of the same bytes
    // silently diverge, which is exactly the class #8103 was still cleaning up.
    //
    // Bounded by `inner_declared_end`, the QUOTED datagram's declared end, not
    // by the backing frame: the #2361 rule the extractor already enforces for
    // transit, applied to the quote. Outer L2 pad or attacker-supplied slack
    // beyond the quoted datagram must not be read as a Key.
    //
    // FAIL-CLOSED BY CONSTRUCTION: every failure path in the extractor returns
    // `Unparseable`, which is a DISTINCT class from `Unkeyed` (#7188 decision
    // 6) and equal to no live session's discriminator — so a truncated or
    // malformed quote MISSES rather than wildcarding across tunnels. That is
    // the acceptance's requirement, and it is met by the type rather than by a
    // check anyone could forget.
    let discriminator = if proto == PROTO_GRE {
        gre_transit_discriminator(frame, l4_off, inner_declared_end)
    } else {
        TunnelDiscriminator::None
    };
    // #9298: the QUOTED PPTP Call ID, extracted with the SAME `inner_declared_end`
    // bound the discriminator above uses -- the #2361 rule applied to the quote,
    // so slack beyond the quoted datagram can never be read as a header field.
    // `pptp_call_id` is the extractor the transit path uses, reused rather than
    // re-spelled, and it refuses on its own terms (version != 1, Routing set,
    // Key clear) by returning `None`.
    //
    // A minimal quote is enough: the classic "IP header + 8 bytes of L4" spans
    // flags(2) proto(2) payload-length(2) call-id(2), so the id is the last two
    // bytes an RFC 792 quote is guaranteed to carry.
    let quoted_pptp_call_id = if proto == PROTO_GRE {
        pptp_call_id(frame, l4_off, inner_declared_end)
    } else {
        None
    };
    Some(EmbeddedV4Header {
        proto,
        discriminator,
        pptp_call_id: quoted_pptp_call_id,
        src,
        dst,
        l4_off,
        src_port,
        dst_port,
    })
}

/// Fragment-aware IPv6 extension-chain walk for QUOTED (embedded)
/// packets inside ICMPv6 errors (#1838 / plan §5.7). #6435: folds the ONE
/// canonical walker (`walk_ipv6_ext_chain`, shared with the forwarding
/// path's `packet_rel_l4_offset_and_protocol(.., AF_INET6)`); #6513-review:
/// judges EVERY sighted Fragment header (not just the recorded first) via
/// `ExtChainWalk::non_first_fragment_offset_seen`, restoring the pre-#6435
/// every-header verdict — a quoted NON-FIRST fragment has no L4 header, and
/// reading "ports" from its payload bytes would enable false NAT/session
/// matches (the bug class the old fixed-40 read accidentally avoided by
/// leaving proto = 44). First and atomic fragments (offset 0) are allowed.
/// Returns the L4 offset relative to the embedded IPv6 header plus the
/// final L4 protocol.
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6_l4(packet: &[u8]) -> Option<(usize, u8)> {
    let walk = walk_ipv6_ext_chain(packet, 0);
    // #1838: a quoted NON-FIRST fragment has no L4 header in the quoted
    // bytes — judged across EVERY Fragment header sighted, so a hostile
    // [Frag(off=0)][Frag(off!=0)][TCP] chain cannot smuggle the second
    // header's payload bytes past this resolver as "ports" (the first-
    // sighting-only check let exactly that through). A declared-but-
    // truncated Fragment header (offset bits unreadable) is NOT rejected
    // here — it fails closed on the `Truncated` outcome below instead,
    // exactly like the pre-#6435 walker's `packet.get(offset..offset + 8)?`
    // (both yield `None`).
    if walk.non_first_fragment_offset_seen {
        return None;
    }
    // #4533: every non-L4 verdict fails CLOSED (None) — an over-bound
    // chain (`OverLimit`, still on an extension header at the
    // MAX_IPV6_EXT_HEADERS bound) never surrenders the unconsumed
    // ext-header offset/type as a fake embedded L4, aligning this walker
    // with the #2292 forwarding walker and the #4435 NAT64 walkers by
    // construction (#6435: they now share the loop, not just the bound).
    match walk.outcome {
        ExtChainOutcome::L4(offset, protocol) => Some((offset, protocol)),
        _ => None,
    }
}

/// Parse the embedded IPv6 header starting at `embedded_ip_start`.
/// Returns None on truncated frame or when the quoted packet is a
/// non-first fragment (no L4 header — see `parse_embedded_v6_l4`).
/// The L4 offset and final protocol come from the fragment-aware
/// extension-chain walk (#1838 — previously a fixed
/// `embedded_ip_start + 40` with the raw next-header byte, which made
/// embedded-ext quoted packets parse as proto = ext-type and silently
/// never match their session). NPTv6 translation is NOT applied
/// here — the caller must do that on `src_wire` if needed.
pub(in crate::afxdp::icmp_embed) fn parse_embedded_v6(
    frame: &[u8],
    embedded_ip_start: usize,
) -> Option<EmbeddedV6Header> {
    if frame.len() < embedded_ip_start + 48 {
        return None;
    }
    // #5568: bound BOTH the quoted-inner extension-header walk AND the L4 read by
    // the QUOTED IPv6 datagram's declared length (`embedded_ip_start + 40 +
    // payload_len`), clamped to the available quote bytes — not the raw outer
    // frame. Otherwise outer-frame slack/padding beyond the quoted datagram could
    // be walked as ext headers and read as inner ports (a manufactured
    // embedded-session tuple). A truncated RFC-minimum quote whose declared
    // `payload_len` exceeds the available bytes is NOT rejected: the clamp keeps
    // the slice at `frame.len()` there, identical to the pre-#5568 read.
    let inner_payload_len =
        u16::from_be_bytes([frame[embedded_ip_start + 4], frame[embedded_ip_start + 5]]) as usize;
    let inner_declared_end = embedded_ip_start
        .saturating_add(40)
        .saturating_add(inner_payload_len)
        .min(frame.len());
    let (rel_l4, proto) = parse_embedded_v6_l4(frame.get(embedded_ip_start..inner_declared_end)?)?;
    let src_wire = Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[embedded_ip_start + 8..embedded_ip_start + 24]).ok()?,
    );
    let dst = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&frame[embedded_ip_start + 24..embedded_ip_start + 40]).ok()?,
    ));
    let l4_off = embedded_ip_start + rel_l4;
    let (src_port, dst_port) = if matches!(proto, PROTO_TCP | PROTO_UDP) {
        if l4_off.saturating_add(4) > inner_declared_end {
            return None;
        }
        let bytes = frame.get(l4_off..l4_off + 4)?;
        (
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        )
    } else if matches!(proto, PROTO_ICMPV6) {
        if l4_off.saturating_add(6) > inner_declared_end {
            return None;
        }
        let bytes = frame.get(l4_off + 4..l4_off + 6)?;
        (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
    } else {
        (0, 0)
    };
    // #9031: the QUOTED GRE discriminator. `gre_transit_discriminator` is the
    // SAME extractor the transit path uses, reused rather than re-spelled — a
    // second parser for one wire format is where two readings of the same bytes
    // silently diverge, which is exactly the class #8103 was still cleaning up.
    //
    // Bounded by `inner_declared_end`, the QUOTED datagram's declared end, not
    // by the backing frame: the #2361 rule the extractor already enforces for
    // transit, applied to the quote. Outer L2 pad or attacker-supplied slack
    // beyond the quoted datagram must not be read as a Key.
    //
    // FAIL-CLOSED BY CONSTRUCTION: every failure path in the extractor returns
    // `Unparseable`, which is a DISTINCT class from `Unkeyed` (#7188 decision
    // 6) and equal to no live session's discriminator — so a truncated or
    // malformed quote MISSES rather than wildcarding across tunnels. That is
    // the acceptance's requirement, and it is met by the type rather than by a
    // check anyone could forget.
    let discriminator = if proto == PROTO_GRE {
        gre_transit_discriminator(frame, l4_off, inner_declared_end)
    } else {
        TunnelDiscriminator::None
    };
    // #9298: the QUOTED PPTP Call ID, extracted with the SAME `inner_declared_end`
    // bound the discriminator above uses -- the #2361 rule applied to the quote,
    // so slack beyond the quoted datagram can never be read as a header field.
    // `pptp_call_id` is the extractor the transit path uses, reused rather than
    // re-spelled, and it refuses on its own terms (version != 1, Routing set,
    // Key clear) by returning `None`.
    //
    // A minimal quote is enough: the classic "IP header + 8 bytes of L4" spans
    // flags(2) proto(2) payload-length(2) call-id(2), so the id is the last two
    // bytes an RFC 792 quote is guaranteed to carry.
    let quoted_pptp_call_id = if proto == PROTO_GRE {
        pptp_call_id(frame, l4_off, inner_declared_end)
    } else {
        None
    };
    Some(EmbeddedV6Header {
        proto,
        discriminator,
        pptp_call_id: quoted_pptp_call_id,
        src_wire,
        dst,
        l4_off,
        src_port,
        dst_port,
    })
}

/// Build the embedded reply key — the session-table key for the
/// "reverse direction" of the embedded packet. For TCP/UDP this swaps
/// src/dst ports; for ICMP/ICMPv6 the echo id stays in place.
pub(in crate::afxdp::icmp_embed) fn embedded_reply_key(
    addr_family: u8,
    protocol: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    // #9031: the quoted tunnel's discriminator. The REVERSE companion of a GRE
    // session carries the same discriminator as its forward key — the tunnel
    // identity is a property of the tunnel, not of the direction — so this is
    // passed through unchanged rather than transformed, unlike the ports.
    discriminator: TunnelDiscriminator,
    // #9162: the routing domain the CALLER resolved for the quoted flow —
    // `ingress_routing_domain` on the interface the ICMP error arrived on, the
    // same value the caller stamps on the forward `embedded_key` it builds
    // alongside this one. Threaded in rather than hardcoded; see the note
    // below for why 0 was wrong and why a real domain is safe in every index
    // this key is probed against.
    routing_domain: u32,
) -> SessionKey {
    let (reply_src_port, reply_dst_port) = embedded_reply_ports(protocol, src_port, dst_port);
    SessionKey {
        addr_family,
        protocol,
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: reply_src_port,
        dst_port: reply_dst_port,
        discriminator,
        // #9162: carry the caller's domain. This used to be a hardcoded 0
        // justified by the `routing_domain: 0` convention in session/key.rs,
        // and THE CITATION WAS THE DEFECT — that convention governs the keys an
        // INSTALLED session is INDEXED UNDER (`reverse_wire_key` /
        // `reverse_canonical_key`), whose probes `reverse_match_key` zeroes to
        // match. It says nothing about a key a caller builds and hands to a
        // lookup, which is all this function produces. #9271 settled the same
        // distinction on the install side; this is the lookup side of it.
        //
        // Both kinds of index this key reaches take a real domain correctly,
        // and each for its own reason:
        //
        //   * EXACT lookups — `lookup_session_across_scopes`, whose four
        //     probes (`key_to_handle`, `forward_wire_index`, and the two
        //     shared maps) are every one domain-PRESERVING. A hardcoded 0
        //     could not reach a session installed in a routing instance at
        //     all. This is the arm that was broken: for NAT64 it is the ONLY
        //     arm, so both directions of NAT64 PMTUD/traceroute were dead in a
        //     VRF (#9162), and for the same-family arms it silently disabled
        //     the #6474 outbound-SNAT reply-key fallback there.
        //   * The REVERSE-MATCH index — `find_forward_nat_match` and
        //     `lookup_shared_forward_nat_match`. Neither requires a zeroed
        //     probe from its caller: both zero it THEMSELVES
        //     (`reverse_match_key`) to find the bucket, then spend the domain
        //     on a preference — the local one as a two-pass walk, the shared
        //     one as an exact-then-zeroed probe pair. Passing a real domain
        //     there is therefore not merely safe, it is what restores the
        //     per-tenant demux #7160 built; passing 0 forced the pre-#7160
        //     fallback pass for every flow.
        //
        // A deployment with no routing-instance interface membership resolves
        // 0 here, so its behaviour is bit-identical to before.
        routing_domain,
    }
}

pub(in crate::afxdp::icmp_embed) fn embedded_reply_ports(
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) -> (u16, u16) {
    if matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (src_port, dst_port)
    } else {
        (dst_port, src_port)
    }
}

#[cfg(test)]
mod embedded_v6_parse_tests {
    use super::*;

    /// Build a minimal embedded IPv6 packet: base header + optional
    /// extension headers + 8 bytes of TCP (ports + seq).
    fn embedded_v6(ext: &[(u8, Vec<u8>)], final_proto: u8) -> Vec<u8> {
        // ext: list of (type_byte, full encoded header bytes); each
        // header's byte 0 (next header) is patched below.
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        let mut chain_types: Vec<u8> = ext.iter().map(|(t, _)| *t).collect();
        chain_types.push(final_proto);
        p[6] = chain_types[0];
        p[7] = 64; // hop limit
        p[8..24].copy_from_slice(&[0x20; 16]); // src
        p[24..40].copy_from_slice(&[0x30; 16]); // dst
        for (i, (_, bytes)) in ext.iter().enumerate() {
            let mut b = bytes.clone();
            b[0] = chain_types[i + 1];
            p.extend_from_slice(&b);
        }
        // 8 bytes of L4: TCP ports 0x1111 / 0x2222 + 4 seq bytes.
        p.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]);
        let plen = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        p
    }

    #[test]
    fn embedded_ext_chain_recovers_true_proto_and_ports() {
        // hop-by-hop (8 bytes) before TCP: the old fixed-40 read saw
        // proto = 0 and garbage ports; the walk recovers TCP at 48.
        let hbh = (0u8, vec![0u8, 0, 0, 0, 0, 0, 0, 0]);
        let p = embedded_v6(&[hbh], PROTO_TCP);
        let (rel, proto) = parse_embedded_v6_l4(&p).expect("walk succeeds");
        assert_eq!((rel, proto), (48, PROTO_TCP));

        let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
        assert_eq!(hdr.proto, PROTO_TCP);
        assert_eq!(hdr.l4_off, 48);
        assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
    }

    #[test]
    fn embedded_mobility_hip_shim6_headers_recover_true_proto() {
        // #4517: an ICMPv6 error that quotes an inner packet whose chain
        // hides the L4 behind a Mobility (135) / HIP (139) / Shim6 (140)
        // extension header must still resolve the embedded TCP so the
        // return-path session/NAT match can form. Before #4517 the walk
        // stopped at type 135/139/140 and reported proto=135 with garbage
        // ports (parity gap vs the canonical afxdp walker).
        for exotic in [135u8, 139u8, 140u8] {
            let eh = (exotic, vec![0u8, 0, 0, 0, 0, 0, 0, 0]); // 8-byte generic EH
            let p = embedded_v6(&[eh], PROTO_TCP);
            let (rel, proto) = parse_embedded_v6_l4(&p)
                .unwrap_or_else(|| panic!("walk past EH type {exotic} must succeed"));
            assert_eq!((rel, proto), (48, PROTO_TCP));
            let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
            assert_eq!(hdr.proto, PROTO_TCP);
            assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
        }
    }

    #[test]
    fn embedded_first_or_atomic_fragment_allowed() {
        // Fragment header with offset 0 (atomic / first fragment):
        // the L4 header IS present in the quoted bytes — match allowed.
        for m_flag in [0u8, 1u8] {
            let frag = (44u8, vec![0u8, 0, 0x00, m_flag, 0, 0, 0, 1]);
            let p = embedded_v6(&[frag], PROTO_TCP);
            let (rel, proto) =
                parse_embedded_v6_l4(&p).expect("first/atomic fragment walks to L4");
            assert_eq!((rel, proto), (48, PROTO_TCP));
            let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
            assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
        }
    }

    #[test]
    fn embedded_double_fragment_chain_never_matches() {
        // #6513 hostile-review pin: a (RFC 8200-non-conformant) chain with
        // a SECOND Fragment header carrying non-zero offset bits must fail
        // closed — the pre-#6435 walker judged EVERY sighted Fragment
        // header; judging only the recorded first sighting let
        // [Frag(off=0)][Frag(off!=0)][TCP] smuggle the second header's
        // payload past this resolver as "ports" (fail-open on the #1838
        // gate). Every-header judgement is restored via
        // ExtChainWalk::non_first_fragment_offset_seen.
        let frag_first = (44u8, vec![44u8, 0, 0, 0, 0, 0, 0, 1]); // next=44, offset 0
        let mut second_bytes = vec![PROTO_TCP, 0, 0, 0, 0, 0, 0, 1];
        second_bytes[2..4].copy_from_slice(&0x0008u16.to_be_bytes()); // offset != 0
        let frag_second = (44u8, second_bytes);
        let p = embedded_v6(&[frag_first.clone(), frag_second], PROTO_TCP);
        assert_eq!(
            parse_embedded_v6_l4(&p),
            None,
            "a second Fragment header with non-zero offset must refuse the chain"
        );
        assert!(
            parse_embedded_v6(&p, 0).is_none(),
            "parse_embedded_v6 must refuse the double-fragment chain"
        );
        // Control: the same two-header chain with offset 0 in BOTH
        // Fragment headers walks to L4 at 40 + 8 + 8 = 56.
        let frag_second_ok = (44u8, vec![PROTO_TCP, 0, 0, 0, 0, 0, 0, 1]);
        let p_ok = embedded_v6(&[frag_first, frag_second_ok], PROTO_TCP);
        let (rel, proto) =
            parse_embedded_v6_l4(&p_ok).expect("all-atomic fragments walk to L4");
        assert_eq!((rel, proto), (56, PROTO_TCP));
    }

    #[test]
    fn embedded_non_first_fragment_never_matches() {
        // Non-first fragment (offset bits nonzero): the "L4 bytes" are
        // payload — parse must return None so no NAT/session match can
        // form (plan §5.7 / Codex r2 medium 1). Offset 1 (0x0008) and
        // a large offset both refuse.
        for off_be in [0x0008u16, 0xABC8] {
            let mut frag_bytes = vec![0u8, 0, 0, 0, 0, 0, 0, 1];
            frag_bytes[2..4].copy_from_slice(&off_be.to_be_bytes());
            let frag = (44u8, frag_bytes);
            let p = embedded_v6(&[frag], PROTO_TCP);
            assert_eq!(
                parse_embedded_v6_l4(&p),
                None,
                "non-first fragment (offset {off_be:#06x}) must not expose payload as ports"
            );
            assert!(
                parse_embedded_v6(&p, 0).is_none(),
                "parse_embedded_v6 must refuse a quoted non-first fragment"
            );
        }
    }

    #[test]
    fn embedded_no_ext_unchanged() {
        // Ext-free quoted packet: identical result to the old fixed-40
        // read (regression guard for the common case).
        let p = embedded_v6(&[], PROTO_TCP);
        let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
        assert_eq!(hdr.proto, PROTO_TCP);
        assert_eq!(hdr.l4_off, 40);
        assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
    }

    #[test]
    fn embedded_seven_ext_headers_still_resolve() {
        // #4533: the bound was bumped from a stale 6 to the shared
        // MAX_IPV6_EXT_HEADERS (8), so a quoted inner packet with up to
        // 7 extension headers (incl the #4517 Mobility/HIP/Shim6/exp
        // exotics) still walks to its terminal L4 — parity with the
        // forwarding/screen/nat64 siblings. The old 6-bound stopped at
        // the 7th header and reported it as a bogus proto.
        let ehs: Vec<(u8, Vec<u8>)> = [0u8, 43, 60, 135, 139, 140, 253]
            .iter()
            .map(|&t| (t, vec![0u8, 0, 0, 0, 0, 0, 0, 0]))
            .collect();
        assert_eq!(ehs.len(), MAX_IPV6_EXT_HEADERS - 1);
        let p = embedded_v6(&ehs, PROTO_TCP);
        let (rel, proto) = parse_embedded_v6_l4(&p).expect("7 ext headers within bound resolve");
        assert_eq!((rel, proto), (40 + 7 * 8, PROTO_TCP));
        let hdr = parse_embedded_v6(&p, 0).expect("parse succeeds");
        assert_eq!(hdr.proto, PROTO_TCP);
        assert_eq!(hdr.l4_off, 40 + 7 * 8);
        assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
    }

    #[test]
    fn embedded_ext_chain_overflow_fails_closed() {
        // #4533: a quoted inner packet with MORE extension headers than
        // MAX_IPV6_EXT_HEADERS must FAIL CLOSED (None) rather than
        // surrendering the ext-header offset/type as a fake embedded L4.
        // Before #4533 the walk stopped at the 6-iteration bound and fell
        // through to `Some((offset, ext_type))`, returning a bogus proto
        // that could not match a real session (fail-SAFE) but diverged
        // from the #2292/#4435 fail-closed doctrine the siblings enforce.
        let ehs: Vec<(u8, Vec<u8>)> = [0u8, 43, 60, 135, 139, 140, 253, 254]
            .iter()
            .map(|&t| (t, vec![0u8, 0, 0, 0, 0, 0, 0, 0]))
            .collect();
        assert_eq!(ehs.len(), MAX_IPV6_EXT_HEADERS);
        let p = embedded_v6(&ehs, PROTO_TCP);
        assert_eq!(
            parse_embedded_v6_l4(&p),
            None,
            "a chain longer than MAX_IPV6_EXT_HEADERS must fail closed"
        );
        assert!(
            parse_embedded_v6(&p, 0).is_none(),
            "parse_embedded_v6 must refuse an over-bound quoted chain"
        );
    }

    #[test]
    fn embedded_esp_stops_walk() {
        // ESP (50) is deliberately NOT walked (encrypted payload,
        // unreadable inner next-header): the walk STOPS at it and reports
        // proto=ESP rather than descending. Preserved across the #4533
        // bound/fail-closed change — ESP hits the terminal `_` arm and
        // returns early, before the loop bound or the post-loop None.
        let esp = crate::ip_proto::PROTO_ESP;
        // ESP directly after the base header.
        let (rel, proto) =
            parse_embedded_v6_l4(&embedded_v6(&[], esp)).expect("ESP resolves at base L4 offset");
        assert_eq!((rel, proto), (40, esp));
        // ESP behind one hop-by-hop header — the walk advances through the
        // EH then STOPS at ESP (offset 48), never reading the payload.
        let hbh = (0u8, vec![0u8, 0, 0, 0, 0, 0, 0, 0]);
        let (rel, proto) =
            parse_embedded_v6_l4(&embedded_v6(&[hbh], esp)).expect("ESP after one EH resolves");
        assert_eq!((rel, proto), (48, esp));
    }

    // #5568 IPv6 sibling (embedded-session tuple from slack): a quoted inner
    // IPv6 datagram declaring payload_len 0 (declared datagram = 40 bytes, NO L4)
    // whose next-header is TCP. Outer-frame slack past byte 40 forges ports. The
    // parser MUST bound BOTH the ext-header walk AND the L4 read by the quoted
    // datagram's declared length and refuse. Reverting to the outer-frame bound
    // returns Some(_) with the forged ports → RED.
    #[test]
    fn embedded_v6_ports_from_slack_beyond_declared_end_not_manufactured() {
        let mut inner = vec![0u8; 40];
        inner[0] = 0x60;
        inner[6] = PROTO_TCP; // next header = TCP directly
        // payload_len (bytes 4..6) stays 0 → declared datagram end = 40.
        inner[8..24].copy_from_slice(&[0x20; 16]);
        inner[24..40].copy_from_slice(&[0x30; 16]);
        // Forged ports in the outer slack beyond the declared datagram.
        inner.extend_from_slice(&[0x30, 0x39, 0x14, 0x51, 0, 0, 0, 0]);
        assert!(
            parse_embedded_v6(&inner, 0).is_none(),
            "ports in slack beyond the quoted IPv6 payload_len (0) must not be read"
        );
    }

    // #5568 anti-over-gate (IPv6): a truncated RFC-minimum quote whose declared
    // payload_len (1280) legitimately EXCEEDS the quoted bytes must STILL parse
    // its quoted ports — the declared-length bound clamps to the available quote,
    // it does not reject a legitimately-truncated quote.
    #[test]
    fn embedded_v6_truncated_quote_still_parses() {
        let mut inner = vec![0u8; 40];
        inner[0] = 0x60;
        inner[6] = PROTO_TCP;
        inner[4..6].copy_from_slice(&1280u16.to_be_bytes()); // original datagram was large
        inner[8..24].copy_from_slice(&[0x20; 16]);
        inner[24..40].copy_from_slice(&[0x30; 16]);
        inner.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]); // 8 quoted L4 bytes
        let hdr =
            parse_embedded_v6(&inner, 0).expect("truncated RFC-minimum v6 quote must still parse");
        assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
    }
}

#[cfg(test)]
mod embedded_v4_fragment_tests {
    use super::*;

    /// Build a minimal embedded IPv4 header (20-byte) + 8 L4 bytes.
    /// `frag_off` is the raw IPv4 fragment-offset field.
    fn embedded_v4(frag_off: u16, proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[6..8].copy_from_slice(&frag_off.to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // 8 L4 bytes: TCP ports 0x1111 / 0x2222 + seq.
        p.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]);
        p
    }

    #[test]
    fn embedded_v4_first_or_atomic_fragment_parses() {
        // offset 0 (atomic) and offset 0 + MF (first) both carry the L4
        // header in the quoted bytes — parse succeeds.
        for frag_off in [0x0000u16, 0x2000] {
            let p = embedded_v4(frag_off, PROTO_TCP);
            let hdr = parse_embedded_v4(&p, 0).expect("first/atomic fragment parses");
            assert_eq!(hdr.proto, PROTO_TCP);
            assert_eq!((hdr.src_port, hdr.dst_port), (0x1111, 0x2222));
        }
    }

    #[test]
    fn embedded_v4_non_first_fragment_refused() {
        // offset bits set: the quoted "ports" are payload — #1852 guard
        // (the IPv4 twin of #1853's parse_embedded_v6_l4) returns None.
        for frag_off in [0x0001u16, 0x2001, 0x1FFF] {
            let p = embedded_v4(frag_off, PROTO_TCP);
            assert!(
                parse_embedded_v4(&p, 0).is_none(),
                "quoted non-first fragment (frag_off {frag_off:#06x}) must not parse"
            );
        }
    }

    // #5568 (security — embedded-session tuple from slack): an ICMP error quotes
    // an inner IPv4 datagram declaring total-length 20 (a bare IP header, NO L4).
    // Outer-frame slack/padding beyond the quoted datagram forges TCP ports of an
    // existing session. The parser MUST bound the L4 read by the quoted IP's
    // declared total-length and refuse — else the forged ports drive a bogus
    // embedded-session/NAT match. Reverting to the outer-frame-only bound returns
    // Some(_) with the forged ports → RED (embedded axis, target-count 1).
    #[test]
    fn embedded_v4_ports_from_slack_beyond_declared_end_not_manufactured() {
        let mut inner = vec![0u8; 20];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&20u16.to_be_bytes()); // total-length 20 — no L4
        inner[9] = PROTO_TCP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 1]);
        inner[16..20].copy_from_slice(&[10, 0, 0, 2]);
        // Outer slack past the declared inner datagram: forged src/dst ports
        // (12345 / 5201) that would look like an existing session tuple.
        inner.extend_from_slice(&[0x30, 0x39, 0x14, 0x51, 0, 0, 0, 0]);
        assert!(
            parse_embedded_v4(&inner, 0).is_none(),
            "ports lie in slack beyond the quoted IP's declared total-length (20) — \
             the parser must not manufacture an embedded-session tuple from them"
        );
    }

    // #5568 anti-over-gate: a legitimate ICMP error quotes only the inner IP
    // header + first 8 bytes (RFC 792 minimum). The inner ORIGINAL total-length
    // (1500) legitimately EXCEEDS the quoted bytes — the parser must still read
    // the 8 quoted L4 bytes (ports), NOT reject the quote.
    #[test]
    fn embedded_v4_truncated_rfc_minimum_quote_still_parses() {
        let mut inner = vec![0u8; 20];
        inner[0] = 0x45;
        inner[2..4].copy_from_slice(&1500u16.to_be_bytes()); // original datagram was large
        inner[9] = PROTO_TCP;
        inner[12..16].copy_from_slice(&[10, 0, 0, 1]);
        inner[16..20].copy_from_slice(&[10, 0, 0, 2]);
        inner.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]); // the 8 quoted bytes
        let hdr =
            parse_embedded_v4(&inner, 0).expect("truncated RFC-minimum quote must still parse");
        assert_eq!(
            (hdr.src_port, hdr.dst_port),
            (0x1111, 0x2222),
            "the quoted ports are within the (large) declared length → read them"
        );
    }
}

/// #9031: the QUOTED GRE discriminator must reach the lookup key.
///
/// `SessionKey` derives Hash/Eq INCLUDING `discriminator` (#7188), and a live
/// accelerated GRE session carries `Unkeyed`/`Keyed(k)`/`Pptp(handle)`. Every
/// embedded lookup key hard-coded `Default::default()` — `None` — so every
/// exact index probe for a GRE quote MISSED: an ICMP error for a translated
/// accelerated tunnel found no NAT state, the outer destination and quoted
/// source could not be restored, and no usable signal reached the endpoint.
/// GRE carries bulk payload, so small probes stay healthy while large traffic
/// stalls after an MTU reduction.
///
/// #8103 threaded the discriminator through the five TRANSFORM helpers and
/// pinned them; those cover transforms of an EXISTING key. This is a key
/// PRODUCED FROM A QUOTED PACKET, which is the gap.
#[cfg(test)]
mod embedded_gre_discriminator_9031_tests {
    use super::*;

    /// A quoted IPv4 datagram carrying a GRE header with `flags`, plus the
    /// optional trailing 4-byte fields those flags declare, then encapsulated
    /// payload.
    ///
    /// The payload is not decoration: `parse_embedded_v4` requires a quote of at
    /// least 28 bytes (the RFC 792 minimum, 20 IP + 8 L4), so a bare 4-byte GRE
    /// header is refused before the discriminator is ever read. A fixture short
    /// of that would make these cells assert about a parse that never happened.
    /// The declared total-length COVERS the payload, so it is inside the quote.
    // #9298: `pub(super)` so the sibling PPTP module reuses ONE quote
    // fixture. Two copies would be two silent claims about the wire shape.
    pub(super) fn quoted_v4_gre(flags_version: u16, tail: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // IPv4, IHL 5
        p[9] = PROTO_GRE;
        p[12..16].copy_from_slice(&[10, 0, 1, 7]); // src
        p[16..20].copy_from_slice(&[10, 0, 2, 8]); // dst
        p.extend_from_slice(&flags_version.to_be_bytes());
        p.extend_from_slice(&[0x08, 0x00]); // protocol type
        p.extend_from_slice(tail);
        while p.len() < 28 {
            p.push(0x5A); // encapsulated payload, inside the declared quote
        }
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    /// A quote whose DECLARED total-length stops after `declared_extra` bytes of
    /// GRE header, with `slack` appended beyond it. Models outer L2 pad or
    /// attacker-supplied bytes that the quoted datagram does not cover.
    // #9298: `pub(super)` so the sibling PPTP module reuses ONE quote
    // fixture. Two copies would be two silent claims about the wire shape.
    pub(super) fn quoted_v4_gre_with_slack(flags_version: u16, declared_extra: &[u8], slack: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[9] = PROTO_GRE;
        p[12..16].copy_from_slice(&[10, 0, 1, 7]);
        p[16..20].copy_from_slice(&[10, 0, 2, 8]);
        p.extend_from_slice(&flags_version.to_be_bytes());
        p.extend_from_slice(&[0x08, 0x00]);
        p.extend_from_slice(declared_extra);
        let total = p.len() as u16; // the quote ENDS here
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p.extend_from_slice(slack);
        while p.len() < 28 {
            p.push(0x5A); // more slack, so the 28-byte parser minimum is met
        }
        p
    }

    // #9298: `pub(super)` so the sibling PPTP module reuses ONE quote
    // fixture. Two copies would be two silent claims about the wire shape.
    pub(super) fn quoted_v6_gre(flags_version: u16, tail: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = PROTO_GRE;
        p[7] = 64;
        p[8..24].copy_from_slice(&[0x20; 16]);
        p[24..40].copy_from_slice(&[0x30; 16]);
        p.extend_from_slice(&flags_version.to_be_bytes());
        p.extend_from_slice(&[0x08, 0x00]);
        p.extend_from_slice(tail);
        while p.len() < 48 {
            p.push(0x5A); // encapsulated payload, inside the declared quote
        }
        let plen = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        p
    }

    const KEY_FLAG: u16 = 0x2000;
    const CKSUM_FLAG: u16 = 0x8000;
    const ROUTING_FLAG: u16 = 0x4000;

    #[test]
    fn a_quoted_unkeyed_gre_yields_unkeyed_not_none_9031() {
        let p = quoted_v4_gre(0, &[]);
        let hdr = parse_embedded_v4(&p, 0).expect("parse");
        assert_eq!(hdr.proto, PROTO_GRE);
        assert_eq!(
            hdr.discriminator,
            TunnelDiscriminator::Unkeyed,
            "#9031: an unkeyed GRE quote must carry Unkeyed. `None` is what every \
             NON-GRE session carries, so it equals no live GRE session's \
             discriminator and every exact index probe misses"
        );
    }

    #[test]
    fn a_quoted_keyed_gre_yields_that_key_9031() {
        for key in [1u32, 0xDEAD_BEEF, u32::MAX] {
            let p = quoted_v4_gre(KEY_FLAG, &key.to_be_bytes());
            let hdr = parse_embedded_v4(&p, 0).expect("parse");
            assert_eq!(
                hdr.discriminator,
                TunnelDiscriminator::Keyed(key),
                "#9031: quoted key {key:#x} must reach the lookup key"
            );
        }
    }

    /// KEYED-ZERO is not UNKEYED (#7188 decision 6). RFC 2890 permits both and
    /// they are different tunnels; collapsing them would let an unkeyed tunnel
    /// join a keyed-zero session.
    #[test]
    fn a_quoted_keyed_zero_gre_is_not_unkeyed_9031() {
        let keyed_zero = parse_embedded_v4(&quoted_v4_gre(KEY_FLAG, &0u32.to_be_bytes()), 0)
            .expect("parse")
            .discriminator;
        let unkeyed = parse_embedded_v4(&quoted_v4_gre(0, &[]), 0)
            .expect("parse")
            .discriminator;
        assert_eq!(keyed_zero, TunnelDiscriminator::Keyed(0));
        assert_ne!(
            keyed_zero, unkeyed,
            "#9031: a Key of literally zero and no Key at all are DIFFERENT \
             tunnels (#7188 decision 6)"
        );
    }

    /// MULTIPLE KEYS must not collide: two tunnels differing only in Key must
    /// produce different lookup keys, which is the whole point of the field.
    #[test]
    fn quotes_differing_only_in_key_do_not_collide_9031() {
        let a = parse_embedded_v4(&quoted_v4_gre(KEY_FLAG, &7u32.to_be_bytes()), 0)
            .expect("parse");
        let b = parse_embedded_v4(&quoted_v4_gre(KEY_FLAG, &8u32.to_be_bytes()), 0)
            .expect("parse");
        let ka = embedded_reply_key(
            libc::AF_INET as u8, a.proto,
            IpAddr::V4(a.src), IpAddr::V4(a.dst), a.src_port, a.dst_port, a.discriminator,
            0,
        );
        let kb = embedded_reply_key(
            libc::AF_INET as u8, b.proto,
            IpAddr::V4(b.src), IpAddr::V4(b.dst), b.src_port, b.dst_port, b.discriminator,
            0,
        );
        assert_ne!(
            ka, kb,
            "#9031: two GRE tunnels differing only in Key produced the SAME \
             lookup key. GRE has no L4 ports, so the discriminator is the only \
             thing separating them — without it one tunnel's ICMP error resolves \
             against another's session"
        );
    }

    /// #9162: the reply key must carry the ROUTING DOMAIN the caller resolved.
    ///
    /// The unit-level twin of the two poll-path cells in
    /// `tests_embedded_poll_filter.rs`. This one is cheap and total: it pins
    /// that the argument reaches the field for BOTH a non-default domain and
    /// the default one, so restoring a `routing_domain: 0` literal reds here
    /// even if someone deletes the fixture cells.
    ///
    /// The old literal was justified by the reverse-MATCH convention in
    /// `session/key.rs`, which governs the keys an INSTALLED session is
    /// INDEXED under — not a probe a caller builds. Every index this key is
    /// looked up in either preserves the domain (the exact ones) or zeroes the
    /// probe itself (`find_forward_nat_match` /
    /// `lookup_shared_forward_nat_match`), so a caller's real domain is
    /// correct in all of them.
    #[test]
    fn the_reply_key_carries_the_callers_routing_domain_9162() {
        let hdr = parse_embedded_v4(&quoted_v4_gre(KEY_FLAG, &42u32.to_be_bytes()), 0)
            .expect("parse");
        for domain in [0u32, 7, 460_657] {
            let reply = embedded_reply_key(
                libc::AF_INET as u8, hdr.proto,
                IpAddr::V4(hdr.src), IpAddr::V4(hdr.dst), hdr.src_port, hdr.dst_port,
                hdr.discriminator,
                domain,
            );
            assert_eq!(
                reply.routing_domain, domain,
                "#9162: the reply key must carry the domain its caller resolved. \
                 Hardcoding 0 made this probe unable to reach any session \
                 installed in a routing instance -- which is every NAT64 session \
                 in a VRF, since `nat64_match.rs` has no second, \
                 domain-agnostic arm to fall back to"
            );
        }
    }

    /// The checksum field is SKIPPED, not validated, and the Key sits AFTER it.
    /// Reading at the wrong offset would yield a plausible-looking wrong key.
    #[test]
    fn a_checksummed_quote_reads_the_key_past_the_checksum_9031() {
        let mut tail = vec![0xAA, 0xBB, 0x00, 0x00]; // checksum + reserved1
        tail.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        let hdr = parse_embedded_v4(&quoted_v4_gre(CKSUM_FLAG | KEY_FLAG, &tail), 0).expect("parse");
        assert_eq!(
            hdr.discriminator,
            TunnelDiscriminator::Keyed(0x1234_5678),
            "#9031: with the checksum bit set the Key is 4 bytes further in; \
             reading at the unchecksummed offset yields 0xAABB0000"
        );
    }

    /// FAIL-CLOSED. A quote we could not read must MISS, never wildcard across
    /// tunnels. `Unparseable` is a distinct class from `Unkeyed` (#7188
    /// decision 6) and equals no live session's discriminator.
    #[test]
    fn an_unreadable_quote_is_unparseable_not_unkeyed_9031() {
        let cases: [(&str, Vec<u8>); 3] = [
            // Version 1 = PPTP enhanced GRE: the 32 bits after the flags word
            // are Payload Length | Call ID, NOT a Key.
            ("pptp version 1", quoted_v4_gre(0x0001, &0u32.to_be_bytes())),
            // Source Route Entries have no fixed offset, so nothing behind them
            // can be located.
            ("source routing", quoted_v4_gre(ROUTING_FLAG | KEY_FLAG, &7u32.to_be_bytes())),
            // K bit set but the DECLARED quote ends before the Key.
            ("truncated key", quoted_v4_gre_with_slack(KEY_FLAG, &[], &[])),
        ];
        for (name, p) in cases {
            let hdr = parse_embedded_v4(&p, 0).expect("parse");
            assert_eq!(
                hdr.discriminator,
                TunnelDiscriminator::Unparseable,
                "#9031 ({name}): an unreadable quote must be Unparseable. \
                 Falling back to Unkeyed would let a malformed header merge into \
                 a legitimate unkeyed session — the failure a fail-closed class \
                 exists to prevent"
            );
            assert_ne!(hdr.discriminator, TunnelDiscriminator::Unkeyed);
        }
    }

    /// BOUNDED BY THE DECLARED QUOTE, not the backing frame (#2361). Outer L2
    /// pad or attacker-supplied slack past the quoted datagram must not be read
    /// as a Key.
    #[test]
    fn a_key_in_slack_past_the_declared_quote_is_not_read_9031() {
        // K bit set; the declared quote ends immediately after the 4-byte GRE
        // header, and a Key-shaped value sits in the slack beyond it.
        let p = quoted_v4_gre_with_slack(KEY_FLAG, &[], &0xCAFE_BABEu32.to_be_bytes());
        let declared =
            u16::from_be_bytes([p[2], p[3]]) as usize;
        assert!(
            p.len() > declared,
            "fixture: the slack must lie OUTSIDE the declared quote, or this \
             cell is not about slack at all"
        );

        let hdr = parse_embedded_v4(&p, 0).expect("parse");
        assert_eq!(
            hdr.discriminator,
            TunnelDiscriminator::Unparseable,
            "#9031: bytes BEYOND the quoted datagram's declared total-length were \
             read as a GRE Key. That is a manufactured tunnel identity from \
             attacker-supplied slack — the #2361 rule, applied to the quote"
        );
        assert_ne!(hdr.discriminator, TunnelDiscriminator::Keyed(0xCAFE_BABE));
    }

    /// NON-GRE COMPATIBILITY CONTROL. Every other protocol must still carry
    /// `None`, or this change would alter identity for every existing session.
    #[test]
    fn non_gre_quotes_still_carry_none_9031() {
        for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP] {
            let mut p = vec![0u8; 20];
            p[0] = 0x45;
            p[9] = proto;
            p[12..16].copy_from_slice(&[10, 0, 1, 7]);
            p[16..20].copy_from_slice(&[10, 0, 2, 8]);
            p.extend_from_slice(&[0x11, 0x11, 0x22, 0x22, 0, 0, 0, 1]);
            let total = p.len() as u16;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            let hdr = parse_embedded_v4(&p, 0).expect("parse");
            assert_eq!(
                hdr.discriminator,
                TunnelDiscriminator::None,
                "#9031: protocol {proto} must keep None — adding this field must \
                 leave every non-GRE protocol's identity unchanged"
            );
        }
    }

    /// IPv6 (the PTB direction) parses the quoted discriminator too. A fix
    /// wired only into the v4 parser leaves every IPv6 PTB for a GRE tunnel
    /// still missing.
    #[test]
    fn the_ipv6_quote_parser_reads_the_discriminator_too_9031() {
        let keyed = parse_embedded_v6(&quoted_v6_gre(KEY_FLAG, &99u32.to_be_bytes()), 0)
            .expect("parse v6");
        assert_eq!(keyed.proto, PROTO_GRE);
        assert_eq!(
            keyed.discriminator,
            TunnelDiscriminator::Keyed(99),
            "#9031: the IPv6 embedded parser must read the quoted Key as well — \
             IPv6 PTB is the MTU-reduction signal for a v6 GRE tunnel, which is \
             the case this defect suppresses most visibly"
        );
        let unkeyed = parse_embedded_v6(&quoted_v6_gre(0, &[]), 0).expect("parse v6");
        assert_eq!(unkeyed.discriminator, TunnelDiscriminator::Unkeyed);
    }

    /// The REVERSE companion carries the SAME discriminator: tunnel identity is
    /// a property of the tunnel, not of the direction. Ports swap; this does not.
    #[test]
    fn the_reply_key_carries_the_same_discriminator_9031() {
        let hdr = parse_embedded_v4(&quoted_v4_gre(KEY_FLAG, &42u32.to_be_bytes()), 0)
            .expect("parse");
        let reply = embedded_reply_key(
            libc::AF_INET as u8, hdr.proto,
            IpAddr::V4(hdr.src), IpAddr::V4(hdr.dst), hdr.src_port, hdr.dst_port,
            hdr.discriminator,
            0,
        );
        assert_eq!(
            reply.discriminator,
            TunnelDiscriminator::Keyed(42),
            "#9031: the reverse companion of a GRE session carries the same \
             discriminator as its forward key; a reply key built with None \
             matches no stored companion"
        );
    }
}

/// #9031 STRUCTURAL: no same-family embedded lookup key may be built with
/// `discriminator: Default::default()`.
///
/// WHY STRUCTURAL, stated rather than implied. The behavioural cells above and
/// in `tests_embedded_poll_filter` bind the PARSER and the REPLY key. They do
/// NOT bind the four FORWARD-key constructors, and the reason is a property of
/// the session table rather than a gap in the fixtures: `install_with_protocol`
/// publishes a REVERSE COMPANION, and `embedded_reply_key` — which is wired —
/// matches that companion. So every fixture that resolves at all resolves
/// through the reply key, and reverting a forward constructor to
/// `Default::default()` leaves every behavioural cell GREEN. I verified that by
/// mutation before writing this guard, rather than assuming it.
///
/// The forward key is still not redundant: an AS-IS hit and a REPLY-KEY hit
/// produce different direction bookkeeping (#6474 `outbound_snat`), so a
/// forward key built with `None` silently shifts which branch classifies the
/// error. That is a real behaviour change with no match/no-match signal, which
/// is exactly the kind of thing a structural guard is for.
///
/// #9031's acceptance asks that "reverting any one constructor to
/// `Default::default()` must red". This is what makes that true.
#[cfg(test)]
mod embedded_discriminator_wiring_9031_tests {
    /// The same-family embedded modules. `nat64_match.rs` is deliberately
    /// EXCLUDED: NAT64 translates the protocol across address families, so a
    /// quoted GRE header on one side names no tunnel identity the other side's
    /// session carries, and `TunnelDiscriminator::None` is correct there. It is
    /// excluded by name with that reason rather than by the pattern happening
    /// not to match, so a future edit cannot quietly enrol it.
    const SAME_FAMILY_SOURCES: [(&str, &str); 4] = [
        ("nat_match_v4.rs", include_str!("nat_match_v4.rs")),
        ("nat_match_v6.rs", include_str!("nat_match_v6.rs")),
        ("session_match.rs", include_str!("session_match.rs")),
        ("parse.rs", include_str!("parse.rs")),
    ];

    #[test]
    fn no_same_family_embedded_key_defaults_its_discriminator_9031() {
        let mut offenders = Vec::new();
        let mut wired = 0usize;
        for (name, src) in SAME_FAMILY_SOURCES {
            for (i, line) in src.lines().enumerate() {
                let t = line.trim();
                if t.starts_with("discriminator: Default::default()") {
                    offenders.push(format!("{name}:{}", i + 1));
                }
                // #9298 RE-ANCHOR. The four forward-key constructors no
                // longer spell the wired value `hdr.discriminator`: they pass
                // it through `resolve_quoted_pptp_discriminator` first, which
                // upgrades an `Unparseable` PPTP quote to the live call's
                // handle and returns every other class untouched. That is the
                // SAME quoted discriminator, resolved — so the site is still
                // wired and this counter must still see it.
                //
                // Re-anchored rather than relaxed: the accepted spellings are
                // an explicit list, so a site that silently reverts to
                // `Default::default()` is still an offender above and a site
                // that drops the field entirely still lowers this count.
                if t.starts_with("discriminator: hdr.discriminator")
                    || t.starts_with("discriminator: quoted_discriminator")
                    || t == "discriminator,"
                {
                    wired += 1;
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "#9031: {offenders:?} build an embedded lookup key with \
             `discriminator: Default::default()` — i.e. `None`. SessionKey's \
             Hash/Eq include the discriminator (#7188), and a live accelerated \
             GRE session carries Unkeyed/Keyed(k)/Pptp(handle), so such a key can \
             never match one: the ICMP error finds no NAT state, the outer \
             destination and quoted source cannot be restored, and PMTUD and \
             unreachable signalling are deterministically suppressed for the \
             tunnel. Pass the QUOTED discriminator (hdr.discriminator)."
        );
        // NON-VACUITY: an empty scan passes the assertion above for free. This
        // is the count that would have caught a guard reading the wrong files.
        assert!(
            wired >= 7,
            "#9031/#9298: only {wired} wired discriminator sites found across \
             the same-family embedded sources; expected at least 7 (four \
             forward keys plus three parse-side field inits). A guard that \
             scans nothing reports no offenders — this is the count that would \
             have caught a guard reading the wrong files, and #9298 raised it \
             from 5 after confirming the true figure by inspection."
        );
    }
}


/// #9298: the QUOTED PPTP Call ID must reach the parser's output.
///
/// This module is the PURE half of the #9298 split. `gre_transit_discriminator`
/// refuses every version-1 header — correctly, because version 1 re-purposes the
/// 32 bits after the flags as `Payload Length | Call ID`, and reading them as an
/// RFC 2890 Key would promote a per-packet-varying length into a stable tunnel
/// identity. So the quote's discriminator is `Unparseable`, and the Call ID has
/// to travel out of the parser as raw BYTES for
/// `resolve_quoted_pptp_discriminator` to turn into a handle where the
/// association table is in scope.
///
/// The two halves are asserted TOGETHER below, because the failure mode of
/// getting this wrong is not a missing field — it is `Keyed(payload_len << 16 |
/// call_id)`, a plausible-looking identity that differs for every packet.
#[cfg(test)]
mod pptp_quote_call_id_9298_tests {
    use super::*;

    /// K bit (0x2000) + version 1 (0x0001), RFC 2637 §4.1.
    const PPTP_FLAGS_V1: u16 = 0x3001;
    /// The per-packet payload length that shares the 32-bit word with the id.
    const PAYLOAD_LEN: [u8; 2] = [0x05, 0xdc];

    fn quoted_v4_pptp(call_id: u16) -> Vec<u8> {
        let mut tail = PAYLOAD_LEN.to_vec();
        tail.extend_from_slice(&call_id.to_be_bytes());
        super::embedded_gre_discriminator_9031_tests::quoted_v4_gre(PPTP_FLAGS_V1, &tail)
    }

    #[test]
    fn a_quoted_pptp_header_yields_the_call_id_and_stays_unparseable_9298() {
        let hdr = parse_embedded_v4(&quoted_v4_pptp(0x0202), 0).expect("parse");
        assert_eq!(hdr.proto, PROTO_GRE);
        assert_eq!(
            hdr.pptp_call_id,
            Some(0x0202),
            "#9298: the quoted Call ID must reach the caller. Without it the \
             ICMP error for a PPTP data tunnel has nothing to resolve against \
             the association table"
        );
        assert_eq!(
            hdr.discriminator,
            TunnelDiscriminator::Unparseable,
            "#9298: the discriminator field itself must STAY Unparseable here. \
             The Call ID is not a tunnel identity on its own — it is a wire \
             value that differs per direction — so the parser must not \
             manufacture one. Only `resolve_quoted_pptp_discriminator`, which \
             can see the association table, may upgrade it"
        );
        // THE FAILURE MODE THIS GUARDS: reading the whole 32-bit word as a Key.
        let as_key = u32::from_be_bytes([PAYLOAD_LEN[0], PAYLOAD_LEN[1], 0x02, 0x02]);
        assert_ne!(
            hdr.discriminator,
            TunnelDiscriminator::Keyed(as_key),
            "#9298: the 32 bits after a version-1 flags word are `Payload \
             Length | Call ID`, and the length varies per packet. Read as an \
             RFC 2890 Key, every packet of one call gets a different identity"
        );
    }

    /// A VERSION-0 quote must yield NO call id. The two dialects share a header
    /// shape and mean different things by it; this is the row that would red if
    /// the extractor stopped checking the version.
    #[test]
    fn a_version_0_keyed_quote_yields_no_call_id_9298() {
        let p = super::embedded_gre_discriminator_9031_tests::quoted_v4_gre(
            0x2000,
            &0xDEAD_BEEFu32.to_be_bytes(),
        );
        let hdr = parse_embedded_v4(&p, 0).expect("parse");
        assert_eq!(
            hdr.pptp_call_id, None,
            "#9298: an RFC 2890 Key is NOT a PPTP Call ID. Treating one as the \
             other would resolve a keyed-GRE quote against the PPTP \
             association table and cross two unrelated identity spaces"
        );
        assert_eq!(hdr.discriminator, TunnelDiscriminator::Keyed(0xDEAD_BEEF));
    }

    /// BOUNDED BY THE DECLARED QUOTE (#2361), same rule as the Key extractor.
    #[test]
    fn a_call_id_in_slack_past_the_declared_quote_is_not_read_9298() {
        let mut slack = PAYLOAD_LEN.to_vec();
        slack.extend_from_slice(&0x0202u16.to_be_bytes());
        let p = super::embedded_gre_discriminator_9031_tests::quoted_v4_gre_with_slack(
            PPTP_FLAGS_V1,
            &[],
            &slack,
        );
        let declared = u16::from_be_bytes([p[2], p[3]]) as usize;
        assert!(
            p.len() > declared,
            "fixture: the slack must lie OUTSIDE the declared quote, or this \
             cell is not about slack at all"
        );
        let hdr = parse_embedded_v4(&p, 0).expect("parse");
        assert_eq!(
            hdr.pptp_call_id, None,
            "#9298: bytes beyond the quoted datagram's declared total-length \
             were read as a Call ID. That is an attacker-chosen handle into the \
             association table, from slack the quoted datagram does not cover"
        );
    }

    /// NON-GRE COMPATIBILITY CONTROL: adding this field must not change any
    /// other protocol's parse.
    #[test]
    fn non_gre_quotes_carry_no_call_id_9298() {
        for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP] {
            let mut p = vec![0u8; 20];
            p[0] = 0x45;
            p[9] = proto;
            p[12..16].copy_from_slice(&[10, 0, 1, 7]);
            p[16..20].copy_from_slice(&[10, 0, 2, 8]);
            // Bytes that WOULD read as flags 0x3001 + a call id if the parser
            // stopped checking the protocol.
            p.extend_from_slice(&[0x30, 0x01, 0x88, 0x0b, 0x05, 0xdc, 0x02, 0x02]);
            let total = p.len() as u16;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            let hdr = parse_embedded_v4(&p, 0).expect("parse");
            assert_eq!(
                hdr.pptp_call_id, None,
                "#9298: protocol {proto} must carry no Call ID — the bytes at \
                 that offset are a TCP/UDP/ICMP header, not a GRE one"
            );
        }
    }

    /// The IPv6 parser reads it too. PPTP over IPv6 is the same enhanced-GRE
    /// header, and a v4-only parse leaves every IPv6 PTB for a PPTP tunnel
    /// unresolvable.
    #[test]
    fn the_ipv6_quote_parser_reads_the_call_id_too_9298() {
        let mut tail = PAYLOAD_LEN.to_vec();
        tail.extend_from_slice(&0x0202u16.to_be_bytes());
        let p = super::embedded_gre_discriminator_9031_tests::quoted_v6_gre(PPTP_FLAGS_V1, &tail);
        let hdr = parse_embedded_v6(&p, 0).expect("parse v6");
        assert_eq!(hdr.proto, PROTO_GRE);
        assert_eq!(hdr.pptp_call_id, Some(0x0202));
        assert_eq!(hdr.discriminator, TunnelDiscriminator::Unparseable);
    }
}


/// #9298 STRUCTURAL: every same-family FORWARD lookup key must carry the
/// RESOLVED quote, not the raw one.
///
/// WHY STRUCTURAL — measured, not assumed. The mutation matrix for #9298 severed
/// each forward-key constructor back to `discriminator: hdr.discriminator` and
/// all three SURVIVED every behavioural cell, including the dedicated PPTP
/// end-to-end ones. The reason is an index rule, not a fixture gap:
/// `SessionTable::index_forward_nat_key` puts every forward entry's reverse wire
/// key into `nat_reverse_index` ALWAYS, NAT or not. So while the REPLY key is
/// wired, `lookup_forward_nat_across_scopes` (in `nat_match_v4`/`v6`) and
/// `find_forward_nat_match` (the third fallback in `session_match`) reach the
/// live session before the as-is forward key is consulted, and a broken forward
/// key has no match/no-match signal. The reply keys DO have one, and the
/// end-to-end cells kill their reverts.
///
/// This is the same conclusion #9031's guard above reached for `Default::default()`,
/// re-measured for the #9298 shape. It needs its own guard because the #9031 one
/// ACCEPTS `hdr.discriminator` — which was the correct spelling until this change,
/// and is now exactly the defect: for a PPTP quote the raw value is `Unparseable`
/// on every packet.
///
/// Scoped to the three same-family match modules; `parse.rs` field inits are the
/// raw value by design (the parser stays pure), and `nat64_match.rs` is excluded
/// for the reason the #9031 guard gives.
#[cfg(test)]
mod embedded_forward_key_resolve_wiring_9298_tests {
    const MATCH_SOURCES: [(&str, &str, usize); 3] = [
        // (file, source, forward keys it builds)
        ("nat_match_v4.rs", include_str!("nat_match_v4.rs"), 1),
        ("nat_match_v6.rs", include_str!("nat_match_v6.rs"), 1),
        ("session_match.rs", include_str!("session_match.rs"), 2),
    ];

    #[test]
    fn every_same_family_forward_key_carries_the_resolved_quote_9298() {
        let mut raw = Vec::new();
        let mut total_resolved = 0usize;
        for (name, src, want) in MATCH_SOURCES {
            let mut resolved = 0usize;
            let mut calls = 0usize;
            for (i, line) in src.lines().enumerate() {
                let t = line.trim();
                if t.starts_with("discriminator: hdr.discriminator") {
                    raw.push(format!("{name}:{}", i + 1));
                }
                if t.starts_with("discriminator: quoted_discriminator") {
                    resolved += 1;
                }
                if t.contains("resolve_quoted_pptp_discriminator(") {
                    calls += 1;
                }
            }
            assert_eq!(
                resolved, want,
                "#9298: {name} builds {want} forward lookup key(s) but only \
                 {resolved} carry `discriminator: quoted_discriminator`. A key \
                 left on the raw quote is `Unparseable` for every PPTP packet \
                 and can never equal a live session's `Pptp(handle)`"
            );
            assert_eq!(
                calls, want,
                "#9298: {name} must call `resolve_quoted_pptp_discriminator` once \
                 per match arm ({want}), found {calls}. The forward keys above \
                 are only correct if the value they carry was resolved"
            );
            total_resolved += resolved;
        }
        assert!(
            raw.is_empty(),
            "#9298: {raw:?} build a forward lookup key from the RAW quote \
             (`hdr.discriminator`). Before #9298 that was correct; now the raw \
             value is `Unparseable` for every PPTP packet, so the key misses. \
             Use `quoted_discriminator`. No behavioural cell can see this — the \
             reply key reaches the session first (see the module doc)."
        );
        // NON-VACUITY: a scan that read nothing would pass `raw.is_empty()`.
        assert_eq!(total_resolved, 4, "#9298: expected exactly 4 wired forward keys");
    }
}
