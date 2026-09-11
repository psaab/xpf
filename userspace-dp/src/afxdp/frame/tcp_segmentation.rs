// TCP segmentation builders extracted from frame/mod.rs (#1046).
// `segment_forwarded_tcp_frames_from_frame` does the heavy lifting;
// `segment_forwarded_tcp_frames` is the XdpDesc adapter wrapper.
// Pure relocation — bodies are byte-for-byte identical; only the
// enclosing module is new and the visibility is rewritten from
// `pub(super)` (visible to afxdp via frame::*) to `pub(in crate::afxdp)`
// so frame/mod.rs can re-export them at the same effective surface
// for tx/dispatch.rs's existing call sites.

use super::*;

/// #5191: the per-segment header fixups every software-segmentation output
/// gets, shared by the copy-path builder here and the prepared-TX twin in
/// `tx/tcp_segmentation.rs`. Both builders clone the ORIGINAL IP and TCP
/// headers verbatim into each output; everything that must NOT be cloned is
/// repaired here, in one place, so the two twins cannot drift.
///
/// `packet` starts at the L3 header. `l4_offset` is the TCP offset relative to
/// it (equal to the IP header length at both call sites — the copied header
/// includes any IPv6 extension chain). `segment_index` is 0 for the first
/// output, `data_offset` is this chunk's byte offset within the original TCP
/// data, and `is_last` marks the final output.
///
/// Caller ordering contract: both twins call this BEFORE the IPv4 header
/// checksum recompute and BEFORE `recompute_l4_checksum_ipv4/6`, so the fields
/// written here are covered by the fresh checksums rather than invalidating
/// them.
///
/// What is repaired, and why cloning it is wrong:
///
/// - **seq** — each segment starts `data_offset` bytes further into the
///   stream. (Pre-#5191 behaviour, unchanged.)
/// - **PSH** — only the final segment carries the original push.
///   (Pre-#5191 behaviour, unchanged.)
/// - **CWR** (RFC 3168 §6.1.2) — a one-shot signal that the sender has already
///   responded to an ECN-Echo. The receiver clears its "keep echoing" state on
///   the first CWR it sees, so a CWR replicated onto later segments retracts an
///   ECE the receiver may have re-raised for a NEW congestion event in between,
///   and the sender never reduces cwnd for it. Kept on segment 0 only — the
///   same rule a TSO NIC and Linux's `tcp_gso_segment` apply.
/// - **URG + urgent pointer** (RFC 9293 §3.1) — the pointer is relative to the
///   segment's OWN sequence number, so cloning it moves the urgent point
///   forward by one chunk per segment and invents urgent data that the sender
///   never marked. A receiver with `SO_OOBINLINE` off pulls the byte at the
///   (wrong) urgent point OUT of the data stream, which corrupts the
///   application byte stream rather than merely mis-signalling. The ABSOLUTE
///   urgent point `seq + urg_ptr` is preserved instead: later segments get
///   `urg_ptr - data_offset`, and a segment that starts past the urgent point
///   has URG cleared (its urgent data was fully delivered by an earlier
///   segment). Preserving the absolute value keeps the RFC 793 and RFC 1122
///   readings of the pointer equivalent — a receiver derives the same urgent
///   sequence number under either.
/// - **IPv4 Identification** (RFC 6864 §4.1) — a NON-atomic datagram (DF
///   clear) must carry a unique Identification per source/destination/protocol
///   while it could still be fragmented downstream. Cloning one ID across N
///   segments lets a downstream fragmenting router produce fragments from
///   DIFFERENT segments that share the reassembly key, so the receiver splices
///   them into a corrupt datagram (caught by the TCP checksum, but only after
///   the data is lost). Each segment gets `id + segment_index`. An ATOMIC
///   datagram (DF set — the normal PMTUD case) keeps the original ID
///   unchanged: RFC 6864 §4.1 says the field is ignored there, so rewriting it
///   would be a gratuitous wire change.
#[inline]
pub(in crate::afxdp) fn finalize_tcp_segment_headers(
    packet: &mut [u8],
    addr_family: u8,
    l4_offset: usize,
    original_seq: u32,
    data_offset: usize,
    segment_index: u16,
    is_last: bool,
) -> Option<()> {
    // IPv4 Identification, before the TCP borrow. Only non-atomic datagrams
    // (DF clear) need distinct IDs; byte 6 bit 0x40 is DF.
    if addr_family as i32 == libc::AF_INET && segment_index > 0 && (*packet.get(6)? & 0x40) == 0 {
        let original_id = u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]);
        let id = original_id.wrapping_add(segment_index);
        packet.get_mut(4..6)?.copy_from_slice(&id.to_be_bytes());
    }

    let tcp = packet.get_mut(l4_offset..)?;
    let seq = original_seq.wrapping_add(data_offset as u32);
    tcp.get_mut(4..8)?.copy_from_slice(&seq.to_be_bytes());
    if !is_last {
        // #9116: FIN, like PSH, belongs on the LAST segment only. A FIN means
        // "no more data from me"; repeating it on every segment would close the
        // half-connection at the first one and leave the rest of the payload
        // outside the sequence space the peer will accept. Clearing it here is
        // what makes admitting a FIN-bearing oversized segment correct rather
        // than merely permitted — the admission gates below now allow FIN, and
        // this is the other half of that change.
        *tcp.get_mut(13)? &= !(TCP_FLAG_PSH | TCP_FLAG_FIN);
    }
    if segment_index == 0 {
        // Segment 0 keeps the original CWR and the original urgent pointer:
        // its sequence number is the original one, so both are already right.
        return Some(());
    }
    *tcp.get_mut(13)? &= !TCP_FLAG_CWR;
    if (*tcp.get(13)? & TCP_FLAG_URG) != 0 {
        let urg_ptr = u32::from(u16::from_be_bytes([*tcp.get(18)?, *tcp.get(19)?]));
        let consumed = data_offset as u32;
        if urg_ptr >= consumed {
            // Still points into (or at the start of) this segment. The
            // subtraction cannot overflow a u16: `urg_ptr` already fits one and
            // only shrinks.
            let rebased = (urg_ptr - consumed) as u16;
            tcp.get_mut(18..20)?.copy_from_slice(&rebased.to_be_bytes());
        } else {
            // The urgent point lies before this segment — an earlier segment
            // already carried the signal with a correct pointer.
            *tcp.get_mut(13)? &= !TCP_FLAG_URG;
            tcp.get_mut(18..20)?.copy_from_slice(&[0, 0]);
        }
    }
    Some(())
}

pub(in crate::afxdp) fn segment_forwarded_tcp_frames_from_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    let meta = meta.into();
    if meta.protocol != PROTO_TCP {
        return None;
    }
    // #2329: mode-aware inner-L3 MTU. The pre-#2329 code used the GRE
    // inner-MTU formula for EVERY tunnel endpoint, so a WireGuard tunnel
    // got the GRE budget (~36-60 bytes too large) and the oversized
    // segments were built then dropped at the WG encap MTU guard
    // (`encap_mtu_drops`) — a blackhole. Dispatch on the endpoint's
    // `TunnelKind` (the #2327 classifier) and reuse the pad-aware WG SSOT
    // `wg::mss::wg_inner_mtu` (#2330) for WireGuard — do NOT re-derive WG
    // overhead here. An unknown/missing tunnel mode yields a 0 budget,
    // which short-circuits to `None` below (fail-closed) and matches the
    // encap dispatch's Unknown-drop arm.
    let mtu = if decision.resolution.tunnel_endpoint_id != 0 {
        // For a tunnel the inner-L3 budget is the encap-mode's exact inner
        // MTU; an Unknown/missing mode yields 0 → fail closed. Do NOT
        // floor a tunnel budget to 1280: a tunnel with a small outer MTU
        // has a genuinely smaller inner budget, and flooring it would
        // re-introduce the oversized submission this fix exists to prevent.
        // #5159: the plain-forward path below no longer floors either — the
        // same oversized submission applies to a plain interface with a
        // valid sub-1280 IPv4 MTU.
        let kind = forwarding
            .tunnel_endpoints
            .get(&decision.resolution.tunnel_endpoint_id)
            .map(|e| tunnel_mode_kind(&e.mode));
        match kind {
            Some(TunnelKind::Gre) => native_gre_inner_mtu(forwarding, decision),
            Some(TunnelKind::WireGuard) => {
                let endpoint = forwarding
                    .tunnel_endpoints
                    .get(&decision.resolution.tunnel_endpoint_id)?;
                let outer_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
                crate::afxdp::wg::mss::wg_inner_mtu(endpoint.outer_family, outer_mtu)
            }
            // Unknown mode or missing endpoint row: 0 budget → None below.
            Some(TunnelKind::Unknown) | None => 0,
        }
    } else {
        // #5159: use the ACTUAL egress MTU. The prior `.max(1280)` floored a
        // valid IPv4 MTU of 68-1279 to the IPv6-minimum LINK MTU (1280, NOT an
        // IPv4 floor — IPv4 min is 68), so a non-DF TCP datagram whose L3 length
        // fell in (real_mtu, 1280] was chunked to 1280 and still oversize. A
        // 0 result (no egress entry / unknown MTU) is NOT chunked to a made-up
        // size: the now-live `mtu == 0` guard below returns None so the frame is
        // forwarded WHOLE (best-effort / fail-OPEN) — in contrast to the TUNNEL
        // branch above, whose 0 budget genuinely fail-CLOSES (an un-encapsulable
        // frame is dropped). If the whole frame is oversize for the real link it
        // may be dropped DOWNSTREAM, but `mtu == 0` here means a route to an
        // unconfigured egress (an inconsistent snapshot), so the practical risk
        // is low.
        forwarding
            .egress
            .get(&decision.resolution.egress_ifindex)
            .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
            .map(|egress| egress.mtu)
            .unwrap_or_default()
    };
    if mtu == 0 {
        return None;
    }
    let Some(l3) = frame_l3_offset(frame) else {
        return None;
    };
    if l3 >= frame.len() {
        return None;
    }
    // #5148: defense in depth — never segment ANY IP fragment (first or
    // non-first). The admission gate `forwarded_tcp_may_need_segmentation`
    // in dispatch/mod.rs already rejects every fragment, so this builder is
    // not reached for one, but re-assert the invariant here so a future
    // caller cannot bypass the gate and let segmentation clone the
    // fragment-bearing IP header (Identification / MF / offset) into
    // overlapping offset-0 pseudo-segments. A fragmented datagram is never
    // transformed into independent TCP segments; return None so the caller
    // forwards the original frame unchanged.
    if is_any_fragment(&frame[l3..], meta.addr_family) {
        return None;
    }
    // #5141: the datagram's authoritative end is the IP header's declared
    // length (IPv4 total_len / IPv6 40 + payload_len), CLAMPED to the backing
    // slice by `declared_l3_end`. Slicing the full `&frame[l3..]` backing
    // instead promotes trailing Ethernet slack / attacker-appended bytes into
    // freshly checksummed segments carrying valid IP lengths — bytes that were
    // never datagram content injected into a valid TCP stream. Every read
    // below (MTU admission, TCP header parse, data slice, per-segment copy
    // loop) is bounded by this clamped `payload`. A declaration that does not
    // even cover the IP+TCP headers leaves `payload` shorter than the header
    // bounds checks require, so it fails closed (returns None → not segmented).
    let Some(l3_end) = declared_l3_end(frame, l3, meta.addr_family) else {
        return None;
    };
    let payload = &frame[l3..l3_end];
    if payload.len() <= mtu {
        return None;
    }
    let Some(frame_l4) = frame_l4_offset(frame, meta.addr_family) else {
        return None;
    };
    let Some(tcp_offset) = frame_l4.checked_sub(l3) else {
        return None;
    };
    let (ip_header_len, tcp_offset) = match meta.addr_family as i32 {
        libc::AF_INET => {
            if payload.len() < 20 {
                return None;
            }
            let ihl = ((payload[0] & 0x0f) as usize) * 4;
            if ihl < 20 || payload.len() < ihl + 20 {
                return None;
            }
            (ihl, ihl)
        }
        libc::AF_INET6 => {
            let ip_header_len = tcp_offset;
            if ip_header_len < 40 || payload.len() < ip_header_len + 20 {
                return None;
            }
            (ip_header_len, ip_header_len)
        }
        _ => return None,
    };
    let tcp_header_len = ((payload.get(tcp_offset + 12)? >> 4) as usize) * 4;
    if tcp_header_len < 20 || payload.len() < tcp_offset + tcp_header_len {
        return None;
    }
    let tcp_flags = *payload.get(tcp_offset + 13)?;
    // #9116: SYN and RST still decline; FIN does NOT.
    //
    // An oversized segment carrying FIN is an ordinary data segment that also
    // closes the sender's half. Declining it sent the frame to
    // `compute_forwarded_egress_ptb`, and on an IPv4 path with DF CLEAR that
    // forwards the original oversized frame whole (`ForwardOversizeNoDf` since
    // #9328), so wherever the path could not carry it the connection close was
    // lost. There is no IPv4 transit fragmentation engine to catch it.
    //
    // SYN carries no bulk payload and its options are per-connection, so
    // splitting one is never right. RST is terminal and payload-bearing RSTs
    // are exotic; declining stays the conservative answer for both.
    //
    // FIN is carried on the LAST segment only — `finalize_tcp_segment_headers`
    // clears it on the others, next to the identical PSH rule.
    if (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_RST)) != 0 {
        return None;
    }
    let Some(segment_payload_max) = mtu.checked_sub(ip_header_len + tcp_header_len) else {
        return None;
    };
    if segment_payload_max == 0 {
        return None;
    }
    let Some(data) = payload.get(tcp_offset + tcp_header_len..) else {
        return None;
    };
    if data.len() <= segment_payload_max {
        return None;
    }

    let Some(dst_mac) = decision.resolution.neighbor_mac else {
        return None;
    };
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                apply_nat_on_fabric,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let original_seq = u32::from_be_bytes([
        *payload.get(tcp_offset + 4)?,
        *payload.get(tcp_offset + 5)?,
        *payload.get(tcp_offset + 6)?,
        *payload.get(tcp_offset + 7)?,
    ]);
    let enforced_ports = expected_ports.or(live_frame_ports_from_meta_bytes(frame, meta));
    let Some(tcp_header) = payload.get(tcp_offset..tcp_offset + tcp_header_len) else {
        return None;
    };
    let Some(ip_header) = payload.get(..ip_header_len) else {
        return None;
    };
    let mut out = Vec::with_capacity((data.len() / segment_payload_max) + 1);
    let mut data_offset = 0usize;
    let mut segment_index = 0u16;
    while data_offset < data.len() {
        let chunk_len = (data.len() - data_offset).min(segment_payload_max);
        let is_last = data_offset + chunk_len == data.len();
        let total_ip_len = ip_header_len + tcp_header_len + chunk_len;
        let mut frame_out = vec![0u8; eth_len + total_ip_len];
        write_eth_header_slice(
            frame_out.get_mut(..eth_len)?,
            dst_mac,
            src_mac,
            vlan_id,
            ether_type,
        )?;
        {
            let packet = frame_out.get_mut(eth_len..)?;
            packet.get_mut(..ip_header_len)?.copy_from_slice(ip_header);
            packet
                .get_mut(ip_header_len..ip_header_len + tcp_header_len)?
                .copy_from_slice(tcp_header);
            packet
                .get_mut(ip_header_len + tcp_header_len..total_ip_len)?
                .copy_from_slice(data.get(data_offset..data_offset + chunk_len)?);

            // #5191: seq / PSH / CWR / URG+urgent-pointer / IPv4 ID, shared
            // with the prepared-TX twin.
            finalize_tcp_segment_headers(
                packet,
                meta.addr_family,
                tcp_offset,
                original_seq,
                data_offset,
                segment_index,
                is_last,
            )?;
        }

        match meta.addr_family as i32 {
            libc::AF_INET => emit_ipv4_segment(
                &mut frame_out,
                eth_len,
                ip_header_len,
                total_ip_len,
                meta,
                decision,
                apply_nat,
                enforced_ports,
            )?,
            libc::AF_INET6 => emit_ipv6_segment(
                &mut frame_out,
                eth_len,
                ip_header_len,
                tcp_header_len,
                chunk_len,
                meta,
                decision,
                apply_nat,
                enforced_ports,
            )?,
            _ => return None,
        }
        if decision.resolution.tunnel_endpoint_id != 0 {
            out.push(encap_tunnel_segment(
                &frame_out, meta, decision, forwarding,
            )?);
        } else {
            out.push(frame_out);
        }
        data_offset += chunk_len;
        segment_index = segment_index.saturating_add(1);
    }
    Some(out)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn segment_forwarded_tcp_frames(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    segment_forwarded_tcp_frames_from_frame(
        frame,
        meta,
        decision,
        forwarding,
        false,
        expected_ports,
    )
}

/// Emit the AF_INET per-segment L3/L4 finalization for one segmented TCP
/// frame: total-length, #2077 fabric-gated TTL drop/decrement, NAT, port
/// enforcement, IP header checksum, and full L4 recompute (#4384 — never an
/// incremental adjust). Operates in place on `frame_out`; a `None` return is
/// the same fail-closed drop the inline arm produced (the caller discards the
/// partial batch). Extracted verbatim from segment_forwarded_tcp_frames_from_frame
/// (#4652); byte-identical body, no added allocation.
#[inline]
fn emit_ipv4_segment(
    frame_out: &mut Vec<u8>,
    eth_len: usize,
    ip_header_len: usize,
    total_ip_len: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    enforced_ports: Option<(u16, u16)>,
) -> Option<()> {
    {
        let packet = frame_out.get_mut(eth_len..)?;
        packet
            .get_mut(2..4)?
            // #8321 findings 19/20: saturate rather than wrap. Not because the
            // wrap is reachable today — it is not, and that was measured rather
            // than assumed (see the reachability note below) — but because
            // wrapping and saturating differ in KIND at the point they diverge.
            // A wrap forges a plausible small length; a saturation produces a
            // value that is wrong on the wire but can never masquerade as
            // valid. `saturate_len16` is the tree's helper for exactly this and
            // these were the only two computed-length casts not using it.
            //
            // REACHABILITY, recorded so it is not re-derived a fourth time:
            // total_ip_len = ip_header_len + tcp_header_len + chunk_len, and
            // chunk_len <= segment_payload_max = mtu - (ip_header_len +
            // tcp_header_len), so total_ip_len <= mtu. The config layer places
            // NO upper bound on mtu (`ValidateIntegerMin(1)`, schema_interfaces.go
            // — the schema cannot express one, which is #8358), but the value
            // reaching the dataplane is read BACK FROM THE KERNEL
            // (`mtu = link.Attrs().MTU`, pkg/dataplane/userspace/interfaces.go),
            // so it is whatever the driver accepted. On every interface this
            // dataplane forwards on that ceiling is far below 65535.
            .copy_from_slice(&saturate_len16(total_ip_len).to_be_bytes());
        // #2077: gate the TTL==1 drop on NOT-fabric-ingress,
        // matching the IPv6 hop-limit gate below and the
        // canonical build/rewrite paths (build/ipv4.rs,
        // frame/mod.rs, rewrite/ipv4.rs). A fabric-ingress
        // segment (FABRIC_INGRESS_FLAG = 0x80) was already
        // decremented by the peer chassis at its real
        // ingress; the fabric crossing is an internal
        // cross-chassis redirect, not an IP hop, so the
        // decrement below is suppressed and the drop must be
        // too — otherwise a legitimately-low-TTL fabric
        // segment is wrongly dropped here (v4 was the lone
        // asymmetric site).
        if (meta.meta_flags & 0x80) == 0 && packet[8] <= 1 {
            return None;
        }
        if apply_nat {
            // #1852 + #5148: non_first_fragment=false — the segmentation
            // admission gate (forwarded_tcp_may_need_segmentation) and the
            // builder's own #5148 guard never admit ANY fragment (first or
            // non-first), so no fragment reaches this NAT leaf.
            apply_nat_ipv4(packet, meta.protocol, decision.nat, false)?;
        }
        if (meta.meta_flags & 0x80) == 0 {
            packet[8] -= 1;
        }
    }
    let _ = enforce_expected_ports(
        frame_out,
        meta.addr_family,
        meta.protocol,
        enforced_ports,
        false,
    )?;
    let packet = frame_out.get_mut(eth_len..)?;
    // IP header checksum: full recompute (only 20 bytes, fast).
    packet.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let ip_sum = checksum16(packet.get(..ip_header_len)?);
    packet
        .get_mut(10..12)?
        .copy_from_slice(&ip_sum.to_be_bytes());
    // L4 checksum: full recompute over the pseudo-header and
    // this segment's actual L4 bytes. A per-segment incremental
    // adjustment from the copied original-frame checksum is
    // never valid (#4384): each segment carries a different
    // payload chunk, a rewritten seq (above), a cleared PSH on
    // non-final segments, and a different pseudo-header length,
    // none of which a NAT IP/port delta can capture — and the
    // NAT delta itself was already folded in by apply_nat_ipv4.
    // The removed incremental branch was gated on
    // `enforced_ports.is_none()`, which is unreachable for any
    // valid segmentable frame (live_frame_ports_from_meta_bytes
    // always resolves ports), so it was dead-but-wrong: a latent
    // corruption landmine had a refactor ever flipped the gate.
    // Mirror the AF_INET6 arm below, which always recomputes.
    recompute_l4_checksum_ipv4(packet, ip_header_len, meta.protocol, false)?;
    Some(())
}

/// Emit the AF_INET6 per-segment L3/L4 finalization: ext-aware payload length
/// (#1838), #2077 fabric-gated hop-limit drop/decrement, NAT, port enforcement,
/// and full L4 recompute. Operates in place on `frame_out`; a `None` return is
/// the inline arm's fail-closed drop. Extracted verbatim (#4652); byte-identical
/// body, no added allocation.
#[inline]
fn emit_ipv6_segment(
    frame_out: &mut Vec<u8>,
    eth_len: usize,
    ip_header_len: usize,
    tcp_header_len: usize,
    chunk_len: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    enforced_ports: Option<(u16, u16)>,
) -> Option<()> {
    {
        let packet = frame_out.get_mut(eth_len..)?;
        // v6 payload length = ext-header bytes + TCP header
        // + chunk. Each segment carries the FULL copied IP
        // header including the extension chain
        // (`ip_header_len` is the parsed ext-aware L4
        // offset), so omitting `ip_header_len - 40` here
        // under-stated the length for every ext-headered
        // segment (#1838). Bit-identical for the no-ext
        // case (ip_header_len == 40).
        let v6_payload_len = (ip_header_len - 40) + tcp_header_len + chunk_len;
        packet
            .get_mut(4..6)?
            // #8321 finding 20: the v6 sibling. See the v4 note above for the
            // reachability argument and for why saturating beats wrapping even
            // where neither can fire.
            .copy_from_slice(&saturate_len16(v6_payload_len).to_be_bytes());
        if (meta.meta_flags & 0x80) == 0 && packet[7] <= 1 {
            return None;
        }
        if apply_nat {
            // `ip_header_len` IS the ext-aware rel_l4: it is
            // `frame_l4_offset - l3` and the segment copies
            // the full IP header incl. the ext chain.
            // #1852 + #5148: non_first_fragment=false — the admission gate
            // and the builder's #5148 guard never admit ANY fragment.
            apply_nat_ipv6(packet, ip_header_len, meta.protocol, decision.nat, false)?;
        }
        if (meta.meta_flags & 0x80) == 0 {
            packet[7] -= 1;
        }
    }
    let _ = enforce_expected_ports(
        frame_out,
        meta.addr_family,
        meta.protocol,
        enforced_ports,
        false,
    )?;
    let packet = frame_out.get_mut(eth_len..)?;
    recompute_l4_checksum_ipv6(packet, ip_header_len, meta.protocol)?;
    Some(())
}

/// Encapsulate one finalized segment for a tunnel egress (#2329 mode-aware
/// dispatch). GRE endpoints take the native-GRE encap, WireGuard endpoints the
/// WG encap path (which pulls the live noise session from forwarding.wg_engines
/// itself), and an Unknown/missing mode fails closed (never GRE-encaps an
/// unrecognized mode). Extracted from segment_forwarded_tcp_frames_from_frame
/// (#4652).
#[inline]
fn encap_tunnel_segment(
    frame_out: &[u8],
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let kind = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
        .map(|e| tunnel_mode_kind(&e.mode));
    match kind {
        Some(TunnelKind::Gre) => {
            encapsulate_native_gre_frame(frame_out, meta, decision, forwarding)
        }
        Some(TunnelKind::WireGuard) => wg::wg_encap_frame(frame_out, meta, decision, forwarding),
        // Unknown mode or missing endpoint row: fail closed.
        Some(TunnelKind::Unknown) | None => None,
    }
}

#[cfg(test)]
mod mode_aware_segmentation_tests {
    //! #2329 fail-on-revert tests for the mode-aware TCP-segmentation
    //! egress path. They lock in BOTH mode gates:
    //!
    //!   (a) inner-L3 MTU math — a WireGuard endpoint must size segments
    //!       to `wg::mss::wg_inner_mtu` (the pad-aware SSOT), NOT the
    //!       larger GRE inner-MTU. A GRE endpoint is unchanged.
    //!   (b) encap dispatch — a WireGuard endpoint's segments must be
    //!       WG/UDP-encapsulated (the same `wg::wg_encap_frame` the normal
    //!       egress uses), NEVER a GRE outer (proto-47). A GRE endpoint
    //!       still GRE-encaps; an unknown/missing mode drops (fail closed).
    //!
    //! If either gate is reverted to the pre-#2329 unconditional-GRE
    //! behavior these tests fail: the WG inner segments would exceed the
    //! WG budget (a) and/or carry a GRE outer (b).

    use super::*;
    use crate::afxdp::wg::session::{SessionRole, WgSession};
    use crate::afxdp::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
    use crate::ip_proto::{PROTO_GRE, PROTO_UDP};
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    const TUN_ID: u16 = 1;
    const EGRESS_IFINDEX: i32 = 362;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let kp = snow::Builder::new(crate::afxdp::wg::WG_NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let mut priv_k = [0u8; 32];
        let mut pub_k = [0u8; 32];
        priv_k.copy_from_slice(&kp.private);
        pub_k.copy_from_slice(&kp.public);
        (priv_k, pub_k)
    }

    /// Build an ESTABLISHED initiator/responder `WgEngine` pair. The
    /// initiator's peer endpoint is pre-configured so `peer_for_dest`
    /// resolves a concrete destination (no learned-endpoint dependency)
    /// and `try_encap` succeeds inside `wg_encap_frame`; the responder is
    /// returned so the test can decrypt the encapped segments and verify
    /// the inner sizing/protocol. Mirrors `wg::tests::established_pair`.
    fn established_engine_pair(peer_cidr: &str) -> (WgEngine, WgEngine) {
        let (init_priv, init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();
        let peer_ep: std::net::SocketAddr = "203.0.113.9:51820".parse().unwrap();

        let init_engine = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: Some(peer_ep),
                persistent_keepalive: 0,
                allowed_ips: vec![peer_cidr.parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        let resp_engine = WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });

        // Drive a real Noise IKpsk2 handshake so the transport keys match,
        // then install both sessions with matching receiver indices.
        let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
        let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
        let mut buf = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut buf).unwrap();
        resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
        let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
        init_hs.read_message(&buf[..n2], &mut sink).unwrap();
        let init_xport = init_hs.into_stateless_transport_mode().unwrap();
        let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
        let now = crate::afxdp::wg::counters::monotonic_now_ns();
        let init_local = 0xaaaa_0001u32;
        let resp_local = 0xbbbb_0001u32;
        init_engine
            .install_session(
                &resp_pub,
                Arc::new(WgSession::new_with_role(
                    init_xport,
                    init_local,
                    resp_local,
                    resp_pub,
                    SessionRole::Initiator,
                    now,
                )),
            )
            .unwrap();
        let resp_session = Arc::new(WgSession::new_with_role(
            resp_xport,
            resp_local,
            init_local,
            init_pub,
            SessionRole::Responder,
            now,
        ));
        resp_session.mark_confirmed();
        resp_engine
            .install_session(&init_pub, resp_session)
            .unwrap();
        (init_engine, resp_engine)
    }

    fn wg_endpoint(outer_family: i32) -> TunnelEndpoint {
        TunnelEndpoint {
            id: TUN_ID,
            logical_ifindex: EGRESS_IFINDEX,
            interface_label: "wg0.0".to_string(),
            interface: "wg0.0".to_string(),
            redundancy_group: 0,
            mode: "wireguard".to_string(),
            outer_family,
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            key: 0,
            ttl: 64,
            transport_table: "inet.0".to_string(),
            wg_listen_port: 51820,
            wg_local_privkey: zeroize::Zeroizing::new([0u8; 32]),
            wg_peers: Vec::new(),
        }
    }

    fn gre_endpoint(outer_family: i32) -> TunnelEndpoint {
        TunnelEndpoint {
            mode: "gre".to_string(),
            ..wg_endpoint(outer_family)
        }
    }

    fn egress_iface(mtu: usize) -> EgressInterface {
        EgressInterface {
            bind_ifindex: EGRESS_IFINDEX,
            vlan_id: 0,
            mtu,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            primary_v6: None,
        }
    }

    /// Resolution that points the test endpoint at itself with both MACs
    /// resolved and `egress_ifindex == endpoint.logical_ifindex` (so the
    /// WG encap `#1873` R-C owner gate passes and the GRE builder builds).
    fn tunnel_resolution() -> ForwardingResolution {
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 12,
            egress_ifindex: EGRESS_IFINDEX,
            tx_ifindex: 12,
            tunnel_endpoint_id: TUN_ID,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        }
    }

    /// Build an L2 IPv4/TCP frame carrying `payload_len` bytes of data,
    /// inner src/dst chosen to land inside the WG peer's AllowedIPs.
    fn ipv4_tcp_frame(payload_len: usize) -> Vec<u8> {
        let src_ip = Ipv4Addr::new(10, 0, 0, 5);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 9);
        let src_port = 40000u16;
        let dst_port = 5201u16;
        let tcp_header_len = 20usize;
        let total_len = (20 + tcp_header_len + payload_len) as u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45,
            0x00,
            (total_len >> 8) as u8,
            total_len as u8,
            0x00,
            0x01,
            0x40,
            0x00,
            64,
            PROTO_TCP,
            0x00,
            0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        // seq, ack, data-offset (5<<4), flags (ACK), window, csum, urg.
        frame.extend_from_slice(&[
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x00, 0x3f, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend((0..payload_len).map(|i| (i & 0xff) as u8));
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        frame
    }

    fn meta_v4() -> ForwardPacketMeta {
        ForwardPacketMeta {
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..ForwardPacketMeta::default()
        }
    }

    // ------- (a) MTU math -------------------------------------------

    #[test]
    fn wireguard_segmentation_uses_wg_inner_mtu_not_gre() {
        // At a 1500 v4 outer MTU the WG inner-L3 budget is 1425 (pad-aware:
        // 1500 - 20 IP - 8 UDP - 16 WG hdr - 16 tag = 1440, minus the
        // worst-case 15-byte WG §5.4.6 transport padding = 1425, the
        // conservative bound `wg_inner_mtu` subtracts for any alignment).
        // The GRE inner budget would be 1476 (only IP+GRE). A
        // 2000-byte inner payload must therefore split with each inner IP
        // total length <= 1425, NOT <= 1476. A revert to GRE math sizes the
        // first segment to ~1476 and this assertion fails.
        let mtu = 1500usize;
        let wg_budget = crate::afxdp::wg::mss::wg_inner_mtu(libc::AF_INET, mtu);
        let gre_budget = 1476usize; // 1500 - 20 (IP) - 4 (GRE no-key)
        assert!(
            wg_budget < gre_budget,
            "test premise: WG inner budget ({wg_budget}) must be < GRE ({gre_budget})"
        );

        let (init_engine, resp_engine) = established_engine_pair("10.0.0.0/24");
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        state
            .tunnel_endpoints
            .insert(TUN_ID, wg_endpoint(libc::AF_INET));
        state.wg_engines.insert(TUN_ID, Arc::new(init_engine));
        state.has_wg_tunnels = true;

        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("WG segmentation must produce frames");
        assert!(segments.len() > 1, "2000 inner must split at the WG budget");

        // Decrypt each segment back out of the WG outer ONCE (the WG engine
        // enforces anti-replay, so a segment may be decapped only once) and
        // collect the inner IPv4 total length. Confirm the UDP outer
        // (gate (b)) before measuring the inner size.
        let inner_lens: Vec<usize> = segments
            .iter()
            .map(|seg| {
                assert_eq!(seg[23], PROTO_UDP, "WG outer must be UDP, not GRE");
                wg_decap_inner_ipv4_total_len(seg, &resp_engine)
            })
            .collect();
        for inner_len in &inner_lens {
            assert!(
                *inner_len <= wg_budget,
                "WG segment inner IP total {inner_len} exceeds WG budget {wg_budget}"
            );
        }
        // The full (largest) segment must be sized exactly to the WG inner
        // budget (1425), NOT the larger GRE budget (1476). This is the
        // direct revert sentinel for the mode-aware MTU gate: a GRE-blind
        // revert would size the full segment to 1476.
        let max_inner = *inner_lens.iter().max().unwrap();
        assert_eq!(
            max_inner, wg_budget,
            "the full segment must be sized exactly to the WG inner budget, not GRE's {gre_budget}"
        );
    }

    #[test]
    fn gre_segmentation_inner_size_unchanged() {
        // The counterfactual GRE endpoint keeps the GRE inner budget: at a
        // 1500 outer MTU the largest inner IP total is 1476 (1500 - 20 - 4).
        let mtu = 1500usize;
        // IPv4-outer GRE, no key: inner budget = 1500 - 20 (outer IP) - 4
        // (GRE) = 1476.
        let gre_budget = native_gre_inner_mtu_for_test(mtu);
        assert_eq!(gre_budget, 1476, "GRE inner budget at 1500 MTU (v4 outer)");

        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        state
            .tunnel_endpoints
            .insert(TUN_ID, gre_endpoint(libc::AF_INET));
        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("GRE segmentation must produce frames");
        assert!(segments.len() > 1);
        // GRE outer is IPv4 (fixture outer_family inet): eth(14) + IPv4(20)
        // + GRE(4) + inner. Inner IP total length must reach the GRE budget,
        // proving the GRE math is untouched (still 1476, NOT the smaller WG
        // 1425 budget).
        let outer_eth = 14usize;
        let gre_inner_start = outer_eth + 20 + 4;
        let max_inner = segments
            .iter()
            .map(|s| {
                let inner = &s[gre_inner_start..];
                u16::from_be_bytes([inner[2], inner[3]]) as usize
            })
            .max()
            .unwrap();
        assert_eq!(
            max_inner, gre_budget,
            "GRE segment inner size must equal the (unchanged) GRE budget"
        );
        // Outer protocol is GRE, never UDP.
        for seg in &segments {
            assert_eq!(&seg[12..14], &[0x08, 0x00], "GRE v4 outer ethertype");
            // IPv4 protocol field is at offset 9 within the outer IP header.
            assert_eq!(seg[outer_eth + 9], PROTO_GRE, "GRE outer proto-47");
        }
    }

    // ------- (b) encap dispatch -------------------------------------

    #[test]
    fn wireguard_segmentation_emits_wg_outer_never_gre() {
        // Already covered by the MTU test's per-segment proto check, but
        // pinned independently so a future MTU-only refactor cannot drop
        // the encap-dispatch gate. Every emitted segment must be a WG/UDP
        // outer and decap cleanly; none may be GRE.
        let (init_engine, resp_engine) = established_engine_pair("10.0.0.0/24");
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(1500));
        state
            .tunnel_endpoints
            .insert(TUN_ID, wg_endpoint(libc::AF_INET));
        state.wg_engines.insert(TUN_ID, Arc::new(init_engine));
        state.has_wg_tunnels = true;
        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("WG segmentation must produce frames");
        for seg in &segments {
            assert_eq!(&seg[12..14], &[0x08, 0x00], "WG v4 outer ethertype");
            assert_eq!(seg[23], PROTO_UDP, "WG outer proto must be UDP(17)");
            assert_ne!(seg[23], PROTO_GRE, "WG segment must never be GRE-encapped");
            // It must decap back to a valid inner IPv4 packet (a GRE-encapped
            // revert would NOT decrypt under the responder engine).
            let _ = wg_decap_inner_ipv4_total_len(seg, &resp_engine);
        }
    }

    #[test]
    fn unknown_tunnel_mode_segmentation_drops_fail_closed() {
        // An endpoint whose mode is neither GRE nor WireGuard must DROP
        // (return None) — never silently GRE-encap (the pre-#2327/#2329
        // fail-open default).
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(1500));
        let mut ep = wg_endpoint(libc::AF_INET);
        ep.mode = "l2tp".to_string();
        state.tunnel_endpoints.insert(TUN_ID, ep);
        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let out = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        );
        assert!(
            out.is_none(),
            "unknown tunnel mode must fail closed (drop), not GRE-encap"
        );
    }

    #[test]
    fn missing_tunnel_endpoint_segmentation_drops_fail_closed() {
        // A non-zero tunnel_endpoint_id that resolves to no row must drop.
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(1500));
        // Intentionally do NOT insert tunnel_endpoints[TUN_ID].
        let decision = SessionDecision {
            resolution: tunnel_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame(2000);
        let out = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        );
        assert!(
            out.is_none(),
            "missing tunnel endpoint row must fail closed (drop)"
        );
    }

    // ------- (c) #4384 per-segment L4 checksum correctness ----------

    /// Non-tunnel (plain L2) forwarding resolution so segments come out as
    /// eth + IPv4 + TCP with no encap wrapper — the simplest frame to
    /// re-verify a TCP checksum over.
    fn plain_resolution() -> ForwardingResolution {
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 12,
            egress_ifindex: EGRESS_IFINDEX,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        }
    }

    /// A correct IPv4 TCP checksum has the property that summing the
    /// pseudo-header plus the L4 bytes WITH the checksum field left in place
    /// folds to zero. Verify each segment independently of the code under
    /// test (the segmenter computes `!sum` and writes it; here we confirm
    /// the on-wire result verifies to 0).
    fn tcp_checksum_verifies_v4(segment: &[u8]) -> bool {
        let eth = 14usize; // no VLAN in these fixtures
        let ihl = ((segment[eth] & 0x0f) as usize) * 4;
        let src = Ipv4Addr::new(
            segment[eth + 12],
            segment[eth + 13],
            segment[eth + 14],
            segment[eth + 15],
        );
        let dst = Ipv4Addr::new(
            segment[eth + 16],
            segment[eth + 17],
            segment[eth + 18],
            segment[eth + 19],
        );
        let l4 = &segment[eth + ihl..];
        checksum16_ipv4(src, dst, PROTO_TCP, l4) == 0
    }

    /// #4384: every emitted segment of a NAT'd (source-NAT) multi-segment
    /// IPv4 TCP flow must carry a per-segment-correct TCP checksum. This
    /// locks the fix that deleted the dead-but-wrong incremental branch and
    /// made the AF_INET arm always full-recompute (mirroring AF_INET6). The
    /// removed branch seeded each segment's checksum from the copied
    /// whole-frame checksum and never accounted for the per-segment payload
    /// chunk, the rewritten seq, the cleared PSH, or the per-segment
    /// pseudo-header length — so any change that flipped its dead gate live
    /// would corrupt every segment. This test would go RED on such a change.
    #[test]
    fn natd_multi_segment_ipv4_tcp_has_correct_per_segment_checksums() {
        let mtu = 1280usize;
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));

        let decision = SessionDecision {
            resolution: plain_resolution(),
            // Source-NAT the flow (10.0.0.5 -> 203.0.113.7) so the checksum
            // must reflect the rewritten pseudo-header source as well as the
            // per-segment payload/seq/PSH/length changes.
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
                ..NatDecision::default()
            },
        };

        // 2000 bytes of data over a 1280 MTU (1240-byte segment payload)
        // forces >= 2 segments, so at least one non-final segment (PSH
        // cleared, non-zero seq offset) is exercised.
        let frame = ipv4_tcp_frame(2000);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("plain IPv4 segmentation must produce frames");
        assert!(
            segments.len() >= 2,
            "2000 bytes over a 1280 MTU must split into multiple segments"
        );

        for (idx, seg) in segments.iter().enumerate() {
            // The source-NAT must have been applied to every segment.
            assert_eq!(
                &seg[14 + 12..14 + 16],
                &[203, 0, 113, 7],
                "segment {idx} must carry the NAT'd source address"
            );
            assert!(
                tcp_checksum_verifies_v4(seg),
                "segment {idx} TCP checksum must verify to zero (per-segment recompute)"
            );
        }
    }

    // ------- (d) #5141 IP-declared-length clamp ---------------------
    //
    // Segmentation must slice the TCP payload from the IP-DECLARED datagram
    // (IPv4 total_len / IPv6 40+payload_len), NOT the raw backing buffer.
    // Trailing Ethernet slack / attacker-appended bytes beyond the declared
    // end are not datagram content and must never be chunked into fresh
    // segments carrying valid IP lengths and TCP checksums (bytes injected
    // into a valid checksummed stream). These tests build frames whose IP
    // header declares FEWER bytes than the backing buffer and assert:
    //   - no slack byte (0xEE) appears in any emitted segment's TCP payload;
    //   - the total emitted TCP payload equals the DECLARED data length;
    //   - a declaration too short to even hold the IP+TCP headers is NOT
    //     segmented (fail closed).
    // All three go RED on a revert of the `declared_l3_end` clamp: the
    // pre-fix builder sliced `&frame[l3..]` and promoted the slack.

    const SLACK_MARKER: u8 = 0xEE;
    const DATA_FILL: u8 = 0x41;

    /// Build an L2 IPv4/TCP frame that declares `declared_data` bytes of TCP
    /// payload via `total_len` but carries `slack` extra bytes (filled with
    /// `SLACK_MARKER`) appended AFTER the declared datagram end. The declared
    /// payload is filled with `DATA_FILL`, disjoint from `SLACK_MARKER`, so a
    /// promoted slack byte is detectable in an emitted segment.
    fn ipv4_tcp_frame_with_slack(declared_data: usize, slack: usize) -> Vec<u8> {
        let src_ip = Ipv4Addr::new(10, 0, 0, 5);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 9);
        let tcp_header_len = 20usize;
        let total_len = (20 + tcp_header_len + declared_data) as u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45,
            0x00,
            (total_len >> 8) as u8,
            total_len as u8,
            0x00,
            0x01,
            0x40,
            0x00,
            64,
            PROTO_TCP,
            0x00,
            0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        // src_port, dst_port
        frame.extend_from_slice(&40000u16.to_be_bytes());
        frame.extend_from_slice(&5201u16.to_be_bytes());
        // seq, ack, data-offset (5<<4), flags (ACK), window, csum, urg.
        frame.extend_from_slice(&[
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x00, 0x3f, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend(std::iter::repeat(DATA_FILL).take(declared_data));
        frame.extend(std::iter::repeat(SLACK_MARKER).take(slack));
        // Fix the IP header checksum over the 20-byte header (the segmenter
        // recomputes per segment, but a well-formed input is more realistic).
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        frame
    }

    /// IPv6 counterpart: declare `declared_data` TCP payload bytes via the
    /// fixed-header `payload_len` (= tcp_header + declared_data) but append
    /// `slack` SLACK_MARKER bytes past the declared datagram end.
    fn ipv6_tcp_frame_with_slack(declared_data: usize, slack: usize) -> Vec<u8> {
        let tcp_header_len = 20usize;
        let payload_len = (tcp_header_len + declared_data) as u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            0,
            0x86dd,
        );
        // IPv6 fixed header (40 bytes).
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // ver/tc/flow
        frame.extend_from_slice(&payload_len.to_be_bytes()); // payload_len
        frame.push(PROTO_TCP); // next header
        frame.push(64); // hop limit
        // src addr 2001:db8::5, dst addr 2001:db8::9
        let mut src = [0u8; 16];
        src[0] = 0x20;
        src[1] = 0x01;
        src[2] = 0x0d;
        src[3] = 0xb8;
        src[15] = 0x05;
        let mut dst = src;
        dst[15] = 0x09;
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        // TCP header (20 bytes): ports, seq, ack, data-offset(5<<4), flags ACK.
        frame.extend_from_slice(&40000u16.to_be_bytes());
        frame.extend_from_slice(&5201u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x00, 0x3f, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend(std::iter::repeat(DATA_FILL).take(declared_data));
        frame.extend(std::iter::repeat(SLACK_MARKER).take(slack));
        frame
    }

    fn meta_v6() -> ForwardPacketMeta {
        ForwardPacketMeta {
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            ..ForwardPacketMeta::default()
        }
    }

    /// Length in bytes of the single hop-by-hop extension header that
    /// [`ipv6_tcp_frame_with_ext_and_slack`] inserts (#5608). One 8-byte
    /// HbH block: 2 header bytes (next-header, hdr-ext-len=0) + a 6-byte
    /// PadN option, so `frame_l4_offset` skips exactly 8 bytes.
    const V6_EXT_LEN: usize = 8;

    /// IPv6-with-extension-header counterpart to
    /// [`ipv6_tcp_frame_with_slack`] (#5608). Inserts one hop-by-hop
    /// extension header (8 bytes) between the fixed IPv6 header and the TCP
    /// header, declares `declared_data` TCP payload bytes via `payload_len`
    /// (= ext-header + tcp-header + declared_data, per RFC 8200 — the field
    /// counts every byte after the 40-byte fixed header), then appends
    /// `slack` SLACK_MARKER bytes past the declared datagram end. The TCP
    /// offset therefore sits at l3 + 40 + 8, so the ext-chain walk in
    /// `frame_l4_offset` must be honored for the clamp math to be correct.
    fn ipv6_tcp_frame_with_ext_and_slack(declared_data: usize, slack: usize) -> Vec<u8> {
        let tcp_header_len = 20usize;
        // payload_len counts the ext chain + TCP header + declared data.
        let payload_len = (V6_EXT_LEN + tcp_header_len + declared_data) as u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            0,
            0x86dd,
        );
        // IPv6 fixed header (40 bytes) — next header 0 (hop-by-hop options).
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // ver/tc/flow
        frame.extend_from_slice(&payload_len.to_be_bytes()); // payload_len
        frame.push(0); // next header = Hop-by-Hop Options
        frame.push(64); // hop limit
        let mut src = [0u8; 16];
        src[0] = 0x20;
        src[1] = 0x01;
        src[2] = 0x0d;
        src[3] = 0xb8;
        src[15] = 0x05;
        let mut dst = src;
        dst[15] = 0x09;
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        // Hop-by-Hop Options header (8 bytes): next-header = TCP,
        // hdr-ext-len = 0 (=> 8 bytes total), then a PadN option
        // (type 1, len 4) filling the remaining 6 bytes.
        frame.extend_from_slice(&[PROTO_TCP, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]);
        // TCP header (20 bytes): ports, seq, ack, data-offset(5<<4), flags ACK.
        frame.extend_from_slice(&40000u16.to_be_bytes());
        frame.extend_from_slice(&5201u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x10, 0x00, 0x3f, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend(std::iter::repeat(DATA_FILL).take(declared_data));
        frame.extend(std::iter::repeat(SLACK_MARKER).take(slack));
        frame
    }

    /// Meta for an IPv6 frame carrying one 8-byte extension header: TCP sits
    /// at l3(14) + 40 + `V6_EXT_LEN`, so the meta-stamped L4 offset must skip
    /// the ext chain (#5608).
    fn meta_v6_ext() -> ForwardPacketMeta {
        ForwardPacketMeta {
            l3_offset: 14,
            l4_offset: (14 + 40 + V6_EXT_LEN) as u16,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            ..ForwardPacketMeta::default()
        }
    }

    /// Slice the TCP payload out of an emitted IPv6 segment whose L3 header is
    /// `ip_header_len` bytes (fixed 40 + extension chain). Mirrors
    /// [`segment_tcp_payload`] but does not assume a 40-byte IPv6 header.
    fn segment_tcp_payload_v6_ext(seg: &[u8], ip_header_len: usize) -> &[u8] {
        let eth = 14usize;
        let tcp_off = eth + ip_header_len;
        let tcp_hdr = ((seg[tcp_off + 12] >> 4) as usize) * 4;
        &seg[tcp_off + tcp_hdr..]
    }

    /// Slice the TCP payload out of a plain (eth+IP+TCP, no VLAN, no tunnel)
    /// emitted segment for either family. `frame_out` is sized exactly to the
    /// datagram, so the payload runs to the end of the segment.
    fn segment_tcp_payload(seg: &[u8], v6: bool) -> &[u8] {
        let eth = 14usize;
        let ip_len = if v6 {
            40
        } else {
            ((seg[eth] & 0x0f) as usize) * 4
        };
        let tcp_off = eth + ip_len;
        let tcp_hdr = ((seg[tcp_off + 12] >> 4) as usize) * 4;
        &seg[tcp_off + tcp_hdr..]
    }

    #[test]
    fn ipv4_segmentation_ignores_trailing_slack_beyond_total_len() {
        // Declared datagram: 20 (IP) + 20 (TCP) + 1400 (data) = 1440 > MTU
        // 1280, so it MUST segment — but only the 1400 declared bytes. 600
        // trailing SLACK_MARKER bytes sit past total_len and must be dropped.
        let mtu = 1280usize;
        let declared_data = 1400usize;
        let slack = 600usize;
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        let decision = SessionDecision {
            resolution: plain_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv4_tcp_frame_with_slack(declared_data, slack);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("declared 1440 > 1280 MTU must segment");
        assert!(segments.len() >= 2, "1440 over 1280 MTU splits");
        let mut total_payload = 0usize;
        for (idx, seg) in segments.iter().enumerate() {
            let payload = segment_tcp_payload(seg, false);
            total_payload += payload.len();
            assert!(
                !payload.contains(&SLACK_MARKER),
                "segment {idx} promoted trailing slack (0xEE) into TCP payload"
            );
        }
        assert_eq!(
            total_payload, declared_data,
            "emitted TCP payload must equal the IP-declared data, not the backing slack"
        );
    }

    #[test]
    fn ipv6_segmentation_ignores_trailing_slack_beyond_payload_len() {
        // Declared datagram: 40 (IP) + 20 (TCP) + 1400 (data) = 1460 > MTU
        // 1280. 600 trailing SLACK_MARKER bytes past payload_len must drop.
        let mtu = 1280usize;
        let declared_data = 1400usize;
        let slack = 600usize;
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        let decision = SessionDecision {
            resolution: plain_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv6_tcp_frame_with_slack(declared_data, slack);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v6(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("declared 1460 > 1280 MTU must segment");
        assert!(segments.len() >= 2, "1460 over 1280 MTU splits");
        let mut total_payload = 0usize;
        for (idx, seg) in segments.iter().enumerate() {
            let payload = segment_tcp_payload(seg, true);
            total_payload += payload.len();
            assert!(
                !payload.contains(&SLACK_MARKER),
                "v6 segment {idx} promoted trailing slack (0xEE) into TCP payload"
            );
        }
        assert_eq!(
            total_payload, declared_data,
            "v6 emitted TCP payload must equal the IP-declared data, not backing slack"
        );
    }

    #[test]
    fn ipv4_segmentation_rejects_declaration_shorter_than_headers() {
        // A large backing buffer (1400 data bytes past L3, well over the MTU)
        // but a lying-short total_len that declares only 30 bytes — fewer than
        // the 40 required for the IP+TCP headers. The datagram is a runt; it
        // must NOT be segmented (fail closed), so none of the 1400 backing
        // bytes are promoted into fresh checksummed segments.
        let mtu = 1280usize;
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        let decision = SessionDecision {
            resolution: plain_resolution(),
            nat: NatDecision::default(),
        };
        // 1400 backing data bytes, but overwrite total_len to a runt 30.
        let mut frame = ipv4_tcp_frame_with_slack(1400, 0);
        let runt_total_len: u16 = 30;
        frame[16] = (runt_total_len >> 8) as u8;
        frame[17] = runt_total_len as u8;
        let out = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v4(),
            &decision,
            &state,
            false,
            None,
        );
        assert!(
            out.is_none(),
            "a declaration shorter than the IP+TCP headers must fail closed (not segment)"
        );
    }

    #[test]
    fn ipv6_segmentation_with_ext_header_ignores_trailing_slack_5608() {
        // #5608: the IPv6-with-extension-header analogue of
        // `ipv6_segmentation_ignores_trailing_slack_beyond_payload_len`.
        // Declared datagram: 40 (fixed IP) + 8 (hop-by-hop) + 20 (TCP) +
        // 1400 (data) = 1468 > MTU 1280, so it MUST segment — but only the
        // 1400 declared bytes. 600 trailing SLACK_MARKER bytes past
        // payload_len must drop, AND the hop-by-hop ext chain must be
        // preserved verbatim in every emitted segment. The clamp math
        // depends on the ext-chain walk (`frame_l4_offset`) resolving the
        // TCP offset to l3 + 40 + 8, and on `ipv6_declared_l3_end` clamping
        // to l3 + 40 + payload_len (which includes the 8 ext bytes).
        let mtu = 1280usize;
        let declared_data = 1400usize;
        let slack = 600usize;
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        let decision = SessionDecision {
            resolution: plain_resolution(),
            nat: NatDecision::default(),
        };
        let frame = ipv6_tcp_frame_with_ext_and_slack(declared_data, slack);
        let segments = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v6_ext(),
            &decision,
            &state,
            false,
            None,
        )
        .expect("declared 1468 > 1280 MTU must segment");
        assert!(segments.len() >= 2, "1468 over 1280 MTU splits");
        // The IP header of every segment is fixed(40) + hop-by-hop(8).
        let ip_header_len = 40 + V6_EXT_LEN;
        let mut total_payload = 0usize;
        for (idx, seg) in segments.iter().enumerate() {
            // Ext chain preserved: fixed-header next-header stays 0 (HbH),
            // and the HbH block still points at TCP with hdr-ext-len 0.
            let eth = 14usize;
            assert_eq!(
                seg[eth + 6],
                0,
                "v6+ext segment {idx} lost the hop-by-hop next-header in the fixed header"
            );
            assert_eq!(
                seg[eth + 40],
                PROTO_TCP,
                "v6+ext segment {idx} corrupted the ext-chain next-header (should point at TCP)"
            );
            assert_eq!(
                seg[eth + 41],
                0,
                "v6+ext segment {idx} corrupted the ext-chain hdr-ext-len"
            );
            let payload = segment_tcp_payload_v6_ext(seg, ip_header_len);
            total_payload += payload.len();
            assert!(
                !payload.contains(&SLACK_MARKER),
                "v6+ext segment {idx} promoted trailing slack (0xEE) into TCP payload"
            );
        }
        assert_eq!(
            total_payload, declared_data,
            "v6+ext emitted TCP payload must equal the IP-declared data, not backing slack"
        );
    }

    #[test]
    fn ipv6_segmentation_rejects_declaration_shorter_than_headers_5608() {
        // #5608: the IPv6 twin of
        // `ipv4_segmentation_rejects_declaration_shorter_than_headers`. A
        // large backing buffer (1400 data bytes past L3, well over the MTU)
        // but a lying-short payload_len that declares only 10 bytes — fewer
        // than the 20 required for the TCP header (so the declared datagram,
        // 40 + 10 = 50 bytes, cannot even hold the fixed IP + TCP headers).
        // The datagram is a runt; it must NOT be segmented (fail closed), so
        // none of the 1400 backing bytes are promoted into fresh checksummed
        // segments. On a revert of the `ipv6_declared_l3_end` clamp the
        // builder would slice the full backing buffer (1460 bytes > MTU) and
        // chunk it, so `out` would be `Some`.
        let mtu = 1280usize;
        let mut state = ForwardingState::default();
        state.egress.insert(EGRESS_IFINDEX, egress_iface(mtu));
        let decision = SessionDecision {
            resolution: plain_resolution(),
            nat: NatDecision::default(),
        };
        // 1400 backing data bytes, but overwrite payload_len to a runt 10.
        let mut frame = ipv6_tcp_frame_with_slack(1400, 0);
        let runt_payload_len: u16 = 10;
        // IPv6 payload_len lives at frame bytes [l3 + 4 .. l3 + 6] = [18..20].
        frame[18] = (runt_payload_len >> 8) as u8;
        frame[19] = runt_payload_len as u8;
        let out = segment_forwarded_tcp_frames_from_frame(
            &frame,
            meta_v6(),
            &decision,
            &state,
            false,
            None,
        );
        assert!(
            out.is_none(),
            "a v6 declaration shorter than the IP+TCP headers must fail closed (not segment)"
        );
    }

    // ------- decap helper -------------------------------------------

    /// Decrypt one WG/UDP outer segment with the responder `engine` and
    /// return the inner IPv4 total-length field. Panics on any decode
    /// failure (the test wants a hard failure if the outer is malformed or
    /// — the revert case — a GRE frame that this WG decap cannot read).
    fn wg_decap_inner_ipv4_total_len(seg: &[u8], engine: &WgEngine) -> usize {
        // outer eth(14) + IPv4(20) + UDP(8) = 42 → WG data record.
        let wg_record = &seg[42..];
        let mut plain = [0u8; 4096];
        let dec = engine
            .try_decap(wg_record, &mut plain)
            .expect("WG outer must decrypt (a GRE revert would not)");
        let inner = &plain[..dec.len];
        assert_eq!(inner[0] >> 4, 4, "decapped inner must be IPv4");
        u16::from_be_bytes([inner[2], inner[3]]) as usize
    }

    /// Mirror of the GRE inner-MTU arithmetic for the no-key v4-outer
    /// fixture (20-byte outer IP + 4-byte GRE), so the GRE-unchanged test
    /// asserts against an explicit constant rather than re-calling the
    /// private helper indirectly.
    fn native_gre_inner_mtu_for_test(outer_mtu: usize) -> usize {
        outer_mtu - 20 - 4
    }
}

#[cfg(test)]
mod saturating_segment_len_8321 {
    use super::*;

    /// #8321 findings 19/20: the two computed-length casts in this file saturate
    /// rather than wrap.
    ///
    /// The wrap is NOT reachable through the production path, and that was
    /// measured — see the reachability note at the v4 site. So this cell binds
    /// the helper's behaviour at the boundary directly, because a cell driving
    /// the segmenter could only ever exercise lengths the MTU permits and would
    /// pass identically with a bare cast. A test that cannot distinguish the
    /// two implementations is not a test of the change.
    ///
    /// What it protects is the DIFFERENCE IN KIND: at 65536 a wrap yields 0 — a
    /// plausible small length that a receiver accepts — while a saturation
    /// yields 0xffff, wrong on the wire but never mistakable for valid.
    #[test]
    fn the_length_field_saturates_rather_than_wrapping_8321() {
        // The value that separates the two implementations. A bare `as u16`
        // gives 0 here; this is the whole reason the helper exists.
        assert_eq!(saturate_len16(65_536), u16::MAX);
        assert_eq!(65_536_usize as u16, 0, "the wrap this replaces");

        // 65540 -> 4 under a wrap: a small, entirely plausible length.
        assert_eq!(saturate_len16(65_540), u16::MAX);

        // CONTROL: every in-range value passes through untouched, so the
        // production path is byte-identical for all reachable inputs. Without
        // this, a helper that returned u16::MAX unconditionally would satisfy
        // the assertions above and corrupt every frame.
        for len in [0usize, 20, 1500, 9216, 65_534, 65_535] {
            assert_eq!(
                saturate_len16(len),
                len as u16,
                "in-range length {len} must pass through unchanged"
            );
        }
    }
}
