use super::*;

pub(super) const FABRIC_INGRESS_FLAG: u8 = 0x80;

pub(super) fn packet_ttl_would_expire(frame: &[u8], meta: UserspaceDpMeta) -> Option<bool> {
    if (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0 {
        return Some(false);
    }
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    match meta.addr_family as i32 {
        libc::AF_INET => Some(*frame.get(l3 + 8)? <= 1),
        libc::AF_INET6 => Some(*frame.get(l3 + 7)? <= 1),
        _ => None,
    }
}

pub(super) fn build_local_time_exceeded_request(
    frame: &[u8],
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    ingress_ident: &BindingIdentity,
    flow: &SessionFlow,
    forwarding: &ForwardingState,
    _dynamic_neighbors: &Arc<ShardedNeighborMap>,
    _ha_state: &BTreeMap<i32, HAGroupRuntime>,
    _now_secs: u64,
) -> Option<PendingForwardRequest> {
    if !matches!(packet_ttl_would_expire(frame, meta), Some(true)) {
        return None;
    }

    let egress = forwarding.egress.get(&ingress_ident.ifindex)?;
    let target_ifindex = if egress.bind_ifindex > 0 {
        egress.bind_ifindex
    } else {
        ingress_ident.ifindex
    };
    let prebuilt_frame = match meta.addr_family as i32 {
        libc::AF_INET => {
            build_local_time_exceeded_v4(frame, meta, ingress_ident.ifindex, forwarding)
        }
        libc::AF_INET6 => {
            build_local_time_exceeded_v6(frame, meta, ingress_ident.ifindex, forwarding)
        }
        _ => return None,
    }?;

    let now_ns = monotonic_nanos();
    let cos = resolve_cos_tx_selection_at(
        forwarding,
        ingress_ident.ifindex,
        meta,
        Some(&flow.forward_key),
        now_ns,
    );
    if cos.drop {
        return None;
    }
    Some(PendingForwardRequest {
        target_ifindex,
        target_binding_index: None,
        ingress_queue_id: ingress_ident.queue_id,
        desc,
        frame: PendingForwardFrame::Prebuilt(prebuilt_frame),
        meta: meta.into(),
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: ingress_ident.ifindex,
                tx_ifindex: target_ifindex,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: Some(egress.src_mac),
                tx_vlan_id: egress.vlan_id,
            },
            nat: NatDecision::default(),
        },
        apply_nat_on_fabric: false,
        expected_ports: None,
        flow_key: Some(flow.forward_key.clone()),
        nat64_reverse: None,
        cos_queue_id: cos.queue_id,
        dscp_rewrite: cos.dscp_rewrite,
        cos_tx_selection_resolved: true,
    })
}

fn ingress_reply_l2(frame: &[u8]) -> Option<([u8; 6], [u8; 6], u16)> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac = <[u8; 6]>::try_from(frame.get(0..6)?).ok()?;
    let src_mac = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    let vlan_id = if matches!(eth_proto, 0x8100 | 0x88a8) {
        let tci = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
        tci & 0x0fff
    } else {
        0
    };
    Some((src_mac, dst_mac, vlan_id))
}

pub(super) fn build_local_time_exceeded_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_vlan_id) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v4?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let dst_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let packet_len = total_len.min(packet.len());
    let quoted_len = packet_len.min(ihl.saturating_add(8));
    let vlan_id = if ingress_vlan_id > 0 {
        ingress_vlan_id
    } else {
        egress.vlan_id
    };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let total_len = 20usize.checked_add(8)?.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + total_len);
    write_eth_header(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        vlan_id,
        0x0800,
    );
    let ip_start = out.len();
    out.extend_from_slice(&[
        0x45,
        0x00,
        ((total_len as u16) >> 8) as u8,
        (total_len as u16) as u8,
        0x00,
        0x00,
        0x00,
        0x00,
        64,
        PROTO_ICMP,
        0,
        0,
    ]);
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());
    let ip_sum = checksum16(&out[ip_start..ip_start + 20]);
    out[ip_start + 10..ip_start + 12].copy_from_slice(&ip_sum.to_be_bytes());
    let icmp_start = out.len();
    out.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16(&out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

pub(super) fn build_local_time_exceeded_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_vlan_id) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v6?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let packet_len = (40 + payload_len).min(packet.len());
    let quoted_len = packet_len.min(48);
    let vlan_id = if ingress_vlan_id > 0 {
        ingress_vlan_id
    } else {
        egress.vlan_id
    };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let outer_payload_len = 8usize.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + 40 + outer_payload_len);
    write_eth_header(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] {
            fallback_src_mac
        } else {
            src_mac
        },
        vlan_id,
        0x86dd,
    );
    out.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        ((outer_payload_len as u16) >> 8) as u8,
        (outer_payload_len as u16) as u8,
        PROTO_ICMPV6,
        64,
    ]);
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());
    let icmp_start = out.len();
    out.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

/// Returns true if the protocol and ICMP type indicate an ICMP error message
/// (Destination Unreachable, Time Exceeded, Parameter Problem, Packet Too Big).
pub(super) fn is_icmp_error(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        PROTO_ICMP => matches!(icmp_type, 3 | 11 | 12),
        PROTO_ICMPV6 => matches!(icmp_type, 1 | 2 | 3 | 4),
        _ => false,
    }
}
