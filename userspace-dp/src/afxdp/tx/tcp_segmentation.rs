use super::*;

#[cold]
pub(super) fn segment_forwarded_tcp_frames_into_prepared(
    target_binding: &mut BindingWorker,
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
    flow_key: Option<SessionKey>,
    cos_queue_id: Option<u8>,
    dscp_rewrite: Option<u8>,
    now_ns: u64,
    post_recycles: &mut Vec<(u32, u64)>,
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> Option<(u32, u64, u32)> {
    let meta = meta.into();
    if meta.protocol != PROTO_TCP || decision.resolution.tunnel_endpoint_id != 0 {
        return None;
    }
    let mtu = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or_default()
        .max(1280);
    if mtu == 0 {
        return None;
    }
    let l3 = frame_l3_offset(frame)?;
    if l3 >= frame.len() {
        return None;
    }
    let payload = &frame[l3..];
    if payload.len() <= mtu {
        return None;
    }
    let frame_l4 = frame_l4_offset(frame, meta.addr_family)?;
    let tcp_offset = frame_l4.checked_sub(l3)?;
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
    if (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)) != 0 {
        return None;
    }
    let segment_payload_max = mtu.checked_sub(ip_header_len + tcp_header_len)?;
    if segment_payload_max == 0 {
        return None;
    }
    let data = payload.get(tcp_offset + tcp_header_len..)?;
    if data.len() <= segment_payload_max {
        return None;
    }

    let segment_count = data.len().div_ceil(segment_payload_max);
    if target_binding.tx_pipeline.free_tx_frames.len() < segment_count
        && (target_binding.tx_pipeline.outstanding_tx > 0
            || !target_binding.tx_pipeline.pending_tx_prepared.is_empty()
            || !target_binding.tx_pipeline.pending_tx_local.is_empty())
    {
        let _ = drain_pending_tx_local_owner(
            target_binding,
            now_ns,
            post_recycles,
            forwarding,
            worker_id,
            worker_commands_by_id,
            cos_owner_worker_by_queue,
            cos_owner_live_by_queue,
        );
    }
    if target_binding.tx_pipeline.free_tx_frames.len() < segment_count {
        return None;
    }

    let dst_mac = decision.resolution.neighbor_mac?;
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
    let tcp_header = payload.get(tcp_offset..tcp_offset + tcp_header_len)?;
    let ip_header = payload.get(..ip_header_len)?;
    let mut prepared: Vec<PreparedTxRequest> = Vec::with_capacity(segment_count);
    let mut total_bytes = 0u64;
    let mut max_frame = 0u32;
    let mut data_offset = 0usize;
    while data_offset < data.len() {
        let chunk_len = (data.len() - data_offset).min(segment_payload_max);
        let is_last = data_offset + chunk_len == data.len();
        let total_ip_len = ip_header_len + tcp_header_len + chunk_len;
        let frame_len = eth_len + total_ip_len;
        if frame_len > tx_frame_capacity() {
            for req in prepared.drain(..).rev() {
                target_binding.tx_pipeline.free_tx_frames.push_front(req.offset);
            }
            return None;
        }
        let Some(tx_offset) = target_binding.tx_pipeline.free_tx_frames.pop_front() else {
            for req in prepared.drain(..).rev() {
                target_binding.tx_pipeline.free_tx_frames.push_front(req.offset);
            }
            return None;
        };
        let Some(frame_out) = (unsafe {
            target_binding
                .umem
                .area()
                .slice_mut_unchecked(tx_offset as usize, frame_len)
        }) else {
            target_binding.tx_pipeline.free_tx_frames.push_front(tx_offset);
            for req in prepared.drain(..).rev() {
                target_binding.tx_pipeline.free_tx_frames.push_front(req.offset);
            }
            return None;
        };

        let built = (|| -> Option<()> {
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

                let tcp = packet.get_mut(tcp_offset..)?;
                let seq = original_seq.wrapping_add(data_offset as u32);
                tcp.get_mut(4..8)?.copy_from_slice(&seq.to_be_bytes());
                if !is_last {
                    tcp[13] &= !TCP_FLAG_PSH;
                }
            }

            match meta.addr_family as i32 {
                libc::AF_INET => {
                    {
                        let packet = frame_out.get_mut(eth_len..)?;
                        packet
                            .get_mut(2..4)?
                            .copy_from_slice(&(total_ip_len as u16).to_be_bytes());
                        if packet[8] <= 1 {
                            return None;
                        }
                        if apply_nat {
                            apply_nat_ipv4(packet, meta.protocol, decision.nat)?;
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
                    )?;
                    let packet = frame_out.get_mut(eth_len..)?;
                    packet.get_mut(10..12)?.copy_from_slice(&[0, 0]);
                    let ip_sum = checksum16(packet.get(..ip_header_len)?);
                    packet
                        .get_mut(10..12)?
                        .copy_from_slice(&ip_sum.to_be_bytes());
                    recompute_l4_checksum_ipv4(packet, ip_header_len, meta.protocol, false)?;
                }
                libc::AF_INET6 => {
                    {
                        let packet = frame_out.get_mut(eth_len..)?;
                        packet
                            .get_mut(4..6)?
                            .copy_from_slice(&((tcp_header_len + chunk_len) as u16).to_be_bytes());
                        if (meta.meta_flags & 0x80) == 0 && packet[7] <= 1 {
                            return None;
                        }
                        if apply_nat {
                            apply_nat_ipv6(packet, meta.protocol, decision.nat)?;
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
                    )?;
                    let packet = frame_out.get_mut(eth_len..)?;
                    recompute_l4_checksum_ipv6(packet, meta.protocol)?;
                }
                _ => return None,
            }
            Some(())
        })();
        if built.is_none() {
            target_binding.tx_pipeline.free_tx_frames.push_front(tx_offset);
            for req in prepared.drain(..).rev() {
                target_binding.tx_pipeline.free_tx_frames.push_front(req.offset);
            }
            return None;
        }

        prepared.push(PreparedTxRequest {
            offset: tx_offset,
            len: frame_len as u32,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports,
            expected_addr_family: meta.addr_family,
            expected_protocol: meta.protocol,
            flow_key: flow_key.clone(),
            egress_ifindex: decision.resolution.egress_ifindex,
            cos_queue_id,
            dscp_rewrite,
        });
        total_bytes += frame_len as u64;
        max_frame = max_frame.max(frame_len as u32);
        data_offset += chunk_len;
    }

    for req in prepared {
        target_binding.tx_pipeline.pending_tx_prepared.push_back(req);
    }
    bound_pending_tx_prepared(target_binding);
    Some((segment_count as u32, total_bytes, max_frame))
}
