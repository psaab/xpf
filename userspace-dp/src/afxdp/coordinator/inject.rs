use super::*;

pub(super) fn stamp_injected_packet_tuple(
    meta: &mut UserspaceDpMeta,
    frame_len: usize,
    dst: IpAddr,
    egress: &EgressInterface,
    slot: u32,
) -> Result<(), String> {
    meta.pkt_len = frame_len.min(u16::MAX as usize) as u16;
    let l3_offset = if egress.vlan_id > 0 { 18 } else { 14 };
    meta.l3_offset = l3_offset;
    meta.flow_src_addr = [0; 16];
    meta.flow_dst_addr = [0; 16];
    meta.flow_src_port = slot as u16;
    meta.flow_dst_port = 0;

    match dst {
        IpAddr::V4(dst_v4) => {
            let src_v4 = egress
                .primary_v4
                .ok_or_else(|| "egress interface has no IPv4 source address".to_string())?;
            meta.addr_family = libc::AF_INET as u8;
            meta.protocol = PROTO_ICMP;
            meta.l4_offset = l3_offset + 20;
            meta.payload_offset = meta.l4_offset + 8;
            meta.flow_src_addr[..4].copy_from_slice(&src_v4.octets());
            meta.flow_dst_addr[..4].copy_from_slice(&dst_v4.octets());
        }
        IpAddr::V6(dst_v6) => {
            let src_v6 = egress
                .primary_v6
                .ok_or_else(|| "egress interface has no IPv6 source address".to_string())?;
            meta.addr_family = libc::AF_INET6 as u8;
            meta.protocol = PROTO_ICMPV6;
            meta.l4_offset = l3_offset + 40;
            meta.payload_offset = meta.l4_offset + 8;
            meta.flow_src_addr.copy_from_slice(&src_v6.octets());
            meta.flow_dst_addr.copy_from_slice(&dst_v6.octets());
        }
    }

    Ok(())
}

/// `request inject-packet` RPC handler. Builds a synthetic packet
/// against the live ForwardingState/HA snapshot, runs it through the
/// resolution path, and reports the disposition.
///
/// Side effects on success: fills `last_resolution`, may bump
/// per-`BindingLiveState` counters, may push an entry into
/// `recent_exceptions`, and may enqueue a TX request on the chosen
/// binding. Lifecycle (worker spawn / shutdown / reconcile / HA) is
/// never touched.
impl super::Coordinator {
    pub fn inject_test_packet(&mut self, req: InjectPacketRequest) -> Result<(), String> {
        let binding = self
            .workers
            .identities
            .get(&req.slot)
            .ok_or_else(|| format!("unknown binding slot {}", req.slot))?;
        let live = self
            .workers
            .live
            .get(&req.slot)
            .ok_or_else(|| format!("binding slot {} has no live state", req.slot))?;
        let ident = binding.clone();
        let packet_length = req.packet_length.max(64);

        if req.metadata_valid {
            let meta = UserspaceDpMeta {
                magic: USERSPACE_META_MAGIC,
                version: USERSPACE_META_VERSION,
                length: std::mem::size_of::<UserspaceDpMeta>() as u16,
                ingress_ifindex: ident.ifindex as u32,
                rx_queue_index: ident.queue_id,
                pkt_len: packet_length.min(u16::MAX as u32) as u16,
                addr_family: req.addr_family,
                protocol: req.protocol,
                config_generation: req.config_generation,
                fib_generation: req.fib_generation,
                ..UserspaceDpMeta::default()
            };
            live.metadata_packets.fetch_add(1, Ordering::Relaxed);
            let disposition = classify_metadata(meta, self.validation);
            record_disposition(
                &ident,
                live,
                super::DispositionCounters::Cold(live),
                disposition,
                packet_length,
                Some(meta),
                &self.recent_exceptions,
                &self.forwarding,
            );
            if disposition == PacketDisposition::Valid && !req.destination_ip.is_empty() {
                if let Ok(dst) = req.destination_ip.parse::<IpAddr>() {
                    let resolution = enforce_ha_resolution(
                        &self.forwarding,
                        &self.ha.rg_runtime,
                        lookup_forwarding_resolution(&self.forwarding, dst),
                    );
                    record_forwarding_disposition(
                        &ident,
                        super::DispositionCounters::Cold(live),
                        resolution,
                        packet_length,
                        Some(meta),
                        None,
                        &self.recent_exceptions,
                        &self.last_resolution,
                        &self.forwarding,
                    );
                    if req.emit_on_wire {
                        let Some(egress) = self.forwarding.egress.get(&resolution.egress_ifindex)
                        else {
                            return Err(format!(
                                "no egress interface metadata for ifindex {}",
                                resolution.egress_ifindex
                            ));
                        };
                        if resolution.disposition != ForwardingDisposition::ForwardCandidate {
                            return Err(format!(
                                "destination is not forwardable via userspace TX: {}",
                                resolution.status(None, &self.forwarding).disposition
                            ));
                        }
                        let target_slot = self
                            .workers
                            .identities
                            .values()
                            .find(|candidate| {
                                candidate.ifindex == egress.bind_ifindex
                                    && candidate.queue_id == ident.queue_id
                            })
                            .or_else(|| {
                                self.workers
                                    .identities
                                    .values()
                                    .find(|candidate| candidate.ifindex == egress.bind_ifindex)
                            })
                            .map(|candidate| candidate.slot)
                            .ok_or_else(|| {
                                format!(
                                    "no bound userspace slot for egress ifindex {}",
                                    egress.bind_ifindex
                                )
                            })?;
                        let target_live = self.workers.live.get(&target_slot).ok_or_else(|| {
                            format!("binding slot {} has no live state", target_slot)
                        })?;
                        let frame = build_injected_packet(&req, dst, resolution, egress)?;
                        let mut tx_meta = meta;
                        stamp_injected_packet_tuple(
                            &mut tx_meta,
                            frame.len(),
                            dst,
                            egress,
                            req.slot,
                        )?;
                        let now_ns = monotonic_nanos();
                        let cos_flow = parse_session_flow_from_meta(tx_meta);
                        let cos = resolve_cos_tx_selection_at(
                            &self.forwarding,
                            resolution.egress_ifindex,
                            tx_meta,
                            cos_flow.as_ref().map(|flow| &flow.forward_key),
                            now_ns,
                        );
                        if cos.drop {
                            return Ok(());
                        }
                        let flow_key = cos_flow.map(|flow| flow.forward_key);
                        target_live.enqueue_tx(TxRequest {
                            bytes: frame,
                            expected_ports: None,
                            expected_addr_family: tx_meta.addr_family,
                            expected_protocol: tx_meta.protocol,
                            flow_key,
                            egress_ifindex: resolution.egress_ifindex,
                            cos_queue_id: cos.queue_id,
                            dscp_rewrite: cos.dscp_rewrite,
                            mirror_clone: false,
                        })?;
                    }
                } else {
                    record_exception(
                        &self.recent_exceptions,
                        &ident,
                        "invalid_destination_ip",
                        packet_length,
                        Some(meta),
                        None,
                        &self.forwarding,
                    );
                }
            } else if req.emit_on_wire {
                return Err("emit-on-wire requires destination-ip and valid metadata".to_string());
            }
            return Ok(());
        }

        live.metadata_errors.fetch_add(1, Ordering::Relaxed);
        record_exception(
            &self.recent_exceptions,
            &ident,
            "metadata_parse",
            packet_length,
            None,
            None,
            &self.forwarding,
        );
        Ok(())
    }
}
