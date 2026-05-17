use super::*;
use crate::INJECT_PACKET_TUPLE_PROTOCOL_VERSION;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InjectedPacketTuple {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub addr_family: u8,
    pub protocol: u8,
}

pub(super) fn validate_injected_packet_tuple(
    req: &InjectPacketRequest,
    dst: IpAddr,
) -> Result<InjectedPacketTuple, String> {
    if req.tuple_metadata_version != INJECT_PACKET_TUPLE_PROTOCOL_VERSION {
        return Err(format!(
            "emit-on-wire requires tuple metadata version {} (got {})",
            INJECT_PACKET_TUPLE_PROTOCOL_VERSION, req.tuple_metadata_version
        ));
    }
    let source_ip = req
        .source_ip
        .parse::<IpAddr>()
        .map_err(|e| format!("invalid injected source_ip {}: {e}", req.source_ip))?;
    let source_port = req
        .source_port
        .ok_or_else(|| "emit-on-wire requires source_port tuple metadata".to_string())?;
    let destination_port = req
        .destination_port
        .ok_or_else(|| "emit-on-wire requires destination_port tuple metadata".to_string())?;
    let (addr_family, protocol) = match (source_ip, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => (libc::AF_INET as u8, PROTO_ICMP),
        (IpAddr::V6(_), IpAddr::V6(_)) => (libc::AF_INET6 as u8, PROTO_ICMPV6),
        _ => {
            return Err(
                "emit-on-wire source_ip and destination_ip must use the same address family"
                    .to_string(),
            );
        }
    };
    if req.addr_family != addr_family {
        return Err(format!(
            "emit-on-wire tuple addr_family {} does not match packet family {}",
            req.addr_family, addr_family
        ));
    }
    if req.protocol != protocol {
        return Err(format!(
            "emit-on-wire supports only protocol {} for this address family (got {})",
            protocol, req.protocol
        ));
    }

    Ok(InjectedPacketTuple {
        source_ip,
        destination_ip: dst,
        source_port,
        destination_port,
        addr_family,
        protocol,
    })
}

pub(super) fn stamp_injected_packet_tuple(
    meta: &mut UserspaceDpMeta,
    frame_len: usize,
    tuple: InjectedPacketTuple,
    egress: &EgressInterface,
) -> Result<(), String> {
    meta.pkt_len = frame_len.min(u16::MAX as usize) as u16;
    let l3_offset = if egress.vlan_id > 0 { 18 } else { 14 };
    meta.l3_offset = l3_offset;
    meta.flow_src_addr = [0; 16];
    meta.flow_dst_addr = [0; 16];
    meta.flow_src_port = tuple.source_port;
    meta.flow_dst_port = tuple.destination_port;
    meta.addr_family = tuple.addr_family;
    meta.protocol = tuple.protocol;

    match (tuple.source_ip, tuple.destination_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            meta.l4_offset = l3_offset + 20;
            meta.payload_offset = meta.l4_offset + 8;
            meta.flow_src_addr[..4].copy_from_slice(&src_v4.octets());
            meta.flow_dst_addr[..4].copy_from_slice(&dst_v4.octets());
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            meta.l4_offset = l3_offset + 40;
            meta.payload_offset = meta.l4_offset + 8;
            meta.flow_src_addr.copy_from_slice(&src_v6.octets());
            meta.flow_dst_addr.copy_from_slice(&dst_v6.octets());
        }
        _ => return Err("injected tuple address family mismatch".to_string()),
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
                        let tuple = validate_injected_packet_tuple(&req, dst)?;
                        let frame = build_injected_packet(
                            &req,
                            tuple.source_ip,
                            tuple.destination_ip,
                            tuple.source_port,
                            resolution,
                            egress,
                        )?;
                        let mut tx_meta = meta;
                        stamp_injected_packet_tuple(&mut tx_meta, frame.len(), tuple, egress)?;
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
