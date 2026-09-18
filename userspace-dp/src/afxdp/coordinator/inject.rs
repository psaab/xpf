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

/// #6563: is `ip` an address THIS FIREWALL answers for?
///
/// `local_v4`/`local_v6` are the GLOBAL local-address membership sets — every
/// interface host address plus every static-NAT/DNAT external IP, table
/// agnostic. Global membership is the right question for SOURCE validation
/// ("is this address ours at all?"), which is deliberately weaker than the
/// table-scoped test `lookup_forwarding_resolution` uses to DECIDE local
/// delivery: an address owned only in another VRF is still ours, and emitting
/// from it is not third-party spoofing.
pub(super) fn is_firewall_local_address(state: &ForwardingState, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => state.local_v4.contains(&v4),
        IpAddr::V6(v6) => state.local_v6.contains(&v6),
    }
}

pub(super) fn validate_injected_packet_tuple(
    req: &InjectPacketRequest,
    dst: IpAddr,
    forwarding: &ForwardingState,
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

    // #6563: `--emit-on-wire` puts a real frame on a real egress interface, and
    // the emit path runs FIB, HA and CoS/output-filter processing but NEVER
    // security policy, screen, or any source check — so before this an
    // operator-arbitrary `source_ip` was emitted verbatim. That is a spoofing
    // primitive, not a diagnostic: the usual "loopback gRPC, therefore
    // administrator-only" bound does not hold here, because #5278 establishes
    // that any provisioned login-class shell user reaches this plane.
    //
    // The source must therefore be an address the firewall itself owns. This
    // gate is on the EMIT path only — `inject-packet` WITHOUT `--emit-on-wire`
    // classifies a synthetic packet and puts nothing on the wire, so it keeps
    // its full diagnostic range including foreign sources.
    if !is_firewall_local_address(forwarding, source_ip) {
        return Err(format!(
            "emit-on-wire source_ip {source_ip} is not an address this firewall \
             owns — emitting it would put a spoofed source on the wire, \
             bypassing the security policy and screen that govern transit \
             traffic; use a local interface or static-NAT address"
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
        // #2443: bound the operator/API-supplied packet length up front,
        // before touching any binding/live state or allocating. An
        // injected packet is emitted as a single unfragmented frame that
        // must fit in one UMEM frame on the TX path, and the limit keeps
        // the IPv4 total-length / IPv6 payload-length wire fields within
        // u16. Keep the 64-byte minimum (applied below), but REJECT (do
        // not clamp) a value above the maximum so an API misuse / DoS
        // attempt surfaces as an error rather than being silently masked.
        Self::check_inject_packet_length(req.packet_length)?;
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
                        let tuple =
                            validate_injected_packet_tuple(&req, dst, &self.forwarding)?;
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
                        // #2362 fold B: classify the injected control packet on
                        // its own stamped tuple — the frame + stamped meta give
                        // the fragment-safe per-packet match inputs.
                        let cos_extra =
                            crate::afxdp::frame::term_match_extra_from_frame(&frame, tx_meta);
                        let cos = resolve_cos_tx_selection_at(
                            &self.forwarding,
                            resolution.egress_ifindex,
                            tx_meta,
                            cos_flow.as_ref().map(|flow| &flow.forward_key),
                            cos_extra,
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
                            overlap_admissions: None,
                            enqueue_ns: 0,
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

    /// #2443: reject an inject request whose packet length exceeds the
    /// maximum. Extracted as a pure associated function so the bound is
    /// unit-testable without standing up a full coordinator with bound
    /// workers. Over-max is REJECTED, not clamped.
    pub(super) fn check_inject_packet_length(packet_length: u32) -> Result<(), String> {
        if packet_length > crate::afxdp::MAX_INJECT_PACKET_LENGTH {
            return Err(format!(
                "inject packet_length {} exceeds maximum {}",
                packet_length,
                crate::afxdp::MAX_INJECT_PACKET_LENGTH
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod inject_length_tests {
    use super::super::Coordinator;

    #[test]
    fn over_max_packet_length_is_rejected() {
        // Fail-on-revert: restoring the old `.max(64)` min-only clamp
        // (i.e. dropping this bound) makes this assertion fail.
        let err = Coordinator::check_inject_packet_length(
            crate::afxdp::MAX_INJECT_PACKET_LENGTH + 1,
        )
        .expect_err("over-max inject length must be rejected");
        assert!(err.contains("exceeds maximum"), "unexpected error: {err}");
    }

    #[test]
    fn giant_packet_length_is_rejected() {
        assert!(Coordinator::check_inject_packet_length(1_000_000).is_err());
    }

    #[test]
    fn at_max_packet_length_is_accepted() {
        assert!(
            Coordinator::check_inject_packet_length(crate::afxdp::MAX_INJECT_PACKET_LENGTH).is_ok()
        );
    }

    #[test]
    fn small_packet_length_is_accepted() {
        assert!(Coordinator::check_inject_packet_length(128).is_ok());
        assert!(Coordinator::check_inject_packet_length(0).is_ok());
    }
}
