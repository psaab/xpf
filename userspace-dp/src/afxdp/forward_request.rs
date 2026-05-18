// Forward-request builders extracted from afxdp.rs (Issue 67.4).
//
// `build_live_forward_request` and `build_live_forward_request_from_frame`
// pack a per-packet ForwardingResolution + SessionMetadata into the
// LiveForwardRequest descriptor that the dispatch path enqueues.
//
// `should_install_local_reverse_session` is the small predicate that
// decides whether the reverse-direction session entry should be
// pre-installed locally vs lazily on first reverse-direction packet.
//
// Pure relocation. `use super::*;` brings every type and helper from
// afxdp.rs into scope.

use super::*;

pub(super) fn should_install_local_reverse_session(
    decision: SessionDecision,
    fabric_ingress: bool,
) -> bool {
    let fabric_wire_placeholder =
        shared_ops::is_fabric_wire_placeholder(fabric_ingress, false, decision);
    decision.resolution.disposition != ForwardingDisposition::FabricRedirect
        || (fabric_ingress && !fabric_wire_placeholder)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_live_forward_request(
    area: &MmapArea,
    binding_lookup: &WorkerBindingLookup,
    current_binding_index: usize,
    ingress_ident: &BindingIdentity,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    fabric_ingress_zone: Option<u16>,
    apply_nat_on_fabric: bool,
    now_ns: u64,
) -> Option<PendingForwardRequest> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_live_forward_request_from_frame(
        binding_lookup,
        current_binding_index,
        ingress_ident,
        desc,
        frame,
        meta,
        decision,
        forwarding,
        flow,
        fabric_ingress_zone,
        apply_nat_on_fabric,
        now_ns,
        None,
        None,
    )
}

pub(super) fn build_live_forward_request_from_frame(
    binding_lookup: &WorkerBindingLookup,
    current_binding_index: usize,
    ingress_ident: &BindingIdentity,
    desc: XdpDesc,
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    fabric_ingress_zone: Option<u16>,
    apply_nat_on_fabric: bool,
    now_ns: u64,
    hints: Option<PendingForwardHints>,
    precomputed_tx_selection: Option<&CachedTxSelectionDescriptor>,
) -> Option<PendingForwardRequest> {
    let hints = hints.unwrap_or_default();
    let target_ifindex = if decision.resolution.tx_ifindex > 0 {
        decision.resolution.tx_ifindex
    } else {
        resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
    };
    // Prefer session flow ports (set by conntrack, immune to DMA races),
    // then live frame ports (lazy — only parsed if session ports unavailable),
    // then metadata as last resort.
    let expected_ports = hints
        .expected_ports
        .or_else(|| authoritative_forward_ports(frame, meta, flow));
    let target_binding_index = hints.target_binding_index.or_else(|| {
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            binding_lookup.fabric_target_index(
                target_ifindex,
                fabric_queue_hash(flow, expected_ports, meta),
            )
        } else {
            binding_lookup.target_index(
                current_binding_index,
                ingress_ident.ifindex,
                ingress_ident.queue_id,
                target_ifindex,
            )
        }
    });
    let mut decision = *decision;
    // #919/#922: ID-keyed redirect — no `zone_id_to_name` round-trip.
    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        && let Some(ingress_zone_id) = fabric_ingress_zone
        && let Some(zone_redirect) =
            resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone_id)
    {
        decision.resolution.src_mac = zone_redirect.src_mac;
    }
    let fallback_flow;
    let tx_selection_flow = if flow.is_some() {
        flow
    } else {
        fallback_flow = parse_session_flow_from_meta(meta);
        fallback_flow.as_ref()
    };
    let cos = precomputed_tx_selection
        .map(|selection| CoSTxSelection {
            queue_id: selection.queue_id,
            dscp_rewrite: selection.dscp_rewrite,
            drop: false,
        })
        .unwrap_or_else(|| {
            resolve_cos_tx_selection_at(
                forwarding,
                decision.resolution.egress_ifindex,
                meta,
                tx_selection_flow.map(|flow| &flow.forward_key),
                now_ns,
            )
        });
    if cos.drop {
        return None;
    }
    Some(PendingForwardRequest {
        target_ifindex,
        target_binding_index,
        ingress_queue_id: ingress_ident.queue_id,
        desc,
        frame: PendingForwardFrame::Live,
        meta: meta.into(),
        decision,
        apply_nat_on_fabric,
        expected_ports,
        flow_key: tx_selection_flow.map(|flow| flow.forward_key.clone()),
        nat64_reverse: None,
        cos_queue_id: cos.queue_id,
        dscp_rewrite: cos.dscp_rewrite,
        cos_tx_selection_resolved: true,
    })
}
