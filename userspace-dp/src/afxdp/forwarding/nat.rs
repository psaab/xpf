//! #5650: source-NAT flow matching and interface-NAT local resolution helpers.
//! Pure code-motion split out of `forwarding/mod.rs` (behavior-identical).

use super::*;

/// #3096: resolve the (ingress, egress) ifindex pair to the interface /
/// routing-instance identity the NAT scope match needs. Borrows the
/// forwarding maps for the lifetime of the match — no per-flow allocation. An
/// ifindex absent from a map yields "" (unscoped / default VRF), so a
/// zone-only or global rule-set is unaffected.
///
/// #9956 F-052: the INGRESS scope resolves on the LOGICAL unit
/// (`resolve_ingress_logical_ifindex`), exactly like the zone / filter /
/// pre-routing-NAT admission sites (#3021/#5802) — the scope maps are keyed by
/// logical unit ifindex, and scoping on the raw physical parent lets one
/// trunk unit match another unit's `from interface` / `from routing-instance`
/// rule. An untagged port resolves logical == physical (byte-identical).
/// `egress_ifindex` is already a resolved logical egress — connected routes
/// carry their unit row's own ifindex (`forwarding_build/interfaces.rs`) and
/// static next-hops resolve through the unit-name map — and is used as-is.
pub(in crate::afxdp) fn nat_scope_ctx_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    egress_ifindex: i32,
    // #9062: SessionKey.routing_domain, passed through rather than re-derived.
    // Re-deriving it here would also need the fabric-encoded zone, and a value
    // that disagreed with the session layer's would make the HA-synced reserve
    // fail to match the flow the active reserved.
    routing_domain: u32,
) -> crate::nat::NatScopeCtx<'_> {
    let logical_ingress =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
            .unwrap_or(ingress_ifindex);
    let name = |ifindex: i32| -> &str {
        forwarding
            .ifindex_to_config_name
            .get(&ifindex)
            .map(String::as_str)
            .unwrap_or("")
    };
    let ri = |ifindex: i32| -> &str {
        forwarding
            .ifindex_to_routing_instance
            .get(&ifindex)
            .map(String::as_str)
            .unwrap_or("")
    };
    crate::nat::NatScopeCtx {
        ingress_ifname: name(logical_ingress),
        egress_ifname: name(egress_ifindex),
        ingress_routing_instance: ri(logical_ingress),
        egress_routing_instance: ri(egress_ifindex),
        routing_domain,
    }
}

// #9902 review: TEST-ONLY — it funnels into the #[cfg(test)]-gated
// `match_source_nat` (Untracked allocator). Was `allow(dead_code)`; the gate
// is what keeps a production caller from silently inheriting it.
#[cfg(test)]
pub(in crate::afxdp) fn match_source_nat_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
) -> Option<NatDecision> {
    let egress = forwarding.egress.get(&egress_ifindex)?;
    let scope = nat_scope_ctx_for_flow(forwarding, ingress_ifindex, ingress_vlan_id,
        egress_ifindex, flow.forward_key.routing_domain);
    match_source_nat(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        &scope,
        from_zone,
        to_zone,
        flow.src_ip,
        flow.dst_ip,
        egress.primary_v4,
        egress.primary_v6,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn match_source_nat_for_flow_result(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_for_flow_result_at(
        forwarding,
        ingress_ifindex,
        ingress_vlan_id,
        from_zone,
        to_zone,
        egress_ifindex,
        flow,
        0,
        false,
        // #6522: no worker context in this `#[cfg_attr(not(test),
        // allow(dead_code))]` helper — keep the untracked contract.
        crate::nat::NatHolder::Untracked,
        &mut counter,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn match_source_nat_for_flow_result_at(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
    now_ns: u64,
    // #1852: gate pool-mode SNAT allocation for non-first fragments.
    non_first_fragment: bool,
    // #6522: the worker whose packet path is allocating, recorded as the
    // allocation's own holder so a sibling worker's replica of the resulting
    // session cannot free a `(pool_addr, port)` this worker still forwards
    // through. See `nat::NatHolder`.
    holder: crate::nat::NatHolder,
    // #2218: out-param — the matched SNAT rule's per-rule hit counter.
    matched_counter: &mut Option<std::sync::Arc<crate::nat::NatRuleCounter>>,
) -> SourceNatLookup {
    let Some(egress) = forwarding.egress.get(&egress_ifindex) else {
        return SourceNatLookup::NoMatch;
    };
    // #3096: resolve the interface / routing-instance scope for this flow.
    let scope = nat_scope_ctx_for_flow(forwarding, ingress_ifindex, ingress_vlan_id,
        egress_ifindex, flow.forward_key.routing_domain);
    crate::nat::match_source_nat_result_for_tuple(
        // #6751: interface-mode SNAT mints its translated identity here.
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        &scope,
        from_zone,
        to_zone,
        flow.src_ip,
        flow.dst_ip,
        // #5687: a real packet always carries a concrete L4 protocol — including
        // IPv4 protocol 0 (HOPOPT) as `Some(0)`, distinct from the address-only
        // wrapper's `None` (tuple unknown). This is what lets a genuine
        // protocol-0 SNAT flow take the real address-only path and its reverse
        // tuple be matched.
        Some(flow.forward_key.protocol),
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        egress.primary_v4,
        egress.primary_v6,
        now_ns,
        non_first_fragment,
        // #4088 (RFC 5508 §3.1): a `SessionFlow` is only built for an
        // ICMP/ICMPv6 protocol when the frame parser matched an
        // identifier-bearing query type (`icmp_identifier_bearing`), so its
        // `src_port` holds a real Query Identifier — even when that id is 0.
        // Signal that authoritatively so pool SNAT translates the id instead
        // of dropping an id==0 query onto the address-only path.
        matches!(
            flow.forward_key.protocol,
            crate::ip_proto::PROTO_ICMP | crate::ip_proto::PROTO_ICMPV6
        ),
        holder,
        matched_counter,
    )
}

pub(in crate::afxdp) fn interface_nat_local_resolution(
    state: &ForwardingState,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    match dst {
        IpAddr::V4(ip) => state
            .interface_nat_v4
            .get(&ip)
            .copied()
            .map(|local_ifindex| ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex,
                egress_ifindex: local_ifindex,
                tx_ifindex: local_ifindex,
                tunnel_endpoint_id: state
                    .tunnel_endpoint_by_ifindex
                    .get(&local_ifindex)
                    .copied()
                    .unwrap_or_default(),
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }),
        IpAddr::V6(ip) => state
            .interface_nat_v6
            .get(&ip)
            .copied()
            .map(|local_ifindex| ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex,
                egress_ifindex: local_ifindex,
                tx_ifindex: local_ifindex,
                tunnel_endpoint_id: state
                    .tunnel_endpoint_by_ifindex
                    .get(&local_ifindex)
                    .copied()
                    .unwrap_or_default(),
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }),
    }
}

pub(in crate::afxdp) fn interface_nat_local_resolution_on_session_miss(
    state: &ForwardingState,
    dst: IpAddr,
    _protocol: u8,
) -> Option<ForwardingResolution> {
    interface_nat_local_resolution(state, dst)
}

pub(in crate::afxdp) fn should_block_tunnel_interface_nat_session_miss(
    state: &ForwardingState,
    dst: IpAddr,
    protocol: u8,
) -> bool {
    matches!(protocol, PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6)
        && matches!(
            interface_nat_local_resolution(state, dst),
            Some(local) if local.tunnel_endpoint_id != 0
        )
}
