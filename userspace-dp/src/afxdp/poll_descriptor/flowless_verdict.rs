// #6386 leaf extraction: the flowless (no-L4) LocalDelivery verdict
// helpers (#3292/#3600/#4743/#6122), lifted verbatim out of
// poll_descriptor/mod.rs: enum FlowlessLocalVerdict,
// ipv6_ext_header_over_limit_drop, flowless_local_delivery_verdict,
// flowless_base_resolution. Each moved bare fn/enum becomes pub(super).
// The three per-packet-capable fns GAIN #[inline] (the only non-motion
// change — restores same-CGU inlining eligibility across the new module
// boundary per the #6386 hot-path contract). Bodies byte-identical to
// their prior location.

use super::filter::{emit_pending_filter_log, host_inbound_gated_lo0_action};
use super::host_inbound_policy::{
    emit_host_inbound_deny, emit_junos_host_deny, junos_host_policy_eval,
};
use super::*;

/// #3292: verdict for the FLOWLESS (no-L4) LocalDelivery security gate. A
/// host-bound flowless packet — a non-first IPv4/IPv6 fragment, or any
/// LocalDelivery packet with no readable L4 header (#2344) — MUST traverse the
/// same management-plane gates the flow-backed LocalDelivery arm applies:
/// host-inbound admission, the lo0 host-bound filter, and `to-zone junos-host`
/// policy. Before #3292 the flowless arm reinjected to the host ungated
/// (fail-open). The synthetic L3 flow carries ports = 0 and is evaluated with
/// `l4_present = false`, so port-bearing host-inbound / lo0 / junos-host terms
/// fail CLOSED while protocol/address/`any` terms still admit — fail-closed
/// without over-gating a legitimately-admitted protocol/address packet.
///
/// Extracted (vs inlined in the un-callable poll loop) so the gate decision is
/// unit-testable; see `flowless_local_delivery_tests`. The poll loop performs
/// the recycle/counter side-effects keyed on the returned verdict. A flowless
/// deny is SILENT (no L4 header to synthesize a reject/RST), mirroring the
/// flowless transit deny — the junos-host deny event is still emitted for parity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum FlowlessLocalVerdict {
    /// All gates passed (or none configured): deliver to the host.
    Deliver,
    /// Host-inbound denied — silent drop; account `host_inbound_denied_packets`.
    HostInboundDeny,
    /// lo0 host-bound filter discard/reject OR `to-zone junos-host` deny/reject —
    /// silent flowless drop.
    Filtered,
}

/// #4743/#10665: fail-closed drop gate for an over-limit IPv6 extension-header
/// chain. Returns `true` (and bumps `ipv6_ext_header_dropped` on `counters`)
/// when `frame` declares a traversable 8th header. Its bytes need not be
/// present: over-limit takes precedence over truncation at that bound. The
/// caller recycles the descriptor and continues. A truncation before the
/// 8th-header declaration, a real-L4 chain, or a non-IPv6 packet returns
/// `false` (unchanged flowless/normal handling). The caller gates this on
/// `flow.is_none()` so it fires only when the helper could not derive an L4
/// tuple; before #4743 that packet was forwarded flowless (`l4_present =
/// false`), an ext-header IDS-evasion. Factored out (rather than inlined) so it
/// is unit-testable for the RED-on-revert counter assertion.
#[inline]
pub(super) fn ipv6_ext_header_over_limit_drop(
    frame: &[u8],
    addr_family: u8,
    counters: &mut BatchCounters,
) -> bool {
    if crate::afxdp::frame::ipv6_ext_chain_over_limit(frame, addr_family) {
        counters.touched = true;
        counters.ipv6_ext_header_dropped += 1;
        return true;
    }
    false
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) fn flowless_local_delivery_verdict(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    extra: crate::filter::TermMatchExtra<'_>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    logical_ingress_ifindex: i32,
    from_zone_id: u16,
    ingress_zone_override: Option<u16>,
    packet_len: u64,
    now_ns: u64,
) -> FlowlessLocalVerdict {
    // A flowless packet's post-IP bytes are payload, never an authoritative L4
    // header, so the ICMP type/code is NOT known (`policy_packet_icmp` returns
    // None on the flow-backed sibling for the same reason). Derive it from the
    // frame-extra so a first-fragment that somehow reaches here with a readable
    // L4 header still supplies its type/code, but a non-first fragment
    // (l4_present = false) fails the ICMP-constrained terms closed.
    let packet_icmp = if extra.l4_present {
        Some((extra.icmp_type, extra.icmp_code))
    } else {
        None
    };
    // Host-inbound admission FIRST, then the lo0 host-bound filter (#3485
    // order). dst_port = 0 (no L4) and the frame-derived `extra`
    // (l4_present = false) so a port-bearing admit / lo0 term cannot match a
    // fragment; the ICMP first-L4-byte is 0 (absent), so the #3171 ICMP/ND
    // global accept does not falsely exempt a fragment whose type we cannot read.
    match host_inbound_gated_lo0_action(
        forwarding,
        logical_ingress_ifindex,
        from_zone_id,
        0,
        matches!(flow.dst_ip, IpAddr::V6(_)),
        0,
        extra,
        flow,
        meta,
        ingress_zone_override,
        now_ns,
    ) {
        None => {
            // #3610: emit the tuple-rich host-inbound deny event before the
            // silent flowless drop so an operator can see WHICH host-bound
            // flowless flow (a non-first fragment / no-L4 packet) the zone
            // host-inbound gate dropped. Reuses the policy-deny event machinery
            // via the shared helper, identical to the flow-backed arms.
            emit_host_inbound_deny(
                forwarding,
                event_stream,
                flow,
                meta,
                from_zone_id,
                flow.forward_key.dst_port,
                now_ns,
            );
            return FlowlessLocalVerdict::HostInboundDeny;
        }
        Some((action, lo0_log)) => {
            // #3615: flowless — no reply can be synthesized (a fragment has no
            // L4 header to build a RST/ICMP unreachable from), so emit the
            // matched lo0 filter-log with the truthful DENY
            // (reject_reply_enqueued = false).
            if let Some(lo0_log) = lo0_log {
                emit_pending_filter_log(event_stream, flow, meta, lo0_log, false, now_ns);
            }
            if !matches!(action, crate::filter::FilterAction::Accept) {
                return FlowlessLocalVerdict::Filtered;
            }
        }
    }
    // `to-zone junos-host` policy AFTER host-inbound admission (Junos order),
    // l4_present = false. A matching deny/reject is a SILENT flowless drop — a
    // fragment has no L4 header to synthesize a RST/ICMP reject from, so #3615
    // logs the truthful DENY (reject_reply_enqueued = false) for observability.
    // #3706: the eval now returns a matching PERMIT too; a flowless fragment is
    // NEVER installed as a session (this synthetic L3 tuple is evaluation- and
    // logging-only), so a permit simply falls through to Deliver with no
    // metadata to carry — only a deny/reject drives the flowless filter drop.
    if let Some(result) = junos_host_policy_eval(
        forwarding,
        flow,
        // #9529: the flowless arm applies no destination translation (a
        // translated flow's later fragments follow fragment association,
        // not this arm), so its wire destination IS its post-translation one.
        (flow.dst_ip, flow.forward_key.dst_port),
        from_zone_id,
        packet_len,
        false,
        packet_icmp,
        now_ns,
    ) {
        if !matches!(result.action, PolicyAction::Permit) {
            emit_junos_host_deny(
                forwarding,
                event_stream,
                flow,
                meta,
                flow.forward_key.dst_port,
                from_zone_id,
                result.policy_id,
                result.action,
                // Flowless: no reply is ever synthesized.
                false,
                now_ns,
            );
            return FlowlessLocalVerdict::Filtered;
        }
    }
    FlowlessLocalVerdict::Deliver
}

/// The flowless route result and any safe pre-routing destination rewrite.
pub(super) struct FlowlessBaseResolution {
    pub(super) resolution: ForwardingResolution,
    pub(super) nat: NatDecision,
    pub(super) dnat_counter: Option<std::sync::Arc<crate::nat::NatRuleCounter>>,
}

/// #3292 / #3600 / #11435: compute the base forwarding resolution for a
/// FLOWLESS (no-L4) packet. Address-only static-DNAT, DNAT, and inbound NPTv6
/// are resolved before local-address checks and the route lookup, matching the
/// flow-backed pre-routing order. Ambiguous or unsupported translations are
/// fail-closed for transit, but first retain untranslated LocalDelivery so its
/// existing host-inbound gates still run.
///
/// INGRESS-interface and interface-NAT local-delivery resolution are still
/// tried BEFORE the PBR (`then routing-instance`) override-aware route-table
/// lookup, so a host-bound flowless packet reaches `LocalDelivery` instead of
/// being steered into an override table that has no local route for it.
#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) fn flowless_base_resolution(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    l3_flow: &SessionFlow,
    meta: UserspaceDpMeta,
    nat_wire_info: super::frag_assoc::FlowlessNatWireInfo,
    ingress_zone_override: Option<u16>,
    fabric_ingress_scope_ifindex: Option<i32>,
    route_override: Option<&str>,
) -> Option<FlowlessBaseResolution> {
    let (nat, dnat_counter) = match super::frag_assoc::flowless_pre_routing_destination_nat(
        forwarding,
        l3_flow,
        meta,
        nat_wire_info,
        ingress_zone_override,
        fabric_ingress_scope_ifindex,
    ) {
        super::frag_assoc::FlowlessPreRoutingNat::None => (NatDecision::default(), None),
        super::frag_assoc::FlowlessPreRoutingNat::Translated { decision, counter } => {
            (decision, counter)
        }
        super::frag_assoc::FlowlessPreRoutingNat::Untranslatable => {
            let resolution = flowless_local_resolution(forwarding, meta, l3_flow.dst_ip)?;
            return Some(FlowlessBaseResolution {
                resolution,
                nat: NatDecision::default(),
                dnat_counter: None,
            });
        }
    };
    let dst = nat.rewrite_dst.unwrap_or(l3_flow.dst_ip);
    let resolution = flowless_local_resolution(forwarding, meta, dst).unwrap_or_else(|| {
        enforce_ha_resolution_snapshot(
            forwarding,
            ha_state,
            now_secs,
            lookup_forwarding_resolution_in_table_with_dynamic(
                forwarding,
                dynamic_neighbors,
                dst,
                route_override,
            ),
        )
    });
    if nat.rewrite_dst.is_some()
        && matches!(
            resolution.disposition,
            ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor
        )
    {
        return None;
    }
    Some(FlowlessBaseResolution {
        resolution,
        nat,
        dnat_counter,
    })
}

#[inline]
fn flowless_local_resolution(
    forwarding: &ForwardingState,
    meta: UserspaceDpMeta,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    ingress_interface_local_resolution_on_session_miss(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        dst,
        meta.protocol,
    )
    .or_else(|| interface_nat_local_resolution_on_session_miss(forwarding, dst, meta.protocol))
}

#[cfg(test)]
#[path = "flowless_verdict_tests.rs"]
mod tests;
