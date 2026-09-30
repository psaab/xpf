use super::*;

mod host_inbound;
mod fib;
pub(in crate::afxdp) use fib::*;
mod tunnel;
pub(in crate::afxdp) use tunnel::*;
mod local_delivery;
pub(in crate::afxdp) use local_delivery::*;
mod pbr;
pub(in crate::afxdp) use pbr::*;
mod ipsec;
pub(in crate::afxdp) use ipsec::*;
mod mss;
mod ipsec_sa;
pub(in crate::afxdp) use ipsec_sa::*;
// #10868: test-only monitor probe and lifecycle skip gate shared by the
// XFRM-dependent coordinator/server lifecycle tests.
#[cfg(test)]
pub(crate) use self::ipsec_sa::{require_xfrm_monitor_for_lifecycle_test, xfrm_monitor_usable};
pub(in crate::afxdp) use mss::*;
mod ha;
pub(in crate::afxdp) use ha::*;
mod nat;
pub(in crate::afxdp) use nat::*;
mod fabric;
pub(in crate::afxdp) use fabric::*;
// #3070: re-export into the afxdp scope so the local-delivery admit path
// (poll_descriptor, via `use self::forwarding::*`) and the forwarding-state
// builder (forwarding_build::zones) can reach them.
pub(in crate::afxdp) use host_inbound::{
    host_inbound_admits, host_inbound_admits_iface, zone_host_inbound_from_snapshot,
    zone_host_inbound_from_tokens,
};

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn zone_pair_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (String, String) {
    zone_pair_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

pub(super) fn zone_pair_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<&str>,
    egress_ifindex: i32,
) -> (String, String) {
    // #921: this helper is `#[cfg_attr(not(test), allow(dead_code))]`
    // (see zone_pair_for_flow above) and is only called from tests.
    // After #921, `ifindex_to_zone_id` and `EgressInterface.zone_id`
    // are u16. Resolve back to the name via `zone_id_to_name` for
    // the test-only String API. Slow path; allocations are fine.
    let from_zone = ingress_zone_override
        .map(|zone| zone.to_string())
        .or_else(|| {
            forwarding
                .ifindex_to_zone_id
                .get(&ingress_ifindex)
                .and_then(|id| forwarding.zone_id_to_name.get(id).cloned())
        })
        .unwrap_or_default();
    // #6713: resolve through the shared `egress_zone_id` so this test-only
    // String twin cannot report a different to-zone than the production
    // u16 resolver below.
    let to_zone = match forwarding.egress_zone_id(egress_ifindex) {
        0 => String::new(),
        id => forwarding
            .zone_id_to_name
            .get(&id)
            .cloned()
            .unwrap_or_default(),
    };
    (from_zone, to_zone)
}

/// #919/#922: zero-allocation production zone-pair resolver. Returns
/// `(from_id, to_id)` u16 pair directly without `String` materialisation.
/// `ingress_zone_override` is `Option<u16>` (parsed from fabric MAC),
/// not `Option<&str>` — callers no longer round-trip through names.
/// Returns `(0, 0)` segments for ifindexes not in the zone maps; the
/// caller treats `0` as "unknown" and falls back to default policy.
#[inline]
/// #7480: the NoRoute slow-path adjudication decision, extracted so it can be
/// tested.
///
/// A `NoRoute` frame is slow-path eligible, so before #7480 it was reinjected to
/// the kernel FIB with no zone policy, session, NAT or screen — and nothing
/// downstream re-checks it. The destination is attacker-chosen, which is what
/// makes it the steerable half of #6664.
///
/// This lives here, as a function, for one reason: the call site is the NoRoute
/// arm of `poll_binding_process_descriptor`, which NO test in this crate can
/// drive (it needs a live binding, a UMEM and a descriptor ring — the same
/// reason #6664 had to use a source guard). Inlining the decision there would
/// make it unbindable; as a function the policy semantics are unit-testable and
/// only the wiring needs a source guard.
///
/// Returns `Some(result)` when the flow is DENIED and the caller must downgrade
/// the disposition to `PolicyDenied`; `None` when it is permitted and the
/// kernel delegation stands.
///
/// `ports` carries the flow-backed vs flowless distinction in ONE place, which
/// is the part that is easy to get wrong:
///   * `Some((src, dst))` — a real flow. Evaluated with its ports and
///     `l4_present = true`, so a port-bearing permit term still matches and a
///     permitted flow is not over-gated into a false drop.
///   * `None` — a flowless packet (non-first fragment / no L4). Evaluated with
///     ports 0 and `l4_present = false`, so port-bearing terms fail CLOSED while
///     address/protocol/`any` terms still match. Parity with the #3291 flowless
///     ForwardCandidate gate and the #4024 MissingNeighbor arm.
///
/// NoRoute may still carry a logical egress identity — for example, a tunnel
/// whose outer destination has no route. Use that identity to select the policy
/// gate: a nonzero logical egress evaluates its configured zone (and denies
/// zone 0), while `egress_ifindex == 0` has no zone to adjudicate and preserves
/// the existing default-policy behavior for kernel delegation.
///
pub(in crate::afxdp) fn noroute_policy_denial(
    policy: &crate::policy::PolicyState,
    from_zone_id: u16,
    to_zone_id: u16,
    egress_ifindex: i32,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    protocol: u8,
    ports: Option<(u16, u16)>,
    policy_icmp: Option<(u8, u8)>,
    packet_len: u64,
) -> Option<crate::policy::PolicyEvaluationResult> {
    let l4_present = ports.is_some();
    let (src_port, dst_port) = ports.unwrap_or((0, 0));
    let evaluate = if egress_ifindex != 0 {
        crate::policy::evaluate_policy_result_l3_aware
    } else {
        crate::policy::evaluate_policy_result_l3_aware_unresolved_egress
    };
    let result = evaluate(
        policy,
        from_zone_id,
        to_zone_id,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        policy_icmp,
        packet_len,
        l4_present,
    );
    if matches!(result.action, crate::policy::PolicyAction::Permit) {
        None
    } else {
        Some(result)
    }
}

/// #9522: the `NoRoute` adjudication entry point.
///
/// `noroute_policy_denial` answers "does the operator's policy deny this?" and
/// the NoRoute arm acts on the answer by DROPPING. That is the only safe
/// disposition now: #9054's capped-import exception restored kernel
/// delegation above the learned-route cap, but that made every kernel-routable
/// destination the helper did not import eligible for transit with no zone
/// policy, session, NAT or screen. #9522 owns that tradeoff and removes the
/// exception. A capped route miss and an uncapped route miss take this exact
/// same policy path.
///
/// The `ForwardingState` argument remains explicit because the caller's
/// runtime state carries the cap flag and the helper status reports it. The
/// flag is diagnostic state only; it is NOT a disposition predicate. Keeping
/// the entry point shared makes that contract visible and prevents a future
/// capped-only delegation fork from bypassing #7480 again.
///
/// Returns `Some(result)` when the flow is DENIED and the caller must downgrade
/// the disposition to `PolicyDenied`; `None` when it is permitted and the
/// kernel delegation stands.
///
/// `ports` carries the flow-backed vs flowless distinction in ONE place:
///   * `Some((src, dst))` — a real flow. Evaluated with its ports and
///     `l4_present = true`, so a port-bearing permit term still matches and a
///     permitted flow is not over-gated into a false drop.
///   * `None` — a flowless packet (non-first fragment / no L4). Evaluated with
///     ports 0 and `l4_present = false`, so port-bearing terms fail CLOSED while
///     address/protocol/`any` terms still match. Parity with the #3291 flowless
///     ForwardCandidate gate and the #4024 MissingNeighbor arm.
///
/// A base NoRoute resolution has `egress_ifindex: 0`, so it has no egress
/// identity and preserves the default-policy decision. Tunnel resolution may
/// remap an outer NoRoute onto a nonzero logical egress; that case evaluates
/// the logical zone, and resolved zone 0 is denied rather than defaulted.
/// #3110 still makes zone 0 ineligible for zone-pair and `junos-global` rules.
pub(in crate::afxdp) fn noroute_policy_denial_gated(
    forwarding: &ForwardingState,
    from_zone_id: u16,
    to_zone_id: u16,
    egress_ifindex: i32,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    protocol: u8,
    ports: Option<(u16, u16)>,
    policy_icmp: Option<(u8, u8)>,
    packet_len: u64,
) -> Option<crate::policy::PolicyEvaluationResult> {
    // The cap is deliberately not consulted here. It remains in
    // ForwardingState for the published diagnostic and metrics, while every
    // NoRoute frame is adjudicated fail-closed by the same predicate.
    noroute_policy_denial(
        &forwarding.policy,
        from_zone_id,
        to_zone_id,
        egress_ifindex,
        src_ip,
        dst_ip,
        protocol,
        ports,
        policy_icmp,
        packet_len,
    )
}

pub(super) fn zone_pair_ids_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<u16>,
    egress_ifindex: i32,
) -> (u16, u16) {
    // #921: single-hop direct lookup. Was two HashMap lookups
    // (ifindex → String → u16) and one String hash; now one
    // (ifindex → u16) for ingress and a struct field load for egress.
    let from_id = ingress_zone_override
        .or_else(|| forwarding.ifindex_to_zone_id.get(&ingress_ifindex).copied())
        .unwrap_or(0);
    // #6713: the to-zone comes from `ForwardingState::egress_zone_id`, which
    // reads `ifindex_unambiguous_zone_id` — the ONLY map it reads; the `egress`
    // arm this comment once described was removed once `populate_egress` began
    // sourcing `EgressInterface::zone_id` from that same ledger, so the two arms
    // had become the same number (see that function's doc, "WHY THERE IS NO
    // LONGER AN `egress` ARM"). NOT `ifindex_to_zone_id` — that map is the from-zone source
    // and carries the LAST zoned row on an ifindex plus the child->parent
    // propagation, so reading it as the to-zone hands an interface a zone the
    // operator never configured on it (#6722). An IPsec secure tunnel (xfrmi) NEVER has one — it is
    // MAC-less, and `populate_egress` requires a resolvable link-layer address
    // — so before this the to-zone of a correctly-zoned tunnel resolved to the
    // "unknown" sentinel 0, against which policy evaluation refuses to match
    // any rule, and every LAN->tunnel packet fell to the default policy no
    // matter what the operator permitted.
    let to_id = forwarding.egress_zone_id(egress_ifindex);
    (from_id, to_id)
}

/// #919/#922 test convenience: ID-pair without override.
#[cfg(test)]
pub(super) fn zone_pair_ids_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (u16, u16) {
    zone_pair_ids_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

pub(super) fn allow_unsolicited_dns_reply(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
) -> bool {
    forwarding.allow_dns_reply
        && flow.forward_key.protocol == PROTO_UDP
        && flow.forward_key.src_port == 53
}


pub(super) fn resolve_ingress_logical_ifindex(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> Option<i32> {
    forwarding
        .ingress_logical_ifindex
        .get(&(ingress_ifindex, ingress_vlan_id))
        .copied()
}

/// #10313/#10656/#11297: true when ingress does not belong to a configured
/// VLAN identity. A nonzero VID must resolve on the parent or configured child;
/// VID 0 is rejected on a tagged-only bind unless an explicit untagged unit 0
/// owns the fallback. Ordinary untagged ports keep the physical fallback.
///
/// The exact `(physical_ifindex, vlan_id)` map remains the logical-ingress
/// resolver. This predicate is its miss-path authority: unlike an ordinary
/// untagged-port miss, an unknown VID or VID 0 on a tagged-only bind must be
/// rejected before cache/session/ARP/decap can observe a fallback zone —
/// whether the fallback is an inherited sibling zone or the port's own zone.
/// XDP can also deliver on a configured VLAN child's own ifindex; the
/// parent-keyed resolver has no `(child_ifindex, VID)` row, so only that
/// child's configured VID is admitted on this miss path.
#[inline]
pub(in crate::afxdp) fn unknown_ingress_vlan(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> bool {
    if ingress_vlan_id == 0 {
        return forwarding
            .tagged_only_ingress_ifindexes
            .contains(&ingress_ifindex);
    }
    if forwarding
        .ingress_logical_ifindex
        .contains_key(&(ingress_ifindex, ingress_vlan_id))
    {
        return false;
    }
    !forwarding.egress.get(&ingress_ifindex).is_some_and(|iface| {
        iface.bind_ifindex != ingress_ifindex && iface.vlan_id == ingress_vlan_id
    })
}

/// #7160 (#2387): the ROUTING DOMAIN a received frame's flow belongs to — the
/// value stamped onto `SessionKey.routing_domain` so two routing instances
/// that share a 5-tuple are two conntrack entries rather than one.
///
/// Resolved from the LOGICAL (VLAN unit) ingress ifindex, exactly like the
/// zone / filter / pre-routing-NAT ingress identity (#3021/#5802): a trunk
/// whose units sit in different routing instances must not collapse onto its
/// parent's first unit. An interface in no routing instance — every interface
/// in a single-instance deployment — is domain 0.
///
/// **Why the INGRESS interface and nothing else.** The reverse key is built by
/// swapping the forward key's fields and never observes the reply packet, so
/// the domain has to be a quantity BOTH directions of a flow compute the same
/// way from their own arriving frame. The ingress interface's routing-instance
/// membership is that quantity for a flow contained in one instance. A PBR
/// `then routing-instance` assignment is NOT: the reply ingresses on an
/// interface the PBR term never touches, so an assigned-domain key could never
/// be recomputed on the reply. See `forwarding/README.md`.
///
/// **Fabric ingress.** A frame arriving over the fabric link did not arrive on
/// the flow's real ingress interface, so the fabric link's own membership (no
/// instance, domain 0) would be a wrong answer, not a missing one. When the
/// peer zone-encoded the ORIGINAL ingress zone into the frame, the domain is
/// resolved from that zone instead (`zone_routing_domain`), which is the same
/// identity the rest of the fabric-ingress path already adjudicates on. An
/// unencoded fabric frame has nothing to resolve and stays domain 0.
///
/// A missing entry for a validated, nonzero zone is a cross-instance ambiguity,
/// not the default instance: return the reserved per-zone session domain.
/// Invalid stamps are rejected earlier by stage 9 and never reach this helper.
/// Native table resolution has no owner row for the synthetic domain and
/// therefore fails closed instead of using MAIN (#11061).
#[inline]
pub(in crate::afxdp) fn ingress_routing_domain(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    fabric_ingress_zone: Option<u16>,
) -> u32 {
    // Single-bool gate: a deployment with no routing-instance interface
    // membership never probes either map, so its session identity is
    // bit-identical to pre-#7160.
    if !forwarding.has_routing_domains {
        return 0;
    }
    if let Some(zone) = fabric_ingress_zone.filter(|zone| *zone != 0) {
        return forwarding
            .zone_routing_domain
            .get(&zone)
            .copied()
            .unwrap_or(crate::session::AMBIGUOUS_FABRIC_DOMAIN_BASE | u32::from(zone));
    }
    let logical = resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
        .unwrap_or(ingress_ifindex);
    forwarding
        .ifindex_to_routing_domain
        .get(&logical)
        .copied()
        .unwrap_or(0)
}

/// Resolve the routing-instance identity of a forward session's egress
/// interface. Reverse-path admission compares the reply's arriving domain with
/// this value, not the forward key's ingress domain or its PBR install table.
#[inline]
pub(in crate::afxdp) fn egress_routing_domain(
    forwarding: &ForwardingState,
    egress_ifindex: i32,
) -> u32 {
    if !forwarding.has_routing_domains {
        return 0;
    }
    forwarding
        .ifindex_to_routing_domain
        .get(&egress_ifindex)
        .copied()
        .unwrap_or(0)
}

/// #10312/#11061: native routing-table resolution has three outcomes.
///
/// `Default` is the real unscoped/main instance; `Table` is a validated
/// per-family registry row; `Unresolvable` means a nonzero flow domain has no
/// current owner or family table. This includes the synthetic nonzero domain
/// for an ambiguous fabric zone. Callers MUST NOT turn the last state into
/// MAIN, because that recreates the RI-to-WAN leak.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum NativeRouteTable {
    Default,
    Table {
        table: String,
        domain: u32,
        check: u32,
    },
    Unresolvable {
        domain: u32,
    },
}

/// #11061 R3: the effective routing domain for one flow, shared by the
/// native-table resolver and the ambiguous-drop counter arms. A 9b-stamped
/// nonzero flow domain wins; otherwise (flowless/L3-only contexts carry
/// domain 0 by construction) fall back to the ingress/zone resolution, which
/// yields the synthetic quarantine domain for an ambiguous fabric zone.
/// The counter arms MUST use this helper — reading the raw flow domain
/// undercounts flowless quarantine drops (their flow is never 9b-stamped).
#[inline]
pub(in crate::afxdp) fn effective_routing_domain_for_flow(
    forwarding: &ForwardingState,
    flow_domain: u32,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    fabric_ingress_zone: Option<u16>,
) -> u32 {
    if flow_domain != 0 {
        flow_domain
    } else {
        ingress_routing_domain(
            forwarding,
            ingress_ifindex,
            ingress_vlan_id,
            fabric_ingress_zone,
        )
    }
}

/// #10312: resolve a native routing-instance member's destination table.
///
/// PBR remains an explicit override, but an interface's own routing-instance
/// membership is also a route-table scope. The packet path has already stamped
/// `flow_domain` from the logical ingress (`stage 9b`); the metadata fallback
/// exists for flowless/L3-only contexts that deliberately carry domain 0.
/// Returning the registry's collision check alongside the table keeps native
/// synthesis on the same install-identity path as PBR installation.
#[inline]
pub(in crate::afxdp) fn native_route_table_for_flow_target(
    forwarding: &ForwardingState,
    flow_domain: u32,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    fabric_ingress_zone: Option<u16>,
    target: IpAddr,
) -> NativeRouteTable {
    let domain = effective_routing_domain_for_flow(
        forwarding,
        flow_domain,
        ingress_ifindex,
        ingress_vlan_id,
        fabric_ingress_zone,
    );
    if domain == 0 {
        return NativeRouteTable::Default;
    }
    let Some(row) = forwarding.install_tables.get(&domain) else {
        return NativeRouteTable::Unresolvable { domain };
    };
    let Some(table) = (match target {
        IpAddr::V4(_) => row.v4.as_ref(),
        IpAddr::V6(_) => row.v6.as_ref(),
    }) else {
        return NativeRouteTable::Unresolvable { domain };
    };
    NativeRouteTable::Table {
        table: table.clone(),
        domain,
        check: row.h2,
    }
}
// #989: clamp_tcp_mss / clamp_tcp_mss_frame relocated to `frame/tcp.rs`.

#[cfg(test)]
mod tests;
// #7520: the ICMP global-accept family-pairing cells.
#[cfg(test)]
#[path = "tests_icmp_family_7520.rs"]
mod tests_icmp_family_7520;
// #7480: the NoRoute slow-path adjudication cells.
#[cfg(test)]
#[path = "tests_noroute_adjudication_7480.rs"]
mod tests_noroute_adjudication_7480;
// #9054: NoRoute under a DECLINED learned-route import.
#[cfg(test)]
#[path = "tests_noroute_capped_import_9054.rs"]
mod tests_noroute_capped_import_9054;
// #9522 Phase 0: selected lookup-semantic coverage for the route FIB (parity
// corpus for a future LPM cutover; test-only, no production change).
#[cfg(test)]
#[path = "tests_lpm_parity_9522.rs"]
mod tests_lpm_parity_9522;
// #11327: zero-disposition statics must not shadow an installable route.
#[cfg(test)]
#[path = "tests_zero_disposition_11327.rs"]
mod tests_zero_disposition_11327;
// #9955: the overlapping-leak resolution differential (kernel rule priority vs
// helper longest-prefix).
#[cfg(test)]
#[path = "tests_leak_overlap_9955.rs"]
mod tests_leak_overlap_9955;
// #9956 F-052: the SNAT scope must resolve on the logical ingress unit.
#[cfg(test)]
#[path = "tests_snat_scope_9956.rs"]
mod tests_snat_scope_9956;
// #10312: native routing-instance member resolution and controls.
#[cfg(test)]
#[path = "tests_ri_native_10312.rs"]
mod tests_ri_native_10312;
// #10691: L2 group-received unicast-IP transit is not PACKET_HOST.
#[cfg(test)]
#[path = "tests_pkt_type_10691.rs"]
mod tests_pkt_type_10691;
