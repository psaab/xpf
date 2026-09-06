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
/// WHAT THIS ACTUALLY DECIDES FOR NoRoute, stated plainly so no one reads more
/// into the generality of the signature than is there. Both `NoRoute`
/// constructors in `fib.rs` set `egress_ifindex: 0`, so the caller always
/// resolves `to_zone_id = 0` — the #3110 unzoned sentinel. #3110 makes a flow
/// with an unknown egress zone ineligible for BOTH zone-pair policies and
/// `junos-global`, so every NoRoute evaluation falls through to the DEFAULT
/// action. Consequences worth knowing before changing this:
///
///   * on a Junos-default deny box a NoRoute frame now DROPS — the intended fix,
///     and availability-visible on upgrade;
///   * an operator's `permit` rule for the ingress zone pair does NOT rescue it,
///     because no zone-pair rule is even consulted;
///   * the `ports` distinction below therefore does not change the outcome on
///     TODAY's only call path. It is honoured anyway so the helper stays correct
///     for a caller that supplies a resolved egress zone, and it is unit-tested
///     as a contract rather than left as an untested claim — but do not read the
///     port handling as load-bearing for NoRoute.
pub(in crate::afxdp) fn noroute_policy_denial(
    policy: &crate::policy::PolicyState,
    from_zone_id: u16,
    to_zone_id: u16,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    protocol: u8,
    ports: Option<(u16, u16)>,
    policy_icmp: Option<(u8, u8)>,
    packet_len: u64,
) -> Option<crate::policy::PolicyEvaluationResult> {
    let l4_present = ports.is_some();
    let (src_port, dst_port) = ports.unwrap_or((0, 0));
    let result = crate::policy::evaluate_policy_result_l3_aware(
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

/// #9054: `noroute_policy_denial` with the one precondition its soundness
/// depends on made explicit.
///
/// `noroute_policy_denial` answers "does the operator's policy deny this?" and
/// #7480's arm acts on the answer by DROPPING. That is right only while
/// `NoRoute` carries information — i.e. while the helper FIB is a
/// near-complete mirror of the kernel's, so a destination missing from it is
/// genuinely unroutable.
///
/// The #8355 learned-route cap suspends that. Above ~65,000 kernel routes the
/// daemon declines the ENTIRE learned-route import rather than a subset, so
/// every dynamically learned destination resolves `NoRoute` for a reason that
/// has nothing to do with the destination. Adjudicating there does not fail
/// closed; it black-holes the whole dynamic FIB, and #8355's own operator log
/// line asserted the opposite ("traffic still forwards through the kernel"),
/// so the first diagnostic an operator reads points away from the cause.
///
/// So when the snapshot says the import was withheld, this returns `None` and
/// the frame keeps the pre-#7480 slow-path delegation. Nothing else changes:
/// an uncapped snapshot takes the identical path it took before.
///
/// The gate is a wrapper rather than an `if` in the caller because the caller
/// (`poll_binding_process_descriptor`'s `NoRoute` arm) is not drivable from any
/// in-crate test — `slow_path_admit_single_site_6664.rs` guards it by reading
/// source. A function is testable; an inline branch there would not have been.
pub(in crate::afxdp) fn noroute_policy_denial_gated(
    forwarding: &ForwardingState,
    from_zone_id: u16,
    to_zone_id: u16,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    protocol: u8,
    ports: Option<(u16, u16)>,
    policy_icmp: Option<(u8, u8)>,
    packet_len: u64,
) -> Option<crate::policy::PolicyEvaluationResult> {
    if forwarding.learned_route_import_capped {
        return None;
    }
    noroute_policy_denial(
        &forwarding.policy,
        from_zone_id,
        to_zone_id,
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
    if let Some(zone) = fabric_ingress_zone {
        return forwarding
            .zone_routing_domain
            .get(&zone)
            .copied()
            .unwrap_or(0);
    }
    let logical = resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
        .unwrap_or(ingress_ifindex);
    forwarding
        .ifindex_to_routing_domain
        .get(&logical)
        .copied()
        .unwrap_or(0)
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
