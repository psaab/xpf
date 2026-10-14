//! #12906: the `NoRoute` policy adjudication as a pure function.
//!
//! The `NoRoute` arm of `poll_binding_process_descriptor` cannot be driven
//! from this crate (it needs a live binding, a UMEM and a descriptor ring —
//! the #7480 note), so the two decisions the arm makes BEFORE the trailing
//! #1913 chokepoint hands a permitted frame to the kernel FIB are extracted
//! here, where a fixture can pin them:
//!
//!   1. WHICH zone pair adjudicates. The #6458 V2 owner-RG gate runs on the
//!      fabric zone stamp FIRST — the same binding the ForwardCandidate
//!      session-miss gate and the MissingNeighbor arm apply. Before #12906
//!      this branch took the RAW stamp, so a stamp whose owner RG was not
//!      forwarding-active locally drove the from-zone anyway.
//!   2. WHICH tuple adjudicates. The #2345 POST-translation destination:
//!      DNAT / static-DNAT / inbound NPTv6 via `decision.nat.rewrite_dst`
//!      (+ `rewrite_dst_port`), NAT64 via a dest-only re-classify — the same
//!      view the ForwardCandidate and MissingNeighbor paths match. Before
//!      #12906 the gate judged the PRE-NAT wire destination, so a deny
//!      written for the translated tuple missed (and a default-permit box
//!      delegated the untranslated frame to the kernel — the #2345 bypass),
//!      while a deny written for the wire tuple matched and cached the
//!      WRONG rule's denial id.
//!
//! Cold path only: this runs once per `NoRoute` disposition on the
//! session-miss epilogue, never per packet of an established flow.

use super::*;

/// The `NoRoute` arm's adjudication: everything the arm's deny handling and
/// the NAT fences below the gate need, in the shape they consume it.
pub(super) struct NoRoutePolicyAdjudication {
    /// The #6458 V2 owner-RG-gated fabric stamp. Every consumer below the
    /// arm's policy gate — the NAT translation fences and the
    /// `stage_flow_cache_deny_seed` call — must see THIS value, not the raw
    /// stamp (the same shadow discipline the session-miss block applies).
    pub(super) gated_ingress_zone_override: Option<u16>,
    pub(super) from_zone_id: u16,
    pub(super) to_zone_id: u16,
    /// The flow-backed/flowless distinction in ONE place, evaluated on the
    /// POST-translation destination port (`None` keeps the #7480/#3291
    /// flowless fail-closed contract: port-bearing terms do not match).
    pub(super) ports: Option<(u16, u16)>,
    /// `Some(result)` when the operator's policy DENIES the post-translation
    /// tuple; `None` when it is permitted and the kernel delegation stands
    /// (subject to the #10679/#11066 NAT translation fences at the call
    /// site, which this struct does not decide).
    pub(super) denial: Option<crate::policy::PolicyEvaluationResult>,
}

/// #12906: adjudicate a `NoRoute` frame's zone-pair policy on the
/// owner-RG-gated zone pair and the #2345 post-translation destination
/// tuple.
///
/// `adj_flow` is the arm's adjudication flow — the real session flow when
/// one was extracted, the synthetic L3 identity for a flowless packet — and
/// `flow_backed` says which (the NAT64 re-classification runs only for a
/// real flow, mirroring the #5174 MissingNeighbor arm). `nat` is the
/// decision's merged NAT state: for a same-family inbound destination
/// translation it already carries `rewrite_dst` / `rewrite_dst_port` (set at
/// the decision build as `nptv6_nat.or(pre_routing_dnat)`), which is exactly
/// the translated tuple the ForwardCandidate path's
/// `policy_dst_ip`/`policy_dst_port` collapse to. NAT64's forward decision
/// is minted only in the ForwardCandidate Permit branch, so a NoRoute NAT64
/// flow arrives with a default `nat`; its post-translation destination is
/// recovered by the same dest-only `classify_ipv6_dest` the MissingNeighbor
/// arm uses (source eligibility / RFC 6146 §3.5 hairpin rejection already
/// ran in the pre-routing classify). Both halves fall back to the wire
/// tuple when no inbound destination translation applies, so an untranslated
/// NoRoute flow adjudicates exactly as before.
#[allow(clippy::too_many_arguments)]
pub(super) fn noroute_policy_adjudication(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_logical: i32,
    ingress_zone_override: Option<u16>,
    resolution: ForwardingResolution,
    nat: crate::nat::NatDecision,
    flow_backed: bool,
    adj_flow: &SessionFlow,
    protocol: u8,
    l4_present: bool,
    policy_icmp: Option<(u8, u8)>,
    packet_len: u64,
    now_ns: u64,
) -> NoRoutePolicyAdjudication {
    // #6458 V2 / #12906: same owner-RG binding as the ForwardCandidate
    // session-miss gate and the MissingNeighbor arm — a zone-encoded fabric
    // stamp drives this policy adjudication only when the resolution's owner
    // RG is forwarding-active locally. For a base NoRoute (`egress_ifindex:
    // 0`) the owner RG is unknown (0), so the stamp degrades to the fabric
    // interface's own zone there; a tunnel NoRoute that retains its logical
    // egress keeps the stamp iff that egress's RG is locally active.
    let gated_ingress_zone_override = crate::afxdp::forwarding::gate_fabric_zone_override_on_owner_rg(
        forwarding,
        ha_state,
        now_secs,
        ingress_zone_override,
        resolution,
    );
    let (from_zone_id, to_zone_id) = crate::afxdp::forwarding::zone_pair_ids_for_flow_with_override(
        forwarding,
        ingress_logical,
        gated_ingress_zone_override,
        resolution.egress_ifindex,
    );
    // #12906 (#2345 parity with the ForwardCandidate session-miss gate and
    // the #5174/#10267 MissingNeighbor arm): judge the POST-translation
    // destination tuple so a NAT-dependent deny lands here exactly as it
    // would on the resolved path. See the module doc for the two halves.
    let nat64_dst_v4 = flow_backed
        .then(|| {
            if nat.rewrite_dst.is_some() {
                return None;
            }
            match adj_flow.dst_ip {
                IpAddr::V6(dst_v6) => {
                    match forwarding.nat64.classify_ipv6_dest(dst_v6) {
                        crate::nat64::Nat64Match::MatchReady { dst_v4, .. } => Some(dst_v4),
                        _ => None,
                    }
                }
                IpAddr::V4(_) => None,
            }
        })
        .flatten();
    let policy_dst_ip = match nat64_dst_v4 {
        Some(dst_v4) => IpAddr::V4(dst_v4),
        None => nat.rewrite_dst.unwrap_or(adj_flow.dst_ip),
    };
    let policy_dst_port = nat.rewrite_dst_port.unwrap_or(adj_flow.forward_key.dst_port);
    let ports = l4_present.then(|| (adj_flow.forward_key.src_port, policy_dst_port));
    let denial = crate::afxdp::forwarding::noroute_policy_denial_gated_at(
        forwarding,
        from_zone_id,
        to_zone_id,
        resolution.egress_ifindex,
        adj_flow.src_ip,
        policy_dst_ip,
        protocol,
        ports,
        policy_icmp,
        packet_len,
        now_ns,
    );
    NoRoutePolicyAdjudication {
        gated_ingress_zone_override,
        from_zone_id,
        to_zone_id,
        ports,
        denial,
    }
}

#[cfg(test)]
#[path = "noroute_adjudication_12906_tests.rs"]
mod noroute_adjudication_12906_tests;
