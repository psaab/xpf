//! #17031: the ONE admission zone-pair gate for session-miss transit
//! policy — generalised from the #12906 `NoRoute` adjudication module.
//!
//! Every session-MISS zone-pair computation (flow-backed miss, flowless
//! ForwardCandidate, MissingNeighbor, NoRoute, queued embedded ICMP) and
//! every non-policy consumer that must agree with it (zone-traffic
//! counters, flow-cache seed stamp) resolves its from-zone through
//! [`admission_zone_override`]: the #6458 V2 owner-RG gate plus the
//! #15916 ambiguous-stamp promotion, in that order, and nowhere else.
//! `gate_fabric_zone_override_on_owner_rg` is called only from this
//! module (and its definition in `forwarding::fabric`);
//! `promote_ambiguous_fabric_zone` is called only from
//! [`admission_zone_override`] / [`promoted_zone_override`] here.
//! Per-site copies of that chain repeatedly shipped subset fixes
//! (#4024, #12905, #12906, #12865, #15916, #16053); there is now a
//! single source of truth, guarded by `transit_policy_tests`.
//!
//!   1. WHICH zone pair adjudicates. [`admission_zone_override`] runs
//!      the owner-RG gate on the fabric zone stamp FIRST. Before
//!      #12906 the NoRoute branch took the RAW stamp, so a stamp whose
//!      owner RG was not forwarding-active locally drove the
//!      from-zone anyway; before #17031 the NoRoute, counter and seed
//!      copies never promoted an ambiguous stamp at all.
//!   2. WHICH tuple adjudicates. The #2345 POST-translation destination:
//!      DNAT / static-DNAT / inbound NPTv6 via `decision.nat.rewrite_dst`
//!      (+ `rewrite_dst_port`), NAT64 via the dest-only re-classify in
//!      [`nat64_dest_only_v4`] / [`post_translation_policy_dst`] — the
//!      same view every transit arm matches. Before #12906 the NoRoute
//!      gate judged the PRE-NAT wire destination, so a deny written for
//!      the translated tuple missed (and a default-permit box delegated
//!      the untranslated frame to the kernel — the #2345 bypass), while
//!      a deny written for the wire tuple matched and cached the WRONG
//!      rule's denial id.
//!
//! The NoRoute adjudication ([`transit_policy_adjudication`], née
//! `noroute_policy_adjudication`) keeps its denial-only evaluator
//! (`noroute_policy_denial_gated_at`: zero-egress exact-pair tiers plus
//! the default policy) — that verdict shape is NoRoute-specific and is
//! NOT interchangeable with the Permit-capable evaluators the other
//! arms use, so the arms share the gate / zone-pair / post-NAT tuple
//! helpers above and keep their own evaluators. Fail-closed direction
//! is unchanged at every migrated site.
//!
//! Cold path only: this runs once per session-miss disposition on the
//! slow path, never per packet of an established flow.

use super::*;

/// #17031: the ONE from-zone rule for session-miss admission.
///
/// `raw` is the validated (proved-punt) zone-encoded fabric stamp,
/// `ambiguous` the withheld claimed zone of a #15916 ambiguous stamp.
/// The claimed zone is promoted only by the packet's own owner-RG
/// proof (`promote_ambiguous_fabric_zone`), and the result — raw or
/// promoted — is then honored only when the resolution's owner RG is
/// forwarding-active locally (`gate_fabric_zone_override_on_owner_rg`,
/// the #6458 V2 gate). Returns `None` (the fabric interface's own
/// zone governs, default-deny) when neither claim survives.
///
/// This is exactly the chain the four promoted admission sites open-
/// coded before #17031 (`gate(raw.or_else(|| promote(ambiguous)))`);
/// the counter, seed and NoRoute copies passed `raw` alone and never
/// promoted — they now pass `ambiguous` here and gain the promotion.
#[inline]
pub(super) fn admission_zone_override(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    raw: Option<u32>,
    ambiguous: Option<u32>,
    resolution: ForwardingResolution,
) -> Option<u32> {
    crate::afxdp::forwarding::gate_fabric_zone_override_on_owner_rg(
        forwarding,
        ha_state,
        now_secs,
        raw.or_else(|| {
            crate::afxdp::forwarding::promote_ambiguous_fabric_zone(
                forwarding, ha_state, now_secs, ambiguous, resolution,
            )
        }),
        resolution,
    )
}

/// #17031: the ungated half of the from-zone rule for consumers that
/// adjudicate RELATED / arrival zone on a finalized resolution and
/// must NOT re-gate a proved punt (embedded-ICMP match arms, NAT64
/// ICMP-error arms): `raw.or_else(|| promote(ambiguous))` verbatim,
/// in one place so a future promotion-rule change reaches them too.
/// Policy consumers use [`admission_zone_override`] instead.
#[inline]
pub(super) fn promoted_zone_override(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    raw: Option<u32>,
    ambiguous: Option<u32>,
    resolution: ForwardingResolution,
) -> Option<u32> {
    raw.or_else(|| {
        crate::afxdp::forwarding::promote_ambiguous_fabric_zone(
            forwarding, ha_state, now_secs, ambiguous, resolution,
        )
    })
}

/// #17031: dest-only NAT64 re-classify shared by the NoRoute and
/// MissingNeighbor post-translation tuples. Returns the extracted
/// IPv4 destination when `dst_ip` is a Pref64 IPv6 destination with a
/// ready NAT64 match; `None` for IPv4, a non-NAT64 IPv6 destination,
/// or when a same-family destination rewrite already exists (the
/// rewrite wins, mirroring both pre-#17031 copies verbatim).
#[inline]
pub(super) fn nat64_dest_only_v4(
    forwarding: &ForwardingState,
    nat: &crate::nat::NatDecision,
    dst_ip: IpAddr,
) -> Option<std::net::Ipv4Addr> {
    if nat.rewrite_dst.is_some() {
        return None;
    }
    match dst_ip {
        IpAddr::V6(dst_v6) => match forwarding.nat64.classify_ipv6_dest(dst_v6) {
            crate::nat64::Nat64Match::MatchReady { dst_v4, .. } => Some(dst_v4),
            _ => None,
        },
        IpAddr::V4(_) => None,
    }
}

/// #17031: the #2345 post-translation policy destination shared by
/// the NoRoute and MissingNeighbor arms: NAT64 extracted IPv4 wins,
/// then the merged same-family rewrite, then the wire destination;
/// the port is the rewritten destination port or the wire port.
#[inline]
pub(super) fn post_translation_policy_dst(
    nat64_dst_v4: Option<std::net::Ipv4Addr>,
    nat: &crate::nat::NatDecision,
    wire_dst_ip: IpAddr,
    wire_dst_port: u16,
) -> (IpAddr, u16) {
    let policy_dst_ip = match nat64_dst_v4 {
        Some(dst_v4) => IpAddr::V4(dst_v4),
        None => nat.rewrite_dst.unwrap_or(wire_dst_ip),
    };
    let policy_dst_port = nat.rewrite_dst_port.unwrap_or(wire_dst_port);
    (policy_dst_ip, policy_dst_port)
}

/// #17031: admission zone pair in one call — [`admission_zone_override`]
/// plus `zone_pair_ids_for_flow_with_override` on the gated value.
/// Returns `(gated_override, from_zone_id, to_zone_id)`; the gated
/// override is returned because several consumers must shadow it for
/// NAT scope / seed stamps, not just the pair.
#[inline]
pub(super) fn transit_zone_pair(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_logical: i32,
    raw: Option<u32>,
    ambiguous: Option<u32>,
    resolution: ForwardingResolution,
) -> (Option<u32>, u32, u32) {
    let gated = admission_zone_override(forwarding, ha_state, now_secs, raw, ambiguous, resolution);
    let (from_zone_id, to_zone_id) = crate::afxdp::forwarding::zone_pair_ids_for_flow_with_override(
        forwarding,
        ingress_logical,
        gated,
        resolution.egress_ifindex,
    );
    (gated, from_zone_id, to_zone_id)
}

/// The `NoRoute` arm's adjudication: everything the arm's deny handling and
/// the NAT fences below the gate need, in the shape they consume it.
/// (#17031: returned by [`transit_policy_adjudication`]; the other transit
/// arms consume the shared helpers directly and keep their own verdict
/// shapes, so this denial-only shape stays NoRoute-specific.)
pub(super) struct TransitPolicyAdjudication {
    /// The admission-gated fabric stamp ([`admission_zone_override`]).
    /// Every consumer below the arm's policy gate — the NAT translation
    /// fences and the `stage_flow_cache_deny_seed` call — must see THIS
    /// value, not the raw stamp (the same shadow discipline the
    /// session-miss block applies).
    pub(super) gated_ingress_zone_override: Option<u32>,
    pub(super) from_zone_id: u32,
    pub(super) to_zone_id: u32,
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

/// Protocol identity passed to the NoRoute policy gate. Flow-backed
/// sessions retain their established tuple; flowless packets must derive
/// protocol from the actual L3 frame, not shim `meta.protocol`.
pub(super) fn noroute_policy_protocol(
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow_backed: bool,
) -> u8 {
    if flow_backed {
        meta.protocol
    } else {
        crate::afxdp::frame::flowless_effective_protocol(frame, meta)
    }
}

/// #12906 / #17031: adjudicate a `NoRoute` frame's zone-pair policy on
/// the admission zone pair ([`transit_zone_pair`] over
/// [`admission_zone_override`]) and the #2345 post-translation
/// destination tuple ([`post_translation_policy_dst`] over
/// [`nat64_dest_only_v4`]).
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
///
/// `ambiguous_zone` is the withheld #15916 ambiguous claimed zone; before
/// #17031 this arm never promoted it (the caller passed the raw stamp
/// alone), so a co-moved tunnel NoRoute punt was judged on the fabric
/// interface's own zone — fail-closed, but not the admission pair.
#[expect(
    clippy::too_many_arguments,
    reason = "#17200: wide dataplane signature; census in docs/log/17200.md"
)]
pub(super) fn transit_policy_adjudication(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_logical: i32,
    ingress_zone_override: Option<u32>,
    ambiguous_zone: Option<u32>,
    resolution: ForwardingResolution,
    nat: crate::nat::NatDecision,
    flow_backed: bool,
    adj_flow: &SessionFlow,
    protocol: u8,
    l4_present: bool,
    policy_icmp: Option<(u8, u8)>,
    packet_len: u64,
    now_ns: u64,
) -> TransitPolicyAdjudication {
    // #6458 V2 / #12906 / #17031: the ONE admission binding — a
    // zone-encoded fabric stamp (proved or owner-promoted ambiguous)
    // drives this policy adjudication only when the resolution's owner
    // RG is forwarding-active locally. For a base NoRoute
    // (`egress_ifindex: 0`) the owner RG is unknown (0), so the stamp
    // degrades to the fabric interface's own zone there; a tunnel
    // NoRoute that retains its logical egress keeps the stamp iff that
    // egress's RG is locally active.
    let (gated_ingress_zone_override, from_zone_id, to_zone_id) = transit_zone_pair(
        forwarding,
        ha_state,
        now_secs,
        ingress_logical,
        ingress_zone_override,
        ambiguous_zone,
        resolution,
    );
    // #12906 (#2345 parity with the ForwardCandidate session-miss gate and
    // the #5174/#10267 MissingNeighbor arm): judge the POST-translation
    // destination tuple so a NAT-dependent deny lands here exactly as it
    // would on the resolved path. See the module doc for the two halves.
    let nat64_dst_v4 = flow_backed
        .then(|| nat64_dest_only_v4(forwarding, &nat, adj_flow.dst_ip))
        .flatten();
    let (policy_dst_ip, policy_dst_port) = post_translation_policy_dst(
        nat64_dst_v4,
        &nat,
        adj_flow.dst_ip,
        adj_flow.forward_key.dst_port,
    );
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
    TransitPolicyAdjudication {
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

#[cfg(test)]
#[path = "transit_policy_tests.rs"]
mod transit_policy_tests;
