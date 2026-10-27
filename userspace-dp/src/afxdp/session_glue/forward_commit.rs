// #17021: single source of truth for the forward-session metadata,
// NAT composition, TCP epilogue, and shared-entry construction shared
// by the ForwardCandidate (transit) install and the MissingNeighbor
// seed. Before this module the seed hand-copied that construction;
// #13526, #14661 and #15948 were lag fixes to the copy, and #15948
// re-diverged (it threaded the stage-9 `ingress_nat_scope_ifindex`,
// which is `None` for every local arrival, instead of transit's
// fabric/local ternary). Every future forward-session obligation now
// lands in one place.

use super::*;

/// Inputs for the one forward-session metadata builder.
pub(in crate::afxdp) struct ForwardMetaInput<'a> {
    pub forwarding: &'a ForwardingState,
    pub ingress_zone: u32,
    pub egress_zone: u32,
    /// Raw frame ingress identity (`meta.ingress_ifindex` /
    /// `meta.ingress_vlan_id`); stamped through
    /// `stamped_ingress_identity` so fabric arrivals record no identity.
    pub ingress_ifindex: u32,
    pub ingress_vlan_id: u16,
    /// Stage-9 validated fabric scope, or `None` for local arrivals.
    /// The builder resolves the local logical unit itself, exactly as
    /// the transit install does (#15176).
    pub ingress_nat_scope_ifindex: Option<i32>,
    pub fabric_ingress: bool,
    pub decision: SessionDecision,
    pub policy_result: Option<crate::policy::PolicyEvaluationResult>,
    pub nat64_reverse: Option<crate::nat64::Nat64ReverseInfo>,
    /// Owner RG stamped on the entry. Transit passes the resolved
    /// owner; the MissingNeighbor seed derives it from the decision
    /// inside the builder (the pre-#17021 seed behavior).
    pub owner_rg_id: Option<i32>,
}

/// Build the forward `SessionMetadata` for both the transit install
/// and the MissingNeighbor seed. The `nat_scope_ifindex` ternary and
/// the `stamped_ingress_identity` rule (#7096) live here only, so the
/// two arms cannot diverge again (#15948).
pub(in crate::afxdp) fn forward_session_metadata(input: ForwardMetaInput<'_>) -> SessionMetadata {
    let ForwardMetaInput {
        forwarding,
        ingress_zone,
        egress_zone,
        ingress_ifindex,
        ingress_vlan_id,
        ingress_nat_scope_ifindex,
        fabric_ingress,
        decision,
        policy_result,
        nat64_reverse,
        owner_rg_id,
    } = input;
    let nat_scope_ifindex = if fabric_ingress {
        ingress_nat_scope_ifindex
    } else {
        Some(
            resolve_ingress_logical_ifindex(forwarding, ingress_ifindex as i32, ingress_vlan_id)
                .unwrap_or(ingress_ifindex as i32),
        )
    };
    let (stamped_ifindex, stamped_vlan) =
        crate::session::stamped_ingress_identity(ingress_ifindex, ingress_vlan_id, fabric_ingress);
    SessionMetadata {
        ingress_ifindex: stamped_ifindex,
        ingress_vlan_id: stamped_vlan,
        forward_ingress_vlan_id: None,
        ingress_zone,
        egress_zone,
        ingress_zone_check: crate::session::zone_vintage_check_for_id(
            &forwarding.zone_id_to_name,
            ingress_zone,
        ),
        egress_zone_check: crate::session::zone_vintage_check_for_id(
            &forwarding.zone_id_to_name,
            egress_zone,
        ),
        owner_rg_id: owner_rg_id
            .unwrap_or_else(|| owner_rg_for_resolution(forwarding, decision.resolution)),
        fabric_ingress,
        is_reverse: false,
        nat64_reverse,
        log_session_init: policy_result.is_some_and(|r| r.log_session_init),
        log_session_close: policy_result.is_some_and(|r| r.log_session_close),
        policy_id: policy_result.map_or(0, |r| r.policy_id),
        inactivity_timeout_ns: crate::session::app_inactivity_timeout_ns(
            policy_result.and_then(|r| r.inactivity_timeout),
        ),
        policy_counter_idx: policy_result.map_or(0, |r| r.policy_counter_idx),
        policy_counter: policy_result.and_then(|r| {
            forwarding
                .policy
                .hit_counter_by_idx(r.policy_counter_idx)
                .cloned()
        }),
        nat_scope_ifindex,
    }
}

/// Outcome of composing the outbound source NAT for a forward flow.
pub(in crate::afxdp) struct ComposedNat {
    pub decision: SessionDecision,
    pub source_nat_release_key: Option<SessionKey>,
    pub source_nat_counter: Option<std::sync::Arc<crate::nat::NatRuleCounter>>,
    pub source_nat_static: Option<bool>,
}

pub(in crate::afxdp) enum NatFailure {
    /// NPTv6 reported the source untranslatable: terminal drop, no
    /// SNAT fallback (§3.7/§3.2). The caller recycles the frame.
    Untranslatable,
    /// Source-NAT allocation failed; the caller records the failure
    /// and recycles the frame.
    SourceNat(SourceNatFailure),
}

/// Compose NPTv6-to-SNAT outbound source NAT into `decision`, exactly
/// as both the transit arm and the MissingNeighbor seed did by hand
/// (#3121). `nat_match_flow` is the post-DNAT flow the caller built;
/// the helpers only differ in how that flow is derived, which stays
/// per-arm.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn compose_outbound_source_nat(
    forwarding: &ForwardingState,
    decision: SessionDecision,
    nat_match_flow: &SessionFlow,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    ingress_nat_scope_ifindex: Option<i32>,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    now_ns: u64,
    non_first_fragment: bool,
    packet_icmp: Option<(u8, u8)>,
    worker_id: u32,
) -> Result<ComposedNat, NatFailure> {
    let mut decision = decision;
    let nptv6_snat = if let IpAddr::V6(mut src_v6) = nat_match_flow.src_ip {
        match forwarding
            .nptv6
            .translate_outbound_result(&mut src_v6, to_zone)
        {
            crate::nptv6::Nptv6Translation::Translated => {
                forwarding.nptv6.record_translation(false);
                Some(NatDecision {
                    rewrite_src: Some(IpAddr::V6(src_v6)),
                    rewrite_dst: None,
                    nat64: false,
                    nptv6: true,
                    ..NatDecision::default()
                })
            }
            crate::nptv6::Nptv6Translation::NoMatch => None,
            crate::nptv6::Nptv6Translation::Untranslatable => {
                forwarding.nptv6.record_untranslatable_drop();
                return Err(NatFailure::Untranslatable);
            }
        }
    } else {
        None
    };
    if let Some(nptv6_decision) = nptv6_snat {
        decision.nat = decision.nat.merge(nptv6_decision);
        return Ok(ComposedNat {
            decision,
            source_nat_release_key: Some(nat_match_flow.forward_key.clone()),
            source_nat_counter: None,
            source_nat_static: None,
        });
    }
    let mut snat_match_counter = None;
    let mut snat_match_static = None;
    match crate::afxdp::poll_descriptor::source_nat_decision_for_flow(
        forwarding,
        ingress_ifindex,
        ingress_vlan_id,
        ingress_nat_scope_ifindex,
        from_zone,
        to_zone,
        egress_ifindex,
        nat_match_flow,
        now_ns,
        non_first_fragment,
        packet_icmp,
        worker_id,
        &mut snat_match_counter,
        &mut snat_match_static,
    ) {
        Ok(snat_decision) => {
            decision.nat = decision.nat.merge(snat_decision);
            Ok(ComposedNat {
                decision,
                source_nat_release_key: Some(nat_match_flow.forward_key.clone()),
                source_nat_counter: snat_match_counter,
                source_nat_static: snat_match_static,
            })
        }
        Err(failure) => Err(NatFailure::SourceNat(failure)),
    }
}

/// TCP epilogue shared by every forward/local/punt install site:
/// seed the window scale and the trigger ISN from the trigger frame.
/// Previously spelled out at five sites, so every epilogue change
/// (#15947/#16042) had to touch all five.
pub(in crate::afxdp) fn seed_forward_tcp_epilogue(
    sessions: &mut SessionTable,
    key: &SessionKey,
    packet_frame: &[u8],
    payload_len: u32,
    tcp_flags: u8,
) {
    if let Some((seq, _, _, scale)) =
        crate::afxdp::frame::extract_tcp_seq_ack_window_scale(packet_frame)
    {
        sessions.seed_tcp_window_scale(key, scale);
        sessions.seed_tcp_isn(key, seq, payload_len, tcp_flags);
    }
}

/// Build the one shared `SyncedSessionEntry` for a just-installed
/// forward session, reading the live wire counters from the table so
/// a PPTP-discriminated GRE key carries its live call-id pair instead
/// of the seed's former hardcoded 0 (#17021).
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn forward_synced_entry(
    sessions: &SessionTable,
    key: SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    source_nat_static: Option<bool>,
    leak_incarnation: Option<u64>,
    origin: SessionOrigin,
    protocol: u8,
    tcp_flags: u8,
    session_id: u64,
    handshake_state_wire: u8,
) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata,
        source_nat_static,
        leak_incarnation: leak_incarnation.unwrap_or(0),
        origin,
        protocol,
        tcp_flags,
        generation: 0,
        session_id,
        tcp_close_class: 0,
        tcp_handshake_state: handshake_state_wire,
        rev_packets: sessions.rev_packets_for(&key),
        fwd_packets: sessions.fwd_packets_for(&key),
        pptp_call_ids: sessions.pptp_call_ids_wire_for(&key),
        persistent_lease_hold: sessions.persistent_lease_hold_for(&key),
    }
}
