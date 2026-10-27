// #1697/#17017: SYN-cookie reply machinery and admission helpers, moved
// out of poll_descriptor/mod.rs so the ingress loop does not carry the
// cookie/DDoS-path bodies in its codegen unit.
//
// `enqueue_syn_cookie_reply` is on the challenge path only and remains
// `#[cold] #[inline(never)]`; `syn_cookie_reply_budget_available` is
// called only by that cold enqueue body. Final transit admission consumes
// the shared pure verdict in `session_admission.rs`, while host admission
// stays caller-owned.

use super::worker::WorkerTxPipeline;
use super::*;
use crate::screen::SynCookieChallenge;
use super::session_admission::{AdmissionInput, cookie_reply_admission_verdict};

/// A SYN-cookie challenge has no effective route, translated tuple, or
/// finalized HA disposition yet. It may pass this point only when it is a
/// genuine session miss; final miss admission performs authoritative
/// martian, policy, host, and disposition checks before any reply.
pub(super) fn syn_cookie_challenge_is_session_miss(
    sessions: &SessionTable,
    flow: Option<&SessionFlow>,
    now_ns: u64,
) -> bool {
    flow.is_some_and(|flow| !sessions.has_session_hit_at(&flow.forward_key, now_ns))
}

/// Final transit admission for a validated cookie ACK or a deferred SYN
/// challenge, evaluated on the effective session-miss tuple.
///
/// `resolution` is the route selected for the translated destination
/// (after DNAT/NPTv6/NAT64 and any PBR table selection). Transit
/// classification receives the wire destination plus the pre-policy
/// translation; policy receives `effective_dst`. HA finalization precedes
/// zone-pair derivation. Locally emitted cookie replies authorize the
/// finalized pair even when HA classifies the transit disposition as
/// `FabricRedirect`: consuming the ACK here would otherwise bypass policy
/// evaluation on the peer. LocalDelivery host admission remains caller-owned
/// and is handled by `syn_cookie_host_admission`. Returning false suppresses
/// only the synthesized ACK-RST.
#[allow(clippy::too_many_arguments)]
pub(super) fn syn_cookie_final_admission(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, crate::afxdp::types::HAGroupRuntime>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u32>,
    packet_fabric_ingress: bool,
    fabric_link_ingress: bool,
    ha_startup_grace_until_secs: u64,
    resolution: ForwardingResolution,
    effective_dst: IpAddr,
    effective_dst_port: u16,
    translated_dst: Option<IpAddr>,
    now_ns: u64,
    now_secs: u64,
) -> bool {
    syn_cookie_final_admission_with_fence(
        forwarding,
        ha_state,
        flow,
        meta,
        ingress_zone_override,
        packet_fabric_ingress,
        fabric_link_ingress,
        ha_startup_grace_until_secs,
        resolution,
        effective_dst,
        effective_dst_port,
        translated_dst,
        false,
        now_ns,
        now_secs,
    )
}

/// Final admission with the unconditional miss-path drop gates folded
/// in (confirmation fold): L2 group-unicast delivery and the bindless
/// IPsec selector fence drop Permit packets on the ordinary miss path
/// after policy, so a challenged SYN must not earn a SYN-ACK when any
/// of them matches. `fence_dropped` is the caller's evaluation of
/// those gates on the packet's composed decision.
#[allow(clippy::too_many_arguments)]
pub(super) fn syn_cookie_final_admission_with_fence(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, crate::afxdp::types::HAGroupRuntime>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u32>,
    packet_fabric_ingress: bool,
    fabric_link_ingress: bool,
    ha_startup_grace_until_secs: u64,
    resolution: ForwardingResolution,
    effective_dst: IpAddr,
    effective_dst_port: u16,
    translated_dst: Option<IpAddr>,
    fence_dropped: bool,
    now_ns: u64,
    now_secs: u64,
) -> bool {
    if fence_dropped {
        return false;
    }
    let ingress_logical = crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let (from_zone_id, _) = zone_pair_ids_for_flow_with_override(
        forwarding,
        ingress_logical,
        ingress_zone_override,
        resolution.egress_ifindex,
    );
    // Match the miss path: HA fabric resolution receives the resolved
    // ingress zone and the original packet's fabric/grace context, not
    // a missing override encoded as zone zero or hard-coded false values.
    let resolution = crate::afxdp::forwarding::finalize_new_flow_ha_resolution(
        forwarding,
        ha_state,
        now_secs,
        resolution,
        packet_fabric_ingress,
        fabric_link_ingress,
        meta.ingress_ifindex as i32,
        from_zone_id,
        ha_startup_grace_until_secs,
    );
    if resolution.disposition == ForwardingDisposition::LocalDelivery {
        return true;
    }
    let (from_zone_id, to_zone_id) = super::session_miss_zone_pair_ids(
        forwarding,
        ingress_logical,
        ingress_zone_override,
        resolution,
    );
    cookie_reply_admission_verdict(
        forwarding,
        &AdmissionInput {
            flow,
            meta: meta.into(),
            resolution,
            class_dst: flow.dst_ip,
            translated_dst,
            policy_dst: effective_dst,
            protocol: meta.protocol,
            policy_dst_port: effective_dst_port,
            policy_icmp: None,
            from_zone_id,
            to_zone_id,
            fabric_arrival_zone: ingress_zone_override,
            now_ns,
        },
    )
    .permits()
}

/// Host-bound counterpart to [`syn_cookie_final_admission`].
///
/// A validated cookie ACK destined to a LocalDelivery service must not
/// earn an ACK-RST merely because its transit/FIB tuple resolves. Run
/// the same first host gates the ordinary LocalDelivery miss path runs:
/// host-inbound + lo0 must admit, and a matching junos-host deny/reject
/// suppresses the reply. This helper is side-effect-light: it evaluates
/// junos-host without counting/reply/event side effects and asks the
/// host-inbound/lo0 helper for its verdict. It does not install a
/// session or forward the ACK; the caller only uses the boolean to gate
/// the synthesized ACK-RST and then recycles the descriptor.
pub(super) fn syn_cookie_host_admission(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u32>,
    effective_dst: IpAddr,
    effective_dst_port: u16,
    now_ns: u64,
) -> bool {
    let ingress_logical = crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let (from_zone_id, _) = zone_pair_ids_for_flow_with_override(
        forwarding,
        ingress_logical,
        ingress_zone_override,
        meta.ingress_ifindex as i32,
    );
    if from_zone_id == 0 {
        return false;
    }
    let Some((lo0_action, _)) = host_inbound_gated_lo0_action(
        forwarding,
        ingress_logical,
        from_zone_id,
        effective_dst,
        effective_dst_port,
        effective_dst.is_ipv6(),
        packet_frame
            .get(meta.l4_offset as usize)
            .copied()
            .unwrap_or(0),
        crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta),
        flow,
        meta,
        ingress_zone_override,
        now_ns,
    ) else {
        return false;
    };
    if lo0_action != crate::filter::FilterAction::Accept {
        return false;
    }
    !matches!(
        junos_host_policy_eval(
            forwarding,
            flow,
            (effective_dst, effective_dst_port),
            from_zone_id,
            0,
            true,
            policy_packet_icmp(packet_frame, meta),
            now_ns,
            true,
        ),
        Some(result) if matches!(
            result.action,
            crate::policy::PolicyAction::Deny | crate::policy::PolicyAction::Reject
        )
    )
}
pub(super) const SYN_COOKIE_REPLY_PENDING_RESERVE: usize = TX_BATCH_SIZE;

pub(super) enum SynCookieReply {
    SynAck(SynCookieChallenge),
    AckRst,
}

#[inline]
pub(super) fn syn_cookie_reply_budget_available(tx_pipeline: &WorkerTxPipeline) -> bool {
    let max_pending = tx_pipeline.max_pending_tx;
    if max_pending == 0 {
        return false;
    }
    if tx_pipeline.free_tx_frames.len() <= SYN_COOKIE_REPLY_PENDING_RESERVE {
        return false;
    }
    let reserve = SYN_COOKIE_REPLY_PENDING_RESERVE.min(max_pending);
    let admitted = tx_pipeline
        .pending_tx_local
        .len()
        .saturating_add(tx_pipeline.pending_tx_prepared.len());
    admitted < max_pending.saturating_sub(reserve)
}

#[cold]
#[inline(never)]
pub(super) fn enqueue_syn_cookie_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
    reply: SynCookieReply,
    counters: &mut BatchCounters,
) -> bool {
    // #15131 (#12864/#14642 parity): GRE/WireGuard decap replaces the
    // inner frame with a synthetic Ethernet header whose MACs are zero
    // and marks it TUNNEL_DECAP_INGRESS_FLAG. Both SYN-cookie legs
    // reflect that header (write_reply_eth_header), so a challenged
    // tunnel inner would emit an unencapsulated SYN-ACK / ACK-RST with
    // dst/src MAC 00:00:00:00:00:00 on the physical underlay binding.
    // Suppress before consuming the TX budget or counting as sent,
    // exactly like the reject / ICMP-error / PTB gates.
    if meta.meta_flags & crate::afxdp::icmp::TUNNEL_DECAP_INGRESS_FLAG != 0 {
        return false;
    }

    // #12319 residual: both SYN-cookie SYN-ACK and ACK-RST reflect the
    // inbound source MAC. A stamped fabric source is synthetic, so such a
    // reply is unreachable backscatter; suppress it before consuming the TX
    // budget or incrementing a sent counter.
    if crate::afxdp::forwarding::ingress_has_synthetic_fabric_source(
        forwarding,
        ifindex,
        packet_frame,
    ) {
        return false;
    }

    if !syn_cookie_reply_budget_available(tx_pipeline) {
        counters.touched = true;
        counters.syn_cookie_reply_budget_drops += 1;
        return false;
    }

    let (bytes, sent_counter): (Option<Vec<u8>>, fn(&mut BatchCounters)) = match reply {
        SynCookieReply::SynAck(challenge) => (
            build_syn_cookie_syn_ack_frame(packet_frame, challenge.cookie_isn, challenge.peer_mss),
            |counters| counters.syn_cookie_syn_ack_sent += 1,
        ),
        SynCookieReply::AckRst => (build_syn_cookie_ack_rst_frame(packet_frame), |counters| {
            counters.syn_cookie_ack_rst_sent += 1
        }),
    };
    let Some(bytes) = bytes else {
        return false;
    };

    // #2238: classify the GENERATED SYN-cookie reply (SYN-ACK or ACK-RST) by
    // its OWN egress 5-tuple + egress interface — the reply egresses on the
    // interface the SYN arrived on, so `ifindex` IS the egress. An output
    // firewall filter terminal `discard`/`reject` (or three-color policer)
    // drops the reply; a parse failure of our own built bytes fails CLOSED
    // (§6.2). A SYN-cookie SYN-ACK dropped by an operator's output filter is
    // a legitimate (rare) choice. Pre-#2238 this enqueued an UNCLASSIFIED
    // TxRequest the drain path honored verbatim — no output filter / CoS /
    // DSCP was applied to the reply.
    //
    // #3035: classify on the LOGICAL egress ifindex, NOT the physical bind
    // `ifindex`. CoS interfaces (forwarding_build/cos.rs) and output filters
    // (filter/compiler.rs) are keyed by the logical unit ifindex; on a VLAN
    // subinterface `ifindex` is the physical parent index, so classifying by
    // it applied the parent's (or first subinterface's) CoS queue / DSCP
    // rewrite / output filter instead of this unit's. Mirrors the #3026
    // generated-ICMP-error fix and the filter/CoS sites via the
    // `resolve_ingress_logical_ifindex` SSOT; `classify_ifindex` is also stored
    // as the TxRequest CoS key below. The request remains in this physical
    // binding's pipeline, which selects the XSK device; for untagged ports
    // logical and physical indexes coincide.
    let now_ns = monotonic_nanos();
    let classify_ifindex =
        resolve_ingress_logical_ifindex(forwarding, ifindex, meta.ingress_vlan_id)
            .unwrap_or(ifindex);
    // #15268: deferred classification (no zone token on this generator, so
    // admission is the successful settle below).
    let mut verdict =
        crate::afxdp::tx::classify_generated_reply_deferred(forwarding, classify_ifindex, &bytes);
    if verdict.drop {
        counters.touched = true;
        if verdict.parse_error {
            counters.generated_reply_classify_parse_errors += 1;
        } else {
            counters.syn_cookie_output_filter_drops += 1;
            if let Some(log_match) = verdict.filter_log {
                super::filter::emit_generated_reply_filter_log(
                    forwarding,
                    event_stream,
                    &bytes,
                    meta,
                    classify_ifindex,
                    log_match,
                    false,
                    now_ns,
                );
            }
        }
        return false;
    }
    if verdict.settle_deferred_side_effects(now_ns) {
        counters.touched = true;
        counters.syn_cookie_output_filter_drops += 1;
        if let Some(log_match) = verdict.filter_log {
            super::filter::emit_generated_reply_filter_log(
                forwarding,
                event_stream,
                &bytes,
                meta,
                classify_ifindex,
                log_match,
                false,
                now_ns,
            );
        }
        return false;
    }
    if let Some(log_match) = verdict.filter_log {
        super::filter::emit_generated_reply_filter_log(
            forwarding,
            event_stream,
            &bytes,
            meta,
            classify_ifindex,
            log_match,
            true,
            now_ns,
        );
    }

    tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes: bytes.into(),
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: flow.map(|flow| flow.forward_key.clone()),
        egress_ifindex: classify_ifindex,
        cos_queue_id: verdict.cos_queue_id,
        dscp_rewrite: verdict.dscp_rewrite,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    });
    counters.touched = true;
    sent_counter(counters);
    true
}

#[cfg(test)]
#[path = "cookie_reply_tests.rs"]
mod tests;
