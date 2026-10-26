// #1697/#17017: SYN-cookie reply machinery and admission helpers, moved
// out of poll_descriptor/mod.rs so the ingress loop does not carry the
// cookie/DDoS-path bodies in its codegen unit.
//
// `enqueue_syn_cookie_reply` is on the challenge path only and remains
// `#[cold] #[inline(never)]`; `syn_cookie_reply_budget_available` is
// called only by that cold enqueue body. The prescreen and final
// admission helpers consume the shared pure verdict in
// `session_admission.rs`, while host admission stays caller-owned.

use super::worker::WorkerTxPipeline;
use super::*;
use crate::screen::SynCookieChallenge;
use super::session_admission::{AdmissionInput, transit_admission_verdict};

/// #15947 (H28-01): may a SYN-cookie reply (SYN-ACK challenge or
/// validated-ACK RST) be emitted for this packet's destination?
///
/// The screen stages run before session/FIB/HA/policy admission, so
/// without this gate a screened SYN above threshold elicits a SYN-ACK
/// (and a validated cookie ACK an ACK-RST) for destinations the
/// firewall would deny, cannot route, classifies martian, or does not
/// own (HA-inactive) — an oracle / split-brain response, and a fresh
/// cookie ISN hijacking an Opening session's retransmitted SYN.
/// This helper is a necessary-but-not-sufficient challenge prescreen:
/// it suppresses disproven replies, but a positive result is NOT final
/// admission. The challenge caller therefore records a deferred
/// challenge and lets the actual miss path re-derive DNAT/NPTv6/
/// NAT64/PBR, select the route, and run the disposition-specific
/// final/host admission before a SYN-ACK is emitted. It retains two
/// useful early signals: an existing session suppresses a fresh
/// cookie, and an unzoned/raw-disproven packet cannot earn a reply.
/// "Plausible" here remains deliberately raw-tuple for transit; final
/// admission's translated tuple is authoritative.
pub(super) fn syn_cookie_reply_admitted(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, crate::afxdp::types::HAGroupRuntime>,
    sessions: &SessionTable,
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u32>,
    now_ns: u64,
    now_secs: u64,
) -> bool {
    let Some(flow) = flow else {
        return false;
    };
    // An existing live session (incl. an Opening handshake's
    // retransmit) follows its session — never a fresh cookie ISN.
    if sessions.has_session_hit_at(&flow.forward_key, now_ns) {
        return false;
    }
    let resolution = crate::afxdp::forwarding::enforce_ha_resolution_snapshot(
        forwarding,
        ha_state,
        now_secs,
        crate::afxdp::forwarding::lookup_forwarding_resolution(forwarding, flow.dst_ip)
            .resolution,
    );
    if resolution.disposition == ForwardingDisposition::LocalDelivery {
        // Round-3/narrow fold: the challenge SYN-ACK itself must pass
        // the same host gates as the validated ACK. The raw destination
        // is the only tuple available on this pre-translation arm, so
        // this checks host-inbound/lo0 + junos-host on it; translated
        // host destinations are governed again at final admission.
        return syn_cookie_host_admission(
            forwarding,
            flow,
            packet_frame,
            meta,
            ingress_zone_override,
            flow.dst_ip,
            flow.forward_key.dst_port,
            now_ns,
        );
    }
    let ingress_logical = crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
        forwarding,
        ingress_logical,
        ingress_zone_override,
        resolution.egress_ifindex,
    );
    transit_admission_verdict(
        forwarding,
        &AdmissionInput {
            flow,
            meta: meta.into(),
            resolution,
            class_dst: flow.dst_ip,
            translated_dst: None,
            policy_dst: flow.dst_ip,
            protocol: meta.protocol,
            policy_dst_port: flow.forward_key.dst_port,
            policy_icmp: None,
            from_zone_id,
            to_zone_id,
            fabric_arrival_zone: ingress_zone_override,
            now_ns,
        },
        None,
    )
    .permits()
}

/// Final admission check for a validated SYN-cookie ACK, evaluated on
/// the actual session-miss context rather than the raw ingress tuple.
///
/// `resolution` must already be the route selected for the translated
/// destination (after DNAT/NPTv6/NAT64 and any PBR table selection).
/// This path intentionally retains its current zone pair (computed after
/// its own HA finalization) and passes `effective_dst` as both the
/// destination-class and policy tuple; #17920 owns any behavior change.
/// LocalDelivery host admission is caller-owned and is handled separately
/// by `syn_cookie_host_admission`. Returning false suppresses only the
/// synthesized ACK-RST.
pub(super) fn syn_cookie_final_admission(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, crate::afxdp::types::HAGroupRuntime>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u32>,
    resolution: ForwardingResolution,
    effective_dst: IpAddr,
    effective_dst_port: u16,
    now_ns: u64,
    now_secs: u64,
) -> bool {
    syn_cookie_final_admission_with_fence(forwarding, ha_state, flow, meta, ingress_zone_override, resolution, effective_dst, effective_dst_port, false, now_ns, now_secs)
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
    resolution: ForwardingResolution,
    effective_dst: IpAddr,
    effective_dst_port: u16,
    fence_dropped: bool,
    now_ns: u64,
    now_secs: u64,
) -> bool {
    if fence_dropped {
        return false;
    }
    let resolution = crate::afxdp::forwarding::finalize_new_flow_ha_resolution(
        forwarding,
        ha_state,
        now_secs,
        resolution,
        false,
        false,
        meta.ingress_ifindex as i32,
        ingress_zone_override.unwrap_or(0),
        0,
    );
    if resolution.disposition == ForwardingDisposition::LocalDelivery {
        return true;
    }
    let ingress_logical = crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
        forwarding,
        ingress_logical,
        ingress_zone_override,
        resolution.egress_ifindex,
    );
    transit_admission_verdict(
        forwarding,
        &AdmissionInput {
            flow,
            meta: meta.into(),
            resolution,
            class_dst: effective_dst,
            translated_dst: None,
            policy_dst: effective_dst,
            protocol: meta.protocol,
            policy_dst_port: effective_dst_port,
            policy_icmp: None,
            from_zone_id,
            to_zone_id,
            fabric_arrival_zone: ingress_zone_override,
            now_ns,
        },
        None,
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
