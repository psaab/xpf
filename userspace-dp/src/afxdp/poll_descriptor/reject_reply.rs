// #2089/#11303 policy `then reject` replies generally follow Junos semantics:
// TCP gets a RST unless a synthetic V1/V2 fabric source MAC on a fabric
// ingress makes it unreplyable (stamp-shaped native MACs still get RSTs);
// UDP gets ICMP/ICMPv6 port-unreachable except on a stamped fabric arrival,
// where the reflected ICMP would target the synthetic stamp, not the client
// (#12319 — suppressed exactly like the #12051 TCP RST, logged as DENY).
// Other protocols drop. Plain `then deny` stays silent. Junos zone `tcp-rst`
// uses the same reply machinery only for non-SYN TCP session misses, not
// policy denies.
// Lifted out of poll_descriptor/mod.rs so the hot ingress loop does not carry
// these cold-path bodies in its codegen unit, mirroring cookie_reply.rs.
//
// `enqueue_policy_reject_reply` is on the cold policy exception arm and fires
// solely for `PolicyAction::Reject`. `enqueue_session_miss_rst` is reached only
// from the strict-SYN miss gate. Both are cold/exception bodies —
// `#[cold] #[inline(never)]` places them in `.text.unlikely`, away from the hot
// loop's cache lines. They share the SYN-cookie TX-frame budget gate so a reply
// flood cannot starve transit TX frames; on budget or build failure the caller
// still drops the packet (fail-closed).

use super::cookie_reply::syn_cookie_reply_budget_available;
use super::filter::emit_generated_reply_filter_log;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::afxdp::event_emit::emit_policy_deny_event;
use crate::afxdp::icmp::build_reject_icmp_unreachable;
use crate::afxdp::icmp_ratelimit::allow_generated_reject;
use crate::afxdp::tx::classify_generated_reply_deferred;
use crate::event_stream::EventStreamWorkerHandle;
use crate::nat::NatDecision;
use crate::policy::PolicyAction;

/// Which source a generated reject/reset reply is attributed to.
///
/// Policy and Filter replies select their per-source reject counters.
/// SessionMiss and Route reuse the same synthesis, output classification,
/// budget, and rate-limit gates but have no policy/filter counters.
pub(super) enum RejectReplySource {
    Policy,
    Filter,
    SessionMiss,
    Route,
}

/// #14021: route `reject` is protocol-independent and may have no session.
/// Its reply is always ICMP Destination Unreachable (never a TCP RST), but
/// shares the policy reject choke's suppression, classification, TX budget,
/// and per-zone generated-error limiter.
#[cold]
#[inline(never)]
pub(super) fn enqueue_route_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
    counters: &mut BatchCounters,
) -> bool {
    // The caller supplies the physical AF_XDP bind port for the shared
    // synthetic-fabric-source guard. The helper resolves the logical VLAN
    // unit itself for reply building and output classification.
    enqueue_reject_reply(
        tx_pipeline,
        forwarding,
        event_stream,
        ingress_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
        RejectReplySource::Route,
        crate::filter::resolve_reject_message("host-unreachable"),
    )
}

#[cold]
#[inline(never)]
pub(super) fn enqueue_policy_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
) -> bool {
    let reject_message = match meta.protocol {
        PROTO_TCP => crate::filter::RejectMessage::ADMIN_PROHIBITED,
        PROTO_UDP => crate::filter::RejectMessage::PORT_UNREACHABLE,
        _ => return false,
    };

    enqueue_reject_reply(
        tx_pipeline,
        forwarding,
        event_stream,
        ingress_ifindex,
        packet_frame,
        meta,
        Some(flow),
        counters,
        RejectReplySource::Policy,
        reject_message,
    )
}

/// #2521: firewall-filter `then reject` synthesizes an active reply using
/// the configured `then reject <message-type>` (admin-prohibited by default)
/// for non-TCP traffic, unlike policy `then reject` (#11303), which sends
/// port-unreachable only for UDP and silently drops other protocols. TCP
/// rejects in both paths use the same RST builder. Both reuse the exact
/// synthesis + #2238 output-classification path via `enqueue_reject_reply`;
/// only the success counter differs (`filter_reject_sent` vs
/// `policy_reject_sent`). Budget and output-filter drops retain source-specific
/// counters, parse errors stay source-neutral, and every failure remains
/// fail-closed (the caller still drops the packet on a `false` return).
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn enqueue_filter_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    // #6854: the ICMP codes the matched term's `then reject <message-type>`
    // resolved to. `RejectMessage::ADMIN_PROHIBITED` for a term with no
    // message-type, which is what this path sent for every reject before.
    reject_message: crate::filter::RejectMessage,
) -> bool {
    enqueue_reject_reply(
        tx_pipeline,
        forwarding,
        event_stream,
        ingress_ifindex,
        packet_frame,
        meta,
        Some(flow),
        counters,
        RejectReplySource::Filter,
        reject_message,
    )
}

/// #11304: policy-deny reply decision shared by both transit call sites and the
/// junos-host policy path. Explicit `then reject` remains active; plain `deny`
/// and default-deny always stay silent, regardless of the ingress zone's
/// `tcp-rst` setting. That setting is handled only at the transit TCP
/// session-miss drop.
///
/// Returns true iff an explicit `then reject` reply was enqueued. The caller
/// still drops the triggering packet regardless (fail-closed).
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn enqueue_deny_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    is_reject: bool,
) -> bool {
    if is_reject {
        return enqueue_policy_reject_reply(
            tx_pipeline,
            forwarding,
            event_stream,
            ingress_ifindex,
            packet_frame,
            meta,
            flow,
            counters,
        );
    }
    false
}

/// #11304: synthesize Junos `tcp-rst` for a non-SYN TCP transit session miss.
/// Called from the strict-SYN fail-closed branch, before the packet is recycled;
/// unlike a policy `reject`, this emits no policy-deny event or reject counter.
/// Reply construction, output filtering, the TX budget, and the per-zone
/// generated-reject limiter are shared with explicit reject replies.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn enqueue_session_miss_rst(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    from_zone_id: u16,
) -> bool {
    if meta.protocol != PROTO_TCP
        || flow.forward_key.protocol != PROTO_TCP
        || crate::tcp_flags::has_syn(meta.tcp_flags)
        || crate::tcp_flags::has_rst(meta.tcp_flags)
        || !forwarding.zone_tcp_rst_enabled(from_zone_id)
    {
        return false;
    }
    enqueue_reject_reply(
        tx_pipeline,
        forwarding,
        event_stream,
        ingress_ifindex,
        packet_frame,
        meta,
        Some(flow),
        counters,
        RejectReplySource::SessionMiss,
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    )
}

/// #3615: enqueue an explicit policy `reject` reply FIRST, THEN emit the
/// policy-deny RT_FLOW carrying the TRUTHFUL action. `enqueue_deny_reply`
/// returns true only when a `then reject` reply was sent; plain `deny` is
/// always silent. Zone `tcp-rst` session-miss replies use a separate path and
/// emit no policy-deny event.
///
/// Both transit deny sites and the junos-host deny route through this single
/// helper so the poll-loop ordering (enqueue-outcome BEFORE emit) is the SAME
/// code path a unit test can drive — the poll loop body itself is un-callable.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn deny_reply_and_emit(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    nat: &NatDecision,
    from_zone_id: u16,
    to_zone_id: u16,
    owner_rg_id: i32,
    policy_id: u32,
    action: PolicyAction,
    app_id: u16,
    now_ns: u64,
) {
    let reject_reply_enqueued = enqueue_deny_reply(
        tx_pipeline,
        forwarding,
        event_stream,
        ingress_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
        matches!(action, PolicyAction::Reject),
    );
    emit_policy_deny_event(
        event_stream,
        flow,
        nat,
        meta,
        from_zone_id,
        to_zone_id,
        owner_rg_id,
        policy_id,
        action,
        app_id,
        reject_reply_enqueued,
        now_ns,
    );
}

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn enqueue_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
    counters: &mut BatchCounters,
    source: RejectReplySource,
    reject_message: crate::filter::RejectMessage,
) -> bool {
    // #12051: a TCP RST reflects the incoming source MAC. A V1/V2 synthetic
    // fabric stamp is not the client's L2 address, so the reflected reset
    // cannot reach the client. Treat it as unreplyable before building or
    // charging the generated-reply budget/rate limit. This shared choke covers
    // policy/filter rejects and zone `tcp-rst` session-miss replies.
    // #12319: the ICMP/ICMPv6 leg reflects the inbound source MAC identically
    // (`ingress_reply_l2`), so a stamped-fabric UDP reject would emit
    // port-unreachable addressed to the synthetic stamp — undeliverable
    // backscatter counted as sent with a REJECT event, against the #3615
    // "never logs a reject that did not happen" contract. The gate is
    // therefore protocol-agnostic: any stamped fabric arrival is unreplyable.
    // #12864: GRE/WireGuard decap uses a zero-MAC synthetic Ethernet header
    // for inner L3. The packet is dropped even when policy chooses `reject`;
    // reflecting its fake L2 would leak an unencapsulated response on the
    // physical binding. No generated-reply budget/token may be consumed.
    if meta.meta_flags & crate::afxdp::icmp::TUNNEL_DECAP_INGRESS_FLAG != 0
        || crate::afxdp::forwarding::ingress_has_synthetic_fabric_source(
            forwarding,
            ingress_ifindex,
            packet_frame,
        )
    {
        return false;
    }

    // #3656: determine reply-build FEASIBILITY before consuming the reject
    // rate-limit token OR counting a TX-frame-budget drop. A frame that can
    // NEVER produce a reply — an inbound TCP RST, an inbound ICMP/ICMPv6 error,
    // a non-first fragment, an L2 group/broadcast frame, an unparseable frame,
    // or an ingress without a primary of the inbound family — is a PLAIN drop.
    // Building the reply first (a pure, side-effect-free reflection of the
    // inbound frame) means such a frame consumes NEITHER the reject rate-limit
    // token (H11: a flood of unreplyable frames must not drain the reject
    // bucket and starve legitimate rejects — a cheap DoS against active reject
    // behavior) NOR a budget-drop counter (H12: an impossible reply must not be
    // mis-attributed as TX queue pressure and hide the true attack shape). The
    // token / budget are consumed only once `Some(bytes)` proves an actual
    // reply exists. This is the residual of #3615, which reordered the event
    // emit + per-source counter split but left the bucket/budget consume AHEAD
    // of the build. #3618 made the rate-limit token PER INGRESS ZONE (resolved
    // below, at the gate), so H11 now protects each zone's bucket independently;
    // the CONSUMPTION ORDERING (feasibility before consume) is unchanged. The
    // extra build under budget/rate pressure is on the already-cold reject
    // exception path. #5569 extends the ordering further: the per-zone token is
    // consumed only AFTER the #2238/#3035 output-filter classification below
    // ADMITS the reply, so a flood of egress-FILTERED rejects (built, feasible,
    // but discarded by the reply's own output filter/policer) no longer drains
    // the zone's bucket and starves a later filter-PERMITTED reject in the SAME
    // zone — see the token gate below and `docs/generated-reply-rate-limit.md`.
    // #3976: resolve the LOGICAL ingress unit ifindex ONCE, up here, so both
    // the non-TCP ICMP/ICMPv6 reject BUILD below and the #3035 output-filter
    // classify further down key off the same value. `forwarding.egress` (and
    // `ingress_logical_ifindex`) are keyed by the LOGICAL unit ifindex
    // (forwarding_build/interfaces.rs), but `ingress_ifindex` here is the
    // PHYSICAL AF_XDP bind port. On a VLAN sub-interface (e.g. reth0.80 on
    // parent reth0) the physical parent is NOT a key in `forwarding.egress`
    // when it has no untagged unit of its own, so the old physical-keyed build
    // missed the sub-if's `EgressInterface` — `primary_v4`/`primary_v6` came up
    // None and `build_reject_icmp_unreachable` returned None → the reject
    // silently degraded to a discard on every VLAN sub-if. Even when the parent
    // DID have an entry, the ICMP source address and the egress `vlan_id`
    // fallback were the parent's, not this unit's → wrong-source / untagged
    // reply dropped on the tagged link. Keying the build off the logical unit
    // ifindex sources the ICMP reply from the sub-if's own primary address and
    // its own `vlan_id`, mirroring the Time Exceeded / Packet-Too-Big builders,
    // which resolve the same logical unit before their egress lookup
    // (`build_local_time_exceeded_request` / `compute_forwarded_egress_ptb`,
    // #6102 — before that fix they wrongly passed the PHYSICAL
    // `ingress_ident.ifindex`). The TCP RST builder is self-contained (it
    // reflects the inbound frame, no egress lookup), so it is unaffected. The
    // physical `ingress_ifindex` is still used for the
    // `TxRequest.egress_ifindex` (the XSK transmit device) below. For a
    // non-VLAN port the logical and physical indexes coincide, so this is a
    let logical_ingress_ifindex =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, meta.ingress_vlan_id)
            .unwrap_or(ingress_ifindex);
    let bytes = if !matches!(source, RejectReplySource::Route) && meta.protocol == PROTO_TCP {
        build_reject_rst_frame(packet_frame)
    } else {
        build_reject_icmp_unreachable(
            packet_frame,
            meta,
            logical_ingress_ifindex,
            forwarding,
            reject_message,
        )
    };
    let Some(bytes) = bytes else {
        // Unreplyable: fail-closed to the silent drop the caller already
        // performs. The REJECT_BUCKET token and the *_reject_reply_budget_drops
        // counters are deliberately left untouched here (#3656 H11/H12).
        return false;
    };

    // TX-frame budget gate (queue protection). Reached ONLY for a buildable
    // reply, so a counted budget drop is truthful TX-frame pressure on a real
    // reply — never a mis-attributed unreplyable frame (#3656 H12).
    if !syn_cookie_reply_budget_available(tx_pipeline) {
        counters.touched = true;
        // #3615 (L04): attribute policy and filter suppressions to their
        // matching source counters. A zone `tcp-rst` session miss is already
        // recorded as a strict-SYN drop and is not a policy/filter reject.
        match source {
            RejectReplySource::Policy => counters.policy_reject_reply_budget_drops += 1,
            RejectReplySource::Filter => counters.filter_reject_reply_budget_drops += 1,
            RejectReplySource::SessionMiss | RejectReplySource::Route => {}
        }
        return false;
    }

    // #2238: classify the GENERATED reply (TCP RST or ICMP/ICMPv6
    // unreachable) by its OWN egress 5-tuple and interface — the logical
    // ingress unit. Output filters and policers on that unit can suppress the
    // reply; a parse failure of our own bytes fails CLOSED (§6.2). The request
    // stays on the physical ingress binding's TX pipeline, but its CoS key is
    // the logical interface so shaping uses the same unit as classification.
    // Pre-#2238 this enqueued an UNCLASSIFIED TxRequest (`cos_queue_id:
    // None, dscp_rewrite: None`) that the drain path honored verbatim — no
    // output filter / CoS / DSCP was ever applied to the reply.
    //
    // #3035: CoS interfaces and output filters are keyed by the logical unit
    // ifindex, not physical `ingress_ifindex`. The resolver above mirrors the
    // #3026 generated-ICMP fix and is shared with the #3976 reject-build path.
    // Untagged logical and physical indexes coincide.
    //
    // #5569: this output-filter classification now runs BEFORE the per-zone
    // reject rate-limit token is consumed (the token block moved BELOW this
    // one). A reply the output filter DROPS — an egress `discard`/`reject`
    // terminal action or a three-color policer on the reply's OWN egress
    // unit, or a fail-closed re-parse error of our own built bytes —
    // therefore spends NO zone token. Before this reorder a flood of
    // egress-FILTERED rejects (whose generated ICMP/RST is discarded by the
    // output filter) drained the ingress zone's shared reject bucket and
    // suppressed a later TCP RST the SAME zone's output filter would have
    // PERMITTED (same-zone cross-protocol starvation). This mirrors the #3656
    // H11 build-before-consume ordering (an unreplyable frame spends no token)
    // and the #5567 feasibility-before-consume reorder on the TE/PTB
    // generators: a resource meant to bound amplification must not be spent on
    // a reply that never leaves the box. The trigger packet is still dropped
    // regardless (fail-closed — the caller drops on a `false` return); only
    // WHEN the token advances changed.
    let now_ns = monotonic_nanos();
    // #15268: deferred classification — the walk neither counts nor meters,
    // so a reply the zone limiter below discards leaves no counter/policer
    // trace. Settlement (and the output filter log) run only once the
    // token admits the reply.
    let mut verdict =
        classify_generated_reply_deferred(forwarding, logical_ingress_ifindex, &bytes);
    if verdict.drop {
        counters.touched = true;
        if verdict.parse_error {
            // A fail-CLOSED re-parse failure of our own generated bytes is a
            // builder/parser bug shared by every generated-reply type (cookie,
            // PTB, time-exceeded, reject), so it stays SOURCE-NEUTRAL (#3615).
            counters.generated_reply_classify_parse_errors += 1;
        } else {
            // #3615 (L05): attribute the egress output-filter suppression to
            // the reply's SOURCE — a filter `then reject` suppressed by an
            // output filter is no longer counted under policy_reject_*.
            match source {
                RejectReplySource::Policy => counters.policy_reject_output_filter_drops += 1,
                RejectReplySource::Filter => counters.filter_reject_output_filter_drops += 1,
                RejectReplySource::SessionMiss | RejectReplySource::Route => {}
            }
            // #15268 (B13-03): the output-filter log fires even though the
            // reply itself is dropped — exactly as transit logs a dropped
            // packet's matched `then log` term.
            if let Some(log_match) = verdict.filter_log {
                emit_generated_reply_filter_log(
                    forwarding,
                    event_stream,
                    &bytes,
                    meta,
                    logical_ingress_ifindex,
                    log_match,
                    false,
                    now_ns,
                );
            }
        }
        // Fail-closed to the silent drop the caller already performs. #5569:
        // reached BEFORE the token gate below, so a filter-dropped (or
        // parse-error) reply consumes no per-zone reject token.
        return false;
    }

    // #2472/#3618: per-ZONE token-bucket rate limit on the LOCALLY-GENERATED
    // reject reply (TCP RST or ICMP/ICMPv6 unreachable). The SYN-cookie
    // TX-frame budget gate above is a queue-protection gate (it keeps the
    // reply ring from starving transit TX), NOT a per-reason rate cap — under
    // a sustained rejected-flow flood it refills as fast as TX drains. The
    // token bucket bounds the generated-error RATE so a flood of rejected
    // flows cannot be amplified into unbounded RST/ICMP backscatter.
    //
    // #3618: the bucket is now PER INGRESS (from) ZONE, not a single global
    // one. `from_zone_id` is resolved from the LOGICAL ingress unit ifindex
    // (the same SSOT the #3976 reply build + #3035 output-classify key off —
    // so a VLAN sub-interface keys its OWN zone's bucket, and `ifindex_to_zone_id`
    // also maps the physical parent so a non-VLAN port resolves identically).
    // Before #3618 a rejected-flow flood ingressing one zone drained the single
    // shared bucket and starved legitimate reject-generation in a DIFFERENT
    // zone; per-zone buckets remove that cross-zone starvation. An unzoned /
    // unknown ingress interface (id 0) falls back to the shared
    // REJECT_FALLBACK_LIMITER (never fail-open). Both policy and filter reject
    // still share the SAME per-zone bucket for a given ingress zone (a single
    // emit path, per the RejectReplySource doc comment). #3656: the token is
    // consumed ONLY for a buildable reply (feasibility is proven above the
    // budget gate), so a flood of unreplyable frames can no longer drain the
    // zone's bucket and starve legitimate rejects (H11). #5569: the token is
    // ALSO consumed only AFTER the output-filter classification above admits
    // the reply, so a flood of egress-FILTERED rejects (built + feasible, but
    // discarded by the reply's own egress output filter / policer) can no
    // longer drain the zone's bucket and suppress a later filter-PERMITTED
    // reject in the SAME zone (same-zone cross-protocol starvation). On
    // bucket-empty we fail-closed to the silent drop the caller already
    // performs and bump the observable aggregate `Reject` rate-limited counter
    // (inside `allow_generated_reject`), which stays a SINGLE atomic so the
    // coordinator status / Prometheus metric is unchanged.
    let from_zone_id = forwarding
        .ifindex_to_zone_id
        .get(&logical_ingress_ifindex)
        .copied()
        .unwrap_or(0);
    let src_ip = flow.map(|flow| flow.src_ip).or_else(|| {
        ForwardPacketMeta::from(meta)
            .l3_addrs_unfiltered()
            .map(|(src, _)| src)
    });
    if !allow_generated_reject(forwarding, from_zone_id, src_ip) {
        counters.touched = true;
        // #3661: keep explicit policy and filter rate-limit counters distinct.
        // Zone `tcp-rst` session misses share this per-zone bucket but stay out
        // of both counters; their strict-SYN drop is recorded separately. The
        // source-neutral `reject_rate_limited_total` therefore includes all
        // three sources and need not equal the two per-source sums.
        match source {
            RejectReplySource::Policy => counters.policy_reject_rate_limit_drops += 1,
            RejectReplySource::Filter => counters.filter_reject_rate_limit_drops += 1,
            RejectReplySource::SessionMiss | RejectReplySource::Route => {}
        }
        return false;
    }

    // #15268: token admitted — replay the deferred counter/policer charges.
    // A red meter suppresses the reply here (the token stays spent: the
    // meter only runs for token-admitted replies).
    if verdict.settle_deferred_side_effects(now_ns) {
        counters.touched = true;
        match source {
            RejectReplySource::Policy => counters.policy_reject_output_filter_drops += 1,
            RejectReplySource::Filter => counters.filter_reject_output_filter_drops += 1,
            RejectReplySource::SessionMiss | RejectReplySource::Route => {}
        }
        if let Some(log_match) = verdict.filter_log {
            emit_generated_reply_filter_log(
                forwarding,
                event_stream,
                &bytes,
                meta,
                logical_ingress_ifindex,
                log_match,
                false,
                now_ns,
            );
        }
        return false;
    }
    if let Some(log_match) = verdict.filter_log {
        emit_generated_reply_filter_log(
            forwarding,
            event_stream,
            &bytes,
            meta,
            logical_ingress_ifindex,
            log_match,
            true,
            now_ns,
        );
    }

    tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: flow.map(|flow| flow.forward_key.clone()),
        egress_ifindex: logical_ingress_ifindex,
        cos_queue_id: verdict.cos_queue_id,
        dscp_rewrite: verdict.dscp_rewrite,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    });
    counters.touched = true;
    match source {
        RejectReplySource::Policy => counters.policy_reject_sent += 1,
        RejectReplySource::Filter => counters.filter_reject_sent += 1,
        RejectReplySource::SessionMiss | RejectReplySource::Route => {}
    }
    true
}

/// #14237: the `RejectRoute` disposition arm, extracted from
/// `poll_binding_process_descriptor` so its call-site wiring is unit-testable
/// (the poll loop body itself is un-callable). The arm MUST supply the
/// physical AF_XDP binding ifindex (`binding_ifindex`) — never a
/// VLAN-resolved logical unit — to `enqueue_route_reject_reply`: the shared
/// synthetic-fabric-source gate keys `ingress_is_fabric` on the physical
/// parent/overlay, while the helper resolves the logical unit itself for
/// reply building. Passing the logical unit (the pre-#14108 defect) missed
/// the fabric link and emitted an ICMP unreachable reflecting the synthetic
/// V2 stamp MAC. The disposition guard lives here too, so a test driving
/// this seam with any other disposition proves the arm stays silent.
#[cold]
#[inline(never)]
pub(super) fn handle_route_reject_disposition(
    disposition: ForwardingDisposition,
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&EventStreamWorkerHandle>,
    binding_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
    counters: &mut BatchCounters,
) -> bool {
    if !matches!(disposition, ForwardingDisposition::RejectRoute) {
        return false;
    }
    enqueue_route_reject_reply(
        tx_pipeline,
        forwarding,
        event_stream,
        binding_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
    )
}

#[cfg(test)]
#[path = "reject_reply_tests.rs"]
mod tests;
