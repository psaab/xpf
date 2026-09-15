// #2089 policy-`reject` reply synthesis: emit a TCP RST (for TCP) or an
// ICMP/ICMPv6 Destination Unreachable, administratively prohibited (for
// every other non-suppressed protocol) instead of the silent drop that
// `then deny` produces. Lifted out of poll_descriptor/mod.rs so the hot
// ingress loop does not carry the reject-path bodies in its codegen unit,
// mirroring cookie_reply.rs.
//
// `enqueue_policy_reject_reply` is on the cold policy-deny exception arm
// only and fires solely when the matched action is `PolicyAction::Reject`,
// so it is a true cold/exception body — `#[cold] #[inline(never)]` places
// it in `.text.unlikely`, away from the hot loop's cache lines. It reuses
// the SYN-cookie TX-frame budget gate so a rejected-flow flood can never
// starve transit TX frames; on a budget or build failure it returns false
// and the caller still drops the packet (fail-closed — never logs a reject
// that did not happen).

use super::cookie_reply::syn_cookie_reply_budget_available;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::afxdp::event_emit::emit_policy_deny_event;
use crate::afxdp::icmp::build_reject_icmp_unreachable;
use crate::afxdp::icmp_ratelimit::allow_generated_reject;
use crate::event_stream::EventStreamWorkerHandle;
use crate::nat::NatDecision;
use crate::policy::PolicyAction;

/// Which `reject` source a synthesized reply is attributed to. Selects the
/// per-source counters so a policy `then reject` and a firewall-filter `then
/// reject` are independently observable, while both flow through the SAME
/// reply-synthesis + output-classification machinery (#2521). The
/// budget-exhaustion / output-filter-drop / parse-error legs are shared with
/// policy reject so #2472's future per-reason rate limiter (which hooks the
/// shared generated-reply path) covers filter reject automatically — there is
/// no parallel, un-limitable emit path.
#[derive(Clone, Copy)]
pub(super) enum RejectReplySource {
    Policy,
    Filter,
}

#[cold]
#[inline(never)]
pub(super) fn enqueue_policy_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
) -> bool {
    enqueue_reject_reply(
        tx_pipeline,
        forwarding,
        ingress_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
        RejectReplySource::Policy,
        // #6854: a POLICY reject has no filter term and so no message-type;
        // it keeps the administratively-prohibited codes it has always sent.
        crate::filter::RejectMessage::ADMIN_PROHIBITED,
    )
}

/// #2521: firewall-filter `then reject` now synthesizes the SAME active
/// reply as policy `reject` (TCP RST for TCP, ICMP/ICMPv6 admin-prohibited
/// unreachable otherwise) instead of the historical silent drop. Reuses the
/// exact synthesis + #2238 output-classification path via the shared
/// `enqueue_reject_reply`; only the success counter differs
/// (`filter_reject_sent` vs `policy_reject_sent`). Budget, output-filter, and
/// parse-error drops share policy reject's counters and its fail-closed
/// behavior (the caller still drops the packet on a `false` return).
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn enqueue_filter_reject_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
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
        ingress_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
        RejectReplySource::Filter,
        reject_message,
    )
}

/// #3071: unified deny-path reply decision shared by both policy-deny call
/// sites in `poll_descriptor`. Replaces the bare `if action == Reject` arm so
/// the zone-level `tcp-rst` knob is honored alongside explicit `then reject`:
///
/// * `is_reject` (policy `then reject`): active reject for EVERY protocol — a
///   TCP RST for TCP, an ICMP/ICMPv6 admin-prohibited unreachable otherwise.
///   Unchanged from #2089.
/// * otherwise (plain `deny` / default-deny): a silent drop UNLESS the flow is
///   TCP AND the INGRESS (from) zone has Junos `tcp-rst` enabled, in which
///   case a TCP RST is sent back toward the source. Junos `tcp-rst` only
///   resets TCP; non-TCP denied traffic and a deny in a non-tcp-rst zone stay
///   silent drops.
///
/// Both legs reuse `enqueue_policy_reject_reply` (the #2521/#2089 synthesis +
/// #2238 output classification + #2472 rate limit + fail-closed budget gate),
/// so a zone-tcp-rst RST is counted under `policy_reject_sent` — it is a
/// policy-deny-driven reset. Returns true iff a reply was enqueued; the caller
/// still performs the silent drop regardless (fail-closed).
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn enqueue_deny_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    is_reject: bool,
    from_zone_id: u16,
) -> bool {
    if is_reject {
        return enqueue_policy_reject_reply(
            tx_pipeline,
            forwarding,
            ingress_ifindex,
            packet_frame,
            meta,
            flow,
            counters,
        );
    }
    if meta.protocol == PROTO_TCP && forwarding.zone_tcp_rst_enabled(from_zone_id) {
        return enqueue_policy_reject_reply(
            tx_pipeline,
            forwarding,
            ingress_ifindex,
            packet_frame,
            meta,
            flow,
            counters,
        );
    }
    false
}

/// #3615: enqueue the policy deny/reject reply FIRST, THEN emit the policy-deny
/// RT_FLOW carrying the TRUTHFUL action. `enqueue_deny_reply` returns whether a
/// TCP RST / ICMP-unreachable was actually enqueued (an explicit `then reject`,
/// or a plain `deny` in a zone with `tcp-rst`); that outcome is threaded into
/// `emit_policy_deny_event` so a `reject` whose reply fail-closed
/// (budget/rate/parse/output-filter) is logged as the truthful DENY rather than
/// claiming an active reject that never left the box. A plain `deny` always
/// logs DENY regardless of whether a zone-`tcp-rst` RST rode out.
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
        ingress_ifindex,
        packet_frame,
        meta,
        flow,
        counters,
        matches!(action, PolicyAction::Reject),
        from_zone_id,
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
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    source: RejectReplySource,
    reject_message: crate::filter::RejectMessage,
) -> bool {
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
    // no-op there.
    let logical_ingress_ifindex =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, meta.ingress_vlan_id)
            .unwrap_or(ingress_ifindex);
    let bytes = if meta.protocol == PROTO_TCP {
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
        // #3615 (L04): attribute the TX-frame-budget suppression to the
        // reply's SOURCE so a firewall-filter `then reject` drop is not
        // conflated with a policy `then reject` drop. Both still share the
        // same budget gate; only the observable counter differs.
        match source {
            RejectReplySource::Policy => counters.policy_reject_reply_budget_drops += 1,
            RejectReplySource::Filter => counters.filter_reject_reply_budget_drops += 1,
        }
        return false;
    }

    // #2238: classify the GENERATED reply (TCP RST or ICMP/ICMPv6
    // unreachable) by its OWN egress 5-tuple + egress interface — the
    // reflected reply egresses on the interface it arrived on, so
    // `ingress_ifindex` IS the egress. An output firewall filter terminal
    // `discard`/`reject` (or three-color policer) on that interface drops
    // the reply; a parse failure of our own built bytes fails CLOSED (§6.2).
    // Pre-#2238 this enqueued an UNCLASSIFIED TxRequest (`cos_queue_id:
    // None, dscp_rewrite: None`) that the drain path honored verbatim — no
    // output filter / CoS / DSCP was ever applied to the reply.
    //
    // #3035: classify on the LOGICAL egress ifindex, NOT the physical
    // `ingress_ifindex`. CoS interfaces (forwarding_build/cos.rs) and output
    // filters (filter/compiler.rs) are keyed by the logical unit ifindex; on
    // a VLAN subinterface `ingress_ifindex` is the physical parent index, so
    // classifying by it applied the parent's (or first subinterface's) CoS
    // queue / DSCP rewrite / output filter instead of this unit's. Mirrors
    // the #3026 generated-ICMP-error fix and the filter/CoS sites via the
    // `resolve_ingress_logical_ifindex` SSOT (#3976: the same
    // `logical_ingress_ifindex` computed above also keys the ICMP reject
    // build); the physical `ingress_ifindex` is still used for the XSK
    // transmit (`egress_ifindex`) below. For a non-VLAN port the logical and
    // physical indexes coincide, so this is a no-op there.
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
    let verdict = classify_generated_reply(forwarding, logical_ingress_ifindex, &bytes, now_ns);
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
    // #9901 (F-074): key the limiter's per-source tier on the trigger's
    // source (`flow` is the pre-NAT session flow, so this is the true origin).
    if !allow_generated_reject(forwarding, from_zone_id, Some(flow.src_ip)) {
        counters.touched = true;
        // #3661: attribute the rate-limit drop to the reply's SOURCE so a
        // firewall-filter `then reject` starvation is not conflated with a
        // policy `then reject` starvation under a rejected-flow flood. Both
        // sources still share the SAME per-zone reject bucket for a given
        // ingress zone (#3618); the aggregate `reject_rate_limited_total`
        // (bumped inside `allow_generated_reject`) stays source-NEUTRAL for
        // back-compat and is a single atomic summed across all zones, and these
        // two per-source per-binding counters sum to it exactly (the reject
        // bucket has this ONE consume site — #3656 proved the token is consumed
        // only for a buildable reply, and #5569 proved it is consumed only for
        // a filter-ADMITTED reply, so a filtered / unreplyable frame reaches
        // neither counter). Mirrors the #3615 output-filter source split above.
        match source {
            RejectReplySource::Policy => counters.policy_reject_rate_limit_drops += 1,
            RejectReplySource::Filter => counters.filter_reject_rate_limit_drops += 1,
        }
        return false;
    }

    tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: Some(flow.forward_key.clone()),
        egress_ifindex: ingress_ifindex,
        cos_queue_id: verdict.cos_queue_id,
        dscp_rewrite: verdict.dscp_rewrite,
        mirror_clone: false,
        enqueue_ns: 0,
    });
    counters.touched = true;
    match source {
        RejectReplySource::Policy => counters.policy_reject_sent += 1,
        RejectReplySource::Filter => counters.filter_reject_sent += 1,
    }
    true
}

#[cfg(test)]
#[path = "reject_reply_tests.rs"]
mod tests;
