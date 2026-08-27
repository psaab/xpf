// #1697 cold-path extraction: interface-input-filter evaluation +
// filter-log emission, lifted out of poll_descriptor/mod.rs.
//
// Inline policy is per-function (NOT blanket #[inline(never)]) so the
// cheap common-case guards stay folded into the hot/warm caller while
// only the rare/heavy bodies are forced out of line:
//
//   - filter_log_ingress_zone_id / filter_log_egress_zone_id: trivial
//     leaf helpers, #[inline] — called from both inline and cold
//     callers; let rustc place them.
//   - emit_cached_input_filter_log / emit_cached_output_filter_log are
//     called UNCONDITIONALLY from stage_flow_cache_hit (#[inline(always)],
//     the established-flow fast path). They stay #[inline] so the
//     `None` filter-log guard folds into the fast path: in the common
//     no-filter-logging case the hot path is a load + branch with NO
//     call and NO 96-byte UserspaceDpMeta copy. The rare non-None tail
//     of the output emitter is split into a #[cold] #[inline(never)]
//     callee (emit_cached_output_filter_log_tail); the input emitter's
//     non-None tail is already just a call to the cold
//     emit_input_filter_log_match.
//   - evaluate_dscp_sensitive_input_filter_on_session_hit runs per
//     packet on the session-hit path for DSCP-sensitive-filter configs
//     (flow_cache.rs:285 does not cache those). It stays #[inline] so
//     the cheap interface_input_filter_varies_per_packet guard folds in
//     (a single fast-map lookup evaluating the #1430 DSCP OR #2362
//     per-packet-L4 OR, #6236 PR-2C) and returns None with no call when
//     no such filter is configured. The post-guard body calls the cold
//     evaluate_non_pbr_input_filter.
//   - evaluate_non_pbr_input_filter / _log_only,
//     emit_input_filter_log_match, apply_lo0_filter_action are the
//     rare/exception bodies: #[cold] #[inline(never)] for .text.unlikely
//     placement away from the hot loop's cache lines.
//
// Bodies are behavior-identical to their previous location in mod.rs.
// The only deltas are: the inline attributes (#[inline] ->
// #[cold] #[inline(never)] on the cold leaves), pub(super) visibility,
// the emit_cached_output_filter_log tail split, and rustfmt
// re-collapsing the now-shorter emit_input_filter_log_match call in
// emit_cached_input_filter_log onto one line (the call previously sat
// in a wider context that forced a multiline layout). No logic,
// side-effect ordering, counter increments, or allocation sites change.

use super::*;
use super::reject_reply::enqueue_filter_reject_reply;
use super::worker::WorkerTxPipeline;
use crate::afxdp::frame::term_match_extra_from_frame;
use crate::filter::TermMatchExtra;

/// #3615: a matched filter-log record whose EMISSION is deferred until AFTER
/// the reject-reply enqueue outcome is known, so the RT_FLOW action can be
/// downgraded REJECT→DENY when the reply fail-closed. Carries everything
/// `emit_filter_log_event` needs beyond (event_stream, flow, meta, now_ns) —
/// which the caller already holds. Produced by `apply_lo0_filter_action` (the
/// lo0 host-bound filter) whose emit was previously inline; returning it lets
/// the flow-backed caller run the reject-reply enqueue FIRST, and the flowless
/// caller (which can synthesize no reply) emit with `reject_reply_enqueued =
/// false`.
#[derive(Clone, Copy)]
pub(super) struct PendingFilterLog {
    pub(super) ingress_zone_id: u16,
    pub(super) egress_zone_id: u16,
    pub(super) filter_id: u32,
    pub(super) term_id: u32,
    pub(super) action: crate::filter::FilterAction,
    pub(super) source: FilterLogSource,
    pub(super) app_id: u16,
}

/// #3615: emit a deferred filter-log record with the ACTUAL reply outcome. Used
/// by both `filter_terminal` (flow-backed) and the flowless LocalDelivery arm
/// (which passes `reject_reply_enqueued = false` because a fragment has no L4
/// header to synthesize a reply from).
#[inline]
pub(super) fn emit_pending_filter_log(
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    log: PendingFilterLog,
    reject_reply_enqueued: bool,
    now_ns: u64,
) {
    emit_filter_log_event(
        event_stream,
        flow,
        meta,
        log.ingress_zone_id,
        log.egress_zone_id,
        log.filter_id,
        log.term_id,
        log.action,
        log.source,
        log.app_id,
        reject_reply_enqueued,
        now_ns,
    );
}

/// #3615: run a filter terminal action's reply + log side-effects in the
/// TRUTHFUL order — enqueue the reject reply FIRST (only for `Reject`), then
/// emit the matched filter-log (if any) with the ACTUAL reply outcome, so a
/// suppressed reject is logged as DENY not REJECT (honoring the
/// `FilterAction::Reject(crate::filter::RejectMessage::ADMIN_PROHIBITED)` contract: a caller that cannot synthesize the reject
/// packet must not log that a reject was generated). Returns `true` iff the
/// packet must be dropped (`action != Accept`); the poll-loop caller performs
/// the recycle / host-bound session teardown on a `true` return. An accepted
/// flow with a `then log` term still emits (reject_reply_enqueued = false, which
/// Accept→PERMIT ignores). Single testable seam for the poll-loop ordering (the
/// loop body itself is un-callable) — see `filter_terminal_tests`.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn filter_terminal(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    ingress_ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    counters: &mut BatchCounters,
    action: crate::filter::FilterAction,
    log: Option<PendingFilterLog>,
    now_ns: u64,
) -> bool {
    let reject_reply_enqueued = if let crate::filter::FilterAction::Reject(reject_msg) = action {
        enqueue_filter_reject_reply(
            tx_pipeline,
            forwarding,
            ingress_ifindex,
            packet_frame,
            meta,
            flow,
            counters,
            reject_msg,
        )
    } else {
        false
    };
    if let Some(log) = log {
        emit_pending_filter_log(event_stream, flow, meta, log, reject_reply_enqueued, now_ns);
    }
    !matches!(action, crate::filter::FilterAction::Accept)
}

#[inline]
pub(super) fn filter_log_ingress_zone_id(
    forwarding: &ForwardingState,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    ingress_logical_ifindex: i32,
) -> u16 {
    ingress_zone_override
        .filter(|id| forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            forwarding
                .ifindex_to_zone_id
                .get(&ingress_logical_ifindex)
                .copied()
        })
        .or_else(|| {
            forwarding
                .ifindex_to_zone_id
                .get(&(meta.ingress_ifindex as i32))
                .copied()
        })
        .unwrap_or(0)
}

/// #6713: resolve through the shared `egress_zone_id` so a filter-log event
/// reports the SAME to-zone the policy plane adjudicated. The sibling
/// `filter_log_ingress_zone_id` above already reads `ifindex_to_zone_id`;
/// reading only `egress` here logged zone 0 for a MAC-less interface (an IPsec
/// xfrmi) whose zone the ingress half resolved correctly.
#[inline]
pub(super) fn filter_log_egress_zone_id(forwarding: &ForwardingState, egress_ifindex: i32) -> u16 {
    forwarding.egress_zone_id(egress_ifindex)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NonPbrInputFilterEval {
    pub(super) action: crate::filter::FilterAction,
    pub(super) cached_log: Option<CachedInputFilterLog>,
}

#[cold]
#[inline(never)]
pub(super) fn evaluate_non_pbr_input_filter(
    forwarding: &ForwardingState,
    extra: TermMatchExtra<'_>,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    routing_eval_follows: bool,
) -> NonPbrInputFilterEval {
    let Some(flow) = flow else {
        return NonPbrInputFilterEval {
            action: crate::filter::FilterAction::Accept,
            cached_log: None,
        };
    };
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    // #2620: pick the counter-ownership policy. `routing_eval_follows` is true
    // on every path whose caller proceeds to
    // `ingress_route_table_override` after an Accept verdict from this precheck.
    // When that path is taken AND the filter is route-lookup-affecting, the
    // routing-instance evaluator runs on the Accept/defer exit and counts the
    // same terms — so this precheck must count only on the terminal
    // discard/reject exit the routing evaluator can't reach (the poll path
    // `continue`s on a non-Accept verdict, never calling the routing
    // evaluator). `OnlyTerminalNonAccept` avoids BOTH the #2620 double-count
    // (count in both evaluators on Accept) AND the under-count regression
    // (count in neither on a discard/reject ahead of the routing-instance
    // term). Otherwise — a non-PBR-affecting filter, or the session-HIT re-eval
    // (`routing_eval_follows == false`, which never invokes the routing
    // evaluator) — this evaluator is the SOLE per-packet counter: `Always`
    // (pre-#2620 behavior).
    let count_policy = if routing_eval_follows
        && crate::filter::interface_filter_affects_route_lookup(
            &forwarding.filter_state,
            ingress_ifindex,
            is_v6,
        ) {
        crate::filter::NonRoutingCountPolicy::OnlyTerminalNonAccept
    } else {
        crate::filter::NonRoutingCountPolicy::Always
    };
    let result = crate::filter::evaluate_interface_filter_non_routing_counted(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
        meta.pkt_len as u64,
        count_policy,
    );
    let ingress_zone_id =
        filter_log_ingress_zone_id(forwarding, meta, ingress_zone_override, ingress_ifindex);
    NonPbrInputFilterEval {
        action: result.action,
        cached_log: result.log_match.map(|log_match| CachedInputFilterLog {
            log_match,
            ingress_zone_id,
        }),
    }
}

#[cold]
#[inline(never)]
pub(super) fn evaluate_non_pbr_input_filter_log_only(
    forwarding: &ForwardingState,
    extra: TermMatchExtra<'_>,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> Option<CachedInputFilterLog> {
    let Some(flow) = flow else {
        return None;
    };
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    let log_match = crate::filter::evaluate_interface_filter_log_match(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
        true,
    )?;
    Some(CachedInputFilterLog {
        log_match,
        ingress_zone_id: filter_log_ingress_zone_id(
            forwarding,
            meta,
            ingress_zone_override,
            ingress_ifindex,
        ),
    })
}

/// #3777: capture this cacheable flow's interface INPUT filter `then count`
/// term handles for replay on every flow-cache HIT. Sibling of
/// `evaluate_non_pbr_input_filter_log_only` (which captures the `then log`
/// descriptor). Cold-path counting already charged the seed packet; this only
/// collects the handles the hit path replays. Returns an empty set when there
/// is no flow, no input filter, or no `then count` term.
#[cold]
#[inline(never)]
pub(super) fn evaluate_non_pbr_input_filter_counters_cached(
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
) -> crate::filter::CachedFilterCounters {
    let Some(flow) = flow else {
        return crate::filter::CachedFilterCounters::default();
    };
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    crate::filter::evaluate_interface_input_filter_counters_cached(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
    )
}

#[inline]
pub(super) fn evaluate_dscp_sensitive_input_filter_on_session_hit(
    forwarding: &ForwardingState,
    frame: &[u8],
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> Option<NonPbrInputFilterEval> {
    let flow = flow?;
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    // #2362: re-evaluate on a session hit whenever the interface input filter
    // carries EITHER a DSCP match term OR a per-packet L4 match term
    // (tcp-flags / is-fragment / icmp-type / icmp-code). Both classes vary per
    // packet within a flow, so the first-packet decision must not be replayed.
    // #6236 PR-2C: fold the two per-flag prechecks (which each looked the same
    // ingress ifindex up on the same-family input fast map) into ONE lookup that
    // evaluates the `has_dscp_match_terms || has_per_packet_l4_match_terms` OR
    // (`Filter::varies_per_packet_within_flow`) off a single borrow. The
    // extra-build stays AFTER this gate so the common no-such-filter case pays
    // ONE FxHashMap lookup (this function is #[inline] on the hot session-hit
    // path).
    if !crate::filter::interface_input_filter_varies_per_packet(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
    ) {
        return None;
    }
    let extra = term_match_extra_from_frame(frame, meta);
    // #2620: the session-HIT re-eval is the SOLE counter for this packet — it
    // never calls `ingress_route_table_override`/the routing evaluator. Pass
    // `routing_eval_follows = false` so it counts on every exit (per-packet,
    // pre-#2620 behavior), even when the filter is route-lookup-affecting.
    Some(evaluate_non_pbr_input_filter(
        forwarding,
        extra,
        Some(flow),
        meta,
        ingress_zone_override,
        false,
    ))
}

#[cold]
#[inline(never)]
pub(super) fn emit_input_filter_log_match(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_log: CachedInputFilterLog,
    // #3615: ACTUAL reject-reply outcome. A `then reject` input-filter term
    // whose reply fail-closed (budget/rate/parse/output-filter) — or any
    // reply-free path (accept `then log`, cached-log replay, flowless
    // fragment) — passes `false` so the RT_FLOW action is downgraded
    // REJECT→DENY and never claims an active reject that was not sent.
    reject_reply_enqueued: bool,
    now_ns: u64,
) {
    emit_filter_log_event(
        event_stream,
        flow,
        meta,
        cached_log.ingress_zone_id,
        0,
        cached_log.log_match.filter_id,
        cached_log.log_match.term_id,
        cached_log.log_match.action,
        FilterLogSource::Input,
        // #2520: resolve the AppID via the hot-path app_catalog.lookup so the
        // filter-log RT_FLOW record carries the application, not UNKNOWN.
        resolve_flow_app_id(&forwarding.app_catalog, flow),
        reject_reply_enqueued,
        now_ns,
    );
}

#[inline]
pub(super) fn emit_cached_input_filter_log(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_descriptor: &RewriteDescriptor,
    now_ns: u64,
) {
    let Some(cached_log) = cached_descriptor.input_filter_log else {
        return;
    };
    // #3615: cache-HIT replay is an established (accepted) flow's `then log`
    // record — a rejected flow is never cached — so no reply is enqueued here
    // and reject_reply_enqueued is false.
    emit_input_filter_log_match(forwarding, event_stream, flow, meta, cached_log, false, now_ns);
}

#[inline]
pub(super) fn emit_cached_output_filter_log(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_decision: SessionDecision,
    cached_descriptor: &RewriteDescriptor,
    cached_metadata: &SessionMetadata,
    // #3608: whether the cached `then reject` reply actually went out; threaded
    // into the RT_FLOW action so a reject that fail-closed logs the truthful DENY
    // (#3615). `false` for a `then accept`/`then discard`/policer log.
    reject_reply_enqueued: bool,
    now_ns: u64,
) {
    let Some(log_match) = cached_descriptor.tx_selection.filter_log else {
        return;
    };
    emit_cached_output_filter_log_tail(
        forwarding,
        event_stream,
        flow,
        meta,
        cached_decision,
        cached_metadata,
        log_match,
        reject_reply_enqueued,
        now_ns,
    );
}

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn emit_cached_output_filter_log_tail(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_decision: SessionDecision,
    cached_metadata: &SessionMetadata,
    log_match: crate::filter::FilterLogMatch,
    reject_reply_enqueued: bool,
    now_ns: u64,
) {
    emit_filter_log_event(
        event_stream,
        flow,
        meta,
        cached_metadata.ingress_zone,
        filter_log_egress_zone_id(forwarding, cached_decision.resolution.egress_ifindex),
        log_match.filter_id,
        log_match.term_id,
        log_match.action,
        FilterLogSource::CachedOutput,
        // #2520: AppID via the hot-path app_catalog.lookup.
        resolve_flow_app_id(&forwarding.app_catalog, flow),
        // #3608/#3615: the cached output-filter `then reject` now DOES synthesize
        // the active reply on the flow-cache-hit path. `reject_reply_enqueued`
        // reports whether it actually went out, so a reject that fail-closed logs
        // the truthful DENY rather than claiming an active reject was sent.
        reject_reply_enqueued,
        now_ns,
    );
}

/// Evaluate the lo0 (host-bound) firewall filter and emit any matched filter
/// log. Returns the matched terminal `FilterAction` (#2521): the caller maps
/// `Accept` → deliver, `Discard` → silent drop, `Reject` → silent drop PLUS a
/// synthesized active reply (TCP RST / ICMP unreachable). Previously this
/// returned a bare `bool` (drop vs deliver), collapsing `Reject` into a silent
/// `Discard` — the parity gap #2521 closes for control-plane / host-bound
/// filters.
#[cold]
#[inline(never)]
pub(super) fn apply_lo0_filter_action(
    forwarding: &ForwardingState,
    extra: TermMatchExtra<'_>,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    // #5857: poll-iteration monotonic timestamp — threaded so the lo0 filter
    // METERS each matched term's three-color policer (control-plane rate limit).
    now_ns: u64,
) -> (crate::filter::FilterAction, Option<PendingFilterLog>) {
    let Some(flow) = flow else {
        return (crate::filter::FilterAction::Accept, None);
    };
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    let result = crate::filter::evaluate_lo0_filter_counted(
        &forwarding.filter_state,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
        meta.pkt_len as u64,
        // #5857: Some(now_ns) meters the policer on every matched lo0 term
        // (drop + color decision), exactly like the interface TX-selection leg.
        Some(now_ns),
    );
    // #5857: a policer that marked this host-bound packet as exceeding/violating
    // (`policer_drop`) forces a DROP even when the matched term's verdict was
    // Accept. This is the control-plane rate-limit enforcement that was inert
    // before #5857: the compiler linked the policer runtime and the evaluator
    // reported a match, but the lo0/local-delivery path never metered nor
    // dropped. A policer drop is a SILENT discard (Junos policer semantics — no
    // TCP RST / ICMP unreachable is synthesized), so it maps to `Discard`, not
    // `Reject`. An already-terminal `Discard`/`Reject` verdict is left intact
    // (the packet drops either way; the term's own action governs reply
    // semantics). Because `policer_drop` is OR-accumulated across the whole
    // `next term` chain, a later permit cannot erase an earlier policer drop.
    let action =
        if result.policer_drop && matches!(result.action, crate::filter::FilterAction::Accept) {
            crate::filter::FilterAction::Discard
        } else {
            result.action
        };
    // #3615: DEFER the filter-log emit — return the matched record so the caller
    // can emit it AFTER the reject-reply enqueue outcome is known (flow-backed)
    // or with reject_reply_enqueued=false (flowless). This preserves the exact
    // emit params previously computed inline.
    let pending = result.log_match.map(|log_match| PendingFilterLog {
        ingress_zone_id: filter_log_ingress_zone_id(
            forwarding,
            meta,
            ingress_zone_override,
            meta.ingress_ifindex as i32,
        ),
        egress_zone_id: 0,
        filter_id: log_match.filter_id,
        term_id: log_match.term_id,
        action: log_match.action,
        source: FilterLogSource::Lo0,
        // #2520: AppID via the hot-path app_catalog.lookup.
        app_id: resolve_flow_app_id(&forwarding.app_catalog, flow),
    });
    (action, pending)
}

/// #3485: host-inbound zone admission MUST gate the lo0 (host-bound) firewall
/// filter on the local-delivery path. `host-inbound-traffic` is the first-line
/// zone control for router self-traffic; a packet it denies is a SILENT drop
/// (Junos posture) and must NOT incur the lo0 filter's active side-effects: the
/// term counter bump (`record_filter_counter`), the filter-log event, and — in
/// the caller — the synthesized TCP RST / ICMP-unreachable reject reply plus the
/// host-bound session teardown. Before #3485 `apply_lo0_filter_action` ran FIRST
/// (codex-review-118 M1), so a service host-inbound would have silently denied
/// still triggered the lo0 reject / RST / teardown / counter / log.
///
/// This helper runs the host-inbound gate FIRST; only an ADMITTED packet pays
/// the lo0 evaluation. It returns:
///   - `None`         => host-inbound DENIED. The lo0 filter was NOT evaluated
///                       (no counter, no log). The caller drops the packet
///                       silently (no reject reply) and tears down any cached
///                       host-bound session.
///   - `Some((action, log))` => host-inbound ADMITTED. `action` is the lo0
///                       verdict the caller handles: `Accept` => deliver;
///                       `Discard` => silent drop; `Reject` => drop + reject
///                       reply. `log` is the matched lo0 filter-log record
///                       (#3615), emitted by the caller AFTER the reject-reply
///                       enqueue so the RT_FLOW action is truthful (a suppressed
///                       reject logs DENY, not REJECT) — via `filter_terminal`
///                       (flow-backed) or `emit_pending_filter_log` (flowless).
///
/// Both LocalDelivery call sites (session-HIT and session-MISS) route through
/// this single helper, which keeps the gate ordering unit-testable (vs two
/// inline blocks that only the un-callable poll loop could exercise). See
/// `lo0_gate_tests` for the RED-on-revert coverage. `host_inbound_zone` is the
/// admission zone (the session metadata's recorded ingress zone on the HIT path,
/// the resolved `from_zone_id` on the MISS path); `lo0_ingress_zone_override` is
/// the lo0 filter-log ingress-zone hint, preserved per-path unchanged.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn host_inbound_gated_lo0_action(
    forwarding: &ForwardingState,
    logical_ingress_ifindex: i32,
    host_inbound_zone: u16,
    dst_port: u16,
    is_v6: bool,
    icmp_first_l4_byte: u8,
    extra: TermMatchExtra<'_>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    lo0_ingress_zone_override: Option<u16>,
    // #5857: poll-iteration monotonic timestamp for the lo0 policer meter.
    now_ns: u64,
) -> Option<(crate::filter::FilterAction, Option<PendingFilterLog>)> {
    // Host-inbound gate FIRST — a denied packet is a fail-closed silent drop
    // with NO lo0 side-effects (#3485). #3362: keyed by ingress interface so a
    // per-interface host-inbound override governs the check where one exists,
    // falling back to the from-zone set otherwise. #3609: the override map
    // (`ifindex_host_inbound`) is keyed by the LOGICAL unit ifindex
    // (`forwarding_build/interfaces.rs`), so the caller passes the resolved
    // logical ingress ifindex — NOT the raw physical `meta.ingress_ifindex` —
    // exactly as the sibling input-filter / zone-pair / CoS sites do
    // (`resolve_ingress_logical_ifindex`). Passing the physical bind port would
    // miss a VLAN sub-interface's override and silently fall back to the zone
    // set (the #3609 bug).
    if !crate::afxdp::forwarding::host_inbound_admits_iface(
        forwarding,
        logical_ingress_ifindex,
        host_inbound_zone,
        meta.protocol,
        dst_port,
        is_v6,
        icmp_first_l4_byte,
    ) {
        return None;
    }
    // Only an admitted packet pays the lo0 evaluation (counter + deferred log).
    // #3615: the lo0 filter-log is now RETURNED (as the second tuple element),
    // not emitted here, so the caller can emit it AFTER the reject-reply
    // enqueue outcome is known and log the truthful action.
    Some(apply_lo0_filter_action(
        forwarding,
        extra,
        Some(flow),
        meta,
        lo0_ingress_zone_override,
        now_ns,
    ))
}

/// #3485: regression tests for the host-inbound-before-lo0 ordering on the
/// local-delivery path. They drive `host_inbound_gated_lo0_action` directly —
/// the single helper both the session-HIT and session-MISS call sites route
/// through — so they pin the ordering the un-callable poll loop enforces.
#[cfg(test)]
mod lo0_gate_tests {
    use super::*;
    use crate::filter::FilterAction;
    use crate::ip_proto::PROTO_TCP;
    use crate::session::SessionKey;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;

    // A configured host-inbound zone with an empty admit set denies TCP/443.
    const DENY_ZONE: u16 = 1;
    // A zone absent from the table => admit-all default (pre-#3070 behaviour).
    const ADMIT_ZONE: u16 = 2;

    /// ForwardingState whose lo0 v4 filter is a single COUNTING REJECT term
    /// matching TCP/443, with `DENY_ZONE` present-but-empty in the host-inbound
    /// table (denies) and `ADMIT_ZONE` absent (admit-all).
    fn forwarding_with_lo0_reject() -> ForwardingState {
        let mut fw = ForwardingState::default();
        fw.filter_state = crate::filter::parse_filter_state(
            &[crate::FirewallFilterSnapshot {
                name: "protect-re".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "deny-web".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    count: "lo0-web".into(),
                    action: "reject".into(),
                    ..Default::default()
                }],
            }],
            &[],
            &[],
            "protect-re",
            "",
        )
        .expect("filter state compiles");
        // Present-but-empty => the zone IS configured and admits nothing, so a
        // TCP/443 host-bound packet is denied (Junos posture).
        fw.zone_host_inbound
            .insert(DENY_ZONE, crate::afxdp::types::ZoneHostInbound::default());
        fw
    }

    /// Packets recorded by the single lo0 term's counter. In `#[cfg(test)]`
    /// `record_filter_counter` updates this atomic immediately, so a non-zero
    /// value proves the lo0 filter actually evaluated the packet.
    fn lo0_term_packets(fw: &ForwardingState) -> u64 {
        fw.filter_state
            .lo0_filter_v4_fast
            .as_ref()
            .expect("lo0 v4 filter present")
            .terms[0]
            .counter
            .packets
            .load(Ordering::Relaxed)
    }

    fn tcp_443_flow_and_meta() -> (SessionFlow, UserspaceDpMeta) {
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let meta = UserspaceDpMeta {
            protocol: PROTO_TCP,
            addr_family: libc::AF_INET as u8,
            l3_offset: 14,
            l4_offset: 34,
            tcp_flags: 0x02,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: src,
                dst_ip: dst,
                src_port: 40000,
                dst_port: 443,
            },
        };
        (flow, meta)
    }

    fn extra() -> TermMatchExtra<'static> {
        TermMatchExtra {
            tcp_flags: 0x02,
            l4_present: true,
            ..Default::default()
        }
    }

    /// A host-inbound-DENIED packet must return `None` (caller drops silently,
    /// no reject reply / no session teardown) AND must NOT evaluate the lo0
    /// filter — its counter stays 0. Reverting the reorder (lo0 first) bumps the
    /// counter to 1 on the denied packet, turning this RED.
    #[test]
    fn host_inbound_deny_skips_lo0_side_effects() {
        let fw = forwarding_with_lo0_reject();
        let (flow, meta) = tcp_443_flow_and_meta();

        let action = host_inbound_gated_lo0_action(
            &fw,
            meta.ingress_ifindex as i32,
            DENY_ZONE,
            443,
            false,
            0,
            extra(),
            &flow,
            meta,
            Some(DENY_ZONE),
            0, // #5857: now_ns — irrelevant (host-inbound denies before lo0 eval)
        );
        assert!(
            action.is_none(),
            "host-inbound deny must short-circuit with None"
        );
        assert_eq!(
            lo0_term_packets(&fw),
            0,
            "lo0 filter must NOT run on a host-inbound-denied packet (#3485)",
        );
    }

    /// A host-inbound-ADMITTED packet preserves the prior behaviour exactly:
    /// the lo0 filter evaluates, returns `Reject`, and its counter bumps.
    #[test]
    fn host_inbound_admit_runs_lo0() {
        let fw = forwarding_with_lo0_reject();
        let (flow, meta) = tcp_443_flow_and_meta();

        let action = host_inbound_gated_lo0_action(
            &fw,
            meta.ingress_ifindex as i32,
            ADMIT_ZONE,
            443,
            false,
            0,
            extra(),
            &flow,
            meta,
            Some(ADMIT_ZONE),
            0, // #5857: now_ns — no policer term in these tests, so unused
        );
        assert_eq!(
            action.map(|(a, _)| a),
            Some(FilterAction::Reject(
                crate::filter::RejectMessage::ADMIN_PROHIBITED
            )),
            "admitted packet runs the lo0 reject term",
        );
        assert_eq!(
            lo0_term_packets(&fw),
            1,
            "lo0 filter must run + count on an admitted packet",
        );
    }

    /// #3609 (M10): a host-bound packet on a VLAN LOGICAL sub-interface must get
    /// its per-interface host-inbound override. The override map
    /// (`ifindex_host_inbound`) is keyed by the LOGICAL unit ifindex
    /// (`forwarding_build::interfaces`), NOT the raw physical bind port carried
    /// in `meta.ingress_ifindex`. `host_inbound_gated_lo0_action` therefore takes
    /// the caller-resolved logical ingress ifindex (as the sibling input-filter /
    /// zone-pair / CoS sites already do) and must honour it.
    ///
    /// Setup: the LOGICAL unit carries a present-but-empty override (deny-all,
    /// the #3362 fail-closed shape); the physical bind port has NO override; the
    /// from-zone is admit-all (absent from `zone_host_inbound`). A TCP/443
    /// host-bound packet arrives on the physical port (`meta.ingress_ifindex =
    /// PHYS`) with the resolved LOGICAL ifindex threaded in. The logical override
    /// governs → DENY (`None`), and the lo0 filter never runs.
    ///
    /// Fail-on-revert: pass the raw physical `meta.ingress_ifindex` instead of
    /// the resolved logical ifindex (the pre-#3609 bug at filter.rs:452-454) and
    /// the lookup misses the override, falls back to the admit-all zone, the lo0
    /// reject term runs, and this returns `Some(Reject)` with the counter bumped
    /// to 1 — RED on BOTH assertions.
    #[test]
    fn host_inbound_override_keyed_by_logical_vlan_ifindex() {
        const PHYS_IFINDEX: u32 = 11;
        const LOGICAL_IFINDEX: i32 = 3011;

        let mut fw = forwarding_with_lo0_reject();
        // The LOGICAL VLAN unit's per-interface override admits nothing
        // (present-but-empty => deny-all). Keyed by the logical unit ifindex,
        // exactly as `forwarding_build::interfaces` populates it.
        fw.ifindex_host_inbound
            .insert(LOGICAL_IFINDEX, crate::afxdp::types::ZoneHostInbound::default());

        let (flow, mut meta) = tcp_443_flow_and_meta();
        // The frame arrives on the PHYSICAL bind port; the physical ifindex has
        // NO override, so a raw-physical lookup would fall back to the zone.
        meta.ingress_ifindex = PHYS_IFINDEX;

        // ADMIT_ZONE is absent from zone_host_inbound (admit-all) — the zone
        // fallback WOULD admit, so only the logical override can deny here.
        let action = host_inbound_gated_lo0_action(
            &fw,
            LOGICAL_IFINDEX,
            ADMIT_ZONE,
            443,
            false,
            0,
            extra(),
            &flow,
            meta,
            Some(ADMIT_ZONE),
            0, // #5857: now_ns — no policer term in these tests, so unused
        );
        assert!(
            action.is_none(),
            "VLAN logical-interface host-inbound override (deny-all) must govern \
             and deny TCP/443 — #3609",
        );
        assert_eq!(
            lo0_term_packets(&fw),
            0,
            "lo0 filter must NOT run when the logical override denies (#3609)",
        );
    }

    /// #5857: a lo0 (host-bound) firewall filter term carrying a named policer
    /// must METER host-bound traffic and DROP packets that exceed the configured
    /// rate. Before #5857 the control-plane rate limit was INERT — the compiler
    /// linked the three-color runtime and `evaluate_lo0_filter_counted` reported
    /// a match + copied `policer_name`, but the local-delivery path
    /// (`apply_lo0_filter_action`) consumed only `action` + `log_match`: it never
    /// metered the policer nor dropped an exceeding packet. An untrusted peer
    /// could therefore exceed the operator's control-plane protection envelope.
    ///
    /// This drives `host_inbound_gated_lo0_action` — the single helper both
    /// LocalDelivery call sites (session-HIT and session-MISS) route through —
    /// with a conforming then an exceeding host-bound UDP packet on an admit-all
    /// zone, and asserts the exceeding packet DROPS and the policer drop counter
    /// advances (proving the meter actually ran, not just that a verdict flipped).
    ///
    /// Fail-on-revert: neutralizing the metering wire-in (the
    /// `apply_term_three_color_policer` call in `eval::merge_matched_modifiers`,
    /// or the `policer_drop`→`Discard` downgrade in `apply_lo0_filter_action`)
    /// leaves the second packet ACCEPTED and `drop_packets` at 0 — RED on both.
    #[test]
    fn lo0_policer_meters_and_drops_host_bound_traffic() {
        // lo0 filter: UDP host-bound traffic is accepted but rate-limited by a
        // single-rate policer (1000-byte bucket) — a control-plane protect-RE
        // filter policing a host-bound service.
        let mut fw = ForwardingState::default();
        fw.filter_state = crate::filter::parse_filter_state(
            &[crate::FirewallFilterSnapshot {
                name: "protect-re".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "police-udp".into(),
                    protocols: vec!["udp".into()],
                    policer: "rl-1kb".into(),
                    action: "accept".into(),
                    count: "lo0-udp".into(),
                    ..Default::default()
                }],
            }],
            &[crate::PolicerSnapshot {
                name: "rl-1kb".into(),
                bandwidth_bps: 8_000, // 1000 bytes/sec committed rate
                burst_bytes: 1_000,   // 1000-byte token bucket
                discard_excess: true,
            }],
            &[],
            "protect-re",
            "",
        )
        .expect("filter state compiles");

        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // meta.pkt_len drives the policer byte count (apply_lo0_filter_action
        // passes it as `packet_bytes`).
        let make = |pkt_len: u16| {
            let meta = UserspaceDpMeta {
                protocol: crate::ip_proto::PROTO_UDP,
                addr_family: libc::AF_INET as u8,
                l3_offset: 14,
                l4_offset: 34,
                pkt_len,
                ..UserspaceDpMeta::default()
            };
            let flow = SessionFlow {
                src_ip: src,
                dst_ip: dst,
                forward_key: SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol: crate::ip_proto::PROTO_UDP,
                    src_ip: src,
                    dst_ip: dst,
                    src_port: 40000,
                    dst_port: 5000,
                },
            };
            (flow, meta)
        };
        let extra_udp = TermMatchExtra {
            l4_present: true,
            ..Default::default()
        };
        // now_ns fixed so the token bucket does NOT refill between the packets.
        const NOW_NS: u64 = 1_000;

        // First 900-byte packet drains most of the 1000-byte bucket — conforming
        // → delivered (Accept).
        let (flow1, meta1) = make(900);
        let first = host_inbound_gated_lo0_action(
            &fw,
            meta1.ingress_ifindex as i32,
            ADMIT_ZONE,
            5000,
            false,
            0,
            extra_udp,
            &flow1,
            meta1,
            Some(ADMIT_ZONE),
            NOW_NS,
        );
        assert_eq!(
            first.map(|(a, _)| a),
            Some(FilterAction::Accept),
            "a conforming host-bound packet must be delivered",
        );

        // Second 900-byte packet exceeds the ~100 remaining tokens — the policer
        // drops it. Before #5857 this was ACCEPTED (rate limit inert).
        let (flow2, meta2) = make(900);
        let second = host_inbound_gated_lo0_action(
            &fw,
            meta2.ingress_ifindex as i32,
            ADMIT_ZONE,
            5000,
            false,
            0,
            extra_udp,
            &flow2,
            meta2,
            Some(ADMIT_ZONE),
            NOW_NS,
        );
        assert_eq!(
            second.map(|(a, _)| a),
            Some(FilterAction::Discard),
            "host-bound traffic above the lo0 policer rate must be dropped (#5857)",
        );

        // The policer's drop counter advanced — proving the meter ran on the
        // host-bound path.
        let status = fw.filter_state.three_color_policer_statuses();
        assert_eq!(status.len(), 1, "one lowered single-rate policer");
        assert!(
            status[0].drop_packets >= 1,
            "the lo0 policer must record the host-bound drop",
        );
    }
}

/// #3615 M10: poll-loop-path ordering coverage for `filter_terminal` — the
/// combining helper the lo0 reject sites call. It must enqueue the reject reply
/// FIRST and emit the filter-log with the ACTUAL reply outcome, so a SUPPRESSED
/// reject (budget/rate/parse/output-filter) logs the truthful DENY, not REJECT.
/// Asserts event action + counter + TX queue length together (issue #3615 M10).
#[cfg(test)]
mod filter_terminal_tests {
    use super::*;
    use crate::ip_proto::{PROTO_ICMP, PROTO_TCP};
    use crate::session::SessionKey;
    use std::net::{IpAddr, Ipv4Addr};

    // RT_FLOW action bytes (event_emit.rs): DENY = 0, REJECT = 2.
    const RT_FLOW_ACTION_DENY: u8 = 0;
    const RT_FLOW_ACTION_REJECT: u8 = 2;

    fn tx_pipeline(max_pending_tx: usize, free_frames: usize) -> WorkerTxPipeline {
        WorkerTxPipeline {
            free_tx_frames: (0..free_frames as u64).collect(),
            pending_tx_prepared: VecDeque::new(),
            pending_tx_local: VecDeque::new(),
            max_pending_tx,
            outstanding_tx: 0,
            pending_fill_frames: VecDeque::new(),
            in_flight_prepared_recycles: FastMap::default(),
            tx_submit_ns: Vec::new().into_boxed_slice(),
        }
    }

    fn event_handle() -> (
        crate::event_stream::EventStreamWorkerHandle,
        std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
    ) {
        crate::event_stream::test_worker_handle(
            8,
            crate::event_stream::DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        )
    }

    fn reject_log() -> PendingFilterLog {
        PendingFilterLog {
            ingress_zone_id: 7,
            egress_zone_id: 0,
            filter_id: 23,
            term_id: 6,
            action: crate::filter::FilterAction::Reject(
                crate::filter::RejectMessage::ADMIN_PROHIBITED,
            ),
            source: FilterLogSource::Lo0,
            app_id: 0,
        }
    }

    fn v4_flow(protocol: u8) -> SessionFlow {
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol,
                src_ip: src,
                dst_ip: dst,
                src_port: 40000,
                dst_port: 443,
            },
        }
    }

    /// TX-frame budget exhausted → a BUILDABLE reject reply is suppressed and
    /// counted as budget pressure. #3656: a budget drop is now attributed only
    /// once reply-build feasibility is proven, so this must drive a real,
    /// parseable TCP SYN (an unparseable/empty frame would be an unreplyable
    /// PLAIN drop that counts NO budget drop — see
    /// `unreplyable_reject_does_not_count_budget_drop_3656` in reject_reply.rs).
    #[test]
    fn filter_terminal_budget_suppressed_reject_logs_deny() {
        let (handle, rx) = event_handle();
        let mut pipeline = tx_pipeline(0, 64); // zero budget => suppressed
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        let flow = v4_flow(PROTO_TCP);
        // A reflected TCP RST is self-contained (build_reject_rst_frame reflects
        // the inbound frame), so a minimal parseable SYN suffices to make the
        // reply FEASIBLE before the budget gate suppresses it.
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6, 0x08, 0x00,
        ]);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        frame.extend_from_slice(&49152u16.to_be_bytes());
        frame.extend_from_slice(&22u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xfa, 0xf0, 0x00, 0x00,
            0x00, 0x00,
        ]);
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 54,
            protocol: PROTO_TCP,
            tcp_flags: 0x02,
            addr_family: libc::AF_INET as u8,
            pkt_len: frame.len() as u16,
            ..UserspaceDpMeta::default()
        };
        let drop = filter_terminal(
            &mut pipeline,
            &forwarding,
            Some(&handle),
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            crate::filter::FilterAction::Reject(crate::filter::RejectMessage::ADMIN_PROHIBITED),
            Some(reject_log()),
            123,
        );
        assert!(drop, "a reject terminal action drops the packet");
        assert!(
            pipeline.pending_tx_local.is_empty(),
            "no reply may be enqueued under budget exhaustion"
        );
        assert_eq!(counters.filter_reject_reply_budget_drops, 1);
        assert_eq!(counters.filter_reject_sent, 0);
        let event = rx
            .try_recv()
            .expect("filter-log event frame")
            .decode_dataplane_event()
            .expect("filter-log payload");
        assert_eq!(
            event.action, RT_FLOW_ACTION_DENY,
            "a suppressed filter reject on the poll path must log DENY, not REJECT"
        );
    }

    /// Egress OUTPUT filter discards the reflected reply → suppressed → the
    /// filter-log reports the truthful DENY and the FILTER-source output-filter
    /// counter increments (not the policy sibling).
    #[test]
    fn filter_terminal_output_filter_suppressed_reject_logs_deny() {
        use crate::afxdp::icmp_ratelimit::{
            GeneratedErrorReason, global_bucket_test_lock, reset_bucket_for_test,
        };
        let _g = global_bucket_test_lock();
        reset_bucket_for_test(GeneratedErrorReason::Reject, 0);

        // Inbound ICMP echo on ifindex 5 → the reject path builds an ICMP
        // unreachable, which the egress output filter (discard icmp) drops.
        let client = Ipv4Addr::new(10, 0, 61, 102);
        let server = Ipv4Addr::new(1, 1, 1, 1);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_ICMP, 0, 0,
        ]);
        frame.extend_from_slice(&client.octets());
        frame.extend_from_slice(&server.octets());
        frame.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]); // ICMP echo
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            pkt_len: frame.len() as u16,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: IpAddr::V4(client),
            dst_ip: IpAddr::V4(server),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_ICMP,
                src_ip: IpAddr::V4(client),
                dst_ip: IpAddr::V4(server),
                src_port: 0x1234,
                dst_port: 0,
            },
        };
        let filter_state = crate::filter::parse_filter_state(
            &[crate::FirewallFilterSnapshot {
                name: "drop-icmp".into(),
                family: "inet".into(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "drop-icmp".into(),
                    action: "discard".into(),
                    protocols: vec!["icmp".into()],
                    ..Default::default()
                }],
            }],
            &[],
            &[crate::InterfaceSnapshot {
                name: "ge-0/0/1.0".into(),
                ifindex: 5,
                filter_output_v4: "drop-icmp".into(),
                ..Default::default()
            }],
            "",
            "",
        )
        .expect("filter state compiles");
        let mut forwarding = ForwardingState {
            filter_state,
            tx_selection_enabled_v4: true,
            ..ForwardingState::default()
        };
        forwarding.egress.insert(
            5,
            EgressInterface {
                bind_ifindex: 5,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone_id: 0,
                redundancy_group: 0,
                primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
                primary_v6: None,
            },
        );
        let (handle, rx) = event_handle();
        let mut pipeline = tx_pipeline(4096, 4096);
        let mut counters = BatchCounters::default();
        let mut log = reject_log();
        log.source = FilterLogSource::Input;
        let drop = filter_terminal(
            &mut pipeline,
            &forwarding,
            Some(&handle),
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            crate::filter::FilterAction::Reject(crate::filter::RejectMessage::ADMIN_PROHIBITED),
            Some(log),
            123,
        );
        assert!(drop, "a reject terminal action drops the packet");
        assert!(
            pipeline.pending_tx_local.is_empty(),
            "the reflected reply is discarded by the egress output filter"
        );
        assert_eq!(counters.filter_reject_output_filter_drops, 1);
        assert_eq!(counters.policy_reject_output_filter_drops, 0);
        assert_eq!(counters.filter_reject_sent, 0);
        let event = rx
            .try_recv()
            .expect("filter-log event frame")
            .decode_dataplane_event()
            .expect("filter-log payload");
        assert_eq!(
            event.action, RT_FLOW_ACTION_DENY,
            "an output-filter-suppressed filter reject must log DENY, not REJECT"
        );
    }

    /// GREEN companion: a TCP reject whose RST IS enqueued logs the truthful
    /// REJECT and increments `filter_reject_sent`.
    #[test]
    fn filter_terminal_success_logs_reject() {
        use crate::afxdp::icmp_ratelimit::{
            GeneratedErrorReason, global_bucket_test_lock, reset_bucket_for_test,
        };
        let _g = global_bucket_test_lock();
        reset_bucket_for_test(GeneratedErrorReason::Reject, 0);
        // A reflected TCP RST is self-contained (build_reject_rst_frame reflects
        // the inbound frame), so a minimal SYN frame suffices.
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6, 0x08, 0x00,
        ]);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        frame.extend_from_slice(&49152u16.to_be_bytes());
        frame.extend_from_slice(&22u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xfa, 0xf0, 0x00, 0x00,
            0x00, 0x00,
        ]);
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 54,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: 0x02,
            pkt_len: frame.len() as u16,
            ..UserspaceDpMeta::default()
        };
        let flow = v4_flow(PROTO_TCP);
        let (handle, rx) = event_handle();
        let mut pipeline = tx_pipeline(4096, 4096);
        let forwarding = ForwardingState::default();
        let mut counters = BatchCounters::default();
        let mut log = reject_log();
        log.source = FilterLogSource::Input;
        let drop = filter_terminal(
            &mut pipeline,
            &forwarding,
            Some(&handle),
            5,
            &frame,
            meta,
            &flow,
            &mut counters,
            crate::filter::FilterAction::Reject(crate::filter::RejectMessage::ADMIN_PROHIBITED),
            Some(log),
            123,
        );
        assert!(drop, "a reject terminal action drops the original packet");
        assert_eq!(counters.filter_reject_sent, 1, "the RST must be enqueued");
        assert_eq!(pipeline.pending_tx_local.len(), 1);
        let event = rx
            .try_recv()
            .expect("filter-log event frame")
            .decode_dataplane_event()
            .expect("filter-log payload");
        assert_eq!(
            event.action, RT_FLOW_ACTION_REJECT,
            "an enqueued filter reject must log the truthful REJECT"
        );
    }
}

/// #6713: the filter-log egress-zone field must report exactly the to-zone the
/// policy plane adjudicated. `emit_cached_output_filter_log_tail` (the
/// flow-cache-hit output path) is the only production caller of
/// `filter_log_egress_zone_id`, and before #6713 it open-coded a
/// `state.egress`-only read.
///
/// Nothing bound that call site: every other filter-log assertion in the suite
/// uses a MAC-FUL interface, where the `egress` row and the ifindex maps agree,
/// so reverting the helper body to
/// `forwarding.egress.get(&ifx).map(|i| i.zone_id).unwrap_or(0)` left the whole
/// suite green.
///
/// Scope, stated precisely because an earlier revision of this comment was not:
/// the tests below that call `filter_log_egress_zone_id` directly bind the
/// HELPER, not its consumer. A helper proven in isolation says nothing about
/// whether the production path still routes through it — someone could re-open
/// the `state.egress`-only read inside `emit_cached_output_filter_log_tail`
/// itself and every direct-helper test would stay green.
/// `cached_output_filter_log_reports_the_adjudicated_zone_6722` therefore drives
/// `emit_cached_output_filter_log_tail` and asserts the EMITTED event, so the
/// consumer is bound too.
#[cfg(test)]
mod filter_log_egress_zone_tests {
    use super::*;
    use crate::afxdp::forwarding_build::build_forwarding_state;
    use crate::afxdp::test_fixtures::{
        LAN_IFINDEX_6722, SHARED_TUNNEL_IFINDEX_6722, TEST_SIBLING_VPN_ZONE_ID_6722,
        ZONED_TUNNEL_IFINDEX_6722, sibling_tunnel_units_snapshot_6722,
    };
    use crate::test_zone_ids::TEST_LAN_ZONE_ID;

    /// #6722: build the state through the REAL `build_forwarding_state` from the
    /// shared secure-tunnel fixture rather than hand-populating a
    /// `ForwardingState`. The round-3 version hand-inserted into
    /// `ifindex_to_zone_id` only, so it encoded a map layout instead of a
    /// snapshot and went red on a builder change that was correct — it could
    /// only ever agree with the resolver by coincidence.
    ///
    /// The fixture gives three ifindexes worth logging:
    ///   - `LAN_IFINDEX_6722`   — MAC-ful and zoned, so it HAS an egress row;
    ///   - `ZONED_TUNNEL_IFINDEX_6722` (`st0.1`) — MAC-less, zoned, its own
    ///     ifindex, so no egress row and the #6713 fallback is the only
    ///     resolver;
    ///   - `SHARED_TUNNEL_IFINDEX_6722` (`st0`/`st0.0`) — MAC-less and
    ///     AMBIGUOUS, so the #6722 gate holds it at 0.
    fn forwarding_with_macless_egress() -> ForwardingState {
        build_forwarding_state(&sibling_tunnel_units_snapshot_6722())
    }

    /// #6713 at the log site: a flow egressing a correctly-zoned MAC-less
    /// tunnel must log that tunnel's zone, not 0.
    #[test]
    fn filter_log_egress_zone_id_reports_a_macless_tunnels_zone_6713() {
        let fw = forwarding_with_macless_egress();
        assert!(
            !fw.egress.contains_key(&ZONED_TUNNEL_IFINDEX_6722),
            "precondition: the MAC-less tunnel has NO egress row -- that hole is \
             what makes this call site interesting"
        );
        assert_eq!(
            filter_log_egress_zone_id(&fw, ZONED_TUNNEL_IFINDEX_6722),
            TEST_SIBLING_VPN_ZONE_ID_6722,
            "the logged to-zone must match the zone the policy plane adjudicated"
        );
        // Control: the MAC-ful interface is unaffected either way.
        assert_eq!(
            filter_log_egress_zone_id(&fw, LAN_IFINDEX_6722),
            TEST_LAN_ZONE_ID
        );
        // An ifindex in neither map is 0.
        assert_eq!(filter_log_egress_zone_id(&fw, 9999), 0);
    }

    /// #6722/#6713 at the PRODUCTION call site, not the helper. The tests above
    /// prove `filter_log_egress_zone_id`; this one drives
    /// `emit_cached_output_filter_log_tail` — the only production caller — and
    /// asserts the zone on the event it actually emits.
    ///
    /// It adjudicates BOTH ifindexes, and the pairing is what makes it bind.
    /// An ambiguous ifindex alone would NOT bind the consumer: after #6722 B1
    /// the egress row's `zone_id` is ledger-derived, so for an ifindex that HAS
    /// an egress row the helper and a raw `state.egress` read agree by
    /// construction, and reverting the call inside
    /// `emit_cached_output_filter_log_tail` stays green. The MAC-less zoned
    /// tunnel is the discriminator: it has NO egress row, so the helper resolves
    /// its zone through the #6713 fallback while a raw `state.egress` read
    /// yields 0.
    ///
    /// (That is not hypothetical — the first version of this test used only the
    /// ambiguous ifindex and the revert-the-caller mutation left it green.)
    #[test]
    fn cached_output_filter_log_reports_the_adjudicated_zone_6722() {
        let fw = forwarding_with_macless_egress();

        // One emission per handle: the event stream is stateful (batching and
        // rate-limit budget are per handle), so reusing one receiver across two
        // emissions makes the SECOND assertion depend on stream internals rather
        // than on the zone. A fresh handle isolates each.
        let logged_zone_for = |egress_ifindex: i32| -> u16 {
            let (handle, rx) = crate::event_stream::test_worker_handle(
                8,
                crate::event_stream::DataplaneEventRateLimitConfig {
                    events_per_second: 0,
                    burst: 0,
                },
            );
            let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
            let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            let flow = SessionFlow {
                src_ip: src,
                dst_ip: dst,
                forward_key: SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol: PROTO_TCP,
                    src_ip: src,
                    dst_ip: dst,
                    src_port: 40000,
                    dst_port: 443,
                },
            };
            let meta = UserspaceDpMeta {
                ingress_ifindex: LAN_IFINDEX_6722 as u32,
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                ..UserspaceDpMeta::default()
            };
            let decision = SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex,
                    tx_ifindex: egress_ifindex,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                },
                nat: NatDecision::default(),
            };
            let metadata = SessionMetadata {
                ingress_zone: TEST_LAN_ZONE_ID,
                // #4983: mirror the frame's own ingress binding (`meta`
                // above), which is what the production install sites stamp.
                // Untagged, hence vlan id 0.
                ingress_ifindex: LAN_IFINDEX_6722 as u32,
                ingress_vlan_id: 0,
                egress_zone: 0,
                owner_rg_id: 0,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
                log_session_init: false,
                log_session_close: false,
                policy_id: 0,
                inactivity_timeout_ns: None,
                policy_counter: None,
                policy_counter_idx: 0,
            };

            emit_cached_output_filter_log_tail(
                &fw,
                Some(&handle),
                &flow,
                meta,
                decision,
                &metadata,
                crate::filter::FilterLogMatch {
                    filter_id: 23,
                    term_id: 6,
                    action: crate::filter::FilterAction::Accept,
                },
                false,
                123,
            );

            let event = rx
                .try_recv()
                .expect("cached output filter-log event")
                .decode_dataplane_event()
                .expect("filter-log payload");
            assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
            event.egress_zone_id
        };

        assert_eq!(
            logged_zone_for(SHARED_TUNNEL_IFINDEX_6722),
            0,
            "the PRODUCTION cached-output path must log the adjudicated 0 for an \
             ambiguous ifindex, not the sibling unit's zone"
        );

        // The DISCRIMINATOR: a MAC-less zoned tunnel has no egress row, so only
        // a caller that still routes through the resolver reports its zone. A
        // raw `state.egress` read here yields 0.
        assert!(
            !fw.egress.contains_key(&ZONED_TUNNEL_IFINDEX_6722),
            "precondition: no egress row, so the #6713 fallback is the only \
             thing that can resolve this zone"
        );
        assert_eq!(
            logged_zone_for(ZONED_TUNNEL_IFINDEX_6722),
            TEST_SIBLING_VPN_ZONE_ID_6722,
            "the PRODUCTION path must still resolve a MAC-less zoned tunnel's \
             zone through the resolver -- an `egress`-only read logs 0 here"
        );
    }

    /// #6722 at the log site: the log field is derived from the SAME resolver
    /// the policy plane adjudicates with, so an AMBIGUOUS ifindex must log 0
    /// here too. A log naming `vpnb` for transit the firewall denied under the
    /// default policy would send an operator hunting a `lan->vpnb` rule that
    /// never ran.
    #[test]
    fn filter_log_egress_zone_id_reports_no_zone_for_an_ambiguous_ifindex_6722() {
        let fw = forwarding_with_macless_egress();
        assert!(
            !fw.egress.contains_key(&SHARED_TUNNEL_IFINDEX_6722),
            "precondition: MAC-less, so no egress row"
        );
        assert_eq!(
            fw.ifindex_to_zone_id
                .get(&SHARED_TUNNEL_IFINDEX_6722)
                .copied()
                .unwrap_or(0),
            TEST_SIBLING_VPN_ZONE_ID_6722,
            "precondition: the map the log site must NOT read carries a real \
             nonzero zone for this ifindex"
        );
        assert_eq!(
            filter_log_egress_zone_id(&fw, SHARED_TUNNEL_IFINDEX_6722),
            0,
            "the logged to-zone must be the adjudicated 0, not the sibling's zone"
        );
    }
}
