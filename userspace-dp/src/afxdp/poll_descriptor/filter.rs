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
//   - evaluate_input_filter_on_session_hit (#7212, formerly
//     evaluate_dscp_sensitive_input_filter_on_session_hit) runs on the
//     session-hit path. It stays #[inline] so the cheap guard folds in —
//     ONE `iface_filter_v{4,6}_fast` lookup now serving both the #1430
//     DSCP / #2362 per-packet-L4 re-eval gate and the #7212 static
//     revalidation gate — and returns None with no call when the ingress
//     interface has no input filter in this family. The post-guard bodies
//     call the cold evaluate_non_pbr_input_filter and the cold
//     revalidate_static_input_filter_on_session_hit.
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

/// #3777/#10566: capture this cacheable flow's interface INPUT filter `then count`
/// term handles for replay on every flow-cache HIT. The seed path charges the
/// handles exactly once (the cold evaluator for misses, or the seed insert arm
/// for an uncounted established-hit ACCEPT); this helper only collects handles.
/// Returns an empty set when there is no flow, no input filter, or no `then count` term.
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

/// #7212: what an established-session HIT owes the ingress interface's INPUT
/// filter, after the ONE `iface_filter_v{4,6}_fast` lookup that decides it.
#[derive(Clone, Debug)]
pub(super) struct SessionHitInputFilterEval {
    /// The verdict + any `then log` record, produced by the ordinary counted
    /// evaluator so a packet the filter drops is counted and logged exactly as a
    /// session-MISS packet would be.
    pub(super) eval: NonPbrInputFilterEval,
    /// #8114 item 1: which evaluator produced `eval.cached_log`, so the emitted
    /// record names the same source the session-MISS path would have named for
    /// the same term. A verdict from a matched `routing-instance` term is
    /// `FilterLogSource::Pbr` — that is what `ingress_route_table_override`
    /// stamps on it — and everything else is `Input`. Getting this wrong does
    /// not change what is dropped; it mislabels the record an operator
    /// correlates against, which is worse than not logging.
    pub(super) log_source: FilterLogSource,
    /// #7212: `Some(canonical key)` when this verdict came from a STATIC-filter
    /// REVALIDATION rather than a per-packet re-evaluation, so a non-`Accept`
    /// action REVOKES the session — both directions, plus its flow-cache slots
    /// — instead of only dropping this packet. `None` on the #1430/#2362
    /// per-packet path, whose verdict is about THIS packet and says nothing
    /// about the flow.
    ///
    /// It carries the KEY rather than a bool because the caller's `resolved.key`
    /// is a WIRE tuple (`ResolvedSessionKey::QueryKey` on a local hit), and an
    /// entry reached through the NAT reverse-translated ALIAS index is stored
    /// under a DIFFERENT key than the one that found it — that tuple names no
    /// entry in the primary index. Handing the caller the canonical key this
    /// revalidation actually resolved is what makes the teardown act on the
    /// session that was judged.
    ///
    /// An ordinary source-NAT reply is NOT that case, and an earlier revision of
    /// this comment said it was: the pair install stores the reverse companion
    /// under `reverse_session_key(forward, nat)`, which is ALREADY the wire reply
    /// tuple, so that reply resolves through the primary index. The alias index
    /// holds the post-de-NAT tuple. The fix is a correct superset either way —
    /// the resolution is right for both — but the severity was overstated.
    pub(super) revoked_key: Option<crate::session::SessionKey>,
}

/// #7212: collect the keys whose flow-cache slots a revocation must evict.
///
/// Three, and each is a different identity the same revoked flow is known by:
///
///   * `canonical_key` — what the SESSION TABLE holds, and what
///     `delete_terminal_filtered_session` deletes;
///   * its COMPANION, derived with the same `reverse_session_key` transform the
///     teardown uses internally, so the eviction set is exactly the deletion
///     set;
///   * `wire_key` — what the packet carried, which is what the FLOW CACHE is
///     keyed by (`FlowCacheEntry::from_forward_decision` stamps
///     `flow.forward_key`). On the NAT reverse-translated alias path that is the
///     TRANSLATED tuple and differs from the canonical key — the same divergence
///     `canonical_session_key` exists for — so evicting only the table's two
///     identities leaves an aliased reply's descriptor live.
///
/// `invalidate_slot` requires exact key equality, so a duplicate would cost one
/// no-op set walk per binding; duplicates are elided here anyway. A named helper
/// rather than three inline pushes because the aliased case is exactly the one
/// an inline version gets wrong, and the poll loop it would live in is not
/// callable from a test.
pub(super) fn collect_revoked_flow_cache_keys(
    wire_key: &crate::session::SessionKey,
    canonical_key: &crate::session::SessionKey,
    nat: crate::nat::NatDecision,
    out: &mut Vec<crate::session::SessionKey>,
) {
    let companion = crate::session::reverse_session_key(canonical_key, nat);
    out.push(canonical_key.clone());
    if companion != *canonical_key {
        out.push(companion);
    }
    if wire_key != canonical_key {
        out.push(wire_key.clone());
    }
}
/// #10467: re-derive a stale established session's PBR route-table identity.
///
/// A plain `routing-instance` term is a permit, not a session revocation
/// (#8114). It still changes the route lookup, though, and the old hit path
/// kept using the cached MAIN resolution forever after a config commit added
/// the term. This helper runs only for the one stale `(generation, ingress)`
/// stamp and resolves the target in the matched table.
///
/// The result is consumed by the poll caller as a pair teardown: changing a
/// route table can also change the egress zone and the reverse companion's
/// route, so the safe cutover is to discard this hit, evict the pair, and let
/// the next packet take the ordinary session-miss path under the new snapshot.
/// The desired `(domain, check)` is compared with the install stamp, so an
/// unrelated generation bump does not churn an unchanged steer. A removed PBR
/// term maps back to MAIN `(0, 0)` and is handled as a route change too.
#[derive(Clone, Debug)]
pub(super) struct SessionHitPbrRouteRevalidation {
    pub(super) canonical_key: crate::session::SessionKey,
    /// `None` for a resolved hit that this worker does not hold locally:
    /// derive/drop the packet, but never hand teardown a key that names no
    /// entry (#8114 sessionless contract).
    pub(super) revoked_key: Option<crate::session::SessionKey>,
    pub(super) resolution: ForwardingResolution,
}

pub(super) fn revalidate_static_pbr_route_on_session_hit(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    sessions: &SessionTable,
    session_key: &crate::session::SessionKey,
    flow: &SessionFlow,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    decision: SessionDecision,
) -> Option<SessionHitPbrRouteRevalidation> {
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    // Static filters are generation-scoped; per-packet route predicates must
    // be evaluated on every HIT, even when the static stamp is Fresh.
    let target = sessions.filter_revalidation_target(session_key, ingress_ifindex);
    let no_local_entry =
        matches!(&target, crate::session::FilterRevalidationTarget::NoLocalEntry);
    let route_filter = crate::filter::interface_filter_route_lookup_affecting(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
    );
    let per_packet_route_filter = route_filter
        .as_ref()
        .is_some_and(|filter| filter.varies_per_packet_within_flow());
    let canonical_key = match target {
        crate::session::FilterRevalidationTarget::Stale(canonical_key) => canonical_key,
        crate::session::FilterRevalidationTarget::Fresh if per_packet_route_filter => {
            // A Fresh target can still be reached through a translated reverse
            // alias. Resolve the slab record's canonical key instead of
            // cloning the wire/query tuple, or pair teardown targets nothing.
            sessions
                .revalidation_canonical_key(session_key)
                .unwrap_or_else(|| session_key.clone())
        }
        crate::session::FilterRevalidationTarget::Fresh => return None,
        crate::session::FilterRevalidationTarget::NoLocalEntry => {
            // There is no local key to revoke. The route result still drives a
            // fail-closed drop for a sessionless PBR hit.
            session_key.clone()
        }
    };
    // A non-PBR filter has no route identity to derive here; its sessionless
    // deny/permit contract is handled by evaluate_input_filter_on_session_hit.
    if no_local_entry && route_filter.is_none() {
        return None;
    }
    // #10312: the production miss path uses native RI membership whenever a
    // route-affecting filter is absent or has no matching PBR term. Preserve
    // that fallback here so an unrelated generation bump does not tear down an
    // unchanged native-RI session. An unresolvable native RI is terminal, not
    // MAIN: it must fail closed on this hit just as it does on a miss.
    let native_route_table = || {
        crate::afxdp::forwarding::native_route_table_for_flow_target(
            forwarding,
            flow.forward_key.routing_domain,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
            ingress_zone_override,
            flow.dst_ip,
        )
    };
    let (desired_identity, table, native_unresolvable) = match route_filter {
            None => match native_route_table() {
                crate::afxdp::forwarding::NativeRouteTable::Default => ((0, 0), None, false),
                crate::afxdp::forwarding::NativeRouteTable::Table {
                    table,
                    domain,
                    check,
                } => ((domain, check), Some(table), false),
                crate::afxdp::forwarding::NativeRouteTable::Unresolvable { .. } => {
                    ((0, 0), None, true)
                }
            },
            Some(filter) => {
                // #8114: every `None` exit must state why the route identity
                // is not being revalidated. Per-packet fields are available on
                // the established HIT just as on MISS, so evaluate these
                // filters against this frame instead of declining the route
                // transition. Static filters keep the tuple-only fast shape.
                let mut extra = if filter.varies_per_packet_within_flow() {
                    crate::afxdp::frame::term_match_extra_from_frame(packet_frame, meta)
                } else {
                    crate::filter::TermMatchExtra::default()
                };
                // #9894: keyed-GRE and other L3-only flows use (0,0) as a
                // synthetic tuple. Port-constrained PBR terms must fail closed
                // on both HIT and MISS, including except/negated-port terms.
                if flow.forward_key.src_port == 0 && flow.forward_key.dst_port == 0 {
                    extra.ports_unknown = true;
                }
                match crate::filter::evaluate_filter_ref_routing_instance_uncounted(
                    filter,
                    flow.src_ip,
                    flow.dst_ip,
                    meta.protocol,
                    flow.forward_key.src_port,
                    flow.forward_key.dst_port,
                    meta.dscp,
                    extra,
                ) {
                    Some(pbr) if pbr.action == crate::filter::FilterAction::Accept => {
                        let identity = crate::session::install_table_identity(pbr.routing_instance);
                        let table = if is_v6 {
                            format!("{}.inet6.0", pbr.routing_instance)
                        } else {
                            format!("{}.inet.0", pbr.routing_instance)
                        };
                        (identity, Some(table), false)
                    }
                    Some(_) => {
                        // Drop/reject terms remain owned by the composed static
                        // evaluator below, which preserves its counted deny
                        // semantics.
                        return None;
                    }
                    None => match native_route_table() {
                        crate::afxdp::forwarding::NativeRouteTable::Default => {
                            ((0, 0), None, false)
                        }
                        crate::afxdp::forwarding::NativeRouteTable::Table {
                            table,
                            domain,
                            check,
                        } => ((domain, check), Some(table), false),
                        crate::afxdp::forwarding::NativeRouteTable::Unresolvable { .. } => {
                            ((0, 0), None, true)
                        }
                    },
                }
            }
        };
    let target = crate::afxdp::session_glue::resolution_target_for_session(flow, decision);
    if native_unresolvable {
        return Some(SessionHitPbrRouteRevalidation {
            revoked_key: (!no_local_entry).then_some(canonical_key.clone()),
            canonical_key,
            resolution: crate::afxdp::forwarding::no_route_resolution(Some(target)),
        });
    }
    if desired_identity == (decision.install_table_domain, decision.install_table_check) {
        return None;
    }
    let resolution =
        crate::afxdp::forwarding::lookup_forwarding_resolution_in_table_with_dynamic(
            forwarding,
            dynamic_neighbors,
            target,
            table.as_deref(),
        );
    Some(SessionHitPbrRouteRevalidation {
        revoked_key: (!no_local_entry).then_some(canonical_key.clone()),
        canonical_key,
        resolution,
    })
}

/// Re-evaluate the ingress interface's INPUT filter for an established-session
/// hit, when it owes one.
///
/// ONE `iface_filter_v{4,6}_fast` lookup decides between the two re-evaluations
/// this path can owe, and `None` — no input filter on this ingress interface in
/// this family — costs exactly that one lookup and nothing else. That is the
/// same cost the pre-#7212 gate (`interface_input_filter_varies_per_packet`)
/// paid, which is why this stays `#[inline]`: the common case folds into the
/// caller as a load and a branch, with the heavy bodies behind `#[cold]` callees.
///
/// **Per-packet (#1430 / #2362).** A filter carrying a DSCP match or a
/// per-packet L4 match (tcp-flags / is-fragment / icmp-type / icmp-code /
/// flexible-match-range) has a verdict that is NOT a function of the 5-tuple, so
/// the first-packet decision must not be replayed: it is re-evaluated on EVERY
/// hit, with its counters and `then log` record. Unchanged from pre-#7212.
///
/// **Static revalidation (#7212).** Every other filter's verdict IS a pure
/// function of `(ingress interface, family, 5-tuple)`, all constant for the life
/// of one direction of a session. So it is re-derived only when the session's
/// stamp predates the live config generation — once per session per generation,
/// not per packet — and the session is re-stamped. The re-derivation is
/// SIDE-EFFECT FREE (`NonRoutingCountPolicy::Never`): a session the filter still
/// permits, which is nearly all of them on nearly every commit, leaves every
/// `then count` term and every `then log` record untouched. Only when the
/// verdict has become a DENY does the ordinary counted evaluator run, so the one
/// packet that is newly denied is counted, logged and rejected exactly once.
///
/// **THE DECLINE SET, enumerated (#8114).** This function's ONE production call
/// site (`poll_descriptor/mod.rs`) is an `if let Some(..)` with no `else` arm,
/// so every `None` here means *the block is skipped and the packet forwards on
/// the existing session decision*. That makes each `None` fail-OPEN with respect
/// to a newly added deny, and "declines" reads more neutral than the posture is.
/// The population is therefore not a list of cases someone noticed — it is every
/// `None`-producing exit, and it is short enough to state in full:
///
/// | exit | condition | can a live deny be missed? |
/// |------|-----------|----------------------------|
/// | `flow?` | the caller passed no flow | NO — the sole production call site passes `Some(flow)` literally; reachable only from tests |
/// | `interface_input_filter(..)?` | no input filter on this ingress + family | NO — there is no filter to deny anything |
/// | `filter.affects_route_lookup` | *(removed)* — the verdict is now COMPOSED from the routing-instance walk plus the non-routing walk | **was YES** — #8114 item 1, closed by `static_input_filter_deny_eval`'s PBR arm |
/// | `FilterRevalidationTarget::Fresh` | the entry's verdict is already derived under the live `(generation, ingress)` | NO — derived, and it was an Accept |
/// | `FilterRevalidationTarget::NoLocalEntry` | no entry this tuple may safely name | **was YES** — #8114 item 2, closed by `sessionless_static_input_filter_verdict` |
/// | `static_input_filter_deny_eval` -> `None` | the filter permits the flow | NO |
///
/// Two consequences of running the predicate rather than trusting the list.
/// First, `NoLocalEntry` has THREE sub-populations, not the two #8114 names: the
/// #2120 transient peer-synced hit, the `max_sessions` reverse-NAT repair, and a
/// STALE PRIMARY HANDLE (`key_to_handle` resolving to a record whose key differs)
/// — the third is unlisted, and it is handled by the same arm because the
/// remedy is identical: derive the verdict, stamp nothing, tear down nothing.
/// Second, #8114's items 3 and 4 are NOT exits of this function at all — they
/// are the flow-cache eviction window and the cross-worker `DeleteSynced`
/// delivery path, downstream of a verdict this function already produced. The
/// issue groups all four as "the revalidation has a verdict but no place to
/// apply it", which is true of 1 and 2 and not of 3 and 4.
///
/// With items 1 and 2 closed, NO exit of this function can miss a live deny:
/// every remaining `None` is either "there is no filter", "the filter permits
/// this flow", or "this flow was already judged under the live pair". The table
/// is kept rather than deleted because that is a property worth being able to
/// re-check against a future exit, and a list of closed items is what makes a
/// NEW one visible.
///
/// Why the ingress interface is read off the packet and not off the session: it
/// is an OBSERVATION of where this direction's traffic actually arrives.
/// `SessionMetadata::ingress_ifindex` deliberately carries `0` for the reverse
/// companion (#4983) precisely because the forward half's `egress_ifindex` is a
/// PREDICTION of where the reply will land, which asymmetric routing can
/// falsify. Forward and reverse are separate entries with separate stamps, so
/// each direction revalidates against its own interface's filter with no stored
/// ingress identity at all.
/// #10566: the second tuple element reports whether a counted evaluator ran
/// for this packet — i.e. whether the seed packet arrives at the flow-cache
/// seed ALREADY charged. `true` on the per-packet `Some` arm and on both DENY
/// `Some` arms; `false` on every uncounted `None` arm (no-flow, no-filter,
/// `Fresh`, `Stale`-ACCEPT, `NoLocalEntry`-ACCEPT). Named explicitly — never
/// derived as `hit.is_some()` — so a future counted-`None` arm cannot silently
/// double-charge at the seed.
#[inline]
pub(super) fn evaluate_input_filter_on_session_hit(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    // The matched entry's CANONICAL key (`ResolvedFlowSessionDecision::key`) —
    // the primary index the stamp is read and written through.
    session_key: &crate::session::SessionKey,
    frame: &[u8],
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> (Option<SessionHitInputFilterEval>, bool) {
    let Some(flow) = flow else {
        // No flow: no lookup ran, nothing counted.
        return (None, false);
    };
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    // THE single lookup. Both arms below read off this one borrow.
    let Some(filter) =
        crate::filter::interface_input_filter(&forwarding.filter_state, ingress_ifindex, is_v6)
    else {
        // No filter: nothing to count, nothing counted.
        return (None, false);
    };
    if filter.varies_per_packet_within_flow() {
        // #1430/#2362 — unchanged. The extra-build stays after the gate so the
        // no-such-filter case never pays it.
        let extra = term_match_extra_from_frame(frame, meta);
        // #2620: the session-HIT re-eval is the SOLE counter for this packet —
        // it never calls `ingress_route_table_override`/the routing evaluator.
        // Pass `routing_eval_follows = false` so it counts on every exit
        // (per-packet, pre-#2620 behavior), even when the filter is
        // route-lookup-affecting.
        // #10566: the counted evaluator ran — the seed must not charge again.
        return (
            Some(SessionHitInputFilterEval {
            eval: evaluate_non_pbr_input_filter(
                forwarding,
                extra,
                Some(flow),
                meta,
                ingress_zone_override,
                false,
            ),
            revoked_key: None,
            log_source: FilterLogSource::Input,
            }),
            true,
        );
    }
    // #7212: a purely STATIC filter.
    //
    // ...unless it is ROUTE-LOOKUP-AFFECTING, in which case this path declines.
    // The non-routing walk the static verdict runs DEFERS on a matched
    // `routing-instance` term — it returns the default Accept before the term's
    // own action is examined — and #4392 established that a
    // `then { routing-instance X; discard; }` term is a DROP, adjudicated by
    // `ingress_route_table_override` on the session-MISS path. Reading that
    // deferral as an Accept would let the revalidation PRESERVE (and stamp) a
    // session the routing-aware evaluation drops: a fail-open, and a stamped one
    // that would not re-derive until the next generation. The walk cannot tell
    // "Accept because nothing matched" from "Accept because it deferred", so
    // declining is the only honest answer available here. It leaves such filters
    // exactly where they were before #7212 — no revocation — rather than
    // inventing a wrong one; a routing-aware static evaluator is #8114.
    // ONE probe answers both questions: which entry does this WIRE tuple name,
    // and does that entry still lack a verdict derived under the live generation
    // on THIS ingress interface. `None` — the answer for every packet but one
    // per session per (generation, ingress) — costs a single hash and a compare,
    // which matters because this runs on every established hit on an interface
    // that has an input filter, i.e. the entire population the feature serves.
    //
    // The resolution is needed because `session_key` is the tuple the packet
    // carried, and a reverse entry reached through the NAT reverse-translated
    // ALIAS index is stored under a DIFFERENT key than the one that found it. A
    // primary-index-only probe reports such an entry fresh forever, and a
    // teardown handed the wire tuple deletes nothing. (An ordinary source-NAT
    // reply is not that case — its companion's primary key IS the wire reply
    // tuple.)
    //
    // `None` also covers "this worker holds no entry for the tuple" — the #2120
    // transient synced-hit path, where the packet was served from the shared map
    // without a local install. There is nothing local to stamp or tear down; the
    // window is bounded by `maybe_promote_synced_session` installing the entry
    // UNVALIDATED, and it is one of the cases #8114 tracks.
    match sessions.filter_revalidation_target(session_key, ingress_ifindex) {
        // The answer for every packet but one per session per (generation,
        // ingress): a single hash and a compare, which is what keeps this
        // affordable on the entire population the feature serves.
        crate::session::FilterRevalidationTarget::Fresh => {
            // #10566: already judged under the live pair — nothing counted.
            (None, false)
        }
        crate::session::FilterRevalidationTarget::Stale(canonical_key) => {
            revalidate_static_input_filter_on_session_hit(
                forwarding,
                sessions,
                canonical_key,
                ingress_ifindex,
                filter,
                flow,
                meta,
                ingress_zone_override,
            )
        }
        // #8114 item 2: a RESOLVED decision with no local entry to name — the
        // #2120 transient peer-synced hit, a reverse-NAT repair refused at
        // `max_sessions`, or a stale primary handle. The packet is being
        // FORWARDED, so declining here (which is what the old
        // `Option<SessionKey>` probe forced, by collapsing this onto the same
        // `None` as "already fresh") left a newly added static deny unapplied to
        // it. Derive the verdict anyway: it is a function of the flow and the
        // interface, not of the entry. Only the STAMP and the pair teardown need
        // an entry, and both are skipped — `revoked_key: None` tells the caller
        // to drop this packet without revoking anything.
        crate::session::FilterRevalidationTarget::NoLocalEntry => {
            sessionless_static_input_filter_verdict(
                forwarding,
                filter,
                ingress_ifindex,
                flow,
                meta,
                ingress_zone_override,
            )
        }
    }
}

/// #7212/#8114: derive the flow's STATIC input-filter verdict and, on a DENY,
/// re-run the ordinary counted/logged evaluator so the packet is charged to its
/// matching `then count` terms and produces its `then log` record exactly once.
///
/// `None` = the filter still PERMITS this flow.
///
/// Extracted so the two callers — the stale-entry revalidation and the
/// sessionless derivation — cannot drift on WHAT the verdict is, only on what
/// they do with it. That is not a tidiness point: the caller drops on the
/// counted walk's action while tearing down on this one's, so the two walks must
/// be handed the same `TermMatchExtra` by construction rather than by two sites
/// remembering to.
///
/// The extra is `TermMatchExtra::default()`, deliberately, and NOT the
/// frame-derived one. `varies_per_packet_within_flow()` is not a complete purity
/// gate: `port_terms_match` also reads the extra, so any term with a PORT
/// constraint fails to match when `(is_fragment && !l4_present)` or
/// `ports_unknown`. An ordinary static shape —
///
///     term web       { from destination-port 5201; then accept; }
///     term deny-rest { then discard; }
///
/// — evaluated against a NON-FIRST FRAGMENT of a permitted flow would skip
/// `web`, fall through to `deny-rest`, and deny a flow the operator permits. One
/// fragment, whole flow gone. `default()` leaves the fragment gate untriggered
/// and every per-packet-L4 condition inert (a static filter carries none by
/// construction), so what remains is exactly the 5-tuple verdict — the right
/// answer in both directions, not merely the safe one.
///
/// **#8114 item 1: the ROUTE-LOOKUP-AFFECTING case.** A filter carrying any
/// `routing-instance` term used to be declined outright, because the non-routing
/// walk DEFERS on a matched one — it returns the default `Accept` before the
/// term's own action is examined — and cannot tell "Accept because nothing
/// matched" from "Accept because it deferred". #4392 established that
/// `then { routing-instance X; discard; }` is a DROP.
///
/// The verdict is now COMPOSED exactly the way the packet path composes it, so
/// the two cannot disagree:
///
/// - Ask the routing-instance walk first. `Some(r)` means a matched TERMINATING
///   term carried a routing-instance, which is what
///   `ingress_route_table_override` acts on: it drops on
///   `Reject`/`Discard` (`r.action`) and otherwise applies the table override
///   and forwards. So `r.action` IS the verdict, deny or permit.
/// - `None` means no PBR term terminated the walk — either a matched
///   terminating term had no routing-instance, or nothing matched. Production
///   returns `RouteOverride::None` there and the packet's verdict comes from the
///   ordinary non-routing walk, so that is what is asked.
///
/// The ONLY case where the two walks differ is the matched routing-instance term
/// with a `discard`/`reject` action — precisely the gap, and precisely why the
/// old code could not read the deferral as an Accept.
///
/// A PLAIN `routing-instance` term (no drop action) is a PERMIT that changes the
/// route table, so it does NOT revoke. That is deliberate and it is a scope
/// statement rather than an oversight: #7212 revokes on DENY, and an established
/// session whose PBR term now points at a different instance keeps the route it
/// was built with until it ages out. Revoking on a route change is a separate
/// question with a different blast radius.
#[cold]
#[inline(never)]
fn static_input_filter_deny_eval(
    forwarding: &ForwardingState,
    filter: &crate::filter::Filter,
    // The LOGICAL ingress this verdict is derived against — needed only to
    // resolve the log's zone id on the PBR arm, which builds its
    // `CachedInputFilterLog` here rather than inside `evaluate_non_pbr_input_filter`.
    logical_ingress_ifindex: i32,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> Option<(NonPbrInputFilterEval, FilterLogSource)> {
    let extra = crate::filter::TermMatchExtra::default();
    if filter.affects_route_lookup
        && let Some(pbr) = crate::filter::evaluate_filter_ref_routing_instance_uncounted(
            filter,
            flow.src_ip,
            flow.dst_ip,
            meta.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
            meta.dscp,
            extra,
        )
    {
        if pbr.action == crate::filter::FilterAction::Accept {
            // Permitted, with a route-table override. Nothing to revoke.
            return None;
        }
        // DENY from a PBR term. Replay the SAME walk WITH counting so the
        // revoking packet is charged to its matching `then count` terms and
        // carries its `then log` record exactly once — the routing-aware twin of
        // the `evaluate_non_pbr_input_filter` replay below. Same `extra`, so the
        // counted walk cannot reach a different term than the verdict did.
        let counted = crate::filter::evaluate_filter_ref_routing_instance_event_counted(
            filter,
            flow.src_ip,
            flow.dst_ip,
            meta.protocol,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
            meta.dscp,
            extra,
            meta.pkt_len as u64,
        )?;
        let ingress_zone_id = filter_log_ingress_zone_id(
            forwarding,
            meta,
            ingress_zone_override,
            logical_ingress_ifindex,
        );
        return Some((
            NonPbrInputFilterEval {
                action: counted.action,
                cached_log: counted.log_match.map(|log_match| CachedInputFilterLog {
                    log_match,
                    ingress_zone_id,
                }),
            },
            FilterLogSource::Pbr,
        ));
    }
    let verdict = crate::filter::filter_ref_static_verdict(
        filter,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
    );
    if verdict == crate::filter::FilterAction::Accept {
        return None;
    }
    Some((
        evaluate_non_pbr_input_filter(
            forwarding,
            extra,
            Some(flow),
            meta,
            ingress_zone_override,
            false,
        ),
        FilterLogSource::Input,
    ))
}

/// #8114 item 2: the static verdict for a packet whose forwarding decision
/// RESOLVED but which has no local session entry.
///
/// Same derivation as the stale-entry path, and deliberately none of its
/// side effects: there is no entry to stamp (so the next packet of this tuple
/// re-derives, which is correct — the state that made it sessionless may have
/// cleared) and none to tear down (`revoked_key: None`). A DENY still drops
/// THIS packet, counted and logged, which is the whole gap: before this the
/// packet forwarded under a filter that denies it.
///
/// The two populations that reach here differ in how long they last, and that
/// is the reason this is not "a bounded transient, ignore it". The #2120
/// peer-synced hit is bounded — `maybe_promote_synced_session` installs the
/// entry UNVALIDATED on a later packet and it revalidates before this node
/// forwards on it as its own. The `max_sessions` reverse-NAT repair
/// (`install_failed`) lasts as long as the session table is full, which is
/// precisely when an operator is most likely to be adding a deny.
#[cold]
#[inline(never)]
fn sessionless_static_input_filter_verdict(
    forwarding: &ForwardingState,
    filter: &crate::filter::Filter,
    logical_ingress_ifindex: i32,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> (Option<SessionHitInputFilterEval>, bool) {
    match static_input_filter_deny_eval(
        forwarding,
        filter,
        logical_ingress_ifindex,
        flow,
        meta,
        ingress_zone_override,
    ) {
        // #10566: DENY ran the counted evaluator (`static_input_filter_deny_eval`
        // replays WITH counting on both its `Some` exits); ACCEPT derived the
        // verdict without counting anything.
        Some((eval, log_source)) => (
            Some(SessionHitInputFilterEval {
                eval,
                revoked_key: None,
                log_source,
            }),
            true,
        ),
        None => (None, false),
    }
}

/// #7212: the cold tail of [`evaluate_input_filter_on_session_hit`] — the
/// session's static input-filter verdict is stale, so re-derive it.
///
/// Split out and `#[cold] #[inline(never)]` because it runs at most once per
/// session per config generation: keeping it out of line leaves the caller's
/// common path (no filter, or a fresh stamp) a lookup and two branches.
///
/// The re-stamp happens on the ACCEPT exit ONLY, and that asymmetry is
/// deliberate.
///
/// On ACCEPT it is the whole point: the session keeps its entry and must not
/// re-derive the same verdict on every later packet of this generation.
///
/// On DENY the caller REVOKES the session, so in the normal case there is no
/// entry left to carry a stamp and the next packet of that 5-tuple takes the
/// session-MISS path — where the filter denies it again, with its counters, its
/// log record and its reject reply. Re-stamping there would only ever matter if
/// the teardown did NOT take, and in exactly that case the stamp is a fail-OPEN:
/// the session would say "already judged under the live generation" and be
/// FORWARDED for the rest of the generation, under a filter that denies it. Not
/// stamping makes the same failure fail CLOSED — the next packet re-derives the
/// same DENY and is dropped again — at the cost of re-running the walk for a
/// flow every packet of which is being dropped anyway. That is also the closer
/// Junos behaviour: a stateless `then count; then discard` term counts every
/// packet it drops.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn revalidate_static_input_filter_on_session_hit(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    // The CANONICAL key, already resolved by the caller.
    canonical_key: crate::session::SessionKey,
    // The LOGICAL ingress this verdict is being derived against — half of the
    // stamp, because the verdict is a function of the interface as well as the
    // snapshot.
    logical_ingress_ifindex: i32,
    filter: &crate::filter::Filter,
    // No `frame`: this evaluation is deliberately frame-INDEPENDENT (see the
    // `TermMatchExtra::default()` note in the body). Taking the frame and not
    // reading it would invite the next author to "use it".
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> (Option<SessionHitInputFilterEval>, bool) {
    // #8114: the verdict derivation moved to `static_input_filter_deny_eval`,
    // shared verbatim with the sessionless path so the two cannot drift on WHAT
    // the verdict is — including the `TermMatchExtra::default()` choice, whose
    // reasoning now lives on that function.
    let Some((eval, log_source)) = static_input_filter_deny_eval(
        forwarding,
        filter,
        logical_ingress_ifindex,
        flow,
        meta,
        ingress_zone_override,
    ) else {
        // The filter still permits this flow. Nothing is counted, nothing is
        // logged, and the session — including its NAT translation, which is the
        // reason #5858's family purge was rejected — is untouched. Re-stamp so
        // no later packet of this generation re-derives the same verdict.
        sessions.mark_filter_revalidated(&canonical_key, logical_ingress_ifindex);
        return (None, false);
    };
    // DENY: deliberately NOT re-stamped — see the header. The caller revokes the
    // session; if that ever fails to take, the next packet must re-derive this
    // same DENY and drop, not be forwarded under a "judged" stamp.
    // #10566: DENY ran the counted evaluator — this packet is charged.
    (Some(SessionHitInputFilterEval {
        eval,
        revoked_key: Some(canonical_key),
        log_source,
    }), true)
}

#[cold]
#[inline(never)]
pub(super) fn emit_input_filter_log_match(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_log: CachedInputFilterLog,
    // #8114 item 1: the source stamped on the emitted record. `Input` for every
    // pre-#8114 caller; `Pbr` when the verdict came from a matched
    // `routing-instance` term, which is what `ingress_route_table_override`
    // stamps on the same term for a session-MISS packet. Taken as a parameter
    // rather than hardcoded so the two paths cannot label the same term
    // differently.
    log_source: FilterLogSource,
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
        log_source,
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
    emit_input_filter_log_match(
        forwarding,
        event_stream,
        flow,
        meta,
        cached_log,
        FilterLogSource::Input,
        false,
        now_ns,
    );
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
    // #8321 (gemini-048 cohort item 1): the RESOLVED LOGICAL ingress ifindex,
    // for the filter-log's ingress-zone attribution. `ifindex_to_zone_id` is
    // keyed by the logical unit ifindex, with the physical parent inserted only
    // as an INHERITED fallback that `forwarding_build::interfaces` REMOVES when
    // the parent's units contest a zone (#7509). Reading the raw physical
    // `meta.ingress_ifindex` here therefore attributed a VLAN host-bound packet
    // to the parent's zone, or to zone 0 when the parent entry had been removed
    // — a wrong `source-zone-name` on the RT_FLOW record, or an empty one.
    //
    // The wrapper `host_inbound_gated_lo0_action` already holds this value and
    // already documents why the physical one is wrong (#3609, for the
    // host-inbound override map keyed the same way); it simply was not threaded
    // this far. The three sibling sites in this file
    // (`evaluate_non_pbr_input_filter`, `..._log_only`, `..._counters_cached`)
    // all resolve it before calling `filter_log_ingress_zone_id`.
    logical_ingress_ifindex: i32,
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
            logical_ingress_ifindex,
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
        // #8321: the same resolved logical ifindex the host-inbound gate above
        // uses — the filter-log's zone attribution reads the same map family.
        logical_ingress_ifindex,
        lo0_ingress_zone_override,
        now_ns,
    ))
}

/// #10038: lo0 host-bound filter WITHOUT the host-inbound service gate, for a
/// solicited reply whose TUN-origin forward companion the HIT arm already
/// proved (`tun_origin_reverse_exempt`). Argument threading is IDENTICAL to
/// the lo0 tail of `host_inbound_gated_lo0_action` above (resolved LOGICAL
/// ingress ifindex per #3609/#8321, zone override hint, policer now_ns per
/// #5857) — only the admits check is skipped. The caller reuses the same
/// `filter_terminal` + may_revoke-gated teardown + accounting block as the
/// admitted arm, so lo0 discard/reject still drops solicited replies with a
/// truthful log (#3615); host-inbound admission is what is bypassed, never
/// the packet filter.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn lo0_action_for_solicited_reply(
    forwarding: &ForwardingState,
    logical_ingress_ifindex: i32,
    extra: TermMatchExtra<'_>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    lo0_ingress_zone_override: Option<u16>,
    now_ns: u64,
) -> (crate::filter::FilterAction, Option<PendingFilterLog>) {
    apply_lo0_filter_action(
        forwarding,
        extra,
        Some(flow),
        meta,
        logical_ingress_ifindex,
        lo0_ingress_zone_override,
        now_ns,
    )
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
                            discriminator: Default::default(),
                            routing_domain: 0,
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

    /// #8321 (gemini-review-048 grouped-cohort item 1): the lo0 filter-log's
    /// ingress-zone attribution must use the RESOLVED LOGICAL ingress ifindex,
    /// not the raw physical bind port.
    ///
    /// `ifindex_to_zone_id` is keyed by the logical unit ifindex
    /// (`forwarding_build::interfaces`), with the physical parent inserted only
    /// as an INHERITED fallback that is REMOVED when the parent's units contest
    /// a zone (#7509). So on a VLAN sub-interface a physical lookup answered
    /// with the PARENT's zone — a different, wrong zone name on the RT_FLOW
    /// record — or with 0 when the parent entry had been dropped.
    ///
    /// The wrapper already held the resolved value and already documented why
    /// the physical one is wrong (#3609, for the host-inbound override map keyed
    /// the same way). It simply was not threaded as far as the log. The three
    /// sibling sites in this file all resolve it; this one did not, and an
    /// asymmetry against three siblings is what made this decidable without
    /// running traffic.
    ///
    /// Consequence is LOG-ONLY, established by reading the consumer:
    /// `ingress_zone_id` is written into `PendingFilterLog` and read at exactly
    /// one place, which passes it to `emit_filter_log_event`. No enforcement
    /// path consumes it.
    #[test]
    fn lo0_filter_log_zone_uses_the_logical_vlan_ifindex_8321() {
        const PHYS_IFINDEX: u32 = 11;
        const LOGICAL_IFINDEX: i32 = 3011;
        const PARENT_ZONE: u16 = 7;
        const UNIT_ZONE: u16 = 9;

        // A lo0 filter whose term LOGS, so a PendingFilterLog is produced at
        // all. The shared `forwarding_with_lo0_reject` fixture counts but does
        // not log, so a cell built on it could never see this field.
        let logging_lo0 = || {
            let mut fw = ForwardingState::default();
            fw.filter_state = crate::filter::parse_filter_state(
                &[crate::FirewallFilterSnapshot {
                    name: "protect-re".into(),
                    family: "inet".into(),
                    terms: vec![crate::FirewallTermSnapshot {
                        name: "log-web".into(),
                        protocols: vec!["tcp".into()],
                        destination_ports: vec!["443".into()],
                        action: "accept".into(),
                        log: true,
                        ..Default::default()
                    }],
                }],
                &[],
                &[],
                "protect-re",
                "",
            )
            .expect("filter state compiles");
            // Both zones must be NAMED or `filter_log_ingress_zone_id` skips the
            // arm that resolved them and falls through to 0, which would make
            // the assertions below pass or fail for the wrong reason.
            fw.zone_id_to_name.insert(PARENT_ZONE, "parent-zone".into());
            fw.zone_id_to_name.insert(UNIT_ZONE, "unit-zone".into());
            fw
        };

        let zone_of = |fw: &ForwardingState| -> u16 {
            let (flow, mut meta) = tcp_443_flow_and_meta();
            meta.ingress_ifindex = PHYS_IFINDEX;
            // Driven through the WRAPPER, not `apply_lo0_filter_action`
            // directly. That is load-bearing: the wrapper is what HOLDS the
            // resolved logical ifindex, and a cell calling the callee with a
            // hand-supplied value stays green when the wrapper stops threading
            // it — measured, that mutation escaped the first draft of this cell.
            let (_action, pending) = host_inbound_gated_lo0_action(
                fw,
                LOGICAL_IFINDEX,
                ADMIT_ZONE,
                443,
                false,
                0,
                extra(),
                &flow,
                meta,
                // No override: this is the session-MISS / flowless shape, where
                // the override is the fabric-MAC stamp and is None for all
                // non-fabric traffic. With an override present the fallback
                // arms never decide anything.
                None,
                0,
            )
            .expect("ADMIT_ZONE is absent from zone_host_inbound (admit-all), so the \
                     host-inbound gate must admit and the lo0 filter must run");
            pending
                .expect("the logging lo0 term must produce a filter-log record")
                .ingress_zone_id
        };

        // SUBJECT: the logical unit and its physical parent are in DIFFERENT
        // zones, which is exactly what a VLAN trunk carrying units in separate
        // zones looks like.
        let mut fw = logging_lo0();
        fw.ifindex_to_zone_id.insert(LOGICAL_IFINDEX, UNIT_ZONE);
        fw.ifindex_to_zone_id.insert(PHYS_IFINDEX as i32, PARENT_ZONE);
        assert_eq!(
            zone_of(&fw),
            UNIT_ZONE,
            "#8321: the lo0 filter-log must attribute a VLAN host-bound packet to the \
             LOGICAL unit's zone. Reading the raw physical bind port names the parent's \
             zone instead, so the RT_FLOW record's source-zone-name is a real zone that \
             the packet did not arrive on — wrong rather than missing, which is worse for \
             anyone reading logs to reconstruct a flow.",
        );

        // CONTROL 1: with NO logical entry the physical fallback must still
        // answer. That arm is deliberate (#921/#3618 child->parent inheritance)
        // and a fix that simply DELETED it would satisfy the subject above while
        // silently zeroing the zone on every untagged port.
        let mut fw = logging_lo0();
        fw.ifindex_to_zone_id.insert(PHYS_IFINDEX as i32, PARENT_ZONE);
        assert_eq!(
            zone_of(&fw),
            PARENT_ZONE,
            "#8321 control: with no logical-unit entry the inherited physical-parent \
             mapping must still resolve the zone",
        );

        // CONTROL 2: neither mapping present resolves to 0, the documented
        // "unknown" value. Without this the two arms above could both be
        // explained by a resolver that returns whatever it last saw.
        assert_eq!(
            zone_of(&logging_lo0()),
            0,
            "#8321 control: an unresolvable ingress interface must attribute zone 0",
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
                                    discriminator: Default::default(),
                                    routing_domain: 0,
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
            backup_retry_scratch: std::collections::VecDeque::new(),
            max_pending_tx,
            outstanding_tx: 0,
            pending_fill_frames: VecDeque::new(),
            in_flight_prepared_recycles: FastMap::default(),
            in_flight_untracked_tx: FastSet::default(),
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
                            discriminator: Default::default(),
                            routing_domain: 0,
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
                            discriminator: Default::default(),
                            routing_domain: 0,
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
                                    discriminator: Default::default(),
                                    routing_domain: 0,
                },
            };
            let meta = UserspaceDpMeta {
                ingress_ifindex: LAN_IFINDEX_6722 as u32,
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                ..UserspaceDpMeta::default()
            };
            let decision = SessionDecision { resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex,
                tx_ifindex: egress_ifindex,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
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
        // #7509 retarget of this cell's non-vacuity guard. It used to read "the
        // map the log site must NOT read carries a nonzero zone for this
        // ifindex", which stopped holding once INGRESS refused the inherited
        // zone too. The replacement is the guard that still discriminates: an
        // UNCONTESTED ifindex in the SAME state logs a real zone here, so
        // "logs 0" cannot pass on a state with no zones in it.
        assert_eq!(
            filter_log_egress_zone_id(&fw, ZONED_TUNNEL_IFINDEX_6722),
            TEST_SIBLING_VPN_ZONE_ID_6722,
            "control: the unambiguous sibling ifindex 43 still logs `vpnb` in this \
             same state"
        );
        assert_eq!(
            fw.ifindex_to_zone_id
                .get(&SHARED_TUNNEL_IFINDEX_6722)
                .copied()
                .unwrap_or(0),
            0,
            "and after #7509 the INGRESS map refuses the shared ifindex as well, so \
             both halves agree that ifindex 42 names no zone"
        );
        assert_eq!(
            filter_log_egress_zone_id(&fw, SHARED_TUNNEL_IFINDEX_6722),
            0,
            "the logged to-zone must be the adjudicated 0, not the sibling's zone"
        );
    }
}

// #7212: the established-session-hit input-filter re-evaluation gate — family,
// VLAN unit, term order, `except`, attach/detach, stamp freshness, and the
// permitted-SNAT pin. Its own file rather than another block in this one, per
// the modularity rule on test files.
#[cfg(test)]
#[path = "filter_revalidation_7212_tests.rs"]
mod filter_revalidation_7212_tests;
