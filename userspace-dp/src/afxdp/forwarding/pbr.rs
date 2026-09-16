//! #5650: policy-based routing — ingress route-table override resolution and
//! its reject-sink/override types. Pure code-motion split out of
//! `forwarding/mod.rs` (behavior-identical).

use super::*;

/// #4392: a reject-reply sink for the flow-backed PBR drop path. Present on the
/// flow-backed session-miss path, which carries a full L4 header and can
/// synthesize a TCP RST / ICMP-unreachable exactly like a non-PBR `then reject`.
/// `None` on the flowless path (a non-first fragment / L3-only packet has no L4
/// header to reflect), where a PBR `reject`/`discard` degrades to a silent drop
/// — identical to the flowless non-PBR input-filter deny.
pub(in crate::afxdp) struct PbrRejectSink<'a> {
    pub(in crate::afxdp) tx_pipeline: &'a mut crate::afxdp::worker::WorkerTxPipeline,
    pub(in crate::afxdp) ingress_ifindex: i32,
    pub(in crate::afxdp) counters: &'a mut crate::afxdp::BatchCounters,
}

/// #4392: the route-lookup decision returned by `ingress_route_table_override`.
///
/// A PBR term `from { ... } then { routing-instance X; reject | discard; }`
/// carries BOTH a routing-instance override AND a drop action. Before this fix
/// the override was applied unconditionally and the packet was FORWARDED into
/// VRF X — a VRF leak plus a false audit (the filter log recorded a deny while
/// the data plane forwarded). The drop action now gates the override.
pub(in crate::afxdp) enum RouteOverride {
    /// No interface input filter affects route lookup here, or no PBR
    /// routing-instance term matched. Use the default route table.
    None,
    /// A PBR routing-instance term matched with a non-drop (accept) action.
    /// Steer the route lookup to this override table (`<ri>.inet[6].0`) and
    /// forward — normal policy-based routing, unchanged.
    /// #9752: carries the installing-table identity alongside the string so
    /// the miss path stamps the session without reverse-parsing the name
    /// (which could desync from this formation site).
    Table {
        /// The override table (`<ri>.inet[6].0` for this packet's family).
        table: String,
        /// The target instance's stable domain id (0 never appears here —
        /// a matched term always names an instance).
        domain: u32,
        /// The owner check for `domain` (same hash's high half).
        check: u32,
    },
    /// A PBR routing-instance term matched with a `reject`/`discard` action.
    /// The caller MUST DROP: do NOT apply the override, do NOT route-lookup or
    /// forward. Any reject reply (TCP RST / ICMP unreachable) has already been
    /// synthesized inside `ingress_route_table_override` when a `PbrRejectSink`
    /// was supplied and the action is `reject`; `discard`, and the flowless
    /// (sink-less) path, drop silently.
    Drop,
}

pub(in crate::afxdp) fn ingress_route_table_override(
    forwarding: &ForwardingState,
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    ingress_zone_override: Option<u16>,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    now_ns: u64,
    reject_sink: Option<PbrRejectSink<'_>>,
) -> RouteOverride {
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    // #6236 PR-2C: the `affects_route_lookup` precheck and the routing-instance
    // evaluation used to look the SAME ingress ifindex up twice on the input fast
    // map. Fold to ONE `.get()`: borrow the route-lookup-affecting filter (the
    // precheck is now `.is_some()` of this same lookup+gate) and evaluate off
    // that borrow. `None` collapses the precheck-false and no-filter cases — both
    // return RouteOverride::None, exactly as before.
    let Some(filter) = crate::filter::interface_filter_route_lookup_affecting(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
    ) else {
        return RouteOverride::None;
    };
    // #2362: PBR terms may carry per-packet L4 match conditions (tcp-flags /
    // is-fragment / icmp-type / icmp-code); build the extra inputs so a
    // `from { tcp-flags ...; } then routing-instance ...` term matches exactly
    // the authored packets. Built AFTER the precheck so a non-route-lookup-
    // affecting filter pays no extra-build.
    let mut extra = crate::afxdp::frame::term_match_extra_from_frame(frame, meta);
    // #9894 (GPT-2): a (0,0)-ported flow is an L3-only enforcement context
    // (ports 0-substituted by construction, #3291) — its "ports" are not on
    // the wire, so port-constrained terms must fail closed instead of
    // matching the synthetic value (a `destination-port 0` positive term or
    // a negated/except term would otherwise spuriously steer). A real
    // TCP/UDP flow never has both ports zero; the builder cannot know (it
    // never sees the flow), so the bit is set HERE, where the evaluated
    // tuple is known.
    if flow.forward_key.src_port == 0 && flow.forward_key.dst_port == 0 {
        extra.ports_unknown = true;
    }
    let routing_result = match crate::filter::evaluate_filter_ref_routing_instance_event_counted(
        filter,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
        meta.pkt_len as u64,
    ) {
        Some(result) => result,
        None => return RouteOverride::None,
    };
    // #4392: a matched PBR routing-instance term may ALSO carry a drop action
    // (`then { routing-instance X; reject | discard; }`). Such a term is a DENY,
    // NOT a forward: the routing-instance override must NOT be applied. On the
    // flow-backed session-miss path a `PbrRejectSink` is supplied, so a `reject`
    // synthesizes the TCP RST / ICMP-unreachable reply here — byte-identical to
    // a non-PBR `then reject` — and its ACTUAL outcome is threaded into the
    // filter log (#3615) below. A `discard`, and the flowless (sink-less) path,
    // drop silently.
    let is_drop = matches!(
        routing_result.action,
        crate::filter::FilterAction::Reject(_) | crate::filter::FilterAction::Discard
    );
    let reject_reply_enqueued = match (routing_result.action, reject_sink) {
        (crate::filter::FilterAction::Reject(reject_msg), Some(sink)) => {
            crate::afxdp::poll_descriptor::reject_reply::enqueue_filter_reject_reply(
                sink.tx_pipeline,
                forwarding,
                sink.ingress_ifindex,
                frame,
                meta,
                flow,
                sink.counters,
                reject_msg,
            )
        }
        _ => false,
    };
    // #2619: emit the accumulated log_match — it captures fall-through
    // `then { log; next term; }` terms ahead of the routing-instance term that
    // the PBR path previously dropped, AND the routing-instance term's own log
    // (latest matched wins). Its action is already normalized to the verdict the
    // packet receives (#2616). Falls back to nothing when no matched term logged.
    if let Some(log_match) = routing_result.log_match {
        let ingress_zone_id = ingress_zone_override
            .filter(|id| forwarding.zone_id_to_name.contains_key(id))
            .or_else(|| forwarding.ifindex_to_zone_id.get(&ingress_ifindex).copied())
            .or_else(|| {
                forwarding
                    .ifindex_to_zone_id
                    .get(&(meta.ingress_ifindex as i32))
                    .copied()
            })
            .unwrap_or(0);
        emit_filter_log_event(
            event_stream,
            flow,
            meta,
            ingress_zone_id,
            0,
            log_match.filter_id,
            log_match.term_id,
            log_match.action,
            FilterLogSource::Pbr,
            // #2520: AppID via the hot-path app_catalog.lookup.
            resolve_flow_app_id(&forwarding.app_catalog, flow),
            // #3615/#4392: report the TRUTHFUL reject outcome. A forward
            // (non-drop) PBR term never rejects (false). A `then reject` on the
            // flow-backed session-miss path synthesizes an RST/ICMP reply above
            // and logs REJECT; a `discard`, or the flowless (sink-less) path,
            // logs the truthful DENY (silent drop).
            reject_reply_enqueued,
            now_ns,
        );
    }
    if is_drop {
        // #4392: reject/discard PBR term — the caller must drop; do NOT apply
        // the routing-instance override or route-lookup/forward.
        return RouteOverride::Drop;
    }
    let routing_instance = routing_result.routing_instance;
    // #9752: the identity travels with the string (no reverse-parsing at the
    // stamp site). A matched term always names a non-empty instance.
    let (domain, check) = crate::session::install_table_identity(routing_instance);
    let table = if is_v6 {
        format!("{routing_instance}.inet6.0")
    } else {
        format!("{routing_instance}.inet.0")
    };
    RouteOverride::Table {
        table,
        domain,
        check,
    }
}

/// #9752: the installing-table stamp for a miss outcome: arm provenance, not
/// disposition. Only the table arm with a live override stamps nonzero;
/// tunnel-egress outcomes stamp `(0,0)` (endpoint-pinned, table-free) and so
/// do precedence/blocked outcomes (no table consulted). Pure so the matrix
/// is unit-testable; the poll-level wiring (override → stamp → install) is
/// pinned by a C2 acceptance cell.
pub(in crate::afxdp) fn install_table_stamp_for_miss(
    pbr_install_table: Option<(u32, u32)>,
    resolved_in_table: bool,
    resolution: ForwardingResolution,
) -> (u32, u32) {
    if resolved_in_table && resolution.tunnel_endpoint_id == 0 {
        pbr_install_table.unwrap_or((0, 0))
    } else {
        (0, 0)
    }
}
