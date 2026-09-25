// #1697 cold-path extraction: source-NAT decision + failure recorder,
// lifted out of poll_descriptor/mod.rs.
//
// Both helpers run only on the session-miss slow path:
// source_nat_decision_for_flow is evaluated once per new flow when the
// session table misses, and record_source_nat_failure fires only on a
// genuine SNAT-exhaustion exception. Neither is reached on the
// established-flow transit fast path (stage_flow_cache_hit), so both are
// #[cold] #[inline(never)] — .text.unlikely placement keeps the
// exception bodies out of the hot ingress loop's codegen unit and
// cache lines.
//
// The bodies were lifted byte-for-byte from their previous location in
// mod.rs (only the enclosing module and inline attributes changed),
// EXCEPT that source_nat_decision_for_flow now passes the EGRESS zone
// (to_zone) instead of from_zone to static_nat.match_snat_with_counter
// per #2871 — the static-NAT reverse-SNAT egress-zone gate, symmetric
// with the #2864 DNAT ingress-zone gate.

use super::*;

/// #6522: resolve the source-NAT decision for a flow and, when it MINTS a pool
/// allocation, record `worker_id` as that allocation's holder.
///
/// The resulting session is replicated to every SIBLING worker
/// (`replicate_session_upsert` fans a `WorkerLocalImport` entry to
/// `peer_worker_commands`, which excludes this worker) and each sibling
/// reserves against the same allocator record. An allocation that does not name
/// its own owner therefore ends up with a holder mask covering every worker
/// EXCEPT the one forwarding, and the last sibling replica to age-reap frees a
/// live `(pool_addr, port)`.
///
/// The parameter is a `u32`, not a `NatHolder`: the packet path cannot express
/// "untracked", so a call site here CANNOT silently opt out of the holder set.
/// The one untracked caller is the read-only fragment probe below, which reaches
/// [`source_nat_decision_with_holder`] directly and mints nothing.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn source_nat_decision_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
    now_ns: u64,
    non_first_fragment: bool,
    worker_id: u32,
    matched_counter: &mut Option<std::sync::Arc<crate::nat::NatRuleCounter>>,
) -> Result<NatDecision, SourceNatFailure> {
    source_nat_decision_with_holder(
        forwarding,
        ingress_ifindex,
        ingress_vlan_id,
        from_zone,
        to_zone,
        egress_ifindex,
        flow,
        now_ns,
        non_first_fragment,
        crate::nat::NatHolder::Worker(worker_id),
        matched_counter,
    )
}

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn source_nat_decision_with_holder(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    // #9956 F-052: threaded to the scope choke point so the SNAT
    // `from interface` / `from routing-instance` match resolves the LOGICAL
    // ingress unit. (This scope feeds only the static-NAT reverse match,
    // which reads the EGRESS half; the pool/interface scope rebuilt inside
    // `match_source_nat_for_flow_result_at` is the load-bearing consumer.)
    ingress_vlan_id: u16,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
    now_ns: u64,
    // #1852: gate pool-mode SNAT allocation for non-first fragments. The
    // static-NAT (address-only) match below is NOT gated — it rewrites
    // the IP on every fragment, which is correct.
    non_first_fragment: bool,
    // #6522: THIS worker's id, recorded as the holder of any pool allocation
    // this decision mints. A locally-born session is replicated to every
    // SIBLING worker and each sibling reserves against the same allocator
    // record, so without the allocating worker's own bit the holder mask names
    // every worker EXCEPT the one forwarding — and the last sibling replica to
    // age-reap frees a live `(pool_addr, port)`.
    holder: crate::nat::NatHolder,
    // #2218: out-param — the matched SNAT/static-SNAT rule's per-rule hit
    // counter (None when no rule matched or the rule has no counter). The
    // caller increments it once per committed translated forward flow.
    matched_counter: &mut Option<std::sync::Arc<crate::nat::NatRuleCounter>>,
) -> Result<NatDecision, SourceNatFailure> {
    *matched_counter = None;
    // #3096: resolve the interface / routing-instance scope for this flow once
    // (cold path). The static-NAT reverse (SNAT) direction matches the rule's
    // `from` external context on EGRESS, so it uses the egress identity.
    let scope = super::super::forwarding::nat_scope_ctx_for_flow(
        forwarding,
        ingress_ifindex,
        ingress_vlan_id,
        egress_ifindex,
        // #9062: the session layer's own domain, not a value re-derived here.
        flow.forward_key.routing_domain,
    );
    // #2871: static-NAT reverse (source) translation is gated on the EGRESS
    // (destination) zone matching the rule's external `from zone`, mirroring
    // the #2864 DNAT ingress-zone gate. Pass `to_zone` (where the packet is
    // headed), NOT `from_zone` — an outbound packet from a static-NAT internal
    // IP destined for another internal zone must NOT be source-translated.
    // #3096: the interface / routing-instance scope is matched on egress too.
    if let Some((decision, counter)) = forwarding.static_nat.match_snat_with_counter_scoped(
        flow.src_ip,
        flow.forward_key.src_port,
        // #3435: gate the reverse static SNAT on the packet DESTINATION (the
        // original client) against `match source-address`, symmetric with the
        // inbound DNAT source gate.
        Some(flow.forward_key.dst_ip),
        to_zone,
        scope.egress_ifname,
        scope.egress_routing_instance,
    ) {
        *matched_counter = counter;
        return Ok(decision);
    }
    match match_source_nat_for_flow_result_at(
        forwarding,
        ingress_ifindex,
        ingress_vlan_id,
        from_zone,
        to_zone,
        egress_ifindex,
        flow,
        now_ns,
        non_first_fragment,
        holder,
        matched_counter,
    ) {
        SourceNatLookup::Matched(decision) => Ok(decision),
        SourceNatLookup::NoMatch => {
            *matched_counter = None;
            Ok(NatDecision::default())
        }
        SourceNatLookup::Unavailable(failure) => {
            *matched_counter = None;
            Err(failure)
        }
    }
}

/// #6122/#10679: READ-ONLY "would source NAT translate this flowless packet?"
/// probe for the same-family NAT transparency fence. It wraps
/// [`source_nat_decision_for_flow`] with `non_first_fragment = true` (which
/// reports a pool-mode match as `Unavailable` BEFORE minting any pool mapping)
/// and collapses the result to a boolean:
///   - `Ok` with a concrete address rewrite (interface / static SNAT) → `true`
///   - `Err` (a pool rule matched but a flowless packet cannot be port-mapped,
///     or an interface rule with no egress address) → `true` (the flow WOULD be
///     source-translated, so the packet must fail closed)
///   - `Ok(NatDecision::default())` (no rule, or an explicit `off` rule) → `false`
///
/// Side-effect-free: it NEVER records a source-NAT allocation failure and
/// mints no session / pool state. The non-first flag is deliberately used for
/// every flowless packet because none has the L4 identity or session required
/// to commit a source-NAT allocation, not only for IP fragments.
#[cold]
#[inline(never)]
pub(super) fn source_nat_would_translate_flowless(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
    now_ns: u64,
) -> bool {
    let mut matched_counter = None;
    match source_nat_decision_with_holder(
        forwarding,
        ingress_ifindex,
        ingress_vlan_id,
        from_zone,
        to_zone,
        egress_ifindex,
        flow,
        now_ns,
        // Mark L4 identity unavailable: pool-mode SNAT reports `Unavailable`
        // before allocating, so this remains a read-only probe for any
        // flowless packet.
        true,
        // #6522: side-effect-free by the contract above — it mints no pool
        // mapping, so there is no allocation to record a holder on.
        crate::nat::NatHolder::Untracked,
        &mut matched_counter,
    ) {
        Ok(decision) => decision.rewrite_src.is_some() || decision.rewrite_dst.is_some(),
        Err(_) => true,
    }
}

#[cold]
#[inline(never)]
pub(super) fn record_source_nat_failure(
    telemetry: &mut TelemetryContext,
    worker_ctx: &WorkerContext,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    from_zone_id: u16,
    to_zone_id: u16,
    packet_length: u32,
    failure: &SourceNatFailure,
) {
    telemetry.counters.touched = true;
    telemetry.counters.exception_packets += 1;
    // #4477: this is the single source-NAT allocation-failure chokepoint (every
    // `SourceNatLookup::Unavailable` funnels here). Tally it so the dead
    // `GlobalCtrNATAllocFail` counter surfaced by `show security flow
    // statistics`, REST, Prometheus, and the CLI reports a real, non-zero value.
    telemetry.counters.nat_alloc_fail += 1;
    let mut debug = ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow);
    debug.from_zone = Some(from_zone_id);
    debug.to_zone = Some(to_zone_id);
    record_source_nat_exception(
        worker_ctx.recent_exceptions,
        &worker_ctx.ident,
        packet_length,
        Some(meta),
        Some(&debug),
        worker_ctx.forwarding,
        failure,
    );
}
