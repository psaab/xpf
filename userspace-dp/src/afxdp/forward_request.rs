// Forward-request builders extracted from afxdp.rs (Issue 67.4).
//
// `build_live_forward_request` and `build_live_forward_request_from_frame`
// pack a per-packet ForwardingResolution + SessionMetadata into the
// LiveForwardRequest descriptor that the dispatch path enqueues.
//
// `should_install_local_reverse_session` is the small predicate that
// decides whether the reverse-direction session entry should be
// pre-installed locally vs lazily on first reverse-direction packet.
//
// Pure relocation. `use super::*;` brings every type and helper from
// afxdp.rs into scope.

use super::*;
use super::worker::WorkerTxPipeline;

/// #3608: the tx-pipeline + counters an output-filter `then reject` needs to
/// synthesize its active reply (TCP RST / ICMP admin-prohibited) on the transit
/// forward path. `build_live_forward_request_from_frame` resolves the output
/// filter inline and, on a `then reject` drop, must emit the same active reply
/// the input/lo0 path already does (#2521) instead of the historical silent
/// drop (#3608). Passed by the poll-loop callers that own the ingress binding's
/// TX pipeline; `None` on the test-only `build_live_forward_request` wrapper and
/// any caller that cannot (or need not) emit a reply, in which case a reject
/// degrades to the prior silent drop and the filter-log truthfully reports DENY.
pub(super) struct ForwardRejectReply<'a> {
    pub(super) tx_pipeline: &'a mut WorkerTxPipeline,
    pub(super) counters: &'a mut BatchCounters,
}

pub(super) fn should_install_local_reverse_session(
    decision: SessionDecision,
    fabric_ingress: bool,
) -> bool {
    let fabric_wire_placeholder =
        shared_ops::is_fabric_wire_placeholder(fabric_ingress, false, decision);
    decision.resolution.disposition != ForwardingDisposition::FabricRedirect
        || (fabric_ingress && !fabric_wire_placeholder)
}

/// Select the PHYSICAL egress ifindex a forwarded frame is DISPATCHED to (the
/// XSK-bound NIC the TX dispatcher looks up via
/// `resolve_pending_forward_target_binding`).
///
/// For a normal flow the resolution's `tx_ifindex` (the physical bind ifindex)
/// is authoritative and taken verbatim — the common fast path, unchanged.
///
/// #6308: a WG transit-egress flow whose WG transport table has ONLY a specific
/// peer route (no default) resolves against the endpoint's ZEROED destination
/// (#2837) to `tx_ifindex = 0` / `egress_ifindex =` the logical wgN ifindex.
/// The pre-#6308 fallback `resolve_tx_binding_ifindex(logical wgN)` returned the
/// logical ifindex, which has no XSK binding → the TX dispatcher
/// NO_EGRESS_BINDING-drops a frame #5292 built correctly. Resolve the physical
/// underlay egress against the SAME selected-peer route #5292 uses for the frame
/// bytes so dispatch and bytes agree on the physical NIC; non-WG /
/// unresolvable-peer paths keep the logical fallback (fail-closed identical to
/// before).
///
/// #6345: the peer-route resolution is consulted FIRST, not only on the
/// `tx_ifindex == 0` path. #6308 left the `tx_ifindex > 0` branch taking the
/// stored resolution verbatim, and for a WG transit-egress flow whose transport
/// table DOES carry a default route that value is the DEFAULT-route parent —
/// while `wg_encap_frame` builds the outer L2/VLAN/src against the SELECTED
/// PEER's more-specific route (#6306). With one underlay the two agree and
/// nothing changes. With SEVERAL (a peer reachable over a different NIC than the
/// default route's) dispatch targeted one NIC while the bytes carried another
/// egress's L2 — a frame emitted on the wrong wire, carrying a source MAC and
/// VLAN that belong to a different segment. Following the peer route on BOTH
/// branches makes dispatch and bytes agree by construction; if that NIC has no
/// XSK binding the dispatcher drops, which is the correct fail-closed posture
/// against emitting a mismatched frame onto the wrong underlay.
///
/// The non-tunnel fast path is still one integer compare: the resolver's first
/// act is `decision.resolution.tunnel_endpoint_id == 0 -> None`, so a plain
/// forward pays a single field test and then takes `tx_ifindex` verbatim
/// exactly as before.
#[inline]
pub(in crate::afxdp) fn resolve_forward_target_ifindex(
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    frame: &[u8],
    frame_addr_family: u8,
    frame_l3_offset_hint: u16,
) -> i32 {
    // #6345: the SELECTED-PEER physical egress is the SSOT for BOTH the frame
    // bytes and the dispatch NIC, so it wins over the stored resolution
    // whenever it resolves — including when `tx_ifindex > 0`.
    if let Some(peer_egress) = crate::afxdp::frame::wg_transit_egress_physical_egress_ifindex(
        decision,
        forwarding,
        frame,
        frame_addr_family,
        frame_l3_offset_hint,
    ) {
        return resolve_tx_binding_ifindex(forwarding, peer_egress);
    }
    if decision.resolution.tx_ifindex > 0 {
        return decision.resolution.tx_ifindex;
    }
    resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_live_forward_request(
    area: &MmapArea,
    binding_lookup: &WorkerBindingLookup,
    current_binding_index: usize,
    ingress_ident: &BindingIdentity,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    fabric_ingress_zone: Option<u16>,
    apply_nat_on_fabric: bool,
    now_ns: u64,
) -> Option<PendingForwardRequest> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_live_forward_request_from_frame(
        binding_lookup,
        current_binding_index,
        ingress_ident,
        desc,
        frame,
        meta,
        decision,
        forwarding,
        flow,
        fabric_ingress_zone,
        apply_nat_on_fabric,
        now_ns,
        None,
        None,
        None,
        None,
        // #5606: test-only wrapper — a NAT64 reverse reply is exercised through
        // `build_live_forward_request_from_frame` directly, so this convenience
        // path carries no reverse info.
        None,
    )
}

pub(super) fn build_live_forward_request_from_frame(
    binding_lookup: &WorkerBindingLookup,
    current_binding_index: usize,
    ingress_ident: &BindingIdentity,
    desc: XdpDesc,
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    fabric_ingress_zone: Option<u16>,
    apply_nat_on_fabric: bool,
    now_ns: u64,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    hints: Option<PendingForwardHints>,
    precomputed_tx_selection: Option<&CachedTxSelectionDescriptor>,
    reject_reply: Option<ForwardRejectReply<'_>>,
    // #5606: the driving session's NAT64 reverse info (original v6 src/dst), or
    // `None` for every non-NAT64 flow. Threaded straight onto
    // `PendingForwardRequest.nat64_reverse`: the TX dispatcher's
    // `build_nat64_forwarded_frame` AF_INET (v4->v6) branch hard-requires it to
    // translate a NAT64 reply back to IPv6 — with `None` it returns `None` and
    // the reply is dropped. The reverse companion session installed for a NAT64
    // flow carries this in its `SessionMetadata`, so the session-hit resolve
    // that produced `decision` supplies it here.
    nat64_reverse: Option<Nat64ReverseInfo>,
) -> Option<PendingForwardRequest> {
    let hints = hints.unwrap_or_default();
    // #6308/#6345: `resolve_forward_target_ifindex` keeps the `tx_ifindex`
    // fast path for every normal forward, and for a WG transit-egress flow
    // resolves the physical underlay egress against the SELECTED PEER route —
    // the same route #5292 builds the frame bytes against — whether or not the
    // transport table carries a default route. Dispatch NIC and frame L2 are
    // therefore the same NIC by construction.
    let target_ifindex = resolve_forward_target_ifindex(
        decision,
        forwarding,
        frame,
        meta.addr_family,
        meta.l3_offset,
    );
    // #2357: a forwarded non-first IP fragment carries no L4 header — its
    // post-IP-header bytes are payload, not ports. #2344 already made it
    // flowless on the policy/session path (`flow` is `None` here), but the
    // TX-CoS / fabric-queue selection below re-derives a ported tuple from
    // metadata/frame independently of that gate. Compute the non-first-
    // fragment predicate ONCE and suppress port synthesis for it so all
    // fragments of one datagram land on the interface default queue / a
    // fragment-stable (port-less) fabric hash and never hit a port-matching
    // output-filter term. The gate fires ONLY for an actual non-first
    // fragment with no real flow — a legitimate flowless TCP/UDP packet
    // (real L4 header, `flow` None) keeps its meta/frame-derived ports.
    let non_first_fragment = flow.is_none() && frame_is_non_first_fragment(frame, meta);
    // Prefer session flow ports (set by conntrack, immune to DMA races),
    // then live frame ports (lazy — only parsed if session ports unavailable),
    // then metadata as last resort.
    let expected_ports = if non_first_fragment {
        None
    } else {
        hints
            .expected_ports
            .or_else(|| authoritative_forward_ports(frame, meta, flow))
    };
    let target_binding_index = hints.target_binding_index.or_else(|| {
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            binding_lookup.fabric_target_index(
                target_ifindex,
                fabric_queue_hash(flow, expected_ports, meta, non_first_fragment),
            )
        } else {
            binding_lookup.target_index(
                current_binding_index,
                ingress_ident.ifindex,
                ingress_ident.queue_id,
                target_ifindex,
            )
        }
    });
    let mut decision = *decision;
    // #919/#922: ID-keyed redirect — no `zone_id_to_name` round-trip.
    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        && let Some(ingress_zone_id) = fabric_ingress_zone
        && let Some(zone_redirect) =
            resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone_id)
    {
        decision.resolution.src_mac = zone_redirect.src_mac;
    }
    let fallback_flow;
    let tx_selection_flow = if flow.is_some() {
        flow
    } else if non_first_fragment {
        // #2357: do NOT synthesize a ported tuple from metadata for a
        // non-first fragment. A `None` flow_key drives
        // `resolve_cos_tx_selection_at` to the interface default queue with
        // NO output-filter (port) evaluation (tx/cos_classify.rs early
        // `None` arm) — so a fragment is never misclassified by, or
        // spuriously dropped by, a port-matching terminal filter term.
        None
    } else if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !meta_icmp_identifier_bearing(frame, meta)
    {
        // #3290: mirror the conntrack-side gate. The XDP shim stamps
        // `meta.flow_src_port` from bytes [l4+4..l4+6] for EVERY ICMP/ICMPv6
        // type with no query-type gate, so synthesizing a tuple here for a
        // non-query ICMP error/control packet (Dest-Unreachable,
        // Packet-Too-Big, Time-Exceeded, Parameter-Problem, Redirect, ND/MLD)
        // would feed a fabricated pseudo-port into TX selection AND CoS
        // output-filter evaluation (`tx/cos_classify.rs` reads
        // flow_key.src_port/dst_port) — and store it in the pending request's
        // `flow_key`. A `None` flow_key takes the same default, no-output-filter
        // path as the fragment case above, matching the flowless verdict
        // `parse_session_flow_from_bytes` produces for these packets on the
        // conntrack side. Identifier-bearing query types keep their tuple (and
        // for those the primary `flow` is already `Some`, so this arm is only
        // reached for the non-query / truncated case).
        None
    } else if matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
        && !meta_l4_ports_in_declared_end(frame, meta)
    {
        // #9894 (GPT-3): mirror the conntrack-side fast-path gate. The shim
        // reads L4 against the frame end INCLUDING slack, so for a short
        // declared length the stamped tuple is phantom — and the primary
        // `flow` is already `None` for it (fast-path gate). Synthesizing
        // here would feed the rejected ports into TX selection, CoS
        // output-filter evaluation and the stored `flow_key`. A `None`
        // flow_key takes the same default, no-output-filter path as the
        // fragment/ICMP arms above. Legitimate flowless TCP/UDP (real L4
        // header, in-declared) keeps its meta/frame-derived ports.
        None
    } else {
        fallback_flow = parse_session_flow_from_meta(meta);
        fallback_flow.as_ref()
    };
    // #3642: an interface `filter output` matches the POST-NAT on-wire tuple —
    // Junos applies output firewall filters on the egress interface AFTER NAT
    // (DNAT pre-route, SNAT post-policy). Derive the egress wire key from the
    // pre-NAT session key + THIS packet's NAT decision. `decision.nat` is in
    // apply-to-this-packet form (`rewrite_forwarded_frame_in_place` /
    // `apply_nat_ipv4/6` write the same rewrite_src/dst to the frame regardless
    // of direction), so `forward_wire_key` yields the exact egress tuple for
    // BOTH the forward leg and the reverse/reply leg. For NAT64 the wire key
    // also carries the egress address family, driving the correct-family
    // output-filter selection downstream (`resolve_cos_tx_selection_internal`).
    // The stored `PendingForwardRequest.flow_key` below stays the PRE-NAT key
    // (CoS flow-bucket hashing / session glue key it consistently with the
    // in-place fast path).
    //
    // #5158: the post-NAT wire key is CORRECT for the egress OUTPUT filter, but
    // the ingress INPUT filter matched this packet on its PRE-NAT ingress tuple
    // (Junos applies input filters BEFORE NAT). Pass the post-NAT wire key for
    // TX selection and the pre-NAT session `forward_key` as the ingress re-walk
    // key so a NAT'd flow still picks up an ingress `then forwarding-class` /
    // dscp-rewrite / three-color policer (`resolve_cos_tx_selection_at_prenat`).
    let tx_selection_wire_key =
        tx_selection_flow.map(|flow| forward_wire_key(&flow.forward_key, decision.nat));
    let ingress_flow_key = tx_selection_flow.map(|flow| &flow.forward_key);
    // #7656: the FLOWLESS arm has no wire key to read the egress family from, so
    // every downstream read fell back to the ingress `meta` — and under NAT64
    // the packet changes family in flight. Synthesize the post-NAT L3 tuple from
    // `meta` + this packet's NAT decision (which does NOT depend on there being a
    // flow) so the output filter is selected AND matched on what actually leaves
    // the box. `None` for a flow-bearing packet, which already has the wire key.
    let flowless_wire_flow = if tx_selection_flow.is_none() {
        l3_wire_session_flow_from_meta(meta, decision.nat)
    } else {
        None
    };
    let cos = precomputed_tx_selection
        .map(|selection| CoSTxSelection {
            queue_id: selection.queue_id,
            dscp_rewrite: selection.dscp_rewrite,
            drop: selection.drop,
            // #3608: preserve the `then reject` subset so the active reject
            // reply is synthesized on the precomputed (flow-cache fallback) path
            // too, not just the freshly resolved path.
            reject: selection.reject,
            // #6854: same reasoning — the precomputed path must carry the
            // configured message-type, or a flow-cache fallback silently
            // downgrades to administratively-prohibited.
            reject_message: selection.reject_message,
            filter_log: selection.filter_log,
        })
        .unwrap_or_else(|| {
            resolve_cos_tx_selection_at_prenat(
                forwarding,
                decision.resolution.egress_ifindex,
                meta,
                tx_selection_wire_key.as_ref(),
                ingress_flow_key,
                // #2362 fold B: build the fragment-safe per-packet match inputs
                // from the live frame so a `from { tcp-flags ... } then
                // forwarding-class X` (or is-fragment / icmp-type) output filter
                // selects the class on exactly the authored packets on the
                // TX-selection / CoS leg, not every packet of the flow.
                crate::afxdp::frame::term_match_extra_from_frame(frame, meta),
                now_ns,
                flowless_wire_flow.as_ref().map(|f| &f.forward_key),
            )
        });
    // #7176 (C179-001): the reject-reply + filter-log side effects of a
    // dropping output-filter verdict live in `apply_cos_drop_side_effects` so
    // the DEFERRED neighbor-retry flush (neighbor_dispatch.rs) applies exactly
    // the same ones. They used to be inline here and only here, which is why a
    // packet buffered pending ARP/ND lost its `then reject` reply and its
    // `then log` event entirely.
    apply_cos_drop_side_effects(
        &cos,
        CoSDropSideEffects {
            forwarding,
            meta,
            ingress_ifindex: ingress_ident.ifindex,
            egress_ifindex: decision.resolution.egress_ifindex,
            fabric_ingress_zone,
            now_ns,
            flowless_wire_flow,
        },
        frame,
        tx_selection_flow,
        reject_reply,
        event_stream,
    );
    if cos.drop {
        return None;
    }
    Some(PendingForwardRequest {
        target_ifindex,
        target_binding_index,
        ingress_queue_id: ingress_ident.queue_id,
        desc,
        frame: PendingForwardFrame::Live,
        meta: meta.into(),
        decision,
        apply_nat_on_fabric,
        expected_ports,
        flow_key: tx_selection_flow.map(|flow| flow.forward_key.clone()),
        // #5606: carry the driving session's NAT64 reverse info so the TX
        // dispatcher can translate a v4->v6 NAT64 reply back to IPv6. `None` for
        // every non-NAT64 flow (the common IPv4/IPv6 same-family path is
        // byte-identical to before).
        nat64_reverse,
        cos_queue_id: cos.queue_id,
        dscp_rewrite: cos.dscp_rewrite,
        cos_tx_selection_resolved: true,
        // #hb166 T-7: the `filter_match_extra` snapshot was removed — CoS TX
        // selection is resolved on the LIVE frame just above (via
        // `resolve_cos_tx_selection_at`), and the deferred recompute path
        // that consumed the snapshot is deleted. Dropping it also removes a
        // per-forwarded-packet `term_match_extra_from_frame(..).to_static()`
        // that produced write-only data.
    })
}

/// #7176 (C179-001): the reject-reply and filter-log side effects owed by a
/// DROPPING output-filter verdict, in one place so every consumer of a
/// `CoSTxSelection` applies the same ones.
///
/// This block used to live inline in `build_live_forward_request_from_frame`
/// and nowhere else. The deferred neighbor-retry flush
/// (`neighbor_dispatch::retry_pending_neigh`) resolves the very same
/// `CoSTxSelection` when a packet buffered pending ARP/ND is finally flushed,
/// but read only `.drop` — so a `then reject` term degraded to a silent
/// discard and a `then log` term emitted nothing, for every packet that
/// happened to arrive before its neighbor was resolved. `CoSTxSelection`'s own
/// contract says otherwise: `reject` exists so "the TX/CoS consumer can
/// synthesize the active reject reply ... instead of the silent drop".
///
/// Kept as a shared helper rather than duplicated: the ordering here is
/// load-bearing (#3615 requires the reply be enqueued BEFORE the log so the
/// logged action is truthful), and a second copy is what produced the original
/// divergence.
///
/// Returns whether a reject reply was actually enqueued, which the filter-log
/// event reports as the truthful action.
/// #7656: the flowless POST-NAT L3 flow.
///
/// A flowless packet (non-first fragment / non-query ICMP) has no
/// `tx_selection_flow`, so every downstream consumer fell back to reading the
/// INGRESS `meta` — its family, its addresses and its protocol. Under NAT64 the
/// packet CHANGES family in flight, so those three are the pre-translation
/// values for a packet that leaves the box as IPv4: the egress output filter was
/// selected from the wrong family, matched against the wrong addresses, and the
/// filter-log event recorded the wrong tuple.
///
/// This rebuilds the L3-only flow from `meta` and then puts it through the SAME
/// `forward_wire_key` the flow-bearing path uses, so family, addresses and
/// protocol (including the NAT64 `ICMPV6`<->`ICMP` swap) move together BY
/// CONSTRUCTION. That is the property that makes this the right shape: the
/// alternative — patching each of the four pre-NAT reads independently — is
/// correct only while four edits stay in agreement, and a partial version of it
/// selects the right filter family and then evaluates it against the wrong
/// addresses, which no address-less test fixture can see.
///
/// Returns `None` exactly where `l3_session_flow_from_meta` does (unparsed or
/// unspecified addresses), so a non-NAT flowless packet is unaffected:
/// `forward_wire_key` leaves family and protocol alone when `nat.nat64` is
/// false and rewrites addresses only where the decision set one.
pub(super) fn l3_wire_session_flow_from_meta(
    meta: UserspaceDpMeta,
    nat: NatDecision,
) -> Option<SessionFlow> {
    let pre = crate::afxdp::frame::l3_enforcement_flow_from_meta(meta)?;
    let key = forward_wire_key(&pre.forward_key, nat);
    Some(SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key,
    })
}

pub(super) struct CoSDropSideEffects<'a> {
    pub(super) forwarding: &'a ForwardingState,
    pub(super) meta: UserspaceDpMeta,
    pub(super) ingress_ifindex: i32,
    pub(super) egress_ifindex: i32,
    pub(super) fabric_ingress_zone: Option<u16>,
    pub(super) now_ns: u64,
    /// #7656: the POST-NAT L3 flow for a FLOWLESS packet, or `None` when the
    /// packet has a `tx_selection_flow` (which already carries the post-NAT wire
    /// tuple) or when no L3 flow could be rebuilt. Used to attribute the
    /// filter-log event to the tuple that actually left the box: without it a
    /// NAT64 fragment logs its pre-translation IPv6 addresses for a packet that
    /// egressed as IPv4 — a WRONG record rather than a missing one, which is
    /// worse for anyone reading logs to reconstruct a flow.
    pub(super) flowless_wire_flow: Option<SessionFlow>,
}

pub(super) fn apply_cos_drop_side_effects(
    cos: &CoSTxSelection,
    ctx: CoSDropSideEffects<'_>,
    frame: &[u8],
    tx_selection_flow: Option<&SessionFlow>,
    reject_reply: Option<ForwardRejectReply<'_>>,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
) -> bool {
    // #3608: an output firewall-filter `then reject` on the transit forward path
    // now emits the SAME active reply as the input/lo0 path (#2521) — a TCP RST
    // for TCP, an ICMP/ICMPv6 admin-prohibited unreachable otherwise — instead
    // of the historical silent drop. The reply reflects the ORIGINAL inbound
    // frame back toward the source via the ingress interface (the source is
    // reachable on the reverse path), reusing the shared reject-synthesis +
    // #2238 output-classification + #2472 rate-limit + fail-closed budget gate.
    // `then discard` and three-color-policer drops stay silent (`cos.reject`
    // isolates the reject subset of `cos.drop`). Enqueue the reply FIRST so the
    // filter-log below reports the TRUTHFUL action (#3615): a reject whose reply
    // fail-closes (budget/rate/parse/output-filter, or a missing tx-pipeline
    // context) logs DENY, not REJECT.
    let reject_reply_enqueued = if cos.drop && cos.reject {
        match (reject_reply, tx_selection_flow) {
            (Some(reply), Some(flow)) => {
                crate::afxdp::poll_descriptor::reject_reply::enqueue_filter_reject_reply(
                    reply.tx_pipeline,
                    ctx.forwarding,
                    ctx.ingress_ifindex,
                    frame,
                    ctx.meta,
                    flow,
                    reply.counters,
                    // #6854: the OUTPUT-filter reject path carries its own
                    // resolved message-type on the CoS selection.
                    cos.reject_message,
                )
            }
            _ => false,
        }
    } else {
        false
    };
    // #5467: a flowless packet (non-first fragment / non-query ICMP) has NO
    // `tx_selection_flow`, yet an interface output `then log` term may have
    // matched its L3 tuple inside `resolve_cos_tx_selection_at` (the flowless
    // enforcement gate). Rebuild the L3-only flow (ports 0) SOLELY to attribute
    // that filter-log event so egress logging is not silently bypassed. The
    // reject reply above stays gated on `tx_selection_flow`, so a flowless deny
    // remains a silent drop (#3615 — no L4 header to synthesize a reply from).
    let flowless_log_flow = if tx_selection_flow.is_none() && cos.filter_log.is_some() {
        // #7656: prefer the POST-NAT tuple when the caller resolved one. The
        // pre-NAT fallback is kept for callers that cannot supply it (and for
        // the non-NAT case, where the two are identical anyway).
        ctx.flowless_wire_flow
            .clone()
            .or_else(|| crate::afxdp::frame::l3_enforcement_flow_from_meta(ctx.meta))
    } else {
        None
    };
    let log_flow = tx_selection_flow.or(flowless_log_flow.as_ref());
    if let (Some(filter_log), Some(flow)) = (cos.filter_log, log_flow) {
        // #9383: the THIRD site found by the `ifindex_to_zone_id` census, and the
        // only remaining one keyed on the raw physical index without a stated
        // reason. This is the filter-log `source-zone` attribution, so the cost is
        // forensic rather than enforcement — but a wrong zone in a security log is
        // exactly what an operator later reasons from, and the arrival VLAN is
        // already in `ctx.meta`. Resolve the LOGICAL unit first, the way the
        // sibling `filter_log_ingress_zone_id` does; `.unwrap_or(physical)` keeps
        // an untagged port byte-identical.
        let ingress_logical = resolve_ingress_logical_ifindex(
            ctx.forwarding,
            ctx.meta.ingress_ifindex as i32,
            ctx.meta.ingress_vlan_id,
        )
        .unwrap_or(ctx.meta.ingress_ifindex as i32);
        let ingress_zone_id = ctx.fabric_ingress_zone
            .filter(|id| ctx.forwarding.zone_id_to_name.contains_key(id))
            .or_else(|| {
                ctx.forwarding
                    .ifindex_to_zone_id
                    .get(&ingress_logical)
                    .copied()
            })
            .unwrap_or(0);
        // #6713: shared resolver — see `ForwardingState::egress_zone_id`. A
        // MAC-less interface (IPsec xfrmi) has no `egress` row, so reading that
        // map directly logged to-zone 0 for a correctly-zoned tunnel.
        let egress_zone_id = ctx.forwarding.egress_zone_id(ctx.egress_ifindex);
        emit_filter_log_event(
            event_stream,
            flow,
            ctx.meta,
            ingress_zone_id,
            egress_zone_id,
            filter_log.filter_id,
            filter_log.term_id,
            filter_log.action,
            FilterLogSource::Output,
            // #2520: AppID via the hot-path app_catalog.lookup.
            resolve_flow_app_id(&ctx.forwarding.app_catalog, flow),
            // #3608/#3615: reports whether the `then reject` reply above actually
            // went out; a `then accept`/`then discard` term, or a reject that
            // fail-closed, keeps this false so the log is truthful.
            reject_reply_enqueued,
            ctx.now_ns,
        );
    }
    reject_reply_enqueued
}
