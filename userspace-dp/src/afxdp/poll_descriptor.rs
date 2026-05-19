// Hot-path inner loop extracted from afxdp.rs (#1054). The body is
// byte-for-byte identical to its previous location; this PR only
// changes the enclosing module so afxdp.rs drops below the
// modularity-discipline LOC threshold. `use super::*;` brings every
// type, constant, and helper from afxdp.rs into scope, including
// the sibling submodules (parser, rst, sharded_neighbor, etc.)
// that the extracted fn references.

use super::*;
use super::poll_stages::{
    stage_classify_fabric_ingress, stage_ipsec_passthrough_check, stage_link_layer_classify,
    stage_native_gre_decap, stage_parse_flow_and_learn, stage_screen_check,
    stage_screen_syn_cookie_ack_on_session_miss, FabricIngressOutcome, StageOutcome,
};
use crate::policy::{evaluate_policy_result_with_len, evaluate_policy_with_len};

#[inline]
fn source_nat_decision_for_flow(
    forwarding: &ForwardingState,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
) -> Result<NatDecision, SourceNatFailure> {
    if let Some(decision) = forwarding.static_nat.match_snat(flow.src_ip, from_zone) {
        return Ok(decision);
    }
    match match_source_nat_for_flow_result(forwarding, from_zone, to_zone, egress_ifindex, flow) {
        SourceNatLookup::Matched(decision) => Ok(decision),
        SourceNatLookup::NoMatch => Ok(NatDecision::default()),
        SourceNatLookup::Unavailable(failure) => Err(failure),
    }
}

#[inline]
fn record_source_nat_failure(
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

#[inline]
fn filter_log_ingress_zone_id(
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

#[inline]
fn filter_log_egress_zone_id(forwarding: &ForwardingState, egress_ifindex: i32) -> u16 {
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|egress| egress.zone_id)
        .unwrap_or(0)
}

#[inline]
fn evaluate_non_pbr_input_filter_log(
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> Option<(crate::filter::FilterLogMatch, u16)> {
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
        true,
    )?;
    let ingress_zone_id =
        filter_log_ingress_zone_id(forwarding, meta, ingress_zone_override, ingress_ifindex);
    Some((log_match, ingress_zone_id))
}

#[inline]
fn emit_input_filter_log_match(
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    log_match: crate::filter::FilterLogMatch,
    now_ns: u64,
) {
    emit_filter_log_event(
        event_stream,
        flow,
        meta,
        ingress_zone_id,
        0,
        log_match.filter_id,
        log_match.term_id,
        log_match.action,
        FilterLogSource::Input,
        now_ns,
    );
}

#[inline]
fn emit_cached_input_filter_log(
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_descriptor: &RewriteDescriptor,
    cached_metadata: &SessionMetadata,
    now_ns: u64,
) {
    let Some(log_match) = cached_descriptor.input_filter_log else {
        return;
    };
    emit_input_filter_log_match(
        event_stream,
        flow,
        meta,
        cached_metadata.ingress_zone,
        log_match,
        now_ns,
    );
}

#[inline]
fn emit_cached_output_filter_log(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    cached_decision: SessionDecision,
    cached_descriptor: &RewriteDescriptor,
    cached_metadata: &SessionMetadata,
    now_ns: u64,
) {
    let Some(log_match) = cached_descriptor.tx_selection.filter_log else {
        return;
    };
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
        now_ns,
    );
}

#[inline]
fn emit_lo0_filter_log(
    forwarding: &ForwardingState,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_ns: u64,
) {
    if event_stream.is_none() {
        return;
    }
    let Some(flow) = flow else {
        return;
    };
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    let Some(log_match) = crate::filter::evaluate_lo0_filter_log_match(
        &forwarding.filter_state,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
    ) else {
        return;
    };
    emit_filter_log_event(
        event_stream,
        flow,
        meta,
        filter_log_ingress_zone_id(
            forwarding,
            meta,
            ingress_zone_override,
            meta.ingress_ifindex as i32,
        ),
        0,
        log_match.filter_id,
        log_match.term_id,
        log_match.action,
        FilterLogSource::Lo0,
        now_ns,
    );
}

// Per-batch packet processing lifted from `poll_binding` (#678).
//
// Runs `binding.xsk.rx.receive(available)` + the descriptor while-let +
// `received.release(); drop(received);` as its own compilation unit so
// it surfaces under its own symbol in `perf top`.
//
// #946 Phase 1 (commit ea8fa4e6) extracted seven per-packet
// sub-stages out of the while-let body into named helpers in
// `afxdp/poll_stages.rs`. The helpers are all `#[inline]` so the
// extracted bodies stay in the caller's CGU and the call/return
// overhead is amortized to zero — the refactor is pure
// code-motion at the IR level (modulo what rustc's inliner picks
// up; the explicit hint matches other hot-path extractions in
// this repo).
#[allow(clippy::too_many_arguments)]
pub(super) fn poll_binding_process_descriptor(
    binding: &mut BindingWorker,
    binding_index: usize,
    area: *const MmapArea,
    available: u32,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    _worker_id: u32,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
) {
        let mut received = binding.xsk.rx.receive(available);
        binding.scratch.scratch_recycle.clear();
        binding.scratch.scratch_forwards.clear();
        binding.scratch.scratch_rst_teardowns.clear();
        while let Some(desc) = received.read() {
            record_rx_descriptor_telemetry(desc, area, telemetry, worker_ctx);
            let mut recycle_now = true;
            if let Some(meta) = try_parse_metadata(unsafe { &*area }, desc) {
                telemetry.counters.metadata_packets += 1;
                let disposition = classify_metadata(meta, validation);
                if disposition == PacketDisposition::Valid {
                    telemetry.counters.validated_packets += 1;
                    telemetry.counters.validated_bytes += desc.len as u64;
                    let Some(raw_frame) =
                        unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                    else {
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    };
                    // #946 Phase 1 stage 5: ARP / NDP link-layer
                    // classification. ARP frames recycle without
                    // transiting; NDP NA learns and falls through.
                    if let StageOutcome::RecycleAndContinue =
                        stage_link_layer_classify(raw_frame, meta, worker_ctx)
                    {
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                    // #946 Phase 1 stage 6: native GRE decap. Caller
                    // binds the active slice locally; helper does NOT
                    // return the slice (would be self-referential).
                    // `owned_packet_frame` MUST be `mut` — deferred
                    // stage-12+ code at lines below calls `.take()`.
                    let (mut meta, mut owned_packet_frame) =
                        stage_native_gre_decap(raw_frame, meta, worker_ctx.forwarding);
                    let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
                    // #946 Phase 1 stage 7+8: parse session flow and
                    // learn the source-side dynamic neighbor.
                    // `learn_from_live_frame` MUST be
                    // `owned_packet_frame.is_none()` — preserves the
                    // GRE guard at the original line 113 (neighbor
                    // learning uses the live UMEM Ethernet frame so
                    // the source MAC is the outer host's, not the
                    // GRE tunnel egress).
                    let flow = stage_parse_flow_and_learn(
                        unsafe { &*area },
                        desc,
                        packet_frame,
                        meta,
                        owned_packet_frame.is_none(),
                        &mut binding.last_learned_neighbor,
                        worker_ctx,
                    );
                    // #946 Phase 1 stage 9: fabric-ingress
                    // classification. Mutates meta.meta_flags. MUST
                    // run before screen/IPsec/flow-cache because they
                    // read meta.meta_flags downstream.
                    let FabricIngressOutcome {
                        ingress_zone_override,
                        packet_fabric_ingress,
                    } = stage_classify_fabric_ingress(packet_frame, &mut meta, worker_ctx);
                    // #946 Phase 1 stage 10: screen / IDS slow-path.
                    // Caller still owns the recycle push (matches
                    // original code's pattern).
                    if let StageOutcome::RecycleAndContinue = stage_screen_check(
                        flow.as_ref(),
                        packet_frame,
                        meta,
                        ingress_zone_override,
                        now_secs,
                        screen,
                        telemetry.counters,
                        worker_ctx,
                    ) {
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                    // #946 Phase 1 stage 11: IPsec passthrough. ESP
                    // (proto 50) and IKE (UDP 500/4500) reinject via
                    // the slow-path TUN; recycle the UMEM frame.
                    if let StageOutcome::RecycleAndContinue = stage_ipsec_passthrough_check(
                        flow.as_ref(),
                        packet_frame,
                        meta,
                        &binding.live,
                        worker_ctx,
                    ) {
                        binding.scratch.scratch_recycle.push(desc.addr);
                        continue;
                    }
                    // ── Flow cache fast path ────────────────────────────
                    // For established TCP (ACK-only) and UDP, check the per-
                    // binding flow cache before the expensive session lookup
                    // + policy + NAT + FIB path. TCP SYN/FIN/RST skip the
                    // cache to ensure proper session lifecycle handling.
                    if FlowCacheEntry::packet_eligible(meta)
                        && let Some(flow) = flow.as_ref()
                    {
                        if let Some(cached) = binding.flow.flow_cache.lookup_counted(
                            &flow.forward_key,
                            FlowCacheLookup::for_packet(meta, validation),
                            now_secs,
                            &worker_ctx.rg_epochs,
                            meta.pkt_len,
                        ) {
                            if !cached_flow_decision_valid(
                                worker_ctx.forwarding,
                                worker_ctx.ha_state,
                                worker_ctx.dynamic_neighbors,
                                now_secs,
                                cached.stamp.owner_rg_id,
                                packet_fabric_ingress,
                                resolution_target_for_session(flow, cached.decision),
                                cached.decision.resolution,
                            ) {
                                binding.flow.flow_cache.invalidate_slot(
                                    &flow.forward_key,
                                    meta.ingress_ifindex as i32,
                                );
                                // Fall through to slow path for full
                                // HA resolution → fabric redirect.
                            } else {
                                let cached_decision = cached.decision;
                                let cached_descriptor = &cached.descriptor;
                                let cached_metadata = &cached.metadata;
                                if let Some(counter) =
                                    cached_descriptor.tx_selection.filter_counter.as_ref()
                                {
                                    crate::filter::record_filter_counter(
                                        counter,
                                        meta.pkt_len as u64,
                                    );
                                }
                                let policer_action =
                                    crate::filter::apply_cached_three_color_policers(
                                        &cached_descriptor.tx_selection.three_color_policers,
                                        now_ns,
                                        meta.pkt_len as u64,
                                    );
                                emit_cached_input_filter_log(
                                    worker_ctx.event_stream,
                                    flow,
                                    meta,
                                    cached_descriptor,
                                    cached_metadata,
                                    now_ns,
                                );
                                emit_cached_output_filter_log(
                                    worker_ctx.forwarding,
                                    worker_ctx.event_stream,
                                    flow,
                                    meta,
                                    cached_decision,
                                    cached_descriptor,
                                    cached_metadata,
                                    now_ns,
                                );
                                if policer_action.drop {
                                    binding.scratch.scratch_recycle.push(desc.addr);
                                    continue;
                                }
                                let cached_queue_id = cached_descriptor.tx_selection.queue_id;
                                let cached_dscp_rewrite = policer_action
                                    .dscp_rewrite
                                    .or(cached_descriptor.tx_selection.dscp_rewrite);
                                // Amortize session timestamp touch — every 64 cache hits.
                                binding.flow.flow_cache_session_touch += 1;
                                if binding.flow.flow_cache_session_touch & 63 == 0 {
                                    sessions.touch(&flow.forward_key, now_ns);
                                }
                                if matches!(
                                    cached_decision.resolution.disposition,
                                    ForwardingDisposition::ForwardCandidate
                                        | ForwardingDisposition::FabricRedirect
                                ) {
                                    // TTL/hop-limit check on flow cache hit path:
                                    // generate ICMP Time Exceeded for packets that
                                    // would expire after decrement.
                                    // #1145: reuse the line-50 raw_frame bind
                                    // instead of re-slicing for the same packet.
                                    let local_icmp_te = build_local_time_exceeded_request(
                                        raw_frame,
                                        desc,
                                        meta,
                                        &worker_ctx.ident,
                                        flow,
                                        worker_ctx.forwarding,
                                        worker_ctx.dynamic_neighbors,
                                        worker_ctx.ha_state,
                                        now_secs,
                                    );
                                    if let Some(request) = local_icmp_te {
                                        binding.scratch.scratch_forwards.push(request);
                                        // Don't recycle here — enqueue_pending_forwards
                                        // returns the frame via pending_fill_frames
                                        // when processing the prebuilt TE response.
                                        continue;
                                    }
                                    telemetry.counters.forward_candidate_packets += 1;
                                    if cached_decision.nat.rewrite_src.is_some() {
                                        telemetry.counters.snat_packets += 1;
                                    }
                                    if cached_decision.nat.rewrite_dst.is_some() {
                                        telemetry.counters.dnat_packets += 1;
                                    }
                                    // ── Inline in-place rewrite fast path ──
                                    // Skip PendingForwardRequest + enqueue_pending_forwards entirely.
                                    // Resolve target binding, rewrite frame in UMEM, push PreparedTxRequest.
                                    let target_ifindex =
                                        if cached_decision.resolution.tx_ifindex > 0 {
                                            cached_decision.resolution.tx_ifindex
                                        } else {
                                            resolve_tx_binding_ifindex(
                                                worker_ctx.forwarding,
                                                cached_decision.resolution.egress_ifindex,
                                            )
                                        };
                                    let expected_ports =
                                        authoritative_forward_ports(packet_frame, meta, Some(flow));
                                    let target_bi =
                                        cached_descriptor.target_binding_index.or_else(|| {
                                            if cached_decision.resolution.disposition
                                                == ForwardingDisposition::FabricRedirect
                                            {
                                                worker_ctx.binding_lookup.fabric_target_index(
                                                    target_ifindex,
                                                    fabric_queue_hash(
                                                        Some(flow),
                                                        expected_ports,
                                                        meta,
                                                    ),
                                                )
                                            } else {
                                                worker_ctx.binding_lookup.target_index(
                                                    binding_index,
                                                    worker_ctx.ident.ifindex,
                                                    worker_ctx.ident.queue_id,
                                                    target_ifindex,
                                                )
                                            }
                                        });
                                    // Check if target is same binding (hairpin) or same-UMEM.
                                    // For simplicity, only do in-place fast path when target == self.
                                    let is_self_target = target_bi == Some(binding_index);
                                    if is_self_target && owned_packet_frame.is_none() {
                                        let ingress_slot = binding.slot;
                                        let flow_key = flow.forward_key.clone();
                                        let mirror_config = resolve_mirror_config(
                                            worker_ctx.forwarding,
                                            meta.ingress_ifindex as i32,
                                            meta.ingress_vlan_id,
                                        );
                                        let mut mirror_next_counter = None;
                                        let mut mirror_admission = mirror_config.and_then(|config| {
                                            let admission = admit_mirror_clone_to_live(
                                                worker_ctx.mirror_targets,
                                                resolve_tx_binding_ifindex(
                                                    worker_ctx.forwarding,
                                                    config.output_ifindex,
                                                ),
                                                worker_ctx.ident.queue_id,
                                                packet_frame.len(),
                                            );
                                            match admission {
                                                Ok(admission) => {
                                                    let mut next_counter =
                                                        binding.mirror_sample_counter;
                                                    if mirror_sample_allows(
                                                        config.rate,
                                                        &mut next_counter,
                                                    ) {
                                                        mirror_next_counter = Some(next_counter);
                                                        Some((config, Ok(admission)))
                                                    } else {
                                                        mirror_next_counter = Some(next_counter);
                                                        None
                                                    }
                                                }
                                                Err(result) => Some((config, Err(result))),
                                            }
                                        });
                                        let mirror_frame_len = packet_frame.len();
                                        let mut mirror_frame = mirror_admission
                                            .as_ref()
                                            .and_then(|(_, admission)| admission.as_ref().ok())
                                            .map(|_| packet_frame.to_vec());
                                        // Try descriptor-based straight-line rewrite first (no branches
                                        // for AF, NAT type, or checksum recomputation).  Falls back to
                                        // generic rewrite on port mismatch, NAT64, or NPTv6.
                                        let rewrite_result = apply_rewrite_descriptor(
                                            unsafe { &*area },
                                            desc,
                                            meta,
                                            &cached_descriptor,
                                            expected_ports,
                                        )
                                        .or_else(|| {
                                            rewrite_forwarded_frame_in_place(
                                                unsafe { &*area },
                                                desc,
                                                meta,
                                                &cached_decision,
                                                cached_descriptor.apply_nat_on_fabric,
                                                expected_ports,
                                            )
                                        });
                                        if let Some(rewrite_result) = rewrite_result {
                                            if let Some(next_counter) = mirror_next_counter {
                                                binding.mirror_sample_counter = next_counter;
                                            }
                                            if let Some((mirror_config, admission)) =
                                                mirror_admission.take()
                                            {
                                                let result = match admission {
                                                    Ok(admission) => {
                                                        if let Some(mirror_frame) =
                                                            mirror_frame.take()
                                                        {
                                                            let cos_queue_id = mirror_cos_queue_id(
                                                                worker_ctx.forwarding,
                                                                mirror_config.output_ifindex,
                                                                meta.into(),
                                                                Some(&flow_key),
                                                            );
                                                            enqueue_admitted_mirror_clone_to_live(
                                                                admission,
                                                                mirror_config,
                                                                mirror_frame,
                                                                meta.into(),
                                                                Some(&flow_key),
                                                                cos_queue_id,
                                                            )
                                                        } else {
                                                            MirrorCloneResult::NoFrame
                                                        }
                                                    }
                                                    Err(result) => result,
                                                };
                                                record_mirror_clone_result(
                                                    &binding.live,
                                                    result,
                                                    mirror_frame_len,
                                                );
                                            }
                                            binding.tx_pipeline.pending_tx_prepared.push_back(
                                                PreparedTxRequest {
                                                    offset: rewrite_result.offset,
                                                    len: rewrite_result.len,
                                                    recycle: PreparedTxRecycle::fill_on_slot(
                                                        ingress_slot,
                                                        rewrite_result.offset,
                                                        desc.addr,
                                                    ),
                                                    expected_ports,
                                                    expected_addr_family: meta.addr_family,
                                                    expected_protocol: meta.protocol,
                                                    flow_key: Some(flow_key),
                                                    egress_ifindex: cached_decision
                                                        .resolution
                                                        .egress_ifindex,
                                                    cos_queue_id: cached_queue_id,
                                                    dscp_rewrite: cached_dscp_rewrite,
                                                    mirror_clone: false,
                                                },
                                            );
                                            binding.tx_counters.pending_in_place_tx_packets += 1;
                                            binding.tx_counters.record_in_place_l2_rewrite(
                                                rewrite_result.l2_rewrite,
                                            );
                                            telemetry.dbg.forward += 1;
                                            telemetry.dbg.tx += 1;
                                            recycle_now = false;
                                        }
                                    }
                                    // Fallback: use PendingForwardRequest path for cross-binding or failure.
                                    if recycle_now {
                                        let cached_precomputed_tx_selection =
                                            CachedTxSelectionDescriptor {
                                                queue_id: cached_queue_id,
                                                dscp_rewrite: cached_dscp_rewrite,
                                                ..CachedTxSelectionDescriptor::default()
                                            };
                                        if let Some(mut request) =
                                            build_live_forward_request_from_frame(
                                                worker_ctx.binding_lookup,
                                                binding_index,
                                                worker_ctx.ident,
                                                desc,
                                                packet_frame,
                                                meta,
                                                &cached_decision,
                                                worker_ctx.forwarding,
                                                Some(flow),
                                                Some(cached_metadata.ingress_zone),
                                                cached_descriptor.apply_nat_on_fabric,
                                                now_ns,
                                                worker_ctx.event_stream,
                                                Some(PendingForwardHints {
                                                    expected_ports,
                                                    target_binding_index: target_bi,
                                                }),
                                                Some(&cached_precomputed_tx_selection),
                                            )
                                        {
                                            request.frame = owned_packet_frame
                                                .take()
                                                .map(PendingForwardFrame::Owned)
                                                .unwrap_or(PendingForwardFrame::Live);
                                            telemetry.dbg.forward += 1;
                                            telemetry.dbg.tx += 1;
                                            binding.scratch.scratch_forwards.push(request);
                                            recycle_now = false;
                                        }
                                    }
                                }
                                if recycle_now {
                                    binding.scratch.scratch_recycle.push(desc.addr);
                                }
                                continue;
                            } // else: cached HA-valid — fast path above
                        }
                    }
                    // ── End flow cache fast path ─────────────────────────
                    let mut debug = flow
                        .as_ref()
                        .map(|flow| ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow));
                    let mut session_ingress_zone: Option<u16> = None;
                    let mut flow_cache_owner_rg_id = 0i32;
                    let mut apply_nat_on_fabric = false;
                    let mut decision = if let Some(flow) = flow.as_ref() {
                        if let Some(resolved) = resolve_flow_session_decision(
                            sessions,
                            binding.bpf_maps.session_map_fd,
                            worker_ctx.shared_sessions,
                            worker_ctx.shared_nat_sessions,
                            worker_ctx.shared_forward_wire_sessions,
                            &worker_ctx.shared_owner_rg_indexes,
                            worker_ctx.peer_worker_commands,
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            worker_ctx.dynamic_neighbors,
                            flow,
                            now_ns,
                            now_secs,
                            meta.protocol,
                            meta.tcp_flags,
                            meta.ingress_ifindex as i32,
                            packet_fabric_ingress,
                            ha_startup_grace_until_secs,
                        ) {
                            telemetry.counters.session_hits += 1;
                            telemetry.dbg.session_hit += 1;
                            if resolved.created {
                                telemetry.counters.session_creates += 1;
                                telemetry.dbg.session_create += 1;
                                // Mirror new session to BPF conntrack map for
                                // `show security flow session` zone/interface display.
                                publish_bpf_conntrack_entry(
                                    conntrack_v4_fd,
                                    conntrack_v6_fd,
                                    &flow.forward_key,
                                    resolved.decision,
                                    &resolved.metadata,
                                    &worker_ctx.forwarding.zone_name_to_id,
                                );
                            }
                            // Log first N session hits from WAN (return path)
                            if cfg!(feature = "debug-log")
                                && meta.ingress_ifindex == 6
                                && telemetry.dbg.wan_return_hits < 5
                            {
                                telemetry.dbg.wan_return_hits += 1;
                                debug_log!(
                                    "DBG WAN_RETURN_HIT[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} nat=({:?},{:?}) rev={}",
                                    telemetry.dbg.wan_return_hits,
                                    flow.src_ip,
                                    flow.forward_key.src_port,
                                    flow.dst_ip,
                                    flow.forward_key.dst_port,
                                    meta.protocol,
                                    meta.tcp_flags,
                                    resolved.decision.nat.rewrite_src,
                                    resolved.decision.nat.rewrite_dst,
                                    resolved.metadata.is_reverse,
                                );
                            }
                            if let Some(debug) = debug.as_mut() {
                                debug.from_zone = Some(resolved.metadata.ingress_zone);
                                debug.to_zone = Some(resolved.metadata.egress_zone);
                            }
                            session_ingress_zone = Some(resolved.metadata.ingress_zone);
                            flow_cache_owner_rg_id = resolved.metadata.owner_rg_id;
                            apply_nat_on_fabric = true;
                            // TTL/hop-limit check on session-hit path: generate
                            // ICMP Time Exceeded for packets that would expire
                            // after decrement. The session-miss path handles this
                            // in build_local_time_exceeded_request(); the session-
                            // hit path previously silently dropped these packets
                            // (the rewrite functions return None for TTL<=1).
                            if matches!(
                                resolved.decision.resolution.disposition,
                                ForwardingDisposition::ForwardCandidate
                            ) {
                                // #1145: reuse line-50 raw_frame bind.
                                let local_icmp_te = build_local_time_exceeded_request(
                                    raw_frame,
                                    desc,
                                    meta,
                                    &worker_ctx.ident,
                                    flow,
                                    worker_ctx.forwarding,
                                    worker_ctx.dynamic_neighbors,
                                    worker_ctx.ha_state,
                                    now_secs,
                                );
                                if let Some(request) = local_icmp_te {
                                    binding.scratch.scratch_forwards.push(request);
                                    // Don't recycle: the TE response references
                                    // the original frame via desc.addr on the request.
                                    // The continue skips recycle_now handling.
                                    continue;
                                }
                            }
                            resolved.decision
                        } else {
                            telemetry.counters.session_misses += 1;
                            telemetry.dbg.session_miss += 1;
                            if let StageOutcome::RecycleAndContinue =
                                stage_screen_syn_cookie_ack_on_session_miss(
                                    Some(flow),
                                    packet_frame,
                                    meta,
                                    ingress_zone_override,
                                    now_secs,
                                    screen,
                                    telemetry.counters,
                                    worker_ctx,
                                )
                            {
                                binding.scratch.scratch_recycle.push(desc.addr);
                                continue;
                            }
                            let resolution_target =
                                parse_packet_destination_from_frame(packet_frame, meta)
                                    .unwrap_or(flow.dst_ip);
                            // Cluster peer return fast path:
                            // a packet arriving from zone-encoded fabric ingress has already
                            // been policy/NAT-validated by the active owner. Allow the inactive
                            // peer to hand it to the resolved local egress zone instead of
                            // treating it as a brand-new flow. Keep pure TCP SYN excluded so
                            // brand-new connects still require local session ownership.
                            if let Some((fabric_return_decision, fabric_return_metadata)) =
                                cluster_peer_return_fast_path(
                                    worker_ctx.forwarding,
                                    worker_ctx.dynamic_neighbors,
                                    packet_frame,
                                    meta,
                                    ingress_zone_override,
                                    resolution_target,
                                )
                            {
                                let ingress_ident = BindingIdentity {
                                    slot: binding.slot,
                                    queue_id: binding.queue_id,
                                    worker_id: binding.worker_id,
                                    interface: binding.interface.clone(),
                                    ifindex: binding.ifindex,
                                };
                                if let Some(mut request) = build_live_forward_request_from_frame(
                                    worker_ctx.binding_lookup,
                                    binding_index,
                                    &ingress_ident,
                                    desc,
                                    packet_frame,
                                    meta,
                                    &fabric_return_decision,
                                    worker_ctx.forwarding,
                                    Some(flow),
                                    None,
                                    false,
                                    now_ns,
                                    worker_ctx.event_stream,
                                    None,
                                    None,
                                ) {
                                    request.frame = owned_packet_frame
                                        .take()
                                        .map(PendingForwardFrame::Owned)
                                        .unwrap_or(PendingForwardFrame::Live);
                                    if sessions.install_with_protocol_with_origin(
                                        flow.forward_key.clone(),
                                        fabric_return_decision,
                                        fabric_return_metadata,
                                        SessionOrigin::ReverseFlow,
                                        now_ns,
                                        meta.protocol,
                                        meta.tcp_flags,
                                    ) {
                                        let _ = publish_live_session_entry(
                                            binding.bpf_maps.session_map_fd,
                                            &flow.forward_key,
                                            NatDecision::default(),
                                            true,
                                        );
                                    }
                                    binding.scratch.scratch_forwards.push(request);
                                    continue;
                                }
                            }

                            // --- DNAT pre-routing ---
                            // Check DNAT table first (port-based DNAT), then
                            // fall back to static NAT DNAT (IP-only 1:1).
                            // The translated destination affects FIB lookup.
                            // #919: ingress_zone_override is now Option<u16>;
                            // DNAT/static NAT lookups still take zone names,
                            // so resolve ID→name lazily on this miss path.
                            let ingress_zone_name = ingress_zone_override
                                .and_then(|id| {
                                    worker_ctx.forwarding.zone_id_to_name.get(&id).map(|s| s.as_str())
                                })
                                .or_else(|| {
                                    // #921: ifindex → u16 → name (slow path; DNAT/static-NAT
                                    // takes &str names).
                                    worker_ctx.forwarding
                                        .ifindex_to_zone_id
                                        .get(&(meta.ingress_ifindex as i32))
                                        .and_then(|id| worker_ctx.forwarding.zone_id_to_name.get(id))
                                        .map(|s| s.as_str())
                                })
                                .unwrap_or("");
                            let dnat_decision = if !worker_ctx.forwarding.dnat_table.is_empty() {
                                worker_ctx.forwarding.dnat_table.lookup(
                                    meta.protocol,
                                    resolution_target,
                                    flow.forward_key.dst_port,
                                    ingress_zone_name,
                                )
                            } else {
                                None
                            };
                            let static_dnat_decision = if dnat_decision.is_none() {
                                worker_ctx.forwarding
                                    .static_nat
                                    .match_dnat(resolution_target, ingress_zone_name)
                            } else {
                                None
                            };
                            let pre_routing_dnat = dnat_decision.or(static_dnat_decision);

                            // --- NPTv6 inbound pre-routing ---
                            // If dst matches an external NPTv6 prefix, translate the
                            // destination to the internal prefix. This is stateless
                            // prefix translation (RFC 6296) -- no L4 checksum update.
                            let nptv6_inbound = if pre_routing_dnat.is_none() {
                                if let IpAddr::V6(mut dst_v6) = resolution_target {
                                    if worker_ctx.forwarding.nptv6.translate_inbound(&mut dst_v6) {
                                        Some(dst_v6)
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            // --- NAT64 pre-routing ---
                            // If dst is IPv6 matching a NAT64 prefix, extract IPv4
                            // dest and allocate an IPv4 SNAT address. Route lookup
                            // must use the IPv4 destination.
                            let nat64_match =
                                if pre_routing_dnat.is_none() && nptv6_inbound.is_none() {
                                    if let IpAddr::V6(dst_v6) = resolution_target {
                                        worker_ctx.forwarding.nat64.match_ipv6_dest(dst_v6).and_then(
                                            |(idx, dst_v4)| {
                                                let snat_v4 =
                                                    worker_ctx.forwarding.nat64.allocate_v4_source(idx)?;
                                                Some((idx, dst_v4, snat_v4, dst_v6))
                                            },
                                        )
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                            let effective_resolution_target =
                                if let Some((_, dst_v4, _, _)) = &nat64_match {
                                    IpAddr::V4(*dst_v4)
                                } else if let Some(internal_dst) = nptv6_inbound {
                                    IpAddr::V6(internal_dst)
                                } else {
                                    match &pre_routing_dnat {
                                        Some(d) => d.rewrite_dst.unwrap_or(resolution_target),
                                        None => resolution_target,
                                    }
                                };
                            let input_filter_log = evaluate_non_pbr_input_filter_log(
                                worker_ctx.forwarding,
                                Some(flow),
                                meta,
                                ingress_zone_override,
                            );
                            let route_table_override = ingress_route_table_override(
                                worker_ctx.forwarding,
                                meta,
                                flow,
                                ingress_zone_override,
                                worker_ctx.event_stream,
                                now_ns,
                            );

                            let resolution = if should_block_tunnel_interface_nat_session_miss(
                                worker_ctx.forwarding,
                                effective_resolution_target,
                                meta.protocol,
                            ) {
                                no_route_resolution(Some(effective_resolution_target))
                            } else {
                                ingress_interface_local_resolution_on_session_miss(
                                    worker_ctx.forwarding,
                                    meta.ingress_ifindex as i32,
                                    meta.ingress_vlan_id,
                                    effective_resolution_target,
                                    meta.protocol,
                                )
                                .or_else(|| {
                                    interface_nat_local_resolution_on_session_miss(
                                        worker_ctx.forwarding,
                                        effective_resolution_target,
                                        meta.protocol,
                                    )
                                })
                                .unwrap_or_else(|| {
                                    enforce_ha_resolution_snapshot(
                                        worker_ctx.forwarding,
                                        worker_ctx.ha_state,
                                        now_secs,
                                        lookup_forwarding_resolution_in_table_with_dynamic(
                                            worker_ctx.forwarding,
                                            worker_ctx.dynamic_neighbors,
                                            effective_resolution_target,
                                            route_table_override.as_deref(),
                                        ),
                                    )
                                })
                            };
                            let fabric_ingress = packet_fabric_ingress;
                            let resolution = prefer_local_forward_candidate_for_fabric_ingress(
                                worker_ctx.forwarding,
                                worker_ctx.ha_state,
                                worker_ctx.dynamic_neighbors,
                                now_secs,
                                fabric_ingress,
                                effective_resolution_target,
                                resolution,
                            );
                            let nptv6_nat = nptv6_inbound.map(|internal_dst| NatDecision {
                                rewrite_src: None,
                                rewrite_dst: Some(IpAddr::V6(internal_dst)),
                                nat64: false,
                                nptv6: true,
                                ..NatDecision::default()
                            });
                            let mut decision = SessionDecision {
                                resolution,
                                nat: nptv6_nat.or(pre_routing_dnat).unwrap_or_default(),
                            };
                            // #919/#922: zero-allocation zone-pair resolution
                            // direct from u16 IDs — no String materialisation
                            // on the per-flow miss path.
                            let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                                worker_ctx.forwarding,
                                meta.ingress_ifindex as i32,
                                ingress_zone_override,
                                resolution.egress_ifindex,
                            );
                            // Borrow zone names as &str for string-typed downstream
                            // callers (static_nat, match_source_nat_for_flow, debug
                            // log). No clone — the borrow lives only inside this
                            // miss-path block while `worker_ctx.forwarding` is held.
                            let from_zone: &str = worker_ctx
                                .forwarding
                                .zone_id_to_name
                                .get(&from_zone_id)
                                .map(|s| s.as_str())
                                .unwrap_or("");
                            let to_zone: &str = worker_ctx
                                .forwarding
                                .zone_id_to_name
                                .get(&to_zone_id)
                                .map(|s| s.as_str())
                                .unwrap_or("");
                            let is_trust_flow = meta.ingress_ifindex == 5
                                || from_zone == "lan"
                                || matches!(flow.src_ip, IpAddr::V4(ip) if ip.octets()[0] == 10);
                            decision.resolution = finalize_new_flow_ha_resolution(
                                worker_ctx.forwarding,
                                worker_ctx.ha_state,
                                now_secs,
                                decision.resolution,
                                packet_fabric_ingress,
                                meta.ingress_ifindex as i32,
                                from_zone_id,
                                ha_startup_grace_until_secs,
                            );
                            // Debug: log session miss with flow details (throttled)
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.session_miss <= 10 || is_trust_flow {
                                    eprintln!(
                                        "DBG SESS_MISS[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} ingress_if={} disp={:?} egress_if={} neigh={:?} zone={}->{}",
                                        telemetry.dbg.session_miss,
                                        flow.src_ip,
                                        flow.forward_key.src_port,
                                        flow.dst_ip,
                                        flow.forward_key.dst_port,
                                        meta.protocol,
                                        meta.tcp_flags,
                                        meta.ingress_ifindex,
                                        resolution.disposition,
                                        resolution.egress_ifindex,
                                        resolution.neighbor_mac.map(|m| format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )),
                                        from_zone,
                                        to_zone,
                                    );
                                    // If from WAN (if6), dump what session key was tried
                                    if meta.ingress_ifindex == 6 {
                                        eprintln!(
                                            "DBG SESS_MISS_KEY: af={} proto={} key={}:{}->{}:{} bpf_entries={} local_sessions={}",
                                            flow.forward_key.addr_family,
                                            flow.forward_key.protocol,
                                            flow.forward_key.src_ip,
                                            flow.forward_key.src_port,
                                            flow.forward_key.dst_ip,
                                            flow.forward_key.dst_port,
                                            count_bpf_session_entries(binding.bpf_maps.session_map_fd),
                                            sessions.len(),
                                        );
                                        // Dump all local sessions to compare
                                        if telemetry.dbg.session_miss <= 3 {
                                            let mut sess_dump = String::new();
                                            let mut count = 0;
                                            sessions.iter_with_origin(|key, decision, metadata, origin| {
                                                if count < 30 {
                                                    use std::fmt::Write;
                                                    let _ = write!(sess_dump,
                                                        "\n  LOCAL_SESS: af={} proto={} {}:{}->{}:{} nat=({:?},{:?}) rev={} synced={} origin={}",
                                                        key.addr_family, key.protocol,
                                                        key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                                                        decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                                        metadata.is_reverse, origin.is_peer_synced(), origin.as_str(),
                                                    );
                                                    count += 1;
                                                }
                                            });
                                            if !sess_dump.is_empty() {
                                                eprintln!("DBG SESS_MISS_DUMP:{sess_dump}");
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(debug) = debug.as_mut() {
                                debug.from_zone = Some(from_zone_id);
                                debug.to_zone = Some(to_zone_id);
                            }
                            // Compute embedded ICMP error flag early so we can skip
                            // the BPF session map publish for ICMP errors. Publishing
                            // them as PASS_TO_KERNEL causes subsequent ICMP errors to
                            // bypass the userspace embedded ICMP NAT reversal.
                            let is_embedded_icmp_error = if worker_ctx.forwarding.allow_embedded_icmp
                                && matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
                            {
                                // #1145: reuse line-50 raw_frame bind.
                                raw_frame
                                    .get(meta.l4_offset as usize)
                                    .copied()
                                    .map(|icmp_type| is_icmp_error(meta.protocol, icmp_type))
                                    .unwrap_or(false)
                            } else {
                                false
                            };
                            if resolution.disposition == ForwardingDisposition::LocalDelivery
                                && !is_embedded_icmp_error
                                && should_cache_local_delivery_session_on_miss(
                                    worker_ctx.forwarding,
                                    effective_resolution_target,
                                    resolution,
                                    meta.protocol,
                                    meta.tcp_flags,
                                )
                            {
                                let local_metadata = SessionMetadata {
                                    ingress_zone: from_zone_id,
                                    egress_zone: to_zone_id,
                                    owner_rg_id: 0,
                                    fabric_ingress: false,
                                    is_reverse: false,
                                    // Keep firewall-local sessions in the helper only for HA
                                    // state. Publish only the exact observed key back into the
                                    // BPF session map so subsequent established packets bypass
                                    // userspace and return directly to the kernel.
                                    nat64_reverse: None,
                                };
                                if install_helper_local_session_on_miss(
                                    sessions,
                                    binding.bpf_maps.session_map_fd,
                                    worker_ctx.shared_sessions,
                                    worker_ctx.shared_nat_sessions,
                                    worker_ctx.shared_forward_wire_sessions,
                                    &worker_ctx.shared_owner_rg_indexes,
                                    &flow.forward_key,
                                    decision,
                                    local_metadata.clone(),
                                    SessionOrigin::LocalMiss,
                                    now_ns,
                                    meta.protocol,
                                    meta.tcp_flags,
                                ) {
                                    telemetry.counters.session_creates += 1;
                                    telemetry.dbg.session_create += 1;
                                    publish_bpf_conntrack_entry(
                                        conntrack_v4_fd,
                                        conntrack_v6_fd,
                                        &flow.forward_key,
                                        decision,
                                        &local_metadata,
                                        &worker_ctx.forwarding.zone_name_to_id,
                                    );
                                }
                            }
                            if is_embedded_icmp_error {
                                #[cfg(feature = "debug-log")]
                                let icmpv6_trace = meta.protocol == PROTO_ICMPV6
                                    && ICMPV6_EMBED_LOGGED.fetch_add(1, Ordering::Relaxed) < 32;
                                if let Some(icmp_match) = try_embedded_icmp_nat_match(
                                    unsafe { &*area },
                                    desc,
                                    meta,
                                    sessions,
                                    worker_ctx.forwarding,
                                    worker_ctx.dynamic_neighbors,
                                    worker_ctx.shared_sessions,
                                    worker_ctx.shared_nat_sessions,
                                    worker_ctx.shared_forward_wire_sessions,
                                    now_ns,
                                ) {
                                    #[cfg(feature = "debug-log")]
                                    if icmpv6_trace {
                                        debug_log!(
                                            "ICMPV6_EMBED: match orig_src={} orig_port={} nat={:?} resolution={:?} egress_if={} tx_if={} neigh={:?}",
                                            icmp_match.original_src,
                                            icmp_match.original_src_port,
                                            icmp_match.nat,
                                            icmp_match.resolution.disposition,
                                            icmp_match.resolution.egress_ifindex,
                                            icmp_match.resolution.tx_ifindex,
                                            icmp_match.resolution.neighbor_mac,
                                        );
                                    }
                                    if icmp_match.nat.rewrite_src.is_some() {
                                        let icmp_resolution = finalize_embedded_icmp_resolution(
                                            worker_ctx.forwarding,
                                            worker_ctx.ha_state,
                                            now_secs,
                                            meta.ingress_ifindex as i32,
                                            &icmp_match,
                                        );
                                        // #1145: reuse line-50 raw_frame bind.
                                        let rewritten = match meta.addr_family as i32 {
                                            libc::AF_INET => build_nat_reversed_icmp_error_v4(
                                                raw_frame,
                                                meta,
                                                &icmp_match,
                                            ),
                                            libc::AF_INET6 => build_nat_reversed_icmp_error_v6(
                                                raw_frame,
                                                meta,
                                                &icmp_match,
                                            ),
                                            _ => None,
                                        };
                                        if let Some(rewritten_frame) = rewritten {
                                            let icmp_decision = SessionDecision {
                                                resolution: icmp_resolution,
                                                nat: NatDecision::default(),
                                            };
                                            let target_ifindex =
                                                if icmp_decision.resolution.tx_ifindex > 0 {
                                                    icmp_decision.resolution.tx_ifindex
                                                } else {
                                                    resolve_tx_binding_ifindex(
                                                        worker_ctx.forwarding,
                                                        icmp_decision.resolution.egress_ifindex,
                                                    )
                                                };
                                            let cos = resolve_cos_tx_selection_at(
                                                worker_ctx.forwarding,
                                                icmp_decision.resolution.egress_ifindex,
                                                meta,
                                                Some(&flow.forward_key),
                                                now_ns,
                                            );
                                            if !cos.drop {
                                                binding.scratch.scratch_forwards.push(PendingForwardRequest {
                                                    target_ifindex,
                                                    target_binding_index: worker_ctx.binding_lookup.target_index(
                                                        binding_index,
                                                        worker_ctx.ident.ifindex,
                                                        worker_ctx.ident.queue_id,
                                                        target_ifindex,
                                                    ),
                                                    ingress_queue_id: worker_ctx.ident.queue_id,
                                                    desc,
                                                    frame: PendingForwardFrame::Prebuilt(
                                                        rewritten_frame,
                                                    ),
                                                    meta: meta.into(),
                                                    decision: icmp_decision,
                                                    apply_nat_on_fabric: false,
                                                    expected_ports: None,
                                                    flow_key: Some(flow.forward_key.clone()),
                                                    nat64_reverse: None,
                                                    cos_queue_id: cos.queue_id,
                                                    dscp_rewrite: cos.dscp_rewrite,
                                                    cos_tx_selection_resolved: true,
                                                });
                                                recycle_now = false;
                                            }
                                            #[cfg(feature = "debug-log")]
                                            if icmpv6_trace {
                                                debug_log!(
                                                    "ICMPV6_EMBED: queued resolution={:?} egress_if={} tx_if={} target_if={}",
                                                    icmp_decision.resolution.disposition,
                                                    icmp_decision.resolution.egress_ifindex,
                                                    icmp_decision.resolution.tx_ifindex,
                                                    target_ifindex,
                                                );
                                            }
                                        } else {
                                            #[cfg(feature = "debug-log")]
                                            if icmpv6_trace {
                                                debug_log!(
                                                    "ICMPV6_EMBED: build_none resolution={:?} egress_if={} tx_if={} neigh={:?}",
                                                    icmp_resolution.disposition,
                                                    icmp_resolution.egress_ifindex,
                                                    icmp_resolution.tx_ifindex,
                                                    icmp_resolution.neighbor_mac,
                                                );
                                            }
                                        }
                                    } else {
                                        #[cfg(feature = "debug-log")]
                                        if icmpv6_trace {
                                            debug_log!(
                                                "ICMPV6_EMBED: no_rewrite nat={:?}",
                                                icmp_match.nat
                                            );
                                        }
                                    }
                                } else {
                                    #[cfg(feature = "debug-log")]
                                    if icmpv6_trace {
                                        debug_log!(
                                            "ICMPV6_EMBED: no_match outer={}:{} -> {}:{} ingress_if={} from_zone={} to_zone={}",
                                            flow.src_ip,
                                            flow.forward_key.src_port,
                                            flow.dst_ip,
                                            flow.forward_key.dst_port,
                                            meta.ingress_ifindex,
                                            from_zone,
                                            to_zone,
                                        );
                                    }
                                }
                                // Permit without policy check or session install.
                                // If NAT reversal was applied, the prebuilt frame
                                // is already queued. If not, fall through to slow-path.
                            } else if decision.resolution.disposition
                                == ForwardingDisposition::ForwardCandidate
                            {
                                let owner_rg_id =
                                    owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                                flow_cache_owner_rg_id = owner_rg_id;
                                // #850: allow-dns-reply admits sessionless DNS replies
                                // through policy (not around it). Always evaluate policy;
                                // the session-install step below is skipped only when
                                // the knob matches AND no NAT is required (to avoid
                                // orphan NAT state without a session anchor).
                                let policy_result = evaluate_policy_result_with_len(
                                    &worker_ctx.forwarding.policy,
                                    from_zone_id,
                                    to_zone_id,
                                    flow.src_ip,
                                    flow.dst_ip,
                                    flow.forward_key.protocol,
                                    flow.forward_key.src_port,
                                    flow.forward_key.dst_port,
                                    desc.len as u64,
                                );
                                if let PolicyAction::Permit = policy_result.action {
                                    // NAT64: cross-family translation takes
                                    // priority over same-family SNAT.
                                    let nat64_info = if let Some((
                                        _,
                                        dst_v4,
                                        snat_v4,
                                        orig_dst_v6,
                                    )) = nat64_match
                                    {
                                        decision.nat =
                                            Nat64State::forward_decision(snat_v4, dst_v4);
                                        Some(Nat64ReverseInfo {
                                            orig_src_v6: match flow.src_ip {
                                                IpAddr::V6(v6) => v6,
                                                _ => std::net::Ipv6Addr::UNSPECIFIED,
                                            },
                                            orig_dst_v6: orig_dst_v6,
                                        })
                                    } else {
                                        // Check NPTv6 outbound, then static NAT SNAT, then interface SNAT.
                                        // Use merge() to combine with any pre-routing DNAT
                                        // decision rather than overwriting it.
                                        let nat_match_flow =
                                            flow.with_destination(effective_resolution_target);
                                        if decision.nat.rewrite_dst.is_none() {
                                            // Try NPTv6 outbound: if src matches an internal prefix,
                                            // translate to external prefix (stateless, no L4 csum update).
                                            let nptv6_snat = if let IpAddr::V6(mut src_v6) =
                                                nat_match_flow.src_ip
                                            {
                                                if worker_ctx.forwarding.nptv6.translate_outbound(&mut src_v6)
                                                {
                                                    Some(NatDecision {
                                                        rewrite_src: Some(IpAddr::V6(src_v6)),
                                                        rewrite_dst: None,
                                                        nat64: false,
                                                        nptv6: true,
                                                        ..NatDecision::default()
                                                    })
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            };
                                            match nptv6_snat.map(Ok).unwrap_or_else(|| {
                                                source_nat_decision_for_flow(
                                                    worker_ctx.forwarding,
                                                    &from_zone,
                                                    &to_zone,
                                                    decision.resolution.egress_ifindex,
                                                    &nat_match_flow,
                                                )
                                            }) {
                                                Ok(snat_decision) => {
                                                    decision.nat = snat_decision;
                                                }
                                                Err(failure) => {
                                                    record_source_nat_failure(
                                                        telemetry,
                                                        worker_ctx,
                                                        meta,
                                                        flow,
                                                        from_zone_id,
                                                        to_zone_id,
                                                        desc.len,
                                                        &failure,
                                                    );
                                                    binding.scratch.scratch_recycle.push(desc.addr);
                                                    continue;
                                                }
                                            }
                                        } else {
                                            match source_nat_decision_for_flow(
                                                worker_ctx.forwarding,
                                                &from_zone,
                                                &to_zone,
                                                decision.resolution.egress_ifindex,
                                                &nat_match_flow,
                                            ) {
                                                Ok(snat_decision) => {
                                                    decision.nat = decision.nat.merge(snat_decision);
                                                }
                                                Err(failure) => {
                                                    record_source_nat_failure(
                                                        telemetry,
                                                        worker_ctx,
                                                        meta,
                                                        flow,
                                                        from_zone_id,
                                                        to_zone_id,
                                                        desc.len,
                                                        &failure,
                                                    );
                                                    binding.scratch.scratch_recycle.push(desc.addr);
                                                    continue;
                                                }
                                            }
                                        }
                                        None
                                    };
                                    // #1145: reuse line-50 raw_frame bind.
                                    let local_icmp_te = build_local_time_exceeded_request(
                                        raw_frame,
                                        desc,
                                        meta,
                                        &worker_ctx.ident,
                                        flow,
                                        worker_ctx.forwarding,
                                        worker_ctx.dynamic_neighbors,
                                        worker_ctx.ha_state,
                                        now_secs,
                                    );
                                    if let Some(request) = local_icmp_te {
                                        binding.scratch.scratch_forwards.push(request);
                                        recycle_now = false;
                                    } else {
                                        let mut created = 0u64;
                                        // #850: DNS-reply fast-path skips session install
                                        // when no NAT is required.  If NAT is required, fall
                                        // through to normal session install so NAT state is
                                        // anchored for GC.
                                        let dns_fastpath_admit =
                                            allow_unsolicited_dns_reply(worker_ctx.forwarding, flow)
                                                && decision.nat.rewrite_src.is_none()
                                                && decision.nat.rewrite_dst.is_none()
                                                && !decision.nat.nat64
                                                && !decision.nat.nptv6;
                                        let track_in_userspace = decision.resolution.disposition
                                            != ForwardingDisposition::LocalDelivery
                                            && !dns_fastpath_admit;
                                        let install_local_reverse =
                                            should_install_local_reverse_session(
                                                decision,
                                                fabric_ingress,
                                            );
                                        let forward_metadata = SessionMetadata {
                                            ingress_zone: from_zone_id,
                                            egress_zone: to_zone_id,
                                            owner_rg_id,
                                            fabric_ingress,
                                            is_reverse: false,
                                            nat64_reverse: nat64_info,
                                        };
                                        if track_in_userspace
                                            && sessions.install_with_protocol_with_origin(
                                                flow.forward_key.clone(),
                                                decision,
                                                forward_metadata.clone(),
                                                SessionOrigin::ForwardFlow,
                                                now_ns,
                                                meta.protocol,
                                                meta.tcp_flags,
                                            )
                                        {
                                            created += 1;
                                            let forward_entry = SyncedSessionEntry {
                                                key: flow.forward_key.clone(),
                                                decision,
                                                metadata: forward_metadata,
                                                origin: SessionOrigin::ForwardFlow,
                                                protocol: meta.protocol,
                                                tcp_flags: meta.tcp_flags,
                                            };
                                            let _ = publish_live_session_entry(
                                                binding.bpf_maps.session_map_fd,
                                                &flow.forward_key,
                                                decision.nat,
                                                false,
                                            );
                                            publish_shared_session(
                                                worker_ctx.shared_sessions,
                                                worker_ctx.shared_nat_sessions,
                                                worker_ctx.shared_forward_wire_sessions,
                                                &worker_ctx.shared_owner_rg_indexes,
                                                &forward_entry,
                                            );
                                            // Populate BPF dnat_table for embedded ICMP NAT reversal.
                                            // Without this, mtr/traceroute intermediate hops are invisible.
                                            publish_dnat_table_entry(
                                                &worker_ctx.dnat_fds,
                                                &flow.forward_key,
                                                decision.nat,
                                            );
                                            replicate_session_upsert(
                                                worker_ctx.peer_worker_commands,
                                                &forward_entry,
                                            );
                                            if let Some((log_match, ingress_zone_id)) =
                                                input_filter_log
                                            {
                                                emit_input_filter_log_match(
                                                    worker_ctx.event_stream,
                                                    flow,
                                                    meta,
                                                    ingress_zone_id,
                                                    log_match,
                                                    now_ns,
                                                );
                                            }
                                        }
                                        let reverse_resolution = reverse_resolution_for_session(
                                            worker_ctx.forwarding,
                                            worker_ctx.ha_state,
                                            worker_ctx.dynamic_neighbors,
                                            flow.src_ip,
                                            from_zone_id,
                                            fabric_ingress,
                                            now_secs,
                                            false,
                                        );
                                        // Install the reverse entry even if the initial reply-side
                                        // resolution is not immediately usable. On live traffic the
                                        // first server reply can arrive before the reverse neighbor
                                        // state has converged on every worker, and dropping the reverse
                                        // entry creation turns that race into a hard policy miss. The
                                        // hit path re-resolves on demand and can fall back to the
                                        // cached decision when neighbor convergence is still in flight.
                                        let reverse_decision = SessionDecision {
                                            resolution: reverse_resolution,
                                            nat: decision.nat.reverse(
                                                flow.src_ip,
                                                flow.dst_ip,
                                                flow.forward_key.src_port,
                                                flow.forward_key.dst_port,
                                            ),
                                        };
                                        // For NAT64: the reverse key is IPv4 (different AF
                                        // from the forward IPv6 key). The reply arrives as
                                        // IPv4: src=dst_v4, dst=snat_v4.
                                        let (reverse_key, reverse_protocol) = if nat64_info
                                            .is_some()
                                        {
                                            let nat = decision.nat;
                                            let dst_v4 = match nat.rewrite_dst {
                                                Some(IpAddr::V4(v4)) => v4,
                                                _ => Ipv4Addr::UNSPECIFIED,
                                            };
                                            let snat_v4 = match nat.rewrite_src {
                                                Some(IpAddr::V4(v4)) => v4,
                                                _ => Ipv4Addr::UNSPECIFIED,
                                            };
                                            // Map protocol: ICMPv6→ICMP for the reverse key.
                                            let rev_proto = match meta.protocol {
                                                PROTO_ICMPV6 => PROTO_ICMP,
                                                p => p,
                                            };
                                            let (src_port, dst_port) = if matches!(
                                                meta.protocol,
                                                PROTO_ICMP | PROTO_ICMPV6
                                            ) {
                                                (
                                                    flow.forward_key.src_port,
                                                    flow.forward_key.dst_port,
                                                )
                                            } else {
                                                (
                                                    flow.forward_key.dst_port,
                                                    flow.forward_key.src_port,
                                                )
                                            };
                                            (
                                                SessionKey {
                                                    addr_family: libc::AF_INET as u8,
                                                    protocol: rev_proto,
                                                    src_ip: IpAddr::V4(dst_v4),
                                                    dst_ip: IpAddr::V4(snat_v4),
                                                    src_port,
                                                    dst_port,
                                                },
                                                rev_proto,
                                            )
                                        } else {
                                            (flow.reverse_key_with_nat(decision.nat), meta.protocol)
                                        };
                                        let _ = reverse_protocol; // used below for install
                                        let reverse_metadata = SessionMetadata {
                                            ingress_zone: to_zone_id,
                                            egress_zone: from_zone_id,
                                            owner_rg_id,
                                            fabric_ingress,
                                            is_reverse: true,
                                            nat64_reverse: nat64_info,
                                        };
                                        if track_in_userspace
                                            && install_local_reverse
                                            && sessions.install_with_protocol_with_origin(
                                                reverse_key.clone(),
                                                reverse_decision,
                                                reverse_metadata.clone(),
                                                SessionOrigin::ReverseFlow,
                                                now_ns,
                                                meta.protocol,
                                                meta.tcp_flags,
                                            )
                                        {
                                            let _ = publish_live_session_key(
                                                binding.bpf_maps.session_map_fd,
                                                &reverse_key,
                                            );
                                            // Verify session keys and log creations (debug-only: BPF syscalls)
                                            if cfg!(feature = "debug-log") {
                                                if verify_session_key_in_bpf(
                                                    binding.bpf_maps.session_map_fd,
                                                    &reverse_key,
                                                ) {
                                                    SESSION_PUBLISH_VERIFY_OK
                                                        .fetch_add(1, Ordering::Relaxed);
                                                } else {
                                                    SESSION_PUBLISH_VERIFY_FAIL
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    debug_log!(
                                                        "SESS_VERIFY_FAIL: reverse key NOT found after publish! \
                                                             af={} proto={} {}:{} -> {}:{} (map_fd={})",
                                                        reverse_key.addr_family,
                                                        reverse_key.protocol,
                                                        reverse_key.src_ip,
                                                        reverse_key.src_port,
                                                        reverse_key.dst_ip,
                                                        reverse_key.dst_port,
                                                        binding.bpf_maps.session_map_fd,
                                                    );
                                                }
                                                if !verify_session_key_in_bpf(
                                                    binding.bpf_maps.session_map_fd,
                                                    &flow.forward_key,
                                                ) {
                                                    debug_log!(
                                                        "SESS_VERIFY_FAIL: forward key NOT found! \
                                                             af={} proto={} {}:{} -> {}:{}",
                                                        flow.forward_key.addr_family,
                                                        flow.forward_key.protocol,
                                                        flow.forward_key.src_ip,
                                                        flow.forward_key.src_port,
                                                        flow.forward_key.dst_ip,
                                                        flow.forward_key.dst_port,
                                                    );
                                                }
                                                let logged = SESSION_CREATIONS_LOGGED
                                                    .fetch_add(1, Ordering::Relaxed);
                                                if logged < 10 {
                                                    debug_log!(
                                                        "SESS_CREATE[{}]: FWD af={} proto={} {}:{} -> {}:{} \
                                                             | REV af={} proto={} {}:{} -> {}:{} \
                                                             | NAT src={:?} dst={:?} \
                                                             | map_fd={} bpf_entries={}",
                                                        logged,
                                                        flow.forward_key.addr_family,
                                                        flow.forward_key.protocol,
                                                        flow.forward_key.src_ip,
                                                        flow.forward_key.src_port,
                                                        flow.forward_key.dst_ip,
                                                        flow.forward_key.dst_port,
                                                        reverse_key.addr_family,
                                                        reverse_key.protocol,
                                                        reverse_key.src_ip,
                                                        reverse_key.src_port,
                                                        reverse_key.dst_ip,
                                                        reverse_key.dst_port,
                                                        decision.nat.rewrite_src,
                                                        decision.nat.rewrite_dst,
                                                        binding.bpf_maps.session_map_fd,
                                                        count_bpf_session_entries(
                                                            binding.bpf_maps.session_map_fd
                                                        ),
                                                    );
                                                    dump_bpf_session_entries(
                                                        binding.bpf_maps.session_map_fd,
                                                        20,
                                                    );
                                                }
                                            }
                                            created += 1;
                                            let reverse_entry = SyncedSessionEntry {
                                                key: reverse_key,
                                                decision: reverse_decision,
                                                metadata: reverse_metadata,
                                                origin: SessionOrigin::ReverseFlow,
                                                protocol: meta.protocol,
                                                tcp_flags: meta.tcp_flags,
                                            };
                                            publish_shared_session(
                                                worker_ctx.shared_sessions,
                                                worker_ctx.shared_nat_sessions,
                                                worker_ctx.shared_forward_wire_sessions,
                                                &worker_ctx.shared_owner_rg_indexes,
                                                &reverse_entry,
                                            );
                                            replicate_session_upsert(
                                                worker_ctx.peer_worker_commands,
                                                &reverse_entry,
                                            );
                                        }
                                        if created > 0 {
                                            telemetry.counters.session_creates += created;
                                            telemetry.dbg.session_create += created;
                                        }
                                    }
                                } else {
                                    emit_policy_deny_event(
                                        worker_ctx.event_stream,
                                        flow,
                                        meta,
                                        from_zone_id,
                                        to_zone_id,
                                        owner_rg_id,
                                        policy_result.policy_id,
                                        policy_result.action,
                                        now_ns,
                                    );
                                    telemetry.dbg.policy_deny += 1;
                                    if cfg!(feature = "debug-log")
                                        && (telemetry.dbg.policy_deny <= 3 || is_trust_flow)
                                    {
                                        debug_log!(
                                            "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
                                            telemetry.dbg.policy_deny,
                                            flow.src_ip,
                                            flow.forward_key.src_port,
                                            flow.dst_ip,
                                            flow.forward_key.dst_port,
                                            meta.protocol,
                                            from_zone,
                                            to_zone,
                                            meta.ingress_ifindex,
                                            resolution.egress_ifindex,
                                        );
                                    }
                                    decision.resolution.disposition =
                                        ForwardingDisposition::PolicyDenied;
                                }
                            } else if decision.resolution.disposition
                                == ForwardingDisposition::HAInactive
                                && !packet_fabric_ingress
                            {
                                let owner_rg_id =
                                    owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                                if owner_rg_id > 0 {
                                    flow_cache_owner_rg_id = owner_rg_id;
                                }
                                // New flow to inactive RG: fabric-redirect to the peer
                                // that owns the egress RG.  Use from_zone_arc directly
                                // (always in scope) rather than going through the debug
                                // struct which may not have been populated.
                                // #919/#922: ID-keyed redirect — no name lookup.
                                if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(
                                    worker_ctx.forwarding,
                                    from_zone_id,
                                )
                                .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                                {
                                    decision.resolution = redirect;
                                }
                            }
                            decision
                        }
                    } else {
                        let non_flow_resolution = enforce_ha_resolution_snapshot(
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            now_secs,
                            resolve_forwarding(
                                unsafe { &*area },
                                desc,
                                meta,
                                worker_ctx.forwarding,
                                worker_ctx.dynamic_neighbors,
                            ),
                        );
                        // For non-flow packets (no L4 ports), also attempt fabric
                        // redirect when the egress RG is inactive.
                        let final_resolution = if non_flow_resolution.disposition
                            == ForwardingDisposition::HAInactive
                            && !packet_fabric_ingress
                        {
                            resolve_fabric_redirect(worker_ctx.forwarding).unwrap_or(non_flow_resolution)
                        } else {
                            non_flow_resolution
                        };
                        SessionDecision {
                            resolution: final_resolution,
                            nat: NatDecision::default(),
                        }
                    };
                    // Safety net: convert any remaining HAInactive to fabric
                    // redirect. Session-hit and new-flow paths each attempt
                    // fabric redirect internally, but demoted sessions that
                    // arrive via DNAT/interface-NAT XDP shim paths can slip
                    // through with HAInactive when the inner conversion found
                    // no fabric link at the time. Anti-loop: never redirect
                    // packets that arrived on the fabric interface itself.
                    // Only redirect when the egress maps to a known RG.
                    // HAInactive with unknown ownership (rg=0) means unresolved
                    // — those should NOT be fabric-redirected.
                    let egress_rg = owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                    if decision.resolution.disposition == ForwardingDisposition::HAInactive
                        && egress_rg > 0
                        && !packet_fabric_ingress
                    {
                        if flow_cache_owner_rg_id <= 0 {
                            flow_cache_owner_rg_id = egress_rg;
                        }
                        // #919: prefer the cached u16 zone ID; fall back to
                        // looking up the ifindex's zone name and translating
                        // to an ID. resolve_zone_encoded_fabric_redirect_by_id
                        // skips the name round-trip.
                        // #921: direct ifindex → u16 (was a two-hop
                        // name round-trip).
                        let zone_id = session_ingress_zone.or_else(|| {
                            worker_ctx
                                .forwarding
                                .ifindex_to_zone_id
                                .get(&(meta.ingress_ifindex as i32))
                                .copied()
                        });
                        if let Some(redirect) = zone_id
                            .and_then(|id| {
                                resolve_zone_encoded_fabric_redirect_by_id(
                                    worker_ctx.forwarding,
                                    id,
                                )
                            })
                            .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                        {
                            decision.resolution = redirect;
                        }
                    }
                    if matches!(
                        decision.resolution.disposition,
                        ForwardingDisposition::ForwardCandidate
                            | ForwardingDisposition::FabricRedirect
                    ) {
                        telemetry.dbg.forward += 1;
                        // Direction-specific tracking
                        let ingress_if = meta.ingress_ifindex as i32;
                        let egress_if = decision.resolution.egress_ifindex;
                        if ingress_if == 5 {
                            telemetry.dbg.rx_from_trust += 1;
                            telemetry.dbg.fwd_trust_to_wan += 1;
                        } else if ingress_if == 6 {
                            telemetry.dbg.rx_from_wan += 1;
                            telemetry.dbg.fwd_wan_to_trust += 1;
                        }
                        // NAT decision tracking
                        if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some()
                        {
                            telemetry.dbg.nat_applied_snat += 1;
                            telemetry.dbg.nat_applied_dnat += 1;
                        } else if decision.nat.rewrite_src.is_some() {
                            telemetry.dbg.nat_applied_snat += 1;
                        } else if decision.nat.rewrite_dst.is_some() {
                            telemetry.dbg.nat_applied_dnat += 1;
                        } else {
                            telemetry.dbg.nat_applied_none += 1;
                        }
                        // Log NAT details for first few forward-candidate packets
                        if cfg!(feature = "debug-log") {
                            if telemetry.dbg.forward <= 10 {
                                let flow_str = flow
                                    .as_ref()
                                    .map(|f| {
                                        format!(
                                            "{}:{} -> {}:{}",
                                            f.src_ip,
                                            f.forward_key.src_port,
                                            f.dst_ip,
                                            f.forward_key.dst_port
                                        )
                                    })
                                    .unwrap_or_else(|| "no-flow".into());
                                let nat_str = format!(
                                    "snat={:?} dnat={:?}",
                                    decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                );
                                eprintln!(
                                    "DBG FWD_DECISION[{}]: ingress_if={} egress_if={} {} {} proto={}",
                                    telemetry.dbg.forward,
                                    ingress_if,
                                    egress_if,
                                    flow_str,
                                    nat_str,
                                    meta.protocol,
                                );
                            }
                        }
                        // TCP flag tracking on forwarded frames
                        if cfg!(feature = "debug-log") {
                            if meta.protocol == 6 {
                                // Compare meta.tcp_flags from BPF shim with raw frame TCP flags.
                                // #1145: reuse line-50 raw_frame bind instead of re-slicing.
                                let raw_tcp_info = extract_tcp_flags_and_window(raw_frame);
                                let raw_flags = raw_tcp_info.map(|(f, _)| f);
                                let raw_window = raw_tcp_info.map(|(_, w)| w);
                                // Log first 20 forwarded TCP packets: compare meta vs raw
                                if telemetry.dbg.forward <= 20 {
                                    let flow_str = flow
                                        .as_ref()
                                        .map(|f| {
                                            format!(
                                                "{}:{} -> {}:{}",
                                                f.src_ip,
                                                f.forward_key.src_port,
                                                f.dst_ip,
                                                f.forward_key.dst_port
                                            )
                                        })
                                        .unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "FWD_TCP_CMP[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} l4_off={} {}",
                                        telemetry.dbg.forward,
                                        meta.tcp_flags,
                                        raw_flags
                                            .map(|f| format!("0x{:02x}", f))
                                            .unwrap_or_else(|| "NONE".into()),
                                        raw_window
                                            .map(|w| format!("{}", w))
                                            .unwrap_or_else(|| "NONE".into()),
                                        desc.len,
                                        meta.l4_offset,
                                        flow_str,
                                    );
                                    // Hex dump bytes around TCP flags position in raw frame.
                                    // #1145: reuse line-50 raw_frame bind (no Option wrapper).
                                    let l4 = meta.l4_offset as usize;
                                    if raw_frame.len() > l4 + 20 {
                                        let tcp_hdr: String = raw_frame[l4..l4 + 20]
                                            .iter()
                                            .map(|b| format!("{:02x}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        eprintln!(
                                            "FWD_TCP_HDR[{}]: offset={} {}",
                                            telemetry.dbg.forward, l4, tcp_hdr
                                        );
                                    }
                                }
                                if (meta.tcp_flags & 0x04) != 0 {
                                    // RST
                                    telemetry.dbg.fwd_tcp_rst += 1;
                                    if telemetry.dbg.fwd_tcp_rst <= 5 {
                                        let flow_str = flow
                                            .as_ref()
                                            .map(|f| {
                                                format!(
                                                    "{}:{} -> {}:{}",
                                                    f.src_ip,
                                                    f.forward_key.src_port,
                                                    f.dst_ip,
                                                    f.forward_key.dst_port
                                                )
                                            })
                                            .unwrap_or_else(|| "no-flow".into());
                                        eprintln!(
                                            "FWD_TCP_RST_DETECT[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} fwd#={} {}",
                                            telemetry.dbg.fwd_tcp_rst,
                                            meta.tcp_flags,
                                            raw_flags
                                                .map(|f| format!("0x{:02x}", f))
                                                .unwrap_or_else(|| "NONE".into()),
                                            raw_window
                                                .map(|w| format!("{}", w))
                                                .unwrap_or_else(|| "NONE".into()),
                                            desc.len,
                                            telemetry.dbg.forward,
                                            flow_str,
                                        );
                                        // Hex dump TCP header when RST detected.
                                        // #1145: reuse line-50 raw_frame bind.
                                        let l4 = meta.l4_offset as usize;
                                        if raw_frame.len() > l4 + 20 {
                                            let tcp_hdr: String = raw_frame[l4..l4 + 20]
                                                .iter()
                                                .map(|b| format!("{:02x}", b))
                                                .collect::<Vec<_>>()
                                                .join(" ");
                                            eprintln!(
                                                "FWD_TCP_RST_HDR[{}]: meta_off={} raw_off={} {}",
                                                telemetry.dbg.fwd_tcp_rst,
                                                l4,
                                                frame_l3_offset(raw_frame).unwrap_or(0),
                                                tcp_hdr
                                            );
                                        }
                                    }
                                }
                                if (meta.tcp_flags & 0x01) != 0 {
                                    // FIN
                                    telemetry.dbg.fwd_tcp_fin += 1;
                                    if telemetry.dbg.fwd_tcp_fin <= 5 {
                                        let flow_str = flow
                                            .as_ref()
                                            .map(|f| {
                                                format!(
                                                    "{}:{} -> {}:{}",
                                                    f.src_ip,
                                                    f.forward_key.src_port,
                                                    f.dst_ip,
                                                    f.forward_key.dst_port
                                                )
                                            })
                                            .unwrap_or_else(|| "no-flow".into());
                                        eprintln!(
                                            "FWD_TCP_FIN[{}]: ingress_if={} {} tcp_flags=0x{:02x}",
                                            telemetry.dbg.fwd_tcp_fin,
                                            meta.ingress_ifindex,
                                            flow_str,
                                            meta.tcp_flags,
                                        );
                                    }
                                }
                                // Detect zero-window in TCP frames by inspecting raw packet
                                if let Some(win) = raw_window {
                                    if win == 0 {
                                        telemetry.dbg.fwd_tcp_zero_window += 1;
                                        if telemetry.dbg.fwd_tcp_zero_window <= 10 {
                                            let flow_str = flow
                                                .as_ref()
                                                .map(|f| {
                                                    format!(
                                                        "{}:{} -> {}:{}",
                                                        f.src_ip,
                                                        f.forward_key.src_port,
                                                        f.dst_ip,
                                                        f.forward_key.dst_port
                                                    )
                                                })
                                                .unwrap_or_else(|| "no-flow".into());
                                            eprintln!(
                                                "FWD_TCP_ZERO_WIN[{}]: ingress_if={} {} meta_flags=0x{:02x} raw_flags={}",
                                                telemetry.dbg.fwd_tcp_zero_window,
                                                meta.ingress_ifindex,
                                                flow_str,
                                                meta.tcp_flags,
                                                raw_flags
                                                    .map(|f| format!("0x{:02x}", f))
                                                    .unwrap_or_else(|| "NONE".into()),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        if should_teardown_tcp_rst(meta, flow.as_ref())
                            && let Some(flow) = flow.as_ref()
                        {
                            binding
                                .scratch.scratch_rst_teardowns
                                .push((flow.forward_key.clone(), decision.nat));
                        }
                        telemetry.counters.forward_candidate_packets += 1;
                        if decision.nat.rewrite_src.is_some() {
                            telemetry.counters.snat_packets += 1;
                        }
                        if decision.nat.rewrite_dst.is_some() {
                            telemetry.counters.dnat_packets += 1;
                        }
                        if let Some(mut request) = build_live_forward_request_from_frame(
                            worker_ctx.binding_lookup,
                            binding_index,
                            &worker_ctx.ident,
                            desc,
                            packet_frame,
                            meta,
                            &decision,
                            worker_ctx.forwarding,
                            flow.as_ref(),
                            session_ingress_zone,
                            apply_nat_on_fabric,
                            now_ns,
                            worker_ctx.event_stream,
                            None,
                            None,
                        ) {
                            request.frame = owned_packet_frame
                                .take()
                                .map(PendingForwardFrame::Owned)
                                .unwrap_or(PendingForwardFrame::Live);
                            telemetry.dbg.tx += 1; // track forward requests queued
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.tx <= 5 {
                                    let dst_mac_str = decision
                                        .resolution
                                        .neighbor_mac
                                        .map(|m| {
                                            format!(
                                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                                m[0], m[1], m[2], m[3], m[4], m[5]
                                            )
                                        })
                                        .unwrap_or_else(|| "NONE".into());
                                    let src_mac_str = decision
                                        .resolution
                                        .src_mac
                                        .map(|m| {
                                            format!(
                                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                                m[0], m[1], m[2], m[3], m[4], m[5]
                                            )
                                        })
                                        .unwrap_or_else(|| "NONE".into());
                                    let flow_str = flow
                                        .as_ref()
                                        .map(|f| {
                                            format!(
                                                "{}:{} -> {}:{}",
                                                f.src_ip,
                                                f.forward_key.src_port,
                                                f.dst_ip,
                                                f.forward_key.dst_port
                                            )
                                        })
                                        .unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "DBG FWD_REQ: target_if={} egress_if={} tx_if={} len={} proto={} vlan={} dst_mac={} src_mac={} flow={}",
                                        request.target_ifindex,
                                        decision.resolution.egress_ifindex,
                                        decision.resolution.tx_ifindex,
                                        desc.len,
                                        meta.protocol,
                                        decision.resolution.tx_vlan_id,
                                        dst_mac_str,
                                        src_mac_str,
                                        flow_str,
                                    );
                                }
                            }
                            let request_target_binding_index = request.target_binding_index;
                            binding.scratch.scratch_forwards.push(request);
                            recycle_now = false;
                            // ── Flow cache population ────────────────────
                            // Cache ForwardCandidate decisions for established
                            // TCP/UDP flows. Skip NAT64/NPTv6 (non-cacheable).
                            if let Some(flow) = flow.as_ref()
                                && let Some(entry) = FlowCacheEntry::from_forward_decision(
                                    flow,
                                    meta,
                                    validation,
                                    decision,
                                    flow_cache_owner_rg_id,
                                    session_ingress_zone,
                                    request_target_binding_index,
                                    evaluate_non_pbr_input_filter_log(
                                        worker_ctx.forwarding,
                                        Some(flow),
                                        meta,
                                        ingress_zone_override,
                                    )
                                    .map(|(log_match, _)| log_match),
                                    worker_ctx.forwarding,
                                    worker_ctx.ha_state,
                                    apply_nat_on_fabric,
                                    &worker_ctx.rg_epochs,
                                )
                            {
                                binding.flow.flow_cache.insert(entry);
                            }
                            // ── End flow cache population ────────────────
                        } else {
                            telemetry.dbg.build_fail += 1;
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.build_fail <= 3 {
                                    eprintln!(
                                        "DBG FWD_BUILD_NONE: egress_if={} tx_if={} neigh={:?} src_mac={:?} len={} proto={}",
                                        decision.resolution.egress_ifindex,
                                        decision.resolution.tx_ifindex,
                                        decision.resolution.neighbor_mac.map(|m| format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )),
                                        decision.resolution.src_mac.map(|m| format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )),
                                        desc.len,
                                        meta.protocol,
                                    );
                                }
                            }
                        }
                    } else {
                        // Debug: count non-forward dispositions
                        match decision.resolution.disposition {
                            ForwardingDisposition::LocalDelivery => {
                                telemetry.dbg.local += 1;
                                emit_lo0_filter_log(
                                    worker_ctx.forwarding,
                                    worker_ctx.event_stream,
                                    flow.as_ref(),
                                    meta,
                                    ingress_zone_override,
                                    now_ns,
                                );
                                // Reinject to slow-path TUN so the kernel
                                // processes host-bound traffic (NDP, ICMP echo,
                                // BGP, etc.).  The first packet creates a BPF
                                // session map entry so subsequent packets bypass
                                // userspace entirely.
                                maybe_reinject_slow_path(
                                    worker_ctx.ident,
                                    &binding.live,
                                    worker_ctx.slow_path.as_deref(),
                                    worker_ctx.local_tunnel_deliveries,
                                    unsafe { &*area },
                                    desc,
                                    meta,
                                    decision,
                                    worker_ctx.recent_exceptions,
                                    worker_ctx.forwarding,
                                );
                                recycle_now = true;
                            }
                            ForwardingDisposition::NoRoute => {
                                telemetry.dbg.no_route += 1;
                                if cfg!(feature = "debug-log") {
                                    if telemetry.dbg.no_route <= 3 {
                                        if let Some(flow) = flow.as_ref() {
                                            eprintln!(
                                                "DBG NO_ROUTE: {}:{} -> {}:{} proto={} ingress_if={}",
                                                flow.src_ip,
                                                flow.forward_key.src_port,
                                                flow.dst_ip,
                                                flow.forward_key.dst_port,
                                                meta.protocol,
                                                meta.ingress_ifindex,
                                            );
                                        }
                                    }
                                }
                            }
                            ForwardingDisposition::MissingNeighbor => {
                                telemetry.dbg.missing_neigh += 1;
                                // #919/#922: zero-allocation ID-native resolution.
                                let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                                    worker_ctx.forwarding,
                                    meta.ingress_ifindex as i32,
                                    ingress_zone_override,
                                    decision.resolution.egress_ifindex,
                                );
                                // Borrow zone names as &str (no clone) for the
                                // string-typed downstream NAT helpers.
                                let from_zone: &str = worker_ctx
                                    .forwarding
                                    .zone_id_to_name
                                    .get(&from_zone_id)
                                    .map(|s| s.as_str())
                                    .unwrap_or("");
                                let to_zone: &str = worker_ctx
                                    .forwarding
                                    .zone_id_to_name
                                    .get(&to_zone_id)
                                    .map(|s| s.as_str())
                                    .unwrap_or("");
                                // Send ARP/NDP solicitation via RAW socket (not XSK)
                                // so the reply goes through the kernel's normal RX
                                // path (cpumap_or_pass), bypassing XSK fill ring issues.
                                // Also reinject original packet to slow-path for kernel
                                // to forward once the neighbor is resolved.
                                // Trigger ARP/NDP resolution via kernel netlink.
                                // Adding an INCOMPLETE neighbor entry makes the
                                // kernel send its own ARP/NDP solicitation through
                                // the normal stack, which correctly handles VLAN
                                // tagging and TX offload. The netlink monitor then
                                // picks up the resolved entry instantly.
                                if let Some(next_hop) = decision.resolution.next_hop {
                                    // Only spawn ping if we don't already have a
                                    // pending probe for this (ifindex, hop).
                                    let already_probing = binding.pending_neigh.iter().any(|p| {
                                        p.decision.resolution.egress_ifindex
                                            == decision.resolution.egress_ifindex
                                            && p.decision.resolution.next_hop == Some(next_hop)
                                    });
                                    if !already_probing {
                                        let iface_name = worker_ctx.forwarding
                                            .ifindex_to_name
                                            .get(&decision.resolution.egress_ifindex)
                                            .cloned();
                                        if let Some(name) = iface_name {
                                            // Fast path: ICMP socket triggers kernel ARP
                                            // in microseconds (no fork/exec).
                                            trigger_kernel_arp_probe(&name, next_hop);
                                        }
                                    }
                                }
                                // Create the session NOW so the SYN-ACK (reverse
                                // direction) finds the forward NAT match and creates
                                // a reverse session. Without this, the SYN-ACK hits
                                // session miss → policy deny (no rule for WAN→LAN).
                                let mut pending_decision = decision;
                                if let Some(flow) = flow.as_ref() {
                                    if let PolicyAction::Permit = evaluate_policy_with_len(
                                        &worker_ctx.forwarding.policy,
                                        from_zone_id,
                                        to_zone_id,
                                        flow.src_ip,
                                        flow.dst_ip,
                                        flow.forward_key.protocol,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_port,
                                        desc.len as u64,
                                    ) {
                                        let nat_match_flow = flow.with_destination(
                                            pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
                                        );
                                        if pending_decision.nat.rewrite_dst.is_none() {
                                            match source_nat_decision_for_flow(
                                                worker_ctx.forwarding,
                                                &from_zone,
                                                &to_zone,
                                                pending_decision.resolution.egress_ifindex,
                                                &nat_match_flow,
                                            ) {
                                                Ok(snat_decision) => {
                                                    pending_decision.nat = snat_decision;
                                                }
                                                Err(failure) => {
                                                    record_source_nat_failure(
                                                        telemetry,
                                                        worker_ctx,
                                                        meta,
                                                        flow,
                                                        from_zone_id,
                                                        to_zone_id,
                                                        desc.len,
                                                        &failure,
                                                    );
                                                    binding.scratch.scratch_recycle.push(desc.addr);
                                                    continue;
                                                }
                                            }
                                        } else {
                                            match source_nat_decision_for_flow(
                                                worker_ctx.forwarding,
                                                &from_zone,
                                                &to_zone,
                                                pending_decision.resolution.egress_ifindex,
                                                &nat_match_flow,
                                            ) {
                                                Ok(snat_decision) => {
                                                    pending_decision.nat =
                                                        pending_decision.nat.merge(snat_decision);
                                                }
                                                Err(failure) => {
                                                    record_source_nat_failure(
                                                        telemetry,
                                                        worker_ctx,
                                                        meta,
                                                        flow,
                                                        from_zone_id,
                                                        to_zone_id,
                                                        desc.len,
                                                        &failure,
                                                    );
                                                    binding.scratch.scratch_recycle.push(desc.addr);
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                    let sess_meta = build_missing_neighbor_session_metadata(
                                        worker_ctx.forwarding,
                                        from_zone_id,
                                        to_zone_id,
                                        packet_fabric_ingress,
                                        pending_decision,
                                    );
                                    if sessions.install_with_protocol_with_origin(
                                        flow.forward_key.clone(),
                                        pending_decision,
                                        sess_meta.clone(),
                                        SessionOrigin::MissingNeighborSeed,
                                        now_ns,
                                        meta.protocol,
                                        meta.tcp_flags,
                                    ) {
                                        let entry = SyncedSessionEntry {
                                            key: flow.forward_key.clone(),
                                            decision: pending_decision,
                                            metadata: sess_meta,
                                            origin: SessionOrigin::MissingNeighborSeed,
                                            protocol: meta.protocol,
                                            tcp_flags: meta.tcp_flags,
                                        };
                                        publish_shared_session(
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
                                            &entry,
                                        );
                                        let _ = publish_session_map_entry_for_session(
                                            binding.bpf_maps.session_map_fd,
                                            &flow.forward_key,
                                            pending_decision,
                                            &entry.metadata,
                                        );
                                        publish_bpf_conntrack_entry(
                                            conntrack_v4_fd,
                                            conntrack_v6_fd,
                                            &flow.forward_key,
                                            pending_decision,
                                            &entry.metadata,
                                            &worker_ctx.forwarding.zone_name_to_id,
                                        );
                                        publish_dnat_table_entry(
                                            &worker_ctx.dnat_fds,
                                            &flow.forward_key,
                                            pending_decision.nat,
                                        );
                                        telemetry.counters.session_creates += 1;
                                    }
                                }
                                // Buffer the packet. The ICMP probe resolves ARP
                                // in ~1ms. The retry loop below re-forwards the
                                // buffered packet once the neighbor resolves via the
                                // netlink monitor. The session was already created
                                // above so the SYN-ACK reverse path works too.
                                // Total latency: ~2ms (ARP + netlink + retry).
                                //
                                // NOTE: we do NOT reinject to slow-path here because
                                // kernel ARP resolution via XDP_PASS breaks VLAN demux
                                // in zero-copy mode (mlx5). The ICMP probe + netlink
                                // monitor + buffer-retry path bypasses this issue.
                                if binding.pending_neigh.len() < MAX_PENDING_NEIGH {
                                    let pending_flow_key = flow
                                        .as_ref()
                                        .map(|flow| flow.forward_key.clone())
                                        .or_else(|| {
                                            parse_session_flow_from_meta(meta)
                                                .map(|flow| flow.forward_key)
                                        });
                                    binding.pending_neigh.push_back(PendingNeighPacket {
                                        addr: desc.addr,
                                        desc,
                                        meta,
                                        decision: pending_decision,
                                        flow_key: pending_flow_key,
                                        queued_ns: now_ns,
                                        probe_attempts: 0,
                                    });
                                    recycle_now = false;
                                }
                                if cfg!(feature = "debug-log") {
                                    if telemetry.dbg.missing_neigh <= 3 {
                                        if let Some(flow) = flow.as_ref() {
                                            eprintln!(
                                                "DBG MISS_NEIGH→{}: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
                                                "SOLICIT+SLOW",
                                                flow.src_ip,
                                                flow.forward_key.src_port,
                                                flow.dst_ip,
                                                flow.forward_key.dst_port,
                                                meta.protocol,
                                                pending_decision.resolution.egress_ifindex,
                                                pending_decision.resolution.next_hop,
                                            );
                                        }
                                    }
                                }
                            }
                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
                            _ => telemetry.dbg.disposition_other += 1,
                        }
                        record_forwarding_disposition(
                            &worker_ctx.ident,
                            DispositionCounters::Hot(telemetry.counters),
                            decision.resolution,
                            desc.len as u32,
                            Some(meta),
                            debug.as_ref(),
                            worker_ctx.recent_exceptions,
                            worker_ctx.last_resolution,
                            worker_ctx.forwarding,
                        );
                        maybe_reinject_slow_path_from_frame(
                            &worker_ctx.ident,
                            &binding.live,
                            worker_ctx.slow_path,
                            worker_ctx.local_tunnel_deliveries,
                            packet_frame,
                            meta,
                            decision,
                            worker_ctx.recent_exceptions,
                            "slow_path",
                            worker_ctx.forwarding,
                        );
                    }
                } else {
                    record_disposition(
                        &worker_ctx.ident,
                        &binding.live,
                        DispositionCounters::Hot(telemetry.counters),
                        disposition,
                        desc.len as u32,
                        Some(meta),
                        worker_ctx.recent_exceptions,
                        worker_ctx.forwarding,
                    );
                }
            } else {
                telemetry.dbg.metadata_err += 1;
                binding.live.metadata_errors.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    worker_ctx.recent_exceptions,
                    &worker_ctx.ident,
                    "metadata_parse",
                    desc.len as u32,
                    None,
                    None,
                    worker_ctx.forwarding,
                );
            }
            if recycle_now {
                binding.scratch.scratch_recycle.push(desc.addr);
            }
        }
        received.release();
        drop(received);
}

// #1128: per-descriptor RX-side bookkeeping lifted out of the inner
// loop in `poll_binding_process_descriptor`.
//
// The work here, in order, is:
//   1. prefetch the metadata header (96 bytes, two cache lines) and
//      the first 64 bytes of frame data into L1 (#909);
//   2. bump the unconditional per-binding counters that drive
//      `show interfaces` and the live status RPCs:
//      `telemetry.counters.{touched, rx_packets, rx_bytes}` and
//      `telemetry.dbg.{rx, rx_bytes_total, rx_max_frame}`;
//   3. for desc.len > 1514, bump `telemetry.dbg.rx_oversized` and
//      (only under `cfg!(feature = "debug-log")`) eprint up to 20
//      oversized-frame breadcrumbs;
//   4. under `cfg!(feature = "debug-log")` only: RX-side TCP flag
//      census (FIN / SYN+ACK / zero-window / RST), poison-
//      descriptor detection, and a per-binding first-10 frame dump.
//
// In release builds without `--features debug-log` every
// `cfg!(...)` branch in steps 3 and 4 collapses to false and LLVM
// eliminates the debug-only body, leaving just the prefetches plus
// the unconditional counter increments in step 2. That residue is
// small enough that LLVM will inline a single call site regardless
// of any annotation. `#[inline]` (not `#[inline(always)]`) is
// deliberate: with `--features debug-log` the body is ~200 LOC, and
// forcing inline of that into the hot loop would bloat L1-i in
// debug builds for no production gain. `#[inline]` lets the
// compiler honor the body-size heuristic, which inlines tight
// production builds and correctly declines on the bulky debug
// path. The goal is *source-level* separation of housekeeping
// noise from forwarding logic, per the modularity discipline in #1128.
#[inline]
fn record_rx_descriptor_telemetry(
    desc: XdpDesc,
    area: *const MmapArea,
    telemetry: &mut TelemetryContext,
    worker_ctx: &WorkerContext,
) {
    // Prefetch the userspace-dp metadata header (96 bytes) at
    // desc.addr - meta_len. try_parse_metadata reads this
    // first, on the magic/version/length compare; before this
    // prefetch landed, that compare consumed ~33 % of
    // poll_binding_process_descriptor self-time on a perf
    // profile under iperf3 -P 128 / 25 Gb/s shaper (#909).
    //
    // The metadata is exactly 96 bytes (UserspaceDpMeta has a
    // const-asserted size; first field is `magic`) and starts
    // 96 bytes before the frame. UMEM frames are 4096-byte
    // aligned with a 256-byte headroom, so desc.addr is
    // 64-byte aligned by construction; the 96 bytes therefore
    // straddle exactly two cache lines and we issue two
    // prefetches.
    #[cfg(target_arch = "x86_64")]
    {
        debug_assert!(
            desc.addr.is_multiple_of(64),
            "UMEM frame at desc.addr={} should be 64-byte aligned",
            desc.addr,
        );
        let meta_len = std::mem::size_of::<UserspaceDpMeta>();
        if (desc.addr as usize) >= meta_len {
            let meta_offset = (desc.addr as usize) - meta_len;
            if let Some(pf_meta) = unsafe { &*area }.slice(meta_offset, meta_len) {
                unsafe {
                    core::arch::x86_64::_mm_prefetch(
                        pf_meta.as_ptr() as *const i8,
                        core::arch::x86_64::_MM_HINT_T0,
                    );
                    core::arch::x86_64::_mm_prefetch(
                        pf_meta.as_ptr().add(64) as *const i8,
                        core::arch::x86_64::_MM_HINT_T0,
                    );
                }
            }
        }
    }

    // Prefetch frame data into L1 while processing telemetry.counters.
    // UMEM frames are cold (last touched by NIC DMA); this hides
    // ~100ns DRAM latency before metadata parse.
    #[cfg(target_arch = "x86_64")]
    if let Some(pf) = unsafe { &*area }.slice(desc.addr as usize, 64.min(desc.len as usize)) {
        unsafe {
            core::arch::x86_64::_mm_prefetch(
                pf.as_ptr() as *const i8,
                core::arch::x86_64::_MM_HINT_T0,
            );
        }
    }
    telemetry.counters.touched = true;
    telemetry.counters.rx_packets += 1;
    telemetry.counters.rx_bytes += desc.len as u64;
    telemetry.dbg.rx += 1;
    telemetry.dbg.rx_bytes_total += desc.len as u64;
    if desc.len > telemetry.dbg.rx_max_frame {
        telemetry.dbg.rx_max_frame = desc.len;
    }
    if desc.len > 1514 {
        telemetry.dbg.rx_oversized += 1;
        if cfg!(feature = "debug-log") {
            thread_local! {
                static OVERSIZED_RX_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
            }
            OVERSIZED_RX_LOG.with(|c| {
                let n = c.get();
                if n < 20 {
                    c.set(n + 1);
                    eprintln!(
                        "DBG OVERSIZED_RX[{}]: if={} q={} desc.len={} (exceeds ETH+MTU 1514)",
                        n, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len,
                    );
                }
            });
        }
    }
    // TCP flag detection on RX
    if cfg!(feature = "debug-log") {
        if desc.len >= 54 {
            if let Some(rx_frame) = unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
            {
                // Check for FIN, SYN+ACK, zero-window
                if let Some(tcp_info) = extract_tcp_flags_and_window(rx_frame) {
                    if (tcp_info.0 & 0x01) != 0 {
                        // FIN
                        telemetry.dbg.rx_tcp_fin += 1;
                    }
                    if (tcp_info.0 & 0x12) == 0x12 {
                        // SYN+ACK
                        telemetry.dbg.rx_tcp_synack += 1;
                    }
                    if tcp_info.1 == 0 && (tcp_info.0 & 0x02) == 0 {
                        // zero window, not SYN
                        telemetry.dbg.rx_tcp_zero_window += 1;
                        if telemetry.dbg.rx_tcp_zero_window <= 10 {
                            eprintln!(
                                "RX_TCP_ZERO_WIN[{}]: if={} q={} len={} flags=0x{:02x}",
                                telemetry.dbg.rx_tcp_zero_window,
                                worker_ctx.ident.ifindex,
                                worker_ctx.ident.queue_id,
                                desc.len,
                                tcp_info.0,
                            );
                        }
                    }
                }
                if frame_has_tcp_rst(rx_frame) {
                    telemetry.dbg.rx_tcp_rst += 1;
                    thread_local! {
                        static RX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                    }
                    RX_RST_LOG_COUNT.with(|c| {
                        let n = c.get();
                        if n < 50 {
                            c.set(n + 1);
                            let summary = decode_frame_summary(rx_frame);
                            eprintln!(
                                "RST_DETECT RX[{}]: if={} q={} len={} {}",
                                n, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len, summary,
                            );
                            if n < 5 {
                                let hex_len = (desc.len as usize).min(rx_frame.len()).min(80);
                                let hex: String = rx_frame[..hex_len]
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                eprintln!("RST_DETECT RX_HEX[{n}]: {hex}");
                            }
                        }
                    });
                }
            }
        }
    }
    // Poison check: detect if kernel recycled descriptor without writing data
    if cfg!(feature = "debug-log") {
        if desc.len >= 8 {
            if let Some(first8) = unsafe { &*area }.slice(desc.addr as usize, 8) {
                if first8 == &0xDEAD_BEEF_DEAD_BEEFu64.to_ne_bytes() {
                    eprintln!(
                        "DBG POISON_DETECTED: if={} q={} desc.addr={:#x} desc.len={} — kernel returned poisoned frame!",
                        worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.addr, desc.len,
                    );
                }
            }
        }
    }
    if cfg!(feature = "debug-log") {
        if telemetry.dbg.rx <= 10 {
            if let Some(rx_frame) = unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
            {
                // Decode IP+TCP details from the frame
                let pkt_detail = decode_frame_summary(rx_frame);
                eprintln!(
                    "DBG RX_ETH[{}]: if={} q={} len={} {}",
                    telemetry.dbg.rx, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len, pkt_detail,
                );
                // Full hex dump for first 3 packets
                if telemetry.dbg.rx <= 3 {
                    let dump_len = (desc.len as usize).min(rx_frame.len()).min(80);
                    let hex: String = rx_frame[..dump_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("DBG RX_HEX[{}]: {}", telemetry.dbg.rx, hex);
                }
            }
        }
    }
}
