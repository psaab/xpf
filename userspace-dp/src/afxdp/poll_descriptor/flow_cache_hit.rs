// #1327 Step 1: stage_flow_cache_hit extracted from the inline body
// of poll_binding_process_descriptor (formerly lines 563-894 of the
// flat poll_descriptor.rs). The flow-cache fast path is the single
// largest self-contained `continue`-terminated block in the function
// and the only stage that's cleanly liftable without touching the
// order-coupled stage-12+ slow path. See
// docs/pr/1327-poll-descriptor-stages/plan.md for the architectural
// verdict on remaining stages.
//
// #6433: the SEED (write) half of the cache contract now lives in the
// `flow_cache_seed.rs` sibling (`stage_flow_cache_seed`) — the #1861
// §5.4 refused-install gate, the #3048/#3918/#5147 pre-resolve
// shard-epoch stamp, and the #3073/#3322 policy-counter stamps review
// against this hit path as one contract.
//
// HOT PATH discipline:
//   - `#[inline(always)]` mandated by the plan (and by Codex
//     round-2 review). The 280-LOC body has a single call site;
//     LLVM produces the same IR as the original inline code. The
//     `cargo asm` spot-check in the test plan confirms no `call`
//     edge to this helper is emitted in optimised builds.
//   - Zero new per-packet allocations: every `cached_*` binding
//     is a borrow into the existing flow-cache Cache entry, never
//     a clone. The two heap interactions in the body are the
//     existing `owned_packet_frame.take()` and the
//     `PendingForwardRequest` build — both pre-existing.
//   - All `scratch_recycle.push` and `scratch_forwards.push`
//     sites run inside this helper. On `FlowCacheOutcome::Consumed`
//     the caller MUST `continue` without touching `desc.addr`
//     again.
//
// Recycle-exit map (verbatim translation of the original 3
// `continue` sites in the source):
//   - Drop path (cached descriptor `.drop` or policer `.drop`):
//     `scratch_recycle.push(desc.addr)` then `return Consumed`.
//   - TTL/hop-limit exceeded → local ICMP TE: `scratch_forwards.push(request)`
//     then `return Consumed` (frame returned via pending_fill_frames
//     later; MUST NOT recycle now — matches the original comment
//     at the line-653 site).
//   - Final fall-out: conditional `scratch_recycle.push(desc.addr)`
//     based on helper-local `recycle_now`, then `return Consumed`.

use std::sync::Arc;

use super::filter::{emit_cached_input_filter_log, emit_cached_output_filter_log};
use super::worker::{WorkerFlowCacheState, WorkerScratch, WorkerTxCounters, WorkerTxPipeline};
use super::*;

/// Outcome of the flow-cache fast-path stage.
///
/// The helper owns `desc.addr` disposition on `Consumed` — the
/// caller must `continue` without touching the descriptor.
///
/// On `FallThrough`, the helper performed no terminal side effect
/// (it may have invalidated a stale cache slot, but it did not
/// push to `scratch_recycle` or `scratch_forwards`); the caller
/// continues to the slow-path session resolution code with
/// `owned_packet_frame` and the descriptor untouched.
pub(super) enum FlowCacheOutcome {
    /// Cache hit. Helper performed any necessary
    /// `scratch_recycle.push` / `scratch_forwards.push`. Caller
    /// MUST `continue` without touching `desc.addr` again.
    Consumed,
    /// Cache miss or HA-invalid cached slot. Caller falls through
    /// to slow-path session resolution.
    FallThrough,
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_flow_cache_hit(
    flow_state: &mut WorkerFlowCacheState,
    tx_pipeline: &mut WorkerTxPipeline,
    tx_counters: &mut WorkerTxCounters,
    scratch: &mut WorkerScratch,
    mirror_sample_counter: &mut u64,
    live: &Arc<BindingLiveState>,
    binding_slot: u32,
    binding_index: usize,
    desc: XdpDesc,
    area: *const MmapArea,
    raw_frame: &[u8],
    owned_packet_frame: &mut Option<Vec<u8>>,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    packet_fabric_ingress: bool,
    validation: ValidationState,
    sessions: &mut SessionTable,
    now_ns: u64,
    now_secs: u64,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
) -> FlowCacheOutcome {
    // Re-derive packet_frame locally (matches L477 of the caller's
    // pre-flow-cache code). The shared borrow lives only inside
    // this helper; NLL releases it before the take() at the
    // fallback-forward branch.
    let packet_frame: &[u8] = owned_packet_frame.as_deref().unwrap_or(raw_frame);

    if let Some(cached) = flow_state.flow_cache.lookup_counted(
        &flow.forward_key,
        // #5139: resolve the LOGICAL (VLAN-selecting) ingress ifindex into the
        // lookup identity so co-parented VLANs don't alias — `worker_ctx.
        // forwarding` carries the (physical, vlan) → logical map.
        FlowCacheLookup::for_packet(meta, validation, worker_ctx.forwarding),
        now_secs,
        &worker_ctx.rg_epochs,
        meta.pkt_len,
    ) {
        // #3048/#5147: a kernel ARP/NDP update may have REPLACED this
        // descriptor's next-hop MAC since it was cached (gateway VRRP
        // failover, NIC swap). The neighbor map advances the epoch of the
        // changed neighbor's SHARD only on a genuine MAC change — never on a
        // same-MAC refresh — so this comparison is free of steady-state
        // re-misses, and a MAC change to a neighbor in a DIFFERENT shard does
        // NOT evict this flow (the #5147 map-wide-thrash fix). The check reads
        // only this flow's own shard slot: a single indexed relaxed atomic
        // load + compare. A mismatch means the cached dst_mac may be stale;
        // evict and re-resolve on the slow path.
        let neighbor_mac_stale = cached.neighbor_mac_epoch_stale(worker_ctx.dynamic_neighbors);
        if neighbor_mac_stale
            || !cached_flow_decision_valid(
                worker_ctx.forwarding,
                worker_ctx.ha_state,
                worker_ctx.dynamic_neighbors,
                now_secs,
                cached.stamp.owner_rg_id,
                packet_fabric_ingress,
                resolution_target_for_session(flow, cached.decision),
                cached.decision.resolution,
            )
        {
            flow_state
                .flow_cache
                .invalidate_slot(&flow.forward_key, meta.ingress_ifindex as i32);
            // Fall through to slow path for full HA resolution / re-resolve
            // the current neighbor MAC (#3048) / fabric redirect.
            return FlowCacheOutcome::FallThrough;
        }
        let cached_decision = cached.decision;
        let cached_descriptor = &cached.descriptor;
        let cached_metadata = &cached.metadata;
        // #3779: TTL/hop-limit check BEFORE any egress side effect. The slow
        // paths (session-hit `poll_descriptor/mod.rs`, session-miss) test TTL
        // before egress accounting, but the cache-hit path used to run the
        // output `then count` replay, the policy hit counter, the three-color
        // policers, the filter logs, AND the terminal drop FIRST — so a TTL=1
        // packet on a red-policer or terminal-output-drop cached flow was
        // dropped/charged without ever emitting ICMP Time Exceeded, and every
        // would-expire packet charged counters/logs/telemetry for traffic that
        // never egressed. Hoist it: for a forward disposition a would-expire
        // packet becomes a Time Exceeded reply, or — when TE is suppressed
        // (ICMP-of-ICMP, rate limited, or an output-filter drop of the reply) —
        // is dropped, in BOTH cases before any egress counter/policer/log moves.
        // Non-expiring packets fall straight through (Some(false)) with no
        // behavior change. A TTL-expired hit returns Consumed here BEFORE the
        // session accounting further down (sessions.account_packet /
        // touch_if_stale): an expired packet is never egressed, so it must not
        // charge session byte/packet counters or refresh the idle timer —
        // matching the slow path, which also drops before accounting.
        if matches!(
            cached_decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
        ) && matches!(packet_ttl_would_expire(packet_frame, meta), Some(true))
        {
            // #5140: the TTL/hop-limit test + the embedded original in the
            // generated Time Exceeded read the INNER packet via `packet_frame`
            // (decapped frame post native-GRE, else `raw_frame`); `meta.l3_offset`
            // is inner-relative after `stage_native_gre_decap`, so the outer
            // `raw_frame` would test the wrong TTL byte. `desc` is still passed to
            // recycle the outer UMEM slot (the reply is a freshly built frame).
            if let Some(request) = build_local_time_exceeded_request(
                packet_frame,
                desc,
                meta,
                &worker_ctx.ident,
                flow,
                worker_ctx.forwarding,
                worker_ctx.dynamic_neighbors,
                worker_ctx.ha_state,
                now_secs,
                telemetry.counters,
            ) {
                scratch.scratch_forwards.push(request);
                // Don't recycle — enqueue_pending_forwards returns the frame via
                // pending_fill_frames when processing the prebuilt TE response.
                return FlowCacheOutcome::Consumed;
            }
            // TTL expired but Time Exceeded suppressed: the packet cannot be
            // forwarded (the rewrite path rejects TTL<=1) and must NOT charge
            // egress counters/policers/logs — drop it here.
            scratch.scratch_recycle.push(desc.addr);
            return FlowCacheOutcome::Consumed;
        }
        // #2573: replay ALL matched `then count` term counters, not just the
        // last. A #2544 fall-through flow can match multiple count terms.
        cached_descriptor
            .tx_selection
            .filter_counters
            .for_each(|counter| {
                crate::filter::record_filter_counter(counter, meta.pkt_len as u64);
            });
        // #3777: replay the interface INPUT filter `then count` handles too.
        // The output/TX side above replayed on every hit since #2573, but the
        // input side captured only a log descriptor — so an input `then count`
        // reported only the seed packet of an N-packet cacheable flow. The
        // routing-instance (PBR) count is excluded at capture time (owned by the
        // routing evaluator), so this cannot double-count a mixed filter.
        cached_descriptor
            .input_filter_counters
            .for_each(|counter| {
                crate::filter::record_filter_counter(counter, meta.pkt_len as u64);
            });
        // #3073: re-count this cached established-session packet against the
        // admitting policy's hit counter, mirroring the `then count` filter
        // replay above. This is the hot path for long-lived flows (most
        // packets of a permitted flow are served from the flow cache), so
        // without it `show security policies hit-count` would still show only
        // the first frame. Counted before the policer/drop checks below to
        // match the cold-path "count at policy match" semantics. The
        // per-worker coalescer keeps it off the shared counter cacheline.
        // #3322: prefer the cached entry's reorder-stable bound handle over
        // the positional idx so a live policy reorder cannot re-attribute this
        // cached flow's packets to a different rule.
        if let Some(counter) = worker_ctx.forwarding.policy.resolve_session_hit_counter(
            cached_metadata.policy_counter.as_ref(),
            cached_metadata.policy_counter_idx,
        ) {
            crate::policy::record_policy_hit_counter(counter, meta.pkt_len as u64);
        }
        let policer_action = crate::filter::apply_cached_three_color_policers(
            &cached_descriptor.tx_selection.three_color_policers,
            now_ns,
            meta.pkt_len as u64,
        );
        emit_cached_input_filter_log(
            worker_ctx.forwarding,
            worker_ctx.event_stream,
            flow,
            meta,
            cached_descriptor,
            now_ns,
        );
        // #3608: an output firewall-filter `then reject` cached on this flow now
        // emits the same active reply (TCP RST / ICMP admin-prohibited) the
        // input/lo0 path already produces (#2521) rather than the historical
        // silent drop. Only the `then reject` subset synthesizes; `then discard`
        // and a red three-color policer stay silent. Enqueue the reply FIRST so
        // the cached output filter-log below reports the TRUTHFUL action (#3615)
        // — a reject whose reply fail-closes logs DENY, not REJECT.
        let output_reject_reply_enqueued = if cached_descriptor.tx_selection.reject {
            super::reject_reply::enqueue_filter_reject_reply(
                tx_pipeline,
                worker_ctx.forwarding,
                worker_ctx.ident.ifindex,
                packet_frame,
                meta,
                flow,
                telemetry.counters,
            )
        } else {
            false
        };
        emit_cached_output_filter_log(
            worker_ctx.forwarding,
            worker_ctx.event_stream,
            flow,
            meta,
            cached_decision,
            cached_descriptor,
            cached_metadata,
            output_reject_reply_enqueued,
            now_ns,
        );
        if cached_descriptor.tx_selection.drop || policer_action.drop {
            scratch.scratch_recycle.push(desc.addr);
            return FlowCacheOutcome::Consumed;
        }
        // #3778: behavior-aggregate (DSCP / 802.1p PCP) classifiers are
        // per-packet in vSRX, but the cached queue was frozen from the SEED
        // packet's DSCP/PCP (the flow-cache key excludes both). When the seed
        // marked this descriptor `ba_reclassify` (a BA classifier is active and
        // no filter forwarding-class pinned the queue), re-resolve THIS packet's
        // queue from its own DSCP/PCP so a mixed-marking flow is not pinned to
        // the first packet's queue. Otherwise the frozen queue is correct.
        let cached_queue_id = if cached_descriptor.tx_selection.ba_reclassify {
            reclassify_cached_ba_queue(
                worker_ctx.forwarding,
                cached_decision.resolution.egress_ifindex,
                meta.dscp,
                meta.ingress_pcp,
                meta.ingress_vlan_present != 0,
            )
            .or(cached_descriptor.tx_selection.queue_id)
        } else {
            cached_descriptor.tx_selection.queue_id
        };
        let cached_dscp_rewrite = policer_action
            .dscp_rewrite
            .or(cached_descriptor.tx_selection.dscp_rewrite);
        // #2220: per-session keepalive. Refresh THIS session's
        // last_seen_ns when it is a quarter of the way to its own
        // expiry. The prior binding-GLOBAL modulo-64 counter touched
        // only the flow that happened to land on a global multiple of
        // 64, so a low-rate flow co-resident with a saturating flow
        // could be served entirely from the cache and reaped mid-flow.
        sessions.touch_if_stale(&flow.forward_key, now_ns);
        // #2501: account this forwarded packet against the session. The packet
        // is keyed by its OWN tuple (`flow.forward_key`); `account_packet`
        // derives the direction from the resolved entry and folds both
        // directions onto the canonical forward entry. HOT PATH: one
        // `key_to_handle` probe (warm — `touch_if_stale` just probed the same
        // key) + a `saturating_add`. Allocation-free, no atomic (worker-owned
        // table).
        // #2749: also observe the packet's TCP control bits + DSCP so the
        // SESSION_CLOSE RT_FLOW frame carries real NetFlow/IPFIX
        // class-of-service / TCP-flags values.
        sessions.account_packet(
            &flow.forward_key,
            meta.pkt_len as u64,
            meta.tcp_flags,
            meta.dscp,
        );
        let mut recycle_now = true;
        if matches!(
            cached_decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
        ) {
            // #3779: the TTL/hop-limit check (and any ICMP Time Exceeded) was
            // hoisted ABOVE the egress side effects earlier in this function, so
            // a packet reaching here has a live TTL. No TTL test remains on the
            // forward fast path.
            telemetry.counters.forward_candidate_packets += 1;
            // #3651: per-zone traffic volume for this forwarded packet — two
            // flat-LUT reads (ingress zone from the shim meta, egress zone from
            // the resolved egress ifindex) into the per-worker thread-local
            // coalescer, folded into the shared store per RX batch.
            crate::afxdp::zone_counters::record_zone_traffic(
                &worker_ctx.forwarding.zone_counter_slot_map,
                meta.ingress_zone,
                worker_ctx
                    .forwarding
                    .egress_zone_id(cached_decision.resolution.egress_ifindex),
                meta.pkt_len as u64,
            );
            if cached_decision.nat.rewrite_src.is_some() {
                telemetry.counters.snat_packets += 1;
            }
            if cached_decision.nat.rewrite_dst.is_some() {
                telemetry.counters.dnat_packets += 1;
            }
            // ── Inline in-place rewrite fast path ──
            // Skip PendingForwardRequest + enqueue_pending_forwards entirely.
            // Resolve target binding, rewrite frame in UMEM, push PreparedTxRequest.
            let target_ifindex = if cached_decision.resolution.tx_ifindex > 0 {
                cached_decision.resolution.tx_ifindex
            } else {
                resolve_tx_binding_ifindex(
                    worker_ctx.forwarding,
                    cached_decision.resolution.egress_ifindex,
                )
            };
            let expected_ports = authoritative_forward_ports(packet_frame, meta, Some(flow));
            let target_bi = cached_descriptor.target_binding_index.or_else(|| {
                if cached_decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                    worker_ctx.binding_lookup.fabric_target_index(
                        target_ifindex,
                        // #2357: a flow-cache hit is a real established
                        // session (never a flowless fragment), so the
                        // non-first-fragment gate is `false` here.
                        fabric_queue_hash(Some(flow), expected_ports, meta, false),
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
                let ingress_slot = binding_slot;
                let flow_key = flow.forward_key.clone();
                let mirror_config = resolve_mirror_config(
                    worker_ctx.forwarding,
                    meta.ingress_ifindex as i32,
                    meta.ingress_vlan_id,
                );
                let mut mirror_next_counter = None;
                let mut mirror_admission = mirror_config.and_then(|config| {
                    // #6114: sample BEFORE reserving the contended cross-worker
                    // clone queue on this established-flow HOT path. Reserving
                    // first (`admit_mirror_clone_to_live`, a true-shared AcqRel
                    // CAS on the target's `pending_tx_admitted`, #4096) made
                    // every established-flow packet hit the shared cacheline
                    // even when it would not be sampled — O(PPS) cross-core
                    // true-sharing instead of the sample rate O(PPS/R). A LOCAL
                    // counter copy defers the commit: `mirror_next_counter` is
                    // applied to `*mirror_sample_counter` only if the in-place
                    // rewrite below succeeds (the fallback path re-runs mirror
                    // selection), preserving today's "no fast-path advance on
                    // rewrite miss" behavior.
                    let mut next_counter = *mirror_sample_counter;
                    let admission = sample_then_admit_mirror_clone(
                        config.rate,
                        &mut next_counter,
                        worker_ctx.mirror_targets,
                        resolve_tx_binding_ifindex(
                            worker_ctx.forwarding,
                            config.output_ifindex,
                        ),
                        worker_ctx.ident.queue_id,
                        packet_frame.len(),
                    );
                    mirror_next_counter = Some(next_counter);
                    match admission {
                        MirrorSampleAdmission::NotSampled => None,
                        MirrorSampleAdmission::Sampled(result) => Some((config, result)),
                    }
                });
                let mirror_frame_len = packet_frame.len();
                let mut mirror_frame = mirror_admission
                    .as_ref()
                    .and_then(|(_, admission)| admission.as_ref().ok())
                    .map(|_| packet_frame.to_vec());
                // Try descriptor-based straight-line rewrite first (no branches
                // for AF, NAT type, or checksum recomputation). Falls back to
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
                        *mirror_sample_counter = next_counter;
                    }
                    if let Some((mirror_config, admission)) = mirror_admission.take() {
                        let result = match admission {
                            Ok(admission) => {
                                if let Some(mirror_frame) = mirror_frame.take() {
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
                        record_mirror_clone_result(live, result, mirror_frame_len);
                    }
                    tx_pipeline.pending_tx_prepared.push_back(PreparedTxRequest {
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
                        egress_ifindex: cached_decision.resolution.egress_ifindex,
                        cos_queue_id: cached_queue_id,
                        dscp_rewrite: cached_dscp_rewrite,
                        mirror_clone: false,
                        enqueue_ns: 0,
                    });
                    tx_counters.pending_in_place_tx_packets += 1;
                    tx_counters.record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
                    telemetry.dbg.forward += 1;
                    telemetry.dbg.tx += 1;
                    recycle_now = false;
                }
            }
            // Fallback: use PendingForwardRequest path for cross-binding or failure.
            if recycle_now {
                let cached_precomputed_tx_selection = CachedTxSelectionDescriptor {
                    queue_id: cached_queue_id,
                    dscp_rewrite: cached_dscp_rewrite,
                    drop: cached_descriptor.tx_selection.drop,
                    ..CachedTxSelectionDescriptor::default()
                };
                if let Some(mut request) = build_live_forward_request_from_frame(
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
                    // #3608: no reject reply here — this fallback runs only for a
                    // NON-dropped cached flow (the `then reject`/`then discard`
                    // drop already returned above at the cached-drop check), so
                    // the precomputed selection is never a reject.
                    None,
                    // #5606: mirror the cached session's NAT64 reverse info onto
                    // the request. Always `None` here — NAT64 flows are excluded
                    // from the flow cache by `FlowCacheEntry::should_cache` (a
                    // version-changing translation cannot use the in-place
                    // byte-rewrite fast path), so a NAT64 reply never reaches
                    // this fast path — but threading it keeps the invariant
                    // "request.nat64_reverse mirrors its driving session
                    // metadata" holding uniformly across every builder call.
                    cached_metadata.nat64_reverse,
                ) {
                    request.frame = owned_packet_frame
                        .take()
                        .map(PendingForwardFrame::Owned)
                        .unwrap_or(PendingForwardFrame::Live);
                    telemetry.dbg.forward += 1;
                    telemetry.dbg.tx += 1;
                    scratch.scratch_forwards.push(request);
                    recycle_now = false;
                }
            }
        }
        if recycle_now {
            scratch.scratch_recycle.push(desc.addr);
        }
        return FlowCacheOutcome::Consumed;
    }
    FlowCacheOutcome::FallThrough
}

// #6304: bind the LIVE mirror call site above. The #6114 tests drive the same
// sample-before-CAS invariant through the DEAD
// `enqueue_sampled_mirror_clone_to_live` wrapper via the shared
// `sample_then_admit_mirror_clone`, so reverting ONLY this call site left the
// suite green. These tests drive `stage_flow_cache_hit` itself.
#[cfg(test)]
#[path = "flow_cache_hit_tests.rs"]
mod flow_cache_hit_tests;
