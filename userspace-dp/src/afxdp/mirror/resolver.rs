use super::*;

// #1986: was a module-private `fn` in the monolithic mirror.rs; widened to
// `pub(super)` so the fast path (now in `fast_path.rs`) can still reach it
// across the new module boundary. `#[inline]` preserves the same-module
// inlining the fast path relied on before the split.
#[inline]
pub(super) fn mirror_target_binding_index(
    binding_lookup: &WorkerBindingLookup,
    ingress_index: usize,
    ingress_ifindex: i32,
    ingress_queue_id: u32,
    mirror_tx_ifindex: i32,
) -> Option<usize> {
    if ingress_ifindex == mirror_tx_ifindex {
        return Some(ingress_index);
    }
    binding_lookup
        .by_if_queue
        .get(&(mirror_tx_ifindex, ingress_queue_id))
        .copied()
        .or_else(|| {
            let indices = binding_lookup.all_by_if.get(&mirror_tx_ifindex)?;
            (indices.len() == 1).then_some(indices[0])
        })
}

// #1986: `#[inline]` added so the fast path's admission check keeps inlining
// after the cross-module split (it was fully inlined when colocated in
// mirror.rs); visibility is unchanged from the monolith.
#[inline]
pub(in crate::afxdp) fn admit_mirror_clone_to_live(
    mirror_targets: &MirrorTargetMap,
    mirror_tx_ifindex: i32,
    ingress_queue_id: u32,
    frame_len: usize,
) -> Result<PendingTxAdmission, MirrorCloneResult> {
    if frame_len > tx_frame_capacity() {
        return Err(MirrorCloneResult::NoFrame);
    }
    let Some(target_live) = mirror_targets.target_live(mirror_tx_ifindex, ingress_queue_id) else {
        return Err(MirrorCloneResult::NoBinding);
    };
    BindingLiveState::try_reserve_mirror_tx_owned(&target_live, MIRROR_PENDING_LIMIT)
        .map_err(|_| MirrorCloneResult::QueueFullCrossWorker)
}

/// Outcome of the mirror sample-then-admit decision (#6114). Splitting the
/// worker-local sampler from the cross-worker reservation lets a caller run the
/// cheap sampler FIRST and only touch the contended clone queue for a packet
/// that is actually selected.
pub(in crate::afxdp) enum MirrorSampleAdmission {
    /// The worker-local sampler declined this packet. Nothing shared was
    /// touched: no reservation, no copy, no clone-queue pressure report.
    NotSampled,
    /// The packet was selected. Carries the reservation outcome: `Ok` holds a
    /// reserved live clone-queue slot, `Err` reports why admission failed
    /// (e.g. `QueueFullCrossWorker`).
    Sampled(Result<PendingTxAdmission, MirrorCloneResult>),
}

// #6114 / #5167: run the worker-local sampler BEFORE reserving the contended
// cross-worker clone queue. `admit_mirror_clone_to_live` performs a true-shared
// AcqRel CAS on the target's `pending_tx_admitted` (#4096), and dropping an
// unused reservation costs a second AcqRel RMW (the `PendingTxAdmission` Drop
// release). Reserving BEFORE sampling made acknowledged cross-core true-sharing
// scale with the FULL unsampled ingress rate O(PPS) instead of the sample rate
// O(PPS/R), so sampling could not bound clone cost. Sample-first: a non-sampled
// packet advances only the worker-local `sample_counter` and returns
// `NotSampled` having touched nothing shared. This is the single home for the
// ordering invariant shared by the established-flow HOT path
// (`poll_descriptor/flow_cache_hit.rs`) and `enqueue_sampled_mirror_clone_to_live`.
#[inline]
pub(in crate::afxdp) fn sample_then_admit_mirror_clone(
    rate: u32,
    sample_counter: &mut u64,
    mirror_targets: &MirrorTargetMap,
    mirror_tx_ifindex: i32,
    ingress_queue_id: u32,
    frame_len: usize,
) -> MirrorSampleAdmission {
    if !mirror_sample_allows(rate, sample_counter) {
        return MirrorSampleAdmission::NotSampled;
    }
    MirrorSampleAdmission::Sampled(admit_mirror_clone_to_live(
        mirror_targets,
        mirror_tx_ifindex,
        ingress_queue_id,
        frame_len,
    ))
}

/// #8367: the mirror/span path consumes a QUEUE and nothing else, so it asks
/// for one. It used to build the whole cached TX-selection descriptor and read
/// `.queue_id` off it, which meant that for a FLOWLESS clone (`flow_key ==
/// None`) it was the one production caller reaching an arm that evaluated the
/// egress output filter against the ingress PRE-NAT tuple — populating `.drop`,
/// `.reject` and `.filter_log` with a verdict it then threw away. This path has
/// no `NatDecision` to synthesize a post-NAT tuple from, and threading one
/// through the mirror path to populate fields the mirror path discards would be
/// a poor trade; `resolve_cached_cos_tx_queue_id` returns the identical queue
/// (behavior-aggregate classification is 5-tuple independent) and leaves the
/// filter verdict to callers that can supply the tuple it must be computed on.
#[inline]
pub(in crate::afxdp) fn mirror_cos_queue_id(
    forwarding: &ForwardingState,
    output_ifindex: i32,
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
) -> Option<u8> {
    resolve_cached_cos_tx_queue_id(forwarding, output_ifindex, meta.into(), flow_key)
}


/// Evaluate the output filter on the analyzer unit for the exact mirror-copy
/// tuple. Unlike the original forwarded frame, this clone has no rewrite
/// decision: its filter tuple is the frame being copied, so use the available
/// flow key (the original packet tuple) or the flowless L3 tuple and derive all
/// per-packet match inputs from the clone bytes.
#[inline]
pub(in crate::afxdp) fn mirror_output_filter_drops(
    forwarding: &ForwardingState,
    output_ifindex: i32,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
    now_ns: u64,
) -> bool {
    let Some((is_v6, src_ip, dst_ip, protocol, src_port, dst_port)) = flow_key
        .map(|key| {
            (
                key.addr_family as i32 == libc::AF_INET6,
                key.src_ip,
                key.dst_ip,
                key.protocol,
                key.src_port,
                key.dst_port,
            )
        })
        .or_else(|| match meta.addr_family as i32 {
            libc::AF_INET => meta.l3_addrs_unfiltered().map(|(src, dst)| {
                (
                    false,
                    src,
                    dst,
                    meta.protocol,
                    meta.flow_src_port,
                    meta.flow_dst_port,
                )
            }),
            libc::AF_INET6 => meta.l3_addrs_unfiltered().map(|(src, dst)| {
                (
                    true,
                    src,
                    dst,
                    meta.protocol,
                    meta.flow_src_port,
                    meta.flow_dst_port,
                )
            }),
            _ => None,
        })
    else {
        return false;
    };
    let Some(output_filter) = crate::filter::interface_output_filter_needing_tx_eval(
        &forwarding.filter_state,
        output_ifindex,
        is_v6,
    ) else {
        return false;
    };

    let mut extra = crate::afxdp::frame::term_match_extra_from_frame(frame, meta);
    if flow_key.is_none() {
        // A flowless mirror has no authoritative transport tuple. Do not let
        // zero-substituted ports match a port-constrained output term.
        extra.ports_unknown = true;
    }
    let result = crate::filter::evaluate_filter_ref_tx_selection_runtime_counted(
        output_filter,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        meta.dscp,
        extra,
        meta.pkt_len as u64,
        now_ns,
    );
    result.policer_drop || result.action != crate::filter::FilterAction::Accept
}
#[inline]
pub(in crate::afxdp) fn record_mirror_clone_result(
    live: &BindingLiveState,
    result: MirrorCloneResult,
    frame_len: usize,
) {
    match result {
        MirrorCloneResult::Enqueued => {
            live.mirrored_packets.fetch_add(1, Ordering::Relaxed);
            live.mirrored_bytes
                .fetch_add(frame_len as u64, Ordering::Relaxed);
        }
        MirrorCloneResult::NoBinding => {
            live.mirror_drops_no_binding.fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::NoFrame => {
            live.mirror_drops_no_frame.fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::TxFrameReserve => {
            live.mirror_drops_tx_frame_reserve
                .fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::QueueFullSameWorker => {
            live.mirror_drops_queue_full.fetch_add(1, Ordering::Relaxed);
            live.mirror_drops_queue_full_same_worker
                .fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::QueueFullCrossWorker => {
            live.mirror_drops_queue_full.fetch_add(1, Ordering::Relaxed);
            live.mirror_drops_queue_full_cross_worker
                .fetch_add(1, Ordering::Relaxed);
        }
        MirrorCloneResult::OutputFiltered => {
            // Policy-denied analyzer copies are not congestion or resource
            // failures; keep the lossy-pressure counters semantically precise.
        }
    }
}
