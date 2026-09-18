use super::*;

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn enqueue_mirror_clone(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    forwarding: &ForwardingState,
    config: MirrorRuntimeConfig,
    ingress_queue_id: u32,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
) -> MirrorCloneResult {
    let mirror_tx_ifindex = resolve_tx_binding_ifindex(forwarding, config.output_ifindex);
    let target_binding_index = mirror_target_binding_index(
        binding_lookup,
        ingress_index,
        ingress_binding.ifindex,
        ingress_queue_id,
        mirror_tx_ifindex,
    );
    let cos_queue_id = mirror_cos_queue_id(forwarding, config.output_ifindex, meta, flow_key);
    let Some(target_binding) = target_binding_index
        .and_then(|idx| binding_by_index_mut(left, ingress_index, ingress_binding, right, idx))
    else {
        return enqueue_mirror_clone_to_live(
            mirror_targets,
            config,
            mirror_tx_ifindex,
            ingress_queue_id,
            frame,
            meta,
            flow_key,
            cos_queue_id,
        );
    };

    enqueue_mirror_clone_to_binding(target_binding, config, frame, meta, flow_key, cos_queue_id)
}

pub(in crate::afxdp) fn enqueue_sampled_mirror_clone(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    ingress_queue_id: u32,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
) -> Option<MirrorCloneResult> {
    let config = resolve_mirror_config(forwarding, ingress_ifindex, ingress_vlan_id)?;
    let mirror_tx_ifindex = resolve_tx_binding_ifindex(forwarding, config.output_ifindex);
    let target_binding_index = mirror_target_binding_index(
        binding_lookup,
        ingress_index,
        ingress_binding.ifindex,
        ingress_queue_id,
        mirror_tx_ifindex,
    );
    let cos_queue_id = mirror_cos_queue_id(forwarding, config.output_ifindex, meta, flow_key);
    if let Some(target_binding_index) = target_binding_index {
        if !mirror_sample_allows(config.rate, &mut ingress_binding.mirror_sample_counter) {
            return None;
        }
        let Some(target_binding) = binding_by_index_mut(
            left,
            ingress_index,
            ingress_binding,
            right,
            target_binding_index,
        ) else {
            return Some(MirrorCloneResult::NoBinding);
        };
        return Some(enqueue_mirror_clone_to_binding(
            target_binding,
            config,
            frame,
            meta,
            flow_key,
            cos_queue_id,
        ));
    } else {
        // #5167: run the worker-local sampler FIRST, mirroring the same-worker
        // branch above. A non-sampled packet must NOT reserve the contended
        // cross-worker clone queue: `admit_mirror_clone_to_live` performs the
        // true-shared AcqRel CAS on the target's `pending_tx_admitted` (#4096).
        // Reserving BEFORE sampling made acknowledged cross-core true-sharing
        // scale with the FULL unsampled ingress rate O(PPS) instead of the
        // sample rate O(PPS/R), so sampling could not bound clone cost. With
        // sample-first, only a SELECTED packet reserves, copies, or reports
        // clone-queue pressure; a non-sampled packet returns `None` having
        // touched nothing shared.
        if !mirror_sample_allows(config.rate, &mut ingress_binding.mirror_sample_counter) {
            return None;
        }
        let admission = match admit_mirror_clone_to_live(
            mirror_targets,
            mirror_tx_ifindex,
            ingress_queue_id,
            frame.len(),
        ) {
            Ok(admission) => admission,
            Err(result) => return Some(result),
        };
        return Some(enqueue_admitted_mirror_clone_to_live(
            admission,
            config,
            frame.to_vec(),
            meta,
            flow_key,
            cos_queue_id,
        ));
    }
}

fn enqueue_mirror_clone_to_binding(
    target_binding: &mut BindingWorker,
    config: MirrorRuntimeConfig,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
    cos_queue_id: Option<u8>,
) -> MirrorCloneResult {
    if frame.len() > tx_frame_capacity() {
        return MirrorCloneResult::NoFrame;
    }
    let pending_mirror_pressure = target_binding
        .tx_pipeline
        .pending_tx_prepared
        .len()
        .saturating_add(target_binding.tx_pipeline.pending_tx_local.len());
    if pending_mirror_pressure >= MIRROR_PENDING_LIMIT {
        return MirrorCloneResult::QueueFullSameWorker;
    }
    if target_binding.tx_pipeline.free_tx_frames.len() <= MIRROR_TX_FRAME_RESERVE {
        return MirrorCloneResult::TxFrameReserve;
    }
    let Some(tx_offset) = target_binding.tx_pipeline.free_tx_frames.pop_front() else {
        return MirrorCloneResult::TxFrameReserve;
    };
    let Some(out) = (unsafe {
        target_binding
            .umem
            .area()
            .slice_mut_unchecked(tx_offset as usize, frame.len())
    }) else {
        target_binding
            .tx_pipeline
            .free_tx_frames
            .push_front(tx_offset);
        return MirrorCloneResult::NoFrame;
    };
    out.copy_from_slice(frame);
    target_binding
        .tx_pipeline
        .pending_tx_prepared
        .push_back(PreparedTxRequest {
            offset: tx_offset,
            len: frame.len() as u32,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: meta.addr_family,
            expected_protocol: meta.protocol,
            flow_key: flow_key.cloned(),
            egress_ifindex: config.output_ifindex,
            cos_queue_id,
            dscp_rewrite: None,
            mirror_clone: true,
            overlap_admissions: None,
            enqueue_ns: 0,
        });
    MirrorCloneResult::Enqueued
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn enqueue_mirror_clone_to_live(
    mirror_targets: &MirrorTargetMap,
    config: MirrorRuntimeConfig,
    mirror_tx_ifindex: i32,
    ingress_queue_id: u32,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
    cos_queue_id: Option<u8>,
) -> MirrorCloneResult {
    let admission = match admit_mirror_clone_to_live(
        mirror_targets,
        mirror_tx_ifindex,
        ingress_queue_id,
        frame.len(),
    ) {
        Ok(admission) => admission,
        Err(result) => return result,
    };
    enqueue_admitted_mirror_clone_to_live(
        admission,
        config,
        frame.to_vec(),
        meta,
        flow_key,
        cos_queue_id,
    )
}

pub(in crate::afxdp) fn enqueue_admitted_mirror_clone_to_live(
    admission: PendingTxAdmission,
    config: MirrorRuntimeConfig,
    frame: Vec<u8>,
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
    cos_queue_id: Option<u8>,
) -> MirrorCloneResult {
    if frame.len() > tx_frame_capacity() {
        return MirrorCloneResult::NoFrame;
    }
    let req = TxRequest {
        bytes: frame,
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: flow_key.cloned(),
        egress_ifindex: config.output_ifindex,
        cos_queue_id,
        dscp_rewrite: None,
        mirror_clone: true,
        overlap_admissions: None,
        enqueue_ns: 0,
    };
    admission
        .enqueue_owned(req)
        .map(|_| MirrorCloneResult::Enqueued)
        .unwrap_or(MirrorCloneResult::QueueFullCrossWorker)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn enqueue_sampled_mirror_clone_to_live(
    live: &BindingLiveState,
    mirror_targets: &MirrorTargetMap,
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    ingress_queue_id: u32,
    sample_counter: &mut u64,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
) -> Option<MirrorCloneResult> {
    let config = resolve_mirror_config(forwarding, ingress_ifindex, ingress_vlan_id)?;
    // #6114: sample BEFORE reserving the contended cross-worker clone queue
    // (see `sample_then_admit_mirror_clone`). A non-sampled packet returns
    // `None` having touched nothing shared — no reservation, no copy, no
    // clone-queue pressure report.
    let admission = match sample_then_admit_mirror_clone(
        config.rate,
        sample_counter,
        mirror_targets,
        resolve_tx_binding_ifindex(forwarding, config.output_ifindex),
        ingress_queue_id,
        frame.len(),
    ) {
        MirrorSampleAdmission::NotSampled => return None,
        MirrorSampleAdmission::Sampled(Ok(admission)) => admission,
        MirrorSampleAdmission::Sampled(Err(result)) => {
            record_mirror_clone_result(live, result, frame.len());
            return Some(result);
        }
    };
    let cos_queue_id = mirror_cos_queue_id(forwarding, config.output_ifindex, meta, flow_key);
    let result = enqueue_admitted_mirror_clone_to_live(
        admission,
        config,
        frame.to_vec(),
        meta,
        flow_key,
        cos_queue_id,
    );
    record_mirror_clone_result(live, result, frame.len());
    Some(result)
}
