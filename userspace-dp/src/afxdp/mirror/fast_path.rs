use super::*;

/// #15114: put a mirror clone on the OUTPUT unit's VLAN, not the ingress one.
/// The clone is transmitted on the analyzer parent binding
/// (`resolve_tx_binding_ifindex(output_ifindex)`), so its outer 802.1Q tag
/// must carry `forwarding.egress_tx_vlan_id(output_ifindex)` — the same VID
/// the forward-path frame builder stamps for that egress. VID 0 (untagged
/// or native-VLAN output) strips any ingress tag; a tagged output rewrites
/// the VID of an existing single tag (preserving PCP/DEI) or pushes one onto
/// an untagged frame. Returns `None` for a frame too short to hold the L2
/// header the rewrite needs — the caller drops it (`NoFrame`) rather than
/// emitting it on the wrong VLAN.
fn mirror_output_frame<'a>(
    forwarding: &ForwardingState,
    output_ifindex: i32,
    frame: &'a [u8],
) -> Option<std::borrow::Cow<'a, [u8]>> {
    use crate::afxdp::ethernet::{ETHERTYPE_VLAN, ETHERTYPE_VLAN_8021AD};
    let target_vid = forwarding.egress_tx_vlan_id(output_ifindex) & 0x0fff;
    if frame.len() < 14 {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let tagged = matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_VLAN_8021AD);
    if tagged && frame.len() < 18 {
        return None;
    }
    // A tag push must splice before a real Ethernet payload; frames that do
    // not parse as IPv4/IPv6/ARP after any single tag are refused rather than
    // mutated into the output VLAN. VID rewrites, strips, and the
    // untagged-to-untagged copy-the-sample case relocate no payload bytes
    // and are untouched.
    if target_vid > 0 && !tagged && !matches!(ether_type, 0x0800 | 0x86dd | 0x0806) {
        return None;
    }
    match (tagged, target_vid) {
        (false, 0) => Some(std::borrow::Cow::Borrowed(frame)),
        (true, 0) => {
            let mut out = Vec::with_capacity(frame.len() - 4);
            out.extend_from_slice(&frame[..12]);
            out.extend_from_slice(&frame[16..]);
            Some(std::borrow::Cow::Owned(out))
        }
        (true, vid) => {
            let mut out = frame.to_vec();
            out[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
            let tci = (u16::from_be_bytes([out[14], out[15]]) & 0xf000) | vid;
            out[14..16].copy_from_slice(&tci.to_be_bytes());
            Some(std::borrow::Cow::Owned(out))
        }
        (false, vid) => {
            let mut out = Vec::with_capacity(frame.len() + 4);
            out.extend_from_slice(&frame[..12]);
            out.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
            out.extend_from_slice(&vid.to_be_bytes());
            out.extend_from_slice(&frame[12..]);
            Some(std::borrow::Cow::Owned(out))
        }
    }
}

/// A mirror sample selected from the original frame but not yet committed to
/// the analyzer queue. The sample counter is committed only after the primary
/// forward is queued; bytes are copied only when that forward rewrites in place.
pub(in crate::afxdp) struct StagedMirrorClone {
    config: MirrorRuntimeConfig,
    next_sample_counter: u64,
    selected: bool,
    frame: Option<Vec<u8>>,
    frame_len: usize,
    meta: ForwardPacketMeta,
    flow_key: Option<SessionKey>,
}

pub(in crate::afxdp) fn stage_sampled_mirror_clone(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    sample_counter: u64,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
) -> Option<StagedMirrorClone> {
    let config = resolve_mirror_config(forwarding, ingress_ifindex, ingress_vlan_id)?;
    let mut next_sample_counter = sample_counter;
    let selected = mirror_sample_allows(config.rate, &mut next_sample_counter);
    Some(StagedMirrorClone {
        config,
        next_sample_counter,
        selected,
        frame: None,
        frame_len: frame.len(),
        meta,
        flow_key: if selected { flow_key.cloned() } else { None },
    })
}

pub(in crate::afxdp) fn snapshot_staged_mirror_clone(staged: &mut StagedMirrorClone, frame: &[u8]) {
    if staged.selected && frame.len() <= tx_frame_capacity() {
        staged.frame = Some(frame.to_vec());
    }
}

pub(in crate::afxdp) fn commit_staged_mirror_clone(
    left: &mut [BindingWorker],
    ingress_index: usize,
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    forwarding: &ForwardingState,
    ingress_queue_id: u32,
    staged: StagedMirrorClone,
    original_frame: &[u8],
    now_ns: u64,
) {
    ingress_binding.mirror_sample_counter = staged.next_sample_counter;
    if !staged.selected {
        return;
    }
    let frame = staged.frame.as_deref().unwrap_or(original_frame);
    let result = if frame.len() <= tx_frame_capacity() {
        enqueue_mirror_clone(
            left,
            ingress_index,
            ingress_binding,
            right,
            binding_lookup,
            mirror_targets,
            forwarding,
            staged.config,
            ingress_queue_id,
            frame,
            staged.meta,
            staged.flow_key.as_ref(),
            now_ns,
        )
    } else {
        MirrorCloneResult::NoFrame
    };
    record_mirror_clone_result(&ingress_binding.live, result, staged.frame_len);
}

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
    now_ns: u64,
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
            forwarding,
            config,
            mirror_tx_ifindex,
            ingress_queue_id,
            frame,
            meta,
            flow_key,
            cos_queue_id,
            now_ns,
        );
    };

    enqueue_mirror_clone_to_binding(
        target_binding,
        forwarding,
        config,
        frame,
        meta,
        flow_key,
        cos_queue_id,
        now_ns,
    )
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
    now_ns: u64,
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
            forwarding,
            config,
            frame,
            meta,
            flow_key,
            cos_queue_id,
            now_ns,
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
        if mirror_output_filter_drops(
            forwarding,
            config.output_ifindex,
            frame,
            meta,
            flow_key,
            now_ns,
        ) {
            return Some(MirrorCloneResult::OutputFiltered);
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
            forwarding,
            config,
            frame.to_vec(),
            meta,
            flow_key,
            cos_queue_id,
            now_ns,
        ));
    }
}

fn enqueue_mirror_clone_to_binding(
    target_binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    config: MirrorRuntimeConfig,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
    cos_queue_id: Option<u8>,
    now_ns: u64,
) -> MirrorCloneResult {
    if mirror_output_filter_drops(
        forwarding,
        config.output_ifindex,
        frame,
        meta,
        flow_key,
        now_ns,
    ) {
        return MirrorCloneResult::OutputFiltered;
    }
    if frame.len() > tx_frame_capacity() {
        return MirrorCloneResult::NoFrame;
    }
    // #15114: rewrite/push/strip the outer tag to the output unit's VID
    // before the clone is copied into the analyzer binding's UMEM.
    let Some(out_frame) = mirror_output_frame(forwarding, config.output_ifindex, frame) else {
        return MirrorCloneResult::NoFrame;
    };
    let frame = out_frame.as_ref();
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
    forwarding: &ForwardingState,
    config: MirrorRuntimeConfig,
    mirror_tx_ifindex: i32,
    ingress_queue_id: u32,
    frame: &[u8],
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
    cos_queue_id: Option<u8>,
    now_ns: u64,
) -> MirrorCloneResult {
    if mirror_output_filter_drops(
        forwarding,
        config.output_ifindex,
        frame,
        meta,
        flow_key,
        now_ns,
    ) {
        return MirrorCloneResult::OutputFiltered;
    }
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
        forwarding,
        config,
        frame.to_vec(),
        meta,
        flow_key,
        cos_queue_id,
        now_ns,
    )
}

pub(in crate::afxdp) fn enqueue_admitted_mirror_clone_to_live(
    admission: PendingTxAdmission,
    forwarding: &ForwardingState,
    config: MirrorRuntimeConfig,
    frame: Vec<u8>,
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
    cos_queue_id: Option<u8>,
    now_ns: u64,
) -> MirrorCloneResult {
    // #15114: rewrite/push/strip the outer tag to the output unit's VID.
    let Some(out_frame) = mirror_output_frame(forwarding, config.output_ifindex, &frame) else {
        return MirrorCloneResult::NoFrame;
    };
    let frame = out_frame.into_owned();
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
    now_ns: u64,
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
    if mirror_output_filter_drops(
        forwarding,
        config.output_ifindex,
        frame,
        meta,
        flow_key,
        now_ns,
    ) {
        record_mirror_clone_result(live, MirrorCloneResult::OutputFiltered, frame.len());
        return Some(MirrorCloneResult::OutputFiltered);
    }
    let cos_queue_id = mirror_cos_queue_id(forwarding, config.output_ifindex, meta, flow_key);
    let result = enqueue_admitted_mirror_clone_to_live(
        admission,
        forwarding,
        config,
        frame.to_vec(),
        meta,
        flow_key,
        cos_queue_id,
        now_ns,
    );
    record_mirror_clone_result(live, result, frame.len());
    Some(result)
}
