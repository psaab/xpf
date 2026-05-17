use super::*;

const MIRROR_TX_FRAME_RESERVE: usize = TX_BATCH_SIZE;
const MIRROR_PENDING_LIMIT: usize = TX_BATCH_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum MirrorCloneResult {
    Enqueued,
    NoBinding,
    NoFrame,
    QueueFull,
}

#[inline]
pub(in crate::afxdp) fn select_mirror_config(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    sample_counter: &mut u64,
) -> Option<MirrorRuntimeConfig> {
    let config = resolve_mirror_config(forwarding, ingress_ifindex, ingress_vlan_id)?;
    mirror_sample_allows(config.rate, sample_counter).then_some(config)
}

#[inline]
pub(in crate::afxdp) fn resolve_mirror_config(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> Option<MirrorRuntimeConfig> {
    let logical_ifindex =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
            .filter(|ifindex| *ifindex > 0)
            .unwrap_or(ingress_ifindex);
    forwarding
        .mirror_configs
        .get(&logical_ifindex)
        .or_else(|| forwarding.mirror_configs.get(&ingress_ifindex))
        .copied()
}

#[inline]
pub(in crate::afxdp) fn mirror_sample_allows(rate: u32, sample_counter: &mut u64) -> bool {
    if rate <= 1 {
        return true;
    }
    let current = *sample_counter;
    *sample_counter = sample_counter.wrapping_add(1);
    let rate = u64::from(rate);
    if rate.is_power_of_two() {
        current & (rate - 1) == 0
    } else {
        current % rate == 0
    }
}

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

    if frame.len() > tx_frame_capacity() {
        return MirrorCloneResult::NoFrame;
    }
    let pending_mirror_pressure = target_binding
        .tx_pipeline
        .pending_tx_prepared
        .len()
        .saturating_add(target_binding.tx_pipeline.pending_tx_local.len());
    if pending_mirror_pressure >= MIRROR_PENDING_LIMIT {
        return MirrorCloneResult::QueueFull;
    }
    if target_binding.tx_pipeline.free_tx_frames.len() <= MIRROR_TX_FRAME_RESERVE {
        return MirrorCloneResult::NoFrame;
    }
    let Some(tx_offset) = target_binding.tx_pipeline.free_tx_frames.pop_front() else {
        return MirrorCloneResult::NoFrame;
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
        });
    MirrorCloneResult::Enqueued
}

fn mirror_target_binding_index(
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
    let target_live = match admit_mirror_clone_to_live(
        mirror_targets,
        mirror_tx_ifindex,
        ingress_queue_id,
        frame.len(),
    ) {
        Ok(target_live) => target_live,
        Err(result) => return result,
    };
    enqueue_admitted_mirror_clone_to_live(
        &target_live,
        config,
        frame.to_vec(),
        meta,
        flow_key,
        cos_queue_id,
    )
}

pub(in crate::afxdp) fn admit_mirror_clone_to_live(
    mirror_targets: &MirrorTargetMap,
    mirror_tx_ifindex: i32,
    ingress_queue_id: u32,
    frame_len: usize,
) -> Result<Arc<BindingLiveState>, MirrorCloneResult> {
    if frame_len > tx_frame_capacity() {
        return Err(MirrorCloneResult::NoFrame);
    }
    let Some(target_live) = mirror_targets.target_live(mirror_tx_ifindex, ingress_queue_id)
    else {
        return Err(MirrorCloneResult::NoBinding);
    };
    if target_live.try_admit_tx_owned().is_err() {
        return Err(MirrorCloneResult::QueueFull);
    }
    Ok(target_live)
}

pub(in crate::afxdp) fn enqueue_admitted_mirror_clone_to_live(
    target_live: &BindingLiveState,
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
    };
    target_live
        .try_enqueue_tx_owned(req)
        .map(|_| MirrorCloneResult::Enqueued)
        .unwrap_or(MirrorCloneResult::QueueFull)
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
    let config =
        select_mirror_config(forwarding, ingress_ifindex, ingress_vlan_id, sample_counter)?;
    let cos_queue_id = mirror_cos_queue_id(forwarding, config.output_ifindex, meta, flow_key);
    let result = enqueue_mirror_clone_to_live(
        mirror_targets,
        config,
        resolve_tx_binding_ifindex(forwarding, config.output_ifindex),
        ingress_queue_id,
        frame,
        meta,
        flow_key,
        cos_queue_id,
    );
    record_mirror_clone_result(live, result, frame.len());
    Some(result)
}

#[inline]
pub(in crate::afxdp) fn mirror_cos_queue_id(
    forwarding: &ForwardingState,
    output_ifindex: i32,
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
) -> Option<u8> {
    resolve_cached_cos_tx_selection(forwarding, output_ifindex, meta.into(), flow_key).queue_id
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
        MirrorCloneResult::QueueFull => {
            live.mirror_drops_queue_full.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MirrorConfigSnapshot;

    fn test_meta() -> ForwardPacketMeta {
        ForwardPacketMeta {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..ForwardPacketMeta::default()
        }
    }

    fn test_cos_interface(default_queue: u8) -> CoSInterfaceConfig {
        CoSInterfaceConfig {
            shaping_rate_bytes: 1_250_000,
            burst_bytes: 64 * 1024,
            default_queue,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: Vec::new(),
        }
    }

    #[test]
    fn sampling_rate_correctness() {
        let mut counter = 0;
        for _ in 0..8 {
            assert!(mirror_sample_allows(0, &mut counter));
            assert!(mirror_sample_allows(1, &mut counter));
        }
        assert_eq!(counter, 0, "mirror-all rates must not advance sampler");

        let mut counter = 0;
        let samples: Vec<bool> = (0..8)
            .map(|_| mirror_sample_allows(4, &mut counter))
            .collect();
        assert_eq!(
            samples,
            vec![true, false, false, false, true, false, false, false]
        );

        let mut counter = 0;
        let samples: Vec<bool> = (0..7)
            .map(|_| mirror_sample_allows(3, &mut counter))
            .collect();
        assert_eq!(samples, vec![true, false, false, true, false, false, true]);
    }

    #[test]
    fn select_mirror_config_prefers_vlan_logical_ifindex() {
        let mut forwarding = ForwardingState::default();
        forwarding.ingress_logical_ifindex.insert((6, 80), 20080);
        forwarding.mirror_configs.insert(
            20080,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
        );
        let mut counter = 0;

        assert_eq!(
            select_mirror_config(&forwarding, 6, 80, &mut counter),
            Some(MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0
            })
        );
    }

    #[test]
    fn select_mirror_config_falls_back_to_parent_ifindex() {
        let mut forwarding = ForwardingState::default();
        forwarding.ingress_logical_ifindex.insert((6, 80), 20080);
        forwarding.mirror_configs.insert(
            6,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
        );
        let mut counter = 0;

        assert_eq!(
            select_mirror_config(&forwarding, 6, 80, &mut counter),
            Some(MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0
            })
        );
    }

    #[test]
    fn cross_binding_inject_preserves_full_frame() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let forwarding = ForwardingState::default();
        let mirror_targets = MirrorTargetMap::default();
        let (left, rest) = bindings.split_at_mut(0);
        let (ingress, right) = rest.split_first_mut().expect("ingress binding");
        let frame: Vec<u8> = (0..96).map(|v| v as u8).collect();

        let result = enqueue_mirror_clone(
            left,
            0,
            ingress,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            0,
            &frame,
            test_meta(),
            None,
        );
        assert_eq!(result, MirrorCloneResult::Enqueued);
        let target = &bindings[1];
        assert_eq!(target.tx_pipeline.pending_tx_prepared.len(), 1);
        let req = target
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("mirror prepared request");
        assert_eq!(req.len, frame.len() as u32);
        assert_eq!(req.egress_ifindex, 22);
        assert_eq!(
            target
                .umem
                .area()
                .slice(req.offset as usize, req.len as usize)
                .expect("mirror frame"),
            frame.as_slice()
        );
    }

    #[test]
    fn cross_worker_live_enqueue_preserves_full_frame() {
        let mut ingress = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
        let bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let forwarding = ForwardingState::default();
        let target_live = Arc::new(BindingLiveState::new());
        let mut mirror_targets = MirrorTargetMap::default();
        mirror_targets.insert(
            &BindingIdentity {
                slot: 9,
                queue_id: 3,
                worker_id: 1,
                interface: Arc::<str>::from("mirror-out"),
                ifindex: 22,
            },
            target_live.clone(),
        );
        let frame: Vec<u8> = (0..96).map(|v| 255u8.wrapping_sub(v as u8)).collect();

        let result = enqueue_mirror_clone(
            &mut [],
            0,
            &mut ingress,
            &mut [],
            &lookup,
            &mirror_targets,
            &forwarding,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            3,
            &frame,
            test_meta(),
            None,
        );

        assert_eq!(result, MirrorCloneResult::Enqueued);
        let mut queued = VecDeque::new();
        target_live.take_pending_tx_into(&mut queued);
        let req = queued.pop_front().expect("cross-worker mirror tx");
        assert_eq!(req.bytes, frame);
        assert_eq!(req.egress_ifindex, 22);
    }

    #[test]
    fn cross_binding_mirror_requires_exact_queue_when_output_is_multiqueue() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 3),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
            BindingWorker::new_for_mirror_test(2, 0, 22, 1),
        ];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let forwarding = ForwardingState::default();
        let mirror_targets = MirrorTargetMap::default();
        let (left, rest) = bindings.split_at_mut(0);
        let (ingress, right) = rest.split_first_mut().expect("ingress binding");

        let result = enqueue_mirror_clone(
            left,
            0,
            ingress,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            3,
            &[0x5a; 64],
            test_meta(),
            None,
        );

        assert_eq!(result, MirrorCloneResult::NoBinding);
        assert!(bindings[1].tx_pipeline.pending_tx_prepared.is_empty());
        assert!(bindings[2].tx_pipeline.pending_tx_prepared.is_empty());
    }

    #[test]
    fn live_mirror_requires_exact_queue_when_output_is_multiqueue() {
        let target_q0 = Arc::new(BindingLiveState::new());
        let target_q1 = Arc::new(BindingLiveState::new());
        let mut mirror_targets = MirrorTargetMap::default();
        for (queue_id, live) in [(0, target_q0.clone()), (1, target_q1.clone())] {
            mirror_targets.insert(
                &BindingIdentity {
                    slot: queue_id + 10,
                    queue_id,
                    worker_id: 1,
                    interface: Arc::<str>::from("mirror-out"),
                    ifindex: 22,
                },
                live,
            );
        }

        let result = enqueue_mirror_clone_to_live(
            &mirror_targets,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            22,
            3,
            &[0x6b; 64],
            test_meta(),
            None,
            None,
        );

        assert_eq!(result, MirrorCloneResult::NoBinding);
        let mut queued = VecDeque::new();
        target_q0.take_pending_tx_into(&mut queued);
        target_q1.take_pending_tx_into(&mut queued);
        assert!(queued.is_empty());
    }

    #[test]
    fn live_mirror_queue_full_drops_before_enqueue() {
        let target_live = Arc::new(BindingLiveState::new());
        target_live.set_max_pending_tx(1);
        assert!(
            target_live
                .try_enqueue_tx_owned(TxRequest {
                    bytes: vec![0x11; 64],
                    expected_ports: None,
                    expected_addr_family: libc::AF_INET as u8,
                    expected_protocol: PROTO_TCP,
                    flow_key: None,
                    egress_ifindex: 22,
                    cos_queue_id: None,
                    dscp_rewrite: None,
                })
                .is_ok()
        );
        let mut mirror_targets = MirrorTargetMap::default();
        mirror_targets.insert(
            &BindingIdentity {
                slot: 9,
                queue_id: 0,
                worker_id: 1,
                interface: Arc::<str>::from("mirror-out"),
                ifindex: 22,
            },
            target_live.clone(),
        );

        let result = enqueue_mirror_clone_to_live(
            &mirror_targets,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            22,
            0,
            &[0x22; 64],
            test_meta(),
            None,
            None,
        );

        assert_eq!(result, MirrorCloneResult::QueueFull);
        let mut queued = VecDeque::new();
        target_live.take_pending_tx_into(&mut queued);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued.pop_front().expect("original request").bytes, vec![0x11; 64]);
    }

    #[test]
    fn mirror_live_enqueue_uses_output_cos_default_queue_without_rewrite() {
        let mut ingress = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
        let bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mut forwarding = ForwardingState::default();
        forwarding.cos.interfaces.insert(22, test_cos_interface(7));
        let target_live = Arc::new(BindingLiveState::new());
        let mut mirror_targets = MirrorTargetMap::default();
        mirror_targets.insert(
            &BindingIdentity {
                slot: 9,
                queue_id: 0,
                worker_id: 1,
                interface: Arc::<str>::from("mirror-out"),
                ifindex: 22,
            },
            target_live.clone(),
        );

        let result = enqueue_mirror_clone(
            &mut [],
            0,
            &mut ingress,
            &mut [],
            &lookup,
            &mirror_targets,
            &forwarding,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            0,
            &[0xdd; 64],
            test_meta(),
            None,
        );

        assert_eq!(result, MirrorCloneResult::Enqueued);
        let mut queued = VecDeque::new();
        target_live.take_pending_tx_into(&mut queued);
        let req = queued.pop_front().expect("mirror tx");
        assert_eq!(req.cos_queue_id, Some(7));
        assert_eq!(req.dscp_rewrite, None);
    }

    #[test]
    fn sampled_live_mirror_enqueue_records_flow_cache_surface() {
        let ingress_live = BindingLiveState::new();
        let target_live = Arc::new(BindingLiveState::new());
        let mut mirror_targets = MirrorTargetMap::default();
        mirror_targets.insert(
            &BindingIdentity {
                slot: 9,
                queue_id: 0,
                worker_id: 1,
                interface: Arc::<str>::from("mirror-out"),
                ifindex: 22,
            },
            target_live.clone(),
        );
        let mut forwarding = ForwardingState::default();
        forwarding.mirror_configs.insert(
            11,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
        );
        let mut sample_counter = 0;
        let frame = vec![0x44; 80];

        let result = enqueue_sampled_mirror_clone_to_live(
            &ingress_live,
            &mirror_targets,
            &forwarding,
            11,
            0,
            0,
            &mut sample_counter,
            &frame,
            test_meta(),
            None,
        );

        assert_eq!(result, Some(MirrorCloneResult::Enqueued));
        assert_eq!(ingress_live.mirrored_packets.load(Ordering::Relaxed), 1);
        assert_eq!(
            ingress_live.mirrored_bytes.load(Ordering::Relaxed),
            frame.len() as u64
        );
        let mut queued = VecDeque::new();
        target_live.take_pending_tx_into(&mut queued);
        assert_eq!(queued.pop_front().expect("mirror tx").bytes, frame);
    }

    #[test]
    fn sampled_live_mirror_sampler_denial_does_not_enqueue() {
        let ingress_live = BindingLiveState::new();
        let target_live = Arc::new(BindingLiveState::new());
        let mut mirror_targets = MirrorTargetMap::default();
        mirror_targets.insert(
            &BindingIdentity {
                slot: 9,
                queue_id: 0,
                worker_id: 1,
                interface: Arc::<str>::from("mirror-out"),
                ifindex: 22,
            },
            target_live.clone(),
        );
        let mut forwarding = ForwardingState::default();
        forwarding.mirror_configs.insert(
            11,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 4,
            },
        );
        let mut sample_counter = 1;

        let result = enqueue_sampled_mirror_clone_to_live(
            &ingress_live,
            &mirror_targets,
            &forwarding,
            11,
            0,
            0,
            &mut sample_counter,
            &[0x44; 80],
            test_meta(),
            None,
        );

        assert_eq!(result, None);
        assert_eq!(sample_counter, 2);
        assert_eq!(ingress_live.mirrored_packets.load(Ordering::Relaxed), 0);
        let mut queued = VecDeque::new();
        target_live.take_pending_tx_into(&mut queued);
        assert!(queued.is_empty());
    }

    #[test]
    fn mirror_output_logical_ifindex_resolves_parent_binding() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            200,
            EgressInterface {
                bind_ifindex: 22,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0; 6],
                zone_id: 1,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );
        let mirror_targets = MirrorTargetMap::default();
        let (left, rest) = bindings.split_at_mut(0);
        let (ingress, right) = rest.split_first_mut().expect("ingress binding");
        let frame: Vec<u8> = (0..96).map(|v| v as u8).collect();

        let result = enqueue_mirror_clone(
            left,
            0,
            ingress,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            MirrorRuntimeConfig {
                output_ifindex: 200,
                rate: 0,
            },
            0,
            &frame,
            test_meta(),
            None,
        );
        assert_eq!(result, MirrorCloneResult::Enqueued);
        let target = &bindings[1];
        let req = target
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("mirror prepared request");
        assert_eq!(req.egress_ifindex, 200);
    }

    #[test]
    fn sampled_live_mirror_resolves_snapshot_logical_ingress_and_output() {
        let ingress_live = BindingLiveState::new();
        let target_live = Arc::new(BindingLiveState::new());
        let mut mirror_targets = MirrorTargetMap::default();
        mirror_targets.insert(
            &BindingIdentity {
                slot: 9,
                queue_id: 0,
                worker_id: 1,
                interface: Arc::<str>::from("mirror-out"),
                ifindex: 22,
            },
            target_live.clone(),
        );
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    ifindex: 6,
                    parent_ifindex: 0,
                    vlan_id: 0,
                    ..InterfaceSnapshot::default()
                },
                InterfaceSnapshot {
                    ifindex: 20080,
                    parent_ifindex: 6,
                    vlan_id: 80,
                    ..InterfaceSnapshot::default()
                },
                InterfaceSnapshot {
                    ifindex: 22,
                    parent_ifindex: 0,
                    vlan_id: 0,
                    hardware_addr: "02:00:00:00:00:16".to_string(),
                    ..InterfaceSnapshot::default()
                },
                InterfaceSnapshot {
                    ifindex: 200,
                    parent_ifindex: 22,
                    vlan_id: 90,
                    ..InterfaceSnapshot::default()
                },
            ],
            mirror_configs: vec![MirrorConfigSnapshot {
                ingress_ifindex: 20080,
                output_ifindex: 200,
                rate: 0,
            }],
            ..ConfigSnapshot::default()
        };
        let forwarding = build_forwarding_state(&snapshot);
        let mut sample_counter = 0;
        let frame = vec![0x88; 80];

        let result = enqueue_sampled_mirror_clone_to_live(
            &ingress_live,
            &mirror_targets,
            &forwarding,
            6,
            80,
            0,
            &mut sample_counter,
            &frame,
            test_meta(),
            None,
        );

        assert_eq!(result, Some(MirrorCloneResult::Enqueued));
        let mut queued = VecDeque::new();
        target_live.take_pending_tx_into(&mut queued);
        let req = queued.pop_front().expect("mirror tx");
        assert_eq!(req.egress_ifindex, 200);
        assert_eq!(req.bytes, frame);
    }

    #[test]
    fn missing_destination_binding_drop_counter() {
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
        let bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let forwarding = ForwardingState::default();
        let mirror_targets = MirrorTargetMap::default();
        let result = enqueue_mirror_clone(
            &mut [],
            0,
            &mut binding,
            &mut [],
            &lookup,
            &mirror_targets,
            &forwarding,
            MirrorRuntimeConfig {
                output_ifindex: 99,
                rate: 0,
            },
            0,
            &[0xaa; 64],
            test_meta(),
            None,
        );
        record_mirror_clone_result(&binding.live, result, 64);
        assert_eq!(result, MirrorCloneResult::NoBinding);
        assert_eq!(
            binding.live.mirror_drops_no_binding.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn out_of_frame_drops_increment_counter() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let forwarding = ForwardingState::default();
        let mirror_targets = MirrorTargetMap::default();
        bindings[1]
            .tx_pipeline
            .free_tx_frames
            .truncate(MIRROR_TX_FRAME_RESERVE);
        let (left, rest) = bindings.split_at_mut(0);
        let (ingress, right) = rest.split_first_mut().expect("ingress binding");
        let result = enqueue_mirror_clone(
            left,
            0,
            ingress,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            0,
            &[0xbb; 64],
            test_meta(),
            None,
        );
        record_mirror_clone_result(&ingress.live, result, 64);
        assert_eq!(result, MirrorCloneResult::NoFrame);
        assert_eq!(
            ingress.live.mirror_drops_no_frame.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn queue_full_drop_counter() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        for idx in 0..MIRROR_PENDING_LIMIT {
            bindings[1]
                .tx_pipeline
                .pending_tx_prepared
                .push_back(PreparedTxRequest {
                    offset: (idx as u64) << UMEM_FRAME_SHIFT,
                    len: 64,
                    recycle: PreparedTxRecycle::FreeTxFrame,
                    expected_ports: None,
                    expected_addr_family: 0,
                    expected_protocol: 0,
                    flow_key: None,
                    egress_ifindex: 22,
                    cos_queue_id: None,
                    dscp_rewrite: None,
                });
        }
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let forwarding = ForwardingState::default();
        let mirror_targets = MirrorTargetMap::default();
        let (left, rest) = bindings.split_at_mut(0);
        let (ingress, right) = rest.split_first_mut().expect("ingress binding");
        let result = enqueue_mirror_clone(
            left,
            0,
            ingress,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            0,
            &[0xcc; 64],
            test_meta(),
            None,
        );
        record_mirror_clone_result(&ingress.live, result, 64);
        assert_eq!(result, MirrorCloneResult::QueueFull);
        assert_eq!(
            ingress.live.mirror_drops_queue_full.load(Ordering::Relaxed),
            1
        );
    }
}
