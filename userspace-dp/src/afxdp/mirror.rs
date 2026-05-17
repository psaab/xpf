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
    sample_counter: &mut u64,
) -> Option<MirrorRuntimeConfig> {
    let config = forwarding.mirror_configs.get(&ingress_ifindex).copied()?;
    mirror_sample_allows(config.rate, sample_counter).then_some(config)
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
    config: MirrorRuntimeConfig,
    ingress_queue_id: u32,
    frame: &[u8],
    expected_addr_family: u8,
    expected_protocol: u8,
) -> MirrorCloneResult {
    let target_binding_index = binding_lookup.target_index(
        ingress_index,
        ingress_binding.ifindex,
        ingress_queue_id,
        config.output_ifindex,
    );
    let Some(target_binding) = target_binding_index
        .and_then(|idx| binding_by_index_mut(left, ingress_index, ingress_binding, right, idx))
    else {
        return MirrorCloneResult::NoBinding;
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
            expected_addr_family,
            expected_protocol,
            flow_key: None,
            egress_ifindex: config.output_ifindex,
            cos_queue_id: None,
            dscp_rewrite: None,
        });
    MirrorCloneResult::Enqueued
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
    fn cross_binding_inject_preserves_full_frame() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let (left, rest) = bindings.split_at_mut(0);
        let (ingress, right) = rest.split_first_mut().expect("ingress binding");
        let frame: Vec<u8> = (0..96).map(|v| v as u8).collect();

        let result = enqueue_mirror_clone(
            left,
            0,
            ingress,
            right,
            &lookup,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            0,
            &frame,
            libc::AF_INET as u8,
            6,
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
    fn missing_destination_binding_drop_counter() {
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
        let bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let result = enqueue_mirror_clone(
            &mut [],
            0,
            &mut binding,
            &mut [],
            &lookup,
            MirrorRuntimeConfig {
                output_ifindex: 99,
                rate: 0,
            },
            0,
            &[0xaa; 64],
            0,
            0,
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
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            0,
            &[0xbb; 64],
            0,
            0,
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
        let (left, rest) = bindings.split_at_mut(0);
        let (ingress, right) = rest.split_first_mut().expect("ingress binding");
        let result = enqueue_mirror_clone(
            left,
            0,
            ingress,
            right,
            &lookup,
            MirrorRuntimeConfig {
                output_ifindex: 22,
                rate: 0,
            },
            0,
            &[0xcc; 64],
            0,
            0,
        );
        record_mirror_clone_result(&ingress.live, result, 64);
        assert_eq!(result, MirrorCloneResult::QueueFull);
        assert_eq!(
            ingress.live.mirror_drops_queue_full.load(Ordering::Relaxed),
            1
        );
    }
}
