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
        oversubscription_policy: CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
    }
}

fn test_tx_request(payload: u8, egress_ifindex: i32) -> TxRequest {
    TxRequest {
        bytes: vec![payload; 64],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
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
    unsafe { target_live.take_pending_tx_into(&mut queued) };
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
    unsafe { target_q0.take_pending_tx_into(&mut queued) };
    unsafe { target_q1.take_pending_tx_into(&mut queued) };
    assert!(queued.is_empty());
}

#[test]
fn live_mirror_queue_full_drops_before_enqueue() {
    let target_live = Arc::new(BindingLiveState::new());
    target_live.set_max_pending_tx(1);
    assert!(
        target_live
            .try_enqueue_tx_owned(test_tx_request(0x11, 22))
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

    assert_eq!(result, MirrorCloneResult::QueueFullCrossWorker);
    let mut queued = VecDeque::new();
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued.pop_front().expect("original request").bytes,
        vec![0x11; 64]
    );
}

#[test]
fn live_mirror_admission_reserves_slot_against_interleaving_producer() {
    let target_live = Arc::new(BindingLiveState::new());
    target_live.set_max_pending_tx(1);
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
    let config = MirrorRuntimeConfig {
        output_ifindex: 22,
        rate: 0,
    };

    let admission =
        admit_mirror_clone_to_live(&mirror_targets, 22, 0, 64).expect("mirror admission");
    assert!(
        target_live
            .try_enqueue_tx_owned(test_tx_request(0x99, 22))
            .is_err(),
        "an admitted mirror must own capacity before its clone is allocated"
    );

    let result = enqueue_admitted_mirror_clone_to_live(
        admission,
        config,
        vec![0x22; 64],
        test_meta(),
        None,
        None,
    );

    assert_eq!(result, MirrorCloneResult::Enqueued);
    let mut queued = VecDeque::new();
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued.pop_front().expect("mirror request").bytes,
        vec![0x22; 64]
    );
}

#[test]
fn live_mirror_queue_full_reserves_headroom_above_mirror_limit() {
    let target_live = Arc::new(BindingLiveState::new());
    target_live.set_max_pending_tx(MIRROR_PENDING_LIMIT * 2);
    for _ in 0..MIRROR_PENDING_LIMIT {
        assert!(
            target_live
                .try_enqueue_tx_owned(test_tx_request(0x11, 22))
                .is_ok()
        );
    }
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

    assert_eq!(result, MirrorCloneResult::QueueFullCrossWorker);
    let mut queued = VecDeque::new();
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    assert_eq!(queued.len(), MIRROR_PENDING_LIMIT);
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
    unsafe { target_live.take_pending_tx_into(&mut queued) };
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
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    let req = queued.pop_front().expect("mirror tx");
    assert!(
        req.mirror_clone,
        "flow-cache mirror surface must preserve mirror identity"
    );
    assert_eq!(req.bytes, frame);
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
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    assert!(queued.is_empty());
}

// #6114 intent resolution: this test previously asserted admit-FIRST ordering
// (`..._queue_full_does_not_advance_sampler`) as intended — a full-queue packet
// must not "consume a mirror sample". #6114 determined that is a SECOND instance
// of the #5167 bug, not a real requirement: the flow-cache surface reserves the
// contended cross-worker clone queue (`admit_mirror_clone_to_live`, a true-shared
// AcqRel CAS on `pending_tx_admitted`, #4096) for EVERY established-flow packet,
// so acknowledged cross-core true-sharing scaled O(PPS) instead of O(PPS/R) on
// the dominant path. "Preserving sample budget on a full queue" only matters
// during a pressure event where clones are already being dropped, is
// statistically irrelevant to a 1-in-N decimation of a lossy clone stream, and
// #5167 already chose sample-first for the identical shared-CAS tradeoff in
// `enqueue_sampled_mirror_clone`. So the ordering is flipped to sample-first
// (via `sample_then_admit_mirror_clone`): a SELECTED packet advances the sampler
// and THEN reports the full-queue pressure.
#[test]
fn sampled_live_mirror_queue_full_advances_sampler_for_selected_6114() {
    let ingress_live = BindingLiveState::new();
    let target_live = Arc::new(BindingLiveState::new());
    target_live.set_max_pending_tx(1);
    assert!(
        target_live
            .try_enqueue_tx_owned(test_tx_request(0x33, 22))
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
    let mut forwarding = ForwardingState::default();
    forwarding.mirror_configs.insert(
        11,
        MirrorRuntimeConfig {
            output_ifindex: 22,
            rate: 4,
        },
    );
    // rate=4 + counter=0 -> mirror_sample_allows == true (this packet IS
    // selected). Sample-first advances the sampler BEFORE it discovers the
    // full queue.
    let mut sample_counter = 0;

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

    assert_eq!(result, Some(MirrorCloneResult::QueueFullCrossWorker));
    assert_eq!(
        sample_counter, 1,
        "#6114: a SELECTED packet advances the sampler before the full-queue \
         admit fails (sample-first); reverting to admit-first leaves it at 0"
    );
    assert_eq!(
        ingress_live.mirror_drops_queue_full.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        ingress_live
            .mirror_drops_queue_full_cross_worker
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        target_live
            .redirect_inbox_overflow_drops
            .load(Ordering::Relaxed),
        0,
        "mirror backpressure must not pollute target redirect overflow counters"
    );
    let mut queued = VecDeque::new();
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    assert_eq!(
        queued.pop_front().expect("original request").bytes,
        vec![0x33; 64]
    );
    assert!(queued.is_empty());
}

/// #6114 FAIL-ON-REVERT: a NON-sampled packet on the flow-cache mirror surface
/// must NOT reserve the (full) cross-worker clone queue. This is the flow-cache
/// analog of #6113's `cross_worker_nonsampled_does_not_reserve_full_queue_5167`,
/// and it guards the ordering used by BOTH `enqueue_sampled_mirror_clone_to_live`
/// and the established-flow HOT path (`poll_descriptor/flow_cache_hit.rs`), which
/// share `sample_then_admit_mirror_clone`.
///
/// With sample-first, a non-sampled packet returns `None` having touched nothing
/// shared: no `admit_mirror_clone_to_live` reservation, no clone-queue pressure
/// counter, the pre-fill untouched, and only the worker-local sampler advanced.
/// Reverting to reserve-before-sample makes the packet call
/// `admit_mirror_clone_to_live` on the full queue and return
/// `Some(QueueFullCrossWorker)` while bumping `mirror_drops_queue_full` — a
/// non-sampled packet reporting clone-queue pressure it should never touch -> RED.
#[test]
fn flow_cache_nonsampled_does_not_reserve_full_queue_6114() {
    let ingress_live = BindingLiveState::new();
    let target_live = Arc::new(BindingLiveState::new());
    // Drive the cross-worker clone queue to its admission cap.
    target_live.set_max_pending_tx(1);
    assert!(
        target_live
            .try_enqueue_tx_owned(test_tx_request(0x33, 22))
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
    let mut forwarding = ForwardingState::default();
    forwarding.mirror_configs.insert(
        11,
        MirrorRuntimeConfig {
            output_ifindex: 22,
            rate: 2,
        },
    );
    // rate=2 + counter=1 -> mirror_sample_allows == false (this packet is NOT
    // selected).
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

    assert_eq!(
        result, None,
        "#6114: a non-sampled packet must NOT reserve the full clone queue \
         (sample-first); reverting to admit-first returns \
         Some(QueueFullCrossWorker)"
    );
    assert_eq!(
        sample_counter, 2,
        "the worker-local sampler still advances for the declined packet"
    );
    assert_eq!(
        ingress_live.mirror_drops_queue_full.load(Ordering::Relaxed),
        0,
        "#6114: a non-sampled packet must not report clone-queue pressure"
    );
    assert_eq!(
        ingress_live
            .mirror_drops_queue_full_cross_worker
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(ingress_live.mirrored_packets.load(Ordering::Relaxed), 0);
    // The pre-fill is the only queued request; the non-sampled packet reserved
    // nothing.
    let mut queued = VecDeque::new();
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    assert_eq!(
        queued.pop_front().expect("original request").bytes,
        vec![0x33; 64]
    );
    assert!(queued.is_empty());
}

#[test]
fn sampled_live_mirror_missing_target_records_drop_counter() {
    let ingress_live = BindingLiveState::new();
    let mirror_targets = MirrorTargetMap::default();
    let mut forwarding = ForwardingState::default();
    forwarding.mirror_configs.insert(
        11,
        MirrorRuntimeConfig {
            output_ifindex: 22,
            rate: 0,
        },
    );
    let mut sample_counter = 0;

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

    assert_eq!(result, Some(MirrorCloneResult::NoBinding));
    assert_eq!(
        sample_counter, 0,
        "missing mirror target must fail before consuming a sample"
    );
    assert_eq!(
        ingress_live.mirror_drops_no_binding.load(Ordering::Relaxed),
        1
    );
    assert_eq!(ingress_live.mirrored_packets.load(Ordering::Relaxed), 0);
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
    unsafe { target_live.take_pending_tx_into(&mut queued) };
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
    assert_eq!(result, MirrorCloneResult::TxFrameReserve);
    assert_eq!(
        ingress
            .live
            .mirror_drops_tx_frame_reserve
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn live_mirror_owner_drops_before_consuming_tx_frame_reserve() {
    let mut binding = BindingWorker::new_for_mirror_test(1, 0, 22, 0);
    binding
        .tx_pipeline
        .free_tx_frames
        .truncate(MIRROR_TX_FRAME_RESERVE);
    let free_before = binding.tx_pipeline.free_tx_frames.len();
    let mut pending = VecDeque::from([TxRequest {
        bytes: vec![0xdd; 64],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 22,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: true,
        overlap_admissions: None,
        enqueue_ns: 0,
    }]);
    let mut shared_recycles = Vec::new();

    let result = match transmit_batch(&mut binding, &mut pending, 0, &mut shared_recycles) {
        Ok(result) => result,
        Err(_) => panic!("mirror reserve drop should not surface as TX retry"),
    };

    assert_eq!(result, (0, 0));
    assert!(pending.is_empty());
    assert_eq!(binding.tx_pipeline.free_tx_frames.len(), free_before);
    assert_eq!(
        binding
            .live
            .mirror_drops_tx_frame_reserve
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        binding.live.mirror_drops_no_frame.load(Ordering::Relaxed),
        0,
        "TX-frame reserve drops must not be conflated with oversize/slice failures"
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
                mirror_clone: true,
                overlap_admissions: None,
                enqueue_ns: 0,
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
    assert_eq!(result, MirrorCloneResult::QueueFullSameWorker);
    assert_eq!(
        ingress.live.mirror_drops_queue_full.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        ingress
            .live
            .mirror_drops_queue_full_same_worker
            .load(Ordering::Relaxed),
        1
    );
}

// =====================================================================
// #5167: cross-worker mirror clone must SAMPLE before it RESERVES the
// contended live clone queue. `enqueue_sampled_mirror_clone`'s cross-worker
// (else) branch previously called `admit_mirror_clone_to_live` (the shared
// AcqRel CAS on the target's `pending_tx_admitted`) BEFORE `mirror_sample_allows`,
// so every unsampled packet reserved/reported clone-queue pressure — acknowledged
// cross-core true-sharing scaled O(PPS) instead of O(PPS/R). The fix runs the
// sampler first, matching the same-worker branch.
// =====================================================================

/// Build a CROSS-worker mirror scenario: the ingress binding is on ifindex 11,
/// the mirror target lives on ifindex 22 and is NOT present in `binding_lookup`,
/// so `mirror_target_binding_index` returns `None` and
/// `enqueue_sampled_mirror_clone` takes the cross-worker (to-live) else branch.
fn cross_worker_mirror_setup(
    rate: u32,
) -> (
    BindingWorker,
    WorkerBindingLookup,
    MirrorTargetMap,
    ForwardingState,
    Arc<BindingLiveState>,
) {
    let ingress = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
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
    let binding_lookup = WorkerBindingLookup::default(); // empty -> None -> else branch
    let mut forwarding = ForwardingState::default();
    forwarding
        .mirror_configs
        .insert(11, MirrorRuntimeConfig { output_ifindex: 22, rate });
    (ingress, binding_lookup, mirror_targets, forwarding, target_live)
}

/// #5167 FAIL-ON-REVERT: a NON-sampled cross-worker packet must NOT reserve the
/// (full) live clone queue. With sample-first it returns `None` having touched
/// nothing shared; the pre-fill is untouched and the sampler advanced once.
/// Reverting to reserve-before-sample makes the packet call
/// `admit_mirror_clone_to_live` on the full queue and return
/// `Some(QueueFullCrossWorker)` (a non-sampled packet reporting clone-queue
/// pressure) -> RED.
#[test]
fn cross_worker_nonsampled_does_not_reserve_full_queue_5167() {
    let (mut ingress, lookup, mirror_targets, forwarding, target_live) =
        cross_worker_mirror_setup(2);
    // Drive the cross-worker clone queue to its admission cap.
    target_live.set_max_pending_tx(1);
    assert!(
        target_live
            .try_enqueue_tx_owned(test_tx_request(0x33, 22))
            .is_ok()
    );
    // rate=2 + counter=1 -> mirror_sample_allows == false (this packet is NOT
    // selected).
    ingress.mirror_sample_counter = 1;

    let mut left: [BindingWorker; 0] = [];
    let mut right: [BindingWorker; 0] = [];
    let frame = vec![0x44; 80];
    let result = enqueue_sampled_mirror_clone(
        &mut left,
        0,
        &mut ingress,
        &mut right,
        &lookup,
        &mirror_targets,
        &forwarding,
        11,
        0,
        0,
        &frame,
        test_meta(),
        None,
    );

    assert_eq!(
        result, None,
        "a non-sampled cross-worker packet must NOT reserve or report clone-queue \
         pressure (sample-first)",
    );
    // The sampler ran FIRST (advanced by one); admission was never attempted.
    assert_eq!(
        ingress.mirror_sample_counter, 2,
        "the worker-local sampler must run before admission",
    );
    // Nothing was cloned: only the pre-fill remains on the target queue.
    let mut queued = VecDeque::new();
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    assert_eq!(
        queued.len(),
        1,
        "the non-sampled packet reserved nothing — only the pre-fill remains",
    );
}

/// #5167 control: a SELECTED (sampled) cross-worker packet on a full queue DOES
/// report clone-queue pressure — the fix bounds pressure reporting to the sample
/// rate, it does not suppress it for selected packets. Passes both before and
/// after the reorder (guards against over-suppression).
#[test]
fn cross_worker_sampled_reports_queue_full_5167() {
    let (mut ingress, lookup, mirror_targets, forwarding, target_live) =
        cross_worker_mirror_setup(2);
    target_live.set_max_pending_tx(1);
    assert!(
        target_live
            .try_enqueue_tx_owned(test_tx_request(0x33, 22))
            .is_ok()
    );
    // rate=2 + counter=0 -> selected.
    ingress.mirror_sample_counter = 0;

    let mut left: [BindingWorker; 0] = [];
    let mut right: [BindingWorker; 0] = [];
    let frame = vec![0x44; 80];
    let result = enqueue_sampled_mirror_clone(
        &mut left,
        0,
        &mut ingress,
        &mut right,
        &lookup,
        &mirror_targets,
        &forwarding,
        11,
        0,
        0,
        &frame,
        test_meta(),
        None,
    );

    assert_eq!(
        result,
        Some(MirrorCloneResult::QueueFullCrossWorker),
        "a selected packet on a full queue must report cross-worker pressure",
    );
    assert_eq!(ingress.mirror_sample_counter, 1, "the selected packet consumed a sample");
}

/// #5167 positive: a SELECTED cross-worker packet on a non-full queue clones to
/// the live target (the reorder does not break the happy path).
#[test]
fn cross_worker_sampled_enqueues_clone_5167() {
    let (mut ingress, lookup, mirror_targets, forwarding, target_live) =
        cross_worker_mirror_setup(2);
    ingress.mirror_sample_counter = 0; // selected

    let mut left: [BindingWorker; 0] = [];
    let mut right: [BindingWorker; 0] = [];
    let frame = vec![0x44; 80];
    let result = enqueue_sampled_mirror_clone(
        &mut left,
        0,
        &mut ingress,
        &mut right,
        &lookup,
        &mirror_targets,
        &forwarding,
        11,
        0,
        0,
        &frame,
        test_meta(),
        None,
    );

    assert_eq!(result, Some(MirrorCloneResult::Enqueued));
    let mut queued = VecDeque::new();
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    let req = queued.pop_front().expect("cross-worker mirror clone");
    assert!(req.mirror_clone, "cloned request must carry mirror identity");
    assert_eq!(req.bytes, frame);
}

/// #5167 sanity: a non-sampled cross-worker packet on a NON-full queue also
/// clones nothing (returns None). This holds both before and after the reorder —
/// it documents the sampling behavior but is NOT the fail-on-revert (the full-
/// queue test above is, because only there does admit's outcome become visible).
#[test]
fn cross_worker_nonsampled_no_clone_nonfull_5167() {
    let (mut ingress, lookup, mirror_targets, forwarding, target_live) =
        cross_worker_mirror_setup(2);
    ingress.mirror_sample_counter = 1; // NOT selected

    let mut left: [BindingWorker; 0] = [];
    let mut right: [BindingWorker; 0] = [];
    let frame = vec![0x44; 80];
    let result = enqueue_sampled_mirror_clone(
        &mut left,
        0,
        &mut ingress,
        &mut right,
        &lookup,
        &mirror_targets,
        &forwarding,
        11,
        0,
        0,
        &frame,
        test_meta(),
        None,
    );

    assert_eq!(result, None);
    let mut queued = VecDeque::new();
    unsafe { target_live.take_pending_tx_into(&mut queued) };
    assert!(queued.is_empty(), "a non-sampled packet must not clone");
}

/// #6304 (test-registration canary). The #6304 guard for the LIVE
/// established-flow mirror call site lives in
/// `poll_descriptor/flow_cache_hit_tests.rs`, which reaches the compiler ONLY
/// through the three-line `#[cfg(test)] #[path = ...] mod` declaration at the
/// foot of `poll_descriptor/flow_cache_hit.rs`. Before this canary, removing
/// that declaration failed neither a build nor a test — it silently
/// unregistered the whole module, and the suite went green with the live call
/// site unbound again, which is the exact failure mode #6304 exists to close.
///
/// The block is matched CONTIGUOUSLY, `#[cfg(test)]` included, because
/// unregistering does not require deleting anything: rewriting the predicate to
/// one that is never satisfied — `#[cfg(any())]` — removes the module from
/// every build just as completely while leaving both the `#[path]` attribute
/// and the `mod` item in the file. A canary that looked for those two
/// substrings independently passed under exactly that edit; verified firsthand.
///
/// A canary inside that module cannot fire (it disappears with it), so this
/// one lives here, in the mirror module that owns the #6114 invariant and is
/// registered independently from `mirror/mod.rs`.
///
/// It remains source text, so it pins the declaration's FORM: a legitimate
/// reformat of those three lines, or a move to a different registration
/// mechanism, must update this test with it.
#[test]
fn live_flow_cache_callsite_tests_are_registered_6304() {
    let src = include_str!("../poll_descriptor/flow_cache_hit.rs");
    assert!(
        src.contains(
            "#[cfg(test)]\n#[path = \"flow_cache_hit_tests.rs\"]\nmod flow_cache_hit_tests;"
        ),
        "#6304: poll_descriptor/flow_cache_hit.rs must still declare its test \
         module under a plain `#[cfg(test)]` — deleting the declaration, or \
         narrowing the predicate so it never holds, leaves the LIVE mirror \
         call-site guards uncompiled and the suite passing vacuously"
    );
}
