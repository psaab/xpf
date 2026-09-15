use super::*;

#[test]
fn cos_queue_rejects_prepared_once_local_items_enter_queue() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    // #774: use cos_queue_push_back so local_item_count
    // stays in sync. Previously this test poked queue.hot.items
    // directly, which bypassed the counter maintenance.
    cos_queue_push_back(
        &mut root.queues[0],
        CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }),
    );
    cos_queue_push_back(
        &mut root.queues[0],
        CoSPendingTxItem::Local(TxRequest {
            bytes: vec![0; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }),
    );

    assert!(!cos_queue_accepts_prepared(&root, Some(5)));
}

#[test]
fn exact_local_fifo_boundary_survives_partial_commit() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![1],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![2],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 256,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));

    let mut free_tx_frames = VecDeque::from([64, 128, 192]);
    let mut scratch_local_tx = Vec::new();

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_local_tx.len(), 2);

    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (sent_packets, sent_bytes) = settle_exact_local_fifo_submission(
        Some(&mut root.queues[0]),
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &mut in_flight_untracked_tx,
        1,
    );
    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert_eq!(free_tx_frames, VecDeque::from([128, 192]));
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(1),
        Some(CoSPendingTxItem::Prepared(req)) if req.offset == 256
    ));

    let build = drain_exact_local_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &area,
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_local_tx.len(), 1);
    assert_eq!(scratch_local_tx[0].offset, 128);
    assert_eq!(free_tx_frames, VecDeque::from([192]));
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![2]
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(1),
        Some(CoSPendingTxItem::Prepared(req)) if req.offset == 256
    ));
}

#[test]
fn drain_exact_prepared_items_to_scratch_recycles_dropped_prepared_frame() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: (tx_frame_capacity() + 1) as u32,
            recycle: PreparedTxRecycle::FillOnSlot(7),
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));

    let mut scratch_prepared_tx = Vec::new();
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();

    let build = drain_exact_prepared_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );

    match build {
        ExactCoSScratchBuild::Drop { dropped_bytes, .. } => {
            assert_eq!(dropped_bytes, (tx_frame_capacity() + 1) as u64);
        }
        ExactCoSScratchBuild::Ready => panic!("oversized prepared frame must drop"),
        ExactCoSScratchBuild::MirrorTxFrameReserve { .. } => {
            panic!("prepared frame must not trip mirror reserve handling")
        }
    }
    assert!(scratch_prepared_tx.is_empty());
    assert!(free_tx_frames.is_empty());
    assert_eq!(pending_fill_frames, VecDeque::from([64]));
    assert!(root.queues[0].hot.items.is_empty());
}

#[test]
fn exact_prepared_fifo_boundary_survives_partial_commit() {
    let area = MmapArea::new(4096).expect("mmap");
    unsafe { area.slice_mut_unchecked(64, 1) }
        .expect("prepared frame 1")
        .copy_from_slice(&[1]);
    unsafe { area.slice_mut_unchecked(128, 1) }
        .expect("prepared frame 2")
        .copy_from_slice(&[2]);

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 128,
            len: 1,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Local(TxRequest {
            bytes: vec![9],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            enqueue_ns: 0,
        }));

    let mut scratch_prepared_tx = Vec::new();
    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();

    let build = drain_exact_prepared_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_prepared_tx.len(), 2);

    let mut in_flight_prepared_recycles = FastMap::default();
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (sent_packets, sent_bytes) = settle_exact_prepared_fifo_submission(
        Some(&mut root.queues[0]),
        &mut scratch_prepared_tx,
        &mut in_flight_prepared_recycles,
        &mut in_flight_untracked_tx,
        1,
    );
    assert_eq!(sent_packets, 1);
    assert_eq!(sent_bytes, 1);
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(1),
        Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
    ));

    let build = drain_exact_prepared_fifo_items_to_scratch(
        &mut root.queues[0],
        &mut scratch_prepared_tx,
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut Vec::new(),
        u64::MAX,
        u64::MAX,
        None,
    );
    assert!(matches!(build, ExactCoSScratchBuild::Ready));
    assert_eq!(scratch_prepared_tx.len(), 1);
    assert_eq!(scratch_prepared_tx[0].offset, 128);
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Prepared(req)) if req.offset == 128
    ));
    assert!(matches!(
        root.queues[0].hot.items.get(1),
        Some(CoSPendingTxItem::Local(req)) if req.bytes == vec![9]
    ));
}

