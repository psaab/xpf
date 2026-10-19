//! queue_service submit tests: submit_local/submit_prepared owner
//! tx-counter bumps and flow-fair local-scratch offset recycling.

use super::*;

// #hb166 T-7: the flow-fair local scratch None arms (queue torn down
// mid-drain) must recycle the popped `free_tx_frames` UMEM offsets, not
// leak them. Pre-fix they bare-`.clear()`ed the scratch, unlike the FIFO
// sibling `settle_exact_local_fifo_submission`. RED-on-revert: the
// recycled offsets stay absent from `free_tx_frames`.
fn t7_local_scratch_entry(offset: u64, len: usize) -> (u64, TxRequest) {
    (
        offset,
        TxRequest {
            bytes: vec![0u8; len],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        },
    )
}

#[test]
fn settle_local_scratch_flow_fair_recycles_offsets_when_queue_gone() {
    let mut free_tx_frames: VecDeque<u64> = VecDeque::new();
    let mut scratch_local_tx: Vec<(u64, TxRequest)> = vec![
        t7_local_scratch_entry(64, 4),
        t7_local_scratch_entry(128, 4),
    ];
    let mut in_flight_untracked_tx = crate::afxdp::FastSet::default();
    let (packets, bytes) = settle_exact_local_scratch_submission_flow_fair(
        None,
        &mut free_tx_frames,
        &mut scratch_local_tx,
        &mut in_flight_untracked_tx,
        0,
        0,
    );
    assert_eq!((packets, bytes), (0, 0));
    assert!(scratch_local_tx.is_empty(), "scratch must be drained");
    let mut recycled: Vec<u64> = free_tx_frames.into_iter().collect();
    recycled.sort_unstable();
    assert_eq!(
        recycled,
        vec![64, 128],
        "both UMEM offsets must be recycled to free_tx_frames, not leaked"
    );
}

#[test]
fn restore_local_scratch_flow_fair_recycles_offsets_when_queue_gone() {
    let mut free_tx_frames: VecDeque<u64> = VecDeque::new();
    let mut scratch_local_tx: Vec<(u64, TxRequest)> = vec![
        t7_local_scratch_entry(64, 4),
        t7_local_scratch_entry(128, 4),
    ];
    restore_exact_local_scratch_to_queue_head_flow_fair(
        None,
        &mut free_tx_frames,
        &mut scratch_local_tx,
    );
    assert!(scratch_local_tx.is_empty(), "scratch must be drained");
    let mut recycled: Vec<u64> = free_tx_frames.into_iter().collect();
    recycled.sort_unstable();
    assert_eq!(
        recycled,
        vec![64, 128],
        "both UMEM offsets must be recycled to free_tx_frames, not leaked"
    );
}

// #4282 part (a): owner-lifecycle TX accounting lock on the CoS submit
// paths. A CoS-forwarded packet MUST bump the owner binding's
// `live.tx_packets` / `live.tx_bytes` exactly like the non-CoS backup
// drain path (`tx/drain/phase_backup.rs`), or `show interfaces` and the
// Prometheus TX gauges undercount every shaped byte.
//
// Verification at HEAD found the accounting already present on all CoS
// ship paths — this is a regression LOCK, not a fix. Every CoS-submit
// settle boundary funnels through exactly one of three `fetch_add`
// sites:
//   1. `submit_local`  — the non-exact CoSBatch::Local batched submit.
//   2. `submit_prepared` — the non-exact CoSBatch::Prepared submit.
//   3. `apply_direct_exact_send_result` — the single funnel for the
//      four exact direct-service settle sites in `service.rs`
//      (local|prepared × FIFO|flow-fair).
// The three tests below pin the (tx_packets, tx_bytes) pair on each,
// so a future refactor that drops the counter goes RED on revert.

/// FAIL-ON-REVERT: neutering either `binding.live.tx_packets` /
/// `tx_bytes` `fetch_add` in `submit_local`'s Ok arm leaves the counter
/// at 0 and the matching assert fails.
#[test]
fn submit_local_bumps_owner_tx_packets_and_bytes() {
    let now_ns = 1_000_000_000u64;
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: true,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 10_000;
    root.queues[0].hot.tokens = 10_000;
    root.queues[0].hot.queued_bytes = 300;

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // Three 100-byte items, all fully shipped through the test TX ring
    // in a single transmit_batch call (TX_BATCH_SIZE == 64).
    let items: VecDeque<TxRequest> = (0..3)
        .map(|_| TxRequest {
            bytes: vec![0u8; 100],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: now_ns,
        })
        .collect();
    let mut shared_recycles = Vec::new();

    let progress = submit_local(
        &mut binding,
        42,
        0,
        CoSServicePhase::Surplus,
        300,
        items,
        now_ns,
        &mut shared_recycles,
    );
    assert!(
        progress,
        "submit_local must report progress on a full commit"
    );

    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        3,
        "submit_local must bump owner tx_packets by the committed packet count",
    );
    assert_eq!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        300,
        "submit_local must bump owner tx_bytes by the committed byte count",
    );
}

/// FAIL-ON-REVERT: neutering either `binding.live.tx_packets` /
/// `tx_bytes` `fetch_add` in `submit_prepared`'s Ok arm leaves the
/// counter at 0 and the matching assert fails.
#[test]
fn submit_prepared_bumps_owner_tx_packets_and_bytes() {
    let now_ns = 1_000_000_000u64;
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: true,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 10_000;
    root.queues[0].hot.tokens = 10_000;
    root.queues[0].hot.queued_bytes = 250;

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // Two prepared items whose frames live in the binding's own UMEM.
    // Production allocates a prepared frame OUT of the free pool, so
    // remove those two offsets from free_tx_frames to mirror that and
    // avoid double-ownership of the frame.
    let specs = [
        (40u64 << UMEM_FRAME_SHIFT, 100u32),
        (41u64 << UMEM_FRAME_SHIFT, 150u32),
    ];
    for (offset, len) in specs {
        let frame = unsafe {
            binding
                .umem
                .area()
                .slice_mut_unchecked(offset as usize, len as usize)
        }
        .expect("umem frame slice");
        frame.fill(0);
    }
    binding
        .tx_pipeline
        .free_tx_frames
        .retain(|&off| off != specs[0].0 && off != specs[1].0);

    let items: VecDeque<PreparedTxRequest> = specs
        .iter()
        .map(|&(offset, len)| PreparedTxRequest {
            offset,
            len,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: now_ns,
        })
        .collect();
    let mut shared_recycles = Vec::new();

    let progress = submit_prepared(
        &mut binding,
        42,
        0,
        CoSServicePhase::Surplus,
        250,
        items,
        now_ns,
        &mut shared_recycles,
    );
    assert!(
        progress,
        "submit_prepared must report progress on a full commit"
    );

    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        2,
        "submit_prepared must bump owner tx_packets by the committed packet count",
    );
    assert_eq!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        250,
        "submit_prepared must bump owner tx_bytes by the committed byte count",
    );
}

/// FAIL-ON-REVERT: removing either `binding.live.tx_packets` /
/// `tx_bytes` `fetch_add` in `apply_direct_exact_send_result` leaves the
/// counter at 0. This is the single owner-TX accounting funnel for all
/// four exact direct-service settle sites in `service.rs`.
#[test]
fn apply_direct_exact_send_result_bumps_owner_tx_packets_and_bytes() {
    let root = test_cos_interface_runtime(0);
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    crate::afxdp::cos::tx_completion::apply_direct_exact_send_result(&mut binding, 42, 0, 4, 6_000);

    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        4,
        "direct-exact settle funnel must bump owner tx_packets",
    );
    assert_eq!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        6_000,
        "direct-exact settle funnel must bump owner tx_bytes",
    );
}

/// #5157 FAIL-ON-REVERT: `transmit_batch` drops a `mirror_clone` request
/// mid-batch (mirror-reserve back-pressure, `free_tx_frames.len() <=
/// MIRROR_TX_FRAME_RESERVE`) via `continue` — a NON-prefix / interior
/// removal. The per-flow bucket accounting in `submit_local` must charge
/// the items ACTUALLY transmitted, by original-input identity, NOT the
/// old `sidecar[..packets]` prefix.
///
/// Batch = [M(mirror, front), A, B]. The front mirror is dropped; A and B
/// ship. The fixed code charges A→bucket_a and B→bucket_b. The reverted
/// prefix code would charge `sidecar[..2]` = {mirror, A} → the dropped
/// mirror's bucket (never sent) and miss B entirely. Two independent
/// asserts (bucket_b == 150, bucket_m == 0) each go RED on revert.
#[test]
fn mirror_interior_drop_preserves_sidecar_attribution_5157() {
    use std::sync::atomic::Ordering;
    let now_ns = 1_000_000_000u64;
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: true,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 10_000;
    root.queues[0].hot.tokens = 10_000;
    root.queues[0].hot.queued_bytes = 450;
    // Promote to flow-fair so the per-bucket sidecar accounting is live
    // (submit_local's `sidecar_len > 0` gate ↔ flow_fair_state.is_some()).
    enable_test_flow_fair(&mut root.queues[0]);
    assert!(root.queues[0].flow_fair(), "queue must be flow-fair");

    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    // The default test binding ships with exactly TX_BATCH_SIZE (64) free
    // TX frames, and MIRROR_TX_FRAME_RESERVE == TX_BATCH_SIZE, so
    // free_tx_frames.len() (64) <= reserve (64): any mirror_clone in the
    // batch is dropped by the reserve gate.
    let seed = test_flow_fair_state(
        &binding
            .cos
            .cos_interfaces
            .get(&42)
            .expect("cos root")
            .queues[0],
    )
    .flow_hash_seed;

    // Three distinct flows with distinct 5-tuples (distinct src ports) so
    // they occupy distinct buckets, and distinct byte lengths so any
    // misattribution is unambiguous.
    let key_m = test_session_key(1111, 5201);
    let key_a = test_session_key(2222, 5201);
    let key_b = test_session_key(3333, 5201);
    let bucket_m = cos_flow_bucket_index(seed, Some(&key_m));
    let bucket_a = cos_flow_bucket_index(seed, Some(&key_a));
    let bucket_b = cos_flow_bucket_index(seed, Some(&key_b));
    assert!(
        bucket_m != bucket_a && bucket_a != bucket_b && bucket_m != bucket_b,
        "test premise: distinct buckets (m={bucket_m} a={bucket_a} b={bucket_b})",
    );

    // Mirror at the FRONT — an interior/non-tail removal relative to the
    // shipped set {A, B}.
    let items: VecDeque<TxRequest> = VecDeque::from([
        TxRequest {
            bytes: vec![0u8; 200],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(key_m.clone()),
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
            mirror_clone: true,
            overlap_admissions: None,
            enqueue_ns: now_ns,
        },
        TxRequest {
            bytes: vec![0u8; 100],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(key_a.clone()),
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: now_ns,
        },
        TxRequest {
            bytes: vec![0u8; 150],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(key_b.clone()),
            egress_ifindex: 42,
            cos_queue_id: Some(0),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: now_ns,
        },
    ]);
    let mut shared_recycles = Vec::new();

    let progress = submit_local(
        &mut binding,
        42,
        0,
        CoSServicePhase::Surplus,
        450,
        items,
        now_ns,
        &mut shared_recycles,
    );
    assert!(
        progress,
        "submit_local must report progress on the A+B commit"
    );

    // Exactly the two non-mirror packets shipped; the front mirror dropped.
    assert_eq!(
        binding.live.tx_packets.load(Ordering::Relaxed),
        2,
        "only the two non-mirror packets transmit",
    );
    assert_eq!(
        binding
            .live
            .mirror_drops_tx_frame_reserve
            .load(Ordering::Relaxed),
        1,
        "the front mirror_clone must be dropped by the reserve gate",
    );

    let ff = test_flow_fair_state(
        &binding
            .cos
            .cos_interfaces
            .get(&42)
            .expect("cos root")
            .queues[0],
    );
    assert_eq!(
        ff.flow_bucket_tx_bytes[bucket_a], 100,
        "flow A must be charged its own 100 bytes",
    );
    // FAIL-ON-REVERT anchor #1: the old sidecar[..packets] prefix stops at
    // A and never reaches B — it charged the dropped front mirror instead.
    assert_eq!(
        ff.flow_bucket_tx_bytes[bucket_b], 150,
        "flow B (shifted past the dropped front mirror) must be charged its \
         150 bytes; the reverted prefix accounting leaves this 0",
    );
    // FAIL-ON-REVERT anchor #2: the dropped mirror must NEVER be charged.
    assert_eq!(
        ff.flow_bucket_tx_bytes[bucket_m], 0,
        "the dropped mirror_clone's flow must not be charged; the reverted \
         prefix accounting would charge it 200 bytes",
    );
}

/// #15172 fixture: flow-fair queue (root 42, queue 0) loaded via REAL
/// cos_queue_push_back with A(1111,100), M(2222,150), B(3333,200).
/// Returns (binding, pre_pop_head_a, bucket_a, bucket_m).
fn mirror_orphan_fixture_15172() -> (BindingWorker, u64, usize, usize) {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 10_000;
    root.queues[0].hot.tokens = 10_000;
    root.queues[0].hot.queued_bytes = 450;
    enable_test_flow_fair(&mut root.queues[0]);
    for (port, len) in [(1111u16, 100usize), (2222, 150), (3333, 200)] {
        cos_queue_push_back(&mut root.queues[0], test_flow_cos_item(port, len));
    }
    let seed = test_flow_fair_state(&root.queues[0]).flow_hash_seed;
    let bucket_a = cos_flow_bucket_index(seed, Some(&test_session_key(1111, 5201)));
    let bucket_m = cos_flow_bucket_index(seed, Some(&test_session_key(2222, 5201)));
    let bucket_b = cos_flow_bucket_index(seed, Some(&test_session_key(3333, 5201)));
    assert!(
        bucket_a != bucket_m && bucket_m != bucket_b && bucket_a != bucket_b,
        "test premise: distinct buckets (a={bucket_a} m={bucket_m} b={bucket_b})",
    );
    let pre_pop_head_a =
        test_flow_fair_state(&root.queues[0]).flow_bucket_head_finish_bytes[bucket_a];
    assert_eq!(pre_pop_head_a, 100, "test premise: A head finish is 100");
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    (binding, pre_pop_head_a, bucket_a, bucket_m)
}

fn build_mirror_batch_15172(binding: &mut BindingWorker) -> (VecDeque<TxRequest>, u64, usize) {
    let queue = &mut binding
        .cos
        .cos_interfaces
        .get_mut(&42)
        .expect("cos root")
        .queues[0];
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    let batch = build_cos_batch_from_queue(
        queue,
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("batch built");
    let (mut items, batch_bytes) = match batch {
        CoSBatch::Local {
            items, batch_bytes, ..
        } => (items, batch_bytes),
        CoSBatch::Prepared { .. } => unreachable!("Local items expected"),
    };
    assert_eq!(items.len(), 3, "test premise: three items built");
    assert_eq!(
        test_flow_fair_state(
            &binding
                .cos
                .cos_interfaces
                .get(&42)
                .expect("cos root")
                .queues[0]
        )
        .pop_snapshot_stack
        .len(),
        3,
        "test premise: one snapshot per built item",
    );
    let pos_of = |port: u16| {
        items
            .iter()
            .position(|r| r.flow_key.as_ref().map(|k| k.src_port) == Some(port))
            .expect("flow present")
    };
    let pos_a = pos_of(1111);
    let pos_m = pos_of(2222);
    assert!(
        pos_a < pos_m,
        "test premise: survivor A (pos {pos_a}) precedes mirror M (pos {pos_m})",
    );
    items[pos_m].mirror_clone = true;
    (items, batch_bytes, pos_m)
}

fn fill_test_tx_ring_15172(binding: &mut BindingWorker) {
    let mut writer = binding.xsk.tx.transmit(64);
    let n = writer.insert((0..64).map(|i| crate::xsk_ffi::xdp::XdpDesc {
        addr: i as u64,
        len: 60,
        options: 0,
    }));
    assert_eq!(n, 64, "test premise: dummy fill inserts 64");
    writer.commit();
}

/// #15172 FAIL-ON-REVERT: batch [A, M(mirror), B] from a flow-fair
/// queue; transmit_batch drops M at the reserve gate; the pre-filled
/// test TX ring forces inserted==0, so both survivors restore LIFO.
/// Pre-fix A's push_front consumes M's orphan snapshot (bucket
/// mismatch assert!(false) panic); the fix removes M's snapshot
/// positionally first, so A restores with its pre-pop head (100).
#[test]
fn mirror_drop_orphan_snapshot_removed_before_retry_restore_15172() {
    let (mut binding, pre_pop_head_a, bucket_a, _m) = mirror_orphan_fixture_15172();
    let (items, batch_bytes, _pos_m) = build_mirror_batch_15172(&mut binding);
    fill_test_tx_ring_15172(&mut binding);
    let mut shared_recycles = Vec::new();
    let progress = submit_local(
        &mut binding,
        42,
        0,
        CoSServicePhase::Guarantee,
        batch_bytes,
        items,
        1_000_000_000,
        &mut shared_recycles,
    );
    assert!(!progress, "inserted==0 retry makes no progress");
    assert_eq!(
        binding
            .live
            .mirror_drops_tx_frame_reserve
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the middle mirror_clone must be dropped by the reserve gate",
    );
    let queue = &binding
        .cos
        .cos_interfaces
        .get(&42)
        .expect("cos root")
        .queues[0];
    let ff = test_flow_fair_state(queue);
    assert_eq!(ff.flow_bucket_items[bucket_a].len(), 1, "A restored");
    assert_eq!(
        ff.flow_bucket_head_finish_bytes[bucket_a], pre_pop_head_a,
        "#15172: A must restore with its OWN pre-pop head finish (100)",
    );
    assert!(
        ff.pop_snapshot_stack.is_empty(),
        "#15172: restore consumes every survivor snapshot",
    );
    assert_eq!(crate::afxdp::cos::queue_ops::cos_queue_len(queue), 2);
}

/// #15172 control: no mirror drop, same inserted==0 retry round-trips.
#[test]
fn no_mirror_drop_retry_restore_round_trips_15172_control() {
    let (mut binding, pre_pop_head_a, bucket_a, _m) = mirror_orphan_fixture_15172();
    let queue = &mut binding
        .cos
        .cos_interfaces
        .get_mut(&42)
        .expect("cos root")
        .queues[0];
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    let batch = build_cos_batch_from_queue(
        queue,
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("batch built");
    let (items, batch_bytes) = match batch {
        CoSBatch::Local {
            items, batch_bytes, ..
        } => (items, batch_bytes),
        CoSBatch::Prepared { .. } => unreachable!("Local items expected"),
    };
    fill_test_tx_ring_15172(&mut binding);
    let mut shared_recycles = Vec::new();
    let progress = submit_local(
        &mut binding,
        42,
        0,
        CoSServicePhase::Guarantee,
        batch_bytes,
        items,
        1_000_000_000,
        &mut shared_recycles,
    );
    assert!(!progress);
    assert_eq!(
        binding
            .live
            .mirror_drops_tx_frame_reserve
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "control: no mirror drop",
    );
    let queue = &binding
        .cos
        .cos_interfaces
        .get(&42)
        .expect("cos root")
        .queues[0];
    let ff = test_flow_fair_state(queue);
    assert_eq!(ff.flow_bucket_items[bucket_a].len(), 1);
    assert_eq!(ff.flow_bucket_head_finish_bytes[bucket_a], pre_pop_head_a);
    assert!(ff.pop_snapshot_stack.is_empty());
    assert_eq!(crate::afxdp::cos::queue_ops::cos_queue_len(queue), 3);
}

/// #15172 control: mirror drop with full commit — no restore occurs.
#[test]
fn mirror_drop_full_commit_no_restore_15172_control() {
    let (mut binding, _pre, _a, _m) = mirror_orphan_fixture_15172();
    let (items, batch_bytes, _pos_m) = build_mirror_batch_15172(&mut binding);
    let mut shared_recycles = Vec::new();
    let progress = submit_local(
        &mut binding,
        42,
        0,
        CoSServicePhase::Guarantee,
        batch_bytes,
        items,
        1_000_000_000,
        &mut shared_recycles,
    );
    assert!(progress, "full commit makes progress");
    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        2,
        "only the two survivors transmit",
    );
    assert_eq!(
        binding
            .live
            .mirror_drops_tx_frame_reserve
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
    );
    let queue = &binding
        .cos
        .cos_interfaces
        .get(&42)
        .expect("cos root")
        .queues[0];
    assert_eq!(crate::afxdp::cos::queue_ops::cos_queue_len(queue), 0);
}

/// #15172 control: positional removal on a FIFO queue is a no-op.
#[test]
fn orphan_removal_fifo_queue_noop_15172_control() {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 8 * 1024 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    assert!(!root.queues[0].flow_fair(), "control premise: FIFO queue");
    assert!(
        !crate::afxdp::cos::queue_ops::cos_queue_remove_orphan_snapshot_at(&mut root.queues[0], 0,),
        "FIFO queue has no snapshot to remove",
    );
}

// #15786 fixture: flow-fair queue (root 42, queue 0) loaded via REAL
// cos_queue_push_back with three Prepared items in distinct buckets:
// A(port 1111, 100B), BAD(port 2222, claimed len exceeds the UMEM frame
// capacity), B(port 3333, 200B). The UMEM frames for A/B are populated
// in the binding's own UMEM; BAD never reaches a frame (stage drops
// it on len). Returns (binding, pre_pop_head_a, bucket_a).
fn prepared_drop_fixture_15786() -> (BindingWorker, u64, usize) {
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "iperf-c".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: false,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    root.tokens = 10_000;
    root.queues[0].hot.tokens = 10_000;
    // queued_bytes is reconciled by the settle from batch_bytes
    // (100 + (capacity+1) + 200 at build); reset to the sent sum here
    // so the post-settle value is directly assertable.
    root.queues[0].hot.queued_bytes = 0;
    enable_test_flow_fair(&mut root.queues[0]);
    let off_a = 40u64 << crate::afxdp::UMEM_FRAME_SHIFT;
    let off_bad = 41u64 << crate::afxdp::UMEM_FRAME_SHIFT;
    let off_b = 42u64 << crate::afxdp::UMEM_FRAME_SHIFT;
    cos_queue_push_back(
        &mut root.queues[0],
        test_flow_prepared_cos_item(1111, 100, off_a),
    );
    cos_queue_push_back(
        &mut root.queues[0],
        test_flow_prepared_cos_item(
            2222,
            (crate::afxdp::tx_frame_capacity() + 1) as u32,
            off_bad,
        ),
    );
    cos_queue_push_back(
        &mut root.queues[0],
        test_flow_prepared_cos_item(3333, 200, off_b),
    );
    let seed = test_flow_fair_state(&root.queues[0]).flow_hash_seed;
    let bucket_a = cos_flow_bucket_index(seed, Some(&test_session_key(1111, 5201)));
    let bucket_bad = cos_flow_bucket_index(seed, Some(&test_session_key(2222, 5201)));
    let bucket_b = cos_flow_bucket_index(seed, Some(&test_session_key(3333, 5201)));
    assert!(
        bucket_a != bucket_bad && bucket_bad != bucket_b && bucket_a != bucket_b,
        "test premise: distinct buckets (a={bucket_a} bad={bucket_bad} b={bucket_b})",
    );
    let pre_pop_head_a =
        test_flow_fair_state(&root.queues[0]).flow_bucket_head_finish_bytes[bucket_a];
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        0,
        vec![(0, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);
    binding.telemetry.dbg_sendto_err = 100; // suppress wake eprintln
    for (off, len) in [(off_a, 100usize), (off_b, 200usize)] {
        let frame = unsafe { binding.umem.area().slice_mut_unchecked(off as usize, len) }
            .expect("umem frame slice");
        frame.fill(0);
    }
    for off in [off_a, off_bad, off_b] {
        binding.tx_pipeline.free_tx_frames.retain(|&o| o != off);
    }
    (binding, pre_pop_head_a, bucket_a)
}

// #15786 FAIL-ON-REVERT: batch [A, BAD(oversized), B] from a flow-fair
// queue. Pre-fix, stage drained + recycled ALL THREE frames and
// returned Err(Drop); submit then restored an EMPTY deque, leaving
// BAD's (and every) pop snapshot orphaned on the stack — the next
// build's LIFO restore would consume the wrong top entry
// (bucket-mismatch panic). Post-fix: A and B transmit, BAD alone is
// recycled + counted once, and no snapshot is orphaned.
#[test]
fn prepared_oversized_drops_only_offender_no_orphan_15786() {
    let (mut binding, _pre, _bucket_a) = prepared_drop_fixture_15786();
    let queue = &mut binding
        .cos
        .cos_interfaces
        .get_mut(&42)
        .expect("cos root")
        .queues[0];
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    let batch = build_cos_batch_from_queue(
        queue,
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("batch built");
    let (items, batch_bytes) = match batch {
        CoSBatch::Prepared {
            items, batch_bytes, ..
        } => (items, batch_bytes),
        CoSBatch::Local { .. } => unreachable!("Prepared items expected"),
    };
    assert_eq!(items.len(), 3, "test premise: three items built");
    let mut shared_recycles = Vec::new();
    let progress = submit_prepared(
        &mut binding,
        42,
        0,
        CoSServicePhase::Guarantee,
        batch_bytes,
        items,
        1_000_000_000,
        &mut shared_recycles,
    );
    assert!(progress, "the two valid frames must transmit");
    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        2,
        "only A and B transmit",
    );
    assert_eq!(
        binding
            .live
            .tx_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        300,
        "100 + 200 valid bytes",
    );
    assert_eq!(
        binding
            .live
            .tx_submit_error_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "exactly the offender counted once",
    );
    let off_bad = 41u64 << crate::afxdp::UMEM_FRAME_SHIFT;
    assert!(
        binding.tx_pipeline.free_tx_frames.contains(&off_bad),
        "BAD's frame recycled",
    );
    let queue = &binding
        .cos
        .cos_interfaces
        .get(&42)
        .expect("cos root")
        .queues[0];
    assert_eq!(
        crate::afxdp::cos::queue_ops::cos_queue_len(queue),
        0,
        "queue drained: survivors sent, offender dropped, none restored",
    );
    assert_eq!(
        test_flow_fair_state(queue).pop_snapshot_stack.len(),
        2,
        "only the two committed snapshots remain (cleared at next build); the dropped frame's snapshot was removed, not orphaned above them",
    );
    let dropped = binding.scratch.scratch_prepared_dropped_orig_idx.clone();
    assert_eq!(dropped.len(), 1, "one dropped original position");
    let committed = binding.scratch.scratch_prepared_committed_orig_idx.clone();
    assert_eq!(committed.len(), 2, "two committed original positions");
}

// #15786 FAIL-ON-REVERT (retry variant): same batch with a pre-filled
// TX ring forcing inserted==0. Pre-fix (collateral Drop) and a naive
// per-frame fix WITHOUT the snapshot unwind both leave BAD's snapshot
// on top of the stack, so A's LIFO restore consumes it →
// bucket-mismatch assert!(false) panic (or a wrong head restore).
// Post-fix: A and B restore with their own snapshots, BAD's is
// removed, and the stack empties exactly.
#[test]
fn prepared_oversized_retry_restore_no_orphan_15786() {
    let (mut binding, pre_pop_head_a, bucket_a) = prepared_drop_fixture_15786();
    let queue = &mut binding
        .cos
        .cos_interfaces
        .get_mut(&42)
        .expect("cos root")
        .queues[0];
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    let batch = build_cos_batch_from_queue(
        queue,
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("batch built");
    let (items, batch_bytes) = match batch {
        CoSBatch::Prepared {
            items, batch_bytes, ..
        } => (items, batch_bytes),
        CoSBatch::Local { .. } => unreachable!("Prepared items expected"),
    };
    fill_test_tx_ring_15172(&mut binding);
    let mut shared_recycles = Vec::new();
    let progress = submit_prepared(
        &mut binding,
        42,
        0,
        CoSServicePhase::Guarantee,
        batch_bytes,
        items,
        1_000_000_000,
        &mut shared_recycles,
    );
    assert!(!progress, "inserted==0 retry makes no progress");
    assert_eq!(
        binding
            .live
            .tx_submit_error_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the offender counted once even on the retry path",
    );
    let queue = &binding
        .cos
        .cos_interfaces
        .get(&42)
        .expect("cos root")
        .queues[0];
    let ff = test_flow_fair_state(queue);
    assert_eq!(ff.flow_bucket_items[bucket_a].len(), 1, "A restored");
    assert_eq!(
        ff.flow_bucket_head_finish_bytes[bucket_a], pre_pop_head_a,
        "#15786: A restores with its OWN pre-pop head finish",
    );
    assert!(
        ff.pop_snapshot_stack.is_empty(),
        "#15786: restore consumes every survivor snapshot; BAD's orphan was removed",
    );
    assert_eq!(crate::afxdp::cos::queue_ops::cos_queue_len(queue), 2);
}

// #15786 control: clean prepared batch (no invalid frame) — no drops,
// no snapshot removal, both frames transmit.
#[test]
fn prepared_clean_batch_no_drop_15786_control() {
    let (mut binding, _pre, _a) = prepared_drop_fixture_15786();
    // Rebuild without BAD: drain the fixture queue and enqueue two
    // clean prepared items directly through the queue.
    let queue = &mut binding
        .cos
        .cos_interfaces
        .get_mut(&42)
        .expect("cos root")
        .queues[0];
    let _ = crate::afxdp::cos::queue_ops::cos_queue_drain_all(queue);
    let off_a = 40u64 << crate::afxdp::UMEM_FRAME_SHIFT;
    let off_b = 42u64 << crate::afxdp::UMEM_FRAME_SHIFT;
    cos_queue_push_back(queue, test_flow_prepared_cos_item(1111, 100, off_a));
    cos_queue_push_back(queue, test_flow_prepared_cos_item(3333, 200, off_b));
    queue.hot.queued_bytes = 300;
    let mut local_scratch = VecDeque::new();
    let mut prepared_scratch = VecDeque::new();
    let batch = build_cos_batch_from_queue(
        queue,
        0,
        u64::MAX,
        u64::MAX,
        CoSServicePhase::Guarantee,
        &mut local_scratch,
        &mut prepared_scratch,
    )
    .expect("batch built");
    let (items, batch_bytes) = match batch {
        CoSBatch::Prepared {
            items, batch_bytes, ..
        } => (items, batch_bytes),
        CoSBatch::Local { .. } => unreachable!("Prepared items expected"),
    };
    let mut shared_recycles = Vec::new();
    let progress = submit_prepared(
        &mut binding,
        42,
        0,
        CoSServicePhase::Guarantee,
        batch_bytes,
        items,
        1_000_000_000,
        &mut shared_recycles,
    );
    assert!(progress);
    assert_eq!(
        binding
            .live
            .tx_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert_eq!(
        binding
            .live
            .tx_submit_error_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "control: no drops",
    );
    assert!(binding.scratch.scratch_prepared_dropped_orig_idx.is_empty());
}
