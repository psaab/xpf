use super::*;

#[test]
fn cos_queue_push_and_pop_track_flow_bucket_bytes() {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    let req_a = TxRequest {
        bytes: vec![0; 1500],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(test_session_key(1111, 5201)),
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };
    let req_b = TxRequest {
        bytes: vec![0; 1500],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(test_session_key(1112, 5201)),
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };
    let bucket_a = cos_flow_bucket_index(
        test_flow_fair_state(queue).flow_hash_seed,
        req_a.flow_key.as_ref(),
    );
    let bucket_b = cos_flow_bucket_index(
        test_flow_fair_state(queue).flow_hash_seed,
        req_b.flow_key.as_ref(),
    );
    assert_ne!(bucket_a, bucket_b);

    cos_queue_push_back(queue, CoSPendingTxItem::Local(req_a));
    cos_queue_push_back(queue, CoSPendingTxItem::Local(req_b));
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 2);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_a],
        1500
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_b],
        1500
    );

    let Some(CoSPendingTxItem::Local(req)) = cos_queue_pop_front(queue) else {
        panic!("expected first queued local request");
    };
    assert_eq!(req.flow_key.as_ref().map(|flow| flow.src_port), Some(1111));
    assert_eq!(test_flow_fair_state(queue).active_flow_buckets, 1);
    assert_eq!(test_flow_fair_state(queue).flow_bucket_bytes[bucket_a], 0);
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_bytes[bucket_b],
        1500
    );
}

/// Pin that `FlowRrRing::remove` correctly de-registers a bucket
/// from an arbitrary position. The MQFQ pop path calls this when
/// a bucket at non-head position (determined by finish-time, not
/// ring order) drains to empty.
#[test]
fn flow_rr_ring_remove_from_middle() {
    let mut ring = FlowRrRing::default();
    ring.push_back(10);
    ring.push_back(20);
    ring.push_back(30);
    ring.push_back(40);
    assert_eq!(ring.len(), 4);

    // Remove from the middle.
    assert!(ring.remove(20));
    assert_eq!(ring.len(), 3);
    let ids: Vec<u16> = ring.iter().collect();
    assert_eq!(ids, vec![10, 30, 40]);

    // Remove head-adjacent.
    assert!(ring.remove(10));
    assert_eq!(ring.len(), 2);
    let ids: Vec<u16> = ring.iter().collect();
    assert_eq!(ids, vec![30, 40]);

    // Remove missing (no-op).
    assert!(!ring.remove(999));
    assert_eq!(ring.len(), 2);

    // Remove tail.
    assert!(ring.remove(40));
    assert_eq!(ring.len(), 1);
    let ids: Vec<u16> = ring.iter().collect();
    assert_eq!(ids, vec![30]);

    // Remove last.
    assert!(ring.remove(30));
    assert_eq!(ring.len(), 0);
    assert!(ring.is_empty());
}

/// Pin the overflow bound on `flow_bucket_{head,tail}_finish_bytes`
/// by driving the ACTUAL runtime field near `u64::MAX` and
/// exercising the real enqueue path through
/// `cos_queue_push_back`/`account_cos_queue_flow_enqueue`.
///
/// Rust reviewer MEDIUM #2 (round-2): the prior revision
/// recomputed the wrap-interval math in the test body and
/// asserted `years_to_wrap > 40`. That is a calculator, not a
/// pin — a regression that narrowed the field to u32, or swapped
/// `saturating_add` for `+`, would have left this test green
/// because the test never touched the field. This revision:
///
///   1. Drives `test_flow_fair_state(queue).queue_vtime` to `u64::MAX - 10_000`.
///   2. Enqueues a 9000-byte packet (MTU-size upper bound).
///   3. Asserts the bucket's head/tail finish DID NOT wrap AND
///      landed at exactly `u64::MAX - 10_000 + 9_000`.
///   4. Enqueues again at u64::MAX-adjacent vtime and asserts
///      the saturating_add path keeps the field bounded.
///
/// A regression that changes the accumulator type to u32,
/// replaces `saturating_add` with `+`, or widens the per-enqueue
/// delta (e.g. by dividing by a small weight) will fail THIS
/// test, not a recomputed calculator.
#[test]
fn mqfq_finish_time_u64_has_decades_of_headroom() {
    let mut root = test_cos_runtime_with_queues(
        100_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 25_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    // Largest plausible single enqueue: MTU 9000 at weight 1.
    const MAX_SINGLE_DELTA: usize = 9_000;
    const SLACK: u64 = 10_000;
    let near_wrap = u64::MAX - SLACK;

    // Drive the runtime field near wrap by setting queue_vtime
    // (the re-anchor source for idle-bucket enqueue). The first
    // enqueue re-anchors head=tail=max(0, near_wrap)+9000 =
    // near_wrap + 9000 — well within u64 and exactly one delta
    // past queue_vtime.
    test_flow_fair_state_mut(queue).queue_vtime = near_wrap;

    let flow_a = test_session_key(9999, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&flow_a));

    cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
    let expected_first = near_wrap + MAX_SINGLE_DELTA as u64;
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        expected_first,
        "first enqueue near u64 wrap must anchor at queue_vtime \
         + bytes; regression to u32 or non-saturating add would \
         fail here with a wrapped or truncated value",
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        expected_first,
    );
    assert!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a] > near_wrap,
        "finish time did not advance past pre-enqueue vtime — \
         type narrowed or wrap occurred",
    );

    // Second enqueue onto the ACTIVE bucket: tail advances by
    // MAX_SINGLE_DELTA, but saturating_add caps at u64::MAX.
    // With near_wrap + 2*9000 = u64::MAX - 10_000 + 18_000 =
    // u64::MAX + 8_000 — this SHOULD saturate to u64::MAX.
    cos_queue_push_back(queue, test_flow_cos_item(9999, MAX_SINGLE_DELTA));
    let new_tail = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a];
    assert!(
        new_tail >= expected_first,
        "tail must monotonically advance; got {} < {}",
        new_tail,
        expected_first,
    );
    assert_eq!(
        new_tail,
        u64::MAX,
        "second enqueue must saturate at u64::MAX (input was \
         near_wrap + 2*9000 > u64::MAX); regression that replaces \
         saturating_add with `+` would panic on overflow in debug \
         builds or wrap in release builds",
    );

    // Head unchanged on active-bucket enqueue (head packet is
    // still the first one).
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        expected_first,
        "active-bucket enqueue must not alter head",
    );

    // Sanity-check the original calculator claim — 40+ years at
    // 100 Gbps — is still true. Kept alongside the real-field
    // pin above; the pin above is what would fail on regression.
    const WRAP_BYTES: u128 = 1u128 << 64;
    let bytes_per_sec: u128 = 100_000_000_000u128 / 8;
    let years_to_wrap = WRAP_BYTES / bytes_per_sec / 60 / 60 / 24 / 365;
    assert!(
        years_to_wrap > 40,
        "u64 finish-time headroom at 100 Gbps should exceed 40 \
         years of uptime, got {} years",
        years_to_wrap,
    );
}

