// Tests for afxdp/tx/cos_classify.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep cos_classify.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "cos_classify_tests.rs"]` from cos_classify.rs.

use super::*;
use crate::afxdp::tx::test_support::*;
use crate::afxdp::types::SharedCoSExactBacklog;
use crate::filter::TermMatchExtra;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSDSCPRewriteRuleEntrySnapshot, CoSDSCPRewriteRuleSnapshot, CoSForwardingClassSnapshot,
    CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSINetPrecedenceClassifierEntrySnapshot, CoSINetPrecedenceClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot,
};

// #hb166 T-4: an explicit request for a queue this interface does NOT
// materialize must fall back to the default (best-effort) queue — forward on
// best-effort, never blackhole. Pre-fix `resolve_cos_queue_idx` returned `None`
// for the miss, which the sole enqueue caller turned into an `Err` → drop
// (the 100% silent blackhole a BA classifier code-point steering to a
// forwarding-class with no scheduler-map entry produced).
//
// FAIL-ON-REVERT: restoring the pre-fix `position()`-returns-None body flips
// the `Some(4)`/`Some(9)` assertions to `None`.
#[test]
fn resolve_cos_queue_idx_falls_back_to_default_on_explicit_queue_miss() {
    let queue = |queue_id: u8, forwarding_class: &str| CoSQueueConfig {
        queue_id,
        forwarding_class: forwarding_class.into(),
        priority: 5,
        transmit_rate_bytes: 10_000_000,
        guarantee_enabled: true,
        exact: false,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        buffer_bytes: COS_MIN_BURST_BYTES,
        dscp_rewrite: None,
        codel_target_ns: 0,
    };
    // Materializes queue 0 (best-effort, the default) at index 0 and queue 5 at
    // index 1. Queue 9 is never built.
    let root = test_cos_runtime_with_queues(
        10_000_000,
        vec![queue(0, "best-effort"), queue(5, "voice")],
    );

    // Unmaterialized queue 9 -> default (best-effort) queue index, NOT None.
    assert_eq!(resolve_cos_queue_idx(&root, Some(9)), Some(0));
    // A materialized non-default queue still resolves to its own index.
    assert_eq!(resolve_cos_queue_idx(&root, Some(5)), Some(1));
    // No request -> default queue.
    assert_eq!(resolve_cos_queue_idx(&root, None), Some(0));
}

#[test]
fn enqueue_exact_queue_publishes_shared_backlog_slot() {
    let root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 125_000_000,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4_000_000,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let mut fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        4,
        vec![(4, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let shared_exact_backlog = Arc::new(SharedCoSExactBacklog::new(1));
    fast_interfaces
        .get_mut(&42)
        .expect("test fast path")
        .shared_exact_backlog = Some(shared_exact_backlog.clone());
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    assert!(
        enqueue_cos_item(
            &mut binding,
            42,
            Some(4),
            512,
            test_flow_cos_item(5201, 512),
            0,
            None,
        )
        .is_ok()
    );

    assert!(
        shared_exact_backlog.has_peer_backlog(1),
        "exact enqueue must publish immediately so peer workers do not undercount exact backlog",
    );
}

// #hb166 T-6(g): a CoS admission drop (buffer / flow-share exceeded) is
// DESIGNED shaping. It is attributed to the dedicated per-reason
// `admission_buffer_drops` / `admission_flow_share_drops` counters and must
// NOT also inflate the aggregate `tx_errors` (an operator reads a saturated
// shaper as a fault) nor allocate a per-drop `set_error(format!())` String.
//
// FAIL-ON-REVERT: restoring the `tx_errors.fetch_add(1)` on the CoS
// admission-overflow path flips the `tx_errors == 0` assertion.
#[test]
fn cos_admission_drop_counts_dedicated_counter_not_tx_errors() {
    // FIFO (non-flow-fair) queue with a small buffer so accumulated
    // queued bytes exceed the buffer limit without any drain.
    let root = test_cos_runtime_with_queues(
        10_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000,
            guarantee_enabled: false,
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

    // Push 1500-byte items without draining until the buffer limit trips.
    // 400 * 1500 = 600 KB dwarfs any COS_MIN_BURST_BYTES-derived limit.
    for _ in 0..400 {
        let _ = enqueue_cos_item(
            &mut binding,
            42,
            Some(0),
            1500,
            test_flow_cos_item(5201, 1500),
            0,
            None,
        );
    }

    let buffer_drops = binding
        .cos
        .cos_interfaces
        .get(&42)
        .and_then(|root| root.queues.first())
        .map(|q| q.telemetry.drop_counters.admission_buffer_drops)
        .expect("queue present");
    assert!(
        buffer_drops > 0,
        "test premise: the buffer cap must trip at least one admission drop",
    );
    assert_eq!(
        binding.live.tx_errors.load(Ordering::Relaxed),
        0,
        "a designed CoS admission (shaping) drop must NOT inflate tx_errors",
    );
    // The #804 disambiguation debug counter still records the overflow.
    assert!(binding.telemetry.dbg_cos_queue_overflow > 0);
}

#[test]
fn clone_prepared_request_for_cos_returns_local_copy_with_metadata() {
    let mut area = MmapArea::new(4096).expect("mmap");
    let payload = [0xde, 0xad, 0xbe, 0xef];
    area.slice_mut(128, payload.len())
        .expect("slice")
        .copy_from_slice(&payload);
    let mut req = PreparedTxRequest {
        offset: 128,
        len: payload.len() as u32,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: Some((1111, 2222)),
        expected_addr_family: libc::AF_INET6 as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1111,
            dst_port: 2222,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: Some(46),
        mirror_clone: true,
        overlap_admissions: None,
        enqueue_ns: 0,
    };

    let local = clone_prepared_request_for_cos(&area, &mut req).expect("local copy");

    assert_eq!(local.bytes, payload);
    assert_eq!(local.expected_ports, Some((1111, 2222)));
    assert_eq!(local.expected_addr_family, libc::AF_INET6 as u8);
    assert_eq!(local.expected_protocol, PROTO_TCP);
    assert_eq!(local.egress_ifindex, 80);
    assert_eq!(local.cos_queue_id, Some(4));
    assert_eq!(local.dscp_rewrite, Some(46));
    assert!(local.mirror_clone);
    assert_eq!(
        local
            .flow_key
            .as_ref()
            .map(|key| (key.src_port, key.dst_port)),
        Some((1111, 2222))
    );
}

#[test]
fn clone_prepared_request_for_cos_rejects_out_of_range_offset() {
    let area = MmapArea::new(256).expect("mmap");
    let mut req = PreparedTxRequest {
        offset: 1024,
        len: 64,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };

    assert!(clone_prepared_request_for_cos(&area, &mut req).is_none());
}

#[test]
fn prepare_local_request_for_cos_preserves_mirror_tx_frame_reserve() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut free_tx_frames = (0..MIRROR_TX_FRAME_RESERVE as u64)
        .map(|idx| idx << UMEM_FRAME_SHIFT)
        .collect::<VecDeque<_>>();
    let original_free = free_tx_frames.clone();
    let req = TxRequest {
        bytes: vec![1, 2, 3, 4],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: None,
        mirror_clone: true,
        overlap_admissions: None,
        enqueue_ns: 0,
    };

    let req = match prepare_local_request_for_cos(&area, &mut free_tx_frames, req) {
        Ok(_) => panic!("mirror clones must not consume the last reserved TX frames"),
        Err(req) => req,
    };

    assert!(req.mirror_clone);
    assert_eq!(free_tx_frames, original_free);
}

#[test]
fn prepare_local_request_for_cos_materializes_prepared_frame() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut free_tx_frames = VecDeque::from([128]);
    let req = TxRequest {
        bytes: vec![0xde, 0xad, 0xbe, 0xef],
        expected_ports: Some((1111, 2222)),
        expected_addr_family: libc::AF_INET6 as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1111,
            dst_port: 2222,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: Some(46),
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };

    let prepared =
        prepare_local_request_for_cos(&area, &mut free_tx_frames, req).expect("prepared");

    assert_eq!(prepared.offset, 128);
    assert_eq!(prepared.len, 4);
    assert_eq!(prepared.recycle, PreparedTxRecycle::FreeTxFrame);
    assert_eq!(prepared.expected_ports, Some((1111, 2222)));
    assert_eq!(prepared.egress_ifindex, 80);
    assert_eq!(prepared.cos_queue_id, Some(5));
    assert_eq!(prepared.dscp_rewrite, Some(46));
    assert!(free_tx_frames.is_empty());
    assert_eq!(area.slice(128, 4).expect("slice"), [0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn prepare_local_request_for_cos_falls_back_when_no_free_tx_frame_exists() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut free_tx_frames = VecDeque::new();
    let req = TxRequest {
        bytes: vec![1, 2, 3, 4],
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
    };

    let req = match prepare_local_request_for_cos(&area, &mut free_tx_frames, req) {
        Ok(_) => panic!("must fall back to local"),
        Err(req) => req,
    };

    assert_eq!(req.bytes, [1, 2, 3, 4]);
    assert!(free_tx_frames.is_empty());
}

#[test]
fn cos_queue_accepts_prepared_when_queue_is_prepared_only() {
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
            overlap_admissions: None,
            enqueue_ns: 0,
        }));

    assert!(cos_queue_accepts_prepared(&root, Some(5)));
}

#[test]
fn demote_prepared_cos_queue_to_local_recycles_frames_and_blocks_prepared_appends() {
    let area = MmapArea::new(4096).expect("mmap");
    unsafe { area.slice_mut_unchecked(64, 4) }
        .expect("frame")
        .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    unsafe { area.slice_mut_unchecked(128, 4) }
        .expect("frame")
        .copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

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
            len: 4,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: Some((1111, 5202)),
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 128,
            len: 4,
            recycle: PreparedTxRecycle::FillOnSlot(7),
            expected_ports: Some((1112, 5202)),
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));

    let mut free_tx_frames = VecDeque::from([512]);
    let mut pending_fill_frames = VecDeque::new();
    assert!(demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut root,
        Some(5),
        None,
    ));

    let items = root.queues[0]
        .hot
        .items
        .iter()
        .map(|item| match item {
            CoSPendingTxItem::Local(req) => req.bytes.clone(),
            CoSPendingTxItem::Prepared(_) => panic!("prepared item should be demoted"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        items,
        vec![vec![0xde, 0xad, 0xbe, 0xef], vec![0xca, 0xfe, 0xba, 0xbe]]
    );
    assert_eq!(free_tx_frames, VecDeque::from([512, 64]));
    assert_eq!(pending_fill_frames, VecDeque::from([128]));
    assert!(!cos_queue_accepts_prepared(&root, Some(5)));
}

/// #926: regression test for the success-path
/// queue_vtime / head-finish preservation. Prepared items
/// across multiple flows are queued, demoted to Local, and
/// the MQFQ frontier (queue_vtime + per-bucket head/tail
/// finish-times) MUST be unchanged. A new flow Y enqueued
/// immediately after demotion MUST anchor at a finish-time
/// that respects the demoted backlog's frontier — i.e. Y
/// cannot jump ahead of the demoted backlog.
#[test]
fn demote_prepared_cos_queue_to_local_preserves_mqfq_frontier() {
    let area = MmapArea::new(4096).expect("mmap");
    unsafe { area.slice_mut_unchecked(64, 4) }
        .expect("frame")
        .copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    unsafe { area.slice_mut_unchecked(128, 4) }
        .expect("frame")
        .copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
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

    // Two distinct flows, each one Prepared item. Bucket
    // indices computed under flow_hash_seed=0 for use in
    // post-demote frontier assertions.
    let key_a = test_session_key(8001, 5201);
    let key_b = test_session_key(8002, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&key_a));
    let bucket_b = cos_flow_bucket_index(0, Some(&key_b));
    assert_ne!(
        bucket_a, bucket_b,
        "test setup: ports 8001/8002 must hash to distinct buckets"
    );

    cos_queue_push_back(
        queue,
        CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(key_a.clone()),
            egress_ifindex: 42,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }),
    );
    cos_queue_push_back(
        queue,
        CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 128,
            len: 1500,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(key_b.clone()),
            egress_ifindex: 42,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }),
    );

    // Snapshot pre-demote MQFQ frontier.
    let pre_vtime = test_flow_fair_state(queue).queue_vtime;
    let pre_head_a = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a];
    let pre_head_b = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b];
    let pre_tail_a = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a];
    let pre_tail_b = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b];
    assert!(pre_head_a > 0);
    assert!(pre_head_b > 0);

    // Demote (success path).
    let mut free_tx_frames = VecDeque::from([512]);
    let mut pending_fill_frames = VecDeque::new();
    assert!(demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut root,
        Some(4),
        None,
    ));

    let queue = &mut root.queues[0];

    // Frontier MUST be unchanged across the success path.
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        pre_vtime,
        "#926 regression: queue_vtime must be preserved across \
         demote success path. Pre={pre_vtime} post={}",
        test_flow_fair_state(queue).queue_vtime
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        pre_head_a,
        "#926: head_finish[A] must be preserved (pre={pre_head_a})"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        pre_head_b,
        "#926: head_finish[B] must be preserved (pre={pre_head_b})"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        pre_tail_a,
        "#926: tail_finish[A] must be preserved"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b],
        pre_tail_b,
        "#926: tail_finish[B] must be preserved"
    );

    // Items now Local. flow_fair=true stores items in
    // per-bucket VecDeques at `flow_bucket_items[bucket]`,
    // not in `queue.hot.items`.
    let mut total_items = 0;
    for bucket in [bucket_a, bucket_b] {
        for item in test_flow_fair_state(queue).flow_bucket_items[bucket].iter() {
            assert!(
                matches!(item, CoSPendingTxItem::Local(_)),
                "demote should convert Prepared → Local"
            );
            total_items += 1;
        }
    }
    assert_eq!(total_items, 2);

    // The frontier-preservation assertions above are the
    // load-bearing test (Codex code review caught that an
    // earlier "Y does not jump ahead" assertion was
    // logically muddled — without the fix, the four
    // assert_eq calls already FAIL at the queue_vtime / head /
    // tail checks; demote_prepared without snapshot/restore
    // leaves queue_vtime=3000 and head_a=head_b=4500, all
    // mismatching the captured pre-state). The Y-anchor
    // behavior at this scenario is identical with-or-without
    // the fix (Y is small enough to anchor below A/B in
    // both cases) so it's not a useful gate.
}

#[test]
fn demote_failure_preserves_mqfq_frontier_across_buckets_9066() {
    // #9066: the FAILURE path's sibling of
    // demote_prepared_cos_queue_to_local_preserves_mqfq_frontier above.
    //
    // The two early returns called cos_queue_restore_front and dropped the
    // saved frontier, justified by a comment saying that rollback is
    // "round-trip neutral per #913 §3.7". That is true for ONE bucket and
    // false for several: each bucket's frontier comes back inflated by the
    // bytes of the OTHER buckets drained ahead of its own last item
    // (measured +4200/+2700/+3300 on three flows). vtime round-trips and
    // relative order survives, so this is not corrupt state — it is a
    // NEWCOMER anchoring at vtime + bytes and being served ahead of the whole
    // restored backlog, which is #926's temporal inversion left open on the
    // failure path.
    //
    // The existing single-bucket cell
    // mqfq_push_front_is_neutral_on_drained_bucket_round_trip CANNOT see this
    // by construction: with one bucket there are no others to drain ahead of
    // it, so the neutrality it asserts is real and irrelevant.
    let area = MmapArea::new(4096).expect("mmap");
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "ff".into(),
            priority: 4,
            transmit_rate_bytes: 10_000_000_000 / 8,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: true,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let queue = &mut root.queues[0];
    enable_test_flow_fair(queue);

    let key_a = test_session_key(8001, 5201);
    let key_b = test_session_key(8002, 5201);
    let bucket_a = cos_flow_bucket_index(0, Some(&key_a));
    let bucket_b = cos_flow_bucket_index(0, Some(&key_b));
    assert_ne!(
        bucket_a, bucket_b,
        "test setup: ports 8001/8002 must hash to distinct buckets — with one \
         bucket this cell degenerates into the single-bucket case it exists to \
         distinguish itself from"
    );

    for (offset, key) in [(64u64, &key_a), (128u64, &key_b)] {
        cos_queue_push_back(
            queue,
            CoSPendingTxItem::Prepared(PreparedTxRequest {
                offset,
                len: 1500,
                recycle: PreparedTxRecycle::FreeTxFrame,
                expected_ports: None,
                expected_addr_family: libc::AF_INET as u8,
                expected_protocol: PROTO_TCP,
                flow_key: Some(key.clone()),
                egress_ifindex: 42,
                cos_queue_id: Some(4),
                dscp_rewrite: None,
                mirror_clone: false,
                overlap_admissions: None,
                enqueue_ns: 0,
            }),
        );
    }

    // The COMMON trigger, not the rare one: a Local item in the queue makes
    // drain_all yield a non-Prepared item and takes the `else` arm. The issue
    // records that the source finding treated this as an aside and named the
    // rarer clone failure as the trigger.
    cos_queue_push_back(
        queue,
        CoSPendingTxItem::Local(TxRequest {
            bytes: vec![0u8; 1500],
            expected_ports: None,
            expected_addr_family: libc::AF_INET as u8,
            expected_protocol: PROTO_TCP,
            flow_key: Some(key_a.clone()),
            egress_ifindex: 42,
            cos_queue_id: Some(4),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }),
    );

    let pre_vtime = test_flow_fair_state(queue).queue_vtime;
    let pre_head_a = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a];
    let pre_head_b = test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b];
    let pre_tail_a = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a];
    let pre_tail_b = test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b];
    assert!(
        pre_head_a > 0 && pre_head_b > 0,
        "fixture: both buckets must carry a frontier, else the assertions below \
         compare zero to zero and pass no matter what the code does"
    );

    let mut free_tx_frames = VecDeque::from([512]);
    let mut pending_fill_frames = VecDeque::new();
    let demoted = demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut root,
        Some(4),
        None,
    );
    assert!(
        !demoted,
        "fixture: the demote must FAIL for this cell to exercise the rollback \
         path at all; a success here means the Local item did not take the \
         `else` arm and every assertion below is measuring the success path"
    );

    let queue = &mut root.queues[0];
    assert_eq!(
        test_flow_fair_state(queue).queue_vtime,
        pre_vtime,
        "#9066: queue_vtime must round-trip across the demote FAILURE path"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_a],
        pre_head_a,
        "#9066: head_finish[A] inflated by the rollback. cos_queue_restore_front \
         is round-trip neutral for ONE bucket only; across several, this bucket \
         comes back carrying the bytes of the others drained ahead of it, and a \
         flow arriving next anchors at vtime + bytes and jumps the whole \
         restored backlog (#926's inversion, on the failure path)"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_head_finish_bytes[bucket_b],
        pre_head_b,
        "#9066: head_finish[B] inflated by the rollback"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_a],
        pre_tail_a,
        "#9066: tail_finish[A] inflated by the rollback"
    );
    assert_eq!(
        test_flow_fair_state(queue).flow_bucket_tail_finish_bytes[bucket_b],
        pre_tail_b,
        "#9066: tail_finish[B] inflated by the rollback"
    );
}

#[test]
fn demote_prepared_cos_queue_to_local_skips_non_exact_queue() {
    let area = MmapArea::new(4096).expect("mmap");
    unsafe { area.slice_mut_unchecked(64, 4) }
        .expect("frame")
        .copy_from_slice(&[1, 2, 3, 4]);

    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "iperf-b".into(),
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
    root.queues[0]
        .hot
        .items
        .push_back(CoSPendingTxItem::Prepared(PreparedTxRequest {
            offset: 64,
            len: 4,
            recycle: PreparedTxRecycle::FreeTxFrame,
            expected_ports: None,
            expected_addr_family: libc::AF_INET6 as u8,
            expected_protocol: PROTO_TCP,
            flow_key: None,
            egress_ifindex: 80,
            cos_queue_id: Some(5),
            dscp_rewrite: None,
            mirror_clone: false,
            overlap_admissions: None,
            enqueue_ns: 0,
        }));

    let mut free_tx_frames = VecDeque::new();
    let mut pending_fill_frames = VecDeque::new();
    assert!(!demote_prepared_cos_queue_to_local(
        &area,
        &mut free_tx_frames,
        &mut pending_fill_frames,
        7,
        &mut root,
        Some(5),
        None,
    ));
    assert!(matches!(
        root.queues[0].hot.items.front(),
        Some(CoSPendingTxItem::Prepared(_))
    ));
    assert!(free_tx_frames.is_empty());
    assert!(pending_fill_frames.is_empty());
}

#[test]
fn resolve_cos_queue_id_prefers_egress_output_filter_forwarding_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-classify".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![
            FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "best-effort".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "wan-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );

    assert_eq!(queue_id, Some(1));
}

// #hb166 T-6(m): fragments / flowless packets (flow_key == None) still carry
// a DSCP. Behavior-aggregate (DSCP) classification is 5-tuple-independent, so
// a marked fragment must land in its BA queue rather than the default queue.
//
// FAIL-ON-REVERT: restoring the `queue_id: iface.map(|i| i.default_queue)`
// None-branch (in BOTH resolve_cos_tx_selection_internal and
// resolve_cached_cos_tx_selection) flips the dscp==46 assertions from
// Some(1) back to Some(0).
#[test]
fn flowless_packet_gets_ba_classification_from_dscp() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            cos_dscp_classifier: "ba".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "ba".into(),
                entries: vec![CoSDSCPClassifierEntrySnapshot {
                    forwarding_class: "expedited-forwarding".into(),
                    loss_priority: String::new(),
                    dscp_values: vec![46],
                }],
            }],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let ef_meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        dscp: 46,
        ..Default::default()
    };
    let be_meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        dscp: 0,
        ..Default::default()
    };

    // Non-cached path (resolve_cos_tx_selection_internal via resolve_cos_queue_id).
    assert_eq!(
        resolve_cos_queue_id(&forwarding, 202, ef_meta, None),
        Some(1),
        "EF-marked flowless packet must hit the BA (EF) queue, not the default",
    );
    assert_eq!(
        resolve_cos_queue_id(&forwarding, 202, be_meta, None),
        Some(0),
        "an unmarked flowless packet falls back to the default queue",
    );

    // Cached-descriptor path.
    assert_eq!(
        resolve_cached_cos_tx_queue_id(&forwarding, 202, ef_meta, None),
        Some(1),
        "cached flowless BA classification must also hit the EF queue",
    );

    // #8367 WIRING: the port-mirror path is the caller this entry point exists
    // for, and it must reach the SAME queue. Asserting only the entry point
    // leaves `mirror_cos_queue_id` free to be re-pointed at anything —
    // including back at the descriptor arm whose filter verdict it discards.
    assert_eq!(
        crate::afxdp::mirror::mirror_cos_queue_id(
            &forwarding,
            202,
            crate::afxdp::types::ForwardPacketMeta::from(ef_meta),
            None
        ),
        Some(1),
        "#8367: a FLOWLESS mirror clone must resolve the same BA queue the cached \
         entry point does — the split is queue-preserving by construction"
    );
    assert_eq!(
        crate::afxdp::mirror::mirror_cos_queue_id(
            &forwarding,
            202,
            crate::afxdp::types::ForwardPacketMeta::from(be_meta),
            None
        ),
        Some(0),
        "#8367: and an unmarked flowless mirror clone still falls back to the \
         interface default queue"
    );
}

#[test]
fn resolve_cos_queue_id_uses_reverse_output_source_port_filter() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0-0-1.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:61:01".into(),
            filter_output_v4: "bandwidth-output-reverse".into(),
            cos_shaping_rate_bytes_per_sec: 25_000_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "bandwidth-limit".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "bandwidth-output-reverse".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "iperf-a-reverse".into(),
                protocols: vec!["tcp".into()],
                source_ports: vec!["5201".into()],
                action: "accept".into(),
                count: "iperf-a-reverse".into(),
                forwarding_class: "iperf-a".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "iperf-a".into(),
                    queue: 4,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "scheduler-be".into(),
                    transmit_rate_bytes: 100_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "scheduler-iperf-a".into(),
                    transmit_rate_bytes: 1_000_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "bandwidth-limit".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "scheduler-be".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-a".into(),
                        scheduler: "scheduler-iperf-a".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let reverse_data = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 80,
            ingress_vlan_id: 80,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            src_port: 5201,
            dst_port: 49152,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );
    let forward_shape_on_reverse_egress = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 80,
            ingress_vlan_id: 80,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            src_port: 49152,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );

    assert_eq!(reverse_data, Some(4));
    assert_eq!(forward_shape_on_reverse_egress, Some(0));
}

#[test]
fn resolve_cached_cos_tx_selection_prefers_egress_output_filter_and_keeps_counter() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-classify".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![
            FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "best-effort".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "wan-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "wan-hits".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let cached = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        &SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    );

    assert_eq!(cached.queue_id, Some(1));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(!cached.filter_counters.is_empty());
}

#[test]
fn resolve_cos_queue_id_uses_ingress_input_filter_when_no_output_filter_exists() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "cos-classify".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "voice".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                forwarding_class: "expedited-forwarding".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );

    assert_eq!(queue_id, Some(1));
}

#[test]
fn resolve_cached_cos_tx_selection_uses_ingress_input_filter_when_no_output_exists() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "cos-classify".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "voice".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "lan-hits".into(),
                forwarding_class: "expedited-forwarding".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let cached = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        &SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    );

    assert_eq!(cached.queue_id, Some(1));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(!cached.filter_counters.is_empty());
}

// #5158: the ingress INPUT filter matched the packet on its PRE-NAT ingress
// tuple (Junos applies input filters BEFORE NAT). The transit forward path
// (`forward_request` / `neighbor_dispatch` / the `flow_cache` seed) builds a
// POST-NAT `forward_wire_key` for the egress OUTPUT filter + TX selection
// (#3642), then hands it to the CoS resolver. Before this fix that SAME post-NAT
// key was reused for the ingress input-filter re-walk, so a NAT'd flow's ingress
// `then forwarding-class` / dscp-rewrite / three-color policer was evaluated
// against the post-NAT addresses/ports and MISSED. The split entry points
// (`resolve_cos_tx_selection_at_prenat` / `resolve_cached_cos_tx_selection_prenat`)
// re-walk the ingress filter on the pre-NAT `ingress_flow_key` while keeping the
// output filter on the post-NAT egress wire key.
//
// FAIL-ON-REVERT: the ingress term matches destination-port 443; the modelled
// DNAT rewrote the egress wire key's destination port to 8443. Feeding the
// pre-NAT key (dst 443) to the re-walk hits the EF forwarding-class (queue 1);
// reusing the post-NAT egress key (dst 8443) misses the term and falls back to
// the default queue (0). Reverting the fix (re-walk on the post-NAT key) flips
// the `Some(1)` assertions to `Some(0)`.
#[test]
fn ingress_input_filter_rewalk_uses_prenat_key_5158() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "cos-classify".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "voice".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                forwarding_class: "expedited-forwarding".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        ingress_vlan_id: 0,
        addr_family: libc::AF_INET as u8,
        dscp: 0,
        ..Default::default()
    };
    // PRE-NAT ingress tuple — destination-port 443, matches the ingress term.
    let ingress_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    // POST-NAT egress wire tuple — DNAT rewrote the destination port to 8443, so
    // it no longer matches the ingress term's destination-port 443.
    let egress_wire_key = SessionKey {
        dst_port: 8443,
        ..ingress_key.clone()
    };
    let now_ns = 1_000_000u64;

    // Runtime path: the ingress re-walk MUST use the pre-NAT key -> EF queue 1.
    let runtime = resolve_cos_tx_selection_at_prenat(
        &forwarding,
        202,
        meta,
        Some(&egress_wire_key),
        Some(&ingress_key),
        TermMatchExtra::default(),
        now_ns,
        None,
    );
    assert_eq!(
        runtime.queue_id,
        Some(1),
        "runtime ingress input-filter re-walk must match the PRE-NAT tuple (dst 443)",
    );

    // Cached-seed path: same contract.
    let cached = resolve_cached_cos_tx_selection_prenat(
        &forwarding,
        202,
        meta,
        &egress_wire_key,
        &ingress_key,
    );
    assert_eq!(
        cached.queue_id,
        Some(1),
        "cached ingress input-filter re-walk must match the PRE-NAT tuple (dst 443)",
    );

    // Positive control: reusing the POST-NAT egress key for the ingress re-walk
    // (the pre-#5158 behaviour) misses the term (dst 8443) and falls back to the
    // default queue. Proves the assertions above bind to the pre-NAT tuple.
    let reverted_runtime = resolve_cos_tx_selection_at_prenat(
        &forwarding,
        202,
        meta,
        Some(&egress_wire_key),
        Some(&egress_wire_key),
        TermMatchExtra::default(),
        now_ns,
        None,
    );
    assert_eq!(
        reverted_runtime.queue_id,
        Some(0),
        "post-NAT key misses the ingress term -> default queue (documents the bug)",
    );
    let reverted_cached = resolve_cached_cos_tx_selection_prenat(
        &forwarding,
        202,
        meta,
        &egress_wire_key,
        &egress_wire_key,
    );
    assert_eq!(reverted_cached.queue_id, Some(0));
}

#[test]
fn resolve_cached_cos_tx_selection_keeps_counter_only_output_filter_hits() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-count".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-count".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-only".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "wan-hits".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 4_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let cached = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        &SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    );

    assert_eq!(cached.queue_id, Some(0));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(!cached.filter_counters.is_empty());
}

#[test]
fn resolve_cos_tx_selection_counts_counter_only_output_filter_hits() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-count".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-count".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-only".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "wan-hits".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 4_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            pkt_len: 1514,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, Some(0));
    assert_eq!(selection.dscp_rewrite, None);

    let filter = forwarding
        .filter_state
        .filters
        .get("inet:wan-count")
        .expect("inet output filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(term.counter.packets.load(Ordering::Relaxed), 1);
    assert_eq!(term.counter.bytes.load(Ordering::Relaxed), 1514);
}

#[test]
fn resolve_cos_tx_selection_drops_terminal_output_filter_without_log() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            dscp: 0,
            pkt_len: 1514,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        TermMatchExtra::default(),
    );

    assert!(selection.drop);
    // #3608: `then discard` is a SILENT drop — it must NOT be flagged as a
    // reject, so no active reply is synthesized for it.
    assert!(!selection.reject, "then discard must not be a reject");
    assert_eq!(selection.queue_id, None);
    assert_eq!(selection.filter_log, None);
}

#[test]
fn resolve_cos_tx_selection_drops_reject_output_filter_without_log() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-reject".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-reject".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "reject".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            dscp: 0,
            pkt_len: 1514,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        TermMatchExtra::default(),
    );

    assert!(selection.drop);
    // #3608 RED-on-revert: `then reject` must be flagged as a reject (distinct
    // from `then discard`) so the TX/CoS consumer synthesizes the active reply
    // instead of a silent drop.
    assert!(selection.reject, "then reject must set the reject flag");
    assert_eq!(selection.queue_id, None);
    assert_eq!(selection.filter_log, None);
}

// #5467: build a UserspaceDpMeta for a FLOWLESS packet (non-first fragment /
// non-query ICMP) — the shim stamps the L3 addresses but there is NO usable L4
// header, so it reaches `resolve_cos_tx_selection` with `flow_key = None`. The
// output-filter enforcement gate must reconstruct the L3 tuple from the meta.
fn flowless_v4_meta(dst: [u8; 4]) -> UserspaceDpMeta {
    let mut flow_src_addr = [0u8; 16];
    let mut flow_dst_addr = [0u8; 16];
    flow_src_addr[..4].copy_from_slice(&[10, 0, 61, 100]);
    flow_dst_addr[..4].copy_from_slice(&dst);
    UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        dscp: 0,
        pkt_len: 1514,
        // A non-first fragment carries NO L4 header: ports absent (0) and
        // `l4_present = false` so port-bearing terms fail closed.
        flow_src_addr,
        flow_dst_addr,
        ..Default::default()
    }
}

/// #8367: the POST-NAT on-wire L3 key that the cached flowless entry point now
/// REQUIRES alongside `flowless_v4_meta`.
///
/// These fixtures are NON-NAT, so the post-NAT tuple IS the meta tuple with
/// ports 0 — bit-identical to what `l3_wire_session_flow_from_meta` produces
/// when the packet's `NatDecision` rewrites nothing. Every cell migrated onto
/// this helper therefore keeps asserting exactly what it asserted while the key
/// was implicit; the NAT'd case (where the two tuples differ, and the point of
/// #8367) is covered by `cached_flowless_output_filter_matches_the_postnat_*`.
fn flowless_v4_wire_key(dst: [u8; 4]) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
        // A flowless packet has no L4 header (#2344/#3290); the cached flowless
        // arm evaluates through the PORTLESS evaluator (#7992) and never reads
        // these.
        src_port: 0,
        dst_port: 0,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

// #5467: the frame-derived per-packet match inputs for a flowless (non-first
// fragment) packet — L4 absent, is-fragment set.
fn flowless_extra() -> TermMatchExtra<'static> {
    TermMatchExtra {
        is_fragment: true,
        l4_present: false,
        ..Default::default()
    }
}

#[test]
fn resolve_cos_tx_selection_flowless_enforces_output_discard() {
    // #5467 RED-on-revert: a flowless packet (flow_key = None) whose L3 tuple
    // matches an interface output `then discard` term MUST fail CLOSED. Before
    // the fix the flowless early-return skipped output-filter evaluation and
    // returned drop:false — a silent egress deny bypass (fail-OPEN).
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop-l3".into(),
            family: "inet".into(),
            // L3-only term (address + protocol, NO ports) so it matches a
            // flowless packet whose L4 ports are absent (0).
            terms: vec![FirewallTermSnapshot {
                name: "drop-host".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec!["tcp".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    // Flowless packet whose L3 dst MATCHES the deny term → fail closed.
    let matched = resolve_cos_tx_selection(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        None,
        flowless_extra(),
    );
    assert!(
        matched.drop,
        "#5467: a flowless packet matching an output `then discard` term must drop"
    );
    assert!(!matched.reject, "then discard is a silent drop, not a reject");
    assert_eq!(matched.filter_log, None);

    // Control: a flowless packet that does NOT match any deny term still
    // egresses (pass-through unchanged, #2357/#3290 preserved).
    let unmatched = resolve_cos_tx_selection(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 201]),
        None,
        flowless_extra(),
    );
    assert!(
        !unmatched.drop,
        "#5467: a flowless packet not matching any deny term must NOT drop"
    );
}

#[test]
fn resolve_cos_tx_selection_flowless_enforces_output_reject() {
    // #5467 RED-on-revert: a flowless packet matching an output `then reject`
    // term must set drop:true AND reject:true (the caller keeps the reject
    // reply silent for a flowless packet — no L4 to synthesize from — but the
    // packet is still denied).
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-reject-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-reject-l3".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-host".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec!["tcp".into()],
                action: "reject".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        None,
        flowless_extra(),
    );
    assert!(selection.drop, "#5467: flowless `then reject` must drop");
    assert!(
        selection.reject,
        "#5467: flowless `then reject` must set the reject flag"
    );
}

#[test]
fn resolve_cos_tx_selection_flowless_enforces_output_log() {
    // #5467 RED-on-revert: a flowless packet matching an output `then log`
    // term must surface the filter-log match (before the fix filter_log was
    // always None on the flowless path — the log was silently bypassed).
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-log-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-log-l3".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "log-host".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec!["tcp".into()],
                action: "accept".into(),
                log: true,
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        None,
        flowless_extra(),
    );
    assert!(
        selection.filter_log.is_some(),
        "#5467: a flowless packet matching an output `then log` term must log"
    );
    assert!(
        !selection.drop,
        "a `then accept` + log term must not drop the packet"
    );
}

#[test]
fn resolve_cos_tx_selection_flowless_port_term_does_not_spuriously_drop() {
    // #5467 / #2357 / #3290: the flowless output-filter gate matches on the L3
    // tuple with ports FORCED TO 0, so a port-BEARING terminal term never
    // matches a fragment — it must NOT be spuriously dropped. This guards the
    // fix from over-dropping legitimate flowless traffic.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop-port".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop-port".into(),
            family: "inet".into(),
            // Port-bearing terminal term: a flowless packet (port 0, L4 absent)
            // must NOT match it.
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        None,
        flowless_extra(),
    );
    assert!(
        !selection.drop,
        "#5467: a port-bearing output term must NOT drop a flowless (port 0) packet"
    );
}

#[test]
fn resolve_cached_cos_tx_selection_flowless_enforces_output_discard() {
    // #6055 RED-on-revert: the CACHED flowless arm (`resolve_cached_cos_tx_selection`
    // with flow_key = None) must honor an interface output `then discard` term
    // against a flowless packet's L3 tuple, exactly like the #5467 fix on the
    // non-cached `_at` arm. Before this fix the cached flowless arm returned
    // drop:false WITHOUT evaluating the output filter at all — a LATENT
    // fail-open. Reverting the hardening back to an unconditional `drop: false`
    // makes the `matched.drop` assertion below FAIL.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop-l3".into(),
            family: "inet".into(),
            // L3-only term (address + protocol, NO ports) so it matches a
            // flowless packet whose L4 ports are absent (0).
            terms: vec![FirewallTermSnapshot {
                name: "drop-host".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec!["tcp".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    // Flowless packet whose L3 dst MATCHES the deny term → must fail closed.
    let matched = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        &flowless_v4_wire_key([172, 16, 80, 200]),
    );
    assert!(
        matched.drop,
        "#6055: a flowless cached-arm packet matching an output `then discard` \
         term must drop (not fail open)"
    );
    assert!(!matched.reject, "then discard is a silent drop, not a reject");
    assert_eq!(matched.filter_log, None);

    // Control: a flowless packet that does NOT match any deny term still
    // egresses (pass-through unchanged, #2357/#3290 preserved).
    let unmatched = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 201]),
        &flowless_v4_wire_key([172, 16, 80, 201]),
    );
    assert!(
        !unmatched.drop,
        "#6055: a flowless cached-arm packet not matching any deny term must NOT drop"
    );
}

#[test]
fn resolve_cached_cos_tx_selection_flowless_enforces_output_reject() {
    // #6055 RED-on-revert: the cached flowless arm must set drop:true AND
    // reject:true for a `then reject` output term (parity with #5467). A revert
    // to the unconditional `reject: false` makes the reject assertion FAIL.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-reject-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-reject-l3".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-host".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec!["tcp".into()],
                action: "reject".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let selection = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        &flowless_v4_wire_key([172, 16, 80, 200]),
    );
    assert!(selection.drop, "#6055: flowless cached `then reject` must drop");
    assert!(
        selection.reject,
        "#6055: flowless cached `then reject` must set the reject flag"
    );
}

#[test]
fn resolve_cached_cos_tx_selection_flowless_enforces_output_log() {
    // #6055 RED-on-revert: a flowless cached-arm packet matching an output
    // `then log` term must surface the filter-log match (before the fix
    // filter_log was always None on the cached flowless path — the log was
    // silently bypassed).
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-log-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-log-l3".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "log-host".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec!["tcp".into()],
                action: "accept".into(),
                log: true,
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let selection = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        &flowless_v4_wire_key([172, 16, 80, 200]),
    );
    assert!(
        selection.filter_log.is_some(),
        "#6055: a flowless cached-arm packet matching an output `then log` term must log"
    );
    assert!(
        !selection.drop,
        "a `then accept` + log term must not drop the packet"
    );
}

#[test]
fn resolve_cached_cos_tx_selection_flowless_port_term_does_not_spuriously_drop() {
    // #6055 / #2357 / #3290: the cached flowless output gate forces ports to 0,
    // so a port-BEARING terminal term never matches a fragment — no spurious
    // drop of legitimate flowless traffic. Guards the hardening from
    // over-dropping.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop-port".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop-port".into(),
            family: "inet".into(),
            // Port-bearing terminal term: a flowless packet (port 0, L4 absent)
            // must NOT match it.
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let selection = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        &flowless_v4_wire_key([172, 16, 80, 200]),
    );
    assert!(
        !selection.drop,
        "#6055: a port-bearing output term must NOT drop a flowless (port 0) cached packet"
    );
}

#[test]
fn resolve_cached_cos_tx_selection_flowless_captures_counter_only_output_filter() {
    // #6360 (#6236 PR-2A coverage): the CACHED flowless arm
    // (`resolve_cached_cos_tx_selection`, flow_key = None) must still walk an
    // interface output filter whose ONLY TX-relevant property is `then count`.
    // Every existing flowless output-filter canary uses a terminal (discard /
    // reject) or log term, so dropping `has_counter_terms` from
    // `Filter::needs_tx_eval()` leaves them GREEN — the flowless CACHED
    // needs_tx_eval predicate at cos_classify.rs:225 (and the
    // `interface_output_filter_needs_tx_eval` accessor it gates on, which since
    // #6236 PR-2B reads `Filter::needs_tx_eval()` off the output fast map) was
    // NOT bound by a counter-only canary. This test binds it: the filter is
    // counter-only (has_counter_terms=true; affects_tx_selection / has_log_terms
    // / has_terminal_action_terms / has_three_color_policer_terms all false), so
    // `needs_tx_eval()` reduces to has_counter_terms alone.
    //
    // RED-on-revert: dropping `has_counter_terms` from `Filter::needs_tx_eval()`
    // makes `interface_output_filter_needs_tx_eval(202)` return false (the outer
    // gate) AND fails the inner `.filter(|f| f.needs_tx_eval())` at :225, so the
    // output filter is never walked, `filter_counters` comes back empty, and the
    // assertion below FAILS.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-count-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-count-l3".into(),
            family: "inet".into(),
            // Counter-only, L3-only term (address + protocol, NO ports) so it
            // matches a flowless packet (L4 ports absent, forced to 0) and the
            // ONLY needs_tx_eval flag it sets is has_counter_terms.
            terms: vec![FirewallTermSnapshot {
                name: "count-host".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec!["tcp".into()],
                action: "accept".into(),
                count: "wan-hits".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let cached = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        &flowless_v4_wire_key([172, 16, 80, 200]),
    );
    assert!(
        !cached.filter_counters.is_empty(),
        "#6360: the cached flowless arm must capture a counter-only output \
         filter's `then count` handle (has_counter_terms drives needs_tx_eval)"
    );
    assert!(
        !cached.drop,
        "a counter-only `then accept` term must not drop the flowless packet"
    );

    // Control: a flowless packet whose L3 dst does NOT match the counted term
    // captures no counter — proves the assertion binds the term MATCH, not the
    // mere presence of a counter-only output filter.
    let unmatched = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 201]),
        &flowless_v4_wire_key([172, 16, 80, 201]),
    );
    assert!(
        unmatched.filter_counters.is_empty(),
        "#6360: a flowless packet not matching the counted term captures no counter",
    );
}

// ---------------------------------------------------------------------------
// #8367 — the CACHED flowless arm must read the POST-NAT on-wire tuple.
// ---------------------------------------------------------------------------
//
// WHAT THESE GUARD, STATED HONESTLY. This arm has no production caller that
// reaches it. `flow_cache.rs`'s seed always supplies a flow key, and the
// port-mirror path (`mirror_cos_queue_id`) consumes only `.queue_id` — and
// since #8367 it asks for only the queue (`resolve_cached_cos_tx_queue_id`), so
// it no longer reaches the descriptor arm at all. These are HARDENING cells,
// not an outage repair, and that distinction belongs next to them rather than
// in a commit message nobody re-reads.
//
// The trap is real all the same. #6055 populated `.drop` / `.reject` /
// `.filter_log` here DELIBERATELY, for a caller that does not exist yet, so
// that the next one to arrive would fail closed instead of waving a
// would-be-dropped flowless packet past an egress `then discard`. Reading the
// ingress (pre-NAT) `meta` for the family, the addresses and the protocol made
// those fields *confidently wrong* rather than merely absent — a trap that
// would present, long after the commit that armed it, as "the output filter
// matched the wrong address". Junos applies an interface `filter output` on the
// EGRESS interface AFTER NAT (#3642).
//
// #8367 removes the trap at the type level: `resolve_cached_cos_tx_selection_flowless`
// REQUIRES the post-NAT key, and there is deliberately no entry point that lets
// it be omitted. These cells bind that the required key is what the three reads
// actually use — a required parameter that nothing reads would be a guarantee
// in shape only.

/// #8367: the cached flowless arm matches the output filter on the POST-NAT
/// SOURCE, and a pre-NAT `from source-address` term no longer fires.
///
/// The fixture is the shape interface SNAT produces: `meta` carries the PRE-NAT
/// source 10.0.61.100 (what arrived), the wire key carries the POST-NAT source
/// 172.16.80.8 (what leaves). Both are IPv4, so — unlike #7656's NAT64 case —
/// there is no family signal at all; the ADDRESS is the only discriminator,
/// which is exactly why the #7656 fixture warning applies here in full. An
/// address-less term fires on whichever tuple the evaluator was handed and
/// cannot tell the two apart.
///
/// Arm C is the flow-bearing POSITIVE CONTROL. Without it, arms A and B are
/// also explained by a filter that never matches anything at all.
#[test]
fn cached_flowless_output_filter_matches_the_postnat_source_8367() {
    // The PRE-NAT ingress tuple, as the shim stamped it on the arriving packet.
    let prenat_meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        dscp: 0,
        pkt_len: 1514,
        flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..Default::default()
    };
    // The POST-NAT on-wire L3 tuple: interface SNAT rewrote the source to the
    // egress interface address. This is what `forward_wire_key(&forward_key,
    // decision.nat)` produces, with ports 0 because a flowless packet has no L4
    // header (#2344/#3290).
    let postnat_wire = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 0,
        dst_port: 0,
        discriminator: Default::default(),
        routing_domain: 0,
    };

    let snapshot = |term_source: &str| ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-src".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-src".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "by-source".into(),
                source_addresses: vec![term_source.into()],
                source_constrained: true,
                protocols: vec!["tcp".into()],
                action: "discard".into(),
                log: true,
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    // ARM A — the POST-NAT source. The packet's on-wire source IS the pool /
    // interface address, so an operator's `from source-address 172.16.80.8/32
    // then discard` MUST fire. Before #8367 this arm read 10.0.61.100 out of
    // `meta`, the term did not match, and the flowless packet was waved past a
    // configured deny.
    let forwarding = build_forwarding_state(&snapshot("172.16.80.8/32"));
    let postnat =
        resolve_cached_cos_tx_selection_flowless(&forwarding, 202, prenat_meta, &postnat_wire);
    assert!(
        postnat.drop,
        "#8367: the cached flowless arm must match the output filter on the \
         POST-NAT on-wire source (172.16.80.8). A `false` here means it is still \
         reading the pre-NAT `meta` tuple, so an egress `then discard` on the \
         NAT pool address never fires for a fragment"
    );
    assert!(
        postnat.filter_log.is_some(),
        "#8367: and the `then log` on that term must be captured, so the event \
         is attributed to the tuple the packet actually left with"
    );

    // ARM B — the PRE-NAT source. This is the address the packet ARRIVED with
    // and no longer carries on the wire, so the term must NOT match. This arm
    // is what makes arm A's `true` about the post-NAT tuple rather than about
    // "any source-address term matches": a mixture that selected the right
    // filter and matched the wrong addresses passes neither arm.
    let forwarding = build_forwarding_state(&snapshot("10.0.61.100/32"));
    let prenat =
        resolve_cached_cos_tx_selection_flowless(&forwarding, 202, prenat_meta, &postnat_wire);
    assert!(
        !prenat.drop,
        "#8367: a `from source-address <pre-NAT>` term must NOT match a packet \
         whose on-wire source has been translated away from it. A `true` here is \
         the pre-#8367 behaviour: the ingress `meta` source is being matched"
    );
    assert_eq!(
        prenat.filter_log, None,
        "#8367: and no log event is owed for a term that did not match"
    );

    // ARM C — FLOW-BEARING POSITIVE CONTROL. Same filter, same interface, same
    // post-NAT tuple, but through the flow-keyed arm (which has always used the
    // post-NAT wire key, #3642). It proves the term is well-formed,
    // TX-eligible, correctly attached, and reachable — so arm B's `false` is
    // about the pre-NAT address and not about a dead fixture.
    let forwarding = build_forwarding_state(&snapshot("172.16.80.8/32"));
    let flow_key = SessionKey {
        src_port: 40000,
        dst_port: 443,
        ..postnat_wire
    };
    let keyed = resolve_cached_cos_tx_selection(&forwarding, 202, prenat_meta, &flow_key);
    assert!(
        keyed.drop,
        "#8367 POSITIVE CONTROL: the flow-bearing arm must drop on the same \
         post-NAT source term. If this fails the fixture is broken and neither \
         flowless arm above proves anything"
    );
}

/// #8367: the output-filter FAMILY and the matched PROTOCOL come from the same
/// wire key as the addresses — one choice, not three reads.
///
/// A mixture is the failure mode #7656 named and this cell is the cached arm's
/// version of it: selecting the egress family while still matching the ingress
/// addresses picks the right filter and then cannot match any address-bearing
/// term in it, which is *less* correct than the original bug and invisible to
/// any fixture whose terms are address-less.
///
/// Neither a family nor a protocol change is reachable through today's cached
/// callers — `flow_cache::should_cache` excludes NAT64 (`&& !decision.nat.nat64`),
/// and NAT64 is the only translation that moves either field. The cell exists
/// anyway, because the arm's whole reason to be populated is the caller that
/// does not exist yet (#6055), and a caller that supplies a cross-family key
/// must not be silently evaluated against the ingress family. Deleting this
/// cell is a decision to re-derive that; do it deliberately or not at all.
#[test]
fn cached_flowless_output_filter_reads_family_and_protocol_from_the_wire_key_8367() {
    // PROTOCOL. `meta` says TCP; the wire key says UDP. The term matches UDP,
    // so it fires only if the protocol came from the key.
    let tcp_meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 1514,
        flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..Default::default()
    };
    let udp_wire = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 0,
        dst_port: 0,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let proto_snapshot = |protocol: &str| ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-proto".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-proto".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "by-proto".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec![protocol.into()],
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&proto_snapshot("udp"));
    assert!(
        resolve_cached_cos_tx_selection_flowless(&forwarding, 202, tcp_meta, &udp_wire).drop,
        "#8367: the matched protocol must come from the wire key (udp), not from \
         `meta.protocol` (tcp)"
    );
    // Control: the term that matches `meta`'s protocol must NOT fire. Without
    // it, "the udp term matched" is also explained by a protocol match that is
    // not being evaluated at all.
    let forwarding = build_forwarding_state(&proto_snapshot("tcp"));
    assert!(
        !resolve_cached_cos_tx_selection_flowless(&forwarding, 202, tcp_meta, &udp_wire).drop,
        "#8367: a term matching the INGRESS meta protocol must not fire on a \
         packet that leaves as another protocol"
    );

    // FAMILY. `meta` says AF_INET; the wire key says AF_INET6. BOTH families
    // have an output filter attached, so neither per-family lookup can
    // short-circuit and a verdict always means "this family's filter ran".
    // The v6 filter discards, the v4 filter accepts-and-logs, so `drop` alone
    // says which family was selected.
    let v6_wire = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6("2001:db8::1".parse().expect("v6 src")),
        dst_ip: IpAddr::V6("2001:db8::2".parse().expect("v6 dst")),
        src_port: 0,
        dst_port: 0,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let family_snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-v4".into(),
            filter_output_v6: "wan-v6".into(),
            ..Default::default()
        }],
        filters: vec![
            FirewallFilterSnapshot {
                name: "wan-v4".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "accept-all".into(),
                    action: "accept".into(),
                    log: true,
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "wan-v6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "drop-all".into(),
                    action: "discard".into(),
                    ..Default::default()
                }],
            },
        ],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&family_snapshot);
    let selection = resolve_cached_cos_tx_selection_flowless(&forwarding, 202, tcp_meta, &v6_wire);
    assert!(
        selection.drop,
        "#8367: the output-filter FAMILY must come from the wire key (inet6), \
         not `meta.addr_family` (inet). A `false` here means the v4 filter ran \
         on a packet leaving as IPv6"
    );
    assert_eq!(
        selection.filter_log, None,
        "#8367: and the v4 filter's `then log` must NOT have fired — that would \
         be the wrong-family filter both matching and logging"
    );
}

#[test]
fn resolve_cos_tx_selection_flowless_counts_counter_only_output_filter() {
    // #6360 (#6236 PR-2A coverage): the RUNTIME flowless arm
    // (`resolve_cos_tx_selection`, flow_key = None) must fire a `then count` on
    // an interface output filter whose ONLY TX-relevant property is the counter.
    // Binds the flowless RUNTIME needs_tx_eval predicate at cos_classify.rs:655
    // (and its `interface_output_filter_needs_tx_eval` accessor gate, fast-map
    // backed since #6236 PR-2B) to has_counter_terms — the existing flowless
    // canaries (terminal / log) do not.
    //
    // RED-on-revert: dropping `has_counter_terms` from `Filter::needs_tx_eval()`
    // skips the output-filter walk, the `then count` term never fires, and the
    // packet/byte counter assertions below FAIL.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-count-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-count-l3".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count-host".into(),
                destination_addresses: vec!["172.16.80.200/32".into()],
                destination_constrained: true,
                protocols: vec!["tcp".into()],
                action: "accept".into(),
                count: "wan-hits".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        None,
        flowless_extra(),
    );
    assert!(
        !selection.drop,
        "a counter-only `then accept` term must not drop the flowless packet"
    );

    // `flowless_v4_meta` stamps pkt_len = 1514; the counted flowless walk must
    // record exactly one packet of that byte length.
    let filter = forwarding
        .filter_state
        .filters
        .get("inet:wan-count-l3")
        .expect("inet output filter");
    let term = filter.terms.first().expect("first term");
    assert_eq!(
        term.counter.packets.load(Ordering::Relaxed),
        1,
        "#6360: the flowless runtime arm must fire the output filter's `then count`",
    );
    assert_eq!(
        term.counter.bytes.load(Ordering::Relaxed),
        1514,
        "#6360: the counted flowless packet's pkt_len must be recorded as bytes",
    );
}

#[test]
fn resolve_cos_tx_selection_uses_ingress_filter_dscp_rewrite_when_no_output_filter_exists() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "cos-classify".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "voice".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                forwarding_class: "expedited-forwarding".into(),
                dscp_rewrite: Some(0),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 46,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, Some(1));
    assert_eq!(selection.dscp_rewrite, Some(0));
}

#[test]
fn resolve_cos_tx_selection_skips_ingress_filter_without_tx_selection_effects() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "sfmix-pbr".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "sfmix-pbr".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "sfmix-route".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "tx-duplicate".into(),
                routing_instance: "sfmix".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 7,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            pkt_len: 1500,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, Some(7));
    assert_eq!(selection.dscp_rewrite, None);
    let filter = forwarding
        .filter_state
        .filters
        .get("inet:sfmix-pbr")
        .expect("filter");
    assert_eq!(
        filter.terms[0]
            .counter
            .packets
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn resolve_cos_tx_selection_returns_none_when_no_cos_or_tx_selection_filters_exist() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: 101,
            parent_ifindex: 5,
            vlan_id: 0,
            hardware_addr: "02:bf:72:00:61:01".into(),
            filter_input_v4: "sfmix-pbr".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "sfmix-pbr".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "sfmix-route".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "tx-duplicate".into(),
                routing_instance: "sfmix".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            pkt_len: 1500,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, None);
    assert_eq!(selection.dscp_rewrite, None);
    let filter = forwarding
        .filter_state
        .filters
        .get("inet:sfmix-pbr")
        .expect("filter");
    assert_eq!(
        filter.terms[0]
            .counter
            .packets
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn resolve_cos_queue_id_falls_back_to_default_queue_without_filter_match() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 7,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            ..Default::default()
        },
        None,
    );

    assert_eq!(queue_id, Some(7));
}

#[test]
fn resolve_cos_queue_id_uses_dscp_classifier_when_filters_do_not_set_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_dscp_classifier: "wan-classifier".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan-classifier".into(),
                entries: vec![CoSDSCPClassifierEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    dscp_values: vec![46],
                }],
            }],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice-sched".into(),
                    },
                ],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "voice-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 46,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );

    assert_eq!(queue_id, Some(5));
}

#[test]
fn resolve_cos_queue_id_uses_ieee8021_classifier_when_filters_do_not_set_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    code_points: vec![5],
                }],
            }],
            dscp_rewrite_rules: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice-sched".into(),
                    },
                ],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "voice-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_vlan_id: 100,
            ingress_pcp: 5,
            ingress_vlan_present: 1,
            addr_family: libc::AF_INET as u8,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );

    assert_eq!(queue_id, Some(5));
}

#[test]
fn resolve_cos_queue_id_does_not_use_ieee8021_classifier_for_untagged_packets() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "bulk".into(),
                    queue: 3,
                },
            ],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    code_points: vec![0],
                }],
            }],
            dscp_rewrite_rules: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "bulk".into(),
                        scheduler: "bulk-sched".into(),
                    },
                ],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "bulk-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_pcp: 0,
            ingress_vlan_present: 0,
            addr_family: libc::AF_INET as u8,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );

    assert_eq!(queue_id, Some(0));
}

// Note on invariant change (replaces the pre-a15a6120 "defaults to iface default" behavior):
// The original shape of this test asserted that an output filter with NO tx-side effect (no
// forwarding_class, no counter) would still shadow the ingress input filter's classification
// and leave egress at the interface default queue.  Commit a15a6120 changed the gating so the
// output filter is skipped entirely when it has neither forwarding_class, dscp_rewrite, nor
// counter terms — matching Junos semantics, where a classify-only output filter that does not
// classify does not clobber upstream classification.  The new invariant asserted below: when
// the output filter has no tx-side effect, ingress input-filter classification is preserved.
#[test]
fn resolve_cos_queue_id_preserves_ingress_classification_when_output_filter_has_no_forwarding_class()
 {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-classify".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![
            FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "wan-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "allow".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 7,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );

    // cos-classify on reth1.0 maps expedited-forwarding -> queue 1.  The output filter
    // wan-classify on reth0.0 has no tx-side effect (no forwarding_class, no dscp_rewrite,
    // no counter), so post-a15a6120 it is bypassed and the ingress classification is
    // preserved.  Pre-a15a6120 this was expected to fall through to the iface default queue
    // (best-effort = 7); that contract no longer holds and is captured by this test.
    assert_eq!(queue_id, Some(1));
}

#[test]
fn resolve_cos_tx_selection_preserves_output_filter_dscp_rewrite_without_forwarding_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-rewrite".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-rewrite".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "rewrite".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                dscp_rewrite: Some(46),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 7,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let selection = resolve_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
        TermMatchExtra::default(),
    );

    assert_eq!(selection.queue_id, Some(7));
    assert_eq!(selection.dscp_rewrite, Some(46));
}

// #3995: a CoS DSCP rewrite-rule keys on (forwarding-class, loss-priority).
// A rule that rewrites `voice low` and `voice high` to DIFFERENT code-points
// must produce the LOW code-point for a low-loss-priority flow and the HIGH
// code-point for a high-loss-priority flow of the same forwarding-class. A
// rewrite entry with NO explicit loss-priority is a wildcard that applies to
// every loss-priority (backward-compat).
//
// FAIL-ON-REVERT: the pre-fix code keyed the rewrite on forwarding-class only
// (`dscp_by_forwarding_class` + `.or_insert`), collapsing (voice, low) and
// (voice, high) to whichever appeared first — so BOTH flows would resolve to
// the SAME code-point and the `21 != 31` distinction (asserted below) would
// vanish. Reverting also drops the rewrite out of `CoSTxSelection.dscp_rewrite`
// entirely (it was applied at drain), flipping the `Some(..)` assertions to
// `None`.
#[test]
fn cos_dscp_rewrite_keys_on_forwarding_class_and_loss_priority() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            cos_dscp_classifier: "ba".into(),
            cos_dscp_rewrite_rule: "rw".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 1,
                },
                CoSForwardingClassSnapshot {
                    name: "data".into(),
                    queue: 2,
                },
            ],
            // The egress DSCP classifier assigns BOTH the queue (via
            // forwarding-class) AND the loss-priority per code-point.
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "ba".into(),
                entries: vec![
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![10],
                    },
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "high".into(),
                        dscp_values: vec![46],
                    },
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "data".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![18],
                    },
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "data".into(),
                        loss_priority: "high".into(),
                        dscp_values: vec![20],
                    },
                ],
            }],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
                name: "rw".into(),
                entries: vec![
                    // voice: loss-priority-DIFFERENTIATED.
                    CoSDSCPRewriteRuleEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        dscp_value: 21,
                    },
                    CoSDSCPRewriteRuleEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "high".into(),
                        dscp_value: 31,
                    },
                    // data: NO explicit loss-priority → wildcard (all LPs).
                    CoSDSCPRewriteRuleEntrySnapshot {
                        forwarding_class: "data".into(),
                        loss_priority: String::new(),
                        dscp_value: 40,
                    },
                ],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 2_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "voice-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "data-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "medium-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "data".into(),
                        scheduler: "data-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);

    // Resolve the egress DSCP rewrite for a flow whose ingress DSCP is `dscp`.
    let rewrite_for = |dscp: u8| -> Option<u8> {
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            addr_family: libc::AF_INET as u8,
            dscp,
            ..Default::default()
        };
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        };
        let selection =
            resolve_cos_tx_selection(&forwarding, 202, meta, Some(&key), TermMatchExtra::default());
        // The cached-descriptor path must resolve identically.
        let cached = resolve_cached_cos_tx_selection(&forwarding, 202, meta, &key);
        assert_eq!(
            selection.dscp_rewrite, cached.dscp_rewrite,
            "runtime and cached CoS rewrite must agree for DSCP {dscp}",
        );
        selection.dscp_rewrite
    };

    // voice/low (DSCP 10) → 21, voice/high (DSCP 46) → 31. The two MUST differ
    // — the whole point of loss-priority keying.
    let voice_low = rewrite_for(10);
    let voice_high = rewrite_for(46);
    assert_eq!(voice_low, Some(21), "voice low-loss-priority rewrite");
    assert_eq!(voice_high, Some(31), "voice high-loss-priority rewrite");
    assert_ne!(
        voice_low, voice_high,
        "#3995: loss-priority must NOT collapse (fc, low) and (fc, high)",
    );

    // data has a wildcard (no loss-priority) rewrite → the SAME code-point for
    // low and high loss-priority (backward-compat).
    assert_eq!(rewrite_for(18), Some(40), "data low → wildcard rewrite");
    assert_eq!(rewrite_for(20), Some(40), "data high → wildcard rewrite");

    // The uniform-only per-queue drain fallback must be None for the
    // differentiated voice class and Some(40) for the wildcard data class.
    let iface = forwarding
        .cos
        .interfaces
        .get(&202)
        .expect("missing CoS interface");
    let voice_queue = iface
        .queues
        .iter()
        .find(|q| q.forwarding_class == "voice")
        .expect("missing voice queue");
    assert_eq!(voice_queue.dscp_rewrite, None);
    let data_queue = iface
        .queues
        .iter()
        .find(|q| q.forwarding_class == "data")
        .expect("missing data queue");
    assert_eq!(data_queue.dscp_rewrite, Some(40));
}

// #1829 Phase 1: `enqueue_cos_item` is the single CoS admission choke
// point and must stamp `enqueue_ns` from the threaded pass `now_ns` on
// every admitted item — the dequeue-side sojourn recorder depends on
// it (an unstamped item is silently skipped, see plan invariant 10).
#[test]
fn enqueue_cos_item_stamps_enqueue_ns_at_admission() {
    let root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 125_000_000,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: 4_000_000,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }],
    );
    let fast_interfaces = test_cos_fast_interfaces(
        42,
        42,
        4,
        vec![(4, test_queue_fast_path(false, 0, None, None))],
        None,
        None,
    );
    let fast_path = fast_interfaces.get(&42).expect("test fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, 42, root, fast_path);

    let now_ns = 777_000_000u64;
    assert!(
        enqueue_cos_item(
            &mut binding,
            42,
            Some(4),
            512,
            test_flow_cos_item(5201, 512),
            now_ns,
            None,
        )
        .is_ok()
    );

    let queue = &binding
        .cos
        .cos_interfaces
        .get(&42)
        .expect("cos interface")
        .queues[0];
    match crate::afxdp::cos::queue_ops::cos_queue_front(queue) {
        Some(CoSPendingTxItem::Local(req)) => assert_eq!(req.enqueue_ns, now_ns),
        Some(CoSPendingTxItem::Prepared(req)) => assert_eq!(req.enqueue_ns, now_ns),
        None => panic!("admitted item must be at the queue front"),
    }
}

// ---------------------------------------------------------------------------
// #2238: classify_generated_reply — output classification of a host-generated
// reply by its OWN egress tuple, fail-CLOSED on a parse failure (§6.2).
// ---------------------------------------------------------------------------

/// Build a minimal untagged IPv4 frame on egress ifindex 202's address pair
/// for the given protocol, with TCP/UDP ports (ignored for ICMP). DSCP via
/// the ToS byte.
fn generated_v4_frame(protocol: u8, tos: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]); // dst mac
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // src mac
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    let l4: Vec<u8> = match protocol {
        PROTO_TCP => {
            let mut v = Vec::new();
            v.extend_from_slice(&src_port.to_be_bytes());
            v.extend_from_slice(&dst_port.to_be_bytes());
            v.extend_from_slice(&[0; 12]); // seq/ack/off-flags/win/csum/urg
            v
        }
        PROTO_UDP => {
            let mut v = Vec::new();
            v.extend_from_slice(&src_port.to_be_bytes());
            v.extend_from_slice(&dst_port.to_be_bytes());
            v.extend_from_slice(&[0; 4]);
            v
        }
        _ => vec![11, 0, 0, 0, 0, 0, 0, 0], // ICMP Time Exceeded
    };
    let total_len = (20 + l4.len()) as u16;
    frame.push(0x45);
    frame.push(tos);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, protocol, 0x00, 0x00]);
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 8).octets());
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
    let csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&csum.to_be_bytes());
    frame.extend_from_slice(&l4);
    frame
}

fn forwarding_with_v4_output_filter(
    filter_name: &str,
    term: FirewallTermSnapshot,
) -> ForwardingState {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: filter_name.into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: filter_name.into(),
            family: "inet".into(),
            terms: vec![term],
        }],
        ..Default::default()
    };
    build_forwarding_state(&snapshot)
}

#[test]
fn classify_generated_reply_drops_icmp_on_terminal_discard() {
    // Output filter `then discard` for `protocol icmp` drops a generated
    // ICMP Time Exceeded reply.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-icmp",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    let frame = generated_v4_frame(PROTO_ICMP, 0x00, 0, 0);
    let verdict = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(
        verdict.drop,
        "generated ICMP reply must be dropped by `then discard`"
    );
    assert!(!verdict.parse_error);
}

#[test]
fn classify_generated_reply_uses_logical_egress_ifindex_3026() {
    // #3026 fail-on-revert. A generated ICMP error leaving a VLAN
    // sub-interface must be classified (CoS / output filter) on the LOGICAL
    // egress unit ifindex (`ingress_ident.ifindex`), NOT the physical
    // `target_ifindex` (= bind_ifindex = the parent). Output filters and CoS
    // are keyed by the logical unit ifindex; the physical parent carries no
    // filter, so classifying by it would silently leak the reply past the
    // operator's `then discard protocol icmp`.
    //
    // Fixture: reth0.80 is the LOGICAL unit (ifindex 202, parent 11, VID 80)
    // and carries the ICMP-discard output filter; the physical parent 11 has
    // NO filter.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 202,
            parent_ifindex: 11,
            vlan_id: 80,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "drop-icmp".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "drop-icmp".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-icmp".into(),
                action: "discard".into(),
                protocols: vec!["icmp".into()],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);
    let frame = generated_v4_frame(PROTO_ICMP, 0x00, 0, 0);

    // Correct (#3026): classify on the LOGICAL egress ifindex 202 -> the
    // output filter matches the generated ICMP and drops it.
    let correct = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(
        correct.drop,
        "the generated ICMP reply must be dropped by the VLAN unit's own \
         output filter (classified on the logical egress ifindex 202)"
    );

    // Pre-fix: classify on the raw PHYSICAL parent ifindex 11. The parent
    // carries no output filter, so the reply is NOT dropped — it leaks past
    // the operator's `then discard protocol icmp` (the #3026 bug). If the
    // fix reverts to `target_ifindex` (physical), the `correct` branch above
    // collapses onto this value and the drop assert fails RED.
    let physical = classify_generated_reply(&forwarding, 11, &frame, 0);
    assert!(
        !physical.drop,
        "the physical parent ifindex 11 has no filter, so a physical-keyed \
         classification would WRONGLY admit the reply (the #3026 bug)"
    );
    assert_ne!(
        correct.drop, physical.drop,
        "logical-keyed (drop) vs physical-keyed (admit) verdicts must \
         diverge, proving the fix changes the classification interface"
    );

    // Non-VLAN preservation: an interface that IS the bind ifindex (logical
    // == physical) classifies identically regardless. reth1.0 below has no
    // parent, so ifindex 24 is both the logical unit and the bind ifindex.
    let untagged = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: 24,
            hardware_addr: "02:bf:72:01:00:01".into(),
            filter_output_v4: "drop-icmp".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "drop-icmp".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-icmp".into(),
                action: "discard".into(),
                protocols: vec!["icmp".into()],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let untagged_fwd = build_forwarding_state(&untagged);
    assert!(
        classify_generated_reply(&untagged_fwd, 24, &frame, 0).drop,
        "an untagged interface (logical == physical == 24) still applies its \
         own output filter — non-VLAN behavior is unchanged by the fix"
    );
}

#[test]
fn classify_generated_reply_ignores_trigger_protocol_filter() {
    // The discriminating test: a filter discarding TCP does NOT drop a
    // generated ICMP reply (proves classify-by-generated-tuple, not trigger).
    let forwarding = forwarding_with_v4_output_filter(
        "drop-tcp",
        FirewallTermSnapshot {
            name: "drop-tcp".into(),
            action: "discard".into(),
            protocols: vec!["tcp".into()],
            ..Default::default()
        },
    );
    let frame = generated_v4_frame(PROTO_ICMP, 0x00, 0, 0);
    let verdict = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(
        !verdict.drop,
        "a TCP-matching filter must not drop the generated ICMP reply"
    );
    assert!(!verdict.parse_error);
}

#[test]
fn classify_generated_reply_assigns_forwarding_class_queue() {
    // `then forwarding-class iperf-a` on the egress output filter routes the
    // generated RST to the queue mapped from that forwarding class.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "fc-tcp".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "fc-tcp".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "fc-rst".into(),
                action: "accept".into(),
                protocols: vec!["tcp".into()],
                forwarding_class: "iperf-a".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "iperf-a".into(),
                    queue: 4,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "a".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-a".into(),
                        scheduler: "a".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let forwarding = build_forwarding_state(&snapshot);
    let frame = generated_v4_frame(PROTO_TCP, 0x00, 80, 49152);
    let verdict = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(!verdict.drop);
    assert_eq!(
        verdict.cos_queue_id,
        Some(4),
        "generated RST routes to the iperf-a queue"
    );
}

#[test]
fn classify_generated_reply_fails_closed_on_parse_failure() {
    // §6.2: a truncated "generated" frame cannot be parsed → fail CLOSED
    // (drop + parse_error), never leak past an output discard.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-icmp",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    // L2 + EtherType only — no L3.
    let frame = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00,
    ];
    let verdict = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(verdict.drop, "parse failure must fail CLOSED (drop)");
    assert!(
        verdict.parse_error,
        "parse failure must set parse_error so the caller counts it"
    );
    assert_eq!(verdict.cos_queue_id, None);
}

#[test]
fn classify_generated_reply_counterfactual_trigger_keying_would_misverdict() {
    // Counter-factual pin (engineering-style "Test strength"): reconstruct
    // the PRE-#2238 call — classify on the TRIGGER tuple (UDP, the inbound
    // flow) — and show it produces the WRONG verdict for the same fixtures.
    // The egress output filter discards ICMP; the generated reply is ICMP.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-icmp",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    let frame = generated_v4_frame(PROTO_ICMP, 0x00, 0, 0);

    // Correct (#2238): classify the GENERATED ICMP bytes → drop.
    let correct = classify_generated_reply(&forwarding, 202, &frame, 0);
    assert!(correct.drop, "the generated ICMP reply must be dropped");

    // Pre-fix: classify on the TRIGGER tuple (a UDP flow) → NOT dropped,
    // because the `protocol icmp` discard term never matches UDP. This is
    // the exact bug (#2238): the reply leaks past the operator's ICMP
    // discard filter.
    let trigger_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 49152,
        dst_port: 53,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let pre_fix = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            pkt_len: 60,
            ..Default::default()
        },
        Some(&trigger_key),
        TermMatchExtra::default(),
        0,
    );
    assert!(
        !pre_fix.drop,
        "trigger-keyed classification would WRONGLY admit the reply (the #2238 bug)"
    );
}

#[test]
fn output_filter_family_selected_by_egress_key_for_nat64_3642() {
    // #3642 NAT64: a v6->v4 flow ingresses as IPv6 (meta.addr_family = v6) but
    // EGRESSES as IPv4. Junos applies the egress interface's output filter AFTER
    // NAT, so the v4 (post-NAT64) output filter must be selected and matched
    // against the v4 egress tuple. Transit callers pass the post-NAT wire key
    // (`forward_wire_key`), whose addr_family is the egress family (v4). The fix
    // selects the output-filter family from that key rather than the ingress
    // meta family.
    //
    // Fixture: egress ifindex 202 carries a v4 `then discard from
    // source-address 192.0.2.8` output filter. The egress wire key is v4 with
    // src 192.0.2.8; the ingress meta is v6.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-nat64-src",
        FirewallTermSnapshot {
            name: "drop-nat64-src".into(),
            protocols: vec!["tcp".into()],
            source_addresses: vec!["192.0.2.8/32".into()],
            source_constrained: true,
            action: "discard".into(),
            ..Default::default()
        },
    );
    // Post-NAT64 egress wire key: IPv4 family, translated v4 src.
    let egress_wire_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        src_port: 33000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    // Ingress metadata is IPv6 (the pre-NAT64 family).
    let ingress_v6_meta = UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        pkt_len: 80,
        ..Default::default()
    };

    let sel = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        ingress_v6_meta,
        Some(&egress_wire_key),
        TermMatchExtra::default(),
        0,
    );
    assert!(
        sel.drop,
        "NAT64 egress is IPv4: the v4 output filter must be selected by the \
         egress-key family and match the v4 src 192.0.2.8. Selecting by the \
         ingress meta family (v6) would look up an absent v6 filter and WRONGLY \
         admit the packet (#3642)"
    );
}

// ---------------------------------------------------------------------------
// #2330: the POST-TRANSFORM inner-source PTB (NAT64/GRE/WG) must route
// through the SAME classify_generated_reply contract as the #2301/#2328
// egress-MTU PTB — i.e. an output `then discard protocol icmp` drops it, and
// a malformed PTB fails closed. This proves the inner-MTU PTB built by
// build_frag_needed_v4 / build_packet_too_big_v6 from the #2330 site is a
// well-formed, classifiable reply (the finalizer enqueue is shared verbatim
// with #2301, so classification behavior is identical).
// ---------------------------------------------------------------------------

/// Build a real inner-source Frag-Needed PTB (carrying an INNER MTU, the
/// #2330 GRE/WG/NAT64 case) on egress ifindex 202's address pair, using the
/// production builder. The trigger is a 1500-byte inner v4 DF UDP datagram.
fn post_transform_inner_frag_needed_ptb(inner_mtu: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]); // fw mac (becomes PTB src side)
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // sender mac (becomes PTB dst)
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let l3 = frame.len();
    let total_len = (20 + 8 + 1500) as u16;
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, 17, 0x00, 0x00]); // DF set, UDP
    frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets()); // inner src
    frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets()); // inner dst
    let ip_csum = crate::afxdp::checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&49152u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&((8 + 1500) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend(std::iter::repeat(0xABu8).take(1500));

    let meta = UserspaceDpMeta {
        ingress_ifindex: 202,
        l3_offset: l3 as u16,
        l4_offset: (l3 + 20) as u16,
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        ..Default::default()
    };

    let mut fwd = ForwardingState::default();
    fwd.egress.insert(
        202,
        EgressInterface {
            bind_ifindex: 0,
            vlan_id: 0,
            mtu: 1400,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    crate::afxdp::build_frag_needed_v4(&frame, meta, 202, &fwd, inner_mtu)
        .expect("inner-source frag-needed must build")
}

#[test]
fn classify_post_transform_inner_ptb_drops_on_terminal_discard() {
    // The #2330 inner-source PTB (advertising a GRE/WG/NAT64 inner MTU)
    // routes through classify_generated_reply exactly like #2328's PTB: an
    // output `then discard protocol icmp` drops it.
    let forwarding = forwarding_with_v4_output_filter(
        "drop-icmp",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    let ptb = post_transform_inner_frag_needed_ptb(1376); // GRE inner MTU
    // Sanity: the built PTB carries the INNER MTU, not the transport MTU.
    let icmp = 14 + 20;
    assert_eq!(ptb[icmp], 3, "ICMP Frag-Needed");
    assert_eq!(
        u16::from_be_bytes([ptb[icmp + 6], ptb[icmp + 7]]),
        1376,
        "PTB advertises the inner MTU"
    );
    let verdict = classify_generated_reply(&forwarding, 202, &ptb, 0);
    assert!(
        verdict.drop,
        "post-transform PTB must honor the output discard filter"
    );
    assert!(
        !verdict.parse_error,
        "a well-formed PTB must NOT fail as a parse error"
    );
}

#[test]
fn classify_post_transform_inner_ptb_admitted_without_filter() {
    // No matching output filter -> the inner PTB is admitted (drop=false),
    // proving classification is keyed on the PTB's own ICMP tuple and the
    // built bytes parse cleanly (so the only drop is an intentional filter).
    let forwarding = forwarding_with_v4_output_filter(
        "drop-tcp",
        FirewallTermSnapshot {
            name: "drop-tcp".into(),
            action: "discard".into(),
            protocols: vec!["tcp".into()],
            ..Default::default()
        },
    );
    let ptb = post_transform_inner_frag_needed_ptb(1325); // WG inner MTU
    let verdict = classify_generated_reply(&forwarding, 202, &ptb, 0);
    assert!(
        !verdict.drop,
        "a TCP-only discard must not drop the ICMP PTB"
    );
    assert!(!verdict.parse_error);
}

// #2362 fold B: the TX-selection / CoS leg must honor a per-packet L4 match
// condition. A `from { tcp-flags syn } then forwarding-class ef` output filter
// selects the EF queue ONLY for a packet whose tcp_flags carry SYN; a non-SYN
// packet of the same 5-tuple falls through to the interface default queue. This
// fails if the TX-selection path reverts to TermMatchExtra::default() (the SYN
// term would never match → no EF selection on any packet → silent under-match).
#[test]
fn resolve_cos_tx_selection_honors_tcp_flags_per_packet_match() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-syn-ef".into(),
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-syn-ef".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "syn-ef".into(),
                protocols: vec!["tcp".into()],
                action: "accept".into(),
                forwarding_class: "expedited-forwarding".into(),
                tcp_flags: Some(0x02), // SYN
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let forwarding = build_forwarding_state(&snapshot);
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let meta = || UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        pkt_len: 1514,
        protocol: PROTO_TCP,
        ..Default::default()
    };

    // SYN packet -> tcp-flags term matches -> EF (queue 1).
    let syn = resolve_cos_tx_selection(
        &forwarding,
        202,
        meta(),
        Some(&key),
        TermMatchExtra {
            tcp_flags: 0x02,
            l4_present: true,
            flex_l3: None,
            ..Default::default()
        },
    );
    assert_eq!(
        syn.queue_id,
        Some(1),
        "SYN must select the EF forwarding-class queue"
    );

    // Pure-ACK packet -> tcp-flags term does NOT match -> interface default queue
    // (queue 0), NOT EF.
    let ack = resolve_cos_tx_selection(
        &forwarding,
        202,
        meta(),
        Some(&key),
        TermMatchExtra {
            tcp_flags: 0x10,
            l4_present: true,
            flex_l3: None,
            ..Default::default()
        },
    );
    assert_ne!(
        ack.queue_id,
        Some(1),
        "a non-SYN packet must NOT be classified into the SYN-gated EF queue (#2362 fold B)"
    );
}


// #2621 regression guard: an accepted input firewall-filter whose fall-through
// `then { forwarding-class; dscp; policer; next term; }` classify term precedes
// a terminating `then routing-instance` (PBR) term must still apply the
// forwarding-class queue, DSCP rewrite, AND three-color policer at egress.
//
// codex review-040 finding 040-07 hypothesized the split PBR/non-PBR session-
// miss evaluators (eval.rs `evaluate_filter_ref_non_routing_counted_v4` returns
// `FilterResult::default()` on a matched routing-instance term) DROP these
// modifiers. That FilterResult feeds ONLY the verdict + log on the miss path
// (`NonPbrInputFilterEval` reads action/log_match only — filter.rs:78-154);
// the modifiers are enforced at TX time, where `resolve_cos_tx_selection` and
// `resolve_cached_cos_tx_selection` re-walk the FULL ingress filter via the
// TX-selection evaluators (`tx_selection.rs` / `cache_sensitive.rs`), which
// ACCUMULATE fc/dscp/three-color-policer across every matched fall-through term
// and only return at the terminating routing-instance term (the LAST relevant
// term). So the classify term's modifiers ARE recovered — #2621 is a false
// positive. This test pins that recovery on BOTH the per-packet live path and
// the cached descriptor path; it goes RED if a future change reintroduces the
// split (e.g. the TX-selection evaluator early-returning at the routing-instance
// term before folding the earlier classify term's modifiers).
fn pbr_classify_then_route_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "classify-then-pbr".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "classify-then-pbr".into(),
            family: "inet".into(),
            terms: vec![
                // Fall-through (`next term`) classify term ahead of the PBR
                // term: forwarding-class + dscp rewrite + a single-rate
                // (three-color) policer whose tiny committed rate/burst meters
                // any real packet RED -> drop.
                FirewallTermSnapshot {
                    name: "classify-before-pbr".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    next_term: true,
                    forwarding_class: "expedited-forwarding".into(),
                    dscp_rewrite: Some(46),
                    policer: "trickle".into(),
                    ..Default::default()
                },
                // Terminating PBR term — routing-instance only, no modifiers.
                FirewallTermSnapshot {
                    name: "steer-blue".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    routing_instance: "blue".into(),
                    ..Default::default()
                },
            ],
        }],
        three_color_policers: vec![ThreeColorPolicerSnapshot {
            name: "trickle".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 1,
            peak_or_excess_rate_bytes_per_sec: 0,
            peak_or_excess_burst_bytes: 1,
            then_action: "discard".into(),
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    }
}

fn pbr_classify_flow_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn pbr_classify_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: 5,
        ingress_vlan_id: 0,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        dscp: 0,
        pkt_len: 1500,
        ..Default::default()
    }
}

#[test]
fn pbr_recovers_classify_modifiers_on_live_tx_selection() {
    // #2621: live (per-packet) TX selection at the PBR-overridden egress must
    // recover the classify term's forwarding-class queue + DSCP rewrite + the
    // three-color policer drop that ride ahead of the routing-instance term.
    let forwarding = build_forwarding_state(&pbr_classify_then_route_snapshot());
    let key = pbr_classify_flow_key();

    // The runtime-counted path actually meters the three-color policer (now_ns
    // present), so its tiny committed burst forces a RED -> drop on a 1500-byte
    // packet — proving the policer modifier is recovered through PBR.
    let metered = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        pbr_classify_meta(),
        Some(&key),
        TermMatchExtra::default(),
        1_000_000_000,
    );
    assert_eq!(
        metered.queue_id,
        Some(1),
        "#2621: forwarding-class -> EF queue must survive the PBR term"
    );
    assert_eq!(
        metered.dscp_rewrite,
        Some(46),
        "#2621: dscp rewrite must survive the PBR term"
    );
    assert!(
        metered.drop,
        "#2621: three-color policer drop must survive the PBR term"
    );
}

#[test]
fn pbr_recovers_classify_modifiers_on_cached_tx_selection() {
    // #2621: the cached descriptor TX selection (flow-cache hit replay) must
    // also recover the classify term's forwarding-class queue + DSCP rewrite
    // ahead of the routing-instance term. (The cached path carries the policer
    // runtimes for cache-hit metering but does not meter at build time, so this
    // arm pins the queue + DSCP recovery; the live arm above pins the drop.)
    let forwarding = build_forwarding_state(&pbr_classify_then_route_snapshot());
    let key = pbr_classify_flow_key();

    let cached = resolve_cached_cos_tx_selection(&forwarding, 202, pbr_classify_meta(), &key);
    assert_eq!(
        cached.queue_id,
        Some(1),
        "#2621: cached forwarding-class -> EF queue must survive the PBR term"
    );
    assert_eq!(
        cached.dscp_rewrite,
        Some(46),
        "#2621: cached dscp rewrite must survive the PBR term"
    );
}

// ============================================================================
// #4085: an interface INPUT filter term carrying BOTH `then count` and a
// tx-selection modifier (`then forwarding-class` / `then dscp`) OR a three-color
// policer must be counted EXACTLY ONCE per packet.
//
// The `then count` hit-counter is owned by the input-filter ACTION evaluation
// (`evaluate_non_pbr_input_filter` -> `evaluate_interface_filter_non_routing_counted`,
// on the session-miss / DSCP-sensitive session-hit path). The CoS TX-selection
// re-walk (`resolve_cos_tx_selection[_at]`) re-reads the SAME `term.counter` Arc
// only to extract forwarding-class / dscp-rewrite for queue selection and to
// METER the ingress three-color policer. Before the fix that re-walk used the
// *counted* eval variant, so it recorded the count a SECOND time — doubling the
// hit counter on every packet of a non-cacheable flow (DSCP-sensitive / NAT64 /
// NPTv6) and on the seed packet of a cacheable flow.
//
// The fix makes the ingress TX-selection leg counter-suppressed
// (`evaluate_filter_ref_tx_selection_{,runtime_}uncounted`); the OUTPUT leg
// stays counted (an output filter is action-evaluated nowhere else), the policer
// still meters, and the cache-hit replay (deduped `filter_counters` +
// `input_filter_counters`) still records exactly once per hit.
//
// Each test replays the session-miss two-leg sequence (action-eval count, then
// TX-selection walk) and asserts the term counter lands on 1, not 2 — RED (2) on
// revert.
// ============================================================================

fn count_fc_two_class_service() -> ClassOfServiceSnapshot {
    ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "expedited-forwarding".into(),
                queue: 1,
            },
        ],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
        schedulers: vec![
            CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 4_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            },
            CoSSchedulerSnapshot {
                name: "ef-sched".into(),
                transmit_rate_bytes: 6_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "strict-high".into(),
                buffer_size_bytes: 64_000,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            },
        ],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![
                CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                },
                CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "expedited-forwarding".into(),
                    scheduler: "ef-sched".into(),
                },
            ],
        }],
        inet_precedence_classifiers: vec![],
    }
}

/// Ingress reth1.0 (ifindex 101, parent 5) carries an input filter with a single
/// `accept; count; forwarding-class expedited-forwarding;` term; egress reth0.0
/// (ifindex 202) is a CoS interface with NO output filter — so the CoS
/// TX-selection re-walks the ingress input filter for its forwarding-class.
fn input_count_fc_snapshot(is_v6: bool) -> ConfigSnapshot {
    let family = if is_v6 { "inet6" } else { "inet" };
    let mut ingress = InterfaceSnapshot {
        name: "reth1.0".into(),
        ifindex: 101,
        parent_ifindex: 5,
        vlan_id: 0,
        hardware_addr: "02:bf:72:00:61:01".into(),
        ..Default::default()
    };
    if is_v6 {
        ingress.filter_input_v6 = "in-count-fc".into();
    } else {
        ingress.filter_input_v4 = "in-count-fc".into();
    }
    ConfigSnapshot {
        interfaces: vec![
            ingress,
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "in-count-fc".into(),
            family: family.into(),
            terms: vec![FirewallTermSnapshot {
                name: "voice".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "lan-hits".into(),
                forwarding_class: "expedited-forwarding".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(count_fc_two_class_service()),
        ..Default::default()
    }
}

/// Ingress input filter term with `then count` AND a three-color policer (tiny
/// committed burst -> RED drop) but NO forwarding-class. The `has_three_color_
/// policer_terms` gate (not `affects_tx_selection`) drives the TX-selection
/// re-walk here; the policer must still METER (drop) while the count is
/// suppressed.
fn input_count_policer_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "in-count-pol".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "in-count-pol".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "metered".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "lan-hits".into(),
                policer: "trickle".into(),
                ..Default::default()
            }],
        }],
        three_color_policers: vec![ThreeColorPolicerSnapshot {
            name: "trickle".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: 1,
            peak_or_excess_rate_bytes_per_sec: 0,
            peak_or_excess_burst_bytes: 1,
            then_action: "discard".into(),
        }],
        class_of_service: Some(count_fc_two_class_service()),
        ..Default::default()
    }
}

/// A plain `accept; count;` input filter with NO tx-selection modifier and NO
/// policer: the CoS TX-selection ingress branch never fires for it, so the
/// counter must be untouched by the re-walk (a no-regression guard, GREEN both
/// before and after the fix).
fn input_count_only_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "in-count-only".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "in-count-only".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "count".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                count: "lan-hits".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(count_fc_two_class_service()),
        ..Default::default()
    }
}

fn count4085_v4_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn count4085_v6_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x61, 0, 0, 0, 100)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 200)),
        src_port: 12345,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn count4085_meta(is_v6: bool) -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: 5,
        ingress_vlan_id: 0,
        addr_family: if is_v6 {
            libc::AF_INET6 as u8
        } else {
            libc::AF_INET as u8
        },
        protocol: PROTO_TCP,
        dscp: 0,
        pkt_len: 1500,
        ..Default::default()
    }
}

/// Read the `Arc<FilterTermCounter>` for the sole `then count` term of the
/// ingress input filter attached at `ifindex`.
fn ingress_count_term_counter(
    forwarding: &ForwardingState,
    ifindex: i32,
    is_v6: bool,
) -> Arc<crate::filter::FilterTermCounter> {
    let filters = if is_v6 {
        &forwarding.filter_state.iface_filter_v6_fast
    } else {
        &forwarding.filter_state.iface_filter_v4_fast
    };
    filters
        .get(&ifindex)
        .expect("ingress input filter present")
        .terms
        .iter()
        .find(|term| term.has_count)
        .expect("input filter carries a `then count` term")
        .counter
        .clone()
}

/// Leg 1 of the session-miss path: the input-filter ACTION evaluation records
/// the `then count` hit-counter exactly once (the ONE legitimate count).
fn count4085_action_eval(forwarding: &ForwardingState, is_v6: bool, key: &SessionKey, pkt_len: u64) {
    crate::filter::evaluate_interface_filter_non_routing_counted(
        &forwarding.filter_state,
        101,
        is_v6,
        key.src_ip,
        key.dst_ip,
        key.protocol,
        key.src_port,
        key.dst_port,
        0,
        TermMatchExtra::default(),
        pkt_len,
        crate::filter::NonRoutingCountPolicy::Always,
    );
}

fn count4085_counts_once_per_miss(is_v6: bool) {
    let forwarding = build_forwarding_state(&input_count_fc_snapshot(is_v6));
    let counter = ingress_count_term_counter(&forwarding, 101, is_v6);
    let key = if is_v6 {
        count4085_v6_key()
    } else {
        count4085_v4_key()
    };
    let meta = count4085_meta(is_v6);

    // Leg 1: action-eval counts once. Assert it landed on the RIGHT counter so a
    // wrong-ifindex zero here can't let a pre-fix leg-2 double masquerade as 1.
    count4085_action_eval(&forwarding, is_v6, &key, meta.pkt_len as u64);
    assert_eq!(
        counter.packets.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "input-filter action-eval records the `then count` exactly once"
    );

    // Leg 2 (runtime, now_ns present): the CoS TX-selection walk recovers the
    // forwarding-class queue but MUST NOT re-record the count.
    let sel = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        meta,
        Some(&key),
        TermMatchExtra::default(),
        1_000_000_000,
    );
    assert_eq!(
        sel.queue_id,
        Some(1),
        "forwarding-class -> EF queue must still be selected"
    );
    assert_eq!(
        counter.packets.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "#4085: the TX-selection ingress leg must NOT re-record the input-filter \
         count (RED == 2 on revert)"
    );
}

#[test]
fn input_filter_count_plus_fc_counts_once_per_miss_v4() {
    count4085_counts_once_per_miss(false);
}

#[test]
fn input_filter_count_plus_fc_counts_once_per_miss_v6() {
    count4085_counts_once_per_miss(true);
}

#[test]
fn input_filter_count_plus_fc_counts_once_none_now_ns_branch_v4() {
    // Exercise the `now_ns == None` entry point (`resolve_cos_tx_selection` ->
    // `evaluate_filter_ref_tx_selection_uncounted`), the sibling of the runtime
    // branch above.
    let forwarding = build_forwarding_state(&input_count_fc_snapshot(false));
    let counter = ingress_count_term_counter(&forwarding, 101, false);
    let key = count4085_v4_key();
    let meta = count4085_meta(false);

    count4085_action_eval(&forwarding, false, &key, meta.pkt_len as u64);
    assert_eq!(counter.packets.load(std::sync::atomic::Ordering::Relaxed), 1);

    let sel = resolve_cos_tx_selection(&forwarding, 202, meta, Some(&key), TermMatchExtra::default());
    assert_eq!(sel.queue_id, Some(1));
    assert_eq!(
        counter.packets.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "#4085: the None-now_ns TX-selection ingress leg must NOT re-count \
         (RED == 2 on revert)"
    );
}

#[test]
fn input_filter_count_plus_policer_counts_once_and_still_meters_v4() {
    // The `has_three_color_policer_terms` gate drives the re-walk. The count must
    // be suppressed BUT the policer must still meter (RED -> drop) — the policer
    // is metered nowhere else.
    let forwarding = build_forwarding_state(&input_count_policer_snapshot());
    let counter = ingress_count_term_counter(&forwarding, 101, false);
    let key = count4085_v4_key();
    let meta = count4085_meta(false);

    count4085_action_eval(&forwarding, false, &key, meta.pkt_len as u64);
    assert_eq!(counter.packets.load(std::sync::atomic::Ordering::Relaxed), 1);

    let sel = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        meta,
        Some(&key),
        TermMatchExtra::default(),
        1_000_000_000,
    );
    assert!(
        sel.drop,
        "#4085: the ingress three-color policer must still meter (RED -> drop) \
         even though the count is suppressed"
    );
    assert_eq!(
        counter.packets.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "#4085: count+policer input term must count once, not twice \
         (RED == 2 on revert)"
    );
}

#[test]
fn plain_count_only_input_filter_unchanged_v4() {
    // No fc / dscp / policer -> the TX-selection ingress branch never fires, so
    // the re-walk leaves the counter untouched (no-regression guard).
    let forwarding = build_forwarding_state(&input_count_only_snapshot());
    let counter = ingress_count_term_counter(&forwarding, 101, false);
    let key = count4085_v4_key();
    let meta = count4085_meta(false);

    count4085_action_eval(&forwarding, false, &key, meta.pkt_len as u64);
    let _ = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        meta,
        Some(&key),
        TermMatchExtra::default(),
        1_000_000_000,
    );
    assert_eq!(
        counter.packets.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "a plain count-only input filter is counted once and untouched by \
         TX-selection"
    );
}

#[test]
fn non_cacheable_flow_counts_once_per_packet_v4() {
    // A non-cacheable (DSCP-sensitive / NAT64 / NPTv6) flow takes the session-miss
    // path on EVERY packet, so the double-count is per-packet, not per-flow.
    // Replay the two-leg miss sequence 3x and require exactly 3 counts (RED == 6
    // on revert).
    let forwarding = build_forwarding_state(&input_count_fc_snapshot(false));
    let counter = ingress_count_term_counter(&forwarding, 101, false);
    let key = count4085_v4_key();
    let meta = count4085_meta(false);

    for _ in 0..3 {
        count4085_action_eval(&forwarding, false, &key, meta.pkt_len as u64);
        let _ = resolve_cos_tx_selection_at(
            &forwarding,
            202,
            meta,
            Some(&key),
            TermMatchExtra::default(),
            1_000_000_000,
        );
    }
    assert_eq!(
        counter.packets.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "#4085: a non-cacheable flow counts once per packet (RED == 6 on revert)"
    );
}

#[test]
fn cache_hit_replays_input_count_exactly_once_v4() {
    // End-to-end exactly-once across a cacheable flow: the seed (miss) packet is
    // counted by the action-eval (leg 1) with the TX-selection re-walk suppressed
    // (leg 2), and each subsequent flow-cache HIT replays the deduped cached
    // counter sets exactly once. seed(1) + 2 hits(1 each) == 3.
    let forwarding = build_forwarding_state(&input_count_fc_snapshot(false));
    let counter = ingress_count_term_counter(&forwarding, 101, false);
    let key = count4085_v4_key();
    let meta = count4085_meta(false);

    // --- seed / miss packet.
    count4085_action_eval(&forwarding, false, &key, meta.pkt_len as u64);
    let _ = resolve_cos_tx_selection_at(
        &forwarding,
        202,
        meta,
        Some(&key),
        TermMatchExtra::default(),
        1_000_000_000,
    );
    assert_eq!(
        counter.packets.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "seed packet counts once"
    );

    // --- build the cached counter sets exactly as flow-cache install does: the
    // cos rebuild folds the input filter's count into `tx_selection.filter_counters`
    // (no output filter present) and the dedicated input replay set is deduped
    // against it (`retain_absent_from`) so the count lives in exactly ONE set.
    let tx = resolve_cached_cos_tx_selection(&forwarding, 202, meta, &key);
    let mut input_counters = crate::filter::evaluate_interface_input_filter_counters_cached(
        &forwarding.filter_state,
        101,
        false,
        key.src_ip,
        key.dst_ip,
        key.protocol,
        key.src_port,
        key.dst_port,
        meta.dscp,
    );
    input_counters.retain_absent_from(&tx.filter_counters);

    // --- two flow-cache HITs: replay both sets once per hit (flow_cache_hit.rs).
    for _ in 0..2 {
        tx.filter_counters
            .for_each(|c| crate::filter::record_filter_counter(c, meta.pkt_len as u64));
        input_counters.for_each(|c| crate::filter::record_filter_counter(c, meta.pkt_len as u64));
    }
    assert_eq!(
        counter.packets.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "#4085: seed (1) + 2 cache hits (1 each) == 3 — hits must count once, \
         not zero or two"
    );
}

// #hb166 T-3 middle case: an INPUT filter assigns a forwarding-class and a
// counter/log-only OUTPUT filter (no `then forwarding-class`) is ALSO attached
// to the egress interface. Junos semantics are output-OVERRIDES-when-set, not
// output-PRESENCE-clears-ingress, so the input-filter class must survive: the
// packet must land in the `expedited-forwarding` queue (1), NOT best-effort (0).
//
// This is the case commit `a15a6120` left broken (it fixed only the
// zero-effect / non-matching output-filter subcase). FAIL-ON-REVERT: restoring
// the `!has_output_filter` gate on `ingress_forwarding_class` flips the queue
// back to best-effort (0).
fn hb166_t3_middle_case_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![
            // Ingress interface with an input filter that classifies to ef.
            InterfaceSnapshot {
                name: "reth1.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                hardware_addr: "02:bf:72:00:61:01".into(),
                filter_input_v4: "cos-classify".into(),
                ..Default::default()
            },
            // Egress interface with CoS queues AND a counter-only output filter.
            InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: 202,
                hardware_addr: "02:bf:72:00:80:08".into(),
                filter_output_v4: "wan-count".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        filters: vec![
            FirewallFilterSnapshot {
                name: "cos-classify".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "voice".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    forwarding_class: "expedited-forwarding".into(),
                    ..Default::default()
                }],
            },
            // Output filter counts only — NO `then forwarding-class`.
            FirewallFilterSnapshot {
                name: "wan-count".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "count-only".into(),
                    protocols: vec!["tcp".into()],
                    destination_ports: vec!["443".into()],
                    action: "accept".into(),
                    count: "wan-hits".into(),
                    ..Default::default()
                }],
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 4_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                ],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    }
}

#[test]
fn resolve_cos_queue_id_preserves_input_fc_under_counter_only_output_filter() {
    let snapshot = hb166_t3_middle_case_snapshot();
    let forwarding = build_forwarding_state(&snapshot);
    let queue_id = resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }),
    );
    assert_eq!(
        queue_id,
        Some(1),
        "a counter-only output filter must NOT clear the input-filter forwarding-class"
    );
}

#[test]
fn resolve_cached_cos_tx_selection_preserves_input_fc_under_counter_only_output_filter() {
    let snapshot = hb166_t3_middle_case_snapshot();
    let forwarding = build_forwarding_state(&snapshot);
    let cached = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        &SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    );
    assert_eq!(
        cached.queue_id,
        Some(1),
        "cached resolver must also keep the input-filter forwarding-class under a counter-only output filter"
    );
    // The output filter still counts (its counter term runs), and the ingress
    // input filter's class survives — output-overrides-when-set semantics.
    assert!(!cached.filter_counters.is_empty());
}

#[test]
fn ieee8021_classifier_fails_closed_on_out_of_range_pcp() {
    // #hb166 T-7: a PCP outside the 3-bit 0..=7 domain must NOT be clamped
    // into a valid index. Pre-fix `pcp.min(7)` routed pcp 8 to the PCP-7
    // class (here queue 3); the fix returns None so the frame falls
    // through to the default queue, matching the #2447 build-side
    // fail-closed posture. RED-on-revert: restoring `.min(7)` flips the
    // pcp-8/255 assertions from None back to Some(3).
    let mut pcp_table = [u8::MAX; 8];
    pcp_table[7] = 3;
    let iface = CoSInterfaceConfig {
        shaping_rate_bytes: 1_000_000,
        burst_bytes: COS_MIN_BURST_BYTES,
        default_queue: 0,
        dscp_classifier: String::new(),
        ieee8021_classifier: "wan-pcp".into(),
        dscp_queue_by_dscp: [u8::MAX; 64],
        ieee8021_queue_by_pcp: pcp_table,
        queue_by_forwarding_class: FastMap::default(),
        queues: vec![],
        oversubscription_policy: crate::afxdp::types::CoSOversubscriptionPolicy::Proportional,
        oversubscription_guarantee_fraction: 0.0,
        priority_low_min_share_bytes: 0,
        inet_precedence_classifier: String::new(),
        inet_precedence_queue_by_prec: [u8::MAX; 8],
    };
    // Valid PCP 7 resolves to its configured queue.
    assert_eq!(
        resolve_cos_ieee8021_classifier_queue_id(&iface, 7, true),
        Some(3)
    );
    // Out-of-range PCP fails closed to None (default queue), NOT clamped to
    // the PCP-7 queue.
    assert_eq!(
        resolve_cos_ieee8021_classifier_queue_id(&iface, 8, true),
        None
    );
    assert_eq!(
        resolve_cos_ieee8021_classifier_queue_id(&iface, 255, true),
        None
    );
    // Untagged frames never classify.
    assert_eq!(
        resolve_cos_ieee8021_classifier_queue_id(&iface, 7, false),
        None
    );
}

// ---------------------------------------------------------------------------
// #6847 — inet-precedence behavior-aggregate classifier.
//
// These are RUNTIME assertions, not compile-and-store checks. Per the #6850
// cohort doctrine a test asserting "the classifier is present in the snapshot"
// passes identically whether or not the dataplane consumes it, which is exactly
// the state this knob was in before #6847: definable, and (after the Go half)
// bindable, with nothing behind it. Each test below drives a packet's DS field
// through the real BA resolution chain and asserts the QUEUE it lands in.
// ---------------------------------------------------------------------------

/// Fixture: interface 202 with three MATERIALIZED queues — best-effort=0,
/// voice=5, video=7 — and whichever classifiers the caller binds. Every
/// forwarding class is in the scheduler-map on purpose: the #hb166 T-4
/// materialized-queue fallback rewrites a classifier result that points at an
/// unmaterialized queue to `default_queue`, which would silently turn a
/// classification assertion into a default-queue assertion and hide a broken
/// arm behind a passing test.
fn inet_precedence_fixture(
    dscp_classifier: &str,
    inet_precedence_classifier: &str,
    dscp_entries: Vec<CoSDSCPClassifierEntrySnapshot>,
    prec_entries: Vec<CoSINetPrecedenceClassifierEntrySnapshot>,
) -> ConfigSnapshot {
    let sched = |name: &str| CoSSchedulerSnapshot {
        name: name.into(),
        transmit_rate_bytes: 3_000_000,
        priority: "low".into(),
        buffer_size_bytes: 64_000,
        ..Default::default()
    };
    let map_entry = |forwarding_class: &str, scheduler: &str| CoSSchedulerMapEntrySnapshot {
        forwarding_class: forwarding_class.into(),
        scheduler: scheduler.into(),
    };
    ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_dscp_classifier: dscp_classifier.into(),
            cos_inet_precedence_classifier: inet_precedence_classifier.into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
                CoSForwardingClassSnapshot {
                    name: "video".into(),
                    queue: 7,
                },
            ],
            dscp_classifiers: if dscp_entries.is_empty() {
                vec![]
            } else {
                vec![CoSDSCPClassifierSnapshot {
                    name: "dscp-cl".into(),
                    entries: dscp_entries,
                }]
            },
            inet_precedence_classifiers: if prec_entries.is_empty() {
                vec![]
            } else {
                vec![CoSINetPrecedenceClassifierSnapshot {
                    name: "prec-cl".into(),
                    entries: prec_entries,
                }]
            },
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    map_entry("best-effort", "be-sched"),
                    map_entry("voice", "voice-sched"),
                    map_entry("video", "video-sched"),
                ],
            }],
            schedulers: vec![sched("be-sched"), sched("voice-sched"), sched("video-sched")],
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn prec_entry(
    forwarding_class: &str,
    loss_priority: &str,
    precedences: Vec<u8>,
) -> CoSINetPrecedenceClassifierEntrySnapshot {
    CoSINetPrecedenceClassifierEntrySnapshot {
        forwarding_class: forwarding_class.into(),
        loss_priority: loss_priority.into(),
        precedences,
    }
}

fn inet_precedence_test_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn inet_precedence_queue_for_dscp(snapshot: &ConfigSnapshot, dscp: u8) -> Option<u8> {
    let forwarding = build_forwarding_state(snapshot);
    let key = inet_precedence_test_key();
    resolve_cos_queue_id(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp,
            ..Default::default()
        },
        Some(&key),
    )
}

/// #6847 the headline runtime assertion: a packet whose IP precedence maps to a
/// forwarding class lands in THAT class's queue.
///
/// DSCP 46 (EF) carries IP precedence 5 (46 >> 3). No DSCP classifier is bound,
/// so the only thing that can steer this packet off the default queue is the
/// inet-precedence arm.
///
/// FAIL-ON-REVERT: delete the
/// `.or_else(|| resolve_cos_inet_precedence_classifier_queue_id(..))` link from
/// the chain and the packet falls through to `iface.default_queue` (0), so the
/// `Some(5)` assertion goes red — the pre-#6847 behaviour.
#[test]
fn inet_precedence_classifier_steers_packet_into_its_forwarding_class_queue() {
    let snapshot = inet_precedence_fixture("", "prec-cl", vec![], vec![prec_entry("voice", "low", vec![5])]);
    assert_eq!(
        inet_precedence_queue_for_dscp(&snapshot, 46),
        Some(5),
        "IP precedence 5 must land in the voice queue"
    );
}

/// #6847: the classifier reads the TOP THREE BITS of the DS field, not the
/// bottom three and not the whole field. This pins the `(dscp >> 3) & 0x7`
/// derivation against the plausible wrong shifts:
///
///   - `dscp & 0x7`   — 46 & 7 = 6, 40 & 7 = 0: neither is precedence 5, and
///                      the two would disagree with each other.
///   - `dscp >> 2`    — 46 >> 2 = 11: masked to 3 by the `& 0x7`, not 5.
///   - no shift/mask  — indexes out of the 8-entry table.
///
/// DSCP 40 (CS5) and 46 (EF) are different code-points that share precedence 5,
/// so they MUST agree; DSCP 24 (CS3) is precedence 3, which this classifier
/// does not map, so it must fall through to the default queue. Asserting both
/// directions is what makes this a shift test rather than a single-value one.
#[test]
fn inet_precedence_classifier_reads_the_top_three_bits_of_the_ds_field() {
    let snapshot = inet_precedence_fixture("", "prec-cl", vec![], vec![prec_entry("voice", "low", vec![5])]);
    for dscp in [40u8, 41, 46, 47] {
        assert_eq!(
            inet_precedence_queue_for_dscp(&snapshot, dscp),
            Some(5),
            "dscp {dscp} is IP precedence 5 and must classify identically"
        );
    }
    for dscp in [0u8, 24, 39, 48] {
        assert_eq!(
            inet_precedence_queue_for_dscp(&snapshot, dscp),
            Some(0),
            "dscp {dscp} is NOT IP precedence 5 and must fall through to the default queue"
        );
    }
}

/// #6847: when a snapshot carries BOTH a dscp and an inet-precedence binding on
/// one interface, DSCP wins.
///
/// A unit binding both is rejected at commit
/// (`validateCoSUnitClassifierConflict`), so this combination only reaches the
/// dataplane via the TOLERANT load / peer-sync path, where the Go side
/// downgrades the rejection to a warning so an already-persisted config still
/// boots (#1960). That warning tells the operator DSCP will win; this test is
/// what makes the statement true. Reordering the two `.or_else` arms silently
/// changes which classifier a booting box honours.
#[test]
fn dscp_classifier_wins_over_inet_precedence_when_both_are_bound() {
    let snapshot = inet_precedence_fixture(
        "dscp-cl",
        "prec-cl",
        vec![CoSDSCPClassifierEntrySnapshot {
            forwarding_class: "voice".into(),
            loss_priority: "low".into(),
            dscp_values: vec![46],
        }],
        // Same packet, different answer: precedence 5 would say video (7).
        vec![prec_entry("video", "low", vec![5])],
    );
    assert_eq!(
        inet_precedence_queue_for_dscp(&snapshot, 46),
        Some(5),
        "DSCP must be consulted first, so the voice queue wins over video"
    );
    // Control: a code-point the DSCP classifier does NOT map still reaches the
    // inet-precedence arm, so this is a precedence-ORDER result and not the
    // inet-precedence arm being dead outright.
    assert_eq!(
        inet_precedence_queue_for_dscp(&snapshot, 40),
        Some(7),
        "an unmapped DSCP must fall through to the inet-precedence arm"
    );
}

/// #6847: a flow on an interface bound ONLY to an inet-precedence classifier is
/// marked for per-packet BA re-classification.
///
/// The flow cache freezes the seed packet's queue unless `ba_reclassify` is
/// set, so leaving inet-precedence out of that gate would pin a flow to the
/// class its FIRST packet happened to carry. That is not "not classifying" —
/// it is classifying once and then silently ignoring every later marking
/// change, which is the same wrong-queue outcome with a harder-to-see cause.
///
/// FAIL-ON-REVERT: drop `|| !iface.inet_precedence_classifier.is_empty()` from
/// the `ba_reclassify` gate and this goes red.
#[test]
fn inet_precedence_classifier_marks_flow_for_ba_reclassification() {
    let snapshot = inet_precedence_fixture("", "prec-cl", vec![], vec![prec_entry("voice", "low", vec![5])]);
    let forwarding = build_forwarding_state(&snapshot);
    let key = inet_precedence_test_key();
    let descriptor = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            addr_family: libc::AF_INET as u8,
            dscp: 46,
            ..Default::default()
        },
        &key,
    );
    assert!(
        descriptor.ba_reclassify,
        "an inet-precedence-classified flow must re-resolve its queue per packet"
    );
    assert_eq!(descriptor.queue_id, Some(5));
}

/// #6847: an interface with NO classifier at all must NOT be marked for BA
/// re-classification. Negative control for the gate above — without it, a gate
/// hard-wired to `true` would pass that test.
#[test]
fn no_classifier_leaves_flow_without_ba_reclassification() {
    let snapshot = inet_precedence_fixture("", "", vec![], vec![]);
    let forwarding = build_forwarding_state(&snapshot);
    let key = inet_precedence_test_key();
    let descriptor = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            addr_family: libc::AF_INET as u8,
            dscp: 46,
            ..Default::default()
        },
        &key,
    );
    assert!(!descriptor.ba_reclassify);
}

/// #6847: the classifier entry's `loss-priority` drives the egress rewrite.
///
/// The queue arm alone would leave `loss-priority high` accepted at commit and
/// silently applied as LOW on egress — an accepted-but-inert sub-knob inside
/// the very feature this issue makes non-inert. The rewrite rule below is
/// loss-priority-DIFFERENTIATED (voice/high -> 34, voice/low -> 10) so the two
/// answers are distinguishable; a uniform rule would pass either way.
///
/// FAIL-ON-REVERT: remove the `inet_precedence_lp_by_prec` consult from
/// `resolve_cos_loss_priority` and the loss-priority falls back to the LOW
/// default, so the rewrite becomes `Some(10)`.
#[test]
fn inet_precedence_classifier_loss_priority_selects_the_egress_rewrite() {
    let mut snapshot = inet_precedence_fixture(
        "",
        "prec-cl",
        vec![],
        vec![prec_entry("voice", "high", vec![5])],
    );
    snapshot.interfaces[0].cos_dscp_rewrite_rule = "voice-rw".into();
    let cos = snapshot.class_of_service.as_mut().expect("fixture cos");
    cos.dscp_rewrite_rules = vec![CoSDSCPRewriteRuleSnapshot {
        name: "voice-rw".into(),
        entries: vec![
            CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "voice".into(),
                loss_priority: "high".into(),
                dscp_value: 34,
            },
            CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "voice".into(),
                loss_priority: "low".into(),
                dscp_value: 10,
            },
        ],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let key = inet_precedence_test_key();
    let descriptor = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 999,
            addr_family: libc::AF_INET as u8,
            dscp: 40,
            ..Default::default()
        },
        &key,
    );
    assert_eq!(descriptor.queue_id, Some(5));
    assert_eq!(
        descriptor.dscp_rewrite,
        Some(34),
        "the entry's loss-priority high must select the high rewrite, not the low default"
    );
}

/// #6854 (review finding): the CACHED descriptor must carry the term's
/// `then reject <message-type>`, not just the reject bit.
///
/// Scope, stated because it is narrower than the sibling in
/// `tests_bind_forward.rs` and the difference matters: that cell reads the ICMP
/// code BYTE off a built reply, which is the real property. This one asserts the
/// value on the carrying struct. It is a weaker instrument and it is here
/// because `stage_flow_cache_hit` — the consumer that replays a cached reject —
/// has no test harness at all, so an end-to-end assertion on the replay path
/// cannot be written without building one first.
///
/// What it does buy: the hop that FILLS the descriptor is mutation-bound.
/// Hardcoding it to the default previously survived the entire suite, which is
/// how a `then reject host-unreachable` could silently revert to
/// administratively-prohibited on cached traffic with everything green.
#[test]
fn cached_cos_tx_selection_carries_the_reject_message_type_6854() {
    let term = |mt: &str| FirewallTermSnapshot {
        name: "reject-host".into(),
        destination_addresses: vec!["172.16.80.200/32".into()],
        destination_constrained: true,
        protocols: vec!["tcp".into()],
        action: "reject".into(),
        reject_message_type: mt.into(),
        ..Default::default()
    };
    let snap = |mt: &str| ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 202,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-reject-l3".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-reject-l3".into(),
            family: "inet".into(),
            terms: vec![term(mt)],
        }],
        ..Default::default()
    };

    // A configured message-type must reach the descriptor as its resolved codes.
    let forwarding = build_forwarding_state(&snap("host-unreachable"));
    let selection = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        &flowless_v4_wire_key([172, 16, 80, 200]),
    );
    assert!(
        selection.reject,
        "#6854 PREMISE: the term must be classified as a reject, or the message-type \
         assertion below is about a descriptor nothing will consume"
    );
    assert_eq!(
        (
            selection.reject_message.v4_code,
            selection.reject_message.v6_code
        ),
        (1, 3),
        "#6854: the cached descriptor must carry `host-unreachable` (ICMPv4 code 1 / \
         ICMPv6 code 3). The default (13, 1) here means a cached reject silently reverts \
         to administratively-prohibited"
    );

    // FLOW-KEYED arm. The two calls above take the FLOWLESS branch (flow_key
    // None), which is a different fill site — the mutation matrix showed the
    // flowless one bound and the flow-keyed one still free, so covering only one
    // of them leaves half the cached path exactly as unverified as before.
    let forwarding = build_forwarding_state(&snap("host-unreachable"));
    let keyed = resolve_cached_cos_tx_selection(
        &forwarding,
        202,
        UserspaceDpMeta {
            ingress_ifindex: 5,
            ingress_vlan_id: 0,
            addr_family: libc::AF_INET as u8,
            dscp: 0,
            ..Default::default()
        },
        &SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    );
    assert!(
        keyed.reject,
        "#6854 PREMISE: the flow-keyed arm must classify the term as a reject"
    );
    assert_eq!(
        (keyed.reject_message.v4_code, keyed.reject_message.v6_code),
        (1, 3),
        "#6854: the FLOW-KEYED cached descriptor must carry the message-type too — this is          a separate fill site from the flowless arm above"
    );

    // And a term with NO message-type must still carry the default, so this
    // change is invisible to a config that does not use the feature. Without
    // this arm, a fill that hardcoded `host-unreachable` would pass above.
    let forwarding = build_forwarding_state(&snap(""));
    let selection = resolve_cached_cos_tx_selection_flowless(
        &forwarding,
        202,
        flowless_v4_meta([172, 16, 80, 200]),
        &flowless_v4_wire_key([172, 16, 80, 200]),
    );
    assert_eq!(
        (
            selection.reject_message.v4_code,
            selection.reject_message.v6_code
        ),
        (13, 1),
        "#6854: a cached reject with no message-type must keep administratively-prohibited"
    );
}

/// #8597 K41: the precondition for the fallback arm's None branch — a prepared
/// descriptor pointing outside the UMEM makes the clone refuse rather than
/// return garbage.
///
/// WHAT THIS DOES AND DOES NOT BIND, stated so nobody reads it as more.
/// It binds that `None` is REACHABLE, which is what makes the caller's arm
/// worth having. It does NOT drive the caller's arm: reaching that needs a
/// prepared item whose enqueue fails AND whose descriptor is already corrupt,
/// and the prepare step writes the offset it later reads back, so nothing in
/// this harness can mint that pairing without a corruption seam that does not
/// exist. The caller's arm is therefore covered by construction (it cannot
/// panic — there is no `expect` left) rather than by a fail-on-revert cell, and
/// the anti-over-count control is the existing
/// `..._admission_drop_does_not_inflate_tx_errors` cell, which still passes:
/// this change adds a `tx_errors` bump on a FAULT and must not disturb the
/// shaping-drop accounting.
#[test]
fn clone_prepared_request_for_cos_refuses_an_out_of_bounds_descriptor_8597_k41() {
    let area = MmapArea::new(4096).expect("mmap");
    let mut req = PreparedTxRequest {
        // Past the end of a 4096-byte area: `area.slice` must refuse.
        offset: 8192,
        len: 64,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 80,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    };
    assert!(
        clone_prepared_request_for_cos(&area, &mut req).is_none(),
        "a descriptor outside the UMEM must make the clone refuse — the caller \
         turns that refusal into a counted drop instead of the worker panic it \
         used to be (#8597 K41)"
    );
}
