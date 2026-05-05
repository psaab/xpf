// Tests for afxdp/tx/cos_classify.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep cos_classify.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "cos_classify_tests.rs"]` from cos_classify.rs.

use super::*;
use crate::afxdp::tx::test_support::*;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    FirewallFilterSnapshot, FirewallTermSnapshot,
};

#[test]
fn resolve_cos_queue_idx_rejects_explicit_queue_miss() {
    let root = test_cos_runtime_with_queues(
        10_000_000,
        vec![CoSQueueConfig {
            queue_id: 5,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 10_000_000,
            exact: false,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );

    assert_eq!(resolve_cos_queue_idx(&root, Some(4)), None);
    assert_eq!(resolve_cos_queue_idx(&root, None), Some(0));
}

#[test]
fn clone_prepared_request_for_cos_returns_local_copy_with_metadata() {
    let mut area = MmapArea::new(4096).expect("mmap");
    let payload = [0xde, 0xad, 0xbe, 0xef];
    area.slice_mut(128, payload.len())
        .expect("slice")
        .copy_from_slice(&payload);
    let req = PreparedTxRequest {
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
        }),
        egress_ifindex: 80,
        cos_queue_id: Some(4),
        dscp_rewrite: Some(46),
    };

    let local = clone_prepared_request_for_cos(&area, &req).expect("local copy");

    assert_eq!(local.bytes, payload);
    assert_eq!(local.expected_ports, Some((1111, 2222)));
    assert_eq!(local.expected_addr_family, libc::AF_INET6 as u8);
    assert_eq!(local.expected_protocol, PROTO_TCP);
    assert_eq!(local.egress_ifindex, 80);
    assert_eq!(local.cos_queue_id, Some(4));
    assert_eq!(local.dscp_rewrite, Some(46));
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
    let req = PreparedTxRequest {
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
    };

    assert!(clone_prepared_request_for_cos(&area, &req).is_none());
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
        }),
        egress_ifindex: 80,
        cos_queue_id: Some(5),
        dscp_rewrite: Some(46),
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.queues[0]
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.queues[0]
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
        }));
    root.queues[0]
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
    ));

    let items = root.queues[0]
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
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;
    queue.flow_hash_seed = 0;

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
        }),
    );

    // Snapshot pre-demote MQFQ frontier.
    let pre_vtime = queue.queue_vtime;
    let pre_head_a = queue.flow_bucket_head_finish_bytes[bucket_a];
    let pre_head_b = queue.flow_bucket_head_finish_bytes[bucket_b];
    let pre_tail_a = queue.flow_bucket_tail_finish_bytes[bucket_a];
    let pre_tail_b = queue.flow_bucket_tail_finish_bytes[bucket_b];
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
    ));

    let queue = &mut root.queues[0];

    // Frontier MUST be unchanged across the success path.
    assert_eq!(
        queue.queue_vtime, pre_vtime,
        "#926 regression: queue_vtime must be preserved across \
         demote success path. Pre={pre_vtime} post={}",
        queue.queue_vtime
    );
    assert_eq!(
        queue.flow_bucket_head_finish_bytes[bucket_a], pre_head_a,
        "#926: head_finish[A] must be preserved (pre={pre_head_a})"
    );
    assert_eq!(
        queue.flow_bucket_head_finish_bytes[bucket_b], pre_head_b,
        "#926: head_finish[B] must be preserved (pre={pre_head_b})"
    );
    assert_eq!(
        queue.flow_bucket_tail_finish_bytes[bucket_a], pre_tail_a,
        "#926: tail_finish[A] must be preserved"
    );
    assert_eq!(
        queue.flow_bucket_tail_finish_bytes[bucket_b], pre_tail_b,
        "#926: tail_finish[B] must be preserved"
    );

    // Items now Local. flow_fair=true stores items in
    // per-bucket VecDeques at `flow_bucket_items[bucket]`,
    // not in `queue.items`.
    let mut total_items = 0;
    for bucket in [bucket_a, bucket_b] {
        for item in queue.flow_bucket_items[bucket].iter() {
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
            exact: false,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    );
    root.queues[0]
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
    ));
    assert!(matches!(
        root.queues[0].items.front(),
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    surplus_sharing: false,
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
        }),
    );

    assert_eq!(queue_id, Some(1));
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    surplus_sharing: false,
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
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(cached.queue_id, Some(1));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(cached.filter_counter.is_some());
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    surplus_sharing: false,
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    surplus_sharing: false,
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
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(cached.queue_id, Some(1));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(cached.filter_counter.is_some());
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
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                surplus_sharing: false,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
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
        Some(&SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        }),
    );

    assert_eq!(cached.queue_id, Some(0));
    assert_eq!(cached.dscp_rewrite, None);
    assert!(cached.filter_counter.is_some());
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
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                surplus_sharing: false,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
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
        }),
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    surplus_sharing: false,
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
        }),
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
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                surplus_sharing: false,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
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
        }),
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
        }),
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
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                surplus_sharing: false,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "voice-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    surplus_sharing: false,
                },
            ],
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "voice-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    surplus_sharing: false,
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "bulk-sched".into(),
                    transmit_rate_bytes: 6_000_000,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
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
fn resolve_cos_queue_id_preserves_ingress_classification_when_output_filter_has_no_forwarding_class(
) {
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
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 10_000_000,
                    transmit_rate_exact: false,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 128_000,
                    surplus_sharing: false,
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
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                surplus_sharing: false,
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
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
        }),
    );

    assert_eq!(selection.queue_id, Some(7));
    assert_eq!(selection.dscp_rewrite, Some(46));
}
