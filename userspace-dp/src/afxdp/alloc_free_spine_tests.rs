//! #17272: warmed flow-cache hit allocation cells.
//!
//! This module is nested under `poll_descriptor::flow_cache_hit_tests` so it
//! can reuse the production-stage fixture and the `StageSeed` warmup seam. The
//! first identical packet is outside the counting window; the next packet is
//! measured after the cache memo and TX queue capacity are warm.

use super::*;
use std::net::Ipv6Addr;

#[test]
fn established_forward_cache_hit_has_no_allocations_17272() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    // Selected mirror intentionally snapshots an owned frame; test the
    // allocation-free unsampled cache-hit arm here.
    fixture.forwarding.mirror_configs.clear();
    let frame = tcp_v4_ack_frame();
    let run = run_stage_seeded(
        &fixture,
        &frame,
        test_meta(&frame),
        cached_entry(),
        0,
        StageSeed {
            warm_before_measure: true,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "premise: the repeated established packet is served by the flow cache"
    );
    assert_eq!(run.flow_cache_tallies.0, 2, "warmup and measured calls both hit");
    assert_eq!(
        run.stage_allocs, 0,
        "#17272: warmed established IPv4 forward cache hit must not allocate"
    );
}

#[test]
fn established_forward_v6_cache_hit_has_no_allocations_17272() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
        src_port: 45678,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut frame = Vec::with_capacity(78);
    frame.extend_from_slice(&[
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0xbf, 0x72, 0x00, 0x01, 0x01,
        0x81, 0x00, 0x00, 0x50, 0x86, 0xdd,
    ]);
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&45678u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, 0x10, 0x20, 0, 0, 0, 0, 0]);
    assert_eq!(frame.len(), 78);

    let mut src_addr = [0; 16];
    src_addr.copy_from_slice(&src.octets());
    let mut dst_addr = [0; 16];
    dst_addr.copy_from_slice(&dst.octets());
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: PHYS_INGRESS_IFINDEX as u32,
        ingress_vlan_id: INGRESS_VLAN_ID,
        ingress_vlan_present: 1,
        l3_offset: 18,
        l4_offset: 58,
        payload_offset: frame.len() as u16,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        flow_src_port: 45678,
        flow_dst_port: 443,
        ..UserspaceDpMeta::default()
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
        forward_key: key.clone(),
    };
    let mut entry = cached_entry();
    entry.key = key;
    entry.descriptor.ether_type = 0x86dd;
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    fixture.forwarding.mirror_configs.clear();
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            flow: Some(flow),
            warm_before_measure: true,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "premise: the repeated IPv6 packet is served by the flow cache"
    );
    assert_eq!(run.flow_cache_tallies.0, 2, "warmup and measured calls both hit");
    let tx_frame = run
        .tx_frame
        .as_deref()
        .expect("the cached IPv6 packet must be emitted");
    assert_eq!(&tx_frame[16..18], &[0x86, 0xdd], "emitted L2 remains IPv6");
    assert_eq!(
        run.stage_allocs, 0,
        "#17272: warmed established IPv6 forward cache hit must not allocate"
    );
}

#[test]
#[ignore = "#19005"]
fn syn_cookie_pool_challenge_has_no_allocations_17272() {
    // #19005 expiry: the pool fence, session-miss spine, and owned reply still allocate.
    let mut snapshot = crate::afxdp::test_fixtures::nat_snapshot();
    snapshot.source_nat_rules = vec![crate::SourceNATRuleSnapshot {
        name: "large-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_addresses: vec!["198.51.0.0/16".to_string()],
        port_low: 5000,
        port_high: 6000,
        ..Default::default()
    }];
    let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
    assert_eq!(forwarding.source_nat_rules[0].pool_ranges_v4.len(), 1);

    let mut binding = crate::afxdp::BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = std::sync::Arc::<str>::from("reth1.0");
    binding.tx_pipeline.pending_tx_local.reserve(64);
    binding.tx_pipeline.pending_tx_prepared.reserve(64);
    let mut sessions = crate::session::SessionTable::new();
    let mut harness = crate::afxdp::tests_support::TxnHarness::new(&binding);
    harness.enable_syn_cookie_for_zone("lan", [0x42; 16]);
    let ha_state = crate::afxdp::tests_support::txn_ha_state();
    let src = Ipv4Addr::new(10, 0, 61, 103);
    let dst = Ipv4Addr::new(9, 9, 9, 9);
    let make_syn = |src_port| {
        let frame = crate::afxdp::tests_support::build_txn_tcp_syn_frame_v4(
            src,
            dst,
            src_port,
            443,
            0x02,
            crate::afxdp::tests_support::TEST_LAN_MAC,
        );
        let mut meta = crate::afxdp::tests_support::txn_meta_v4(24, 0x02, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&src.octets());
        meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
        meta.flow_src_port = src_port;
        (frame, meta)
    };

    let (initial_frame, initial_meta) = make_syn(49200);
    let ((initial, _), _) = harness.run(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &initial_frame,
        initial_meta,
    );
    assert_eq!(initial.syn_cookie_challenges, 0);
    binding.tx_pipeline.pending_tx_local.clear();

    let (challenge_frame, challenge_meta) = make_syn(49201);
    let ((warm_batch, _), _) = harness.run(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &challenge_frame,
        challenge_meta,
    );
    assert_eq!(warm_batch.syn_cookie_challenges, 1);
    assert_eq!(warm_batch.syn_cookie_syn_ack_sent, 1);
    binding.tx_pipeline.pending_tx_local.clear();

    // Repeat the same challenged tuple after warmup; fixture creation, queue
    // capacity, and the first reply are outside this allocator-counted poll.
    let ((measured, _), allocations) = harness.run(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &challenge_frame,
        challenge_meta,
    );
    assert_eq!(measured.syn_cookie_challenges, 1);
    assert_eq!(measured.syn_cookie_syn_ack_sent, 1);
    assert_eq!(
        allocations, 0,
        "#17272: warmed pool-mode SYN-cookie challenge must not allocate"
    );
}
