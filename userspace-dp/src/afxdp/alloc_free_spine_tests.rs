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
