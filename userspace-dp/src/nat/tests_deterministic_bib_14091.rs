// #14091 RED: deterministic NAPT64 mappings are keyed by the full remote flow,
// but RFC 6146 requires one BIB per (protocol, subscriber, source port, scope).
use super::allocator::{DeterministicV6, NatHolder, PortAllocator};
use super::source::SourceNatFlowKey;
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const POOL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const SUB: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
fn flow(dst: Ipv4Addr, dst_port: u16) -> SourceNatFlowKey {
    flow_from_source(40000, dst, dst_port)
}

fn flow_from_source(src_port: u16, dst: Ipv4Addr, dst_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey { protocol: 6, src_ip: IpAddr::V6(SUB), dst_ip: IpAddr::V4(dst), src_port, dst_port, routing_scope: 0 }
}
#[test]
fn deterministic_napt64_same_transport_to_two_remotes_shares_bib_14091() {
    let allocator = PortAllocator::new(1, 1024, 1087);
    let params = DeterministicV6 {
        block_size: 32, blocks_per_ip: 2, host_prefix_len: 32,
        host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(), host_count: 1,
    };
    let first_flow = flow(Ipv4Addr::new(8,8,8,8), 443);
    let second_flow = flow(Ipv4Addr::new(1,1,1,1), 53);
    let first = allocator.allocate_deterministic_v6(first_flow, &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    let second = allocator.allocate_deterministic_v6(second_flow, &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    assert_eq!(first, second, "same subscriber transport must reuse one BIB tuple across remote endpoints");
    assert_eq!(allocator.live_flow_count(), 2, "the two remote-specific sessions remain independently tracked");
    let distinct_transport = flow_from_source(40001, Ipv4Addr::new(8, 8, 4, 4), 443);
    let other = allocator.allocate_deterministic_v6(
        distinct_transport,
        &[POOL],
        params,
        SUB,
        NatHolder::Untracked,
    ).unwrap();
    assert_ne!(first, other, "different subscriber source ports must retain distinct BIBs");

    assert!(allocator.release_flow(first_flow, first, 10, NatHolder::Untracked));
    assert_eq!(allocator.live_flow_count(), 2);
    let third_flow = flow(Ipv4Addr::new(9, 9, 9, 9), 80);
    let third = allocator.allocate_deterministic_v6(third_flow, &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    assert_eq!(third, second, "tearing down one session must not retire a BIB with another active session");
    assert_eq!(allocator.live_flow_count(), 3);
    assert!(allocator.deterministic_v6_tuple_matches(params, SUB, &[POOL], 0, POOL, second.port));
    assert!(
        !allocator.deterministic_v6_tuple_matches(params, SUB, &[POOL], 0, POOL, 1060),
        "HA must reject a translated port outside this subscriber's deterministic block"
    );
    let synced_flow = flow(Ipv4Addr::new(2, 2, 2, 2), 8443);
    assert!(super::reserve_nat64_pool_port(
        &allocator,
        synced_flow,
        POOL,
        second.port,
        0,
        true,
        15,
        NatHolder::Worker(1),
    ), "HA reservation for another destination must join the existing BIB");
    assert_eq!(allocator.live_flow_count(), 4);
    assert!(allocator.release_flow(synced_flow, second, 18, NatHolder::Worker(1)));
    assert!(allocator.release_flow(second_flow, second, 20, NatHolder::Untracked));
    assert!(allocator.release_flow(third_flow, third, 20, NatHolder::Untracked));
    allocator.debug_gc_expired_chunked(300_000_000_021, 16);
    let after_expiry = allocator.allocate_deterministic_v6_at(
        flow(Ipv4Addr::new(4, 4, 4, 4), 53),
        &[POOL],
        params,
        SUB,
        300_000_000_021,
        NatHolder::Untracked,
    ).unwrap();
    assert_eq!(after_expiry, second, "an idle BIB is retained until the 300-second timeout, then GC makes its deterministic port reusable");
}

#[test]
fn deterministic_napt64_destinations_racing_share_one_bib_14091() {
    let allocator = PortAllocator::new(1, 1024, 1087);
    let params = DeterministicV6 {
        block_size: 32,
        blocks_per_ip: 2,
        host_prefix_len: 32,
        host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(),
        host_count: 1,
    };
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let first_allocator = allocator.clone();
    let first_barrier = barrier.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first_allocator
            .allocate_deterministic_v6(
                flow(Ipv4Addr::new(8, 8, 8, 8), 443),
                &[POOL],
                params,
                SUB,
                NatHolder::Untracked,
            )
            .unwrap()
    });
    let second_barrier = barrier.clone();
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        allocator
            .allocate_deterministic_v6(
                flow(Ipv4Addr::new(1, 1, 1, 1), 53),
                &[POOL],
                params,
                SUB,
                NatHolder::Untracked,
            )
            .unwrap()
    });
    barrier.wait();
    let first = first_thread.join().unwrap();
    let second = second_thread.join().unwrap();
    assert_eq!(first, second, "concurrent remote-specific sessions must converge on one BIB tuple");
}

#[test]
fn deterministic_napt64_bib_identity_teardown_and_idle_import_14091() {
    let params = DeterministicV6 { block_size: 32, blocks_per_ip: 2, host_prefix_len: 32, host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(), host_count: 1 };
    let allocator = PortAllocator::new(1, 1024, 1087);
    let tcp_flow = flow(Ipv4Addr::new(8, 8, 8, 8), 443);
    let mut udp_flow = flow_from_source(40000, Ipv4Addr::new(8, 8, 8, 8), 53); udp_flow.protocol = 17;
    let mut scoped_flow = flow(Ipv4Addr::new(8, 8, 8, 8), 443); scoped_flow.routing_scope = 7;
    let tcp = allocator.allocate_deterministic_v6(tcp_flow, &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    let udp = allocator.allocate_deterministic_v6(udp_flow, &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    let scoped = allocator.allocate_deterministic_v6(scoped_flow, &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    assert_ne!(tcp, udp, "protocol is part of the BIB identity");
    assert_ne!(tcp, scoped, "routing scope is part of the BIB identity");
    let debug = allocator.debug_persistent_lease_for_flow(&tcp_flow, super::source::PersistentNatPermit::AnyRemoteHost).unwrap();
    assert!(debug.deterministic && debug.deterministic_identity == Some(super::DeterministicPortedIdentity::V6(params)));
    assert!(allocator.rollback_flow(tcp_flow, tcp, 10, NatHolder::Untracked));
    assert_eq!(allocator.debug_recycled_ports(0), vec![tcp.port], "#14625: deterministic rollback recycles (bounded ring; claim_in_block ignores it)");
    let tcp2 = allocator.allocate_deterministic_v6(tcp_flow, &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    assert!(allocator.release_flow(tcp_flow, tcp2, 20, NatHolder::Untracked));
    assert!(allocator.release_flow(udp_flow, udp, 20, NatHolder::Untracked));
    assert!(allocator.release_flow(scoped_flow, scoped, 20, NatHolder::Untracked));
    assert!(!allocator.debug_recycled_ports(0).is_empty(), "#14625: deterministic releases recycle (bounded ring; claim_in_block ignores it)");
    let exported = allocator.export_idle_leases(21);
    assert_eq!(exported.len(), 3, "idle deterministic BIBs must be exportable for failover");
    assert!(exported.iter().all(|r| r.deterministic && r.deterministic_identity == Some(super::DeterministicPortedIdentity::V6(params))));
    let standby = PortAllocator::new(1, 1024, 1087);
    for rec in &exported {
        assert_eq!(standby.import_idle_lease(rec, &[IpAddr::V4(POOL)], 300_000_000_000, 1_000), super::IdleLeaseImport::Installed, "idle failover import must preserve deterministic BIB");
    }
    let joined = standby.allocate_deterministic_v6(flow(Ipv4Addr::new(1, 1, 1, 1), 53), &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    assert_eq!(joined.port, exported.iter().find(|r| r.protocol == 6 && r.routing_scope == 0).unwrap().translated_port, "post-failover local flow must join imported BIB");
    assert!(!allocator.deterministic_v6_tuple_matches(params, SUB, &[POOL], 0, POOL, exported[0].translated_port + 32), "coordinator must reject ports outside the subscriber block");
    let mut mismatched = exported[0].clone(); mismatched.deterministic_identity = Some(super::DeterministicPortedIdentity::V6(DeterministicV6 { block_size: 64, ..params }));
    assert_ne!(mismatched.deterministic_identity, exported[0].deterministic_identity, "configuration identity must be distinguishable");
}
