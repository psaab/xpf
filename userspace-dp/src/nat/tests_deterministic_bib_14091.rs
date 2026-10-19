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
        Some(params),
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

#[test]
fn deterministic_napt64_expired_block_bibs_reclaimed_on_exhaustion_14670() {
    let allocator = PortAllocator::new(1, 1024, 1027);
    let params = DeterministicV6 {
        block_size: 4, blocks_per_ip: 1, host_prefix_len: 32,
        host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(), host_count: 1,
    };
    let mut flows = Vec::new();
    let mut tuples = Vec::new();
    for i in 0..4u16 {
        let f = flow_from_source(40000 + i, Ipv4Addr::new(8, 8, 8, 8), 443);
        let t = allocator.allocate_deterministic_v6_at(f, &[POOL], params, SUB, 1, NatHolder::Untracked).unwrap();
        flows.push(f);
        tuples.push(t);
    }
    assert_eq!(allocator.snapshot().persistent_leases, 4);
    for (f, t) in flows.iter().zip(tuples.iter()) {
        assert!(allocator.release_flow(*f, *t, 20, NatHolder::Untracked));
    }
    assert_eq!(allocator.live_flow_count(), 0);
    let later = 20 + 300_000_000_001u64;
    let new_flow = flow_from_source(40010, Ipv4Addr::new(9, 9, 9, 9), 80);
    let got = allocator.allocate_deterministic_v6_at(new_flow, &[POOL], params, SUB, later, NatHolder::Untracked)
        .expect("expired BIBs in the subscriber block must be reclaimed on exhaustion");
    assert!((1024..=1027).contains(&got.port), "reclaimed port must be inside the subscriber block, got {}", got.port);
    assert_eq!(allocator.snapshot().persistent_leases, 1, "expired block BIBs must be GC'd, not left as phantom leases");
}

#[test]
fn deterministic_napt64_rollback_preserves_imported_bib_14670() {
    let params = DeterministicV6 { block_size: 32, blocks_per_ip: 2, host_prefix_len: 32, host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(), host_count: 1 };
    let origin = PortAllocator::new(1, 1024, 1087);
    let f0 = flow(Ipv4Addr::new(8, 8, 8, 8), 443);
    let t0 = origin.allocate_deterministic_v6(f0, &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    assert!(origin.release_flow(f0, t0, 20, NatHolder::Untracked));
    let exported = origin.export_idle_leases(21);
    assert_eq!(exported.len(), 1);
    let standby = PortAllocator::new(1, 1024, 1087);
    assert_eq!(standby.import_idle_lease(&exported[0], &[IpAddr::V4(POOL)], 300_000_000_000, 1_000), super::IdleLeaseImport::Installed);
    let join_flow = flow(Ipv4Addr::new(1, 1, 1, 1), 53);
    let joined = standby.allocate_deterministic_v6_at(join_flow, &[POOL], params, SUB, 2_000, NatHolder::Untracked).unwrap();
    assert_eq!(joined.port, exported[0].translated_port);
    let before = standby.debug_persistent_lease_for_flow(&join_flow, super::source::PersistentNatPermit::AnyRemoteHost).unwrap();
    assert!(before.imported, "joined lease must still be the imported BIB");
    assert!(standby.rollback_flow(join_flow, joined, 3_000, NatHolder::Untracked));
    let after = standby.debug_persistent_lease_for_flow(&join_flow, super::source::PersistentNatPermit::AnyRemoteHost)
        .expect("rollback of a flow joining an imported BIB must not delete the BIB");
    assert_eq!(after.translated, before.translated);
    assert_eq!(after.active_flows, 0);
    assert!(after.imported);
    let rejoined = standby.allocate_deterministic_v6_at(flow(Ipv4Addr::new(2, 2, 2, 2), 8443), &[POOL], params, SUB, 4_000, NatHolder::Untracked).unwrap();
    assert_eq!(rejoined.port, exported[0].translated_port);
}

#[test]
fn deterministic_napt64_capacity_reuse_and_max_tracked_14670() {
    let allocator = PortAllocator::new(1, 1024, 1024);
    let params = DeterministicV6 {
        block_size: 1, blocks_per_ip: 1, host_prefix_len: 32,
        host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(), host_count: 1,
    };
    let f1 = flow(Ipv4Addr::new(8, 8, 8, 8), 443);
    let t1 = allocator.allocate_deterministic_v6_at(f1, &[POOL], params, SUB, 1, NatHolder::Untracked).unwrap();
    let f2 = flow(Ipv4Addr::new(1, 1, 1, 1), 53);
    let err = allocator.allocate_deterministic_v6_at(f2, &[POOL], params, SUB, 2, NatHolder::Untracked);
    assert!(err.is_err(), "full-block BIB reuse must enforce max_tracked_flows, got {err:?} (t1={t1:?})");
    assert_eq!(allocator.live_flow_count(), 1);
}

#[test]
fn deterministic_napt64_synced_first_bib_joins_local_15179() {
    // #15179: standby imports a deterministic session before any BIB exists.
    // The synced reserve must stamp the prefix's deterministic identity so a
    // post-failover local same-socket flow to a new remote joins the synced
    // tuple instead of failing AllocatorExhausted.
    let params = DeterministicV6 {
        block_size: 32, blocks_per_ip: 2, host_prefix_len: 32,
        host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(), host_count: 1,
    };
    let standby = PortAllocator::new(1, 1024, 1087);
    // Synced tuple is inside SUB's block (1024..=1055 for this fixture).
    let synced_tuple = super::allocator::TranslatedTuple { ip: IpAddr::V4(POOL), port: 1030 };
    let synced_flow = flow(Ipv4Addr::new(2, 2, 2, 2), 8443);
    assert!(super::reserve_nat64_pool_port(
        &standby,
        synced_flow,
        POOL,
        synced_tuple.port,
        0,
        Some(params),
        10,
        NatHolder::Worker(1),
    ), "synced-first reserve must install the BIB");
    let debug = standby.debug_persistent_lease_for_flow(&synced_flow, super::source::PersistentNatPermit::AnyRemoteHost).unwrap();
    assert!(debug.deterministic, "synced-first lease must be deterministic");
    assert_eq!(debug.deterministic_identity, Some(super::DeterministicPortedIdentity::V6(params)), "synced-first lease must carry the prefix deterministic identity");
    assert!(debug.imported);
    // Local same-socket flow to a NEW remote must join the synced tuple.
    let local_flow = flow(Ipv4Addr::new(9, 9, 9, 9), 80);
    let joined = standby.allocate_deterministic_v6(local_flow, &[POOL], params, SUB, NatHolder::Untracked)
        .expect("local same-socket new-remote flow must join the synced-first BIB, not AllocatorExhausted");
    assert_eq!(joined, synced_tuple, "local flow must return the synced tuple");
    assert_eq!(standby.live_flow_count(), 2);
    // Control: local-first path is unchanged — a fresh allocator's local
    // allocation still mints its own deterministic tuple in the block.
    let local_first = PortAllocator::new(1, 1024, 1087);
    let first_local = local_first.allocate_deterministic_v6(flow(Ipv4Addr::new(8, 8, 8, 8), 443), &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    let second_local = local_first.allocate_deterministic_v6(flow(Ipv4Addr::new(1, 1, 1, 1), 53), &[POOL], params, SUB, NatHolder::Untracked).unwrap();
    assert_eq!(first_local, second_local, "local-first control: same socket across remotes shares one BIB");
}
