// #10721: a deterministic PAT allocation must keep scanning its assigned
// subscriber block when an address-only flow already owns one candidate's
// exact reverse identity. Reaching the end of the block, not the first such
// collision, is what makes this allocator exhausted.
// Fail-on-revert: the old check returned AllocatorExhausted on the first exact
// collision, so retry tests require the next port while full-block controls
// require exhaustion only after every port is owned.

use super::allocator::{DeterministicV4, DeterministicV6, NatHolder, PortAllocator};
use super::source::{SourceNatFailureReason, SourceNatFlowKey};
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const POOL_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const V4_SUBSCRIBER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
const V6_SUBSCRIBER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const PORT_LOW: u16 = 20_000;
const PORT_HIGH: u16 = 20_003;
const BLOCK_SIZE: u16 = PORT_HIGH - PORT_LOW + 1;

fn flow(src_ip: IpAddr, src_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip,
        dst_ip: IpAddr::V4(REMOTE_IP),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn deterministic_v4() -> DeterministicV4 {
    DeterministicV4 {
        block_size: BLOCK_SIZE,
        blocks_per_ip: 1,
        host_base: u32::from(V4_SUBSCRIBER),
        host_count: 1,
    }
}

fn deterministic_v6() -> DeterministicV6 {
    DeterministicV6 {
        block_size: BLOCK_SIZE,
        blocks_per_ip: 4,
        host_prefix_len: 32,
        host_base: V6_SUBSCRIBER.octets(),
        host_count: 4,
    }
}

fn reserve_v4_identity(alloc: &PortAllocator, port: u16) {
    let address_only = flow(IpAddr::V4(V4_SUBSCRIBER), port);
    let translated = alloc
        .reserve_address_only(address_only, IpAddr::V4(POOL_IP), NatHolder::Untracked)
        .expect("address-only owner reserves its wire identity");
    assert_eq!(translated.port, port);
}

fn reserve_v6_identity(alloc: &PortAllocator, port: u16) {
    let address_only = flow(IpAddr::V6(V6_SUBSCRIBER), port);
    let translated = alloc
        .reserve_address_only(address_only, IpAddr::V4(POOL_IP), NatHolder::Untracked)
        .expect("address-only owner reserves its wire identity");
    assert_eq!(translated.port, port);
}

#[test]
fn deterministic_v4_skips_address_only_collision_within_block_10721() {
    let alloc = PortAllocator::new(1, PORT_LOW, PORT_HIGH);
    reserve_v4_identity(&alloc, PORT_LOW);

    let translated = alloc
        .allocate_deterministic_v4(
            flow(IpAddr::V4(V4_SUBSCRIBER), 40_000),
            &[POOL_IP],
            deterministic_v4(),
            V4_SUBSCRIBER,
            NatHolder::Untracked,
        )
        .expect("the next port in the assigned block is available");

    assert_eq!(translated.ip, IpAddr::V4(POOL_IP));
    assert_eq!(translated.port, PORT_LOW + 1);
    assert!(!alloc.debug_is_port_occupied(0, PORT_LOW));
    assert!(alloc.debug_is_port_occupied(0, PORT_LOW + 1));
}

#[test]
fn deterministic_v6_skips_address_only_collision_within_block_10721() {
    let alloc = PortAllocator::new(1, PORT_LOW, PORT_HIGH);
    reserve_v6_identity(&alloc, PORT_LOW);

    let translated = alloc
        .allocate_deterministic_v6(
            flow(IpAddr::V6(V6_SUBSCRIBER), 40_000),
            &[POOL_IP],
            deterministic_v6(),
            V6_SUBSCRIBER,
            NatHolder::Untracked,
        )
        .expect("the next port in the assigned block is available");

    assert_eq!(translated.ip, IpAddr::V4(POOL_IP));
    assert_eq!(translated.port, PORT_LOW + 1);
    assert!(!alloc.debug_is_port_occupied(0, PORT_LOW));
    assert!(alloc.debug_is_port_occupied(0, PORT_LOW + 1));
}

#[test]
fn deterministic_v4_exhausts_only_after_every_block_port_collides_10721() {
    let alloc = PortAllocator::new(1, PORT_LOW, PORT_HIGH);
    for port in PORT_LOW..=PORT_HIGH {
        reserve_v4_identity(&alloc, port);
    }

    assert_eq!(
        alloc.allocate_deterministic_v4(
            flow(IpAddr::V4(V4_SUBSCRIBER), 40_000),
            &[POOL_IP],
            deterministic_v4(),
            V4_SUBSCRIBER,
            NatHolder::Untracked,
        ),
        Err(SourceNatFailureReason::AllocatorExhausted),
    );
    assert_eq!(alloc.debug_occupied_count(), 0);
}

#[test]
fn deterministic_v6_exhausts_only_after_every_block_port_collides_10721() {
    let alloc = PortAllocator::new(1, PORT_LOW, PORT_HIGH);
    for port in PORT_LOW..=PORT_HIGH {
        reserve_v6_identity(&alloc, port);
    }

    assert_eq!(
        alloc.allocate_deterministic_v6(
            flow(IpAddr::V6(V6_SUBSCRIBER), 40_000),
            &[POOL_IP],
            deterministic_v6(),
            V6_SUBSCRIBER,
            NatHolder::Untracked,
        ),
        Err(SourceNatFailureReason::AllocatorExhausted),
    );
    assert_eq!(alloc.debug_occupied_count(), 0);
}
