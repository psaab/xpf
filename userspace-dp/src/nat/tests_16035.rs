//! #16035: freed PAT ports on small pools must sit out a minimum
//! reuse delay (quarantine) before any new flow can claim them, so a
//! delayed UDP reply for the old flow cannot land on a new owner of
//! the same (translated_ip, port, remote). Large pools and TCP are
//! controls: large pools already de-facto quarantine via FIFO-after-
//! fresh-range, and TCP endpoints reject stray segments by seq.
//!
//! Cells drive the real `PortAllocator` (allocate -> release ->
//! reallocate at injected monotonic times), not the ring in isolation,
//! so reverting the quarantine in EITHER the keyed probe or the
//! recycled phase turns the tiny-pool cell red: pre-fix, the freed
//! port's bit is clear and the very next claim at the same instant
//! hands it straight back out.

use super::allocator::{PoolAddressFamily, PortAllocator, TranslatedTuple};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use super::*;
use std::net::{IpAddr, Ipv4Addr};

const POOL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const T0: u64 = 1_000_000_000_000;
const QUARANTINE_NS: u64 = super::allocator::PAT_PORT_QUARANTINE_NS_FOR_TEST;

fn flow(protocol: u8, src_port: u16, dst_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port,
        dst_port,
        routing_scope: 0,
    }
}

fn alloc_at(alloc: &PortAllocator, f: SourceNatFlowKey, now_ns: u64) -> TranslatedTuple {
    let addrs = [POOL];
    alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            now_ns,
            NatHolder::Untracked,
            0,
        )
        .expect("allocation must succeed")
}

fn alloc_err_at(alloc: &PortAllocator, f: SourceNatFlowKey, now_ns: u64) -> bool {
    let addrs = [POOL];
    alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            now_ns,
            NatHolder::Untracked,
            0,
        )
        .is_err()
}

/// Tiny pool (2 ports), UDP: fill it, free one port, and the freed
/// port must NOT be reissued during the quarantine — a new flow is
/// refused (both ports unavailable to it) — then must be reissued
/// once the delay has passed. Pre-fix the middle claim succeeds with
/// the just-freed port, which is exactly the misdelivery window.
#[test]
fn tiny_pool_udp_freed_port_quarantined_16035() {
    let alloc = PortAllocator::new(1, 1024, 1025);
    let a = flow(17, 40_000, 53);
    let b = flow(17, 40_001, 53);
    let ta = alloc_at(&alloc, a, T0);
    let tb = alloc_at(&alloc, b, T0);
    assert_ne!(ta.port, tb.port, "fixture: two distinct ports");
    assert!(
        alloc_err_at(&alloc, flow(17, 40_002, 53), T0),
        "full pool refuses"
    );

    // Free A's port at T0; a new UDP flow at the same instant (and
    // just before the delay elapses) must not receive it.
    assert!(alloc.release_flow(a, ta, T0, NatHolder::Untracked));
    let c = flow(17, 40_003, 53);
    assert!(
        alloc_err_at(&alloc, c, T0),
        "#16035: just-freed UDP port on a tiny pool must be quarantined, not instantly reused"
    );
    assert!(
        alloc_err_at(&alloc, c, T0 + QUARANTINE_NS - 1),
        "#16035: port must stay quarantined until the minimum reuse delay elapses"
    );
    // After the delay the port is reusable again (no leak).
    let tc = alloc_at(&alloc, c, T0 + QUARANTINE_NS);
    assert_eq!(
        tc.port, ta.port,
        "after quarantine the freed port must be handed out again"
    );
}

/// Control: TCP on the same tiny pool also sits out the delay at the
/// allocator layer (the allocator is protocol-blind; TCP's safety
/// argument is that it would not NEED the delay, not that it is
/// exempted). This pins that the fix did not special-case UDP in a
/// way that lets TCP — or any other protocol — bypass the gate, and
/// that TCP reuse works normally after the delay.
#[test]
fn tiny_pool_tcp_control_reuses_after_delay_16035() {
    let alloc = PortAllocator::new(1, 1024, 1025);
    let a = flow(6, 40_000, 443);
    let b = flow(6, 40_001, 443);
    let ta = alloc_at(&alloc, a, T0);
    let _tb = alloc_at(&alloc, b, T0);
    assert!(alloc.release_flow(a, ta, T0, NatHolder::Untracked));
    let c = flow(6, 40_003, 443);
    assert!(
        alloc_err_at(&alloc, c, T0),
        "allocator-level quarantine is protocol-uniform on small pools"
    );
    let tc = alloc_at(&alloc, c, T0 + QUARANTINE_NS);
    assert_eq!(tc.port, ta.port, "TCP port reusable after the delay");
}

/// Control: a LARGE pool must not pay the delay — a freed port there
/// is reachable again immediately through the normal probe/ring,
/// because FIFO-after-fresh-range already spaces reuse. 1024 ports
/// (> SMALL_POOL_QUARANTINE_MAX_RANGE): fill, free one, reclaim at
/// the same instant must succeed.
#[test]
fn large_pool_no_quarantine_16035() {
    let alloc = PortAllocator::new(1, 1024, 2047);
    let a = flow(17, 40_000, 53);
    let ta = alloc_at(&alloc, a, T0);
    assert!(alloc.release_flow(a, ta, T0, NatHolder::Untracked));
    // A different flow may or may not land on ta's port (keyed probe
    // over 1024 ports), but SOME allocation must succeed instantly —
    // the pool is nearly empty, so any quarantine-induced refusal of
    // the whole claim would be the blanket-tax regression.
    let tb = alloc_at(&alloc, flow(17, 40_001, 53), T0);
    assert!((1024..=2047).contains(&tb.port));
}

/// Occupancy-level pin: the recycled phase itself honours the delay
/// and RETAINS (does not drop) a quarantined token, preserving its
/// original free time across repeated claims inside the window.
#[test]
fn recycled_phase_retains_quarantined_token_16035() {
    let alloc = PortAllocator::new(1, 1024, 1025);
    let a = flow(17, 40_000, 53);
    let b = flow(17, 40_001, 53);
    let ta = alloc_at(&alloc, a, T0);
    let _tb = alloc_at(&alloc, b, T0);
    assert!(alloc.release_flow(a, ta, T0, NatHolder::Untracked));
    // Inside the window the recycled phase yields nothing, twice,
    // and the token survives both walks.
    assert_eq!(alloc.debug_claim_recycled_only_at(0, T0), None);
    assert_eq!(alloc.debug_claim_recycled_only_at(0, T0 + 1), None);
    assert_eq!(
        alloc.debug_recycled_ports(0),
        vec![ta.port],
        "quarantined token must be retained, not dropped"
    );
    // At the boundary it is claimable through the ring.
    assert_eq!(
        alloc.debug_claim_recycled_only_at(0, T0 + QUARANTINE_NS),
        Some(ta.port),
        "token must be claimable once the delay elapses"
    );
}
