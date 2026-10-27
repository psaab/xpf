//! #17033: the idempotent-reuse holder-recording return is single-sourced
//! behind `PortAllocator::reenter_existing_locked`, and a synced PAT
//! refresh now bumps `reuses_total` like its synced address-only twin.

use super::allocator::{NatHolder, PortAllocator, TranslatedTuple};
use super::source::SourceNatFlowKey;
use std::net::{IpAddr, Ipv4Addr};

const POOL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

fn v4_flow(src_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

/// #17033: a synced PAT reservation that AGREES with the incumbent is the
/// periodic-refresh / worker 2..N fan-out path. It must record the holder
/// AND bump `reuses_total` — exactly as the synced address-only twin
/// (`reserve_address_only_maybe_persistent`) already does. Before this fix
/// `reserve_flow_maybe_persistent_inner` was the only one of the 13
/// idempotent-reuse copies that skipped the counter, so the metric (and
/// the test discriminator built on it: "bumped only on the idempotent
/// path") silently excluded synced PAT refreshes.
///
/// Fail-on-revert: drop the `ReuseCount::Counted` bump on this path (or
/// revert to the hand-copied return without it) and `reuses_total` stays
/// 0 below while the holder assertion still passes.
#[test]
fn synced_pat_refresh_bumps_reuses_total_17033() {
    let alloc = PortAllocator::new(1, 1024, 65535);
    let flow = v4_flow(41001);
    let tuple = TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: 20001,
    };
    assert!(
        alloc.reserve_flow(flow, tuple, 0, false, 1_000, NatHolder::Worker(0)),
        "precondition: the first synced reserve must install the record"
    );
    assert_eq!(
        alloc.snapshot().reuses_total,
        0,
        "precondition: a fresh install is not a reuse"
    );

    // The refresh: same flow, same tuple, a second worker.
    let mut previous = None;
    assert!(
        alloc.reserve_flow_maybe_persistent(
            flow,
            tuple,
            0,
            false,
            2_000,
            NatHolder::Worker(1),
            None,
            false,
            &mut previous,
        ),
        "an agreeing synced PAT refresh must be admitted as a reuse"
    );
    assert_eq!(
        alloc.snapshot().reuses_total,
        1,
        "a synced PAT refresh must bump reuses_total like the synced \
         address-only twin (#17033); zero means this path still skips \
         the counter and the exported metric silently excludes it"
    );
    assert_eq!(
        alloc.holder_mask_for_flow(&flow),
        Some(0b11),
        "the refresh must also record worker 1 as a holder (#9145/#6211 F2)"
    );

    // A same-worker refresh is still an idempotent reuse (OR cannot
    // inflate the mask, but the counter counts re-entries).
    let mut previous = None;
    assert!(alloc.reserve_flow_maybe_persistent(
        flow,
        tuple,
        0,
        false,
        3_000,
        NatHolder::Worker(1),
        None,
        false,
        &mut previous,
    ));
    assert_eq!(
        alloc.snapshot().reuses_total,
        2,
        "every idempotent re-entry bumps reuses_total, including a \
         same-worker refresh"
    );
    assert_eq!(
        alloc.holder_mask_for_flow(&flow),
        Some(0b11),
        "a same-worker refresh must not inflate the holder mask"
    );
}
