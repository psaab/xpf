//! #8447: the persistent-NAT admission counter pair.
//!
//! The cluster measurement that found #8447 could see only that no session
//! installed. It could not say whether the allocator REFUSED the flow or
//! installed it and immediately reclaimed it, and those have different fixes.
//! These counters make that difference readable — and readable from a Rust
//! test, so every future question about this path does not need the shared
//! cluster's lock.
//!
//! BOTH ARMS ARE COUNTED, and that is the point rather than symmetry for its
//! own sake. A lone "declined" counter reading zero is equally consistent with
//! "nothing was declined" and with "this path never ran", which are the two
//! answers the question is between. Only a non-zero `admitted` alongside it
//! rules the second out.

use super::allocator::{NatHolder, PoolAddressFamily, PortAllocator};
use super::source::{PersistentNatPermit, SourceNatFlowKey, allocate_nat64_pool_port};
use std::net::{IpAddr, Ipv4Addr};

const TCP: u8 = 6;
const TIMEOUT_NS: u64 = 300 * 1_000_000_000;

fn flow(src: &str, sport: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: TCP,
        src_ip: src.parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: sport,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn persistent_alloc(
    alloc: &PortAllocator,
    addrs: &[Ipv4Addr],
    f: SourceNatFlowKey,
) -> Result<(), ()> {
    alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(addrs),
            0,
            false,
            true, // persistent_nat
            PersistentNatPermit::TargetHostPort,
            0,
            TIMEOUT_NS,
            1_000,
            NatHolder::Untracked,
            0,
        )
        .map(|_| ())
        .map_err(|_| ())
}

/// Both arms, in one run, on a one-port pool: the first persistent flow is
/// admitted and the second is declined. Asserting them together is what makes
/// each number mean something — a decline count on its own cannot be told from
/// a path that never executed.
#[test]
fn persistent_admission_counts_both_arms_8447() {
    let addrs = ["203.0.113.1".parse::<Ipv4Addr>().unwrap()];
    let alloc = PortAllocator::new(1, 1024, 1024); // exactly one port

    assert!(persistent_alloc(&alloc, &addrs, flow("10.0.0.1", 5000)).is_ok());
    let snap = alloc.snapshot();
    assert_eq!(
        snap.persistent_admitted_total, 1,
        "the first flow is admitted"
    );
    assert_eq!(
        snap.persistent_declined_total, 0,
        "and nothing has been declined yet — this zero is only meaningful \
         because the admitted count above is non-zero"
    );

    // The single port is taken, so a DIFFERENT source (a distinct lease key)
    // cannot be satisfied.
    assert!(persistent_alloc(&alloc, &addrs, flow("10.0.0.2", 5000)).is_err());
    let snap = alloc.snapshot();
    assert_eq!(snap.persistent_admitted_total, 1, "still one admission");
    assert_eq!(snap.persistent_declined_total, 1, "and now one decline");
}

/// The pair is specific to the persistent path: a NON-persistent allocation
/// must move neither counter. Without this, "admitted" would climb on ordinary
/// pool traffic and a reader could not attribute it to persistent NAT at all.
#[test]
fn a_non_persistent_allocation_moves_neither_counter_8447() {
    let addrs = ["203.0.113.1".parse::<Ipv4Addr>().unwrap()];
    let alloc = PortAllocator::new(1, 1024, 2048);
    alloc
        .allocate_translation(
            flow("10.0.0.1", 5000),
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false, // NOT persistent
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            1_000,
            NatHolder::Untracked,
            0,
        )
        .expect("control: an ordinary pool allocation must succeed");
    let snap = alloc.snapshot();
    assert_eq!(
        snap.allocations_total, 1,
        "control: the allocation really happened, so the zeroes below are not \
         'nothing ran'"
    );
    assert_eq!(snap.persistent_admitted_total, 0);
    assert_eq!(snap.persistent_declined_total, 0);
}

/// The refusal shape that is EASIEST to miss: an empty pool is rejected before
/// the allocator reaches its locked path at all. The counter lives on a wrapper
/// precisely so this is still counted — instrumenting inside the body would
/// report "declined = 0" for a pool that refused every single flow, which is
/// the exact reading this issue exists to prevent.
#[test]
fn an_early_config_shape_refusal_is_still_counted_declined_8447() {
    let empty: [Ipv4Addr; 0] = [];
    let alloc = PortAllocator::new(1, 1024, 2048);
    assert!(persistent_alloc(&alloc, &empty, flow("10.0.0.1", 5000)).is_err());
    let snap = alloc.snapshot();
    assert_eq!(
        snap.persistent_declined_total, 1,
        "a pre-locked-path refusal must still land in the decline counter"
    );
    assert_eq!(snap.persistent_admitted_total, 0);
}

/// #17046 acceptance: a NAT64 BIB mint via `allocate_nat64_pool_port`
/// bumps `persistent_admitted_total` by exactly 1. Before the fix this
/// mint routed through `allocate_translation_with_exclusions`, the one
/// wrapper with no #8447 epilogue, so the counter stayed at 0. A
/// declined NAT64 mint (empty pool) must count the other arm.
#[test]
fn nat64_bib_mint_counts_persistent_admitted_17046() {
    let pool = ["203.0.113.1".parse::<Ipv4Addr>().unwrap()];
    let alloc = PortAllocator::new(1, 1024, 2048);
    let bib_flow = SourceNatFlowKey {
        protocol: TCP,
        src_ip: "2001:db8::1".parse::<IpAddr>().unwrap(),
        dst_ip: "2001:db8::2".parse::<IpAddr>().unwrap(),
        src_port: 5000,
        dst_port: 443,
        routing_scope: 0,
    };
    let (ip, _port) =
        allocate_nat64_pool_port(&alloc, bib_flow, &pool, 1_000, NatHolder::Untracked)
            .expect("NAT64 BIB mint must succeed on a fresh pool");
    assert_eq!(ip, pool[0]);
    let snap = alloc.snapshot();
    assert_eq!(
        snap.persistent_admitted_total, 1,
        "a NAT64 BIB mint is a persistent admission and must count it"
    );
    assert_eq!(snap.persistent_declined_total, 0);
    let empty: [Ipv4Addr; 0] = [];
    let alloc2 = PortAllocator::new(1, 1024, 2048);
    assert!(
        allocate_nat64_pool_port(&alloc2, bib_flow, &empty, 1_000, NatHolder::Untracked).is_err()
    );
    let snap2 = alloc2.snapshot();
    assert_eq!(snap2.persistent_admitted_total, 0);
    assert_eq!(
        snap2.persistent_declined_total, 1,
        "a refused NAT64 BIB mint must count as declined, not vanish"
    );
}

/// #17046 structural pin: the #8447 epilogue is single-sourced. The
/// allocator source must contain exactly one admission-counter
/// selection/bump site; a second copy-pasted epilogue (the pre-fix
/// shape) fails this cell even if every behavioural cell still passes.
#[test]
fn persistent_admission_epilogue_is_single_sourced_17046() {
    let src = include_str!("allocator/mod.rs");
    let selections = src.matches("&self.shared.persistent_admitted_total").count();
    assert_eq!(
        selections, 1,
        "exactly one counter-selection site may exist in allocator/mod.rs, got {selections}"
    );
    let epilogue = src
        .split("if req.persistent.is_some()")
        .nth(1)
        .expect("the single allocate() epilogue must exist");
    let epilogue = &epilogue[..epilogue.len().min(400)];
    assert_eq!(
        epilogue.matches("counter.fetch_add(1, Ordering::Relaxed)").count(),
        1,
        "the allocate() epilogue must bump exactly one selected counter"
    );
    assert_eq!(
        src.matches("persistent_admitted_total").count(),
        7,
        "admitted counter may be named only at field/ctors/snapshot/epilogue sites"
    );
    assert!(
        !src.contains("fn allocate_translation_with_zones"),
        "the counted zones wrapper must not return as a second epilogue copy"
    );
    assert!(
        !src.contains("fn allocate_translation_with_exclusions_and_zones"),
        "the counted exclusions+zones wrapper must not return as a second epilogue copy"
    );
}
