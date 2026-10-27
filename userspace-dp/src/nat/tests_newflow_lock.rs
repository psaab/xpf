// #4800/#17036: tests for the SNAT pool allocator's counted lock
// contention accounting — the NAT-allocator leg of the new-flow-install
// ceiling instrumentation. Since #15956 the allocator has two counted
// lock domains: the 16 flow-shard mutexes (`flow_shard_lock_*`) and the
// retained `live` RwLock write guard (`live_write_lock_*`); the legacy
// `live_lock_*` totals are their documented sum, kept for one release.
//
// The measurement these back exists to settle a specific question: at a
// sustained new-flow rate, is either allocator lock domain a material
// contributor, or do `publish_shared_session` and the N-way
// `replicate_session_upsert` fan-out saturate first? That question has an
// answer only if each domain reports BOTH how often it was taken and
// how often it had to block, so every test here treats each pair as a pair.
//
// `PortAllocator` instances are per-test, so these assertions are exact:
// unlike the process-global publish/replication counters, no concurrently
// running test can touch this allocator's atomics.

use super::allocator::PoolAddressFamily;
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn pool_flow(src_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.61.50".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn allocate(alloc: &PortAllocator, addrs: &[Ipv4Addr], src_port: u16, now_ns: u64) {
    alloc
        .allocate_translation(
            pool_flow(src_port),
            PoolAddressFamily::V4(addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            now_ns,
            crate::nat::NatHolder::Untracked,
            0,
        )
        .expect("free range must allocate");
}

/// The acquisition counter is the DENOMINATOR half of the pair. Without it a
/// contention count is uninterpretable: 500 blocked acquisitions out of 600
/// is a saturated mutex, out of 60,000,000 it is noise. This binds that the
/// allocate path reports its acquisitions at all, and that the count scales
/// with the number of allocations rather than being stamped once.
///
/// RED on revert: restoring `self.shared.live.lock()` at the
/// `allocate_translation` sites leaves both counters at 0, so the
/// strictly-increasing assertion fails on its message.
#[test]
fn allocate_counts_live_lock_acquisitions() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 1024, 2048);

    let base = alloc.snapshot();
    assert_eq!(
        base.live_lock_acquisitions_total, 0,
        "a fresh allocator must start with no counted acquisitions"
    );

    allocate(&alloc, &addrs, 40000, 1_000);
    let after_one = alloc.snapshot();
    assert!(
        after_one.live_lock_acquisitions_total > 0,
        "allocate_translation must count its live-mutex acquisition; got {}",
        after_one.live_lock_acquisitions_total
    );

    allocate(&alloc, &addrs, 40001, 2_000);
    let after_two = alloc.snapshot();
    assert!(
        after_two.live_lock_acquisitions_total > after_one.live_lock_acquisitions_total,
        "a second allocation must count further acquisitions: {} -> {}",
        after_one.live_lock_acquisitions_total,
        after_two.live_lock_acquisitions_total
    );

    // Uncontended throughout: one thread, so nothing can ever block. A
    // nonzero value here would mean the counter counts acquisitions rather
    // than BLOCKED acquisitions, which would read as permanent saturation
    // on the cluster and send the #2852 Phase-2 decision the wrong way.
    assert_eq!(
        after_two.live_lock_contended_total, 0,
        "single-threaded allocation cannot contend"
    );
}

/// #17036 acceptance: a non-persistent fast-path allocation with an
/// empty expiry index bumps ONLY the split counters attributable to
/// that allocation's counted locks (one flow-shard + one live-write),
/// and the legacy totals remain their sum. RED on revert to the
/// single summed pair: the split fields stay 0 (or the shard field
/// absorbs the live-write count) and these equalities fail.
#[test]
fn fast_path_allocation_counts_split_lock_domains_17036() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 1024, 2048);
    let base = alloc.snapshot();
    assert_eq!(base.flow_shard_lock_acquisitions_total, 0);
    assert_eq!(base.live_write_lock_acquisitions_total, 0);
    allocate(&alloc, &addrs, 40000, 1_000);
    let after = alloc.snapshot();
    assert_eq!(
        after.flow_shard_lock_acquisitions_total - base.flow_shard_lock_acquisitions_total,
        1,
        "one fast-path allocation must count exactly one flow-shard acquisition"
    );
    assert_eq!(
        after.live_write_lock_acquisitions_total - base.live_write_lock_acquisitions_total,
        1,
        "one fast-path allocation with an empty expiry index must count exactly one live-write (try_write) acquisition and no GC live-write"
    );
    assert_eq!(
        after.live_lock_acquisitions_total,
        after.flow_shard_lock_acquisitions_total + after.live_write_lock_acquisitions_total,
        "legacy acquisitions must remain the documented sum of the split domains"
    );
    assert_eq!(
        after.live_lock_contended_total,
        after.flow_shard_lock_contended_total + after.live_write_lock_contended_total,
        "legacy contended must remain the documented sum of the split domains"
    );
    assert_eq!(after.flow_shard_lock_contended_total, 0);
    assert_eq!(after.live_write_lock_contended_total, 0);
}

/// #17036 acceptance: a persistent mint goes through the serialized
/// locked path, so it bumps the live-write counter (the lease mint is
/// a live-write critical section) and its legacy sum tracks it. RED
/// on revert to the single pair: the live-write field stays 0.
#[test]
fn persistent_mint_counts_live_write_lock_17036() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 1024, 2048);
    let base = alloc.snapshot();
    alloc
        .allocate_translation(
            pool_flow(40000),
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::TargetHostPort,
            0,
            60_000_000_000,
            1_000,
            crate::nat::NatHolder::Untracked,
            0,
        )
        .expect("persistent allocation must succeed");
    let after = alloc.snapshot();
    assert!(
        after.live_write_lock_acquisitions_total > base.live_write_lock_acquisitions_total,
        "a persistent mint must bump the live-write counter: {} -> {}",
        base.live_write_lock_acquisitions_total,
        after.live_write_lock_acquisitions_total
    );
    assert_eq!(
        after.live_lock_acquisitions_total,
        after.flow_shard_lock_acquisitions_total + after.live_write_lock_acquisitions_total,
        "legacy acquisitions must remain the documented sum after a persistent mint"
    );
}

/// The contention counter must actually fire when another thread holds the
/// map mutex. This is the signal the whole measurement rests on, so it is
/// forced deterministically rather than raced for: the test thread parks on
/// the `live` guard, the allocating thread's `try_lock` is therefore
/// guaranteed to fail, and only then is the guard released.
///
/// RED on revert: restoring the plain `lock()` removes the try-lock probe
/// entirely, the counter never moves, and the `>= 1` assertion fails on its
/// message. (The allocation itself still succeeds under the revert — the
/// counting is the only thing that changes — so this cannot go red for a
/// compile or behavioural reason.)
#[test]
fn allocate_counts_a_blocked_live_lock_acquisition() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let alloc = Arc::new(PortAllocator::new(1, 1024, 2048));
    assert_eq!(alloc.snapshot().live_lock_contended_total, 0);

    // Signals that the worker thread is inside allocate_translation and has
    // therefore already run (and failed) its try_lock.
    let blocked = Arc::new(AtomicBool::new(false));

    let guard = alloc.debug_live();
    let worker = {
        let alloc = Arc::clone(&alloc);
        let blocked = Arc::clone(&blocked);
        std::thread::spawn(move || {
            let addrs = [pool_ip];
            blocked.store(true, Ordering::SeqCst);
            allocate(&alloc, &addrs, 40000, 1_000);
        })
    };

    // Wait until the worker has entered the allocation call, then give it
    // time to reach the lock. It cannot proceed past the mutex while this
    // thread holds `guard`, so releasing after the flag is set means the
    // try_lock failure has either already happened or is imminent — and the
    // join below waits for the allocation either way.
    while !blocked.load(Ordering::SeqCst) {
        std::hint::spin_loop();
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
    drop(guard);
    worker.join().expect("allocating thread must not panic");

    let snap = alloc.snapshot();
    assert!(
        snap.live_lock_contended_total >= 1,
        "an allocation that blocked on a held live mutex must be counted as \
         contended; got {} contended / {} acquisitions",
        snap.live_lock_contended_total,
        snap.live_lock_acquisitions_total
    );
    assert!(
        snap.live_lock_acquisitions_total >= snap.live_lock_contended_total,
        "contended ({}) can never exceed acquisitions ({}) — the ratio the \
         harness computes would be > 1",
        snap.live_lock_contended_total,
        snap.live_lock_acquisitions_total
    );
}

/// OVER-REACH GUARD. `snapshot()` takes the same `live` mutex, and it is
/// called by the ~1s status poll that READS these counters. If it counted
/// itself, a completely idle firewall would report a steadily climbing
/// acquisition rate and every contention RATIO on the cluster would be
/// diluted by the observer — the measurement would be wrong in the
/// reassuring direction.
///
/// Stays GREEN under the revert (which makes both counters permanently 0, so
/// "unchanged across snapshots" still holds). That is what distinguishes it
/// from a restatement of the fix: it constrains what the change must NOT do.
#[test]
fn snapshot_does_not_count_its_own_live_lock_acquisition() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 1024, 2048);
    allocate(&alloc, &addrs, 40000, 1_000);

    let first = alloc.snapshot();
    // Several more polls with no traffic in between.
    let _ = alloc.snapshot();
    let _ = alloc.snapshot();
    let last = alloc.snapshot();

    assert_eq!(
        last.live_lock_acquisitions_total, first.live_lock_acquisitions_total,
        "status polling must not inflate the acquisition denominator"
    );
    assert_eq!(
        last.live_lock_contended_total, first.live_lock_contended_total,
        "status polling must not inflate the contention numerator"
    );
}

/// OVER-REACH GUARD. Counting must be observation only: the translation the
/// allocator hands out, and the allocation/reuse/exhaustion counters the
/// existing NAT status surface already reports, must be exactly what they
/// were before the instrumentation.
///
/// Stays GREEN under the revert.
#[test]
fn live_lock_counting_does_not_disturb_allocation_results() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 1024, 1027);

    let translated = alloc
        .allocate_translation(
            pool_flow(40000),
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            1_000,
            crate::nat::NatHolder::Untracked,
            0,
        )
        .expect("free range must allocate");
    assert_eq!(translated.ip, IpAddr::V4(pool_ip));
    assert!(
        (1024..=1027).contains(&translated.port),
        "translated port {} outside the configured range",
        translated.port
    );

    let snap = alloc.snapshot();
    assert_eq!(snap.allocations_total, 1, "one fresh allocation");
    assert_eq!(snap.reuses_total, 0, "no reuse on a first-touch flow");
    assert_eq!(snap.exhaustion_total, 0, "range had free ports");
    assert_eq!(snap.live_flows, 1, "the flow is tracked");
    assert_eq!(snap.used_ports, 1, "exactly one occupancy bit set");
}

/// #15956: distinct flows must not serialize on one flow's shard.
/// The test thread holds flow A's shard write guard; allocating a
/// flow on a DIFFERENT shard must complete while it is held, and
/// allocating flow A itself must block until release. RED on
/// revert to the single `live` mutex: the different-flow
/// allocation would block on the same mutex the guard holds.
#[test]
fn distinct_flow_allocation_does_not_block_on_held_shard_15956() {
    use super::allocator::{LIVE_SHARDS_FOR_TEST, live_shard_index_for_test};
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = Arc::new(PortAllocator::new(1, 1024, 65535));
    // Find two flows on different shards and one on the held shard.
    let held_flow = pool_flow(40000);
    let held_shard = live_shard_index_for_test(&held_flow);
    let mut other_flow = None;
    for p in 40001..41000u16 {
        let f = pool_flow(p);
        if live_shard_index_for_test(&f) != held_shard {
            other_flow = Some(f);
            break;
        }
    }
    let other_flow = other_flow.expect("a different-shard flow exists");
    let _ = LIVE_SHARDS_FOR_TEST;
    // Allocate the held flow first so its record exists.
    allocate(&alloc, &addrs, 40000, 1_000);
    let guard = alloc.debug_hold_flow_shard(&held_flow);
    // Different-shard allocation completes under the held guard.
    let done = Arc::new(AtomicBool::new(false));
    let worker = {
        let alloc = Arc::clone(&alloc);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let addrs2 = [pool_ip];
            alloc
                .allocate_translation(
                    other_flow,
                    PoolAddressFamily::V4(&addrs2),
                    0,
                    false,
                    false,
                    PersistentNatPermit::TargetHostPort,
                    0,
                    0,
                    2_000,
                    crate::nat::NatHolder::Untracked,
                    0,
                )
                .expect("different-shard allocation must succeed under held shard");
            done.store(true, Ordering::SeqCst);
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        done.load(Ordering::SeqCst),
        "different-shard allocation blocked on a held shard — flow map is still globally serialized (#15956)"
    );
    drop(guard);
    worker.join().expect("worker must not panic");
    assert_eq!(
        alloc.live_flow_count(),
        2,
        "both flows tracked across shards"
    );
}

/// #15956: the exact cap spans shards — filling to max_tracked_flows
/// across many shards then allocating one more must exhaust, and
/// releasing one (any shard) must admit exactly one more.
#[test]
fn cross_shard_cap_is_exact_15956() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    // 4 ports -> max_tracked_flows is bounded by capacity; allocate all.
    let alloc = PortAllocator::new(1, 1024, 1027);
    for p in 40000..40004u16 {
        allocate(&alloc, &addrs, p, 1_000);
    }
    assert_eq!(alloc.live_flow_count(), 4);
    let err = alloc.allocate_translation(
        pool_flow(40010),
        PoolAddressFamily::V4(&addrs),
        0,
        false,
        false,
        PersistentNatPermit::TargetHostPort,
        0,
        0,
        2_000,
        crate::nat::NatHolder::Untracked,
        0,
    );
    assert!(
        err.is_err(),
        "fifth flow over the cross-shard cap must exhaust"
    );
    // Release one and exactly one more fits.
    let t = alloc
        .allocate_translation(
            pool_flow(40000),
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            3_000,
            crate::nat::NatHolder::Untracked,
            0,
        )
        .expect("idempotent re-allocate returns existing");
    assert!(alloc.release_flow(pool_flow(40000), t, 4_000, crate::nat::NatHolder::Untracked));
    allocate(&alloc, &addrs, 40010, 100_000_000_000);
    assert_eq!(alloc.live_flow_count(), 4);
}

/// #15956 fold: retire_worker must COMPLETE the persistent lease
/// of a last-holder flow it unlinks, exactly as release_flow does.
/// Before the fold it only unlinked the record: the lease kept
/// `active_flows == 1`, never entered the idle-expiry index, and
/// no GC path could reclaim it (or its port).
#[test]
fn retire_worker_completes_persistent_lease_15956() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 1024, 65535);
    let flow = pool_flow(41000);
    let translated = alloc
        .allocate_translation(
            flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::TargetHostPort,
            0,
            60_000_000_000,
            1_000,
            crate::nat::NatHolder::Worker(0),
            0,
        )
        .expect("persistent allocation must succeed");
    let before = alloc
        .debug_persistent_lease_for_flow(&flow, PersistentNatPermit::TargetHostPort)
        .expect("lease must exist while the flow is live");
    assert_eq!(
        before.active_flows, 1,
        "fixture: lease must start with one active flow"
    );
    assert_eq!(
        alloc.retire_worker(0, 2_000),
        1,
        "retiring the sole holder must free exactly the one record"
    );
    assert_eq!(
        alloc.live_flow_count(),
        0,
        "the retired flow's record must be gone"
    );
    let after = alloc
        .debug_persistent_lease_for_flow(&flow, PersistentNatPermit::TargetHostPort)
        .expect("the idle lease record itself survives completion");
    assert_eq!(
        after.active_flows, 0,
        "retire must complete the lease (active_flows 1 -> 0); without completion the lease is never idle and no GC path can reclaim it"
    );
    assert_eq!(after.completed_flows, before.completed_flows + 1);
    assert!(
        alloc.debug_is_port_occupied(0, translated.port),
        "the completed idle lease keeps its port bit until expiry — completion reclaims via the expiry index, not by freeing the bit here"
    );
}

/// #15956 fold: a non-persistent admission uses the sharded flow map, but it
/// must fall back to the locked path if the PAT reverse-owner index cannot be
/// published while a reader holds `live`. That fallback is allowed to wait;
/// the important part is that the eventual PAT admission is visible to an
/// address-only mint.
#[test]
fn new_flow_allocation_falls_back_and_publishes_pat_owner_under_held_live_read_15956() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = Arc::new(PortAllocator::new(1, 20_000, 20_001));
    let guard = alloc.debug_hold_live_read();
    let done = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicBool::new(false));
    let contended_before = alloc.debug_live_lock_contended_total();
    let worker = {
        let alloc = Arc::clone(&alloc);
        let done = Arc::clone(&done);
        let started = Arc::clone(&started);
        std::thread::spawn(move || {
            let addrs2 = [pool_ip];
            started.store(true, Ordering::SeqCst);
            alloc
                .allocate_translation(
                    pool_flow(42_000),
                    PoolAddressFamily::V4(&addrs2),
                    0,
                    false,
                    false,
                    PersistentNatPermit::TargetHostPort,
                    0,
                    0,
                    2_000,
                    crate::nat::NatHolder::Untracked,
                    0,
                )
                .expect("new-flow allocation must succeed");
            done.store(true, Ordering::SeqCst);
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !started.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        started.load(Ordering::SeqCst),
        "worker must start allocation"
    );
    while !done.load(Ordering::SeqCst)
        && alloc.debug_live_lock_contended_total() == contended_before
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let observed_contention = alloc.debug_live_lock_contended_total() > contended_before;
    let completed_under_read = done.load(Ordering::SeqCst);
    drop(guard);
    worker.join().expect("worker must not panic");
    assert!(
        observed_contention || completed_under_read,
        "worker must attempt the contended live write or finish before the deadline"
    );
    assert_eq!(alloc.live_flow_count(), 1);

    let pat = alloc
        .debug_live_flow_translated(&pool_flow(42_000))
        .expect("PAT flow must remain live");
    assert!(
        alloc.debug_pat_owns_wire_identity(&pool_flow(42_000), pat),
        "PAT owner must be present after the contended fallback completes"
    );

    assert!(
        alloc
            .reserve_address_only(
                pool_flow(pat.port),
                IpAddr::V4(pool_ip),
                0,
                crate::nat::NatHolder::Untracked,
            )
            .is_err(),
        "address-only admission must see the PAT reverse owner published under contention"
    );
}

/// #17024 gate: with ONE free port, a contended fast-path claim must not be
/// quarantined on release — the fallback must be able to reclaim it.
#[test]
fn single_free_port_survives_contended_fast_path_claim_17024() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let alloc = Arc::new(PortAllocator::new(1, 20_000, 20_000));
    let guard = alloc.debug_hold_live_read();
    let started = Arc::new(AtomicBool::new(false));
    let contended_before = alloc.debug_live_lock_contended_total();
    let worker = {
        let alloc = Arc::clone(&alloc);
        let started = Arc::clone(&started);
        std::thread::spawn(move || {
            let addrs = [pool_ip];
            started.store(true, Ordering::SeqCst);
            alloc
                .allocate_translation(
                    pool_flow(42_000),
                    PoolAddressFamily::V4(&addrs),
                    0,
                    false,
                    false,
                    PersistentNatPermit::TargetHostPort,
                    0,
                    0,
                    2_000,
                    crate::nat::NatHolder::Untracked,
                    0,
                )
                .expect("fallback must reclaim the only port after contention")
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !started.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        started.load(Ordering::SeqCst),
        "worker must start allocation"
    );
    while alloc.debug_live_lock_contended_total() == contended_before
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        alloc.debug_live_lock_contended_total() > contended_before,
        "worker must hit the contended fast-path try_write"
    );
    drop(guard);
    let pat = worker.join().expect("worker must not panic");
    assert_eq!(pat.port, 20_000);
    assert!(
        alloc.debug_pat_owns_wire_identity(&pool_flow(42_000), pat),
        "PAT owner must be published by the fallback"
    );
    assert!(alloc.debug_is_port_occupied(0, 20_000));
    assert_eq!(alloc.live_flow_count(), 1);
}

/// #17024 gate: remaining capacity must survive contention — a 2-port pool
/// with one port already occupied must still admit via the fallback.
#[test]
fn remaining_capacity_survives_contended_fast_path_claim_17024() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = Arc::new(PortAllocator::new(1, 20_000, 20_001));
    let first = alloc
        .allocate_translation(
            pool_flow(41_000),
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            false,
            PersistentNatPermit::TargetHostPort,
            0,
            0,
            1_000,
            crate::nat::NatHolder::Untracked,
            0,
        )
        .expect("first allocation must succeed");
    assert!(alloc.debug_is_port_occupied(0, first.port));

    let guard = alloc.debug_hold_live_read();
    let started = Arc::new(AtomicBool::new(false));
    let contended_before = alloc.debug_live_lock_contended_total();
    let worker = {
        let alloc = Arc::clone(&alloc);
        let started = Arc::clone(&started);
        std::thread::spawn(move || {
            let addrs2 = [pool_ip];
            started.store(true, Ordering::SeqCst);
            alloc
                .allocate_translation(
                    pool_flow(42_000),
                    PoolAddressFamily::V4(&addrs2),
                    0,
                    false,
                    false,
                    PersistentNatPermit::TargetHostPort,
                    0,
                    0,
                    2_000,
                    crate::nat::NatHolder::Untracked,
                    0,
                )
                .expect("fallback must reclaim the last free port")
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !started.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        started.load(Ordering::SeqCst),
        "worker must start allocation"
    );
    while alloc.debug_live_lock_contended_total() == contended_before
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        alloc.debug_live_lock_contended_total() > contended_before,
        "worker must hit the contended fast-path try_write"
    );
    drop(guard);
    let second = worker.join().expect("worker must not panic");
    assert_ne!(second.port, first.port);
    assert!(alloc.debug_is_port_occupied(0, second.port));
    assert!(
        alloc.debug_pat_owns_wire_identity(&pool_flow(42_000), second),
        "PAT owner must be published by the fallback"
    );
    assert_eq!(alloc.live_flow_count(), 2);
}

/// #15956 fold 2: exact-cap race across shards. At cap-1, a
/// fast-path insert (thread A) and a displaced restore (thread B)
/// — different flows, different shards — must NOT both admit:
/// exactly one wins the shared atomic admission counter, the
/// tracked count never exceeds the cap, and after the winner
/// releases, the loser path admits exactly one more. With the
/// pre-fold `len()`-check-then-insert, both racers pass at cap-1
/// and the count overshoots to cap+1.
#[test]
fn restore_and_fast_insert_race_at_cap_minus_one_admits_exactly_one_15956() {
    use std::sync::{Arc, Barrier};
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    // 10 ports -> cap 10. Fill 9 with address-only records (no
    // bitmap bits, so both racers' port/bit prechecks pass).
    let alloc = Arc::new(PortAllocator::new(1, 1024, 1033));
    for i in 0..9u16 {
        let f = pool_flow(41000 + i);
        alloc
            .reserve_address_only(f, IpAddr::V4(pool_ip), 0, crate::nat::NatHolder::Untracked)
            .expect("address-only fill must succeed");
    }
    assert_eq!(alloc.live_flow_count(), 9, "fixture: cap-1");
    assert_eq!(
        alloc.debug_admission_count(),
        9,
        "admission counter tracks the fill"
    );

    // Displaced incumbent for the restore racer: reserve T1,
    // capture-replace with T2, roll T2 back (sole holder), so
    // restore_displaced must re-insert T1 into an ABSENT slot.
    let flow = pool_flow(42000);
    let t1 = crate::nat::allocator::TranslatedTuple {
        ip: IpAddr::V4(pool_ip),
        port: 1024,
    };
    let t2 = crate::nat::allocator::TranslatedTuple {
        ip: IpAddr::V4(pool_ip),
        port: 1025,
    };
    assert!(alloc.reserve_flow(flow, t1, 0, false, 1_000, crate::nat::NatHolder::Untracked));
    let mut snapshot = None;
    assert!(alloc.reserve_flow_maybe_persistent(
        flow,
        t2,
        0,
        false,
        2_000,
        crate::nat::NatHolder::Untracked,
        None,
        true,
        &mut snapshot,
    ));
    let snapshot = Arc::new(snapshot.expect("capture must produce a snapshot"));
    assert!(alloc.rollback_flow(flow, t2, 3_000, crate::nat::NatHolder::Untracked));
    // The reserve+rollback above netted zero; still cap-1. The
    // T2 reserve consumed a slot and its rollback released it.
    assert_eq!(
        alloc.live_flow_count(),
        9,
        "fixture: back to cap-1 before the race"
    );
    assert_eq!(alloc.debug_admission_count(), 9);

    // Racer A: fast-path allocate a NEW flow (distinct shard
    // from the restore flow — assert the premise).
    let fast_flow = pool_flow(43000);
    {
        use super::allocator::live_shard_index_for_test;
        assert_ne!(
            live_shard_index_for_test(&fast_flow),
            live_shard_index_for_test(&flow),
            "fixture: racers must be on different shards or the race is not cross-shard"
        );
    }
    let barrier = Arc::new(Barrier::new(2));
    let racer_a = {
        let alloc = Arc::clone(&alloc);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            alloc
                .allocate_translation(
                    fast_flow,
                    PoolAddressFamily::V4(&addrs),
                    0,
                    false,
                    false,
                    PersistentNatPermit::TargetHostPort,
                    0,
                    0,
                    4_000,
                    crate::nat::NatHolder::Untracked,
                    0,
                )
                .is_ok()
        })
    };
    let racer_b = {
        let alloc = Arc::clone(&alloc);
        let barrier = Arc::clone(&barrier);
        let snapshot = Arc::clone(&snapshot);
        std::thread::spawn(move || {
            barrier.wait();
            snapshot.restore_displaced(t2, 4_000)
        })
    };
    let a_ok = racer_a.join().expect("fast racer must not panic");
    let b_ok = racer_b.join().expect("restore racer must not panic");
    assert!(
        a_ok ^ b_ok,
        "exactly one racer may admit at cap-1 (fast={a_ok}, restore={b_ok}); both passing overshoots the cap"
    );
    assert_eq!(
        alloc.live_flow_count(),
        10,
        "tracked count must land exactly ON the cap, never above"
    );
    assert_eq!(
        alloc.debug_admission_count(),
        10,
        "admission counter must equal the tracked count after the race"
    );
    // The loser can be told apart and retried after a release:
    // release whichever won, then the other path admits.
    if a_ok {
        let t = alloc
            .allocate_translation(
                fast_flow,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                false,
                PersistentNatPermit::TargetHostPort,
                0,
                0,
                5_000,
                crate::nat::NatHolder::Untracked,
                0,
            )
            .expect("winner re-allocate returns existing");
        assert!(alloc.release_flow(fast_flow, t, 6_000, crate::nat::NatHolder::Untracked));
        assert!(
            snapshot.restore_displaced(t2, 7_000),
            "restore admits after the winner releases"
        );
    } else {
        assert_eq!(alloc.debug_live_flow_translated(&flow), Some(t1));
        assert!(alloc.release_flow(flow, t1, 6_000, crate::nat::NatHolder::Untracked));
        allocate(&alloc, &addrs, 43000, 7_000);
    }
    assert_eq!(alloc.live_flow_count(), 10);
    assert_eq!(
        alloc.debug_admission_count(),
        10,
        "admission counter must not leak across release/re-admit"
    );
}

/// #15956 fold 3: a synced persistent reserve that loses the
/// tracked-flow admission race must NOT leave a minted lease
/// behind. The fold-2 loser minted the lease (`active_flows=1`,
/// in no expiry index) and then discovered the loss at insert —
/// that lease could never drain or be GC-reclaimed. Fold 3
/// admits BEFORE the mint, so the loser never mints: after the
/// refusal there is no lease for the source at all (not an
/// active one, not an idle one), the bitmap bit is unreserved,
/// and a retry after a slot frees mints cleanly.
#[test]
fn synced_persistent_reserve_admit_loser_mints_no_lease_15956() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    // Cap 10; fill all 10 tracked slots with address-only records.
    let alloc = PortAllocator::new(1, 1024, 1033);
    for i in 0..10u16 {
        let f = pool_flow(41000 + i);
        alloc
            .reserve_address_only(f, IpAddr::V4(pool_ip), 0, crate::nat::NatHolder::Untracked)
            .expect("address-only fill must succeed");
    }
    assert_eq!(alloc.live_flow_count(), 10);
    assert_eq!(alloc.debug_admission_count(), 10);

    // Synced persistent reserve for a new source at full cap:
    // must refuse (false) BEFORE minting.
    let flow = pool_flow(44000);
    let translated = crate::nat::allocator::TranslatedTuple {
        ip: IpAddr::V4(pool_ip),
        port: 1024,
    };
    let key = flow.persistent_source_key(PersistentNatPermit::TargetHostPort);
    let _ = key;
    let mut snapshot = None;
    let admitted = alloc.reserve_flow_maybe_persistent(
        flow,
        translated,
        0,
        false,
        5_000,
        crate::nat::NatHolder::Worker(0),
        Some((key, 60_000_000_000)),
        false,
        &mut snapshot,
    );
    assert!(
        !admitted,
        "synced persistent reserve at full cap must refuse"
    );
    assert_eq!(
        alloc.live_flow_count(),
        10,
        "loser must not add a tracked record"
    );
    assert_eq!(
        alloc.debug_admission_count(),
        10,
        "loser must not leak an admission slot"
    );
    assert!(
        alloc
            .debug_persistent_lease_for_flow(&flow, PersistentNatPermit::TargetHostPort)
            .is_none(),
        "admit loser must mint NO lease — a minted active_flows=1 lease is unindexed and unreclaimable (fold 3)"
    );
    assert!(
        !alloc.debug_is_port_occupied(0, translated.port),
        "loser must not leave the bitmap bit reserved"
    );

    // Free one slot; the same reserve now mints + admits cleanly.
    let f0 = pool_flow(41000);
    let t0 = crate::nat::allocator::TranslatedTuple {
        ip: IpAddr::V4(pool_ip),
        port: 41000,
    };
    assert!(alloc.release_flow(f0, t0, 6_000, crate::nat::NatHolder::Untracked));
    let mut snapshot2 = None;
    assert!(
        alloc.reserve_flow_maybe_persistent(
            flow,
            translated,
            0,
            false,
            7_000,
            crate::nat::NatHolder::Worker(0),
            Some((key, 60_000_000_000)),
            false,
            &mut snapshot2,
        ),
        "reserve must succeed once a slot frees"
    );
    let lease = alloc
        .debug_persistent_lease_for_flow(&flow, PersistentNatPermit::TargetHostPort)
        .expect("winner mints the lease");
    assert_eq!(
        lease.active_flows, 1,
        "winner's lease has exactly its one active flow"
    );
    assert_eq!(alloc.live_flow_count(), 10);
    assert_eq!(alloc.debug_admission_count(), 10);
    let _ = addrs;
}

/// #17041: seed one non-expired idle persistent lease. The persistent
/// flow is allocated then released; completion re-arms its expiry to
/// `release_ns + timeout`, so the lease sits in `lease_expirations`
/// with a future earliest expiry at every later allocation time used
/// below.
fn seed_idle_persistent_lease_17041(alloc: &PortAllocator, addrs: &[Ipv4Addr]) {
    let flow = pool_flow(41_000);
    let translated = alloc
        .allocate_translation(
            flow,
            PoolAddressFamily::V4(addrs),
            0,
            false,
            true,
            PersistentNatPermit::TargetHostPort,
            0,
            60_000_000_000,
            1_000,
            crate::nat::NatHolder::Untracked,
            0,
        )
        .expect("persistent seed allocation must succeed");
    assert!(
        alloc.release_flow(flow, translated, 2_000, crate::nat::NatHolder::Untracked),
        "persistent seed release must succeed"
    );
    let live = alloc.debug_live();
    assert_eq!(
        live.lease_expirations.len(),
        1,
        "fixture: exactly one idle lease must be indexed for expiry"
    );
    assert!(
        live.lease_expirations
            .first()
            .is_some_and(|(expires_at_ns, _)| *expires_at_ns > 2_000),
        "fixture: the seeded idle lease must not yet be expired"
    );
}

/// #17041: with one non-expired idle lease, 100 non-persistent
/// fast-path allocations must add 0 `debug_gc_lock_acquisitions`.
/// RED on revert: the emptiness-only pre-check fell through to the
/// blocking write lock on every allocation (100 acquisitions).
#[test]
fn idle_lease_gc_takes_no_write_lock_over_fast_path_allocs_17041() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = PortAllocator::new(1, 20_000, 21_000);
    seed_idle_persistent_lease_17041(&alloc, &addrs);
    let before = alloc.debug_gc_lock_acquisitions();
    for i in 0..100u16 {
        allocate(&alloc, &addrs, 30_000 + i, 3_000);
    }
    assert_eq!(
        alloc.debug_gc_lock_acquisitions() - before,
        0,
        "non-expired idle lease must not force a GC write-lock acquisition per fast-path allocation (#17041)"
    );
    assert_eq!(alloc.live_flow_count(), 100);
}

/// #17041: parameterised held-READ cell over {empty index, one
/// non-expired idle lease}. A non-persistent allocation must complete
/// while another thread holds the `live` READ guard. On the second
/// arm this is RED at the pre-fix head: GC's blocking `lock_live()`
/// waited behind the held reader before the allocation's own
/// try-write fallback could run. GREEN after: GC peeks the earliest
/// expiry under the read guard, sees nothing expired, and never
/// takes the write lock; the allocation then completes via its
/// existing contended fallback once the guard drops — or, if it
/// finishes earlier, that also satisfies completion. The assertion
/// mirrors the #15956/#17024 fallback cell: completion (before or
/// after drop) plus PAT-owner visibility.
#[test]
fn new_flow_allocation_completes_under_held_live_read_15956() {
    for seed_idle in [false, true] {
        let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
        let addrs = [pool_ip];
        let alloc = Arc::new(PortAllocator::new(1, 20_000, 20_100));
        if seed_idle {
            seed_idle_persistent_lease_17041(&alloc, &addrs);
        }
        let guard = alloc.debug_hold_live_read();
        let done = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let contended_before = alloc.debug_live_lock_contended_total();
        let worker = {
            let alloc = Arc::clone(&alloc);
            let done = Arc::clone(&done);
            let started = Arc::clone(&started);
            std::thread::spawn(move || {
                let addrs2 = [pool_ip];
                started.store(true, Ordering::SeqCst);
                alloc
                    .allocate_translation(
                        pool_flow(42_000),
                        PoolAddressFamily::V4(&addrs2),
                        0,
                        false,
                        false,
                        PersistentNatPermit::TargetHostPort,
                        0,
                        0,
                        3_000,
                        crate::nat::NatHolder::Untracked,
                        0,
                    )
                    .expect("new-flow allocation must succeed");
                done.store(true, Ordering::SeqCst);
            })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !started.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            started.load(Ordering::SeqCst),
            "worker must start allocation"
        );
        // Give the worker a bounded window to either complete or hit
        // the contended try-write. With the fix, GC adds no blocking
        // write acquisition, so the only wait is the allocation's own
        // documented fallback. Without the fix (idle-lease arm), GC
        // itself blocks behind the held reader, which neither
        // completes nor records contention promptly — the loop below
        // still exits on deadline and the post-drop assertions catch
        // a worker that never ran at all via live_flow_count.
        while !done.load(Ordering::SeqCst)
            && alloc.debug_live_lock_contended_total() == contended_before
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let observed_contention = alloc.debug_live_lock_contended_total() > contended_before;
        let completed_under_read = done.load(Ordering::SeqCst);
        let gc_before_drop = alloc.debug_gc_lock_acquisitions();
        assert_eq!(
            gc_before_drop, 0,
            "seed_idle={seed_idle}: GC must not acquire the live write lock while nothing has expired (#17041)"
        );
        drop(guard);
        worker.join().expect("worker must not panic");
        // Post-join is where the pre-fix code diverges: the GC
        // blocked in lock_live() behind the reader acquires once
        // the guard drops (delta 1); the fix never acquires (0).
        assert_eq!(
            alloc.debug_gc_lock_acquisitions(),
            0,
            "seed_idle={seed_idle}: GC must not acquire the live write lock at all while nothing has expired (#17041)"
        );
        assert!(
            observed_contention || completed_under_read,
            "seed_idle={seed_idle}: worker must attempt the contended live write or finish before the deadline"
        );
        assert_eq!(
            alloc.live_flow_count(),
            1,
            "seed_idle={seed_idle}: exactly the worker flow must be live"
        );
        let pat = alloc
            .debug_live_flow_translated(&pool_flow(42_000))
            .expect("PAT flow must remain live");
        assert!(
            alloc.debug_pat_owns_wire_identity(&pool_flow(42_000), pat),
            "seed_idle={seed_idle}: PAT owner must be present after allocation"
        );
    }
}

/// #17041: an actually-expired idle lease is still reclaimed by the
/// chunked GC (peek does not weaken correctness), and a contended
/// write guard makes GC skip rather than block: behind a held READ
/// guard the sweep returns 0 promptly and reclaims once uncontended.
#[test]
fn expired_lease_still_reclaimed_and_contended_gc_skips_17041() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = Arc::new(PortAllocator::new(1, 20_000, 20_100));
    seed_idle_persistent_lease_17041(&alloc, &addrs);
    // Expiry was re-armed to 2_000 + 60s on release; sweep past it.
    let past_expiry = 2_000 + 60_000_000_000 + 1;
    {
        let _guard = alloc.debug_hold_live_read();
        assert_eq!(
            alloc.debug_gc_expired_chunked(past_expiry, 8),
            0,
            "contended GC must skip, not block, behind a held live READ guard (#17041)"
        );
    }
    assert_eq!(
        alloc.debug_gc_expired_chunked(past_expiry, 8),
        1,
        "expired idle lease must still be reclaimed once uncontended (#17041)"
    );
    let live = alloc.debug_live();
    assert!(live.persistent_by_source.is_empty());
    assert!(live.lease_expirations.is_empty());
}
