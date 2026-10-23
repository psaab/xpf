// #4800: tests for the SNAT pool allocator's `live` map-mutex contention
// accounting — the NAT-allocator leg of the new-flow-install ceiling
// instrumentation.
//
// The measurement these back exists to settle a specific question: at a
// sustained new-flow rate, is the residual Phase-1 (#2852) map mutex a
// material contributor, or do `publish_shared_session` and the N-way
// `replicate_session_upsert` fan-out saturate first? That question has an
// answer only if the allocator reports BOTH how often it took the mutex and
// how often it had to block, so every test here treats the two as a pair.
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
    allocate(&alloc, &addrs, 40010, 5_000);
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

/// #15956 fold (narrowed claim): the non-persistent admission
/// fast path is shard + SHARED `live` read — it must complete
/// while another thread holds the `live` READ guard (readers are
/// concurrent under the RwLock), which the pre-fold Mutex design
/// could not do. The write guard is still taken, briefly and
/// only, by lease-coupled/pressure paths and the try-only PAT
/// publish; an allocation that falls into those may wait for a
/// writer, bounded by that writer's critical section.
#[test]
fn new_flow_allocation_completes_under_held_live_read_15956() {
    let pool_ip: Ipv4Addr = "203.0.113.1".parse().unwrap();
    let addrs = [pool_ip];
    let alloc = Arc::new(PortAllocator::new(1, 1024, 65535));
    let guard = alloc.debug_hold_live_read();
    let done = Arc::new(AtomicBool::new(false));
    let worker = {
        let alloc = Arc::clone(&alloc);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let addrs2 = [pool_ip];
            alloc
                .allocate_translation(
                    pool_flow(42000),
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
                .expect("new-flow allocation must succeed under held live read guard");
            done.store(true, Ordering::SeqCst);
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        done.load(Ordering::SeqCst),
        "new-flow allocation blocked while the live READ lock was held — admission still serializes on the retained state lock (#15956 fold)"
    );
    drop(guard);
    worker.join().expect("worker must not panic");
    assert_eq!(alloc.live_flow_count(), 1);
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
