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
            now_ns,
            crate::nat::NatHolder::Untracked, 0)
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
            1_000,
            crate::nat::NatHolder::Untracked, 0)
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
