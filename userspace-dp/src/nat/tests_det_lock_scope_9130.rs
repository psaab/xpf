// #9130: the deterministic-CGNAT allocator's lock SCOPE.
//
// `allocate_deterministic_v4` / `_v6` used to hold the `live` map mutex across
// the whole linear CAS probe of the subscriber's port block, so the hold time
// was O(occupied prefix of the block) — up to a few thousand CAS attempts for a
// subscriber near its own block budget — while the sibling PAT path
// (`allocate_translation_inner`) had been DELIBERATELY restructured the other
// way in #4676: claim the port lock-free, take the mutex only for the tiny
// reuse/cap/insert critical section.
//
// The measurement problem these cells solve: lock HOLD TIME is not observable
// from a return value, and a timing assertion would be flaky. So the scope is
// bound structurally instead — the occupancy bitmap is CAS-based and lives
// OUTSIDE the mutex, so a thread holding `debug_live()` can watch the bitmap
// while an allocating worker is blocked on the map mutex. If the probe runs
// inside the mutex the bit can never appear while the guard is held; if it runs
// outside it must. That is a total, non-timing discriminator: the "still
// running" case is excluded by joining the worker at the end of the test.

use super::allocator::{DeterministicV4, DeterministicV6, PortAllocator, TranslatedTuple};
use super::source::{SourceNatFailureReason, SourceNatFlowKey};
use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Bounded so a regression that never claims the port fails the assertion
/// instead of hanging the suite.
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(5);

const POOL_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

fn v4_flow(src: Ipv4Addr, src_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn v6_flow(src: Ipv6Addr, src_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

/// 1 pool address, ports 1024..=2047 (1024 ports), block_size 256 ->
/// blocks_per_ip 4, subscriber CIDR 100.64.0.0/30 (4 subscribers).
fn det_v4() -> DeterministicV4 {
    DeterministicV4 {
        block_size: 256,
        blocks_per_ip: 4,
        host_base: u32::from(Ipv4Addr::new(100, 64, 0, 0)),
        host_count: 4,
    }
}

fn det_v6() -> DeterministicV6 {
    DeterministicV6 {
        block_size: 256,
        blocks_per_ip: 4,
        host_prefix_len: 32,
        host_base: "2001:db8::".parse::<Ipv6Addr>().expect("base").octets(),
        host_count: 4,
    }
}

/// Poll a lock-free predicate until it holds or the deadline expires.
fn wait_until(mut p: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + OBSERVE_TIMEOUT;
    while Instant::now() < deadline {
        if p() {
            return true;
        }
        std::hint::spin_loop();
    }
    false
}

/// THE LOCK-SCOPE CELL (v4). While this thread holds the allocator's `live`
/// mutex, a worker allocating a deterministic flow must still make progress on
/// the occupancy bitmap — because the block probe no longer runs under that
/// mutex.
///
/// RED on revert: move the `for p in port_start..=port_end` probe back inside
/// the `let mut live = self.lock_live();` scope and the worker cannot touch the
/// bitmap until this thread drops `guard`, so `debug_occupied_count()` stays 0
/// for the whole `OBSERVE_TIMEOUT` and the first assertion fails on its message.
#[test]
fn deterministic_v4_block_probe_runs_outside_the_allocator_mutex_9130() {
    let alloc = Arc::new(PortAllocator::new(1, 1024, 2047));
    assert_eq!(
        alloc.debug_occupied_count(),
        0,
        "fixture: a fresh allocator owns no ports"
    );

    let entered = Arc::new(AtomicBool::new(false));
    let guard = alloc.debug_live();

    let worker = {
        let alloc = Arc::clone(&alloc);
        let entered = Arc::clone(&entered);
        std::thread::spawn(move || {
            let pool = [POOL_V4];
            entered.store(true, Ordering::SeqCst);
            alloc.allocate_deterministic_v4(
                v4_flow(Ipv4Addr::new(100, 64, 0, 1), 40000),
                &pool,
                det_v4(),
                Ipv4Addr::new(100, 64, 0, 1),
                NatHolder::Untracked,
            )
        })
    };

    assert!(
        wait_until(|| entered.load(Ordering::SeqCst)),
        "fixture: the worker thread must reach the allocation call"
    );
    let claimed_while_locked = wait_until(|| alloc.debug_occupied_count() == 1);
    // Read the bitmap ONE more time before releasing, so the assertion message
    // reports the state that was actually observed under the guard.
    let observed = alloc.debug_occupied_count();
    drop(guard);
    let out = worker.join().expect("allocating thread must not panic");

    assert!(
        claimed_while_locked,
        "the block probe must claim a port while another thread holds the live \
         mutex — the probe runs OUTSIDE that mutex (#9130). Observed occupancy \
         {observed} after {OBSERVE_TIMEOUT:?} with the guard held"
    );
    let t = out.expect("the allocation must still succeed once the mutex is free");
    assert_eq!(t.ip, IpAddr::V4(POOL_V4), "subscriber 1 -> pool address 0");
    // Subscriber index 1 -> block 1 -> [1024 + 256, 1024 + 511].
    assert!(
        (1280..=1535).contains(&t.port),
        "subscriber 1 must land in its own block [1280,1535]; got {}",
        t.port
    );
    assert_eq!(
        alloc.debug_occupied_count(),
        1,
        "exactly the one claimed port stays occupied"
    );
}

/// THE LOCK-SCOPE CELL (v6). The NAPT64 arm is a SEPARATE function with the
/// same shape; measured, reverting only the v6 arm leaves the v4 cell green.
///
/// RED on revert: identical to the v4 cell, on `allocate_deterministic_v6`.
#[test]
fn deterministic_v6_block_probe_runs_outside_the_allocator_mutex_9130() {
    let alloc = Arc::new(PortAllocator::new(1, 1024, 2047));
    let entered = Arc::new(AtomicBool::new(false));
    let guard = alloc.debug_live();

    let worker = {
        let alloc = Arc::clone(&alloc);
        let entered = Arc::clone(&entered);
        std::thread::spawn(move || {
            let pool = [POOL_V4];
            let src: Ipv6Addr = "2001:db8:0:1::".parse().expect("src");
            entered.store(true, Ordering::SeqCst);
            alloc.allocate_deterministic_v6(
                v6_flow(src, 40000),
                &pool,
                det_v6(),
                src,
                NatHolder::Untracked,
            )
        })
    };

    assert!(
        wait_until(|| entered.load(Ordering::SeqCst)),
        "fixture: the worker thread must reach the allocation call"
    );
    let claimed_while_locked = wait_until(|| alloc.debug_occupied_count() == 1);
    let observed = alloc.debug_occupied_count();
    drop(guard);
    let out = worker.join().expect("allocating thread must not panic");

    assert!(
        claimed_while_locked,
        "the NAPT64 block probe must claim a port while another thread holds the \
         live mutex (#9130). Observed occupancy {observed} after \
         {OBSERVE_TIMEOUT:?} with the guard held"
    );
    let t = out.expect("the allocation must still succeed once the mutex is free");
    assert!(
        (1280..=1535).contains(&t.port),
        "subscriber word 1 must land in block 1 [1280,1535]; got {}",
        t.port
    );
}

/// OVER-REACH GUARD, and the reason the idempotent re-entry check is NOT
/// allowed to move below the probe.
///
/// A live flow's OWN port is occupied — by itself. If the probe ran first, a
/// subscriber whose block is FULL would find no free port and be told
/// `AllocatorExhausted` for a flow that already holds a translation, turning a
/// working flow's second packet into a drop. The naive "probe first, then take
/// the lock" restructure has exactly that defect, and it is invisible to every
/// other cell here because they all use blocks with free ports.
///
/// GREEN at master (the pre-fix code checks re-entry first too). It constrains
/// what the fix must NOT do, so it is not a restatement of the fix.
#[test]
fn a_full_block_still_re_enters_its_own_live_flow_9130() {
    // block_size 1: the subscriber's block is one port wide, so allocating once
    // fills it completely. A wider block could not distinguish "re-entry was
    // checked first" from "the probe happened to find a free sibling port".
    let det = DeterministicV4 {
        block_size: 1,
        blocks_per_ip: 4,
        host_base: u32::from(Ipv4Addr::new(100, 64, 0, 0)),
        host_count: 4,
    };
    let alloc = PortAllocator::new(1, 1024, 1027);
    let pool = [POOL_V4];
    let src = Ipv4Addr::new(100, 64, 0, 2);
    let flow = v4_flow(src, 40000);

    let first = alloc
        .allocate_deterministic_v4(flow.clone(), &pool, det, src, NatHolder::Untracked)
        .expect("the first flow must claim the subscriber's single block port");
    assert_eq!(first.port, 1026, "subscriber 2 -> block 2 -> port 1024+2");
    assert_eq!(
        alloc.debug_occupied_count(),
        1,
        "fixture: the subscriber's whole block is now occupied"
    );

    let again = alloc
        .allocate_deterministic_v4(flow, &pool, det, src, NatHolder::Untracked)
        .expect(
            "a second packet of a LIVE flow must re-enter its own translation even \
             though its block is full — probing first would return exhaustion",
        );
    assert_eq!(
        again, first,
        "idempotent re-entry must return the SAME tuple"
    );
    assert_eq!(
        alloc.debug_occupied_count(),
        1,
        "re-entry must not claim a second port"
    );
}

/// The give-back branch: the flow-table CAP is checked AFTER the port is
/// claimed (that is where the PAT fast path checks its own), so a refused
/// allocation must hand the port back — and hand it back WITHOUT recycling it.
/// A deterministic port is reusable via its occupancy bit alone; pushing it onto
/// the per-address FIFO recycle queue leaks it, because the deterministic
/// allocation path never drains that queue (#4559 / #5178).
///
/// Construction: fill `live_by_flow` to the cap with real deterministic flows,
/// then clear ONE subscriber's occupancy bits out of band (`debug_clear_owner`,
/// which does not touch `live_by_flow`). A fresh flow for that subscriber now
/// finds a free port, claims it, and is refused by the cap.
///
/// RED on revert: drop the `free_translated_port(ip_idx, port, false)` on the
/// cap arm and the occupancy assertion fails (a port leaks per refusal);
/// change its `false` to `true` and the recycle-queue assertion fails.
#[test]
fn a_cap_refusal_gives_the_claimed_port_back_unrecycled_9130() {
    // 1 address x 4 ports -> allocator_capacity 4 = max_tracked_flows.
    let det = DeterministicV4 {
        block_size: 1,
        blocks_per_ip: 4,
        host_base: u32::from(Ipv4Addr::new(100, 64, 0, 0)),
        host_count: 4,
    };
    let alloc = PortAllocator::new(1, 1024, 1027);
    let pool = [POOL_V4];

    for sub in 0..4u32 {
        let src = Ipv4Addr::from(u32::from(Ipv4Addr::new(100, 64, 0, 0)) + sub);
        alloc
            .allocate_deterministic_v4(
                v4_flow(src, 40000 + sub as u16),
                &pool,
                det,
                src,
                NatHolder::Untracked,
            )
            .expect("each of the four subscribers must claim its block port");
    }
    assert_eq!(
        alloc.live_flow_count(),
        4,
        "fixture: the flow table must be at its cap"
    );

    // Free subscriber 0's port bit WITHOUT removing its live_by_flow entry, so
    // the probe below succeeds and the cap check is what refuses.
    alloc.debug_clear_owner(0, IpAddr::V4(POOL_V4), 1024);
    let occupied_before = alloc.debug_occupied_count();
    assert_eq!(
        occupied_before, 3,
        "fixture: exactly one port bit was cleared out of band"
    );
    assert!(
        alloc.debug_recycled_ports(0).is_empty(),
        "fixture: nothing has been recycled yet"
    );

    let src0 = Ipv4Addr::new(100, 64, 0, 0);
    let refused = alloc.allocate_deterministic_v4(
        v4_flow(src0, 50000),
        &pool,
        det,
        src0,
        NatHolder::Untracked,
    );
    assert_eq!(
        refused.err(),
        Some(SourceNatFailureReason::AllocatorExhausted),
        "a flow table at its cap must refuse"
    );
    assert_eq!(
        alloc.debug_occupied_count(),
        occupied_before,
        "the refused allocation must give its claimed port back — occupancy must \
         be exactly what it was before the call"
    );
    assert!(
        alloc.debug_recycled_ports(0).is_empty(),
        "a deterministic port must be given back via free_no_recycle: the \
         deterministic path never drains the per-address recycle queue, so a \
         recycled token is a leak (#4559 / #5178). Queue holds {:?}",
        alloc.debug_recycled_ports(0)
    );
}

/// OVER-REACH GUARD. The restructure must not change what the allocator hands
/// out: distinct subscribers still land on their own fixed blocks, and a second
/// distinct flow from the SAME subscriber still takes the next free port in that
/// subscriber's block (never a sibling subscriber's).
///
/// GREEN at master. Its job is to catch a restructure that made the lock scope
/// right and the allocation wrong.
#[test]
fn the_restructure_does_not_change_which_block_a_subscriber_gets_9130() {
    let alloc = PortAllocator::new(1, 1024, 2047);
    let pool = [POOL_V4];
    let det = det_v4();

    let mut seen: Vec<(Ipv4Addr, TranslatedTuple)> = Vec::new();
    for sub in 0..4u32 {
        let src = Ipv4Addr::from(u32::from(Ipv4Addr::new(100, 64, 0, 0)) + sub);
        for n in 0..3u16 {
            let t = alloc
                .allocate_deterministic_v4(
                    v4_flow(src, 40000 + n),
                    &pool,
                    det,
                    src,
                    NatHolder::Untracked,
                )
                .expect("in-range subscriber must allocate");
            let lo = 1024 + sub as u16 * 256;
            assert!(
                (lo..lo + 256).contains(&t.port),
                "subscriber {src} flow {n} must stay in block [{lo},{}]; got {}",
                lo + 255,
                t.port
            );
            // First free port in the block, in order.
            assert_eq!(t.port, lo + n, "the probe must claim the first free port");
            seen.push((src, t));
        }
    }
    assert_eq!(
        alloc.debug_occupied_count(),
        12,
        "12 distinct ports claimed"
    );
    let mut ports: Vec<u16> = seen.iter().map(|(_, t)| t.port).collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 12, "no two flows may share a translated port");
}

/// The idempotency RACE arm: another worker installed this flow between this
/// one's lock-free port claim and its insert. The loser must return the
/// WINNER's translation and give its own claimed port back — un-recycled.
///
/// Forced deterministically rather than raced for (see
/// `debug_insert_live_locked`): this thread parks on the live mutex, waits for
/// the worker to claim its port (visible lock-free on the occupancy bitmap),
/// injects the winning record, and only then releases. Without the forcing the
/// arm fires once in many runs and a mutation there scores as survived.
///
/// RED on revert: delete the post-probe `live_by_flow.get(&flow)` arm and the
/// worker overwrites the injected record with its own tuple, so the returned
/// tuple is not the winner's AND the port stays occupied — two assertions fail.
/// Change its `free_translated_port(..., false)` to `true` and the recycle-queue
/// assertion fails.
#[test]
fn an_idempotency_race_gives_the_claimed_port_back_unrecycled_9130() {
    let alloc = Arc::new(PortAllocator::new(1, 1024, 2047));
    let entered = Arc::new(AtomicBool::new(false));
    let src = Ipv4Addr::new(100, 64, 0, 1);
    let flow = v4_flow(src, 40000);

    let mut guard = alloc.debug_live();
    let worker = {
        let alloc = Arc::clone(&alloc);
        let entered = Arc::clone(&entered);
        let flow = flow.clone();
        std::thread::spawn(move || {
            let pool = [POOL_V4];
            entered.store(true, Ordering::SeqCst);
            alloc.allocate_deterministic_v4(flow, &pool, det_v4(), src, NatHolder::Untracked)
        })
    };

    assert!(
        wait_until(|| entered.load(Ordering::SeqCst)),
        "fixture: the worker thread must reach the allocation call"
    );
    assert!(
        wait_until(|| alloc.debug_occupied_count() == 1),
        "fixture: the worker must have claimed its port lock-free and be parked \
         on the insert critical section"
    );

    // The winner's tuple is deliberately OUTSIDE the allocator's port range and
    // claims no occupancy bit, so the occupancy assertion below reads only the
    // loser's give-back.
    let winner = TranslatedTuple {
        ip: IpAddr::V4(POOL_V4),
        port: 9999,
    };
    PortAllocator::debug_insert_live_locked(&mut guard, flow, winner, 0, true);
    drop(guard);
    let out = worker
        .join()
        .expect("allocating thread must not panic")
        .expect("the loser must succeed with the winner's translation, not fail");

    assert_eq!(
        out, winner,
        "the loser of the idempotency race must return the WINNER's translation"
    );
    assert_eq!(
        alloc.debug_occupied_count(),
        0,
        "the loser must give its claimed port back"
    );
    assert!(
        alloc.debug_recycled_ports(0).is_empty(),
        "the give-back must be free_no_recycle — the deterministic path never \
         drains the per-address recycle queue (#4559 / #5178). Queue holds {:?}",
        alloc.debug_recycled_ports(0)
    );
}

/// #9902 F-098 (v4 behavior): the word-skipping probe claims the first free
/// port ascending, reports a full block as exhaustion (bumping the counter),
/// and reclaims a freed port as the new lowest-free — the exact contract the
/// naive per-port loop provided.
#[test]
fn deterministic_block_probe_claims_first_free_reclaims_and_reports_full_9902() {
    let alloc = PortAllocator::new(1, 1024, 2047);
    let pool = [POOL_V4];
    let det = det_v4();
    let src = Ipv4Addr::new(100, 64, 0, 0); // block 0: [1024, 1279].
    let ip = IpAddr::V4(POOL_V4);
    // Neighbor-block ports pin the probe inside its block: it must neither
    // claim them nor disturb them.
    alloc.debug_seed_owner(0, ip, 1280);
    for p in 1024..1279u16 {
        alloc.debug_seed_owner(0, ip, p);
    }
    let t = alloc
        .allocate_deterministic_v4(v4_flow(src, 40000), &pool, det, src, NatHolder::Untracked)
        .expect("one free port left in the block");
    assert_eq!(t.port, 1279, "must claim the only free port");
    assert!(
        alloc.debug_is_port_occupied(0, 1280),
        "probe must not disturb the neighboring block"
    );
    let before = alloc.snapshot().exhaustion_total;
    let err = alloc
        .allocate_deterministic_v4(v4_flow(src, 40001), &pool, det, src, NatHolder::Untracked)
        .expect_err("a full block must report exhaustion");
    assert!(
        matches!(err, SourceNatFailureReason::AllocatorExhausted),
        "full block must be AllocatorExhausted, got {err:?}"
    );
    assert_eq!(
        alloc.snapshot().exhaustion_total,
        before + 1,
        "full block must bump exhaustion_total exactly once"
    );
    alloc.debug_clear_owner(0, ip, 1100);
    let t = alloc
        .allocate_deterministic_v4(v4_flow(src, 40002), &pool, det, src, NatHolder::Untracked)
        .expect("freed port must be reclaimable");
    assert_eq!(t.port, 1100, "must reclaim the freed port as lowest-free");
}

/// #9902 F-098 (v4 attempt bound): on a dense-prefix fixture the probe loads
/// one word per 64 occupied ports and performs exactly one claim RMW — NOT one
/// RMW per occupied port. `debug_seed_owner` sets bits without touching the
/// counters, so one measured allocation reads exact.
///
/// FAIL-ON-REVERT: restore the naive `for p in port_start..=port_end` loop and
/// the RMW count is 201, not 1 (verified by scratch-revert during review).
#[test]
fn deterministic_block_probe_attempts_bounded_by_words_9902() {
    let alloc = PortAllocator::new(1, 1024, 2047);
    let pool = [POOL_V4];
    let det = det_v4();
    let src = Ipv4Addr::new(100, 64, 0, 0); // block 0: [1024, 1279].
    let ip = IpAddr::V4(POOL_V4);
    for p in 1024..1224u16 {
        alloc.debug_seed_owner(0, ip, p);
    }
    assert_eq!(alloc.debug_probe_attempts(0), (0, 0), "seeding must not count");
    let t = alloc
        .allocate_deterministic_v4(v4_flow(src, 40000), &pool, det, src, NatHolder::Untracked)
        .expect("ports free in the block");
    assert_eq!(t.port, 1224, "must claim the first free port");
    assert_eq!(
        alloc.debug_probe_attempts(0),
        (4, 1),
        "200 occupied ports = 3 skipped full words + 1 word holding the \
         candidate: 4 loads and exactly 1 claim RMW"
    );
    // A full block loads every word and attempts no claim.
    for p in 1224..1280u16 {
        alloc.debug_seed_owner(0, ip, p);
    }
    let err = alloc
        .allocate_deterministic_v4(v4_flow(src, 40001), &pool, det, src, NatHolder::Untracked)
        .expect_err("a full block must report exhaustion");
    assert!(matches!(err, SourceNatFailureReason::AllocatorExhausted));
    assert_eq!(
        alloc.debug_probe_attempts(0),
        (8, 1),
        "full-block probe adds 4 loads and 0 claim RMWs"
    );
}

/// #9902 F-098 (v6 attempt bound): the NAPT64 arm shares the helper, so the
/// same bound holds there — a v6-only bypass of the helper cannot stay green.
#[test]
fn deterministic_v6_block_probe_attempts_bounded_by_words_9902() {
    let alloc = PortAllocator::new(1, 1024, 2047);
    let pool = [POOL_V4];
    let det = det_v6();
    let src: Ipv6Addr = "2001:db8::".parse().expect("base");
    let ip = IpAddr::V4(POOL_V4);
    for p in 1024..1224u16 {
        alloc.debug_seed_owner(0, ip, p);
    }
    let t = alloc
        .allocate_deterministic_v6(v6_flow(src, 40000), &pool, det, src, NatHolder::Untracked)
        .expect("ports free in the block");
    assert_eq!(t.port, 1224, "must claim the first free port of block 0");
    assert_eq!(
        alloc.debug_probe_attempts(0),
        (4, 1),
        "v6 arm must share the word-skipping probe, not a per-port loop"
    );
}

/// #9902 F-098 (v6 behavior mirror): first-free claim and full-block
/// exhaustion on the NAPT64 arm.
#[test]
fn deterministic_v6_block_probe_claims_first_free_and_reports_full_9902() {
    let alloc = PortAllocator::new(1, 1024, 2047);
    let pool = [POOL_V4];
    let det = det_v6();
    let src: Ipv6Addr = "2001:db8::".parse().expect("base");
    let ip = IpAddr::V4(POOL_V4);
    for p in 1024..1279u16 {
        alloc.debug_seed_owner(0, ip, p);
    }
    let t = alloc
        .allocate_deterministic_v6(v6_flow(src, 40000), &pool, det, src, NatHolder::Untracked)
        .expect("one free port left in the block");
    assert_eq!(t.port, 1279, "must claim the only free port");
    let err = alloc
        .allocate_deterministic_v6(v6_flow(src, 40001), &pool, det, src, NatHolder::Untracked)
        .expect_err("a full block must report exhaustion");
    assert!(matches!(err, SourceNatFailureReason::AllocatorExhausted));
}

/// #9902 F-098 (edge masks): blocks are arbitrary positive sizes, so the probe
/// must mask out-of-block bits in the first and last word — both-edges-in-one-
/// word, a 63/64 boundary crossing, a partial final word with the highest valid
/// port, and untouched neighbors.
#[test]
fn deterministic_block_probe_edge_masks_9902() {
    let pool = [POOL_V4];
    let ip = IpAddr::V4(POOL_V4);
    // Both edges in one word: block_size 32 -> block 0 = offsets [0, 31].
    {
        let alloc = PortAllocator::new(1, 1024, 2047);
        let det = DeterministicV4 {
            block_size: 32,
            blocks_per_ip: 32,
            host_base: u32::from(Ipv4Addr::new(100, 64, 0, 0)),
            host_count: 32,
        };
        let src = Ipv4Addr::new(100, 64, 0, 0);
        for p in 1024..1055u16 {
            alloc.debug_seed_owner(0, ip, p);
        }
        let t = alloc
            .allocate_deterministic_v4(
                v4_flow(src, 40000),
                &pool,
                det,
                src,
                NatHolder::Untracked,
            )
            .expect("one free port in the one-word block");
        assert_eq!(t.port, 1055, "must claim the block's last port");
        alloc.debug_seed_owner(0, ip, 1055);
        assert!(
            matches!(
                alloc.allocate_deterministic_v4(
                    v4_flow(src, 40001),
                    &pool,
                    det,
                    src,
                    NatHolder::Untracked
                ),
                Err(SourceNatFailureReason::AllocatorExhausted)
            ),
            "a full one-word block must report exhaustion, never an out-of-block bit"
        );
    }
    // 63/64 boundary crossing: block_size 128 -> block 0 = offsets [0, 127].
    // Word 0 is fully occupied; only offset 64 (the first bit of word 1) is free.
    {
        let alloc = PortAllocator::new(1, 1024, 2047);
        let det = DeterministicV4 {
            block_size: 128,
            blocks_per_ip: 8,
            host_base: u32::from(Ipv4Addr::new(100, 64, 0, 0)),
            host_count: 8,
        };
        let src = Ipv4Addr::new(100, 64, 0, 0);
        for p in 1024..1152u16 {
            if p == 1088 {
                continue;
            }
            alloc.debug_seed_owner(0, ip, p);
        }
        let t = alloc
            .allocate_deterministic_v4(
                v4_flow(src, 40000),
                &pool,
                det,
                src,
                NatHolder::Untracked,
            )
            .expect("offset 64 free across the word boundary");
        assert_eq!(t.port, 1088, "must cross into word 1 for the free bit");
    }
    // Partial final word + highest valid port: range 1024..=2000 (977 ports).
    // Block 3 = [1792, 2000]; the last word's bits past offset 976 are masked.
    {
        let alloc = PortAllocator::new(1, 1024, 2000);
        let det = DeterministicV4 {
            block_size: 256,
            blocks_per_ip: 4,
            host_base: u32::from(Ipv4Addr::new(100, 64, 0, 0)),
            host_count: 4,
        };
        let src = Ipv4Addr::new(100, 64, 0, 3);
        for p in 1792..2000u16 {
            alloc.debug_seed_owner(0, ip, p);
        }
        let t = alloc
            .allocate_deterministic_v4(
                v4_flow(src, 40000),
                &pool,
                det,
                src,
                NatHolder::Untracked,
            )
            .expect("highest port free in the partial-word block");
        assert_eq!(t.port, 2000, "must claim the highest valid port");
        alloc.debug_seed_owner(0, ip, 2000);
        assert!(
            matches!(
                alloc.allocate_deterministic_v4(
                    v4_flow(src, 40001),
                    &pool,
                    det,
                    src,
                    NatHolder::Untracked
                ),
                Err(SourceNatFailureReason::AllocatorExhausted)
            ),
            "masked-out-of-range bits must never be claimed"
        );
        assert_eq!(
            alloc.debug_occupied_count(),
            209,
            "exactly the 209 block ports occupied, nothing outside"
        );
    }
    // Adjacent out-of-block neighbors stay owned by their own blocks.
    {
        let alloc = PortAllocator::new(1, 1024, 2047);
        let det = DeterministicV4 {
            block_size: 32,
            blocks_per_ip: 32,
            host_base: u32::from(Ipv4Addr::new(100, 64, 0, 0)),
            host_count: 32,
        };
        let src = Ipv4Addr::new(100, 64, 0, 1); // block 1: [1056, 1087].
        alloc.debug_seed_owner(0, ip, 1055); // block 0's last port.
        alloc.debug_seed_owner(0, ip, 1088); // block 2's first port.
        for p in 1056..1087u16 {
            if p == 1060 {
                continue;
            }
            alloc.debug_seed_owner(0, ip, p);
        }
        let t = alloc
            .allocate_deterministic_v4(
                v4_flow(src, 40000),
                &pool,
                det,
                src,
                NatHolder::Untracked,
            )
            .expect("one free port in block 1");
        assert_eq!(t.port, 1060, "must claim inside the block");
        assert!(
            alloc.debug_is_port_occupied(0, 1055) && alloc.debug_is_port_occupied(0, 1088),
            "adjacent out-of-block ports must stay owned"
        );
    }
}

/// #9902 F-098 (progress under contention): 4 threads drain one 256-port block
/// concurrently. Every allocation must succeed exactly once with a distinct
/// port — a claim-loss retry that reloaded words or retried tried bits could
/// livelock or double-claim here. Joined directly like the #9130 cells: a
/// forward-progress failure hangs the suite loudly rather than flaking.
#[test]
fn deterministic_block_probe_progress_under_contention_9902() {
    let alloc = Arc::new(PortAllocator::new(1, 1024, 2047));
    let det = det_v4();
    let src = Ipv4Addr::new(100, 64, 0, 2); // block 2: [1536, 1791].
    let mut workers = Vec::new();
    for t in 0..4u16 {
        let alloc = Arc::clone(&alloc);
        workers.push(std::thread::spawn(move || {
            let pool = [POOL_V4];
            let mut ports = Vec::new();
            for i in 0..64u16 {
                let flow = v4_flow(src, 50000 + t * 64 + i);
                let out = alloc
                    .allocate_deterministic_v4(flow, &pool, det, src, NatHolder::Untracked)
                    .expect("block has room for every worker's flows");
                ports.push(out.port);
            }
            ports
        }));
    }
    let mut all = Vec::new();
    for w in workers {
        all.extend(w.join().expect("worker must not panic"));
    }
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 256, "every flow must hold a DISTINCT port");
    assert!(
        all.iter().all(|p| (1536..=1791).contains(p)),
        "every claim must stay in block 2"
    );
    assert_eq!(alloc.debug_occupied_count(), 256);
}
