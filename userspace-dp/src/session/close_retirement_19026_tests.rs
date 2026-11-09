//! #19026 (fold cycle 3): the close-retirement directory, the node's one owner
//! of a restored session's Close obligation. Pure directory semantics and its
//! concurrency under real threads; the producers (claim, replacement,
//! takeover) are pinned through production paths in
//! `afxdp/worker/loop_body/promote_fence_concurrency_19026_tests.rs`.

use super::*;
use crate::session::{SessionOrigin, SessionTable};
use std::sync::Arc;

const SEC: u64 = 1_000_000_000;
const HOLD: u64 = 14 * SEC;

/// A restored session's Close delta (session id `id`, owner RG `rg`).
fn close_for(id: u64, rg: i32) -> SessionDelta {
    let req = crate::SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_UDP,
        src_ip: "10.0.63.106".to_string(),
        dst_ip: "172.16.80.211".to_string(),
        src_port: (id & 0xffff) as u16,
        dst_port: 9,
        owner_rg_id: rg,
        session_id: id,
        ..crate::SessionSyncRequest::default()
    };
    let entry = crate::server::helpers::build_synced_session_entry(
        &req,
        &rustc_hash::FxHashMap::default(),
        0,
    )
    .expect("FIXTURE: entry");
    let mut table = SessionTable::new();
    table.emit_close_delta_with_origin(
        entry.key,
        entry.decision,
        entry.metadata,
        SessionOrigin::SharedPromote,
        false,
        id,
    );
    table.drain_deltas(1).pop().expect("FIXTURE: close delta")
}

fn directory() -> CloseRetirementDirectory {
    let directory = CloseRetirementDirectory::default();
    directory.set_hold_ns(HOLD);
    directory
}

#[test]
fn create_is_compare_and_insert_and_the_tombstone_fences_late_producers_19026() {
    let dir = directory();
    let close = close_for(0x1001, 1);
    assert_eq!(dir.try_create(0x1001, 1, 100 * SEC, &close), CreateOutcome::Created);
    assert_eq!(dir.try_create(0x1001, 2, 100 * SEC, &close), CreateOutcome::Exists);
    assert!(dir.contains(0x1001));
    // The Close's flush turns it into a tombstone for two holds.
    dir.mark_flushed(0x1001, &close.key, 50 * SEC);
    assert!(matches!(dir.entry_for_test(0x1001), Some(Retirement::Flushed { .. })));
    assert_eq!(
        dir.try_create(0x1001, 2, 100 * SEC, &close),
        CreateOutcome::Exists,
        "a late producer loses to the tombstone"
    );
    // A tombstone is never taken over; it expires after two holds.
    assert!(dir.sweep(2, 50 * SEC + 2 * HOLD - 1, &[], &|_| true).is_empty());
    assert!(dir.contains(0x1001));
    assert!(dir.sweep(2, 50 * SEC + 2 * HOLD, &[], &|_| true).is_empty());
    assert!(!dir.contains(0x1001), "expired tombstone");
    assert_eq!(dir.len(), 0);
}

#[test]
fn a_flush_for_another_key_or_id_does_not_retire_the_entry_19026() {
    let dir = directory();
    let close = close_for(0x1002, 1);
    let other = close_for(0x1003, 1);
    assert_eq!(dir.try_create(0x1002, 1, 100 * SEC, &close), CreateOutcome::Created);
    dir.mark_flushed(0x1002, &other.key, 50 * SEC);
    dir.mark_flushed(0x1003, &close.key, 50 * SEC);
    assert!(matches!(dir.entry_for_test(0x1002), Some(Retirement::Pending { .. })));
}

/// Conditions 1: the directory is bounded; at the cap a producer gets `Full`
/// and must emit its Close anyway (at-least-once, never a silent drop).
#[test]
fn at_the_cap_producers_emit_anyway_19026() {
    let dir = CloseRetirementDirectory::with_cap(3);
    for id in 1..=3u64 {
        let outcome = dir.try_create(id, 1, 100 * SEC, &close_for(id, 1));
        assert_eq!(outcome, CreateOutcome::Created);
    }
    assert_eq!(dir.len(), 3, "filled to the cap");
    let full = dir.try_create(4, 1, 100 * SEC, &close_for(4, 1));
    assert_eq!(full, CreateOutcome::Full);
    assert!(full.emits(), "fail safe: the producer emits its Close directly");
    assert!(!CreateOutcome::Exists.emits());
    assert!(!dir.contains(4), "nothing is recorded past the cap");
    assert_eq!(
        CloseRetirementDirectory::default().try_create(9, 1, 1, &close_for(9, 1)),
        CreateOutcome::Created
    );
    assert!(CLOSE_RETIREMENT_CAP >= 2 * 24_000, "covers two 24k-session bursts");
}

#[test]
fn takeover_after_the_deadline_and_retry_now_for_a_full_ring_19026() {
    let dir = directory();
    let close = close_for(0x1004, 1);
    assert_eq!(dir.try_create(0x1004, 7, 100 * SEC, &close), CreateOutcome::Created);
    assert!(dir.sweep(8, 99 * SEC, &[], &|_| true).is_empty(), "not due yet");
    let taken = dir.sweep(8, 100 * SEC, &[], &|_| true);
    assert_eq!(taken.len(), 1, "an expired entry is taken over");
    assert_eq!(taken[0].session_id, 0x1004);
    match dir.entry_for_test(0x1004) {
        Some(Retirement::Pending { owner_worker, retry_at_ns, .. }) => {
            assert_eq!(owner_worker, 8);
            assert_eq!(retry_at_ns, 100 * SEC + HOLD);
        }
        other => panic!("expected the taken entry, got {other:?}"),
    }
    // The taker's push found a full ring: due at once for the next sweep.
    dir.retry_now(0x1004, 101 * SEC);
    assert_eq!(dir.sweep(9, 101 * SEC, &[], &|_| true).len(), 1);
}

/// A live owner renews the entries it still holds a Close for, so a sweep
/// by another worker never takes them over (exactly once while it lives).
#[test]
fn a_live_owner_renews_and_is_never_taken_over_19026() {
    let dir = directory();
    let close = close_for(0x1005, 1);
    assert_eq!(dir.try_create(0x1005, 7, 10 * SEC, &close), CreateOutcome::Created);
    for t in 1..=60u64 {
        let now = t * SEC;
        assert!(dir.sweep(7, now, &[0x1005], &|_| true).is_empty(), "the owner renews");
        assert!(dir.sweep(8, now, &[], &|_| true).is_empty(), "t={t}: no takeover");
    }
    // A non-owner listing the id does not renew it.
    assert!(dir.sweep(8, 61 * SEC, &[0x1005], &|_| true).is_empty());
    assert_eq!(dir.sweep(8, 60 * SEC + HOLD, &[], &|_| true).len(), 1, "the owner stopped");
}

/// Conditions 2: a Pending entry whose owner RG this node no longer forwards
/// is dropped without a Close; the RG's new owner closes the session through
/// its own copy and idle expiry.
#[test]
fn an_entry_of_an_rg_this_node_no_longer_forwards_is_dropped_19026() {
    let dir = directory();
    assert_eq!(dir.try_create(0x1006, 7, 10 * SEC, &close_for(0x1006, 2)), CreateOutcome::Created);
    assert_eq!(dir.try_create(0x1007, 7, 10 * SEC, &close_for(0x1007, 1)), CreateOutcome::Created);
    let forwards = |rg: i32| rg == 1;
    let taken = dir.sweep(8, 20 * SEC, &[], &forwards);
    assert_eq!(taken.len(), 1, "only the forwarded RG's entry is taken over");
    assert_eq!(taken[0].session_id, 0x1007);
    assert!(!dir.contains(0x1006), "the other RG's entry is dropped, not emitted");
}

/// Conditions 3 (real threads): two producers racing to create the same
/// session's entry: exactly one wins, every time.
#[test]
fn racing_creators_produce_exactly_one_winner_19026() {
    for round in 0..300u64 {
        let dir = Arc::new(directory());
        let close = Arc::new(close_for(0x2000 + round, 1));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2u32)
            .map(|worker| {
                let (dir, close, barrier) = (dir.clone(), close.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    dir.try_create(close.session_id, worker, 100 * SEC, &close)
                })
            })
            .collect();
        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().expect("join")).collect();
        let created = outcomes.iter().filter(|o| **o == CreateOutcome::Created).count();
        assert_eq!(created, 1, "round {round}: {outcomes:?}");
    }
}

/// Conditions 3 (real threads): a takeover racing the owner's renewal at the
/// deadline. Exactly one of them wins, and the entry agrees with it: either
/// the taker got the Close and owns the entry, or the owner renewed and the
/// taker got nothing.
#[test]
fn takeover_racing_a_renewal_is_consistent_19026() {
    let mut taken_rounds = 0;
    for round in 0..500u64 {
        let dir = Arc::new(directory());
        let id = 0x3000 + round;
        let close = close_for(id, 1);
        assert_eq!(dir.try_create(id, 7, 10 * SEC, &close), CreateOutcome::Created);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let owner = {
            let (dir, barrier) = (dir.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                dir.sweep(7, 10 * SEC, &[id], &|_| true).len()
            })
        };
        let taker = {
            let (dir, barrier) = (dir.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                dir.sweep(8, 10 * SEC, &[], &|_| true).len()
            })
        };
        let owner_took = owner.join().expect("owner");
        let taker_took = taker.join().expect("taker");
        let owner_now = match dir.entry_for_test(id) {
            Some(Retirement::Pending { owner_worker, .. }) => owner_worker,
            other => panic!("round {round}: {other:?}"),
        };
        // The owner's own sweep may also take its due entry before renewing
        // is relevant (it is the owner either way); the taker takes only if
        // it ran first.
        assert!(owner_took + taker_took <= 1, "round {round}: one push at most");
        if taker_took == 1 {
            taken_rounds += 1;
            assert_eq!(owner_now, 8, "round {round}: the taker owns what it took");
        } else {
            assert_eq!(owner_now, 7, "round {round}: the owner kept it");
        }
    }
    let _ = taken_rounds;
}
