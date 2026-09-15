//! #9644: lock-free roam-snapshot cells for `note/take_worker_observed_endpoint`.
//!
//! Each cell pins worker-observable behavior, never the mechanism:
//! a cell that stays green when the snapshot is deleted (all reports
//! still flow through the mutex slot) is vacuous, so every suppression
//! assertion is paired with a shared-write-stability read (seq/epoch/
//! pending bit-identical) or the mutex-held adversary.

use super::peer::{decode_roam_endpoint, encode_roam_endpoint};
use super::tests::established_pair;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

const A: &str = "203.0.113.7:51820";
const B: &str = "198.51.100.9:51820";
const C: &str = "192.0.2.55:41820";

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("test address")
}

fn fixture() -> (super::WgEngine, [u8; 32]) {
    let allowed: Vec<ipnet::IpNet> = vec!["10.123.0.0/24".parse().unwrap()];
    let (_init, resp, init_pub, _resp_pub) = established_pair(allowed.clone(), allowed);
    (resp, init_pub)
}

fn snapshot_state(
    engine: &super::WgEngine,
    pk: &[u8; 32],
) -> (u64, u64, u64, bool) {
    let peer = engine.peer_arc(pk).expect("responder knows the peer");
    let snap = &peer.roam_snapshot;
    (
        snap.seq.load(Ordering::Relaxed),
        snap.live_epoch.load(Ordering::Relaxed),
        snap.snap_epoch.load(Ordering::Relaxed),
        peer.roamed_endpoint_pending.load(Ordering::Relaxed),
    )
}

/// The encoding is total and injective, including the V6 words the
/// production path always zeroes: a scope-only difference must be a
/// different snapshot, or a link-local roam would be invisible.
#[test]
fn snapshot_encoding_round_trips_9644() {
    let v4 = addr(A);
    assert_eq!(decode_roam_endpoint(&encode_roam_endpoint(v4)), Some(v4));
    let v6native: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
    assert_eq!(
        decode_roam_endpoint(&encode_roam_endpoint(v6native)),
        Some(v6native)
    );
    // Nonzero flowinfo/scope survive the round trip (production never
    // sends them — `outer_source_ip` zero-fills — but the helpers
    // must not silently drop them).
    let v6scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1".parse().unwrap(),
        51820,
        7,
        3,
    ));
    assert_eq!(
        decode_roam_endpoint(&encode_roam_endpoint(v6scoped)),
        Some(v6scoped)
    );
    // The all-zero snapshot (fresh peer) is None, never an endpoint.
    assert_eq!(decode_roam_endpoint(&[0, 0, 0, 0, 0]), None);
    // Unknown family discriminant is None, not a fabricated address.
    let mut bad = encode_roam_endpoint(v4);
    bad[0] |= 9u64 << 56;
    assert_eq!(decode_roam_endpoint(&bad), None);
    // A V4-mapped V6 and its canonical V4 are distinct snapshots —
    // canonicalization stays the drain's job, as with the slot.
    let mapped: SocketAddr = "[::ffff:203.0.113.7]:51820".parse().unwrap();
    assert_ne!(
        encode_roam_endpoint(mapped),
        encode_roam_endpoint(v4),
        "mapped and canonical forms must not alias in the snapshot"
    );
}

/// Steady state: the duplicate reports nothing AND publishes nothing
/// observable — no seq/epoch/pending write. A lock-path duplicate
/// (`lock` + equal + return) also leaves these unchanged, so this
/// cell pairs with the mutex-held adversary below, which only the
/// lock-free path can pass.
#[test]
fn steady_state_suppresses_without_shared_write_9644() {
    let (engine, pk) = fixture();
    let a = addr(A);
    assert!(engine.note_worker_observed_endpoint(&pk, a));
    let before = snapshot_state(&engine, &pk);
    assert!(
        !engine.note_worker_observed_endpoint(&pk, a),
        "an unchanged endpoint reports nothing"
    );
    assert_eq!(
        snapshot_state(&engine, &pk),
        before,
        "the duplicate must publish nothing observable"
    );
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(a));
    assert_eq!(engine.take_worker_observed_endpoint(&pk), None);
}

/// The behavioral pin for mutex-freedom: with the mailbox mutex held
/// by another thread, a steady-state note must still complete
/// promptly. RED on the pre-#9644 code (it blocks on `lock()` and
/// the recv times out); GREEN only via the lock-free path. The guard
/// is released before joining so a regression fails instead of
/// hanging the harness.
#[test]
fn suppression_needs_no_mutex_9644() {
    let (engine, pk) = fixture();
    let a = addr(A);
    assert!(engine.note_worker_observed_endpoint(&pk, a));
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(a));
    // Re-report post-drain so the snapshot is fresh (today's cadence).
    assert!(engine.note_worker_observed_endpoint(&pk, a));
    assert!(
        !engine.note_worker_observed_endpoint(&pk, a),
        "precondition: steady state suppresses"
    );

    let engine = Arc::new(engine);
    let peer = engine.peer_arc(&pk).expect("responder knows the peer");
    let guard = peer
        .roamed_endpoint
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = {
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || {
            let reported = engine.note_worker_observed_endpoint(&pk, a);
            let _ = tx.send(reported);
        })
    };
    let outcome = rx.recv_timeout(std::time::Duration::from_secs(5));
    drop(guard);
    let _ = worker.join();
    assert_eq!(
        outcome,
        Ok(false),
        "a steady-state note must complete without the mailbox mutex"
    );
}

/// Post-drain re-report is today's cadence and stays it: each take
/// bumps the generation, so the next packet of the same endpoint
/// always re-reports (this is what refreshes `last_authenticated_rx`
/// every pass and heals socket/DNS overwrites — plan §5.3).
#[test]
fn post_drain_rereports_like_today_9644() {
    let (engine, pk) = fixture();
    let a = addr(A);
    assert!(engine.note_worker_observed_endpoint(&pk, a));
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(a));
    assert!(
        engine.note_worker_observed_endpoint(&pk, a),
        "post-take the slot is empty, so the slow path must publish (report paths are mutex-serialized, identical to today)"
    );
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(a));
    assert_eq!(engine.take_worker_observed_endpoint(&pk), None);
}

/// A changed endpoint reports exactly once; the drain adopts it once.
#[test]
fn change_reports_once_then_drains_9644() {
    let (engine, pk) = fixture();
    let (a, b) = (addr(A), addr(B));
    assert!(engine.note_worker_observed_endpoint(&pk, a));
    assert!(!engine.note_worker_observed_endpoint(&pk, a));
    assert!(
        engine.note_worker_observed_endpoint(&pk, b),
        "a genuinely new endpoint must report"
    );
    assert!(!engine.note_worker_observed_endpoint(&pk, b));
    let before = snapshot_state(&engine, &pk);
    assert!(!engine.note_worker_observed_endpoint(&pk, b));
    assert_eq!(
        snapshot_state(&engine, &pk),
        before,
        "the second duplicate must not republish"
    );
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(b));
    assert_eq!(engine.take_worker_observed_endpoint(&pk), None);
}

/// Control-thread restart with engine reuse (zai-r1 hole): after a
/// drain, invalidation forces the next packet to re-report (empty
/// mailbox). With a report still queued, invalidation must NOT
/// duplicate it — the pending report belongs to the new consumer —
/// but it MUST advance the generation and republish the snapshot:
/// with `invalidate_roam_snapshots()` no-op'd the populated half
/// fast-suppresses with zero state change, so the epoch/seq
/// assertions below fail.
#[test]
fn restart_invalidation_rereports_empty_and_populated_9644() {
    let (engine, pk) = fixture();
    let (a, b) = (addr(A), addr(B));
    // Empty mailbox: drained, then the consumer restarts. The take
    // already bumped the generation; invalidation must bump it again
    // — that second bump is invalidate's own observable effect.
    assert!(engine.note_worker_observed_endpoint(&pk, a));
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(a));
    let (_, live_drained, _, _) = snapshot_state(&engine, &pk);
    engine.invalidate_roam_snapshots();
    let (_, live_invalidated, _, _) = snapshot_state(&engine, &pk);
    assert_eq!(
        live_invalidated,
        live_drained + 1,
        "invalidate must bump even on an empty mailbox (no-op invalidate keeps the epoch)"
    );
    assert!(
        engine.note_worker_observed_endpoint(&pk, a),
        "a fresh consumer must re-learn the live endpoint"
    );
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(a));
    // Populated mailbox: queued, never taken, snapshot fresh — then
    // the restart. The next note must still suppress (no duplicate),
    // but through the SLOW path: the stale epoch forces lock +
    // repair, republishing the snapshot at the live generation.
    assert!(engine.note_worker_observed_endpoint(&pk, b));
    let (seq_fresh, live_fresh, _, pending_fresh) = snapshot_state(&engine, &pk);
    assert!(pending_fresh, "fixture precondition: the report is queued");
    engine.invalidate_roam_snapshots();
    assert!(
        !engine.note_worker_observed_endpoint(&pk, b),
        "the queued report is still queued — no duplicate"
    );
    let (seq_repaired, live_now, snap_epoch_now, pending_now) =
        snapshot_state(&engine, &pk);
    assert_eq!(
        live_now,
        live_fresh + 1,
        "invalidate must advance the generation"
    );
    assert_eq!(
        snap_epoch_now, live_now,
        "repair must restamp to the live generation (no-op repair leaves it stale)"
    );
    assert!(
        seq_repaired > seq_fresh,
        "repair must publish (no-op invalidate leaves the sequence)"
    );
    assert!(
        pending_now,
        "the queued report stays pending across the restart"
    );
    assert_eq!(
        engine.take_worker_observed_endpoint(&pk),
        Some(b),
        "the new consumer still adopts the queued roam"
    );
    assert_eq!(engine.take_worker_observed_endpoint(&pk), None);
}

/// A stale-but-equal slow hit repairs the snapshot: after racing an
/// invalidation, the repairing note restamps to the live generation
/// and advances the sequence; the next packet suppresses with zero
/// further shared write (no permanently-cold state). Capturing state
/// BEFORE the repair is what makes this cell sensitive: a repair
/// no-op'd to bare `return false` leaves the stamped epoch stale and
/// the sequence still, failing both freshness assertions.
#[test]
fn racing_invalidation_regains_suppression_9644() {
    let (engine, pk) = fixture();
    let b = addr(B);
    assert!(engine.note_worker_observed_endpoint(&pk, b));
    let (seq_before, live_before, _, _) = snapshot_state(&engine, &pk);
    // Race the invalidation between two identical observations.
    engine.invalidate_roam_snapshots();
    let (_, live_raced, _, _) = snapshot_state(&engine, &pk);
    assert_eq!(live_raced, live_before + 1);
    assert!(
        !engine.note_worker_observed_endpoint(&pk, b),
        "equal slot: suppress, repairing the snapshot"
    );
    let (seq_after, live_after, snap_epoch_after, _) = snapshot_state(&engine, &pk);
    assert_eq!(live_after, live_raced, "nothing else moved the generation");
    assert_eq!(
        snap_epoch_after, live_after,
        "repair must restamp a stale snapshot to live"
    );
    assert!(
        seq_after > seq_before,
        "repair must publish (a bare equal-return leaves the sequence)"
    );
    assert!(
        !engine.note_worker_observed_endpoint(&pk, b),
        "repaired snapshot must suppress"
    );
    assert_eq!(
        snapshot_state(&engine, &pk),
        (seq_after, live_after, snap_epoch_after, true),
        "stable traffic after repair takes no further slow path"
    );
}

/// Concurrent reports, takes, and invalidations: takes adopt only
/// genuinely reported values (no fabrication, no torn mix — the slot
/// is mutex-guarded while the snapshot races lock-free), nothing
/// wedges, and steady state restores deterministically after quiesce.
/// Three reporters publish DISTINCT multiword V6 endpoints (address
/// words, ports, and scope spread across w0..w4) while the main
/// thread interleaves the two consumer transitions — take and
/// consumer-start invalidation. The prior same-value cell drained
/// pre-spawn on one atomic word and proved nothing about races; this
/// one holds on EVERY interleaving (oracles are universal, never
/// timing-dependent).
#[test]
fn concurrent_reports_takes_and_invalidations_coalesce_9644() {
    let (engine, pk) = fixture();
    let va: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
    let vb: SocketAddr = SocketAddr::V6(std::net::SocketAddrV6::new(
        "2001:db8::ffff:2".parse().unwrap(),
        41820,
        0,
        0,
    ));
    let vc: SocketAddr = SocketAddr::V6(std::net::SocketAddrV6::new(
        "2001:db8::3".parse().unwrap(),
        51820,
        0,
        9,
    ));
    let reported = [va, vb, vc];
    let engine = Arc::new(engine);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let mut handles = Vec::new();
    for &ep in &reported {
        let (engine, stop, barrier) =
            (Arc::clone(&engine), Arc::clone(&stop), Arc::clone(&barrier));
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                engine.note_worker_observed_endpoint(&pk, ep);
            }
        }));
    }
    barrier.wait();
    // Main thread interleaves takes with consumer-start invalidations
    // while publishes fly. Every drained value must be a reported one.
    let mut taken = Vec::new();
    for _ in 0..400 {
        if let Some(ep) = engine.take_worker_observed_endpoint(&pk) {
            assert!(
                reported.contains(&ep),
                "a drain must only ever adopt a reported endpoint"
            );
            taken.push(ep);
        }
        engine.invalidate_roam_snapshots();
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("reporter thread");
    }
    // Quiesce: drain the residue under the same oracle.
    while let Some(ep) = engine.take_worker_observed_endpoint(&pk) {
        assert!(
            reported.contains(&ep),
            "post-chaos residue must also be a reported endpoint"
        );
        taken.push(ep);
    }
    // Deterministic tail on the quiesced mailbox (slot is empty):
    // report once, suppress with no further shared write, then prove
    // the take bumped — with the bump no-op'd the post-take note
    // would suppress instead of re-reporting.
    assert!(engine.note_worker_observed_endpoint(&pk, va));
    let settled = snapshot_state(&engine, &pk);
    assert!(!engine.note_worker_observed_endpoint(&pk, va));
    assert_eq!(
        snapshot_state(&engine, &pk),
        settled,
        "post-chaos steady state suppresses lock-free"
    );
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(va));
    assert!(
        engine.note_worker_observed_endpoint(&pk, va),
        "post-take must re-report: proves the take bumped the generation"
    );
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(va));
    assert_eq!(engine.take_worker_observed_endpoint(&pk), None);
}

/// Distinct V6 endpoints (address and port) are distinct roams.
#[test]
fn v6_roam_reports_distinct_endpoints_9644() {
    let (engine, pk) = fixture();
    let v6a: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
    let v6b: SocketAddr = "[2001:db8::2]:51820".parse().unwrap();
    let v6c: SocketAddr = "[2001:db8::1]:41820".parse().unwrap();
    assert!(engine.note_worker_observed_endpoint(&pk, v6a));
    assert!(
        engine.note_worker_observed_endpoint(&pk, v6b),
        "a new V6 address must report"
    );
    assert!(
        engine.note_worker_observed_endpoint(&pk, v6c),
        "a new V6 port must report"
    );
    // Last-write-wins: the drain adopts the latest.
    assert_eq!(engine.take_worker_observed_endpoint(&pk), Some(v6c));
    assert_eq!(engine.take_worker_observed_endpoint(&pk), None);
}
