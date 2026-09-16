//! #9644: lock-free roam-snapshot cells for `note/take_worker_observed_endpoint`.
//!
//! Each cell pins worker-observable behavior, never the mechanism:
//! a cell that stays green when the snapshot is deleted (all reports
//! still flow through the mutex slot) is vacuous, so every suppression
//! assertion is paired with a snapshot-write-stability read (seq/epoch/
//! pending bit-identical) or the mutex-held adversary. ("Snapshot
//! write" is exactly the seq/epoch/pending words: the table/peer `Arc`
//! refcount touches in `peer_arc` are out of scope for every oracle
//! here.) Concurrent cells additionally gate on reporter progress so
//! they fail loudly — never pass vacuously — when no overlap happens.

use super::peer::{RoamSnapshot, decode_roam_endpoint, encode_roam_endpoint};
use super::tests::established_pair;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
/// lock-free path can pass. (The `Arc` refcounts in `peer_arc` are
/// still touched; the oracle is the snapshot words, not all memory.)
#[test]
fn steady_state_suppresses_without_snapshot_write_9644() {
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
/// further snapshot write (no permanently-cold state). Capturing state
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
/// consumer-start invalidation. The main thread runs until EVERY
/// reporter has published through the window (per-reporter progress
/// counters, bounded spin), so the concurrent phase provably contains
/// reporter work — a main thread that outruns the reporters fails
/// loudly instead of passing on the sequential tail alone. Every
/// oracle holds on EVERY interleaving (universal, never
/// timing-dependent); seqlock-reader acceptance itself is pinned by
/// the `read_validated_endpoint` cells below, not by this mailbox
/// oracle.
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
    // Notes each reporter must complete inside the concurrent window
    // before the main thread may stop it. Any positive count proves
    // overlap; 50 keeps the window meaningfully concurrent without
    // costing measurable time (a note is sub-microsecond).
    const MIN_REPORTS_PER_REPORTER: u64 = 50;
    const MAX_MAIN_ITERS: u64 = 1_000_000;
    let engine = Arc::new(engine);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let progress: Arc<[AtomicU64; 3]> =
        Arc::new([AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)]);
    let mut handles = Vec::new();
    for (i, &ep) in reported.iter().enumerate() {
        let (engine, stop, barrier, progress) = (
            Arc::clone(&engine),
            Arc::clone(&stop),
            Arc::clone(&barrier),
            Arc::clone(&progress),
        );
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                engine.note_worker_observed_endpoint(&pk, ep);
                progress[i].fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    barrier.wait();
    // Main thread interleaves takes with consumer-start invalidations
    // until every reporter has published through the window. Every
    // drained value must be a reported one.
    let mut taken = Vec::new();
    let mut iters = 0u64;
    while progress
        .iter()
        .any(|p| p.load(Ordering::Relaxed) < MIN_REPORTS_PER_REPORTER)
    {
        if let Some(ep) = engine.take_worker_observed_endpoint(&pk) {
            assert!(
                reported.contains(&ep),
                "a drain must only ever adopt a reported endpoint"
            );
            taken.push(ep);
        }
        engine.invalidate_roam_snapshots();
        iters += 1;
        assert!(
            iters < MAX_MAIN_ITERS,
            "reporters stalled: {iters} take/invalidate rounds without {MIN_REPORTS_PER_REPORTER} notes per reporter"
        );
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("reporter thread");
    }
    for (i, p) in progress.iter().enumerate() {
        assert!(
            p.load(Ordering::Relaxed) >= MIN_REPORTS_PER_REPORTER,
            "reporter {i} must publish inside the concurrent window"
        );
    }
    // Quiesce: drain the residue under the same oracle.
    while let Some(ep) = engine.take_worker_observed_endpoint(&pk) {
        assert!(
            reported.contains(&ep),
            "post-chaos residue must also be a reported endpoint"
        );
        taken.push(ep);
    }
    // The very first note (empty slot, zeroed snapshot) always
    // reports, and every report is eventually drained exactly once
    // (a take that swaps `pending` true provably takes `Some`: the
    // publish's slot write precedes its pending store under the same
    // mutex the take serializes on) — so an empty `taken` means the
    // concurrent phase never happened, not that it coalesced.
    assert!(
        !taken.is_empty(),
        "the concurrent window must adopt at least one report"
    );
    // Deterministic tail on the quiesced mailbox (slot is empty):
    // report once, suppress with no further snapshot write, then prove
    // the take bumped — with the bump no-op'd the post-take note
    // would suppress instead of re-reporting. (Unchanged snapshot
    // words alone do NOT prove lock-freedom — a lock-path duplicate
    // leaves them unchanged too — so this tail pairs with
    // `suppression_needs_no_mutex_9644`, which only the lock-free
    // path can pass.)
    assert!(engine.note_worker_observed_endpoint(&pk, va));
    let settled = snapshot_state(&engine, &pk);
    assert!(!engine.note_worker_observed_endpoint(&pk, va));
    assert_eq!(
        snapshot_state(&engine, &pk),
        settled,
        "post-chaos steady state publishes nothing further"
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

/// The production snapshot-validation decision against controlled
/// torn/stale states: `read_validated_endpoint` is the exact fast-path
/// read (the hot path calls it; the mailbox mutex is never touched
/// here), driven single-threaded through odd, mixed-word, and
/// stale-epoch publications. Each rejection below fails if its guard
/// is deleted: without the odd check the in-flight states validate
/// (`s0 == s1`, both odd, epochs matching); without the epoch checks
/// the bumped state validates. Deterministic — no threads, no timing.
#[test]
fn snapshot_reader_rejects_inflight_and_stale_9644() {
    let a: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
    let b = SocketAddr::V6(std::net::SocketAddrV6::new(
        "2001:db8:1:2:3:4:5:6".parse().unwrap(),
        41820,
        7,
        9,
    ));
    let wa = encode_roam_endpoint(a);
    let wb = encode_roam_endpoint(b);
    assert!(
        wa.iter().zip(wb.iter()).all(|(x, y)| x != y),
        "fixture precondition: every word differs, so any mixed-word publication decodes to neither endpoint"
    );
    let snap = RoamSnapshot::new();
    // Fresh (family-0 sentinel) validates to nothing.
    assert_eq!(snap.read_validated_endpoint(), None);
    // A complete epoch-0 publication of A validates to A.
    snap.begin_publish();
    snap.commit_publish(wa, 0);
    assert_eq!(snap.read_validated_endpoint(), Some(a));
    // In-flight publication of B with MIXED words (w0 of B, rest of
    // A): the odd sequence must reject it even though the epochs
    // still match. Without the odd gate this validates to a neither
    // endpoint (s0 == s1, epochs equal, mixed words decode).
    snap.begin_publish();
    snap.w0.store(wb[0], Ordering::Relaxed);
    assert_eq!(
        snap.read_validated_endpoint(),
        None,
        "an in-flight mixed-word publication must not validate"
    );
    // In-flight with ALL words of B: still odd, still rejected.
    // Without the odd gate this validates to Some(b).
    snap.w1.store(wb[1], Ordering::Relaxed);
    snap.w2.store(wb[2], Ordering::Relaxed);
    snap.w3.store(wb[3], Ordering::Relaxed);
    snap.w4.store(wb[4], Ordering::Relaxed);
    snap.snap_epoch.store(0, Ordering::Relaxed);
    assert_eq!(
        snap.read_validated_endpoint(),
        None,
        "an in-flight complete-word publication must not validate while odd"
    );
    // Closed, the same words validate to B.
    snap.commit_publish(wb, 0);
    assert_eq!(snap.read_validated_endpoint(), Some(b));
    // A drained/restarted generation (live bumped past the stamped
    // epoch) must not validate: without the epoch checks this
    // returns Some(b) and the next packet wrongly suppresses.
    snap.bump_live_epoch();
    assert_eq!(
        snap.read_validated_endpoint(),
        None,
        "a stale-epoch snapshot must not validate"
    );
    // Republishing at the live generation restores validation.
    let live = snap.live_epoch.load(Ordering::Relaxed);
    snap.begin_publish();
    snap.commit_publish(wb, live);
    assert_eq!(snap.read_validated_endpoint(), Some(b));
}

/// The production reader against racing publications: a writer
/// alternating two every-word-distinct V6 endpoints through the
/// production `begin/commit_publish` at full speed while the main
/// thread hammers the production `read_validated_endpoint`.
/// Universal oracle: every accepted read is a COMPLETE publication
/// (A or B — the encoding is injective, so a torn mix decodes to
/// neither); a validator that skips the `s0 == s1` check accepts
/// mixes and fails. The writer runs TIGHT (no stretching): a reader
/// loads its words nanoseconds after `s0`, so only a production-rate
/// publisher lands stores inside that span — stretched windows just
/// separate the timescales and never straddle. Overlap is proven,
/// not assumed: the reader must observe the writer strictly
/// mid-stream (the writer yields every 256 publications to keep that
/// window open). (The Acquire fence has no x86-observable mutant —
/// TSO orders the loads regardless — so the fence is pinned by
/// review, not here.)
#[test]
fn snapshot_reader_accepts_only_complete_publications_9644() {
    use std::sync::atomic::AtomicBool;
    let a: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
    let b = SocketAddr::V6(std::net::SocketAddrV6::new(
        "2001:db8:1:2:3:4:5:6".parse().unwrap(),
        41820,
        7,
        9,
    ));
    let wa = encode_roam_endpoint(a);
    let wb = encode_roam_endpoint(b);
    assert!(
        wa.iter().zip(wb.iter()).all(|(x, y)| x != y),
        "fixture precondition: every word differs, so a torn mix decodes to neither endpoint"
    );
    const PUBS: u64 = 20_000;
    let snap = Arc::new(RoamSnapshot::new());
    let pubs = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let writer = {
        let (snap, pubs, done) = (Arc::clone(&snap), Arc::clone(&pubs), Arc::clone(&done));
        std::thread::spawn(move || {
            for i in 0..PUBS {
                let w = if i & 1 == 0 { wa } else { wb };
                snap.begin_publish();
                snap.commit_publish(w, 0);
                pubs.fetch_add(1, Ordering::Relaxed);
                // Keep the overlap window open; the publications
                // themselves run at production rate between yields.
                if i % 256 == 255 {
                    std::thread::yield_now();
                }
            }
            done.store(true, Ordering::Relaxed);
        })
    };
    let mut reads = 0u64;
    let mut overlapped = false;
    while !done.load(Ordering::Relaxed) {
        if let Some(x) = snap.read_validated_endpoint() {
            assert!(
                x == a || x == b,
                "the reader must only ever accept a complete publication, got {x:?}"
            );
        }
        reads += 1;
        // Strictly mid-stream: the writer started and has not
        // finished while this read executed.
        let p = pubs.load(Ordering::Relaxed);
        if p > 0 && p < PUBS {
            overlapped = true;
        }
    }
    writer.join().expect("writer thread");
    assert!(
        overlapped,
        "the reader must observe the writer mid-stream ({reads} reads, {PUBS} publications)"
    );
    // Deterministic anchor: quiesced, the final publication (B —
    // PUBS is even, so the last write is index PUBS-1, odd, B) reads
    // back exactly.
    assert_eq!(pubs.load(Ordering::Relaxed), PUBS);
    assert_eq!(snap.read_validated_endpoint(), Some(b));
}
