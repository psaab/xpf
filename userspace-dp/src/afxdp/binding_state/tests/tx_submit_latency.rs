// #812 TX submit-latency histogram tests (stamp/reap fold, OOB
// handling, cross-thread skew bound). Split from umem/tests.rs (#4667).

use super::*;

// -------------------------------------------------------------
// #812 test pins. Plan §6.1 + §5.1 / §5.2 / §5.4.
// -------------------------------------------------------------

#[test]
fn tx_latency_hist_bucket_boundary_roundtrip() {
    // #812 plan §6.1 test #1. Drive the production helper
    // `record_tx_completions_with_stamp` with deterministic T0
    // and T0 + K values and assert exactly one count lands in
    // the predicted bucket per K. Pair with the existing
    // `bucket_index_for_ns` boundary pins so a bucket-layout
    // drift breaks BOTH tests, not just this one.
    for &delta_ns in &[500u64, 1500, 10_000, 100_000, 10_000_000] {
        let live = BindingLiveState::new();
        let owner = &live.owner_profile_owner;
        // Sidecar big enough for one slot at frame 0.
        let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; 1];
        let t0 = 10_000_000_000u64;
        // Stamp: offset 0 → slot 0.
        crate::afxdp::tx::stamp_submits(&mut sidecar, [0u64].into_iter(), t0);
        let (count, sum) = crate::afxdp::tx::record_tx_completions_with_stamp(
            &mut sidecar,
            &[0u64],
            t0 + delta_ns,
            owner,
        );
        assert_eq!(count, 1);
        assert_eq!(sum, delta_ns);
        let bucket = bucket_index_for_ns(delta_ns);
        for b in 0..TX_SUBMIT_LAT_BUCKETS {
            let got = owner.tx_submit_latency_hist[b].load(Ordering::Relaxed);
            let expected = if b == bucket { 1 } else { 0 };
            assert_eq!(
                got, expected,
                "delta_ns={delta_ns} bucket={bucket}: hist[{b}] = {got}, want {expected}",
            );
        }
        assert_eq!(owner.tx_submit_latency_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            owner.tx_submit_latency_sum_ns.load(Ordering::Relaxed),
            delta_ns,
        );
        // Sidecar slot is cleared after the reap fold — another
        // completion against the same offset without a fresh
        // stamp MUST NOT produce a second bucket increment
        // (plan §5.4 phantom-completion handling).
        assert_eq!(sidecar[0], TX_SIDECAR_UNSTAMPED);
    }
}

#[test]
fn tx_latency_hist_partial_batch_stamping_only_touches_accepted_prefix() {
    // #812 plan §6.1 test #2. Build a scratch of 256 offsets;
    // stamp with `inserted ∈ {1, 2, 32, 64, 256}`. Assert only
    // the first `inserted` sidecar slots hold the stamp and the
    // tail remains at TX_SIDECAR_UNSTAMPED — the Codex HIGH #1
    // small-batch regime contract (plan §3.1).
    for &inserted in &[1usize, 2, 32, 64, 256] {
        let frames = 256u64;
        let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; frames as usize];
        let offsets: Vec<u64> = (0..frames).map(|i| i << UMEM_FRAME_SHIFT).collect();
        let ts = 42_000_000_000u64;
        // Only the accepted prefix is passed to stamp_submits —
        // matches the six submit-site call pattern
        // (`.take(inserted as usize)`).
        crate::afxdp::tx::stamp_submits(&mut sidecar, offsets.iter().take(inserted).copied(), ts);
        for (i, slot) in sidecar.iter().enumerate() {
            if i < inserted {
                assert_eq!(
                    *slot, ts,
                    "inserted={inserted}: slot[{i}] = {slot}, want {ts}",
                );
            } else {
                assert_eq!(
                    *slot, TX_SIDECAR_UNSTAMPED,
                    "inserted={inserted}: tail slot[{i}] must not be stamped",
                );
            }
        }
    }
}

#[test]
fn tx_latency_hist_retry_unwind_leaves_no_stamps() {
    // #812 plan §6.1 test #3. The `inserted == 0` retry-unwind
    // path at the commit-rejected sites (e.g. tx/transmit.rs::commit-rejected helpers
    // / tx/transmit.rs::ring-rejected paths) hands NO offsets to `stamp_submits`
    // — the descriptors are pushed back onto free_tx_frames
    // and the call-site Pattern is `.take(inserted as usize)`
    // which is `.take(0)` here. Pin the behaviour by invoking
    // stamp_submits with an empty iterator and asserting every
    // sidecar slot remains at the unstamped sentinel.
    let frames = 8u64;
    let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; frames as usize];
    let empty: std::iter::Empty<u64> = std::iter::empty();
    crate::afxdp::tx::stamp_submits(&mut sidecar, empty, 77_000_000_000u64);
    for (i, slot) in sidecar.iter().enumerate() {
        assert_eq!(
            *slot, TX_SIDECAR_UNSTAMPED,
            "slot[{i}]: retry-unwind must not leave a stamp behind",
        );
    }
}

#[test]
fn tx_latency_hist_sentinel_skip_for_unstamped_completion() {
    // #812 plan §6.1 test #5 + §5.4. A completion against a
    // sidecar slot that is still at TX_SIDECAR_UNSTAMPED (e.g.
    // a cross-restart leftover, or a `monotonic_nanos() == 0`
    // clock-gettime failure that caused `stamp_submits` to
    // early-return without touching the slot) MUST NOT bump any
    // bucket. Pins the Codex round-1 MED + Rust round-1 MED-2
    // fix: `stamp_submits(..., ts=0)` no longer writes the
    // sentinel — it returns without touching the sidecar, so the
    // slot retains its pre-existing "unstamped" state.
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; 2];
    // Offset 0: never stamped at all. Offset 1: attempted stamp
    // with ts=0 (VDSO-failure simulation) — the new semantics
    // skip the write entirely, leaving the slot at UNSTAMPED.
    crate::afxdp::tx::stamp_submits(&mut sidecar, [1u64 << UMEM_FRAME_SHIFT].into_iter(), 0);
    // Both slots are UNSTAMPED: slot 0 was never touched, slot 1
    // was early-returned on the ts=0 gate (NOT sentinel-written).
    assert_eq!(sidecar[0], TX_SIDECAR_UNSTAMPED);
    assert_eq!(sidecar[1], TX_SIDECAR_UNSTAMPED);
    let completed = [0u64, 1u64 << UMEM_FRAME_SHIFT];
    let (count, sum) = crate::afxdp::tx::record_tx_completions_with_stamp(
        &mut sidecar,
        &completed,
        123_456,
        owner,
    );
    assert_eq!(count, 0, "both completions must be dropped");
    assert_eq!(sum, 0);
    for b in 0..TX_SUBMIT_LAT_BUCKETS {
        assert_eq!(
            owner.tx_submit_latency_hist[b].load(Ordering::Relaxed),
            0,
            "bucket {b} must stay 0 on unstamped completions",
        );
    }
}

#[test]
fn tx_latency_hist_single_thread_sum_equals_count() {
    // #812 plan §6.1 test #6 / §5.2. Drive N synthetic stamps +
    // completions in one thread (no race); assert the sum of
    // the histogram buckets exactly equals the observed count
    // AND equals the snapshot's `tx_submit_latency_count`.
    // Under single-threaded drive this is a hard equality; the
    // cross-thread loosening lives in the bounded-skew test
    // below.
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    let n: u64 = 10_000;
    let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; n as usize];
    let offsets: Vec<u64> = (0..n).map(|i| i << UMEM_FRAME_SHIFT).collect();
    let t0 = 1_000_000_000u64;
    // Spread the deltas across a few buckets so we don't trivially
    // pile all mass into bucket 0.
    let deltas: Vec<u64> = (0..n)
        .map(|i| 500 + (i % 7) * 2_500) // 500, 3000, 5500, ...
        .collect();
    // Stamp each offset individually at a distinct time so the
    // completion delta lands on the prescribed `delta_i`.
    for i in 0..n as usize {
        crate::afxdp::tx::stamp_submits(&mut sidecar, [offsets[i]].into_iter(), t0 - deltas[i]);
    }
    // Single reap: pretend we observe all completions at time t0.
    crate::afxdp::tx::record_tx_completions_with_stamp(&mut sidecar, &offsets, t0, owner);
    let snap = live.snapshot();
    let sum_buckets: u64 = snap.tx_submit_latency_hist.iter().copied().sum();
    assert_eq!(sum_buckets, n);
    assert_eq!(snap.tx_submit_latency_count, n);
    let expected_sum_ns: u64 = deltas.iter().copied().sum();
    assert_eq!(snap.tx_submit_latency_sum_ns, expected_sum_ns);
}

#[test]
fn tx_latency_hist_cross_thread_snapshot_skew_within_bound() {
    // #812 plan §6.1 test #7 (Codex round-1 HIGH #2). Spawn a
    // REAL writer thread and a REAL reader thread (the previous
    // pin did both halves on the main thread, so the "cross-
    // thread" label was a lie). The writer drives the PRODUCTION
    // helpers `stamp_submits` + `record_tx_completions_with_stamp`
    // — not raw `fetch_add` — so the pin exercises the actual
    // shipped fold, not a synthetic one.
    //
    // Deterministic bound (#4011): the old bound was
    //   K_skew = ceil(λ_obs × W_read_max) + 2
    // where λ_obs = count_final / elapsed_wall_ns (the AVERAGE
    // production rate over the whole run) and W_read_max = the
    // MAXIMUM snapshot read window observed. Multiplying an average
    // rate by a maximum window under-estimates the emission during
    // any single window whose INSTANTANEOUS writer rate ran above
    // the average — ordinary under a loaded box / scheduler jitter
    // — so a legitimately-bounded skew could exceed the modelled
    // K_skew and trip the pin (the load-sensitive flake that made
    // `make test` itself flaky once #4006 wired the Rust suite in).
    //
    // Fix: MEASURE per-window emission directly instead of
    // modelling it from a global average. The writer increments the
    // histogram bucket BEFORE `count` (stats.rs
    // record_tx_completions_with_stamp: bucket fetch_add, then
    // count fetch_add) and the reader reads the histogram BEFORE
    // `count` (snapshot.rs: snapshot_hist, then count load); both
    // counters are monotonic. The reader brackets each snapshot
    // with a raw `count` load before and after, so
    //   window_delta = count_after − count_before
    // is exactly how many completions the writer published during
    // that snapshot's whole read window — the only records that can
    // make `sum(hist)` and `count` disagree for THIS sample. With a
    // single sequential writer under TSO at most one record is
    // "hist done, count pending" at any instant, giving the proven
    //   |sum − count| ≤ window_delta + 1.
    //
    // Pin assertion (per sample): |sum(hist) − count| ≤
    // window_delta + K_MARGIN, K_MARGIN = 2. This holds under ANY
    // load — window_delta scales with whatever the writer actually
    // did during a preempted read — yet still catches the real
    // defect the pin guards: a torn/dropped accounting bug that
    // loses a bucket or count increment drives |sum − count| toward
    // count_final (millions), unbounded relative to the handful of
    // records in any single window_delta.
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    let live = Arc::new(BindingLiveState::new());
    let stop = Arc::new(AtomicBool::new(false));
    let reader_warm = Arc::new(AtomicBool::new(false));

    // Writer: owns its own sidecar (plan §3.3 single-writer
    // invariant) and runs the real stamp→reap fold in a tight
    // loop. `sidecar_len = 64` gives the writer room to hold 64
    // in-flight "frames" without cycling the whole array each
    // iteration.
    let writer_live = Arc::clone(&live);
    let writer_stop = Arc::clone(&stop);
    let writer_warm = Arc::clone(&reader_warm);
    let writer_handle = std::thread::spawn(move || {
        let owner = &writer_live.owner_profile_owner;
        let sidecar_len: u64 = 64;
        let mut sidecar: Vec<u64> = vec![TX_SIDECAR_UNSTAMPED; sidecar_len as usize];
        let offsets: Vec<u64> = (0..sidecar_len).map(|i| i << UMEM_FRAME_SHIFT).collect();
        let mut cursor: u64 = 0;
        // Warm phase: run 10k cycles before signalling the reader
        // so the λ_obs calculation is computed over the steady-
        // state regime, not startup (Codex §7 / plan §6.1).
        for _ in 0..10_000u64 {
            let offset = offsets[(cursor % sidecar_len) as usize];
            let t_submit = cursor.saturating_add(1);
            crate::afxdp::tx::stamp_submits(&mut sidecar, std::iter::once(offset), t_submit);
            let t_complete = t_submit + 1024;
            crate::afxdp::tx::record_tx_completions_with_stamp(
                &mut sidecar,
                &[offset],
                t_complete,
                owner,
            );
            cursor = cursor.wrapping_add(1);
        }
        writer_warm.store(true, Ordering::Release);
        while !writer_stop.load(Ordering::Relaxed) {
            let offset = offsets[(cursor % sidecar_len) as usize];
            let t_submit = cursor.saturating_add(1);
            crate::afxdp::tx::stamp_submits(&mut sidecar, std::iter::once(offset), t_submit);
            let t_complete = t_submit + 1024;
            crate::afxdp::tx::record_tx_completions_with_stamp(
                &mut sidecar,
                &[offset],
                t_complete,
                owner,
            );
            cursor = cursor.wrapping_add(1);
        }
    });

    // Reader: dedicated thread that snapshots the binding's
    // atomics and records every `|sum − count|` plus the
    // measured read window. The reader captures samples into
    // a shared Mutex<Vec<_>> the main thread consumes after
    // join.
    #[derive(Clone, Copy)]
    struct Sample {
        skew: i64,
        window_delta: u64,
    }
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::with_capacity(5_000)));
    let reader_live = Arc::clone(&live);
    let reader_stop = Arc::clone(&stop);
    let reader_warm_rd = Arc::clone(&reader_warm);
    let reader_samples = Arc::clone(&samples);
    let reader_handle = std::thread::spawn(move || {
        // Wait for writer warmup (bounded — don't hang tests if
        // the writer never warms).
        let wait_deadline = Instant::now() + Duration::from_secs(2);
        while !reader_warm_rd.load(Ordering::Acquire) && Instant::now() < wait_deadline {
            std::thread::yield_now();
        }
        // Run for a real wall-clock duration, not a fixed count
        // (Codex round-2 HIGH-2). The writer+reader loop overlaps
        // for the entire 200 ms window orchestrated below; the
        // reader keeps snapshotting until the main thread signals
        // `stop`, so the observed race window is time-bounded,
        // not iteration-count-bounded.
        //
        // Bracket each snapshot with a raw `count` load before and
        // after (#4011). `count` is monotonic, so
        // `count_after − count_before` is exactly how many
        // completions the writer published during this snapshot's
        // read window — the per-sample bound denominator, measured
        // rather than modelled from a global average rate.
        let mut local = Vec::with_capacity(16_384);
        while !reader_stop.load(Ordering::Relaxed) {
            let count_before = reader_live
                .owner_profile_owner
                .tx_submit_latency_count
                .load(Ordering::Relaxed);
            let snap = reader_live.snapshot();
            let count_after = reader_live
                .owner_profile_owner
                .tx_submit_latency_count
                .load(Ordering::Relaxed);
            let count = snap.tx_submit_latency_count as i64;
            let sum_buckets: i64 = snap.tx_submit_latency_hist.iter().copied().sum::<u64>() as i64;
            let skew = (sum_buckets - count).abs();
            let window_delta = count_after.saturating_sub(count_before);
            local.push(Sample { skew, window_delta });
        }
        *reader_samples.lock().unwrap() = local;
    });

    // Let the writer+reader run for a bounded wall window, then
    // shut the writer down and join both threads.
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    writer_handle.join().expect("writer thread joins cleanly");
    reader_handle.join().expect("reader thread joins cleanly");

    let count_final = live.snapshot().tx_submit_latency_count;
    assert!(
        count_final > 0,
        "writer thread produced no completions — harness broken",
    );

    let gathered = samples.lock().unwrap().clone();
    assert!(
        !gathered.is_empty(),
        "reader thread produced no snapshots — harness broken",
    );

    // Per-sample deterministic bound (#4011): for every snapshot
    //   |sum(hist) − count| ≤ window_delta + K_MARGIN.
    // K_MARGIN = 2 = the proven +1 in-flight boundary (one record
    // "hist done, count pending" under TSO's single sequential
    // writer) plus one unit of weak-memory reorder slack. `excess`
    // = skew − window_delta is how far a sample exceeds the ideal
    // `skew ≤ window_delta`; the worst `excess` across all samples
    // must stay within K_MARGIN, independent of scheduler load.
    const K_MARGIN: i64 = 2;
    let mut max_skew = 0i64;
    let mut max_window_delta = 0u64;
    let mut max_excess = i64::MIN;
    let mut worst = Sample {
        skew: 0,
        window_delta: 0,
    };
    for s in &gathered {
        let excess = s.skew - s.window_delta as i64;
        if excess > max_excess {
            max_excess = excess;
            worst = *s;
        }
        if s.skew > max_skew {
            max_skew = s.skew;
        }
        if s.window_delta > max_window_delta {
            max_window_delta = s.window_delta;
        }
    }
    assert!(
        max_excess <= K_MARGIN,
        "cross-thread skew exceeds per-window bound: worst sample \
         skew={} window_delta={} excess={} (> K_MARGIN={}); \
         max_skew={max_skew} max_window_delta={max_window_delta} \
         count_final={count_final} samples={}",
        worst.skew,
        worst.window_delta,
        max_excess,
        K_MARGIN,
        gathered.len(),
    );
    eprintln!(
        "tx_latency_hist_cross_thread_snapshot_skew_within_bound: \
         max_excess={max_excess} K_MARGIN={K_MARGIN} \
         max_skew={max_skew} max_window_delta={max_window_delta} \
         count_final={count_final} samples={}",
        gathered.len(),
    );
}

#[test]
fn tx_submit_ns_sidecar_single_writer_ownership_is_rc_not_arc() {
    // #812 plan §6.1 test #6 (per §3.3 single-writer
    // invariant). `WorkerUmem` is `Rc<WorkerUmemInner>` at
    // umem/mod.rs — NOT `Arc` — enforcing single-owner
    // semantics on the sidecar's backing UMEM. A future
    // refactor that quietly upgrades the field to `Arc` to
    // share bindings across threads would silently break the
    // no-atomic assumption on `tx_submit_ns: Box<[u64]>`.
    //
    // We cannot run a full `WorkerUmem::new` here because
    // UMEM allocation requires CAP_NET_ADMIN for the XDP
    // socket — it fails in the standard unit-test
    // environment. Instead we pin the type identity at
    // compile time via two complementary fn-pointer probes
    // that mechanically require the Rc-shape API:
    //
    // 1. `shares_allocation_with`: body uses `Rc::ptr_eq`.
    //    An Arc migration would need `Arc::ptr_eq` and the
    //    method's source line breaks before this test even
    //    gets a chance to run.
    // 2. `allocation_ptr`: body uses `Rc::as_ptr`. Same
    //    shape.
    //
    // And at runtime we assert that two `Clone`s of the
    // same WorkerUmem share allocation, which exercises
    // `Rc::ptr_eq` on a live pair. We build the pair
    // without hitting the kernel by wrapping a direct
    // `WorkerUmemInner` with a 1-byte MmapArea and a stub
    // Umem — bypassing the `new` path that requires root.
    //
    // If the single-writer invariant ever needs re-
    // establishment with a shared-ownership backing (Arc),
    // the refactor will cascade through both the fn-pointer
    // lines here AND the `tx_submit_ns: Box<[u64]>` field
    // itself (which is sound only under single-owner
    // access) — a loud failure, not silent drift.
    let _: fn(&WorkerUmem, &WorkerUmem) -> bool = WorkerUmem::shares_allocation_with;
    let _: fn(&WorkerUmem) -> *const WorkerUmemInner = WorkerUmem::allocation_ptr;
    let _: fn(&WorkerUmem) -> *mut crate::xsk_ffi::XskUmemOpaque = WorkerUmem::as_raw_umem_ptr;
}

#[test]
fn tx_latency_hist_shared_umem_secondary_offsets_all_stamped_15244() {
    // #15244 (A61-01): under a shared UMEM the pool is filled for
    // the WHOLE group and each binding pops its carve-out
    // sequentially, so the secondary owns offsets `[N, 2N)` while
    // its own per-binding frame count is only N. Pre-fix the
    // sidecar was sized to that per-binding count, so
    // `stamp_submits` silently dropped every secondary stamp (and
    // the reap fold dropped every matching completion) and the
    // #812 histogram covered only the owner / a
    // direction-dependent subset. The fix sizes the sidecar to
    // `worker_umem.total_frames()` (the group sum) via
    // `tx_submit_sidecar_len`.
    //
    // RED on the pre-fix mechanism: `tx_submit_sidecar_len` does
    // not exist pre-fix (the production literal was
    // `vec![...; total_frames as usize]` with the per-binding
    // count), and a sidecar built the old way (length N) drops the
    // secondary stamps asserted below — the former
    // `tx_latency_hist_shared_umem_oob_offset_stamp_silent_drop`
    // pin asserted exactly that drop and is superseded by this
    // test. The acceptance probe: `secondary_stamped=N/N`.
    //
    // The pool models `WorkerUmemPool::new(2N)`: offsets
    // `[0, 2N)` in frame order; the owner pops `[0, N)`, the
    // secondary `[N, 2N)`.
    let n: u32 = 4;
    let umem = WorkerUmem::new_for_test(2 * n).expect("group umem");
    let secondary_len = crate::afxdp::worker::tx_submit_sidecar_len(&umem);
    assert_eq!(
        secondary_len, (2 * n) as usize,
        "#15244: sidecar must span the whole shared region (group sum), \
         not the secondary's own {n}-frame carve-out"
    );
    let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; secondary_len];
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    let t0 = 42_000_000_000u64;
    // The secondary submits its whole carve-out `[N, 2N)`.
    let secondary_offsets: Vec<u64> = (n..2 * n)
        .map(|idx| (idx as u64) << UMEM_FRAME_SHIFT)
        .collect();
    crate::afxdp::tx::stamp_submits(&mut sidecar, secondary_offsets.iter().copied(), t0);
    let secondary_stamped = sidecar[(n as usize)..]
        .iter()
        .filter(|slot| **slot == t0)
        .count();
    assert_eq!(
        secondary_stamped, n as usize,
        "#15244: secondary_stamped={secondary_stamped}/{} — every shared \
         secondary stamp above its own frame count must land in its own \
         sidecar",
        n
    );
    assert!(
        sidecar[..(n as usize)]
            .iter()
            .all(|slot| *slot == TX_SIDECAR_UNSTAMPED),
        "the owner's half of the sidecar must stay unstamped"
    );
    // Every secondary completion is counted by its own binding.
    let (count, sum) = crate::afxdp::tx::record_tx_completions_with_stamp(
        &mut sidecar,
        &secondary_offsets,
        t0 + 10_000,
        owner,
    );
    assert_eq!(
        count, n as u64,
        "#15244: every secondary completion must be counted by its own binding"
    );
    assert_eq!(sum, (n as u64) * 10_000);
    assert_eq!(owner.tx_submit_latency_count.load(Ordering::Relaxed), n as u64);
}

#[test]
fn tx_latency_hist_shared_umem_oob_offset_stamp_silent_drop() {
    // #812 Rust round-1 HIGH-1, narrowed by #15244 (A61-01): an
    // offset past the WHOLE UMEM region (not merely past this
    // binding's own carve-out — those now stamp, see
    // `tx_latency_hist_shared_umem_secondary_offsets_all_stamped_15244`)
    // is genuinely foreign: a stale/cross-restart offset, never a
    // live submit from this binding. `stamp_submits` MUST drop it
    // silently — touching it would either overflow or corrupt an
    // unrelated slot.
    //
    // Pin: build a region-sized sidecar, drive `stamp_submits`
    // with one in-range and two past-the-region offsets, assert
    // the in-range slot landed exactly the stamp and ALL other
    // slots are untouched.
    let sidecar_len: u64 = 4;
    let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; sidecar_len as usize];
    let in_range = 1u64 << UMEM_FRAME_SHIFT; // idx 1, inside
    let just_past = sidecar_len << UMEM_FRAME_SHIFT; // idx == len (past region)
    let far_past = (sidecar_len + 1000) << UMEM_FRAME_SHIFT; // idx len+1000
    let ts = 42_000_000_000u64;
    crate::afxdp::tx::stamp_submits(
        &mut sidecar,
        [in_range, just_past, far_past].into_iter(),
        ts,
    );
    // Slot 1 stamped; slots 0, 2, 3 unchanged. Past-region offsets
    // produced NO allocation (slice not grown) and NO mutation
    // outside the bounds.
    assert_eq!(sidecar.len(), sidecar_len as usize, "len unchanged");
    assert_eq!(sidecar[0], TX_SIDECAR_UNSTAMPED);
    assert_eq!(sidecar[1], ts);
    assert_eq!(sidecar[2], TX_SIDECAR_UNSTAMPED);
    assert_eq!(sidecar[3], TX_SIDECAR_UNSTAMPED);
}

#[test]
fn tx_latency_hist_shared_umem_oob_offset_reap_no_phantom_bucket() {
    // #812 Rust round-1 HIGH-1 companion, narrowed by #15244: drive
    // `record_tx_completions_with_stamp` with an offset past the
    // WHOLE region. `get_mut` returns None → the fold treats the
    // "stamp" as TX_SIDECAR_UNSTAMPED → the delta check drops the
    // sample → NO bucket bumped, NO `count` / `sum_ns` increment.
    // This is the reap-side half of the "honest histogram"
    // invariant: genuinely foreign offset noise cannot produce a
    // phantom completion.
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    let sidecar_len: u64 = 4;
    let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; sidecar_len as usize];
    // Pre-stamp slot 0 with a legitimate value so a phantom
    // cross-slot bleed would be visible as a bucket bump.
    let t0 = 5_000_000_000u64;
    crate::afxdp::tx::stamp_submits(&mut sidecar, [0u64].into_iter(), t0);
    // Completion against a past-region offset — must be dropped.
    let oob_offset = (sidecar_len + 7) << UMEM_FRAME_SHIFT;
    let (count, sum) = crate::afxdp::tx::record_tx_completions_with_stamp(
        &mut sidecar,
        &[oob_offset],
        t0 + 10_000,
        owner,
    );
    assert_eq!(count, 0, "past-region completion must not be counted");
    assert_eq!(sum, 0, "past-region completion must not bump sum_ns");
    for b in 0..TX_SUBMIT_LAT_BUCKETS {
        assert_eq!(
            owner.tx_submit_latency_hist[b].load(Ordering::Relaxed),
            0,
            "bucket {b} must stay 0 on past-region completion",
        );
    }
    // Slot 0 is still stamped — the foreign reap must not have
    // touched any in-range slot.
    assert_eq!(sidecar[0], t0, "in-range slot corrupted by foreign reap");
}
